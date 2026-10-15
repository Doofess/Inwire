/**
 * The one place a capture's frames are deleted without a click (ADR 0052).
 *
 *   npx tsx scripts/capture/segment-guard.ts
 *
 * A capture that follows the agent's ring deletes a segment when the agent
 * deletes the ring file it held. `planSegmentEviction` decides which may go;
 * this holds every refusal in it, one at a time, against the case where the
 * same segment WOULD go - so each check fails if its rule is taken out, rather
 * than passing because something else refused first. Then the volume: the
 * only directories it removes are ones it named itself, from a number.
 *
 * `prune-guard.ts` is the same kind of script for ADR 0012's other delete.
 * No frames here: the rule is over segment numbers and sequence numbers, and
 * `segments.ts` beside this drives the real capture through it.
 */
import { mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  planSegmentEviction, segmentName, segmentNumberOf, type EvictionFacts, type SegmentMeta,
} from '../../src/services/capture/segments';
import { captureVolume } from '../../electron/store/volume';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

/**
 * Chunks 0-1 in segment 1, 2-3 in segment 2, 4 in segment 3 (being written).
 * Segment 1 holds seq 0-999, segment 2 seq 1000-1999, all of run 1.
 */
function facts(change: Partial<EvictionFacts> = {}, meta: Record<number, Partial<SegmentMeta>> = {}): EvictionFacts {
  const segments = [1, 1, 2, 2, 3];
  const base: Record<number, SegmentMeta> = {
    1: { epoch: 1, maxSeq: 999, mixed: false },
    2: { epoch: 1, maxSeq: 1999, mixed: false },
    3: { epoch: 1, maxSeq: 2400, mixed: false },
  };
  const merged = new Map<number, SegmentMeta>();
  for (const [n, m] of Object.entries(base)) merged.set(Number(n), { ...m, ...meta[Number(n)] });
  return {
    chunkCount: segments.length,
    floorChunk: 0,
    segmentOf: (chunk) => segments[chunk],
    current: 3,
    oldestStaged: 3,
    meta: merged,
    deleted: { epoch: 1, lastSeq: 1999 },
    ...change,
  };
}
const plan = (f: EvictionFacts) => planSegmentEviction(f);

console.log('--- what may go ---\n');
check('segments whose every frame is at or below the deleted file go, oldest first',
  plan(facts()), { floorChunk: 4, remove: [1, 2] });
check('only as far as the deleted file reaches',
  plan(facts({ deleted: { epoch: 1, lastSeq: 999 } })), { floorChunk: 2, remove: [1] });
check('from the floor, never again below it',
  plan(facts({ floorChunk: 2 })), { floorChunk: 4, remove: [2] });

console.log('\n--- what may not, each against a case that otherwise would ---\n');
check('a segment with a frame past the deleted file waits',
  plan(facts({ deleted: { epoch: 1, lastSeq: 998 } })), { floorChunk: 0, remove: [] });
check('a segment of another run of the agent is kept',
  plan(facts({ deleted: { epoch: 2, lastSeq: 1999 } })), { floorChunk: 0, remove: [] });
check('a segment holding a frame no ring filed, or another run\'s, is kept',
  plan(facts({}, { 1: { mixed: true } })), { floorChunk: 0, remove: [] });
check('a segment this run knows nothing of - one written before a reopen - is kept',
  plan(facts({ meta: new Map() })), { floorChunk: 0, remove: [] });
check('the segment being written is kept',
  plan(facts({ current: 2, deleted: { epoch: 1, lastSeq: 9999 } })), { floorChunk: 2, remove: [1] });
check('a segment with a frame still staged is kept',
  plan(facts({ oldestStaged: 2 })), { floorChunk: 2, remove: [1] });
check('segment 0, the capture\'s own files, is never removed',
  plan(facts({ segmentOf: (chunk) => [0, 0, 2, 2, 3][chunk] }, { 0: { epoch: 1, maxSeq: 0, mixed: false } })),
  { floorChunk: 0, remove: [] });
check('the walk stops at the first segment kept: what has gone is a prefix',
  plan(facts({}, { 1: { maxSeq: 5000 } })), { floorChunk: 0, remove: [] });

console.log('\n--- names ---\n');
check('a segment\'s directory is seg- and six digits', segmentName(12), 'seg-000012');
for (const bad of [0, -1, 1.5, 1_000_000, Number.NaN]) {
  let threw = false;
  try { segmentName(bad); } catch { threw = true; }
  check(`segment ${bad} has no name`, threw, true);
}
check('only seg- and six digits read as a segment',
  ['seg-000001', 'seg-000000', 'seg-1', 'seg-0000001', 'seg-000001.txt', 'SEG-000001', 'notes', '..']
    .map(segmentNumberOf),
  [1, null, null, null, null, null, null, null]);

console.log('\n--- the volume ---\n');
const root = mkdtempSync(join(tmpdir(), 'inwire-segment-guard-'));
try {
  const volume = captureVolume(root);
  const id = 'cap-20260928-120000-guard';
  const opened = volume.open(id);
  const segments = opened.segments!;
  segments.open(1).byt.write(0, new Uint8Array([1]));
  segments.open(2).byt.write(0, new Uint8Array([2]));
  // Things a person could leave in a capture's folder, that look close.
  const dir = join(root, id);
  mkdirSync(join(dir, 'seg-1'));
  mkdirSync(join(dir, 'pcapng'));
  writeFileSync(join(dir, 'seg-000003.txt'), 'not a segment');
  check('the volume lists its segments and nothing that only resembles one', segments.list(), [1, 2]);
  segments.remove(1);
  check('removing a segment removes exactly that directory',
    readdirSync(dir).sort(),
    ['frames.iwbyt', 'index.iwidx', 'pcapng', 'prefix.iwpfx', 'records.iwrec', 'seg-000002',
      'seg-000003.txt', 'seg-1', 'streams.iwdig', 'summary.iwsum']);
  check('a removed segment is not found again', segments.find(1), null);
  let refused = false;
  try { segments.remove(0); } catch { refused = true; }
  check('segment 0 - the capture\'s own files - cannot be removed as a segment', refused, true);
  opened.close();
} finally {
  rmSync(root, { recursive: true, force: true });
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All segment guard checks passed.');
process.exit(0);
