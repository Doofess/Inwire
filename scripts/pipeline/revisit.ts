/**
 * The gate for rebuilding a frame's tree from its own record (ADR 0049).
 *
 *   npx tsx scripts/pipeline/revisit.ts
 *
 * Every frame of every real fixture is dissected twice. First as it arrives,
 * in order, with the real trackers behind a `FrameRecorder` - which is exactly
 * what the app does, plus a record of what the trackers said. Then each frame
 * alone, from its bytes and its record, with a `FrameRevisit` in the trackers'
 * place. The two trees must render identically, for every frame.
 *
 * There are exactly two acceptable outcomes per frame, and the whole point of
 * the gate is that there is no third:
 *
 * - **equal** - the revisit gave back the tree arrival built;
 * - **miss** - the revisit could not, and said so with `RecordMiss`. The app
 *   then builds that tree another way.
 *
 * A revisit that finishes with a DIFFERENT tree is a confident wrong answer
 * about a frame somebody is looking at, and is the one thing that fails this
 * script. Misses are counted by reason and printed.
 *
 * Also printed, not asserted: what the records cost - bytes per frame raw and
 * deflated in the store's own 4,096-frame chunks at its own level - and which
 * answers the bytes go to.
 *
 * Real captures only (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync } from 'node:fs';
import { deflateSync } from 'fflate';
import { RecordMiss, recordComposition, recordRefs } from '../../src/services/dissect/frameRecord';
import { FIXTURES, arrive, firstDifference, render, revisit } from './arrival';

/** The store's chunk size and deflate level (chunkCodec.ts, captureWriter.ts). */
const CHUNK_FRAMES = 4096;
const STORE_LEVEL = 6;

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)?.slice(0, 400)}`);
    console.log(`        actual   ${JSON.stringify(actual)?.slice(0, 400)}`);
  }
}

function percentile(sorted: number[], p: number): number {
  return sorted.length === 0 ? 0 : sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))];
}

async function runFixture(name: string, path: string) {
  const { arrived, patchesFor, host, ms: arrivalMs } = await arrive(path);

  // --- revisit: every frame alone ---------------------------------------------
  let equal = 0;
  let wrong = 0;
  const misses = new Map<string, number>();
  const wrongExamples: string[] = [];
  const t1 = performance.now();
  for (const { packet, record, input } of arrived) {
    try {
      // Other frames' bytes, as the store hands them over: by id, and only for
      // the frames the record names.
      const named = new Set(recordRefs(record));
      const layers = revisit(input, packet.id, record, host, patchesFor.get(packet.id) ?? [],
        (frame) => (named.has(frame) ? arrived[frame - 1]?.input.bytes : undefined));
      const want = render(packet.layers);
      const got = render(layers);
      if (want === got) {
        equal += 1;
      } else {
        wrong += 1;
        if (wrongExamples.length < 5) wrongExamples.push(`frame ${packet.id}: ${firstDifference(want, got)}`);
      }
    } catch (error) {
      if (!(error instanceof RecordMiss)) throw error;
      misses.set(error.reason, (misses.get(error.reason) ?? 0) + 1);
    }
  }
  const revisitMs = performance.now() - t1;

  // --- what the records cost ----------------------------------------------------
  const sizes = arrived.map((a) => a.record.length).sort((a, b) => a - b);
  const raw = sizes.reduce((s, n) => s + n, 0);
  let deflated = 0;
  for (let i = 0; i < arrived.length; i += CHUNK_FRAMES) {
    const chunk = arrived.slice(i, i + CHUNK_FRAMES);
    const joined = new Uint8Array(chunk.reduce((s, a) => s + a.record.length, 0));
    let at = 0;
    for (const a of chunk) { joined.set(a.record, at); at += a.record.length; }
    deflated += deflateSync(joined, { level: STORE_LEVEL }).length;
  }
  const missed = [...misses.values()].reduce((s, n) => s + n, 0);
  const byQuestion = new Map<string, number>();
  for (const a of arrived) {
    for (const [question, bytes] of recordComposition(a.record)) {
      byQuestion.set(question, (byQuestion.get(question) ?? 0) + bytes);
    }
  }

  console.log(`\n--- ${name}: ${arrived.length.toLocaleString()} frames ---`);
  console.log(`      equal ${equal.toLocaleString()}, missed ${missed.toLocaleString()}, wrong ${wrong}`);
  for (const [reason, count] of [...misses].sort((a, b) => b[1] - a[1])) {
    console.log(`        miss ${count.toString().padStart(6)}  ${reason}`);
  }
  console.log(`      record: mean ${(raw / arrived.length).toFixed(1)} B, p99 ${percentile(sizes, 0.99)} B, `
    + `max ${sizes[sizes.length - 1]} B raw; ${(deflated / arrived.length).toFixed(1)} B/frame deflated`);
  const heaviest = [...byQuestion].sort((a, b) => b[1] - a[1]).slice(0, 6);
  console.log(`      raw bytes by question: ${heaviest
    .map(([q, b]) => `${q} ${((100 * b) / raw).toFixed(0)}%`).join(', ')}`);
  console.log(`      arrival ${arrivalMs.toFixed(0)} ms, revisit of every frame ${revisitMs.toFixed(0)} ms `
    + `(${((revisitMs * 1000) / arrived.length).toFixed(1)} us a frame)`);
  for (const example of wrongExamples) console.log(`        WRONG ${example}`);

  check(`${name}: no frame is revisited into a different tree`, wrong, 0);
  check(`${name}: every frame either matches or says why it cannot`, equal + missed + wrong, arrived.length);
  // Phase 3 of ADR 0049 reached every frame of the real fixtures, none of which
  // carries a key log. A miss here now is a regression, not a gap.
  check(`${name}: every frame is rebuilt from its record`, missed, 0);
}

async function main() {
  let ran = 0;
  for (const { name, path, optional } of FIXTURES) {
    if (!existsSync(path)) {
      console.log(`SKIP  ${name}: ${path} is not present${optional ? ' (optional)' : ''} - see test/fixtures/README.md`);
      continue;
    }
    await runFixture(name, path);
    ran += 1;
  }
  if (ran === 0) console.log('\nAll revisit checks passed (skipped).');
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All revisit checks passed.');
  process.exit(0);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
