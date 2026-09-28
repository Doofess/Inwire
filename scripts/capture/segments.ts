/**
 * The capture on disk follows the agent's ring (ADR 0052).
 *
 *   npx tsx scripts/capture/segments.ts
 *
 * A capture whose agent writes a ring of pcapng files keeps its data in a
 * segment per ring file, and when the agent deletes a file the segment goes
 * with it: the list starts later, a filter scans what is left, an export
 * writes what is left, and a reopened capture is the same capture. This drives
 * that whole path through the real `CaptureHost` over the real `inwire`
 * capture's frames, filed into ring files the way the pipeline Worker files
 * them - by the agent's `capture_boundary` messages, through `RingFiling`.
 *
 * The ring here is the agent's arithmetic, not a guess at it: a file every
 * `FILE_FRAMES` frames, the boundary sent before the file's first frame, and
 * the oldest file deleted as the file `KEEP` after it opens - which is when the
 * agent's writer deletes one. Skips cleanly without the fixture.
 */
import { serialize, deserialize } from 'node:v8';
import { CaptureHost } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { MatchSet } from '../../src/services/capture/matchSet';
import { plainForStore } from '../../src/services/capture/storePacket';
import { segmentName } from '../../src/services/capture/segments';
import { RingFiling } from '../../src/services/pipeline/ringFiling';
import { compile } from '../../src/services/filter/compile';
import { exportFrames, exportTotal, linkTypeTable, type CaptureRowReader } from '../../src/services/export/exportFrames';
import { loadRealCaptures } from '../export/realCaptures';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
import type { RawFrame } from '../../src/services/capture/captureWriter';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 300));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 300));
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/** A copy, by the serialiser a `postMessage` across processes uses. */
const crossed = <T>(value: T): T => deserialize(serialize(value)) as T;

const FILE_FRAMES = 1_000;
const KEEP = 3;
const BATCH = 300;

function sameBytes(a: Uint8Array | undefined, b: Uint8Array): boolean {
  if (a === undefined || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** A host over memory, a way to ask it things, and what it said unasked. */
function harness(volume = new MemoryVolume()) {
  const waiting = new Map<number, (message: FromCapture) => void>();
  const floors: Extract<FromCapture, { type: 'floor' }>[] = [];
  const failuresSaid: string[] = [];
  let ready: Extract<FromCapture, { type: 'ready' }> | null = null;
  let stats: Extract<FromCapture, { type: 'stats' }> | null = null;
  const host = new CaptureHost(volume, (message) => {
    const copy = crossed(message);
    if (copy.type === 'failure') failuresSaid.push(copy.message);
    if (copy.type === 'floor') floors.push(copy);
    if (copy.type === 'ready') ready = copy;
    if (copy.type === 'stats') stats = copy;
    const id = (copy as { requestId?: number }).requestId;
    if (id === undefined || copy.type === 'scanProgress') return;
    const settle = waiting.get(id);
    waiting.delete(id);
    settle?.(copy);
  }, { scanSliceMs: 0 });
  let nextRequest = 1;
  const ask = (build: (requestId: number) => ToCapture) => new Promise<FromCapture>((resolve) => {
    const requestId = nextRequest++;
    waiting.set(requestId, resolve);
    host.receive(build(requestId));
  });
  const reader: CaptureRowReader = {
    async readRowsAt(from, to) {
      const answer = await ask((requestId) => ({ type: 'rowsAt', requestId, from, to }));
      return answer.type === 'blocks' ? answer.blocks : [];
    },
    async readBytes(ids) {
      const answer = await ask((requestId) => ({ type: 'read', requestId, ids: [...ids] }));
      return new Map(answer.type === 'bytes' ? answer.frames : []);
    },
    async ordinalOf(id) {
      const answer = await ask((requestId) => ({ type: 'locate', requestId, id }));
      return answer.type === 'located' ? answer.ordinal : -1;
    },
    captureFloor: () => floors[floors.length - 1]?.floorOrdinal ?? ready?.floorOrdinal ?? 0,
  };
  return {
    host, volume, floors, failuresSaid, reader,
    ready: () => ready,
    lastStats: () => stats,
    send: (message: ToCapture) => host.receive(crossed(message)),
    async scan(filter: string): Promise<MatchSet | null> {
      const answer = await ask((requestId) => ({ type: 'scan', requestId, filter }));
      if (answer.type !== 'scanDone' || answer.bits === null) return null;
      return MatchSet.fromBytes(answer.frameCount, answer.bits);
    },
    async stats() {
      host.receive({ type: 'stats' });
      await host.drain();
    },
  };
}

/**
 * Feeds `packets` the way a live capture does: the agent's boundaries and
 * deletions to `RingFiling` and on to the store, each frame's bytes filed by
 * its sequence number, then its row. `withhold` names boundaries the pipe
 * shed. Returns the filing, and the files deleted.
 */
function feedRing(
  store: ReturnType<typeof harness>, packets: readonly Packet[], withhold: ReadonlySet<number> = new Set(),
): { filing: RingFiling; deleted: number[] } {
  const filing = new RingFiling();
  const deleted: number[] = [];
  for (let at = 0; at < packets.length; at += BATCH) {
    const batch = packets.slice(at, at + BATCH);
    const frames: RawFrame[] = [];
    for (let i = 0; i < batch.length; i++) {
      const seq = at + i;
      if (seq % FILE_FRAMES === 0) {
        const file = seq / FILE_FRAMES + 1;
        // The agent's writer deletes the oldest file as a file past `KEEP`
        // opens; the Worker passes the report on with its epoch.
        if (file > KEEP) {
          const gone = file - KEEP;
          deleted.push(gone);
          store.send({ type: 'ringDeleted', epoch: filing.epoch || 1, lastSeq: gone * FILE_FRAMES - 1 });
        }
        if (!withhold.has(file)) filing.boundary(file, seq);
      }
      const p = batch[i];
      const part = filing.partOf(seq);
      frames.push(part === undefined
        ? { id: p.id, tsUs: p.tsUs, bytes: p.rawBytes }
        : { id: p.id, tsUs: p.tsUs, bytes: p.rawBytes, ring: part });
    }
    store.send({ type: 'appendBytes', frames });
    store.send({ type: 'append', packets: batch.map(plainForStore) });
  }
  return { filing, deleted };
}

async function main(): Promise<void> {
  const captures = await loadRealCaptures();
  const inwire = captures.find((c) => c.name === 'inwire');
  if (inwire === undefined) {
    console.log('SKIP  the inwire fixture is not present (test/fixtures/README.md)');
    process.exit(0);
  }
  const packets = inwire.packets;
  const files = Math.ceil(packets.length / FILE_FRAMES);
  const kept = [files - KEEP + 1, files - KEEP + 2, files];
  const floorOrdinal = (files - KEEP) * FILE_FRAMES;
  const floorId = packets[floorOrdinal].id;
  console.log(`${packets.length} frames of ${inwire.name}, ${files} ring files of ${FILE_FRAMES}, keeping ${KEEP}\n`);

  console.log('--- the ring, live ---\n');
  const id = 'cap-20260928-120000-ring';
  const store = harness();
  store.send({ type: 'open', captureId: id });
  feedRing(store, packets);
  await store.host.drain();
  const live = store.floors.map((f) => f.floorOrdinal);
  checkTrue('the capture follows the ring while it runs, a file at a time',
    live.length > 0 && live.every((f, i) => f % FILE_FRAMES === 0 && (i === 0 || f > live[i - 1])));
  store.send({ type: 'finish' });
  await store.host.drain();

  check('each ring file had a segment of its own, and the deleted ones are gone',
    store.volume.segmentsOf(id), kept);
  const floor = store.floors[store.floors.length - 1];
  check('the app is told where the capture now starts',
    floor === undefined ? null : [floor.floorOrdinal, floor.floorId],
    [floorOrdinal, floorId]);
  await store.stats();
  check('...and what it can still supply', store.lastStats()?.storedRange ?? null,
    { first: floorId, last: packets[packets.length - 1].id });
  check('...and says how much the ring took',
    [store.lastStats()?.stats.segmentsEvicted, store.lastStats()?.stats.framesEvicted],
    [files - KEEP, floorOrdinal]);

  const below = await store.reader.readRowsAt(0, 10);
  check('a position below the floor reads as a hole', below.length, 0);
  const above = await store.reader.readRowsAt(floorOrdinal, floorOrdinal + 1);
  check('the floor is the first frame of the oldest kept file',
    above[0]?.firstOrdinal === floorOrdinal ? above[0].packets[0].id : null, floorId);
  const bytes = await store.reader.readBytes([packets[0].id, floorId, packets[packets.length - 1].id]);
  check('bytes of a frame the ring took are absent', bytes.has(packets[0].id), false);
  checkTrue('...and of the frames it kept are the capture\'s own',
    sameBytes(bytes.get(floorId), packets[floorOrdinal].rawBytes)
    && sameBytes(bytes.get(packets[packets.length - 1].id), packets[packets.length - 1].rawBytes));
  check('a frame the ring took cannot be located', await store.reader.ordinalOf(packets[5].id), -1);
  check('...and the first one kept is at the floor', await store.reader.ordinalOf(floorId), floorOrdinal);

  const expression = 'tcp';
  const matches = await store.scan(expression);
  const predicate = compile(expression);
  const expected: number[] = [];
  packets.forEach((p, ordinal) => { if (ordinal >= floorOrdinal && predicate(p)) expected.push(ordinal); });
  const found: number[] = [];
  if (matches !== null) for (let r = 0; r < matches.count(); r++) found.push(matches.ordinalAt(r));
  check('a filter scans what is left, and answers as the in-memory filter does', found, expected);

  // The export reads the disk from the floor. A one-frame window - the newest
  // frame, as a live capture's window ends - puts every other frame on the
  // disk half the floor governs.
  const scope = { window: [packets[packets.length - 1]], filter: null };
  const exported: Packet[] = [];
  const total = await exportTotal(scope, store.reader);
  let unreadable = -1;
  for await (const page of exportFrames(scope, store.reader, {
    hydrateBytes: true, linkTypes: linkTypeTable([], scope.window),
  })) {
    exported.push(...page.packets);
    unreadable = page.unreadable;
  }
  check('an export counts what is left', total, packets.length - floorOrdinal);
  check('...writes exactly that, from the first frame kept',
    [exported.length, exported[0]?.id, unreadable], [packets.length - floorOrdinal, floorId, 0]);
  checkTrue('...with the frames\' own bytes',
    exported.every((p, i) => sameBytes(p.rawBytes, packets[floorOrdinal + i].rawBytes)));

  await store.stats();
  check('no failures were reported', store.failuresSaid, []);

  console.log('\n--- reopened ---\n');
  // A crash between writing the floor and deleting the segment behind it
  // leaves the segment on disk; recovery deletes it.
  const volume = store.volume;
  store.host.close();
  const opened = volume.open(id);
  opened.segments!.open(1).byt.write(0, new Uint8Array([1, 2, 3]));
  opened.close();
  check('(a segment below the floor was left behind)', volume.segmentsOf(id).includes(1), true);
  const again = harness(volume);
  again.send({ type: 'open', captureId: id, requestId: 1 });
  await again.host.drain();
  const ready = again.ready();
  check('a reopened capture knows its floor',
    ready === null ? null : [ready.floorOrdinal, ready.floorId, ready.frameCount],
    [floorOrdinal, floorId, packets.length]);
  check('...and recovery deleted what was left below it', volume.segmentsOf(id), kept);
  check('...and its rows are the same rows',
    (await again.reader.readRowsAt(floorOrdinal, floorOrdinal + 1))[0]?.packets[0]?.id ?? null, floorId);
  check('...and numbering resumes past every id it ever used, taken or not',
    ready?.lastId, packets[packets.length - 1].id);
  again.host.close();

  console.log('\n--- a boundary the pipe shed ---\n');
  // File 3's boundary never arrives: its frames are filed under file 2. When
  // file 2 is deleted, the segment holding both must wait - deleting it would
  // take frames the agent still has in file 3.
  const shed = harness();
  const shedId = 'cap-20260928-120000-shed';
  shed.send({ type: 'open', captureId: shedId });
  const shedPackets = packets.slice(0, FILE_FRAMES * 5);
  feedRing(shed, shedPackets, new Set([3]));
  shed.send({ type: 'finish' });
  await shed.host.drain();
  // Files 1 and 2 are deleted (5 files, keeping 3); segment 2 holds files 2
  // and 3, so only file 1's segment can go.
  check('the segment holding a shed file\'s frames waits for that file',
    shed.volume.segmentsOf(shedId), [2, 3, 4]);
  const file3 = shedPackets[FILE_FRAMES * 2 + 10];
  check('...so a frame the agent still holds is still here',
    (await shed.reader.readBytes([file3.id])).has(file3.id), true);
  shed.send({ type: 'ringDeleted', epoch: 1, lastSeq: FILE_FRAMES * 3 - 1 });
  await shed.host.drain();
  check('...and it goes when that file does', shed.volume.segmentsOf(shedId), [3, 4]);
  shed.host.close();

  console.log('\n--- an agent with no ring ---\n');
  const plain = harness();
  const plainId = 'cap-20260928-120000-none';
  plain.send({ type: 'open', captureId: plainId });
  for (let at = 0; at < packets.length; at += BATCH) {
    const batch = packets.slice(at, at + BATCH);
    plain.send({ type: 'appendBytes', frames: batch.map((p) => ({ id: p.id, tsUs: p.tsUs, bytes: p.rawBytes })) });
    plain.send({ type: 'append', packets: batch.map(plainForStore) });
  }
  plain.send({ type: 'ringDeleted', epoch: 1, lastSeq: packets.length });
  plain.send({ type: 'finish' });
  await plain.host.drain();
  check('frames no ring filed stay in the capture\'s own files, and nothing goes',
    [plain.volume.segmentsOf(plainId), plain.floors.length], [[], 0]);
  plain.host.close();

  console.log('\n--- ring filing ---\n');
  const filing = new RingFiling();
  filing.boundary(1, 0);
  filing.boundary(2, 100);
  check('a frame is filed by its sequence number, whichever order it arrives in',
    [filing.partOf(150), filing.partOf(99), filing.partOf(0)],
    [{ epoch: 1, file: 2, seq: 150 }, { epoch: 1, file: 1, seq: 99 }, { epoch: 1, file: 1, seq: 0 }]);
  filing.boundary(1, 0);
  check('file 1 again is a new run of the agent\'s capture', filing.partOf(150), { epoch: 2, file: 1, seq: 150 });
  check('segment names are six digits', segmentName(7), 'seg-000007');

  console.log();
  if (failures > 0) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All segment checks passed.');
  process.exit(0);
}

void main();
