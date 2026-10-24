/**
 * Exporting "marked packets only" (ADR 0067): the store answers which stored
 * ordinals the marks name, and the export scope counts them.
 *
 *   npx tsx scripts/export/marked-scope.ts
 *
 * Driven through the real `CaptureHost` over a `MemoryVolume`, the way
 * `scripts/capture/marks-store.ts` is: rows through `plainForStore` and a `v8`
 * round trip, `host.drain()` between sends and answers.
 *
 * Marks `[2, 5, 99]` where 99 is not stored: the ring may have expired a mark's
 * frame, or it may never have been stored, and either way it is left out of the
 * set and out of the count (Review Focus 1).
 */
import { CaptureHost } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { plainForStore } from '../../src/services/capture/storePacket';
import { MatchSet } from '../../src/services/capture/matchSet';
import { exportTotal, type CaptureRowReader } from '../../src/services/export/exportFrames';
import { markedExportCount } from '../../src/lib/captureRowSpace';
import { serialize, deserialize } from 'node:v8';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 400));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 400));
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function row(id: number): Packet {
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
    source: '10.0.0.2', destination: '10.0.0.3', sourcePort: 50000, destPort: 443,
    protocol: 'TCP', frameProtocols: ['eth', 'ethertype', 'ip', 'tcp'], fields: {},
    length: 60, info: '', status: 'ok', interfaceName: 'eth0', layers: [],
    rawBytes: new Uint8Array([id & 0xff, 0, 0, 0]),
  } as Packet;
}
const rows = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => row(from + i));
const crossed = (packets: readonly Packet[]): Packet[] =>
  deserialize(serialize(packets.map((p) => plainForStore(p)))) as Packet[];

const said: FromCapture[] = [];
const store = new CaptureHost(new MemoryVolume(), (message) => said.push(message), {});
const send = (message: ToCapture) => store.receive(message);
const of = <T extends FromCapture['type']>(type: T) =>
  said.filter((m) => m.type === type) as Extract<FromCapture, { type: T }>[];

async function answer<T extends FromCapture['type']>(type: T, requestId: number): Promise<Extract<FromCapture, { type: T }>> {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const found = of(type).find((m) => (m as { requestId: number }).requestId === requestId);
    if (found !== undefined) return found;
    await sleep(1);
  }
  throw new Error(`no ${type} answered request ${requestId}`);
}

let next = 100;
/** The window's first frame is placed by `locate`; that is all `exportTotal` asks of a reader here. */
const reader: CaptureRowReader = {
  async ordinalOf(id) {
    const requestId = next++;
    send({ type: 'locate', requestId, id });
    return (await answer('located', requestId)).ordinal;
  },
  async readRowsAt() { return []; },
  async readBytes() { return new Map(); },
};

const ID = 'cap-20261024-120000-mks1';
send({ type: 'open', captureId: ID });
send({ type: 'append', packets: crossed(rows(1, 10)) });
send({ type: 'finish' });
send({ type: 'marks', captureId: ID, ids: [2, 5, 99] });
await store.drain();

console.log('--- 1. markMatches answers the stored marks only ---\n');

send({ type: 'markMatches', requestId: 1 });
const marked = await answer('markMatches', 1);
check('1. count leaves the unstored id out', marked.count, 2);
const set = MatchSet.fromBytes(marked.frameCount, marked.bits);
const ordinals: number[] = [];
for (let k = 0; k < set.count(); k++) ordinals.push(set.ordinalAt(k));
check('...and the set is the ordinals of ids 2 and 5', ordinals, [1, 4]);
check('...over the whole stored capture', marked.frameCount, 10);

console.log('\n--- 2. exportTotal counts the marked frames ---\n');

{
  // The whole capture is the window: disk matches are not counted below it.
  const whole = await exportTotal({ window: rows(1, 10), filter: null, marked: { ids: new Set([2, 5, 99]), matches: set } }, reader);
  check('2. a window holding everything counts 2', whole, 2);
  // Ids 1-5 are only on disk; the window starts at 6. Disk answers 2 and 5.
  const split = await exportTotal({ window: rows(6, 10), filter: null, marked: { ids: new Set([2, 5, 99]), matches: set } }, reader);
  check('...a window that starts at 6 counts the same 2 from disk', split, 2);
  // A mark in the window is counted from memory.
  const inWindow = await exportTotal({ window: rows(6, 10), filter: null, marked: { ids: new Set([2, 5, 8]), matches: set } }, reader);
  check('...and a mark inside the window adds one', inWindow, 3);
}

console.log('\n--- 3. markMatches leaves a running scan alone ---\n');

{
  // A 0 ms slice makes the scan yield after every chunk, and five chunks keep
  // it running when the next message is handled. A scan that finished in its
  // first slice would prove nothing about being left alone.
  const slow = new CaptureHost(new MemoryVolume(), (message) => said.push(message), { scanSliceMs: 0 });
  slow.receive({ type: 'open', captureId: 'cap-20261024-120000-mks2' });
  slow.receive({ type: 'append', packets: crossed(rows(1, 20_000)) });
  slow.receive({ type: 'finish' });
  slow.receive({ type: 'marks', captureId: 'cap-20261024-120000-mks2', ids: [7] });
  await slow.drain();
  slow.receive({ type: 'scan', requestId: 50, filter: 'tcp' });
  const stillRunning = of('scanDone').every((m) => m.requestId !== 50);
  slow.receive({ type: 'markMatches', requestId: 51 });
  await answer('markMatches', 51);
  const done = await answer('scanDone', 50);
  check('3. the scan was still running when markMatches was asked', stillRunning, true);
  check('...and completed, not cancelled', { cancelled: done.cancelled, hasBits: done.bits !== null, message: done.message },
    { cancelled: false, hasBits: true, message: null });
  check('...and exactly one scanDone for it', of('scanDone').filter((m) => m.requestId === 50).length, 1);
  slow.close();
}

console.log('\n--- 4. a frame.marked filter reads the marks in the window too ---\n');

{
  // The store's scan answers `frame.marked` over disk from its own set; the
  // window half filters in the renderer and has to be handed the same set, or
  // "Export filtered" with `frame.marked == 1` drops every marked frame still
  // in memory.
  const filtered = await exportTotal({
    window: rows(1, 10), filter: { expression: 'frame.marked == 1', matches: null }, marks: new Set([2, 5]),
  }, reader);
  check('4. frame.marked == 1 over a window holding everything counts 2', filtered, 2);
  const changed = await exportTotal({
    window: rows(1, 10), filter: { expression: 'frame.marked == 1', matches: null }, marks: new Set([3]),
  }, reader);
  check('...and a new set over the same window is not answered from the old one', changed, 1);
}

console.log('\n--- 5. the Export panel offers the count the export writes ---\n');

{
  // A live capture: the store holds 1-10, the window 6-14, and 11-14 are still
  // staged - marked there, but no answer from the store can name them. The
  // panel used to show the store's 2 and call a marked frame "not kept".
  const ids = new Set([2, 5, 12, 99]);
  const window = rows(6, 14);
  const written = await exportTotal({ window, filter: null, marked: { ids, matches: set } }, reader);
  check('5. the export writes 2 from disk and 12 from the window', written, 3);
  check('...and the panel offers the same', markedExportCount(set, 5, 0, window, ids), 3);
  // A window with a gap in its ids still counts by membership, not by range.
  const gapped = [...rows(6, 8), ...rows(12, 14)];
  check('...a window with a gap in its ids', markedExportCount(set, 5, 0, gapped, new Set([7, 10, 13])), 2 + 2);
  // A ring that expired ordinal 1 (id 2) leaves only id 5 on disk.
  check('...and a ring floor drops the expired mark', markedExportCount(set, 5, 2, window, ids), 2);
}

store.close();

console.log(failures === 0 ? '\nAll marked-scope checks passed.' : `\n${failures} marked-scope check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
