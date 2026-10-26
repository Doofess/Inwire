/**
 * Every message the capture store answers, driven through the real host.
 *
 *   npx tsx scripts/capture/store-protocol.ts
 *
 * ## What it proves, and what it cannot
 *
 * `CaptureHost` is the routing, and its header names what it decides: when a
 * capture is closed, what an append with nothing open does, whether a failed
 * read still answers, which directories a prune may touch. Every one of those
 * has a silent failure behind it, and none of them is reachable from the
 * modules below - `captureWriter.ts` and `captureReader.ts` are tested against
 * a `MemoryBlockFile` and never see a message at all.
 *
 * This drives the message union against a `CaptureVolume` over memory. It
 * proves **the protocol**, not Electron's IPC: there is no `MessagePort` here
 * and no second process. What crosses a real port is proved by the app
 * running - `scripts/electron/smoke.ts`.
 *
 * ## The rule with a hanging UI behind it
 *
 * *Every request-shaped message answers, even when it fails.* The caller holds
 * a promise per request; a silent drop leaves the hex viewer spinning for the
 * life of the window. So the first section below is not about correct answers
 * at all - it asks each request in a state where it must fail, and asserts an
 * answer came back anyway.
 *
 * ## The scan is the reason this exists now
 *
 * A scan is the first message that is not one request and one reply: it runs
 * for seconds, in slices, reporting as it goes, and it can be cancelled or
 * overtaken or have its capture closed underneath it. Four of the assertions
 * below are about the state machine that makes that safe, and the one that
 * matters most is that a **read is answered while a scan is still running** -
 * which is the entire reason `step()` is sliced rather than a loop.
 */
import { CaptureHost } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { MatchSet } from '../../src/services/capture/matchSet';
import { CHUNK_FRAMES } from '../../src/services/capture/chunkCodec';
import { compile } from '../../src/services/filter/compile';
import { plainForStore } from '../../src/services/capture/storePacket';
import { FieldBlock } from '../../src/services/dissect/fieldBlock';
import { DENSE_FIELDS } from '../../src/services/dissect/denseFields';
import { PackSender, PackedFlush, packRows, type PackedRows, type RowPack } from '../../src/services/pipeline/rowPack';
import { CaptureIndex } from '../../src/services/capture/captureIndex';
import { readExact } from '../../src/services/capture/blockFile';
import { decodeDigest } from '../../src/services/conversation/digestCodec';
import type { RowOverlay } from '../../src/services/pipeline/rowOverlay';
import { inflateSync } from 'fflate';
import { serialize, deserialize } from 'node:v8';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
import type { Packet } from '../../src/types/packet';
import { packFrames } from '../../src/services/capture/frameSlab';

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

/** A host with everything it said recorded, in order. */
function host(options: { scanSliceMs?: number } = {}) {
  const volume = new MemoryVolume();
  const said: FromCapture[] = [];
  const store = new CaptureHost(volume, (message) => said.push(message), options);
  return {
    volume, said, store,
    send: (message: ToCapture) => store.receive(message),
    /** Everything of one type said so far. */
    of<T extends FromCapture['type']>(type: T): Extract<FromCapture, { type: T }>[] {
      return said.filter((m) => m.type === type) as Extract<FromCapture, { type: T }>[];
    },
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Waits for the `scanDone` carrying `requestId`, or gives up.
 *
 * By id rather than by count, and that is not fussiness: a scan that
 * supersedes another produces the cancellation FIRST, so "wait for one more
 * scanDone" returns while the scan being waited for is still running.
 */
async function untilScanDone(
  said: FromCapture[], requestId: number, ms = 20_000,
): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (said.some((m) => m.type === 'scanDone' && m.requestId === requestId)) return true;
    await sleep(1);
  }
  return false;
}

function frame(id: number, over: Partial<Packet> = {}): Packet {
  return {
    id,
    source: '10.0.0.4',
    destination: '93.184.216.34',
    protocol: 'TCP',
    info: `frame ${id}`,
    status: 'ok',
    length: 100 + (id % 900),
    tsUs: 1_788_000_000_000_000 + id * 1000,
    relativeTime: id / 1000,
    timeDelta: 0.001,
    interfaceName: 'eth0',
    layers: [],
    rawBytes: new Uint8Array([id & 0xff, (id >> 8) & 0xff, 0, 0, 0, 0, 0, 0]),
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    sourcePort: 50000 + (id % 3),
    destPort: 443,
    fields: { 'tcp.seq': id },
    ...over,
  } as Packet;
}

/** A third of them UDP/DNS, so a filter has something to divide. */
function traffic(count: number): Packet[] {
  const out: Packet[] = [];
  for (let i = 1; i <= count; i++) {
    out.push(i % 3 === 0
      ? frame(i, {
          protocol: 'UDP', destPort: 53,
          frameProtocols: ['frame', 'eth', 'ip', 'udp', 'dns'],
        })
      : frame(i));
  }
  return out;
}

/**
 * Frames as the store actually receives them: through a structured clone.
 *
 * Not a detail. Every test here used to hand `CaptureHost` the very objects it
 * built, in one JavaScript context, and that is not the shape of the real
 * thing - the store is a `utilityProcess` and every frame arrives cloned. A
 * clone carries Maps and typed arrays and **drops prototypes**, so a `Packet`
 * carrying a `FieldBlock` in `cols` arrives as data with no `read` on it.
 *
 * That shipped. `encodeChunk` threw `block.read is not a function` on every
 * chunk, the throw was caught and reported as a non-fatal failure, and the
 * store wrote raw bytes and no rows at all - for the life of every capture,
 * with `ordinalOf` answering -1 and the app reading that as "the window is the
 * whole capture". Nothing here could see it, because nothing here cloned.
 *
 * `v8.serialize`/`deserialize` rather than `structuredClone`: it is the same
 * serialiser a `postMessage` across a process boundary uses, and it is
 * unambiguously a copy.
 */
function crossed(packets: readonly Packet[]): Packet[] {
  return deserialize(serialize(packets)) as Packet[];
}

/** Appends and seals, so the frames are in chunks rather than staged. */
async function fill(h: ReturnType<typeof host>, captureId: string, packets: Packet[]) {
  h.send({ type: 'open', captureId });
  for (let i = 0; i < packets.length; i += 1000) {
    h.send({ type: 'append', packets: crossed(packets.slice(i, i + 1000)) });
  }
  h.send({ type: 'finish' });
  await h.store.drain();
}

/** Every ordinal a `MatchSet` holds. Compared as a list, never as a count. */
function ordinals(set: MatchSet): number[] {
  const out: number[] = [];
  for (let k = 0; k < set.count(); k++) out.push(set.ordinalAt(k));
  return out;
}

console.log('--- every request answers, especially when it fails ---\n');

{
  // Nothing open. Each of these has no answer to give and must give one.
  const h = host();
  h.send({ type: 'read', requestId: 1, ids: [1, 2] });
  h.send({ type: 'chunk', requestId: 2, chunk: 0 });
  h.send({ type: 'rowsAt', requestId: 3, from: 0, to: 10 });
  h.send({ type: 'locate', requestId: 4, id: 1 });
  h.send({ type: 'scan', requestId: 5, filter: 'tcp' });
  h.send({ type: 'rowsForOrdinals', requestId: 6, ordinals: [0, 5] });
  h.send({ type: 'flowOrdinals', requestId: 7, kind: 'udp', key: 1, fromId: 1, toId: 2, startChunk: 0 });
  await h.store.drain();
  check('a flowOrdinals answers empty, with no next page', h.of('flowOrdinals'), [
    { type: 'flowOrdinals', requestId: 7, ordinals: [], nextChunk: null, searched: 1 },
  ]);

  check('a read with no capture open answers empty', h.of('bytes'), [
    { type: 'bytes', requestId: 1, frames: [] },
  ]);
  check('a chunk read answers empty', h.of('rows'), [
    { type: 'rows', requestId: 2, packets: [] },
  ]);
  check('a rowsAt answers empty', h.of('blocks'), [
    { type: 'blocks', requestId: 3, blocks: [] },
  ]);
  check('a locate answers -1', h.of('located'), [
    { type: 'located', requestId: 4, ordinal: -1 },
  ]);
  check('a scattered row read answers empty', h.of('rowsByOrdinal'), [
    { type: 'rowsByOrdinal', requestId: 6, rows: [] },
  ]);
  const done = h.of('scanDone');
  check('a scan answers, and says why', done.length === 1 && done[0].message, 'no capture is open');
  check('...with no bitmap', done[0]?.bits, null);
}

{
  // An append before an open. Silent once, and it cost 500 frames.
  const h = host();
  h.send({ type: 'append', packets: traffic(10) });
  h.send({ type: 'append', packets: traffic(10) });
  await h.store.drain();
  const failed = h.of('failure');
  check('an orphaned append is reported', failed.length, 1);
  checkTrue('...and only once, however many arrive',
    failed[0]?.message.includes('before a capture was opened') === true);
}

console.log('\n--- open, write, read back ---\n');

const packets = traffic(CHUNK_FRAMES * 3 + 700);

{
  const h = host();
  await fill(h, 'cap-20260912-120000-aaaa', packets);

  const ready = h.of('ready');
  check('open answers ready once', ready.length, 1);
  // A fresh open describes what was ALREADY there, which for a new capture is
  // nothing - the appends come after it. The reopen below is where the count
  // has to be right, and it is the one a restore depends on.
  check('...and a new capture holds nothing yet', ready[0]?.frameCount, 0);
  check('...so numbering starts from zero', ready[0]?.lastId, 0);

  h.send({ type: 'locate', requestId: 10, id: packets[5000].id });
  h.send({ type: 'read', requestId: 11, ids: [packets[7].id] });
  h.send({ type: 'rowsAt', requestId: 12, from: 5000, to: 5040 });
  await h.store.drain();

  check('locate answers the position, not the id', h.of('located')[0]?.ordinal, 5000);
  check('a read answers the frame asked for',
    h.of('bytes')[0]?.frames.map(([id]) => id), [packets[7].id]);
  const blocks = h.of('blocks')[0]?.blocks ?? [];
  checkTrue('rowsAt answers whole chunks around the range', blocks.length >= 1);
  checkTrue('...covering the position asked for',
    blocks.some((b) => 5000 >= b.firstOrdinal && 5000 < b.firstOrdinal + b.packets.length));

  // Scattered positions, which is what a filtered list asks for. Chosen to
  // land in four different chunks and in no order, plus a duplicate and one
  // past the end - because the failure being guarded against is a row paired
  // with the WRONG position, which looks like a working list showing the
  // wrong frames.
  const wanted = [9000, 12, 12, 4096, 8191, 4095, packets.length + 5, packets.length - 1];
  h.send({ type: 'rowsForOrdinals', requestId: 14, ordinals: wanted });
  await h.store.drain();

  const got = new Map(h.of('rowsByOrdinal').find((m) => m.requestId === 14)?.rows ?? []);
  check('every position that exists comes back',
    [...got.keys()].sort((a, b) => a - b),
    [12, 4095, 4096, 8191, 9000, packets.length - 1]);
  check('...paired with the row that is actually there',
    [...got].map(([ordinal, packet]) => packet.id === packets[ordinal].id),
    [true, true, true, true, true, true]);
  checkTrue('a position past the end is absent rather than an error',
    !got.has(packets.length + 5));

  // Reopening finds it. This is the restore, and the same message.
  h.send({ type: 'open', captureId: 'cap-20260912-120000-aaaa', requestId: 13 });
  await h.store.drain();
  const reopened = h.of('ready').find((m) => m.requestId === 13);
  check('a reopen finds every frame that was written', reopened?.frameCount, packets.length);
  check('...and closed the first handle before taking a second', h.volume.outstanding, 1);

  h.store.close();
  check('close releases the handles', h.volume.outstanding, 0);
}

console.log('\n--- a frame carrying its dense columns ---\n');

{
  // The shape the app actually sends, before `plainForStore` folds it flat: a
  // `Packet` whose 33 commonest fields live in a `FieldBlock` the buffer owns
  // (ADRs 0017, 0018). This is the case that shipped broken.
  const block = new FieldBlock(DENSE_FIELDS, 4096);
  const withColumns: Packet[] = [];
  for (let i = 1; i <= 5000; i++) {
    const row = block.claimRow();
    block.write(row, 'ip.src', '10.0.0.4');
    block.write(row, 'tcp.srcport', 50000 + (i % 3));
    const packet = frame(i);
    withColumns.push({ ...packet, cols: block, row, fields: { 'tcp.seq': i } });
  }

  // Unflattened, it does not survive the crossing - and now says why rather
  // than throwing `read is not a function` from three frames down.
  const h = host();
  h.send({ type: 'open', captureId: 'cap-20260912-220000-0005' });
  h.send({ type: 'append', packets: crossed(withColumns) });
  h.send({ type: 'finish' });
  await h.store.drain();
  const complaint = h.of('failure')[0]?.message ?? '';
  checkTrue('a frame that crossed with its field block is refused, loudly',
    complaint.includes('structured clone'));
  checkTrue('...and the message names the fix',
    complaint.includes('storePacket'));
  h.store.close();

  // The route that actually shipped, and the reason `plainForStore` copies
  // even when there is nothing to fold: the app calls it BEFORE the buffer's
  // field writer attaches the block, and `send` posts a microtask later. A
  // pass-through would hand the clone a packet that grew a `FieldBlock` in
  // between.
  const later = frame(99_001);
  const snapshot = plainForStore(later);
  const claimed = block.claimRow();
  Object.assign(later, { cols: block, row: claimed });
  checkTrue('a snapshot taken before the block was attached does not grow one',
    (snapshot as { cols?: unknown }).cols === undefined);
  checkTrue('...and is not the same object', snapshot !== later);

  // Flattened, everything the block held is on disk and readable.
  const g = host();
  await fill(g, 'cap-20260912-220000-0006', withColumns.map(plainForStore));
  g.send({ type: 'chunk', requestId: 900, chunk: 0 });
  g.send({ type: 'locate', requestId: 901, id: 4000 });
  await g.store.drain();

  const rows = g.of('rows').find((m) => m.requestId === 900)?.packets ?? [];
  check('flattened, the rows are stored', rows.length, 4096);
  check('...with the sparse field', rows[10]?.fields?.['tcp.seq'], 11);
  // The point of the whole exercise: a value that lived in a dense column is
  // on disk under its own name. Losing these silently is what "no rows at all"
  // was hiding.
  check('...and the dense ones, under their own names',
    [rows[10]?.fields?.['ip.src'], rows[10]?.fields?.['tcp.srcport']],
    ['10.0.0.4', 50002]);
  check('and the capture is addressable', g.of('located')[0]?.ordinal, 3999);
  g.store.close();
}

console.log('\n--- a live capture, which never calls finish ---\n');

{
  // The case the app is actually in, and the one every test above skips: a
  // capture still running. `fill` seals everything with `finish()`; a live
  // capture seals only what `drainReady` has aged out, so the newest frames
  // are staged and not addressable.
  //
  // This exists because the app answers `below = 0` for a capture of a million
  // frames - `ordinalOf(window[0].id)` keeps returning -1 - and the RAM
  // window's oldest frame ought to be long sealed. Either that is reproducible
  // here, or the cause is somewhere this harness does not reach, and knowing
  // which is worth one section.
  const LIVE = 200_000;
  /** What the buffer holds at the smallest budget, which is where it showed. */
  const WINDOW = 112_000;

  const h = host();
  h.send({ type: 'open', captureId: 'cap-20260912-210000-0004' });
  for (let i = 0; i < LIVE; i += 300) {
    const batch: Packet[] = [];
    for (let j = 0; j < 300 && i + j < LIVE; j++) {
      const id = i + j + 1;
      // 300 µs apart, which is 3,300 frames a second - the rate the app was
      // driven at. The horizon is two seconds OR 100,000 frames.
      batch.push(frame(id, { tsUs: 1_788_000_000_000_000 + id * 300 }));
    }
    h.send({ type: 'append', packets: batch });
  }
  await h.store.drain();

  const oldestInWindow = LIVE - WINDOW + 1;
  h.send({ type: 'locate', requestId: 800, id: oldestInWindow });
  h.send({ type: 'locate', requestId: 801, id: 1 });
  h.send({ type: 'locate', requestId: 802, id: LIVE });
  await h.store.drain();

  const at = (requestId: number) => h.of('located').find((m) => m.requestId === requestId)?.ordinal;
  check('the capture\'s first frame is addressable', at(801), 0);
  check('the window\'s oldest frame is addressable, without a finish',
    at(800), oldestInWindow - 1);
  // The newest frame is inside the staging ring, and -1 there is correct:
  // "not addressable yet" is exactly what it is.
  check('the newest frame is not, and says so', at(802), -1);

  h.store.close();
}

console.log('\n--- prune touches only what this app named ---\n');

{
  const h = host();
  await fill(h, 'cap-20260912-120000-aaaa', traffic(10));
  h.volume.plant('cap-20260912-130000-bbbb');
  h.volume.plant('My Documents');
  h.send({ type: 'prune', keep: ['cap-20260912-120000-aaaa'] });
  await h.store.drain();

  check('the named capture survives and the other goes',
    h.volume.list().sort(), ['My Documents', 'cap-20260912-120000-aaaa']);
  checkTrue('...and the foreign entry is reported rather than removed silently',
    h.of('failure').some((m) => m.message.includes('not captures')));
}

console.log('\n--- the scan: the same answer the filter already gives ---\n');

{
  const h = host({ scanSliceMs: 0 });
  await fill(h, 'cap-20260912-140000-cccc', packets);

  const expressions = ['tcp', 'dns', 'udp && frame.len > 500', '!tcp'];
  for (const [i, expression] of expressions.entries()) {
    // A fresh id each time. Reusing one made the wait return on the PREVIOUS
    // scan's answer and compare the wrong bitmap - which passed for `tcp`,
    // because `tcp` was the answer it kept finding.
    const requestId = 100 + i;
    h.send({ type: 'scan', requestId, filter: expression });
    checkTrue(`${expression}: the scan finished`, await untilScanDone(h.said, requestId));
    const done = h.of('scanDone').find((m) => m.requestId === requestId)!;

    // The oracle: the same expression run over the same packets in memory.
    const predicate = compile(expression);
    const expected: number[] = [];
    for (let i = 0; i < packets.length; i++) if (predicate(packets[i])) expected.push(i);

    // Round-tripped through the wire's bytes, not read off the scan's own
    // object - the bitmap is what actually crosses, and a layout the two ends
    // disagreed about would mark the wrong frames rather than fail.
    const set = done.bits === null ? null : MatchSet.fromBytes(done.frameCount, done.bits);
    check(`${expression}: exactly the frames the in-memory filter matches`,
      set === null ? null : ordinals(set), expected);
  }
}

console.log('\n--- the scan is sliced, so the store still answers ---\n');

{
  // One chunk a slice, which makes the interleaving countable rather than a
  // race: four chunks is four slices, and a read sent immediately after the
  // scan must not wait for all of them.
  const h = host({ scanSliceMs: 0 });
  await fill(h, 'cap-20260912-150000-dddd', packets);
  h.said.length = 0;

  h.send({ type: 'scan', requestId: 200, filter: 'tcp' });
  h.send({ type: 'read', requestId: 201, ids: [packets[3].id] });
  h.send({ type: 'locate', requestId: 202, id: packets[9].id });
  checkTrue('the scan finished', await untilScanDone(h.said, 200));

  const order = h.said.map((m) => m.type);
  const readAt = order.indexOf('bytes');
  const locateAt = order.indexOf('located');
  const doneAt = order.indexOf('scanDone');
  checkTrue('a read is answered while the scan is still running',
    readAt >= 0 && readAt < doneAt);
  checkTrue('...and so is a locate', locateAt >= 0 && locateAt < doneAt);

  // The read has to be right as well as prompt. A reader mid-scan is the case
  // where a shared cursor or a reused buffer would show.
  check('...and answers correctly', h.of('bytes')[0]?.frames.length, 1);
}

console.log('\n--- cancelling, overtaking, and closing underneath it ---\n');

{
  const h = host({ scanSliceMs: 0 });
  await fill(h, 'cap-20260912-160000-eeee', packets);
  h.said.length = 0;

  // A second filter supersedes the first. The first must settle, or its
  // caller waits for ever on an answer nobody will send.
  h.send({ type: 'scan', requestId: 300, filter: 'tcp' });
  h.send({ type: 'scan', requestId: 301, filter: 'dns' });
  checkTrue('the second scan finished', await untilScanDone(h.said, 301));

  const done = h.of('scanDone');
  check('both scans answered', done.map((m) => m.requestId), [300, 301]);
  check('the superseded one says it was cancelled', done[0]?.cancelled, true);
  check('...and hands back no bitmap, rather than a partial one', done[0]?.bits, null);
  check('the current one completed', done[1]?.cancelled, false);
  checkTrue('...with a bitmap', done[1]?.bits !== null);
}

{
  const h = host({ scanSliceMs: 0 });
  await fill(h, 'cap-20260912-170000-ffff', packets);
  h.said.length = 0;

  h.send({ type: 'scan', requestId: 400, filter: 'tcp' });
  h.send({ type: 'scanCancel', requestId: 400 });
  await h.store.drain();
  await sleep(30);

  const done = h.of('scanDone');
  check('a cancel answers exactly once', done.length, 1);
  check('...as cancelled', done[0]?.cancelled, true);

  // A stale cancel must not abandon the scan that replaced it. This is the
  // shape of every "the user retyped the filter" sequence.
  h.said.length = 0;
  h.send({ type: 'scan', requestId: 401, filter: 'dns' });
  h.send({ type: 'scanCancel', requestId: 400 });
  checkTrue('the new scan finished', await untilScanDone(h.said, 401));
  check('a cancel for a finished scan does not stop the next one',
    h.of('scanDone').map((m) => ({ id: m.requestId, cancelled: m.cancelled })),
    [{ id: 401, cancelled: false }]);
}

{
  const h = host({ scanSliceMs: 0 });
  await fill(h, 'cap-20260912-180000-0001', packets);
  h.said.length = 0;

  // The capture closes while slices are queued behind it. Every one of those
  // holds a reader over files that are about to go, and a slice that ran
  // afterwards would read a closed handle - which on `node:fs` is EBADF and
  // on a `MemoryBlockFile` is silently the wrong bytes.
  h.send({ type: 'scan', requestId: 500, filter: 'tcp' });
  h.send({ type: 'discard', captureId: 'cap-20260912-180000-0001' });
  await h.store.drain();
  await sleep(50);

  const done = h.of('scanDone');
  check('discarding the capture settles the scan', done.length, 1);
  check('...as cancelled', done[0]?.cancelled, true);
  check('and nothing failed', h.of('failure'), []);
  check('no handle was left open', h.volume.outstanding, 0);
}

{
  const h = host({ scanSliceMs: 0 });
  await fill(h, 'cap-20260912-180000-0002', packets);
  h.said.length = 0;

  // Reopening the SAME capture, which is the case the slice loop's id check
  // cannot catch: the id still matches, so the scan carries on holding a
  // reader over the files `open` just closed and replaced. Only settling the
  // scan when the handles close covers this one - and on a real volume the
  // difference is a read from a closed descriptor.
  h.send({ type: 'scan', requestId: 501, filter: 'tcp' });
  h.send({ type: 'open', captureId: 'cap-20260912-180000-0002', requestId: 502 });
  checkTrue('the scan settled', await untilScanDone(h.said, 501));

  const done = h.of('scanDone');
  check('reopening the same capture settles the scan', done.length, 1);
  check('...as cancelled, rather than answering from a stale reader',
    done[0]?.cancelled, true);
  check('one handle open, not two', h.volume.outstanding, 1);
  h.store.close();
}

console.log('\n--- a filter that does not compile ---\n');

{
  const h = host();
  await fill(h, 'cap-20260912-190000-0002', traffic(100));
  h.said.length = 0;

  h.send({ type: 'scan', requestId: 600, filter: 'tcp.port ==' });
  await h.store.drain();
  await sleep(10);

  const done = h.of('scanDone');
  check('a syntax error answers rather than throwing', done.length, 1);
  checkTrue('...with a message', (done[0]?.message ?? '').length > 0);
  check('...and no bitmap', done[0]?.bits, null);
  check('...and is not reported as a store failure', h.of('failure'), []);
}

console.log('\n--- rows from the Worker that wrote their bytes (bytesSent) ---\n');

{
  // A live capture's rows come from the pipeline Worker on its own port, after
  // the bytes it posted there, and without them (ADR 0053): the same rows as
  // an `append` with bytes, the same bytes on disk, and an empty `rawBytes`
  // never written as a frame.
  const packets = traffic(5000);
  const withBytes = host();
  await fill(withBytes, 'cap-20261009-010000-0001', packets);
  const split = host();
  split.send({ type: 'open', captureId: 'cap-20261009-010000-0002' });
  for (let i = 0; i < packets.length; i += 700) {
    const group = packets.slice(i, i + 700);
    split.send({ type: 'appendBytes', slab: packFrames(group.map((p) => ({ id: p.id, tsUs: p.tsUs, bytes: p.rawBytes }))) });
    split.send({ type: 'append', bytesSent: true, packets: crossed(group.map((p) => ({ ...p, rawBytes: new Uint8Array(0) }))) });
  }
  // A row this sender never wrote bytes for, which must not become a frame.
  split.send({ type: 'append', bytesSent: true, packets: crossed([frame(9_999, { rawBytes: new Uint8Array(0) })]) });
  split.send({ type: 'finish' });
  await split.store.drain();
  for (const h of [withBytes, split]) {
    h.send({ type: 'chunk', requestId: 1, chunk: 0 });
    h.send({ type: 'chunk', requestId: 2, chunk: 1 });
    h.send({ type: 'read', requestId: 3, ids: [1, 4097, 5000] });
    h.send({ type: 'locate', requestId: 4, id: 9_999 });
    h.send({ type: 'stats' });
  }
  await withBytes.store.drain();
  await split.store.drain();
  const rowsOf = (h: ReturnType<typeof host>) => h.of('rows').flatMap((m) => m.packets);
  check('the rows on disk are the rows an append with bytes writes',
    JSON.stringify(rowsOf(split)), JSON.stringify(rowsOf(withBytes)));
  check('...5,000 of them', rowsOf(split).length, 5000);
  check('...and the bytes are the bytes',
    split.of('bytes')[0]?.frames.map(([id, b]) => [id, [...b]]),
    withBytes.of('bytes')[0]?.frames.map(([id, b]) => [id, [...b]]));
  check('a row whose bytes never came is not stored as a frame', split.of('located')[0]?.ordinal, -1);
  check('...nor counted as one',
    split.of('stats').at(-1)?.stats.framesWritten, withBytes.of('stats').at(-1)?.stats.framesWritten);
  check('...and nothing failed', split.of('failure').length, 0);
  withBytes.store.close();
  split.store.close();
}

console.log('\n--- packed rows from the Worker (appendPacked) ---\n');

{
  // A shard's rows reach the store as the pack the shard encoded, a flush at a
  // time, with one pack read across two messages. The rows on disk and the
  // frames beside them must be those an `append` with bytes writes, and a row
  // that came without bytes must never be written as an empty frame.
  const PACK_ROWS = 400;
  const GROUP = 700;
  const packets = traffic(5000);
  const outside = frame(9_999);
  const reference = host();
  await fill(reference, 'cap-20261024-010000-0001', [...packets, outside]);

  const packed = host();
  packed.send({ type: 'open', captureId: 'cap-20261024-010000-0002' });
  const bare = (p: Packet): Packet => ({ ...p, rawBytes: new Uint8Array(0) });
  const packs: RowPack[] = [];
  for (let i = 0; i < packets.length; i += PACK_ROWS) {
    const rows = packets.slice(i, i + PACK_ROWS).map(bare);
    packs.push(packRows(packs.length, rows, rows.map(() => 8)));
  }
  // The Worker's own sender, so a pack goes once and a later message names it only by key.
  const sender = new PackSender();
  const sent: PackedRows[] = [];
  // `ahead`: whether the Worker wrote these rows' bytes ahead of them on this port.
  const post = (flush: PackedFlush, ahead: boolean) => {
    const rows = deserialize(serialize(sender.seal(flush))) as PackedRows;
    sent.push(rows);
    packed.send({ type: 'appendPacked', rows, sent: new Uint8Array(rows.order.length / 2).fill(ahead ? 1 : 0) });
  };
  for (let i = 0; i < packets.length; i += GROUP) {
    const group = packets.slice(i, i + GROUP);
    packed.send({ type: 'appendBytes', slab: packFrames(group.map((p) => ({ id: p.id, tsUs: p.tsUs, bytes: p.rawBytes }))) });
    const flush = new PackedFlush();
    for (const p of group) flush.packed(packs[Math.floor((p.id - 1) / PACK_ROWS)], (p.id - 1) % PACK_ROWS, null, null);
    post(flush, true);
  }
  // A row whose bytes never came, and which brings none: held, never written as a frame.
  const lost = new PackedFlush();
  lost.packed(packRows(packs.length, [bare(frame(9_998))], [8]), 0, null, null);
  post(lost, true);
  // Outside the run: nobody wrote this frame's bytes ahead, so the row brings them.
  const odd = new PackedFlush();
  odd.packed(packRows(packs.length + 1, [bare(outside)], [8]), 0, outside.rawBytes, null);
  post(odd, false);
  packed.send({ type: 'finish' });
  await packed.store.drain();

  checkTrue('a pack was read across two messages (400 rows against groups of 700)',
    sent[0].packs.some((p) => p.key === 1) && !sent[1].packs.some((p) => p.key === 1)
    && Array.from(sent[1].order).some((v, at) => at % 2 === 0 && v === 1));
  for (const h of [reference, packed]) {
    h.send({ type: 'chunk', requestId: 1, chunk: 0 });
    h.send({ type: 'chunk', requestId: 2, chunk: 1 });
    h.send({ type: 'read', requestId: 3, ids: [1, 4097, 5000, 9_999] });
    h.send({ type: 'locate', requestId: 4, id: 9_999 });
    h.send({ type: 'locate', requestId: 5, id: 9_998 });
    h.send({ type: 'stats' });
  }
  await reference.store.drain();
  await packed.store.drain();
  const rowsOf = (h: ReturnType<typeof host>) => h.of('rows').flatMap((m) => m.packets);
  check('the rows on disk are the rows an append with bytes writes',
    JSON.stringify(rowsOf(packed)), JSON.stringify(rowsOf(reference)));
  check('...5,001 of them', rowsOf(packed).length, 5001);
  check('a row whose bytes never came is not stored as a frame', packed.of('located')[1]?.ordinal, -1);
  check('...and the bytes are the bytes',
    packed.of('bytes')[0]?.frames.map(([id, b]) => [id, [...b]]),
    reference.of('bytes')[0]?.frames.map(([id, b]) => [id, [...b]]));
  checkTrue('...none of them empty', (packed.of('bytes')[0]?.frames ?? []).every(([, b]) => b.length === 8));
  check('the row outside the run is stored, with its frame',
    packed.of('located')[0]?.ordinal, reference.of('located')[0]?.ordinal);
  check('...and the frames written are those an append writes',
    packed.of('stats').at(-1)?.stats.framesWritten, reference.of('stats').at(-1)?.stats.framesWritten);
  check('...and nothing failed', packed.of('failure').length, 0);
  reference.store.close();
  packed.store.close();
}

{
  // An agent's metadata-only frame rides beside packed rows as an object with no
  // bytes, which nobody wrote ahead of it. It must be stored as a plain `append`
  // stores it - not taken for a row whose bytes went ahead and then counted missed
  // when they never arrive. Which rows had their bytes sent is the Worker's to
  // say; the store cannot tell from an empty `rawBytes`.
  const meta: Packet = { ...frame(7), rawBytes: new Uint8Array(0) };
  const plain = host();
  plain.send({ type: 'open', captureId: 'cap-20261024-020000-0001' });
  plain.send({ type: 'append', packets: [deserialize(serialize(meta)) as Packet] });
  plain.send({ type: 'finish' });
  const packed = host();
  packed.send({ type: 'open', captureId: 'cap-20261024-020000-0002' });
  const flush = new PackedFlush();
  flush.object(meta, meta.rawBytes);
  const rows = deserialize(serialize(new PackSender().seal(flush))) as PackedRows;
  packed.send({ type: 'appendPacked', rows, sent: new Uint8Array([0]) });
  packed.send({ type: 'finish' });
  for (const h of [plain, packed]) {
    h.send({ type: 'locate', requestId: 1, id: 7 });
    h.send({ type: 'stats' });
  }
  await plain.store.drain();
  await packed.store.drain();
  checkTrue('...a metadata-only frame beside packed rows is stored as an append stores it',
    plain.of('located')[0]?.ordinal !== undefined && plain.of('located')[0]?.ordinal !== -1
    && packed.of('located')[0]?.ordinal === plain.of('located')[0]?.ordinal);
  check('...with the same frames written', packed.of('stats').at(-1)?.stats.framesWritten,
    plain.of('stats').at(-1)?.stats.framesWritten);
  plain.store.close();
  packed.store.close();
}

console.log('\n--- packed rows kept in their packs, and decoded (packNative) ---\n');

{
  // The same appendPacked flows into two hosts, one writing a shard's rows as
  // version-3 chunks that keep their packs (`packNative`, the default) and one
  // decoding them at the seal (the kill switch). Everything a reader can ask
  // must agree: the rows, the scans, the digest, the writer's counters. And the
  // first host must really have written version 3, or this proves nothing.
  const PACK = 400;
  const GROUP = 700;

  /** A bigint-safe structural form: sorted keys, no undefined, typed arrays as lists. */
  const canon = (value: unknown): unknown => {
    if (typeof value === 'bigint') return { big: value.toString() };
    if (value instanceof Uint8Array || value instanceof Int32Array) return Array.from(value);
    if (Array.isArray(value)) return value.map(canon);
    if (value instanceof Map) return { map: [...value.entries()].map(([k, v]) => [canon(k), canon(v)]) };
    if (value !== null && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(value).sort()) {
        const v = (value as Record<string, unknown>)[key];
        if (v !== undefined) out[key] = canon(v);
      }
      return out;
    }
    return value;
  };
  const cross = <T>(message: T): T => deserialize(serialize(message)) as T;

  const rowOf = (id: number): Packet => frame(id, {
    streamId: 1 + (id % 6),
    ...(id % 9 === 0 ? { protocol: 'UDP', frameProtocols: ['frame', 'eth', 'ip', 'udp'], destPort: 53 } : {}),
    fields: {
      'tcp.seq': id, 'tcp.len': id % 50, 'tcp.flags.syn': id % 6 === 1 ? 1 : 0,
      'tcp.flags.ack': 1, 'tcp.flags.fin': 0, 'tcp.flags.reset': 0,
    },
    // Present on some rows, so an overlay that clears them has something to clear.
    ...(id % 5 === 0 ? { expert: [{ message: `orig ${id}` }], tsNanos: BigInt(id) * 1000n, tsPrecision: 9 } : {}),
  });
  const bareOf = (id: number): Packet => ({ ...rowOf(id), rawBytes: new Uint8Array(0) });
  /** All four members of a `RowOverlay`, including the two that clear a key. */
  const overlayOf = (id: number): RowOverlay | null => {
    if (id % 11 !== 0) return null;
    switch ((id / 11) % 4) {
      case 0: return { fields: { 'tls.stream': id, 'inwire.process.name': 'tool.exe' } };
      case 1: return { expert: [{ message: `gap ${id}` }, { message: 'second' }] };
      case 2: return { tsPrecision: 6, tsNanos: BigInt(id) * 1000n + 123n };
      default: return { expert: undefined, tsNanos: undefined, tsPrecision: 3 };
    }
  };

  const phost = (packNative: boolean) => {
    const volume = new MemoryVolume();
    const said: FromCapture[] = [];
    const store = new CaptureHost(volume, (message) => said.push(message), { writer: { packNative } });
    return {
      volume, said, store,
      send: (message: ToCapture) => store.receive(message),
      of<T extends FromCapture['type']>(type: T): Extract<FromCapture, { type: T }>[] {
        return said.filter((m) => m.type === type) as Extract<FromCapture, { type: T }>[];
      },
      /** The packs the host's reader still holds. */
      held: () => (store as unknown as { packs: { held: number } }).packs.held,
    };
  };
  type PHost = ReturnType<typeof phost>;

  /** One capture of `n` frames: a seventh are objects, the rest packed over two interleaved lanes. */
  function drive(h: PHost, captureId: string, n: number, sender: PackSender, tail: boolean): void {
    h.send({ type: 'open', captureId });
    const isObject = (id: number) => id % 7 === 0;
    // The last rows of each flush bring their own bytes, as rows outside the run
    // do: after the bytes of the rest, never before a lower id's.
    const carries = (id: number) => (id - 1) % GROUP >= GROUP - 5;
    const lanes: Packet[][] = [[], []];
    const at = new Map<number, { lane: number; k: number }>();
    for (let id = 1; id <= n; id++) {
      if (isObject(id)) continue;
      const lane = id % 2;
      at.set(id, { lane, k: lanes[lane].length });
      lanes[lane].push(bareOf(id));
    }
    const packOf = new Map<string, RowPack>();
    let key = 0;
    for (let lane = 0; lane < 2; lane++) {
      for (let s = 0; s < lanes[lane].length; s += PACK) {
        const rows = lanes[lane].slice(s, s + PACK);
        packOf.set(`${lane}:${s / PACK}`, packRows(key++, rows, rows.map(() => 8)));
      }
    }
    const post = (flush: PackedFlush, flags: number[]) => {
      h.send(cross({ type: 'appendPacked', rows: sender.seal(flush), sent: Uint8Array.from(flags) }) as ToCapture);
    };
    for (let from = 1; from <= n; from += GROUP) {
      const ids = Array.from({ length: Math.min(GROUP, n - from + 1) }, (_, i) => from + i);
      h.send(cross({
        type: 'appendBytes',
        slab: packFrames(ids.filter((id) => !carries(id)).map((id) => {
          const p = rowOf(id);
          return { id, tsUs: p.tsUs, bytes: p.rawBytes };
        })),
      }));
      const flush = new PackedFlush();
      const flags: number[] = [];
      for (const id of ids) {
        if (isObject(id)) {
          const object = carries(id) ? rowOf(id) : bareOf(id);
          flush.object(object, object.rawBytes);
        } else {
          const { lane, k } = at.get(id)!;
          flush.packed(packOf.get(`${lane}:${Math.floor(k / PACK)}`)!, k % PACK, carries(id) ? rowOf(id).rawBytes : null, overlayOf(id));
        }
        flags.push(carries(id) ? 0 : 1);
      }
      post(flush, flags);
      // Patches after the rows: two on one row (arrival order), a relabel, one for a
      // row long sealed, and one for a row that has not arrived yet (both missed).
      h.send(cross({
        type: 'patches',
        patches: [
          { frameId: from + 3, suffix: ' [a]' },
          { frameId: from + 5, suffix: ' [b]', protocolLabel: 'TLSv1.3' },
          { frameId: from + 3, suffix: ' [c]' },
          { frameId: from + 10, suffix: ' [d]' },
          { frameId: from - 2500, suffix: ' [old]' },
          { frameId: from + GROUP + 2, suffix: ' [early]' },
        ],
      }));
    }
    if (tail) {
      // A pack read only in part and then left, as a stopped capture leaves one.
      const rows = Array.from({ length: 50 }, (_, i) => bareOf(n + 1 + i));
      const pack = packRows(9000, rows, rows.map(() => 8));
      const flush = new PackedFlush();
      for (let i = 0; i < 10; i++) flush.packed(pack, i, rowOf(n + 1 + i).rawBytes, null);
      post(flush, new Array(10).fill(0));
    }
    h.send({ type: 'finish' });
  }

  /** Everything a reader can ask of the finished capture. */
  async function collect(h: PHost, captureId: string, base: number) {
    await h.store.drain();
    h.send({ type: 'stats' });
    await h.store.drain();
    const stats = h.of('stats').at(-1)!.stats;
    const rows: Packet[] = [];
    for (let c = 0; c < stats.chunksWritten; c++) {
      h.send({ type: 'chunk', requestId: base + c, chunk: c });
      await h.store.drain();
      rows.push(...h.of('rows').find((m) => m.requestId === base + c)!.packets);
    }
    const scans: unknown[] = [];
    const filters = ['tcp', 'udp', 'tls.stream == 44', 'tcp.seq > 3000 && tcp.seq < 3900', 'frame.number > 8000'];
    for (let i = 0; i < filters.length; i++) {
      h.send({ type: 'scan', requestId: base + 500 + i, filter: filters[i] });
      await untilScanDone(h.said, base + 500 + i);
      const done = h.of('scanDone').find((m) => m.requestId === base + 500 + i)!;
      scans.push({ message: done.message, count: done.bits === null ? null : done.bits.reduce((a, b) => a + popcount(b), 0), bits: done.bits });
    }
    h.send({ type: 'read', requestId: base + 900, ids: [1, 2, 13, 14, 4097, 4098, 8999] });
    await h.store.drain();
    const bytes = h.of('bytes').find((m) => m.requestId === base + 900)!.frames;

    const files = h.volume.open(captureId);
    const indexBytes = new Uint8Array(files.index.size());
    files.index.read(0, indexBytes);
    const index = CaptureIndex.parse(indexBytes);
    const versions: number[] = [];
    for (let c = 0; c < index.chunkCount; c++) {
      const r = index.record(c);
      const summary = inflateSync(readExact(files.sum, r.sumOffset, r.sumLength));
      versions.push(summary[4] | (summary[5] << 8));
    }
    const digest = decodeDigest(readExact(files.digest, 0, files.digest.size()), inflateSync);
    files.close();
    return { stats, rows, scans, bytes, versions, digest };
  }
  const popcount = (b: number) => { let c = 0; for (; b; b &= b - 1) c++; return c; };

  const run = async (packNative: boolean) => {
    const h = phost(packNative);
    // Nothing open: read before anything else, said once, and no pack left held.
    for (const key of [5, 6]) {
      const stray = new PackedFlush();
      const pack = packRows(key, [bareOf(1), bareOf(2)], [8, 8]);
      stray.packed(pack, 0, null, null);
      stray.packed(pack, 1, null, null);
      h.send(cross({ type: 'appendPacked', rows: new PackSender().seal(stray), sent: new Uint8Array([1, 1]) }) as ToCapture);
    }
    await h.store.drain();
    const orphan = { held: h.held(), failures: h.of('failure').map((m) => m.message) };

    const sender = new PackSender();
    drive(h, 'cap-20261025-010000-0001', 9000, sender, true);
    const first = await collect(h, 'cap-20261025-010000-0001', 1000);
    const heldAfterFirst = h.held();

    // A new capture: the Worker's sender starts over and says so.
    const second = new PackSender();
    drive(h, 'cap-20261025-010000-0002', 900, second, false);
    const next = await collect(h, 'cap-20261025-010000-0002', 3000);
    const failures = h.of('failure').map((m) => m.message);
    const heldAfterSecond = h.held();
    h.store.close();
    return { orphan, first, heldAfterFirst, next, heldAfterSecond, failures };
  };

  const native = await run(true);
  const decoded = await run(false);

  checkTrue('an appendPacked with no capture open fails once, with the same message, and leaves no pack held',
    native.orphan.failures.length === 1 && native.orphan.failures[0].includes('before a capture was opened') && native.orphan.held === 0);
  check('...for both hosts', canon(native.orphan), canon(decoded.orphan));
  checkTrue('...and nothing else failed', native.failures.length === 1 && decoded.failures.length === 1);

  for (const [label, a, b] of [['first capture', native.first, decoded.first], ['second capture', native.next, decoded.next]] as const) {
    checkTrue(`${label}: rows were read back (${a.rows.length})`, a.rows.length >= (label === 'first capture' ? 9000 : 900));
    check(`${label}: ${a.rows.length} rows read back are the rows packNative off reads back`, canon(a.rows), canon(b.rows));
    check(`${label}: the scans answer alike`, canon(a.scans), canon(b.scans));
    checkTrue(`${label}: ...and they found something (${a.scans.map((s) => (s as { count: number }).count).join(', ')})`,
      a.scans.slice(0, 3).every((s) => ((s as { count: number | null }).count ?? 0) > 0));
    check(`${label}: the bytes read are alike`, canon(a.bytes), canon(b.bytes));
    check(`${label}: the digest snapshot is the same`, canon(a.digest), canon(b.digest));
    checkTrue(`${label}: ...and holds streams`, (a.digest?.entries.length ?? 0) > 0);
    check(`${label}: the writer's counters are the same`, canon(a.stats), canon(b.stats));
    checkTrue(`${label}: ...patches both applied and missed (${a.stats.patchesApplied}/${a.stats.patchesMissed})`,
      a.stats.patchesApplied > 0 && a.stats.patchesMissed > 0);
    checkTrue(`${label}: packNative wrote a version 3 chunk (${a.versions.join(',')})`, a.versions.some((v) => v === 3));
    checkTrue(`${label}: ...and packNative off wrote only version 2 (${b.versions.join(',')})`, b.versions.every((v) => v === 2));
  }
  // Agreement between the hosts cannot see a loss both share (an overlay dropped
  // before the writer is handed the slot is dropped by both), so the writes are
  // also read off the rows by name, in each host.
  for (const [label, rows] of [['packNative', native.first.rows], ['decoded', decoded.first.rows]] as const) {
    const byId = (id: number) => rows.find((r) => r.id === id)!;
    check(`${label}: an overlay's fields reach the stored row`,
      [byId(44).fields?.['tls.stream'], byId(44).fields?.['inwire.process.name']], [44, 'tool.exe']);
    check(`${label}: ...its expert list`, byId(55).expert?.map((e) => e.message), ['gap 55', 'second']);
    check(`${label}: ...its clock`, [byId(66).tsPrecision, String(byId(66).tsNanos)], [6, '66123']);
    check(`${label}: ...and one that clears expert and tsNanos clears them`,
      [byId(165).expert, byId(165).tsNanos === undefined, byId(165).tsPrecision, 'expert' in byId(165)], [undefined, true, 3, false]);
    checkTrue(`${label}: patches land on a packed row in arrival order (${byId(4).info})`,
      byId(4).info.indexOf('[a]') >= 0 && byId(4).info.indexOf('[a]') < byId(4).info.indexOf('[c]'));
  }
  check('the first capture leaves its half-read pack held, as expected', [native.heldAfterFirst, decoded.heldAfterFirst], [1, 1]);
  check('a new capture drops it (packsReset) and reads its own packs to the end', [native.heldAfterSecond, decoded.heldAfterSecond], [0, 0]);
}

console.log('\n--- the stream digest answer carries every kind ---\n');

{
  const none = host();
  none.send({ type: 'streamDigest', requestId: 1, since: 0 });
  await none.store.drain();
  check('no capture: the answer has empty udp, quic and a zero captureEnd',
    [none.of('streamDigest')[0]?.udp, none.of('streamDigest')[0]?.quic, none.of('streamDigest')[0]?.captureEnd], [[], [], 0]);

  const h = host();
  const udp = (id: number, fromClient: boolean) => frame(id, {
    protocol: 'UDP', frameProtocols: ['eth', 'ip', 'udp'], fields: { 'udp.stream': 4 },
    source: fromClient ? '10.0.0.4' : '93.184.216.34', destination: fromClient ? '93.184.216.34' : '10.0.0.4',
    sourcePort: fromClient ? 50000 : 5353, destPort: fromClient ? 5353 : 50000,
  });
  const quic = (id: number, fromClient: boolean) => frame(id, {
    protocol: 'QUIC', frameProtocols: ['eth', 'ip', 'udp', 'quic'],
    fields: { 'udp.stream': 5, 'quic.connection.number': 2, 'quic.long.packet_type': 0, 'quic.version': 1 },
    source: fromClient ? '10.0.0.4' : '93.184.216.34', destination: fromClient ? '93.184.216.34' : '10.0.0.4',
    sourcePort: fromClient ? 50001 : 443, destPort: fromClient ? 443 : 50001,
  });
  h.send({ type: 'open', captureId: 'cap-20261026-010000-0001' });
  h.send({ type: 'append', packets: crossed([udp(1, true), udp(2, false), quic(3, true), quic(4, false)]) });
  h.send({ type: 'streamDigest', requestId: 2, since: 0 });
  await h.store.drain();
  // The answer is what the store's process posts, so it goes through v8 as well.
  const answer = deserialize(serialize(h.of('streamDigest')[0])) as Extract<FromCapture, { type: 'streamDigest' }>;
  check('an open capture: two UDP flows, keyed by udp.stream (the QUIC datagrams are one)', answer.udp.map((s) => [s.kind, s.key]), [['udp', 4], ['udp', 5]]);
  check('...one QUIC connection, keyed by its number', answer.quic.map((s) => [s.kind, s.key]), [['quic', 2]]);
  check('...and the capture\'s end is the newest row\'s time', answer.captureEnd, 4 / 1000);
  // `flowOrdinals` answers over the same port, and through v8 as well. It reads
  // sealed chunks, so the capture is finished first.
  h.send({ type: 'finish' });
  h.send({ type: 'flowOrdinals', requestId: 3, kind: 'quic', key: 2, fromId: 1, toId: 4, startChunk: 0 });
  h.send({ type: 'flowOrdinals', requestId: 4, kind: 'udp', key: 4, fromId: 1, toId: 4, startChunk: 0 });
  h.send({ type: 'flowOrdinals', requestId: 5, kind: 'udp', key: 5, fromId: 1, toId: 4, startChunk: 0 });
  await h.store.drain();
  const pages = deserialize(serialize(h.of('flowOrdinals'))) as Extract<FromCapture, { type: 'flowOrdinals' }>[];
  check('flowOrdinals answers a QUIC connection and a UDP flow, whole, on the wire (the QUIC rows are in their UDP flow too)',
    pages, [
      { type: 'flowOrdinals', requestId: 3, ordinals: [2, 3], nextChunk: null, searched: 1 },
      { type: 'flowOrdinals', requestId: 4, ordinals: [0, 1], nextChunk: null, searched: 1 },
      { type: 'flowOrdinals', requestId: 5, ordinals: [2, 3], nextChunk: null, searched: 1 },
    ]);
  h.store.close();
}

console.log('\n--- progress ---\n');

{
  const h = host({ scanSliceMs: 0 });
  // Enough frames that progress has something to report: the threshold is
  // 150,000, so a capture below it correctly sends none at all.
  await fill(h, 'cap-20260912-200000-0003', traffic(400_000));
  h.said.length = 0;

  h.send({ type: 'scan', requestId: 700, filter: 'tcp' });
  checkTrue('the scan finished', await untilScanDone(h.said, 700, 120_000));

  const progress = h.of('scanProgress');
  checkTrue(`progress was reported (${progress.length} messages)`, progress.length > 0);
  checkTrue('...far less often than once a slice',
    progress.length < Math.ceil(400_000 / 4096) / 2);
  checkTrue('...monotonically',
    progress.every((m, i) => i === 0 || m.framesDone > progress[i - 1].framesDone));
  checkTrue('...never claiming more than the capture holds',
    progress.every((m) => m.framesDone <= m.frameCount && m.matches <= m.framesDone));
  check('...against a denominator fixed at the start',
    [...new Set(progress.map((m) => m.frameCount))].length, 1);
}

console.log(failures === 0
  ? '\nAll capture store protocol checks passed.'
  : `\n${failures} capture store protocol check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
