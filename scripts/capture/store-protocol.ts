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
import { CaptureHost, type CaptureVolume, type OpenVolume } from '../../src/services/capture/captureHost';
import { MemoryBlockFile } from '../../src/services/capture/blockFile';
import { MatchSet } from '../../src/services/capture/matchSet';
import { CHUNK_FRAMES } from '../../src/services/capture/chunkCodec';
import { compile } from '../../src/services/filter/compile';
import type { CaptureFiles } from '../../src/services/capture/captureWriter';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
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

/**
 * The four files, in memory, surviving a close.
 *
 * Reopening has to find what was written - recovery, the resume and the torn
 * tail are the whole point of `open` being one message rather than two - so
 * the files outlive the `OpenVolume` that wrapped them.
 */
class MemoryVolume implements CaptureVolume {
  readonly directory = 'C:\\memory\\captures';
  private readonly stored = new Map<string, CaptureFiles>();
  /** Opens minus closes. A leaked handle is a Windows EBUSY on the next prune. */
  outstanding = 0;

  open(captureId: string): OpenVolume {
    let files = this.stored.get(captureId);
    if (files === undefined) {
      files = {
        index: new MemoryBlockFile(), pfx: new MemoryBlockFile(),
        sum: new MemoryBlockFile(), byt: new MemoryBlockFile(),
      };
      this.stored.set(captureId, files);
    }
    this.outstanding++;
    let closed = false;
    return {
      ...files,
      close: () => {
        if (closed) return;
        closed = true;
        this.outstanding--;
      },
    };
  }

  list(): string[] { return [...this.stored.keys()]; }
  remove(captureId: string): void { this.stored.delete(captureId); }
  freeBytes(): number { return 1_000_000_000_000; }
  /** Entries that are not captures, for the prune guard. */
  plant(name: string): void {
    this.stored.set(name, {
      index: new MemoryBlockFile(), pfx: new MemoryBlockFile(),
      sum: new MemoryBlockFile(), byt: new MemoryBlockFile(),
    });
  }
}

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

/** Appends and seals, so the frames are in chunks rather than staged. */
async function fill(h: ReturnType<typeof host>, captureId: string, packets: Packet[]) {
  h.send({ type: 'open', captureId });
  for (let i = 0; i < packets.length; i += 1000) {
    h.send({ type: 'append', packets: packets.slice(i, i + 1000) });
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
  await h.store.drain();

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

  // Reopening finds it. This is the restore, and the same message.
  h.send({ type: 'open', captureId: 'cap-20260912-120000-aaaa', requestId: 13 });
  await h.store.drain();
  const reopened = h.of('ready').find((m) => m.requestId === 13);
  check('a reopen finds every frame that was written', reopened?.frameCount, packets.length);
  check('...and closed the first handle before taking a second', h.volume.outstanding, 1);

  h.store.close();
  check('close releases the handles', h.volume.outstanding, 0);
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
