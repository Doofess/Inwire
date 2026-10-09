/**
 * Assertion tests for a stream's frames as the ladder draws them (ADR 0055).
 *
 *   npx tsx scripts/session/ladder-runs.ts
 *
 * Two things are held here, and each fails invisibly on the screen:
 *
 *   - **The folding rule.** A frame that says something - a flag, a finding,
 *     the first or the last - stands alone; a quiet run folds into one band.
 *     A band folded across a change of colour rule would be painted in one
 *     rule's colour for frames another rule matched, which is a chip that lies.
 *   - **Where a stream's frames come from.** `loadStreamFrames` pages the
 *     store's ordinals, reads rows a page at a time, then adds what is still
 *     only in RAM - in id order, with no frame twice and none skipped. A
 *     duplicate draws one frame as two arrows; a hole is a frame that is
 *     simply not there, which is a thing captures really do and so must never
 *     be faked.
 */
import type { Packet } from '../../src/types/packet';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import type { StreamSummary } from '../../src/services/conversation/streamDigest';
import {
  loadStreamFrames, type StreamFrameSource,
} from '../../src/services/conversation/streamFrames';
import { foldRuns, itemTime, type LadderItem } from '../../src/components/ladder/ladderRuns';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

const CLIENT = { address: '10.0.0.2', port: 50000 };

let nextId = 1;
/**
 * A TCP row as the store would hand it back. `rule` is a test-only field the
 * fake `ruleKeyOf` reads, standing in for the matched colour rule.
 */
function row(
  fromClient: boolean, flags: string,
  extra: Partial<Packet> & { seq?: number; ack?: number; len?: number; rule?: string } = {},
): Packet {
  const { seq, ack, len, rule, ...rest } = extra;
  const fields: Record<string, number | string> = {
    'tcp.flags.syn': flags.includes('S') ? 1 : 0, 'tcp.flags.ack': flags.includes('A') ? 1 : 0,
    'tcp.flags.fin': flags.includes('F') ? 1 : 0, 'tcp.flags.reset': flags.includes('R') ? 1 : 0,
    ...(seq !== undefined ? { 'tcp.seq': seq } : {}), ...(ack !== undefined ? { 'tcp.ack': ack } : {}),
    'tcp.len': len ?? 0,
    ...(rule !== undefined ? { 'test.rule': rule } : {}),
  };
  const id = nextId++;
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
    source: fromClient ? '10.0.0.2' : '93.184.216.34', destination: fromClient ? '93.184.216.34' : '10.0.0.2',
    sourcePort: fromClient ? 50000 : 443, destPort: fromClient ? 443 : 50000,
    protocol: 'TCP', frameProtocols: ['eth', 'ethertype', 'ip', 'tcp'], fields,
    length: 60 + (len ?? 0), info: '', status: 'ok', streamId: 7, ...rest,
  } as Packet;
}

const ruleKeyOf = (p: Packet): string => String(fieldValue(p, 'test.rule') ?? '');
const NONE: ReadonlySet<number> = new Set();

/** `[frame, frame, band(50), frame]` as a string, which is what each case reads as. */
function shape(items: readonly LadderItem[]): string[] {
  return items.map((i) => (i.kind === 'frame' ? 'frame' : `band(${i.count})`));
}

function handshake(): Packet[] {
  return [row(true, 'S', { seq: 0 }), row(false, 'SA', { seq: 0, ack: 1 }), row(true, 'A', { seq: 1, ack: 1 })];
}
function data(n: number, fromClient = true, rule = 'data'): Packet[] {
  return Array.from({ length: n }, () => row(fromClient, 'A', { len: 100, rule }));
}

// --- A quiet run folds into one band ----------------------------------------------
{
  nextId = 1;
  const frames = [...handshake(), ...data(50), row(true, 'FA')];
  const items = foldRuns(frames, CLIENT, ruleKeyOf, NONE);
  check('a handshake, fifty quiet frames and a FIN fold to three frames, a band and a frame',
    shape(items), ['frame', 'frame', 'frame', 'band(50)', 'frame']);
  const band = items[3];
  if (band.kind === 'band') {
    check('the band goes the way its frames went', band.from, 'client');
    check('...and is keyed by its first frame', [band.first.id, band.last.id], [4, 53]);
    check('...and sums its frames\' bytes', band.bytes, 50 * 160);
    check('...and spans its frames\' time', [band.time, band.endTime], [frames[3].relativeTime, frames[52].relativeTime]);
    check('...and carries the one rule its frames matched', band.ruleKey, 'data');
    check('itemTime reads a band\'s start', itemTime(band), frames[3].relativeTime);
  }
  check('itemTime reads a frame\'s own time', itemTime(items[0]), frames[0].relativeTime);
  check('the handshake frames carry their lanes',
    items.slice(0, 3).map((i) => i.from), ['client', 'server', 'client']);
  checkTrue('a frame item is the frame itself, not a copy',
    items[0].kind === 'frame' && items[0].packet === frames[0]);
}

// --- A band breaks on a change of colour rule (Review Focus 5) --------------------
//
// A band takes exactly one rule's colour. Folded across a change of rule it
// would be painted in one rule's colour for frames another rule matched - a
// chip that lies about what the list shows.
{
  nextId = 1;
  const frames = [...handshake(), ...data(25, true, 'a'), ...data(25, true, 'b'), row(true, 'FA')];
  const items = foldRuns(frames, CLIENT, ruleKeyOf, NONE);
  check('fifty frames whose rule changes at the twenty-fifth give two bands of twenty-five',
    shape(items), ['frame', 'frame', 'frame', 'band(25)', 'band(25)', 'frame']);
  check('...each in its own rule',
    items.slice(3, 5).map((i) => (i.kind === 'band' ? i.ruleKey : '')), ['a', 'b']);
}

// --- A frame that says something stands alone -------------------------------------
{
  nextId = 1;
  const quiet = data(50);
  quiet[24].analysisFlags = ['retransmission'];
  const frames = [...handshake(), ...quiet, row(true, 'FA')];
  check('a retransmission in the middle splits the band around a lone frame',
    shape(foldRuns(frames, CLIENT, ruleKeyOf, NONE)),
    ['frame', 'frame', 'frame', 'band(24)', 'frame', 'band(25)', 'frame']);

  nextId = 1;
  const flagged = data(50);
  flagged[24].fields!['inwire.expert.category'] = 'Note';
  check('an expert category does the same',
    shape(foldRuns([...handshake(), ...flagged, row(true, 'FA')], CLIENT, ruleKeyOf, NONE)),
    ['frame', 'frame', 'frame', 'band(24)', 'frame', 'band(25)', 'frame']);

  nextId = 1;
  const reset = [...handshake(), ...data(10), row(false, 'R'), ...data(10), row(true, 'FA')];
  check('so does a RST', shape(foldRuns(reset, CLIENT, ruleKeyOf, NONE)),
    ['frame', 'frame', 'frame', 'band(10)', 'frame', 'band(10)', 'frame']);

  // The first and the last frame are always drawn, flags or not: a band that
  // swallowed the first frame would hide where the stream was joined.
  nextId = 1;
  check('the first and last frames stand alone even when quiet',
    shape(foldRuns(data(20), CLIENT, ruleKeyOf, NONE)), ['frame', 'band(18)', 'frame']);
  check('a band of one is drawn as a frame',
    shape(foldRuns(data(3), CLIENT, ruleKeyOf, NONE)), ['frame', 'frame', 'frame']);
}

// --- Direction breaks a band ---------------------------------------------------------
{
  nextId = 1;
  const frames = Array.from({ length: 20 }, (_, i) => row(i % 2 === 0, 'A', { len: 10 }));
  const items = foldRuns(frames, CLIENT, ruleKeyOf, NONE);
  check('alternating directions give no band at all', items.length, 20);
  checkTrue('...so every frame is drawn', items.every((i) => i.kind === 'frame'));
  check('...each from the lane that sent it',
    items.slice(0, 4).map((i) => i.from), ['client', 'server', 'client', 'server']);
}

// --- An opened band comes back as frames ------------------------------------------------
{
  nextId = 1;
  const frames = [...handshake(), ...data(50), row(true, 'FA')];
  const folded = foldRuns(frames, CLIENT, ruleKeyOf, NONE);
  const first = folded[3].kind === 'band' ? folded[3].first.id : -1;
  const items = foldRuns(frames, CLIENT, ruleKeyOf, new Set([first]));
  check('with the band\'s first id in expanded, its frames come back as frames',
    items.length, frames.length);
  checkTrue('...every one a frame', items.every((i) => i.kind === 'frame'));
  check('...in order', items.map((i) => (i.kind === 'frame' ? i.packet.id : -1)), frames.map((f) => f.id));
  check('an id that is not a band\'s first opens nothing',
    shape(foldRuns(frames, CLIENT, ruleKeyOf, new Set([first + 1]))), shape(folded));
}

// --- A band is bounded ------------------------------------------------------------------------
{
  nextId = 1;
  const frames = [row(true, 'S'), ...data(100_050), row(true, 'FA')];
  check('a run past BAND_MAX frames is cut into bands of at most that many',
    shape(foldRuns(frames, CLIENT, ruleKeyOf, NONE)), ['frame', 'band(100000)', 'band(50)', 'frame']);
}

// --- Where a stream's frames come from ---------------------------------------------------------

interface FakeSource extends StreamFrameSource {
  ordinalCalls: number[];
  rowCalls: number[];
}

/** Ordinals `0..n-1` paged by `pageSize` chunks, each ordinal holding the row at that index. */
function fakeSource(disk: readonly Packet[], pageSize: number, onRead?: () => void): FakeSource {
  const source: FakeSource = {
    ordinalCalls: [], rowCalls: [],
    streamOrdinals(_streamId, _fromId, _toId, startChunk) {
      source.ordinalCalls.push(startChunk);
      const from = startChunk * pageSize;
      const ordinals = Array.from({ length: Math.min(pageSize, disk.length - from) }, (_, i) => from + i);
      const nextChunk = from + pageSize < disk.length ? startChunk + 1 : null;
      return Promise.resolve({ ordinals, nextChunk });
    },
    readRowsFor(ordinals) {
      source.rowCalls.push(ordinals.length);
      onRead?.();
      const rows = new Map<number, Packet>();
      for (const o of ordinals) rows.set(o, disk[o]);
      return Promise.resolve(rows);
    },
  };
  return source;
}

function summaryOf(frames: readonly Packet[], firstId = frames[0].id): StreamSummary {
  return {
    streamId: 7, firstId, lastId: frames[frames.length - 1].id,
  } as StreamSummary;
}

const ids = (frames: readonly Packet[]) => frames.map((f) => f.id);

await (async () => {
  nextId = 1;
  const disk = data(400);
  // RAM overlaps the end of the disk, which is what a live capture looks like:
  // the Worker's window holds frames the store has sealed too.
  const ram = [...disk.slice(350), ...data(30)];
  // A frame of another stream and a UDP frame carrying this stream's id, in RAM
  // and past the last disk id: neither is this stream's.
  ram.push(row(true, 'A', { streamId: 8 }));
  ram.push(row(true, 'A', { frameProtocols: ['eth', 'ethertype', 'ip', 'udp'] }));
  const expected = [...disk, ...ram.slice(50, 80)];

  const source = fakeSource(disk, 300);
  const progress: number[] = [];
  const frames = await loadStreamFrames(summaryOf(expected), ram, source, (n) => progress.push(n));

  check('streamOrdinals is paged until nextChunk is null', source.ordinalCalls, [0, 1]);
  check('rows are read 256 ordinals at a time', source.rowCalls, [256, 44, 100]);
  check('progress reports the frames loaded so far', progress, [256, 300, 400]);
  check('the result is the disk rows, then the RAM rows past the last disk id', ids(frames), ids(expected));
  check('...with no id twice', new Set(ids(frames)).size, frames.length);
  checkTrue('...in id order', frames.every((f, i) => i === 0 || f.id > frames[i - 1].id));
  checkTrue('...and another stream\'s frame is not among them', !frames.some((f) => f.streamId === 8));
  checkTrue('...nor a UDP frame', frames.every((f) => f.frameProtocols?.includes('tcp')));
})();

await (async () => {
  nextId = 1;
  const disk = data(400);
  const source = fakeSource(disk, 300);
  const frames = await loadStreamFrames(summaryOf(disk), [], source);
  check('nothing in RAM: the disk rows alone', ids(frames), ids(disk));

  nextId = 1;
  const only = data(20);
  const empty = fakeSource([], 300);
  const fromRam = await loadStreamFrames(summaryOf(only), only, empty);
  check('nothing on disk: every RAM frame of the stream', ids(fromRam), ids(only));
  check('...having asked the store once', empty.ordinalCalls, [0]);
})();

await (async () => {
  nextId = 1;
  const disk = data(400);
  const signal = { cancelled: false };
  const source = fakeSource(disk, 300, () => { signal.cancelled = true; });
  const frames = await loadStreamFrames(summaryOf(disk), [], source, undefined, signal);
  check('cancelled after the first page of rows: what it has is returned', frames.length, 256);
  check('...and no further page is asked for', [source.ordinalCalls, source.rowCalls], [[0], [256]]);
})();

await (async () => {
  nextId = 1;
  const disk = data(10);
  const source = fakeSource(disk, 300);
  // A row the store could not read back is skipped, not drawn as a hole.
  const partial: StreamFrameSource = {
    streamOrdinals: (...args) => source.streamOrdinals(...args),
    async readRowsFor(ordinals) {
      const rows = await source.readRowsFor(ordinals);
      rows.delete(4);
      return rows;
    },
  };
  const frames = await loadStreamFrames(summaryOf(disk), [], partial);
  check('a row the store did not answer is skipped', ids(frames), ids(disk).filter((id) => id !== 5));
})();

// --- The ring floor marker (Review Focus 4) ---------------------------------------------------
//
// A capture following the agent's ring loses its oldest segments, and the
// summary remembers a first frame the store no longer holds. The ladder reads
// `frames[0].id > summary.firstId` as "frames before this were removed" and
// says so; this fixes the contract that comparison rests on.
await (async () => {
  nextId = 1;
  const gone = data(500);
  const kept = data(100);
  const source = fakeSource(kept, 300);
  const frames = await loadStreamFrames(summaryOf([...gone, ...kept]), [], source);
  check('the summary still names the first frame the ring removed', summaryOf([...gone, ...kept]).firstId, 1);
  checkTrue('...and the first frame loaded has a greater id', frames[0].id > 1);
  check('...which is the first frame the store still holds', frames[0].id, kept[0].id);
})();

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All ladder run checks passed.');
process.exit(0);
