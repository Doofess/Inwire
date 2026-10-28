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
 *   - **What is written beside the arrows.** Each side's state goes on the row
 *     of the frame that moved it, inside a band when that frame folded into
 *     one; a gap marker takes a row only where the time axis gives it none,
 *     and the ring-floor marker wins over the joined one. An end marker on a
 *     stream that closed cleanly, or under a page that is not the last, would
 *     be the view claiming more than the capture holds (ADR 0055 §4).
 *   - **Colour comes from the colour rules and nowhere else.** The ladder's
 *     sources carry no rose, sky, red, amber or fuchsia utility and no
 *     `--color-*` literal (the Global Constraint), and the view asks the
 *     engine for both the chip's style and the band's rule key.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Packet } from '../../src/types/packet';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import { segmentOf, type StreamStep, type StreamSummary } from '../../src/services/conversation/streamDigest';
import { TcpStateMachine, type TcpOutcome } from '../../src/services/conversation/tcpStates';
import {
  keepFrames, KEPT_FRAMES_MAX, loadStreamFrames, progressGate, recallFrames, type StreamFrameSource,
} from '../../src/services/conversation/streamFrames';
import { rechoosesWindow, revealStep } from '../../src/components/ladder/ladderFollow';
import { flowSummaryIsTarget, summaryIsTarget, type StreamTarget } from '../../src/services/followStream';
import type { QuicSummary, UdpSummary } from '../../src/services/conversation/flowSummary';
import { foldRuns, itemTime, type LadderItem } from '../../src/components/ladder/ladderRuns';
import { layoutLadder, MIN_ROW_GAP, revealScroll, rowMeta, type LadderLayout } from '../../src/components/ladder/ladderLayout';
import {
  lanePills, markLadder, MARK_ROW, ROW_ABOVE, ROW_BELOW,
} from '../../src/components/ladder/ladderMarks';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

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
    'tcp.flags.push': flags.includes('P') ? 1 : 0,
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

// --- Acknowledgements ride along (ADR 0055 §1, owner 2026-10-24) -------------------------
//
// A receiver acknowledges every second segment. Broken on every change of
// direction, a bulk transfer folds into runs of two and the band the ADR
// describes cannot occur. A pure ACK from the other lane rides in the data's
// band, counted apart, in the data's rule.

/** As `shape`, with the riders: `band(100+50)` is a hundred data frames and fifty ACKs. */
function riders(items: readonly LadderItem[]): string[] {
  return items.map((i) => (i.kind === 'frame' ? 'frame' : `band(${i.count}+${i.acks})`));
}
/** A bulk transfer from the server, the client acknowledging every second segment. */
function bulk(segments: number, ackRule = 'ack'): Packet[] {
  const out: Packet[] = [];
  for (let i = 0; i < segments; i++) {
    out.push(row(false, 'A', { len: 1000, rule: 'data' }));
    if (i % 2 === 1) out.push(row(true, 'A', { rule: ackRule }));
  }
  return out;
}

// --- Acknowledgements ride along in the band they acknowledge ---------------------
{
  nextId = 1;
  const frames = [...handshake(), row(true, 'PA', { len: 200, rule: 'req' }), ...bulk(100), row(false, 'FA')];
  const items = foldRuns(frames, CLIENT, ruleKeyOf, NONE);
  check('a bulk transfer ACKed every second segment folds into one band',
    riders(items), ['frame', 'frame', 'frame', 'frame', 'band(100+50)', 'frame']);
  const band = items[4];
  if (band.kind === 'band') {
    check('...that goes the data\'s way', band.from, 'server');
    check('...counts only the data frames\' bytes', band.bytes, 100 * 1060);
    check('...takes the data\'s rule, never the ACKs\'', band.ruleKey, 'data');
    check('...and spans from the first data frame to the last ACK',
      [band.first.id, band.last.id], [frames[4].id, frames[frames.length - 2].id]);
  }
  const opened = foldRuns(frames, CLIENT, ruleKeyOf, new Set([frames[4].id]));
  check('opened, every frame comes back', opened.length, frames.length);
  check('...each ACK in the lane that sent it',
    opened.slice(4, 8).map((i) => i.from), ['server', 'server', 'client', 'server']);
}

// --- What does not ride along -------------------------------------------------------
{
  nextId = 1;
  const withData = [...handshake(), ...bulk(10)];
  withData.splice(8, 0, row(true, 'PA', { len: 50, rule: 'data' }));
  withData.push(row(false, 'FA'));
  check('a frame with payload from the other side still breaks the band',
    riders(foldRuns(withData, CLIENT, ruleKeyOf, NONE)).filter((s) => s !== 'frame').length > 1, true);

  nextId = 1;
  const dup = [...handshake(), ...bulk(20)];
  dup[10].analysisFlags = ['duplicate_ack'];
  dup.push(row(false, 'FA'));
  checkTrue('a duplicate ACK stands alone',
    foldRuns(dup, CLIENT, ruleKeyOf, NONE).some((i) => i.kind === 'frame' && i.packet === dup[10]));

  nextId = 1;
  const pingPong = [row(true, 'S'), ...Array.from({ length: 20 }, (_, i) => row(i % 2 === 0, 'A')), row(true, 'FA')];
  check('pure ACKs both ways do not fold into one another',
    foldRuns(pingPong, CLIENT, ruleKeyOf, NONE).length, pingPong.length);

  // One segment and its ACK are two frames; folded, they read "1 frames ·
  // 1 ACK" and hide both behind a click. A band is a run of data.
  nextId = 1;
  const single = [...handshake(), ...bulk(1), row(true, 'A', { rule: 'ack' }), row(false, 'FA')];
  check('one data frame and its ACK are drawn as frames, not a band',
    riders(foldRuns(single, CLIENT, ruleKeyOf, NONE)), single.map(() => 'frame'));
  nextId = 1;
  const pair = [...handshake(), ...bulk(2), row(false, 'FA')];
  check('two data frames and an ACK are a band', riders(foldRuns(pair, CLIENT, ruleKeyOf, NONE)),
    ['frame', 'frame', 'frame', 'band(2+1)', 'frame']);
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
  /** The `flowOrdinals` asks, as `[kind, key, fromId, toId, startChunk]`. */
  flowCalls: unknown[][];
}

/** Ordinals `0..n-1` paged by `pageSize` chunks, each ordinal holding the row at that index. */
function fakeSource(disk: readonly Packet[], pageSize: number, onRead?: () => void): FakeSource {
  const source: FakeSource = {
    ordinalCalls: [], rowCalls: [], flowCalls: [],
    streamOrdinals(_streamId, _fromId, _toId, startChunk) {
      source.ordinalCalls.push(startChunk);
      const from = startChunk * pageSize;
      const ordinals = Array.from({ length: Math.min(pageSize, disk.length - from) }, (_, i) => from + i);
      const nextChunk = from + pageSize < disk.length ? startChunk + 1 : null;
      return Promise.resolve({ ordinals, nextChunk });
    },
    flowOrdinals(kind, key, fromId, toId, startChunk) {
      source.flowCalls.push([kind, key, fromId, toId, startChunk]);
      const from = startChunk * pageSize;
      const ordinals = Array.from({ length: Math.min(pageSize, disk.length - from) }, (_, i) => from + i);
      const nextChunk = from + pageSize < disk.length ? startChunk + 1 : null;
      return Promise.resolve({ ordinals, nextChunk, searched: nextChunk === null ? 1 : (from + pageSize) / disk.length });
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

  // The view draws the stream from its first page, so progress hands over the
  // frames so far as well as the count - the array being filled, by reference.
  nextId = 1;
  const disk2 = data(400);
  // Read at the callback, because what is handed over keeps filling.
  const handed: { loaded: number; soFar: readonly Packet[]; count: number; ids: number[] }[] = [];
  const result = await loadStreamFrames(summaryOf(disk2), [], fakeSource(disk2, 300),
    (loaded, soFar) => handed.push({ loaded, soFar, count: soFar.length, ids: ids(soFar) }));
  checkTrue('...and the frames so far, as many as it says', handed.every((h) => h.count === h.loaded));
  check('...the first page being the first 256 rows', handed[0].ids, ids(disk2.slice(0, 256)));
  checkTrue('...and it is the one array being filled, not a copy each time',
    handed.every((h) => h.soFar === result));
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
  const progress: number[] = [];
  const frames = await loadStreamFrames(summaryOf(disk), [], source, (n) => progress.push(n), signal);
  check('cancelled after the first page of rows: what it has is returned', frames.length, 256);
  check('...and no further page is asked for', [source.ordinalCalls, source.rowCalls], [[0], [256]]);
  // The page that resolved after the cancel is not reported either: the
  // caller has moved on, and a report now would land under the next stream.
  check('...and the page that resolved after the cancel is not reported', progress, []);

  // With RAM frames past the disk: appending them behind an unfinished read
  // would leave a hole between the two that reads as frames the capture lost.
  nextId = 1;
  const disk2 = data(400);
  const ram = [...disk2.slice(350), ...data(30)];
  const cut = { cancelled: false };
  const source2 = fakeSource(disk2, 300, () => { cut.cancelled = true; });
  const partial = await loadStreamFrames(summaryOf([...disk2, ...ram.slice(50)]), ram, source2, undefined, cut);
  check('...and nothing from RAM is appended behind it', ids(partial), ids(disk2.slice(0, 256)));
})();

await (async () => {
  nextId = 1;
  const disk = data(10);
  const source = fakeSource(disk, 300);
  // A row the store could not read back is skipped, not drawn as a hole.
  const partial: StreamFrameSource = {
    streamOrdinals: (...args) => source.streamOrdinals(...args),
    flowOrdinals: (...args) => source.flowOrdinals(...args),
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

// --- Which summary is the target's -------------------------------------------------------------
//
// The digest is keyed by the tracker's stream index, which starts again at
// zero in every capture, and a Follow Stream target outlives the capture it
// was chosen in. The five-tuple says whether the summary under that index is
// this conversation.
{
  const summary = { client: { address: '10.0.0.2', port: 50000 }, server: { address: '93.184.216.34', port: 443 } };
  const target = (over: Partial<StreamTarget> = {}): StreamTarget => ({
    kind: 'tcp', addressA: '10.0.0.2', portA: 50000, addressB: '93.184.216.34', portB: 443, streamId: 7, ...over,
  });
  checkTrue('a summary of the target\'s two ends is its own', summaryIsTarget(summary, target()));
  checkTrue('...whichever end the target names first', summaryIsTarget(summary, target({
    addressA: '93.184.216.34', portA: 443, addressB: '10.0.0.2', portB: 50000,
  })));
  checkTrue('another port under the same index is another conversation', !summaryIsTarget(summary, target({ portA: 50001 })));
  checkTrue('a UDP target has no TCP summary', !summaryIsTarget(summary, target({ kind: 'udp' })));
  checkTrue('nor has a target with no stream index', !summaryIsTarget(summary, target({ streamId: undefined })));
}

// --- What is written beside the arrows -----------------------------------------------------------

/** The layout of `frames` folded with nothing expanded, over `window` or the whole extent. */
function laidOut(frames: readonly Packet[], height: number, window?: { from: number; to: number }): LadderLayout {
  const items = foldRuns(frames, CLIENT, ruleKeyOf, NONE);
  const extent = { from: frames[0].relativeTime, to: frames[frames.length - 1].relativeTime };
  return layoutLadder(items, window ?? extent, height);
}

/** A summary with the fields the marks and pills read, and nothing a test does not set. */
function summaryWith(
  frames: readonly Packet[], over: Partial<StreamSummary> = {},
): StreamSummary {
  return {
    ...summaryOf(frames),
    joinedMidStream: false, outcome: 'closed cleanly', steps: [],
    toServer: { packets: 0, bytes: 0, first: null, last: null },
    toClient: { packets: 0, bytes: 0, first: null, last: null },
    ...over,
  } as StreamSummary;
}

const ys = (marked: { arrows: { y: number }[] }) => marked.arrows.map((a) => a.y);
const kinds = (marked: { marks: { kind: string }[] }) => marked.marks.map((m) => m.kind);

// Three frames a millisecond apart over 480px: 240px between rows, room for anything.
{
  nextId = 1;
  const frames = [row(true, 'S'), row(false, 'SA'), row(true, 'A')];
  const layout = laidOut(frames, 480);
  check('the layout under test spaces its rows by time', layout.arrows.map((a) => a.y), [0, 240, 480]);

  const none = markLadder(layout, frames, null, true);
  check('no summary: no marks', none.marks, []);
  check('...no room taken above the plot', none.topRoom, 0);
  check('...and the arrows as the layout placed them', ys(none), [0, 240, 480]);
  checkTrue('...by reference', none.arrows.every((a, i) => a === layout.arrows[i]));
  check('...with the layout\'s own height', none.contentHeight, layout.contentHeight);

  const quiet = markLadder(layout, frames, summaryWith(frames), true);
  check('a closed stream the capture saw whole: no marks either', quiet.marks, []);

  const joined = markLadder(layout, frames, summaryWith(frames, { joinedMidStream: true }), true);
  check('joined mid-stream: one mark above the plot', kinds(joined), ['joined']);
  check('...saying so', joined.marks[0].text, 'Joined mid-stream: the handshake was not captured');
  check('...centred in the row it takes', joined.marks[0].y, -MARK_ROW / 2);
  check('...which is what the plot moves down by', joined.topRoom, MARK_ROW);
  check('...so the first arrow stays on its tick', ys(joined), [0, 240, 480]);
}

// The ring floor: the summary remembers a first frame the store no longer holds.
{
  nextId = 501;
  const frames = [row(true, 'A', { len: 10 }), row(false, 'A', { len: 10 }), row(true, 'A', { len: 10 })];
  const layout = laidOut(frames, 480);
  const summary = summaryWith(frames, { firstId: 1, joinedMidStream: true });
  const marked = markLadder(layout, frames, summary, true);
  check('frames before the first loaded were removed: the ring-floor mark, and only it', kinds(marked), ['ring-floor']);
  check('...naming the first frame still held', marked.marks[0].text, 'Frames before #501 were removed by the ring');
  checkTrue('...over the joined mark, because a ring that deleted a handshake did not make it unseen',
    summary.joinedMidStream && !kinds(marked).includes('joined'));

  // A rebuilt digest folds from the floor, so the stream's first frame IS the
  // first one held and the comparison above cannot see the cut: the store says so.
  const expired = summaryWith(frames, { firstId: frames[0].id, joinedMidStream: true, startExpired: true });
  const expiredMarks = markLadder(layout, frames, expired, true);
  check('a start the ring removed before a rebuild: the ring-floor mark, not joined', kinds(expiredMarks), ['ring-floor']);
  check('...worded as the ring cut is', expiredMarks.marks[0].text, 'Frames before #501 were removed by the ring');

  const later = markLadder(laidOut(frames, 480, { from: frames[1].relativeTime, to: frames[2].relativeTime }), frames, summary, true);
  check('with the stream\'s start above the window, nothing is said about it', later.marks, []);
  check('...and no room is taken', later.topRoom, 0);
}

// A lost segment, where the time axis already leaves a row's room.
{
  nextId = 1;
  const frames = [row(true, 'S'), row(false, 'SA'), row(true, 'A')];
  frames[2].analysisFlags = ['lost_segment'];
  const layout = laidOut(frames, 480);
  const marked = markLadder(layout, frames, summaryWith(frames), true);
  check('a lost segment: a mark before its frame', kinds(marked), ['lost']);
  check('...saying so', marked.marks[0].text, 'Packets missing here');
  check('...in the gap above the frame\'s chip', marked.marks[0].y, 480 - ROW_ABOVE - MARK_ROW / 2);
  check('...and nothing moved, because the gap had the room', ys(marked), [0, 240, 480]);
}

// Revealing a row in the ladder's own scroller. Nudging a burst apart can push
// rows below the viewport, so a frame inside the time window is not
// necessarily on screen: a state picked on the map at a 700px window landed
// on the bottom edge with its chips and number cut off.
{
  // A 400px viewport scrolled to 100 shows 100..500.
  check('a row already in view leaves the scroll alone', revealScroll(100, 400, 200, 240), 100);
  check('a row below scrolls just far enough to show it whole', revealScroll(100, 400, 480, 520), 120);
  check('a row above scrolls up to its top', revealScroll(100, 400, 60, 100), 60);
  check('a row taller than the viewport shows its top', revealScroll(0, 20, 50, 90), 50);
}

// The line under an arrow keeps to the lanes. At the 1024 minimum with the side
// bar and the map open the lanes are under 200px apart, and the crowded note
// ran over both of them and into the next row's.
{
  // 6px a character at 10px, so 5.4 at the line's 9px.
  check('a wide ladder says a crowded row is not to scale',
    rowMeta('#442-#443', 1506, true, 600, 6), '#442-#443 · 1506 B · ordered, not to scale');
  check('a narrow one drops the note rather than overrun the lanes',
    rowMeta('#442-#443', 1506, true, 190, 6), '#442-#443 · 1506 B');
  check('a row that is to scale never carries it', rowMeta('#415', 66, false, 600, 6), '#415 · 66 B');
}

// A lost segment in a burst, where the rows are already at the minimum gap.
{
  // A row reaches ROW_ABOVE over its line and ROW_BELOW under it; two rows
  // closer than that overprint one's number on the next's chip.
  checkTrue('the minimum row gap clears a row\'s own extent', MIN_ROW_GAP >= ROW_ABOVE + ROW_BELOW);
  const G = MIN_ROW_GAP;
  nextId = 1;
  const frames = Array.from({ length: 5 }, (_, i) => row(i % 2 === 0, 'A', { len: 10 }));
  frames[2].analysisFlags = ['lost_segment'];
  const layout = laidOut(frames, 60);
  check('the layout under test is nudged to the minimum gap', layout.arrows.map((a) => a.y), [0, G, 2 * G, 3 * G, 4 * G]);
  const marked = markLadder(layout, frames, summaryWith(frames), true);
  const least = G + ROW_BELOW + MARK_ROW + ROW_ABOVE;
  check('the flagged row moves down to clear a marker row under the one above', ys(marked)[2], least);
  check('...and every row below it moves by the same amount', ys(marked), [0, G, least, least + G, least + 2 * G]);
  check('...the rows above it do not', ys(marked).slice(0, 2), [0, G]);
  check('...the mark sits in the row opened', marked.marks[0].y, least - ROW_ABOVE - MARK_ROW / 2);
  check('...and the drawing grows to hold the last row', marked.contentHeight, least + 2 * G);
  checkTrue('...with the moved arrows copied and the rest by reference',
    marked.arrows[0] === layout.arrows[0] && marked.arrows[2] !== layout.arrows[2]);
}

// A lost segment on the first row drawn has no row above to sit between: it
// goes above the plot, after any mark about the stream's start.
{
  nextId = 1;
  const frames = [row(true, 'S'), row(false, 'SA'), row(true, 'A')];
  frames[1].analysisFlags = ['lost_segment'];
  const window = { from: frames[1].relativeTime, to: frames[2].relativeTime };
  const marked = markLadder(laidOut(frames, 480, window), frames, summaryWith(frames), true);
  check('a lost segment on the first row drawn is marked above the plot', kinds(marked), ['lost']);
  check('...in the row the plot moved down by', [marked.marks[0].y, marked.topRoom], [-MARK_ROW / 2, MARK_ROW]);
  check('...and the arrows stay on their ticks', ys(marked), [0, 480]);

  nextId = 501;
  const cut = [row(true, 'A', { len: 10 }), row(false, 'A', { len: 10 }), row(true, 'A', { len: 10 })];
  cut[0].analysisFlags = ['lost_segment'];
  const stacked = markLadder(laidOut(cut, 480), cut, summaryWith(cut, { firstId: 1 }), true);
  check('two marks above the plot stack, the stream\'s start first', kinds(stacked), ['ring-floor', 'lost']);
  check('...each in its own row', stacked.marks.map((m) => m.y), [-MARK_ROW * 1.5, -MARK_ROW / 2]);
  check('...and the plot moves down by both', stacked.topRoom, 2 * MARK_ROW);
}

// The end marker: only under the last frame, only once every frame is in,
// and only for a connection the capture left open.
{
  nextId = 1;
  const frames = [row(true, 'S'), row(false, 'SA'), row(true, 'A')];
  const layout = laidOut(frames, 480);
  const openEnded: TcpOutcome[] = ['open', 'closing', 'half-closed by client', 'half-closed by server'];
  const ended: TcpOutcome[] = ['closed cleanly', 'reset by client', 'reset by server', 'refused', 'no reply', 'handshake unfinished'];
  for (const outcome of openEnded) {
    const marked = markLadder(layout, frames, summaryWith(frames, { outcome }), true);
    check(`${outcome}: the state is unknown after the capture ended`, kinds(marked), ['open-end']);
    check('...said under the last row', marked.marks[0].y, 480 + ROW_BELOW + MARK_ROW / 2);
    check('...which the drawing grows to hold', marked.contentHeight, 480 + ROW_BELOW + MARK_ROW);
  }
  check('...in those words', markLadder(layout, frames, summaryWith(frames, { outcome: 'open' }), true).marks[0].text,
    'State unknown after the capture ended');
  for (const outcome of ended) {
    check(`${outcome}: nothing is unknown about the end`, kinds(markLadder(layout, frames, summaryWith(frames, { outcome }), true)), []);
  }
  check('while the stream is still loading, the last row is not the last frame: no end mark',
    kinds(markLadder(layout, frames, summaryWith(frames, { outcome: 'open' }), false)), []);
  const above = laidOut(frames, 480, { from: frames[0].relativeTime, to: frames[1].relativeTime });
  check('with the stream\'s end below the window, no end mark either',
    kinds(markLadder(above, frames, summaryWith(frames, { outcome: 'open' }), true)), []);
}

// Each side's state, on the row of the frame that moved it.
{
  /** The digest's own steps for these frames, from the real machine. */
  const stepsOf = (frames: readonly Packet[]): StreamStep[] => {
    const machine = new TcpStateMachine();
    const steps: StreamStep[] = [];
    for (const p of frames) {
      const side = p.sourcePort === CLIENT.port ? 'client' : 'server';
      for (const t of machine.apply(segmentOf(p, side))) steps.push({ ...t, frameId: p.id, time: p.relativeTime });
    }
    return steps;
  };

  // The handshake's third segment is a plain ACK under the same colour rule as
  // the data behind it, which is what folds it into their band.
  nextId = 1;
  const frames = [
    row(true, 'S', { seq: 0 }), row(false, 'SA', { seq: 0, ack: 1 }), row(true, 'A', { seq: 1, ack: 1, rule: 'data' }),
    ...data(50),
    row(true, 'FA', { seq: 5001, ack: 1 }), row(false, 'FA', { seq: 1, ack: 5002 }), row(true, 'A', { seq: 5002, ack: 2 }),
  ];
  const steps = stepsOf(frames);
  const layout = laidOut(frames, 4000);
  const rowOf = (id: number) => layout.arrows.find((a) => a.item.kind === 'frame' && a.item.packet.id === id)!.y;
  const band = layout.arrows.find((a) => a.item.kind === 'band')!;
  check('the frames under test fold the third handshake segment into the data band',
    band.item.kind === 'band' ? [band.item.first.id, band.item.last.id] : [], [3, 53]);

  const pills = lanePills(layout.arrows, steps);
  const brief = (p: { side: string; to: string; y: number; evidence: string; slot: number }) =>
    `${p.side} ${p.to} @${p.y} ${p.evidence} ${p.slot}`;
  check('every step of a closed connection is a pill, on the row of its frame', pills.map(brief), [
    `client SYN_SENT @${rowOf(1)} sent 0`,
    `server LISTEN @${rowOf(1)} inferred 0`,
    `server SYN_RCVD @${rowOf(2)} sent 0`,
    `client ESTABLISHED @${band.y} sent 0`,
    `server ESTABLISHED @${band.y} received 0`,
    `client FIN_WAIT_1 @${rowOf(54)} sent 0`,
    `server CLOSE_WAIT @${rowOf(54)} received 0`,
    `client FIN_WAIT_2 @${rowOf(55)} received 0`,
    `server LAST_ACK @${rowOf(55)} sent 0`,
    `server CLOSED @${rowOf(56)} received 0`,
    `client TIME_WAIT @${rowOf(56)} sent 0`,
  ]);
  checkTrue('...a step on a frame inside a band goes on the band\'s row',
    pills.filter((p) => p.to === 'ESTABLISHED').every((p) => p.y === band.y && p.frameId === 3));
  check('a state seen sent carries no note', pills.find((p) => p.to === 'SYN_SENT')!.note, null);
  check('one reached by receiving says the arrival was assumed',
    pills.find((p) => p.to === 'CLOSE_WAIT')!.note, 'assumed: the segment was seen, its arrival was not');
  check('one nothing on the wire shows says so',
    pills.find((p) => p.to === 'LISTEN')!.note, 'inferred: not visible on the wire');
  check('TIME_WAIT is expected, never observed',
    pills.find((p) => p.to === 'TIME_WAIT')!.text, 'TIME_WAIT (expected)');
  check('...and every other pill says its state', pills.filter((p) => p.to !== 'TIME_WAIT').map((p) => p.text),
    pills.filter((p) => p.to !== 'TIME_WAIT').map((p) => p.to));

  const close = laidOut(frames, 480, { from: frames[53].relativeTime, to: frames[55].relativeTime });
  check('a step whose frame is outside the window has no row, and no pill',
    lanePills(close.arrows, steps).map((p) => p.to),
    ['FIN_WAIT_1', 'CLOSE_WAIT', 'FIN_WAIT_2', 'LAST_ACK', 'CLOSED', 'TIME_WAIT']);
  check('no steps: no pills', lanePills(layout.arrows, []), []);

  // A SYN+ACK answering a SYN the capture missed takes the server through
  // LISTEN to SYN_RCVD in one frame: two pills on one lane, the state it is in
  // nearest the lane.
  nextId = 1;
  const missedSyn = [row(false, 'SA'), row(true, 'A'), ...data(5)];
  const two = lanePills(laidOut(missedSyn, 480).arrows, stepsOf(missedSyn));
  check('two states for one side on one frame are slotted, the later nearest the lane',
    two.filter((p) => p.frameId === 1).map(brief), [
      'server LISTEN @0 inferred 1',
      'server SYN_RCVD @0 sent 0',
      'client SYN_SENT @0 inferred 0',
    ]);
}

// --- Colour comes from the colour rules and nowhere else (Global Constraint) -------------------
{
  const dir = 'src/components/ladder';
  const files = readdirSync(join(root, dir)).filter((f) => /\.tsx?$/.test(f)).map((f) => `${dir}/${f}`);
  checkTrue('the ladder\'s sources are under test', files.includes(`${dir}/LadderView.tsx`));
  // A utility of one of the five hues, `text-rose-500` or `bg-sky-400`, is
  // the hue, a dash and a shade; the word alone would match "shared-".
  const hue = /\b(rose|sky|red|amber|fuchsia)-\d{2,3}\b/;
  for (const file of files) {
    const text = readFileSync(join(root, file), 'utf8');
    check(`${file} carries no rose, sky, red, amber or fuchsia utility`, text.match(hue)?.[0] ?? null, null);
    check(`${file} carries no --color-* literal`, text.includes('--color-'), false);
  }
  const view = readFileSync(join(root, `${dir}/LadderView.tsx`), 'utf8');
  checkTrue('the chip is painted by getPacketStyle', view.includes('colorEngine.getPacketStyle(packet, packetTheme)'));
  checkTrue('the fold is keyed by getMatchedRuleName', view.includes('colorEngine.getMatchedRuleName(p)'));
  checkTrue('and the one highlight is --primary', view.includes("'var(--primary)'"));

  // The state map beside it keeps the same discipline: its text is the
  // theme's currentColor through a text-* class, its path is --primary, and
  // no fill or stroke is a literal - so Day and Night are one drawing.
  checkTrue('the state map\'s source is under test', files.includes(`${dir}/TcpStateMap.tsx`));
  const map = readFileSync(join(root, `${dir}/TcpStateMap.tsx`), 'utf8');
  check('the state map paints no fill or stroke literal', map.match(/(?:fill|stroke)=["']#[0-9a-fA-F]/)?.[0] ?? null, null);
  checkTrue('...its text is currentColor', !/<text[^>]*fill=(?!"currentColor")/.test(map.replace(/\n\s*/g, ' ')));
  checkTrue('...its taken path is --primary', map.includes("'var(--primary)'"));
  checkTrue('...its current state is the rail\'s active fill, the accent at 20%', /fillOpacity=\{current \? 0\.2 : 1\}/.test(map));
  checkTrue('...and its caption is the ADR\'s', map.includes('States are inferred from one vantage point. Dashed: implied, not seen.'));
}

// --- Whether a page of progress reaches the views ------------------------------------------------
//
// The pane publishes a loading stream page by page. Two pages must never be
// published: one inside the flush interval of the last, and any page at all
// once the stream was left - a page of stream A resolving after stream B is on
// screen would put A's frames under B's summary, and the ladder would read
// B's first id against A's first frame as a ring floor.
{
  const signal = { cancelled: false };
  const gate = progressGate(signal, 100);
  check('the first page passes whenever it comes', gate(5), true);
  check('a page inside the interval does not', gate(50), false);
  check('...nor one a tick short of it', gate(104), false);
  check('one a full interval on does', gate(105), true);
  check('...and starts the next interval from itself', gate(150), false);
  signal.cancelled = true;
  check('after a cancel nothing passes', gate(1000), false);
  check('...however long it has been', gate(1e9), false);
  const fresh = progressGate({ cancelled: true }, 100);
  check('a gate made after the cancel passes nothing either', fresh(0), false);
}

// --- The pane's load wiring, read from its source ------------------------------------------------
//
// What follows is React state and effects, which plain `tsx` cannot drive; the
// rules are read from the source instead, as `scripts/session/view.ts` reads
// `App.tsx`. Each is a line whose absence fails silently on screen.
{
  const pane = readFileSync(join(root, 'src/components/stream-follower/StreamFollowerPane.tsx'), 'utf8');
  const hook = readFileSync(join(root, 'src/hooks/useStreamDigest.ts'), 'utf8');
  const loader = readFileSync(join(root, 'src/services/conversation/streamFrames.ts'), 'utf8');
  const view = readFileSync(join(root, 'src/components/ladder/LadderView.tsx'), 'utf8');

  // A new capture drops everything the pane keeps per stream, because every
  // one of those is keyed by a frame id and ids start again from one.
  checkTrue('the digest hook returns the capture it is answering for',
    /return \{ summaries, udp, quic, tls, dhcp, captureEnd, rebuilding, partial, captureId \}/.test(hook));
  const reset = pane.match(/const seenCapture = useRef\(captureId\);[\s\S]*?\}, \[captureId\]\);/)?.[0] ?? '';
  checkTrue('the pane has an effect keyed on the capture id', reset.length > 0);
  for (const call of ['cache.current.clear()', 'setStream(null)', 'setExpanded(NONE_EXPANDED)']) {
    checkTrue(`...which drops the per-stream state: ${call}`, reset.includes(call));
  }
  checkTrue('...declared before the load, so a commit that does both resets first',
    pane.indexOf('}, [captureId]);') < pane.indexOf('}, [captureId, summaryId]);'));
  // A load begun against a stale digest must not outlive the capture it was
  // begun under: the effect's cleanup cancels it when the capture id changes.
  checkTrue('the load is cancelled and begun again when the capture changes',
    pane.includes('}, [captureId, summaryId]);'));
  checkTrue('the digest hook keeps nothing across a disable',
    /return \(\) => \{\s*alive = false;[\s\S]*?setSummaries\(new Map\(\)\);\s*setUdp\(new Map\(\)\);\s*setQuic\(new Map\(\)\);\s*setTls\(new Map\(\)\);\s*setDhcp\(new Map\(\)\);\s*setCaptureEnd\(0\);\s*setCaptureId\(null\);\s*setRebuilding\(null\);\s*setPartial\(false\);\s*\};/.test(hook));

  // A page of a stream that was left is never published, and the summary goes
  // only with the frames it describes.
  checkTrue('the loader reports no page after a cancel', loader.includes('if (!signal?.cancelled) onProgress?.('));
  checkTrue('the pane publishes through the gate', pane.includes('progressGate(signal, PUBLISH_MS)') && pane.includes('if (!publish(performance.now())) return;'));
  checkTrue('the summary reaches the ladder only with frames read through it, and only a TCP one',
    pane.includes('summary={loaded !== null ? tcpSummary : null}'));
  checkTrue('...the state map is docked for a TCP summary alone, never for UDP or QUIC',
    /\{loaded !== null && tcpSummary !== null && \(\s*<>\s*\{\(docked \|\| mapOpen\) && \(\s*<aside/.test(pane) && !/<TcpStateMap\s+summary=\{summary\}/.test(pane));
  checkTrue('DNS marks wait for the last page: a query whose answer is on a later page is not marked no answer',
    pane.includes('hasDnsTally && !stillReading ? dnsMarks(frames, captureEnd, captureFinished)') && pane.includes('const stillReading = loaded?.loading != null;'));
  checkTrue('...the ladder is told what it is folding', pane.includes('kind={target.kind}') && view.includes("foldRuns(frames, client, ruleKeyOf, expanded, kind, notes)"));
  checkTrue('...and frames cached for a stream are keyed by kind as well as key',
    pane.includes('new Map<string, Packet[]>()') && pane.includes('streamKey(target.kind, target.streamId)'));
  checkTrue('...a QUIC connection\'s phase line scrolls through the state map\'s request',
    /label="QUIC phases"[\s\S]*?onPick=\{pickState\}/.test(pane));
  checkTrue('a failed read falls back to the buffer rather than reading "Reading 0 of N" for good',
    /\.catch\(\(error: unknown\) => \{[\s\S]*?setStream\(null\);/.test(pane));

  // A band closed over the selected frame stays closed until the selection
  // moves; a selected row that a later fold puts into a band opens it.
  // Keyed per source: the selection and the highlight by their id, the state
  // map by its request, so a second click on one state reopens a band the
  // user closed between.
  checkTrue('the ladder opens a band for an id once, not once per fold',
    view.includes('const autoOpened = useRef') && view.includes('if (key === autoOpened.current[source]) return;')
    && view.includes('[scrollToFrameId, scrollTo]'));
  checkTrue('...remembering only an id it opened a band for',
    view.includes("if (holder === 'row') { autoOpened.current[source] = undefined; return; }"));
  // The ladder draws nothing by direction, so the direction legend is the dialogue's alone.
  checkTrue('the direction legend is not shown over the ladder', /\{tab !== 'ladder' && \([\s\S]*?Client Traffic/.test(pane));
}

// --- Window and reveal decisions (final review I4, I5) --------------------------------------------
{
  nextId = 1;
  check('a different stream always chooses the window again',
    [rechoosesWindow('stream', false), rechoosesWindow('stream', true)], [true, true]);
  check('a page chooses it again while the user has not touched it',
    rechoosesWindow('page', false), true);
  check('...and not after a zoom, pan, minimap drag or state click',
    rechoosesWindow('page', true), false);

  check('a reveal waits while its row is not placed',
    revealStep(42, null, 100, 400), { pending: 42, scrollTop: 100 });
  check('...and is answered once the row is placed, scrolling just far enough',
    revealStep(42, { top: 480, bottom: 520 }, 100, 400), { pending: null, scrollTop: 120 });
  check('...answered even when the row was already in view (nothing to scroll)',
    revealStep(42, { top: 200, bottom: 240 }, 100, 400), { pending: null, scrollTop: 100 });
  check('no request, no scroll', revealStep(null, { top: 480, bottom: 520 }, 100, 400), { pending: null, scrollTop: 100 });

  const view = readFileSync(join(root, 'src/components/ladder/LadderView.tsx'), 'utf8');
  checkTrue('every user move of the window goes through takeWindow (wheel, pan buttons, minimap)',
    !/\bonWindow=\{setWindow\}/.test(view) && !/onClick=\{\(\) => setWindow/.test(view)
    && view.includes('onWindow={takeWindow}') && /takeWindow\(\(current\) => event\.shiftKey/.test(view));
  checkTrue('a state click marks the window taken',
    /scrolledRef\.current = scrollTo;[\s\S]{0,300}actedRef\.current = true;/.test(view));
  checkTrue('choosing the window again clears the answered state-map request',
    /scrolledRef\.current = null;\s*setWindow\(initialWindow/.test(view));
  checkTrue('pages go through the user-acted guard, a new stream resets it',
    view.includes("rechoose('page')") && view.includes("if (trigger === 'stream') actedRef.current = false;"));
  checkTrue('a reveal re-runs its layout effect on request, not on the next unrelated render',
    /\}, \[marked, plotTop, revealTick\]\);/.test(view) && view.includes('setRevealTick((t) => t + 1)')
    && !view.includes('revealRef.current = selectedId') && !view.includes('revealRef.current = scrollTo.frameId'));
}

// --- Frames kept by the pane, and the reader's chunk (final review I4) --------------------------
{
  const f = (n: number) => Array.from({ length: n }, () => ({}) as Packet);
  const kept = new Map<number, Packet[]>();
  keepFrames(kept, 1, f(1)); keepFrames(kept, 2, f(1));
  recallFrames(kept, 1);
  keepFrames(kept, 3, f(1));
  check('only the last two streams are kept, the one recalled surviving', [...kept.keys()], [1, 3]);
  check('a recall of a stream not kept finds nothing', recallFrames(kept, 2), undefined);
  keepFrames(kept, 4, f(KEPT_FRAMES_MAX + 1));
  check('a stream over the frame cap is not kept (and costs nobody else their place)', [...kept.keys()], [1, 3]);
  keepFrames(kept, 3, f(KEPT_FRAMES_MAX + 1));
  check('...and a kept stream that grew past it is dropped', [...kept.keys()], [1]);

  const reader = readFileSync(join(root, 'src/services/capture/captureReader.ts'), 'utf8');
  checkTrue('readRowsFor decodes through the one-chunk cache (scripts/capture/stream-reader.ts counts it)',
    /readRowsFor[\s\S]*?this\.rowsOfChunk\(chunk\)/.test(reader));
}

// --- UDP flows and QUIC connections (ADR 0055 stage 2) ------------------------------------------

/** A datagram of UDP flow 3, as the store would hand it back; `rule` as in `row`. */
function udpRow(fromClient: boolean, extra: Partial<Packet> & { rule?: string } = {}): Packet {
  const { rule, ...rest } = extra;
  const id = nextId++;
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
    source: fromClient ? '10.0.0.2' : '93.184.216.34', destination: fromClient ? '93.184.216.34' : '10.0.0.2',
    sourcePort: fromClient ? 50000 : 5353, destPort: fromClient ? 5353 : 50000,
    protocol: 'UDP', frameProtocols: ['eth', 'ethertype', 'ip', 'udp'],
    fields: { 'udp.stream': 3, ...(rule !== undefined ? { 'test.rule': rule } : {}) },
    length: 100, info: '', status: 'ok', ...rest,
  } as Packet;
}
const udpRun = (n: number, fromClient: boolean, rule = 'a') => Array.from({ length: n }, () => udpRow(fromClient, { rule }));

{
  nextId = 1;
  const frames = [
    ...udpRun(1, true), ...udpRun(10, true), ...udpRun(5, false), ...udpRun(4, true, 'b'), ...udpRun(1, false),
  ];
  for (const kind of ['udp', 'quic'] as const) {
    check(`a ${kind.toUpperCase()} band breaks on direction and on a rule change`,
      shape(foldRuns(frames, CLIENT, ruleKeyOf, NONE, kind)),
      ['frame', 'band(10)', 'band(5)', 'band(4)', 'frame']);
  }
  const udp = foldRuns(frames, CLIENT, ruleKeyOf, NONE, 'udp');
  check('...each band goes the way its frames went', udp.map((i) => i.from), ['client', 'client', 'server', 'client', 'server']);
  check('...in its own rule', udp.flatMap((i) => (i.kind === 'band' ? [i.ruleKey] : [])), ['a', 'a', 'b']);
  check('...and none carries riders, which is TCP\'s',
    udp.flatMap((i) => (i.kind === 'band' ? [i.acks] : [])), [0, 0, 0]);
}
{
  // A finding, a flag or an expert category breaks a band, and the frame stands alone.
  nextId = 1;
  const frames = [
    ...udpRun(1, true), ...udpRun(4, true),
    udpRow(true, { rule: 'a', analysisFlags: ['retransmission'] } as Partial<Packet>),
    ...udpRun(4, true),
    udpRow(true, { rule: 'a', fields: { 'udp.stream': 3, 'test.rule': 'a', 'inwire.expert.category': 'warning' } }),
    ...udpRun(4, true), ...udpRun(1, false),
  ];
  check('a UDP band breaks on an analysis flag and on an expert finding, which stand alone',
    shape(foldRuns(frames, CLIENT, ruleKeyOf, NONE, 'udp')),
    ['frame', 'band(4)', 'frame', 'band(4)', 'frame', 'band(4)', 'frame']);
  nextId = 1;
  const alternating = Array.from({ length: 12 }, (_, i) => udpRow(i % 2 === 0, { rule: 'a' }));
  check('...and alternating directions never fold', shape(foldRuns(alternating, CLIENT, ruleKeyOf, NONE, 'udp')),
    alternating.map(() => 'frame'));
  // standsAlone and isPureAck are TCP's: TCP fields on a UDP row mean nothing to a UDP band.
  nextId = 1;
  const withTcpFields = [
    ...udpRun(1, true),
    ...udpRun(3, true), udpRow(true, { rule: 'a', fields: { 'udp.stream': 3, 'test.rule': 'a', 'tcp.flags.fin': 1 } }), ...udpRun(3, true),
    udpRow(false, { rule: 'a', fields: { 'udp.stream': 3, 'test.rule': 'a', 'tcp.len': 0, 'tcp.flags.ack': 1 } }),
    ...udpRun(2, true), ...udpRun(1, false),
  ];
  check('...and a TCP flag or a bare ACK on a UDP row neither breaks a band nor rides one',
    shape(foldRuns(withTcpFields, CLIENT, ruleKeyOf, NONE, 'udp')), ['frame', 'band(7)', 'frame', 'band(2)', 'frame']);
  check('an opened UDP band is its frames', shape(foldRuns(frames, CLIENT, ruleKeyOf, new Set([frames[1].id]), 'udp')),
    ['frame', ...Array(4).fill('frame'), 'frame', 'band(4)', 'frame', 'band(4)', 'frame']);
}
{
  // Five unanswered queries in a row: each carries a `no answer` note, and a
  // band would hide the very marks the ladder draws them for.
  nextId = 1;
  const frames = [...udpRun(1, true), ...udpRun(5, true), ...udpRun(1, false)];
  const notes = new Map(frames.slice(1, 6).map((p) => [p.id, 'no answer'] as const));
  check('a frame with a note stands alone, so a run of unanswered queries keeps its marks',
    shape(foldRuns(frames, CLIENT, ruleKeyOf, NONE, 'udp', notes)), frames.map(() => 'frame'));
  check('...and without notes the same run folds', shape(foldRuns(frames, CLIENT, ruleKeyOf, NONE, 'udp')),
    ['frame', 'band(5)', 'frame']);
}
{
  // A TCP stream's pure ACK rides a band; a UDP datagram that merely looks like one does not.
  nextId = 1;
  const tcp = [row(true, 'A', { len: 100 }), ...data(4), row(false, 'A', { len: 0 }), ...data(4), row(true, 'FA')];
  check('TCP keeps its riders: the default kind folds a bare ACK into the band',
    foldRuns(tcp, CLIENT, ruleKeyOf, NONE).flatMap((i) => (i.kind === 'band' ? [i.acks] : [])), [1]);
  check('...and as an explicit tcp kind, the same',
    shape(foldRuns(tcp, CLIENT, ruleKeyOf, NONE, 'tcp')), shape(foldRuns(tcp, CLIENT, ruleKeyOf, NONE)));
}

{
  // A DHCP exchange's client is a MAC, which no frame's source is, so a lane
  // comes from the message type (ruling S3-7): a unicast renewal's request
  // comes from the offered address and still goes the client's way.
  nextId = 1;
  const MAC_CLIENT = { address: '02:00:00:00:00:01', port: 68 };
  const dhcpRow = (src: string, sport: number, dst: string, dport: number, type: number): Packet => {
    const id = nextId++;
    return {
      id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
      source: src, destination: dst, sourcePort: sport, destPort: dport,
      protocol: 'DHCP', frameProtocols: ['eth', 'ethertype', 'ip', 'udp', 'dhcp'],
      fields: { 'dhcp.id': 0xdeadbeef, 'dhcp.option.dhcp': type },
      length: 342, info: '', status: 'ok',
    } as unknown as Packet;
  };
  const frames = [
    dhcpRow('0.0.0.0', 68, '255.255.255.255', 67, 1),
    dhcpRow('192.0.2.1', 67, '192.0.2.50', 68, 2),
    dhcpRow('0.0.0.0', 68, '255.255.255.255', 67, 3),
    dhcpRow('192.0.2.1', 67, '192.0.2.50', 68, 5),
    dhcpRow('192.0.2.50', 68, '192.0.2.1', 67, 3),
    dhcpRow('192.0.2.7', 67, '192.0.2.1', 67, 5),
  ];
  const items = foldRuns(frames, MAC_CLIENT, ruleKeyOf, NONE, 'dhcp');
  check('a DHCP ladder draws a renewal\'s request from the client',
    items.map((i) => i.from), ['client', 'server', 'client', 'server', 'client', 'server']);
  check('...every exchange row is drawn as itself', shape(items), frames.map(() => 'frame'));
}

await (async () => {
  // loadStreamFrames: a flow reads through flowOrdinals, with its kind and key.
  nextId = 1;
  const disk = udpRun(400, true);
  const quicRam = (n: number, connection: number | null): Packet[] => Array.from({ length: n }, () => udpRow(true, {
    protocol: 'QUIC', frameProtocols: ['eth', 'ethertype', 'ip', 'udp', 'quic'],
    fields: { 'udp.stream': 9, ...(connection === null ? {} : { 'quic.connection.number': connection }) },
  }));
  const udpSummary = (frames: readonly Packet[]) => ({
    kind: 'udp', key: 3, firstId: frames[0].id, lastId: frames[frames.length - 1].id,
  }) as UdpSummary;

  const ram = [...disk.slice(350), ...udpRun(30, true)];
  // Past the last disk id and not this flow's: another udp.stream, a TCP row carrying
  // stream id 3, a QUIC connection, and a QUIC datagram with no connection number
  // (which is UDP stream 9 by the digest's rule, not stream 3).
  ram.push(udpRow(true, { fields: { 'udp.stream': 4 } }));
  ram.push(row(true, 'A', { streamId: 3 }));
  ram.push(...quicRam(2, 6), ...quicRam(1, null));
  const expected = [...disk, ...ram.slice(50, 80)];
  const source = fakeSource(disk, 300);
  const frames = await loadStreamFrames(udpSummary(expected), ram, source);
  check('loadStreamFrames reads a UDP flow through flowOrdinals, from chunk 0, then the next page',
    source.flowCalls.map((c) => [c[0], c[1], c[4]]), [['udp', 3, 0], ['udp', 3, 1]]);
  check('...with the summary\'s first and last id', [source.flowCalls[0][2], source.flowCalls[0][3]], [expected[0].id, expected[expected.length - 1].id]);
  check('...never asking the TCP request', source.ordinalCalls, []);
  check('...and the RAM tail is this flow\'s frames only, by the digest\'s routing', ids(frames), ids(expected));

  // A QUIC connection: the RAM tail is matched on its connection number.
  nextId = 1;
  const qdisk = quicRam(50, 6);
  const qram = [...qdisk.slice(40), ...quicRam(5, 6), ...quicRam(3, 7), ...udpRun(2, true)];
  const qsource = fakeSource(qdisk, 300);
  const quic = await loadStreamFrames(
    { kind: 'quic', key: 6, firstId: qdisk[0].id, lastId: qdisk[49].id } as QuicSummary, qram, qsource);
  check('a QUIC connection reads through flowOrdinals as quic', qsource.flowCalls.map((c) => [c[0], c[1]]), [['quic', 6]]);
  check('...its RAM tail is its own connection\'s frames', ids(quic), ids([...qdisk, ...qram.slice(10, 15)]));

  // Cancelling stops between pages exactly as it does for TCP.
  nextId = 1;
  const big = udpRun(900, true);
  const signal = { cancelled: false };
  const cancelling = fakeSource(big, 300);
  const progress: number[] = [];
  const partial = await loadStreamFrames(udpSummary(big), [], cancelling, (n) => { progress.push(n); signal.cancelled = true; }, signal);
  check('a cancelled flow read stops at the next boundary, as a TCP one does', [partial.length, cancelling.flowCalls.length], [256, 1]);

  // A sparse flow: pages with no frames still report how far the search has got.
  nextId = 1;
  const sparse = udpRun(3, true);
  const pages = [
    { ordinals: [] as number[], nextChunk: 1 as number | null, searched: 0.25 },
    { ordinals: [], nextChunk: 2, searched: 0.5 },
    { ordinals: [0, 1], nextChunk: 3, searched: 0.75 },
    { ordinals: [2], nextChunk: null, searched: 1 },
  ];
  const sparseSource = (onPage?: () => void): StreamFrameSource => ({
    streamOrdinals: () => Promise.resolve({ ordinals: [], nextChunk: null }),
    flowOrdinals(_kind, _key, _fromId, _toId, startChunk) { onPage?.(); return Promise.resolve(pages[startChunk]); },
    readRowsFor: (ordinals) => Promise.resolve(new Map(ordinals.map((o) => [o, sparse[o]]))),
  });
  const seen: [number, number | undefined][] = [];
  const loaded = await loadStreamFrames(udpSummary(sparse), [], sparseSource(),
    (n, _soFar, searched) => seen.push([n, searched]));
  check('a flow\'s progress moves on a page with no frames',
    seen, [[0, 0.25], [0, 0.5], [2, 0.75], [3, 1]]);
  check('...and the frames are still all there', ids(loaded), ids(sparse));

  const stop = { cancelled: false };
  const afterCancel: number[] = [];
  await loadStreamFrames(udpSummary(sparse), [], sparseSource(() => { if (afterCancel.length === 1) stop.cancelled = true; }),
    (n) => afterCancel.push(n), stop);
  check('...but not after a cancel', afterCancel, [0]);

  const tcp = data(5);
  const tcpArgs: unknown[][] = [];
  await loadStreamFrames(summaryOf(tcp), [], fakeSource(tcp, 300), (...args) => tcpArgs.push(args));
  check('a TCP stream\'s progress carries no searched fraction', tcpArgs.map((a) => a[2]), [undefined]);
})();

{
  const flow = (kind: 'udp' | 'quic') => ({ kind, client: { address: '10.0.0.2', port: 50000 }, server: { address: '93.184.216.34', port: 443 } }) as UdpSummary | QuicSummary;
  const target = (over: Partial<StreamTarget> = {}): StreamTarget => ({
    kind: 'udp', addressA: '10.0.0.2', portA: 50000, addressB: '93.184.216.34', portB: 443, streamId: 3, ...over,
  });
  checkTrue('a UDP summary of the target\'s two ends is its own', flowSummaryIsTarget(flow('udp'), target()));
  checkTrue('...whichever end the target names first', flowSummaryIsTarget(flow('udp'), target({
    addressA: '93.184.216.34', portA: 443, addressB: '10.0.0.2', portB: 50000,
  })));
  checkTrue('a QUIC summary is a QUIC target\'s', flowSummaryIsTarget(flow('quic'), target({ kind: 'quic' })));
  checkTrue('...and not a UDP target\'s, nor the other way round',
    !flowSummaryIsTarget(flow('quic'), target()) && !flowSummaryIsTarget(flow('udp'), target({ kind: 'quic' })));
  checkTrue('another port under the same key is another flow', !flowSummaryIsTarget(flow('udp'), target({ portA: 50001 })));
  checkTrue('a target with no key has no summary', !flowSummaryIsTarget(flow('udp'), target({ streamId: undefined })));
  checkTrue('a TCP target has no flow summary', !flowSummaryIsTarget(flow('udp'), target({ kind: 'tcp' })));
}

// --- A band's label names its riders ---------------------------------------------------------
{
  nextId = 1;
  const frames = [...handshake(), row(true, 'PA', { len: 200, rule: 'req' }), ...bulk(100), row(false, 'FA')];
  const band = laidOut(frames, 2000).arrows.find((a) => a.item.kind === 'band');
  check('a data band says how many ACKs rode along, apart from its frames and bytes',
    band?.info.replace(/ · [0-9.]+ s$/, ''), '100 frames · 103.5 KB · 50 ACKs');
  check('...and is as thick as its data, not its ACKs', band?.length, 1060);
  nextId = 1;
  const plain = laidOut([...handshake(), ...data(50), row(true, 'FA')], 2000).arrows.find((a) => a.item.kind === 'band');
  checkTrue('a band with no riders does not mention ACKs', plain !== undefined && !plain.info.includes('ACK'));
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All ladder run checks passed.');
process.exit(0);
