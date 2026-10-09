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
  loadStreamFrames, type StreamFrameSource,
} from '../../src/services/conversation/streamFrames';
import { summaryIsTarget, type StreamTarget } from '../../src/services/followStream';
import { foldRuns, itemTime, type LadderItem } from '../../src/components/ladder/ladderRuns';
import { layoutLadder, type LadderLayout } from '../../src/components/ladder/ladderLayout';
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
  const frames = await loadStreamFrames(summaryOf(disk), [], source, undefined, signal);
  check('cancelled after the first page of rows: what it has is returned', frames.length, 256);
  check('...and no further page is asked for', [source.ordinalCalls, source.rowCalls], [[0], [256]]);

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

// A lost segment in a burst, where the rows are already at the minimum gap.
{
  nextId = 1;
  const frames = Array.from({ length: 5 }, (_, i) => row(i % 2 === 0, 'A', { len: 10 }));
  frames[2].analysisFlags = ['lost_segment'];
  const layout = laidOut(frames, 60);
  check('the layout under test is nudged to the minimum gap', layout.arrows.map((a) => a.y), [0, 26, 52, 78, 104]);
  const marked = markLadder(layout, frames, summaryWith(frames), true);
  const least = 26 + ROW_BELOW + MARK_ROW + ROW_ABOVE;
  check('the flagged row moves down to clear a marker row under the one above', ys(marked)[2], least);
  check('...and every row below it moves by the same amount', ys(marked), [0, 26, least, least + 26, least + 52]);
  check('...the rows above it do not', ys(marked).slice(0, 2), [0, 26]);
  check('...the mark sits in the row opened', marked.marks[0].y, least - ROW_ABOVE - MARK_ROW / 2);
  check('...and the drawing grows to hold the last row', marked.contentHeight, least + 52);
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
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All ladder run checks passed.');
process.exit(0);
