/**
 * The frames in flight, counted by estimated bytes as well as by number.
 *
 *   npx tsx scripts/pipeline/backlog-bytes.ts
 *
 * One connection of a real burst is a fifth of its frames and one shard's work,
 * and at 65,536 frames in flight that connection's frames filled the allowance
 * while the other shards sat idle (ADR 0053, "Shard skew"). The flush now stops
 * on bytes - `PARALLEL_BACKLOG_BYTES` of `inFlightCost` - and on a high frame
 * cap, `PARALLEL_BACKLOG_FRAMES`, which bounds the entry map. Rows decoded at
 * the merge are counted with lane 0's results waiting (`DECODED_ROW_COST`).
 *
 * Held here: `inFlightBytes` is the sum of `inFlightCost` over frames
 * dispatched and not yet merged, markers not counted, and is back to exactly
 * zero after every merge, after a reset and after a shard dies; the flush's
 * decisions (`parallelRoom`, `parallelRoomAgain`) stop on bytes within one
 * slice, on the frame cap, and on the lane-0 bound, each alone; and a capture
 * of 60-byte frames is admitted past the old 65,536 and stopped at the cap.
 */
import { ethernet, ipv4, tcpFrame, udp } from '../parity/synthetic';
import {
  Coordinator, DECODED_ROW_COST, LANE_ZERO_WAITING_BYTES, PARALLEL_BACKLOG_BYTES, PARALLEL_BACKLOG_FRAMES, coordinatorSequencer,
  flushTake, inFlightCost, parallelRoom, parallelRoomAgain, type CoordFrame,
} from '../../src/services/pipeline/coordinator';
import { Shard, shardEnv } from '../../src/services/pipeline/shard';
import type { FromShard, ToShard } from '../../src/services/pipeline/shardProtocol';
import { FIXED_ENV, trackers } from './virtualShards';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` (${detail})` : ''}`);
}

/** One shard whose messages are held until `deliver` is called. */
function rig() {
  const toShard: ToShard[] = [];
  const toCoordinator: FromShard[] = [];
  const shard = new Shard((message, transfer) => {
    toCoordinator.push(structuredClone(message, { transfer: transfer as ArrayBuffer[] }));
  }, { shards: 1, env: FIXED_ENV, withTrees: false });
  const merged: number[] = [];
  const sequencer = coordinatorSequencer();
  const coordinator = new Coordinator({
    shards: 1, trackers: trackers(sequencer), sequencer, env: shardEnv(FIXED_ENV, 1),
    ifaceOf: () => undefined,
    send: (_, message, transfer) => { toShard.push(structuredClone(message, { transfer: transfer as ArrayBuffer[] })); },
    emit: (m) => { merged.push(m.id); },
  });
  const deliver = (): void => {
    for (;;) {
      if (toShard.length > 0) shard.handle(toShard.shift()!);
      else if (toCoordinator.length > 0) coordinator.receive(0, toCoordinator.shift()!);
      else return;
    }
  };
  return { coordinator, merged, deliver };
}

function frameOf(id: number, bytes: Uint8Array): CoordFrame {
  return {
    id, bytes, tsUs: 1_000_000 + id, relativeTime: id / 1e6, timeDelta: 1e-6,
    origLen: bytes.length, linktype: 1, facts: {},
  };
}

/** A TCP segment for the shard, `payload` bytes of data on a connection of its own. */
const segment = (id: number, payload: number): CoordFrame =>
  frameOf(id, tcpFrame(40000, 443, id, 1, new Uint8Array(payload)));

/** A UDP datagram, which lane 0 dissects. */
const datagram = (id: number, payload: number): CoordFrame =>
  frameOf(id, Uint8Array.from([
    ...ethernet(0x0800).build(), ...ipv4(17, udp(50000 + (id % 1000), 9999, new Uint8Array(payload).fill(id & 0xff))),
  ]));

/** The first fragment of a TCP datagram: the coordinator holds everything behind it until the shard answers. */
function fragment(id: number): CoordFrame {
  const bytes = tcpFrame(40001, 443, id, 1, new Uint8Array(40));
  bytes[14 + 6] |= 0x20; // more fragments
  return frameOf(id, bytes);
}

const costOf = (frames: readonly CoordFrame[]): number => frames.reduce((sum, f) => sum + inFlightCost(f.bytes.length), 0);

console.log('\n--- what is counted, and when it is let go ---\n');
{
  const { coordinator, merged, deliver } = rig();
  check('nothing is counted before a frame is handed over', coordinator.inFlightBytes === 0);
  const frames = [segment(1, 100), datagram(2, 300), segment(3, 1000), datagram(4, 64), segment(5, 6)];
  coordinator.dispatch(frames);
  check('a dispatched frame is counted at its cost, on a shard or on lane 0',
    coordinator.inFlightBytes === costOf(frames), `${coordinator.inFlightBytes} against ${costOf(frames)}`);
  check('the cost is the captured bytes and the overhead', inFlightCost(100) - inFlightCost(0) === 100 && inFlightCost(0) > 0);
  deliver();
  check('every frame merges, in order', merged.length === frames.length && merged.every((id, i) => id === i + 1), `${merged.length} merged`);
  check('...and nothing is counted once they have', coordinator.inFlightBytes === 0, `${coordinator.inFlightBytes}`);
}

{
  // A frame held behind a barrier is counted already, and a marker between frames never is.
  const { coordinator, merged, deliver } = rig();
  const frames = [fragment(1), segment(2, 50), datagram(3, 80), segment(4, 7)];
  coordinator.dispatch(frames);
  coordinator.broadcast({ type: 'flows', table: { full: true, procs: {}, add: [], gone: [] }, nowUs: 0 });
  // `backlog` counts the marker waiting in the queue (frames + 1): proof it is pending behind the barrier.
  check('frames waiting behind a barrier are counted, and a marker is not',
    coordinator.inFlightBytes === costOf(frames) && coordinator.backlog === frames.length + 1,
    `${coordinator.inFlightBytes} against ${costOf(frames)}, backlog ${coordinator.backlog}`);
  deliver();
  check('the barrier clears and all of them merge', merged.length === frames.length, `${merged.length} merged`);
  check('...and nothing is counted once they have', coordinator.inFlightBytes === 0, `${coordinator.inFlightBytes}`);
}

{
  // The cost is the one counted at dispatch, not read again from bytes that may
  // have moved on: frames held behind a barrier are routed later, and the
  // caller's buffers can be transferred away in between (3.1).
  const { coordinator, merged, deliver } = rig();
  const own = (frame: CoordFrame): CoordFrame => ({ ...frame, bytes: new Uint8Array(frame.bytes) });
  const frames = [fragment(1), own(segment(2, 300)), own(datagram(3, 500)), own(segment(4, 90))];
  const cost = costOf(frames);
  coordinator.dispatch(frames);
  for (const frame of frames.slice(1)) structuredClone(frame.bytes.buffer, { transfer: [frame.bytes.buffer as ArrayBuffer] });
  check('the frames behind the barrier lost their bytes before being routed', frames[1].bytes.length === 0);
  check('...and the count held at dispatch is not changed by it', coordinator.inFlightBytes === cost,
    `${coordinator.inFlightBytes} against ${cost}`);
  deliver();
  check('...so every one merges and the count returns to zero', merged.length === frames.length && coordinator.inFlightBytes === 0,
    `${merged.length} merged, ${coordinator.inFlightBytes} bytes`);
}

{
  const { coordinator } = rig();
  coordinator.dispatch([segment(1, 400), datagram(2, 400), segment(3, 400)]);
  check('frames are in flight before a reset', coordinator.inFlightBytes > 0);
  const fresh = coordinatorSequencer();
  coordinator.reset({ trackers: trackers(fresh), sequencer: fresh });
  check('a reset forgets what was in flight', coordinator.inFlightBytes === 0 && coordinator.backlog === 0,
    `${coordinator.inFlightBytes} bytes, ${coordinator.backlog} frames`);
  coordinator.dispatch([segment(10, 10)]);
  check('and counting starts again after it', coordinator.inFlightBytes === inFlightCost(segment(10, 10).bytes.length));
}

{
  // A shard that dies with frames in flight: those fail where they are, and a
  // frame routed after it goes to lane 0 (no shard is left to take it).
  const { coordinator, merged, deliver } = rig();
  const before = [segment(1, 100), segment(2, 100), datagram(3, 100), segment(4, 100)];
  coordinator.dispatch(before);
  check('four frames are in flight, none merged', coordinator.inFlightBytes === costOf(before) && merged.length === 0);
  coordinator.shardFailed(0, 'test');
  check('when the shard dies they fail and merge, and none stays counted',
    merged.length === before.length && coordinator.inFlightBytes === 0, `${merged.length} merged, ${coordinator.inFlightBytes} bytes`);
  const after = [segment(5, 200), segment(6, 200)];
  coordinator.dispatch(after);
  deliver();
  check('frames routed to lane 0 after it are counted and released as well',
    merged.length === before.length + after.length && coordinator.inFlightBytes === 0,
    `${merged.length} merged, ${coordinator.inFlightBytes} bytes`);
}

console.log('\n--- answered frames waiting behind the hot shard ---\n');
{
  // Skew's own state: one shard never answers, the other's frames are answered
  // and wait to merge behind it. With more than one interface each of them
  // holds a decoded row, measured at about 3.1 kB more than a light one
  // (`DECODED_ROW_COST`), which the bytes in flight do not count.
  const run = (decodeRows: boolean) => {
    const toShard: ToShard[][] = [[], []];
    const back: FromShard[] = [];
    const shards = [0, 1].map(() => new Shard((message, transfer) => {
      back.push(structuredClone(message, { transfer: transfer as ArrayBuffer[] }));
    }, { shards: 2, env: FIXED_ENV, withTrees: false }));
    const merged: number[] = [];
    const sequencer = coordinatorSequencer();
    const coordinator = new Coordinator({
      shards: 2, route: 'connection', trackers: trackers(sequencer), sequencer, env: shardEnv(FIXED_ENV, 2),
      ifaceOf: () => undefined,
      send: (s, message, transfer) => { toShard[s].push(structuredClone(message, { transfer: transfer as ArrayBuffer[] })); },
      emit: (m) => { merged.push(m.id); },
    });
    coordinator.decodeRows = decodeRows;
    const deliver = (s: number): void => {
      for (;;) {
        const out = toShard[s].shift();
        if (out !== undefined) shards[s].handle(out);
        const answer = back.shift();
        if (answer !== undefined) coordinator.receive(s, answer);
        if (out === undefined && answer === undefined) return;
      }
    };
    const hot = frameOf(1, tcpFrame(40000, 443, 1, 1, new Uint8Array(10)));
    const cold = Array.from({ length: 20 }, (_, i) => frameOf(i + 2, tcpFrame(40001, 443, i + 2, 1, new Uint8Array(10))));
    coordinator.dispatch([hot, ...cold]);
    const hotShard = toShard[0].length > 0 ? 0 : 1;
    deliver(1 - hotShard);
    const waiting = coordinator.laneZeroWaiting;
    deliver(hotShard);
    return { waiting, merged: merged.length, after: coordinator.laneZeroWaiting, bytes: coordinator.inFlightBytes };
  };
  const decoded = run(true);
  check('20 answered rows decoded and waiting are counted as results waiting to merge',
    decoded.waiting === 20 * DECODED_ROW_COST, `${decoded.waiting} against ${20 * DECODED_ROW_COST}`);
  check('...and let go when the hot shard answers and they merge',
    decoded.merged === 21 && decoded.after === 0 && decoded.bytes === 0, `${decoded.merged} merged, ${decoded.after} waiting`);
  const light = run(false);
  check('light rows (one interface) are not counted as decoded', light.waiting === 0 && light.merged === 21,
    `${light.waiting} waiting`);
  // A light answered frame holds about 0.7 kB of heap while it waits (measured
  // 643-756 B with each frame its own buffer), whatever its size: at the frame
  // cap, tiny frames are bounded by that and not by their bytes.
  check('the frame cap holds light answered frames to about 120 MB of heap',
    PARALLEL_BACKLOG_FRAMES * 768 <= 120 * 2 ** 20, `${((PARALLEL_BACKLOG_FRAMES * 768) / 2 ** 20).toFixed(0)} MiB`);
}

console.log('\n--- the flush\'s decisions ---\n');
{
  const at = (backlog: number, laneZeroWaiting: number, inFlightBytes: number) => ({ backlog, laneZeroWaiting, inFlightBytes });
  check('room is what was asked for when all three are low', parallelRoom(4000, at(0, 0, 0)) === 4000);
  check('no room once the bytes in flight reach the bound, however few frames',
    parallelRoom(4000, at(0, 0, PARALLEL_BACKLOG_BYTES)) === 0);
  check('one byte under, the whole slice goes (an overshoot of at most one slice)',
    parallelRoom(4000, at(0, 0, PARALLEL_BACKLOG_BYTES - 1)) === 4000);
  check('the frame cap bounds it too', parallelRoom(4000, at(PARALLEL_BACKLOG_FRAMES - 10, 0, 0)) === 10);
  check('no room at the frame cap', parallelRoom(4000, at(PARALLEL_BACKLOG_FRAMES, 0, 0)) === 0);
  check('the lane-0 bound still stops it alone', parallelRoom(4000, at(100, LANE_ZERO_WAITING_BYTES, 100)) === 0);
  check('...and one byte under it does not', parallelRoom(4000, at(100, LANE_ZERO_WAITING_BYTES - 1, 100)) === 4000);
  const burstFrame = inFlightCost(1114);
  check('the bound admits 131,072 frames of the burst\'s mean size',
    parallelRoom(1, at(131_071, 0, 131_071 * burstFrame)) === 1, `${(PARALLEL_BACKLOG_BYTES / 2 ** 20).toFixed(0)} MiB`);

  const half = { bytes: PARALLEL_BACKLOG_BYTES / 2, frames: PARALLEL_BACKLOG_FRAMES / 2, lane0: LANE_ZERO_WAITING_BYTES / 2 };
  check('a merge asks for a flush once bytes, frames and lane 0 are each under half',
    parallelRoomAgain(at(half.frames - 1, half.lane0 - 1, half.bytes - 1)));
  check('...and not while the bytes are at half', !parallelRoomAgain(at(0, 0, half.bytes)));
  check('...nor while the frames are', !parallelRoomAgain(at(half.frames, 0, 0)));
  check('...nor while lane 0 is', !parallelRoomAgain(at(0, half.lane0, 0)));

  const stopped = { capturing: false, behind: false };
  check('a stop with shards takes a slice inside the bytes bound',
    flushTake(250_000, 3000, stopped, at(0, 0, 0)) === 3000);
  check('...and nothing while the bytes are at the bound', flushTake(250_000, 3000, stopped, at(0, 0, PARALLEL_BACKLOG_BYTES)) === 0);
}

console.log('\n--- a flush that follows them, with the shard never answering ---\n');
{
  // 60-byte ACKs: a count bound of 65,536 held 4 MB of them; the bytes bound
  // lets many more in, and the frame cap still stops the flush.
  const { coordinator, merged, deliver } = rig();
  const SLICE = 3000;
  let next = 1;
  for (;;) {
    const take = parallelRoom(SLICE, coordinator);
    if (take === 0) break;
    coordinator.dispatch(Array.from({ length: take }, () => segment(next++, 6)));
  }
  const handed = next - 1;
  check('60-byte frames are admitted past the old 65,536', handed > 65_536, `${handed} frames handed over`);
  check('...and the frame cap stops the flush, within one slice',
    handed >= PARALLEL_BACKLOG_FRAMES && handed < PARALLEL_BACKLOG_FRAMES + SLICE, `${handed} against ${PARALLEL_BACKLOG_FRAMES}`);
  check('...with the bytes still well under their bound', coordinator.inFlightBytes < PARALLEL_BACKLOG_BYTES,
    `${(coordinator.inFlightBytes / 2 ** 20).toFixed(0)} MiB`);
  check('the flush is not asked back while it is over', !parallelRoomAgain(coordinator));
  deliver();
  check('once the shard answers every frame merges', merged.length === handed, `${merged.length} of ${handed}`);
  check('...nothing is counted, and the flush is asked back', coordinator.inFlightBytes === 0 && parallelRoomAgain(coordinator));
}

{
  // Large frames: the bytes bound stops the flush well before the frame cap.
  const { coordinator, deliver } = rig();
  const SLICE = 500;
  const big = new Uint8Array(tcpFrame(40000, 443, 1, 1, new Uint8Array(60_000)));
  let next = 1;
  for (;;) {
    const take = parallelRoom(SLICE, coordinator);
    if (take === 0) break;
    // One buffer shared by every frame: the coordinator copies what it sends and reads the rest.
    coordinator.dispatch(Array.from({ length: take }, () => frameOf(next++, big)));
  }
  const handed = next - 1;
  const bytes = coordinator.inFlightBytes;
  check('60 kB frames stop at the byte bound, far below the frame cap', handed < PARALLEL_BACKLOG_FRAMES / 4, `${handed} frames`);
  check('...within one slice of it', bytes >= PARALLEL_BACKLOG_BYTES && bytes < PARALLEL_BACKLOG_BYTES + SLICE * inFlightCost(big.length),
    `${(bytes / 2 ** 20).toFixed(0)} MiB`);
  deliver();
  check('...and they all merge and are let go', coordinator.inFlightBytes === 0 && coordinator.backlog === 0, `${coordinator.inFlightBytes}`);
}

console.log(failures === 0 ? '\nAll backlog-bytes checks passed.' : `\n${failures} backlog-bytes check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
