/**
 * What lane 0 may hold while the shards are behind.
 *
 *   npx tsx scripts/pipeline/lane-zero-bound.ts
 *
 * Lane 0 dissects a frame the moment it is handed over and keeps the whole
 * result until every shard frame before it has merged. `PARALLEL_BACKLOG`
 * counted those frames and nothing counted what they held: on a capture of
 * TCP and QUIC, with the shards behind, the coordinator held 33-38k lane-0
 * results at 41 kB each and the renderer died out of heap (ADR 0053, phase 5).
 *
 * Held here: `laneZeroWaiting` is the sum of the waiting results'
 * `laneZeroCost`, back to zero when they merge or the capture is reset; the
 * flush's decisions, `parallelRoom` and `parallelRoomAgain`, stop at
 * `LANE_ZERO_WAITING_BYTES`; and a flush that follows them, with the one shard
 * never answering, stops within one slice of the limit instead of at 65,536
 * frames. The last block prints what a waiting result really retains beside
 * the estimate, and fails if the estimate is under it by a third or more.
 */
import { setFlagsFromString } from 'node:v8';
import { runInNewContext } from 'node:vm';
import { ipv4, ethernet, tcpFrame, udp } from '../parity/synthetic';
import {
  Coordinator, LANE_ZERO_WAITING_BYTES, PARALLEL_BACKLOG, coordinatorSequencer, flushTake, laneZeroCost,
  parallelRoom, parallelRoomAgain, type CoordFrame,
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
  }, { shards: 1, cacheFrames: 64, env: FIXED_ENV, withTrees: false });
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

/** A frame per id: id 1 a TCP segment for the shard, every later one a UDP datagram for lane 0. */
function frameAt(id: number): CoordFrame {
  const bytes = id === 1
    ? tcpFrame(40000, 443, 1, 1, new Uint8Array(32))
    : Uint8Array.from([
      ...ethernet(0x0800).build(),
      ...ipv4(17, udp(50000 + (id % 1000), 9999, new Uint8Array(64).fill(id & 0xff))),
    ]);
  return {
    id, bytes, tsUs: 1_000_000 + id, relativeTime: id / 1e6, timeDelta: 1e-6,
    origLen: bytes.length, linktype: 1, facts: {},
  };
}

console.log('\n--- what is counted, and when it is let go ---\n');
{
  const { coordinator, merged, deliver } = rig();
  const frames = Array.from({ length: 2000 }, (_, i) => frameAt(i + 1));
  coordinator.dispatch(frames);
  const owed = frames.slice(1).reduce((sum, f) => sum + laneZeroCost(f.bytes.length), 0);
  check('nothing merges while the shard frame before them is unanswered', merged.length === 0, `${merged.length} merged`);
  check('every lane-0 result waiting is counted at its estimate',
    coordinator.laneZeroWaiting === owed, `${coordinator.laneZeroWaiting} against ${owed}`);
  deliver();
  check('the shard answers and all 2,000 merge, in order',
    merged.length === 2000 && merged.every((id, i) => id === i + 1), `${merged.length} merged`);
  check('...and nothing is counted once they have', coordinator.laneZeroWaiting === 0, `${coordinator.laneZeroWaiting}`);

  coordinator.dispatch([{ ...frameAt(1), id: 2001 }, frameAt(2002)]);
  check('a lane-0 result behind a new shard frame is counted again', coordinator.laneZeroWaiting > 0);
  const fresh = coordinatorSequencer();
  coordinator.reset({ trackers: trackers(fresh), sequencer: fresh });
  check('a reset forgets what was waiting', coordinator.laneZeroWaiting === 0, `${coordinator.laneZeroWaiting}`);
}

console.log('\n--- the flush\'s two decisions ---\n');
{
  const at = (backlog: number, laneZeroWaiting: number) => ({ backlog, laneZeroWaiting });
  check('room is what was asked for when both are low', parallelRoom(4000, at(0, 0)) === 4000);
  check('the frame limit still bounds it', parallelRoom(4000, at(PARALLEL_BACKLOG - 10, 0)) === 10);
  check('no room once lane 0 holds its limit, however few frames that is',
    parallelRoom(4000, at(100, LANE_ZERO_WAITING_BYTES)) === 0);
  check('just under the limit, the frame count decides', parallelRoom(4000, at(100, LANE_ZERO_WAITING_BYTES - 1)) === 4000);
  check('a merge asks for a flush once both are under half', parallelRoomAgain(at(0, LANE_ZERO_WAITING_BYTES / 2 - 1)));
  check('...and not while lane 0 is still over half', !parallelRoomAgain(at(0, LANE_ZERO_WAITING_BYTES / 2)));
  check('...nor while the frames are', !parallelRoomAgain(at(PARALLEL_BACKLOG / 2, 0)));
}

console.log('\n--- a flush that follows them, with the shard never answering ---\n');
{
  setFlagsFromString('--expose-gc');
  const gc = runInNewContext('gc') as () => void;
  const { coordinator, merged, deliver } = rig();
  // The Worker's slice at 60,000 frames a second: SLICE_MS of them.
  const SLICE = 3000;
  let next = 1;
  gc();
  const before = process.memoryUsage().heapUsed;
  for (;;) {
    const take = parallelRoom(SLICE, coordinator);
    if (take === 0) break;
    coordinator.dispatch(Array.from({ length: take }, () => frameAt(next++)));
    if (next > PARALLEL_BACKLOG + 1) break;
  }
  gc();
  const retained = process.memoryUsage().heapUsed - before;
  const handed = next - 1;
  const waiting = coordinator.laneZeroWaiting;
  check('it stops before the frame limit', handed < PARALLEL_BACKLOG, `${handed} frames handed over`);
  check('it stops at the byte limit, within one slice',
    waiting >= LANE_ZERO_WAITING_BYTES && waiting < LANE_ZERO_WAITING_BYTES + SLICE * laneZeroCost(frameAt(2).bytes.length),
    `${(waiting / 2 ** 20).toFixed(0)} MiB estimated`);
  const perResult = retained / (handed - 1);
  const estimate = laneZeroCost(frameAt(2).bytes.length);
  check('the estimate is not under what a waiting result retains by a third',
    estimate >= perResult * 2 / 3, `${(perResult / 1024).toFixed(1)} kB retained, ${(estimate / 1024).toFixed(1)} kB estimated`);
  deliver();
  check('once the shard answers, every frame merges', merged.length === handed, `${merged.length} of ${handed}`);
  check('...and the flush is asked back', parallelRoomAgain(coordinator));
}

console.log('\n--- Stop, with everything that waited released at once ---\n');
{
  // Past the bound, frames wait in the Worker's `released`, up to main's
  // 256 MB credit. Stop used to hand all of them over in one call - one
  // synchronous dissection of every lane-0 frame while the shard frame before
  // them waited for an answer that call left no room to read.
  const SLICE = 3000;
  const stopped = { capturing: false, behind: false };
  check('a stop without shards still releases everything', flushTake(250_000, SLICE, stopped, null) === 250_000);
  check('a stop with shards takes a slice', flushTake(250_000, SLICE, stopped, { backlog: 0, laneZeroWaiting: 0 }) === SLICE);
  check('...and nothing while lane 0 holds its limit',
    flushTake(250_000, SLICE, stopped, { backlog: 0, laneZeroWaiting: LANE_ZERO_WAITING_BYTES }) === 0);
  check('a stop is not held back by a slow store, as before',
    flushTake(250_000, SLICE, { capturing: false, behind: true }, { backlog: 0, laneZeroWaiting: 0 }) === SLICE);
  check('while capturing a slow store still holds the flush',
    flushTake(250_000, SLICE, { capturing: true, behind: true }, { backlog: 0, laneZeroWaiting: 0 }) === 0);

  // The drain as the Worker runs it: take what the flush allows, and when it
  // allows nothing, let the shard answer.
  const { coordinator, merged, deliver } = rig();
  const total = 40_000;
  let next = 1;
  let peak = 0;
  while (next <= total) {
    const take = flushTake(total - next + 1, SLICE, stopped, coordinator);
    if (take === 0) { deliver(); continue; }
    coordinator.dispatch(Array.from({ length: take }, () => frameAt(next++)));
    peak = Math.max(peak, coordinator.laneZeroWaiting);
  }
  deliver();
  check('draining 40,000 waiting frames never holds more than the limit and one slice',
    peak < LANE_ZERO_WAITING_BYTES + SLICE * laneZeroCost(frameAt(2).bytes.length), `peak ${(peak / 2 ** 20).toFixed(0)} MiB`);
  check('...and every one of them merges, in order',
    merged.length === total && merged.every((id, i) => id === i + 1), `${merged.length} of ${total}`);
}

console.log(failures === 0 ? '\nAll lane-zero bound checks passed.' : `\n${failures} lane-zero bound check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
