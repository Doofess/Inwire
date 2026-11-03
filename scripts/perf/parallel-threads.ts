/**
 * Dissection on real threads: how fast the coordinator and N shards get
 * through a capture, against one core (ADR 0053 phase 3).
 *
 *   npx tsx scripts/perf/parallel-threads.ts --pcap some.pcapng [--shards 2,4,6]
 *     [--route connection|pair] [--in-flight 2] [--backlog-mb N | --backlog FRAMES]
 *
 * The coordinator runs here and each shard on a `worker_threads` thread, over
 * the same messages - structured clones, buffers transferred - the app's
 * nested Workers use. Every configuration dissects the capture twice and
 * times the second pass, so each thread's code is as warm as a capture a few
 * seconds in. One core is timed the same way.
 *
 * What it leaves out is the app's own traffic around a merged frame - the
 * post to the renderer and the records to the store - which the coordinator
 * pays with or without shards. So this is dissection's ceiling;
 * `ui-burst-drive.ts` is the app's.
 *
 * A measurement with no right answer, so not a test (`check.ts` NOT_TESTS).
 */
import { readFileSync } from 'node:fs';
import { Worker } from 'node:worker_threads';
import { performance as nodePerformance } from 'node:perf_hooks';
import { PcapService } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { FrameClock, Sequencer } from '../../src/services/dissect/sequencer';
import { LIVE_ENV } from '../../src/services/dissect/dissectEnv';
import { FrameDissector } from '../../src/services/pipeline/frameDissector';
import {
  Coordinator, PARALLEL_BACKLOG_FRAMES, coordinatorSequencer, parallelRoom, type CoordFrame, type ShardRoute,
} from '../../src/services/pipeline/coordinator';
import { shardEnv } from '../../src/services/pipeline/shard';
import type { FromShard, ToShard } from '../../src/services/pipeline/shardProtocol';

function arg(name: string): string | undefined {
  const at = process.argv.indexOf(name);
  return at > 0 ? process.argv[at + 1] : undefined;
}

const pcap = arg('--pcap');
if (!pcap) {
  console.log('usage: npx tsx scripts/perf/parallel-threads.ts --pcap some.pcapng [--shards 2,4,6] [--route connection|pair] [--in-flight 2]');
  process.exit(2);
}
const shardCounts = (arg('--shards') ?? '2,4,6').split(',').map(Number);
const route = (arg('--route') ?? 'connection') as ShardRoute;
const inFlight = Number(arg('--in-flight') ?? 2);
/** Frames handed to the coordinator at a time, as the Worker's flush does. */
const DISPATCH = 2048;
/**
 * How many frames dispatch may hand over now. By default the Worker's own
 * decision (`parallelRoom`: `PARALLEL_BACKLOG_BYTES`, `PARALLEL_BACKLOG_FRAMES`
 * and the lane-0 bound). `--backlog-mb N` moves the byte bound; `--backlog N`
 * replaces both with a frame count, for comparing with the runs made before
 * the bound counted bytes.
 */
const backlogFrames = arg('--backlog');
const backlogMb = arg('--backlog-mb');
function room(coordinator: Coordinator): number {
  if (backlogFrames !== undefined) return coordinator.backlog <= Number(backlogFrames) ? DISPATCH : 0;
  if (backlogMb !== undefined) {
    if (coordinator.inFlightBytes >= Number(backlogMb) * 1024 * 1024) return 0;
    return Math.max(0, Math.min(DISPATCH, PARALLEL_BACKLOG_FRAMES - coordinator.backlog));
  }
  return parallelRoom(DISPATCH, coordinator);
}

function trackers(sequencer: Sequencer) {
  return {
    tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(sequencer),
    dns: new DnsTracker(), l3: new L3Tracker(sequencer),
  };
}

type Stats = { type: 'stats'; handleMs: number; postMs: number; frames: number; utilization: number };

async function main(): Promise<void> {
  const file = new File([new Uint8Array(readFileSync(pcap!))], 'capture.pcapng');
  const { frames } = await PcapService.extractFrames(file, Number.POSITIVE_INFINITY);
  const clock = new FrameClock();
  const inputs = frames.map((frame, i) => {
    const { relativeTime, timeDelta } = clock.fromNanos(frame.tsNanos);
    return {
      id: i + 1, bytes: frame.rawBytes, tsUs: Number(frame.tsNanos / 1000n), relativeTime, timeDelta,
      origLen: frame.origLen, linktype: frame.linktype,
      facts: { nanosRemainder: frame.tsPrecision > 6 ? Number(frame.tsNanos % 1000n) : undefined },
    };
  });
  console.log(`${inputs.length.toLocaleString()} frames from ${pcap}`);

  // One core, as the single Worker dissects - its second pass.
  let oneCore = 0;
  for (let pass = 0; pass < 2; pass++) {
    const dissector = new FrameDissector(trackers(new Sequencer()), undefined, null);
    const t0 = performance.now();
    for (const input of inputs) {
      try {
        dissector.dissect({ ...input, bytes: input.bytes.slice() });
      } catch { /* the same frames fail either way */ }
    }
    oneCore = inputs.length / ((performance.now() - t0) / 1000);
  }
  console.log(`one core:                ${oneCore.toFixed(0).padStart(7)} frames/s  (${(1e6 / oneCore).toFixed(1)} us a frame)`);

  for (const shards of shardCounts) {
    const workers = Array.from({ length: shards }, () => new Worker(new URL('./parallelShard.ts', import.meta.url), {
      execArgv: process.env.SHARD_PROFILE ? ['--import', 'tsx', '--cpu-prof', `--cpu-prof-dir=${process.env.SHARD_PROFILE}`] : ['--import', 'tsx'],
    }));
    for (const worker of workers) worker.postMessage({ type: 'init', shards } satisfies ToShard);
    let merged = 0;
    let wake: (() => void) | null = null;
    const sequencer = coordinatorSequencer();
    const coordinator = new Coordinator({
      shards, route, trackers: trackers(sequencer), sequencer, env: shardEnv(LIVE_ENV, shards),
      maxInFlight: inFlight,
      ifaceOf: () => undefined,
      send: (shard, message, transfer) => workers[shard].postMessage(message, transfer as ArrayBuffer[]),
      emit: () => { merged++; },
    });
    let stats: string[] = [];
    workers.forEach((worker, s) => worker.on('message', (message: FromShard | Stats) => {
      if (message.type === 'stats') {
        stats.push(`shard ${s}: ${(message.utilization * 100).toFixed(0)}% busy, `
          + `${message.frames ? ((message.handleMs * 1000) / message.frames).toFixed(1) : '-'} us a frame handled, `
          + `${message.frames ? ((message.postMs * 1000) / message.frames).toFixed(1) : '-'} of it posting`);
      } else {
        coordinator.receive(s, message);
      }
      wake?.();
    }));

    let line = '';
    for (let pass = 0; pass < 2; pass++) {
      if (pass === 1) {
        const fresh = coordinatorSequencer();
        coordinator.reset({ trackers: trackers(fresh), sequencer: fresh });
        for (const worker of workers) worker.postMessage({ type: 'stats' });
        while (stats.length < shards) await new Promise<void>((resolve) => { wake = resolve; });
        stats = [];
      }
      merged = 0;
      const t0 = performance.now();
      const elu0 = nodePerformance.eventLoopUtilization();
      let dispatchMs = 0;
      let peakFrames = 0;
      let peakBytes = 0;
      for (let i = 0; i < inputs.length;) {
        // A whole chunk or nothing: the Worker's flush hands a slice at a time, and a
        // dribble of a few frames a merge makes tiny batches the shards pay for.
        const whole = Math.min(DISPATCH, inputs.length - i);
        let take = room(coordinator);
        while (take < whole) {
          await new Promise<void>((resolve) => { wake = resolve; });
          take = room(coordinator);
        }
        take = whole;
        wake = null;
        const chunk: CoordFrame[] = inputs.slice(i, i + take).map((input) => ({ ...input, bytes: input.bytes.slice() }));
        i += chunk.length;
        const c0 = performance.now();
        coordinator.dispatch(chunk);
        dispatchMs += performance.now() - c0;
        peakFrames = Math.max(peakFrames, coordinator.backlog);
        peakBytes = Math.max(peakBytes, coordinator.inFlightBytes);
        // The shards' answers come in between dispatches, as on the Worker's event loop.
        await new Promise((resolve) => setImmediate(resolve));
      }
      while (merged < inputs.length) await new Promise<void>((resolve) => { wake = resolve; });
      const rate = inputs.length / ((performance.now() - t0) / 1000);
      const elu = nodePerformance.eventLoopUtilization(elu0);
      line = `${shards} shards (${route}, ${inFlight} in flight): ${rate.toFixed(0).padStart(7)} frames/s, `
        + `${(rate / oneCore).toFixed(2)}x one core; lanes ${coordinator.perLane.join(' / ')}\n`
        + `        coordinator ${(elu.utilization * 100).toFixed(0)}% busy, ${((dispatchMs * 1000) / inputs.length).toFixed(1)} us a frame dispatching; `
        + `peak in flight ${peakFrames.toLocaleString()} frames, ${(peakBytes / 2 ** 20).toFixed(0)} MiB estimated`;
    }
    for (const worker of workers) worker.postMessage({ type: 'stats' });
    while (stats.length < shards) await new Promise<void>((resolve) => { wake = resolve; });
    console.log(line);
    for (const s of stats) console.log(`        ${s}`);
    for (const worker of workers) await worker.terminate();
  }
}

void main();
