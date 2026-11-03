/**
 * What one shard spends a frame, on one thread with nothing else in the way.
 *
 *   node --expose-gc --import tsx scripts/perf/shard-cost.ts --pcap some.pcapng [--frames 100000] [--reps 7]
 *
 * `parallel-threads.ts` times shards on real threads, and on a machine that is
 * doing anything else its one-shard figure moved from 36.6 to 49.5 us a frame
 * between three runs of the same build - too far apart to see a 2% change in
 * the shard's own work (ADR 0053, "Shard skew"). This takes the threads and the
 * coordinator out of the timing: it records, once, every message a single
 * shard is sent for the capture (a real coordinator, the shard in-process,
 * their answers handed across by structured clone as a port would), then
 * replays those messages into a fresh `Shard` `--reps` times and reports the
 * fastest and the median. The fastest is the figure a cut is judged on: noise
 * only ever adds time.
 *
 * `--alloc-prof <file.heapprofile>` adds one replay under V8's sampling heap
 * profiler, collected objects included, and prints the bytes a frame each
 * function allocated: where the shard's collection time comes from.
 *
 * Under `--cpu-prof` the profile is the shard's work alone, reps included.
 * Run it under `node --import tsx` rather than `npx tsx` so `--expose-gc` and
 * `--cpu-prof` reach the process that does the work.
 *
 * A measurement, so not a test (`check.ts` NOT_TESTS).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { Session } from 'node:inspector';
import { PcapService } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { FrameClock, type Sequencer } from '../../src/services/dissect/sequencer';
import { LIVE_ENV } from '../../src/services/dissect/dissectEnv';
import { Coordinator, coordinatorSequencer, type CoordFrame } from '../../src/services/pipeline/coordinator';
import { Shard, shardEnv } from '../../src/services/pipeline/shard';
import type { FromShard, ToShard } from '../../src/services/pipeline/shardProtocol';

function arg(name: string): string | undefined {
  const at = process.argv.indexOf(name);
  return at > 0 ? process.argv[at + 1] : undefined;
}

const pcap = arg('--pcap');
if (!pcap) {
  console.log('usage: node --expose-gc --import tsx scripts/perf/shard-cost.ts --pcap some.pcapng [--frames 100000] [--reps 7]');
  process.exit(2);
}
const maxFrames = Number(arg('--frames') ?? 100_000);
const reps = Number(arg('--reps') ?? 7);
const allocProf = arg('--alloc-prof');
/** Frames handed to the coordinator at a time, as `parallel-threads.ts` does. */
const DISPATCH = 2048;
const gc = (globalThis as { gc?: () => void }).gc;

function trackers(sequencer: Sequencer) {
  return {
    tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(sequencer),
    dns: new DnsTracker(), l3: new L3Tracker(sequencer),
  };
}

async function main(): Promise<void> {
  const file = new File([new Uint8Array(readFileSync(pcap!))], 'capture.pcapng');
  const { frames } = await PcapService.extractFrames(file, maxFrames);
  const clock = new FrameClock();
  const inputs: CoordFrame[] = frames.map((frame, i) => {
    const { relativeTime, timeDelta } = clock.fromNanos(frame.tsNanos);
    return {
      id: i + 1, bytes: frame.rawBytes, tsUs: Number(frame.tsNanos / 1000n), relativeTime, timeDelta,
      origLen: frame.origLen, linktype: frame.linktype,
      facts: { nanosRemainder: frame.tsPrecision > 6 ? Number(frame.tsNanos % 1000n) : undefined },
    };
  });

  // Record: a coordinator and one in-process shard, every message cloned as a port would.
  const recorded: ToShard[] = [];
  const toShard: ToShard[] = [];
  const toCoordinator: FromShard[] = [];
  const live = new Shard((message, transfer) => {
    toCoordinator.push(structuredClone(message, { transfer: transfer as ArrayBuffer[] }));
  }, { shards: 1 });
  const sequencer = coordinatorSequencer();
  let merged = 0;
  const coordinator = new Coordinator({
    shards: 1, route: 'connection', trackers: trackers(sequencer), sequencer, env: shardEnv(LIVE_ENV, 1),
    ifaceOf: () => undefined,
    send: (_shard, message, transfer) => {
      const clone = structuredClone(message, { transfer: transfer as ArrayBuffer[] });
      recorded.push(structuredClone(clone));
      toShard.push(clone);
    },
    emit: () => { merged++; },
  });
  const deliver = () => {
    for (;;) {
      const out = toShard.shift();
      if (out !== undefined) live.handle(out);
      const back = toCoordinator.shift();
      if (back !== undefined) coordinator.receive(0, back);
      if (out === undefined && back === undefined) return;
    }
  };
  for (let i = 0; i < inputs.length; i += DISPATCH) {
    coordinator.dispatch(inputs.slice(i, i + DISPATCH).map((input) => ({ ...input, bytes: input.bytes.slice() })));
    deliver();
  }
  deliver();
  const onShard = coordinator.perLane[1];
  console.log(`${inputs.length.toLocaleString()} frames, ${onShard.toLocaleString()} on the shard, `
    + `${merged.toLocaleString()} merged, ${recorded.length} messages`);

  // Replay into a fresh shard, timed alone.
  const times: number[] = [];
  for (let rep = 0; rep < reps; rep++) {
    const messages = recorded.map((m) => structuredClone(m));
    const shard = new Shard(() => { /* the answers are not the measurement */ }, { shards: 1 });
    gc?.();
    const t0 = performance.now();
    for (const message of messages) shard.handle(message);
    times.push(performance.now() - t0);
  }
  const perFrame = times.map((ms) => (ms * 1000) / onShard);
  const sorted = [...perFrame].sort((a, b) => a - b);
  console.log(`us a frame: fastest ${sorted[0].toFixed(2)}, median ${sorted[Math.floor(sorted.length / 2)].toFixed(2)}`
    + ` (${perFrame.map((x) => x.toFixed(2)).join(' ')})${gc ? '' : '; no --expose-gc, so no collection between reps'}`);

  if (allocProf !== undefined) await allocations(recorded, onShard, allocProf);
}

/**
 * One more replay under V8's sampling heap profiler, counting what the
 * collector has already taken back (`--heap-prof` keeps only what is still
 * alive at exit, which says nothing about churn). Prints the bytes a frame
 * each function allocated, and writes the `.heapprofile` for DevTools.
 */
async function allocations(recorded: ToShard[], onShard: number, out: string): Promise<void> {
  const session = new Session();
  session.connect();
  const post = (method: string, params?: object) => new Promise<unknown>((resolve, reject) => {
    session.post(method, params ?? {}, (err, result) => (err ? reject(err) : resolve(result)));
  });
  const messages = recorded.map((m) => structuredClone(m));
  const shard = new Shard(() => { /* not the measurement */ }, { shards: 1 });
  await post('HeapProfiler.enable');
  await post('HeapProfiler.startSampling', {
    samplingInterval: 4096, includeObjectsCollectedByMajorGC: true, includeObjectsCollectedByMinorGC: true,
  });
  for (const message of messages) shard.handle(message);
  const { profile } = await post('HeapProfiler.stopSampling') as { profile: SamplingNode & object };
  session.disconnect();
  writeFileSync(out, JSON.stringify(profile));
  const self = new Map<string, number>();
  const walk = (node: SamplingNode) => {
    const where = `${node.callFrame.functionName || '(anonymous)'} ${node.callFrame.url.split('/').slice(-2).join('/')}`;
    self.set(where, (self.get(where) ?? 0) + node.selfSize);
    for (const child of node.children) walk(child);
  };
  walk((profile as unknown as { head: SamplingNode }).head);
  const total = [...self.values()].reduce((a, b) => a + b, 0);
  console.log(`allocated ${(total / onShard).toFixed(0)} bytes a frame (sampled); by function:`);
  for (const [where, bytes] of [...self].sort((a, b) => b[1] - a[1]).slice(0, 25)) {
    console.log(`  ${(bytes / onShard).toFixed(0).padStart(6)} B  ${(100 * bytes / total).toFixed(1).padStart(5)}%  ${where}`);
  }
}

interface SamplingNode {
  callFrame: { functionName: string; url: string };
  selfSize: number;
  children: SamplingNode[];
}

void main();
