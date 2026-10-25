/**
 * The coordinator and its shards in one process, lifted out of
 * `scripts/pipeline/parallel.ts` so a second script can run a capture through
 * them and read what the merge emits (`scripts/capture/pack-native-equality.ts`).
 *
 * The real `Coordinator` and `Shard` classes, every message between them put
 * through `structuredClone` with its buffers transferred, as a `postMessage`
 * does, and delivered in a shuffled order across the shards, as real threads
 * would. Not an assertion script: it ends no process, so `check.ts` does not
 * run it on its own.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { Sequencer, FrameClock } from '../../src/services/dissect/sequencer';
import { LIVE_ENV, type DissectEnv } from '../../src/services/dissect/dissectEnv';
import { Coordinator, WatchedTcpOrder, type CoordFrame, type Merged, type ShardRoute } from '../../src/services/pipeline/coordinator';
import { Shard, shardEnv } from '../../src/services/pipeline/shard';
import type { FromShard, ToShard } from '../../src/services/pipeline/shardProtocol';
import type { FlowAnnotationStore } from '../../src/services/flowAnnotations';
import type { HostIdentity } from '../../src/services/direction';

/** The live environment with its clock stopped, so two runs' records can agree. */
export const FIXED_ENV: DissectEnv = { ...LIVE_ENV, now: () => new Date(Date.UTC(2026, 9, 8)) };

export interface Input {
  id: number; bytes: Uint8Array; tsUs: number; relativeTime: number; timeDelta: number;
  origLen: number; linktype: number; facts: { nanosRemainder?: number };
}

export interface Capture { name: string; inputs: Input[]; host: HostIdentity | undefined; keys: string | null }

export async function load(name: string, bytes: Uint8Array, keysPath?: string): Promise<Capture> {
  const file = new File([bytes], 'capture.pcap');
  const { frames } = await PcapService.extractFrames(file, Number.POSITIVE_INFINITY);
  const host = PcapService.inferHostFromFrames(frames);
  const clock = new FrameClock();
  const inputs = frames.map((frame, i) => {
    const { relativeTime, timeDelta } = clock.fromNanos(frame.tsNanos);
    return {
      id: i + 1, bytes: frame.rawBytes, tsUs: Number(frame.tsNanos / 1000n), relativeTime, timeDelta,
      origLen: frame.origLen, linktype: frame.linktype,
      facts: { nanosRemainder: frame.tsPrecision > 6 ? Number(frame.tsNanos % 1000n) : undefined },
    };
  });
  const keys = keysPath !== undefined && existsSync(keysPath) ? readFileSync(keysPath, 'utf8') : null;
  return { name, inputs, host, keys };
}

export function trackers(sequencer: Sequencer) {
  return {
    tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
    dns: new DnsTracker(), l3: new L3Tracker(sequencer),
  };
}

export type Table = Parameters<FlowAnnotationStore['apply']>[0];

/** A socket table, and the index of the first frame that arrives after it. */
export interface TableAt { at: number; table: Table }

/** A deterministic shuffle. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

export interface Config {
  label: string;
  shards: number;
  route: ShardRoute;
  assign?: () => (key: string, shards: number) => number;
}

export interface Stats {
  lanes: number[];
  crossLane: number;
  barrierMismatch: number;
  ms: number;
  /** Packs the coordinator decoded, packs the shards sent, and results whose side said `needsRow`. */
  packsDecoded: number;
  packs: number;
  needsRowResults: number;
}

export interface DriveOptions {
  /** Called with every frame the coordinator merges, in id order. */
  emit: (merged: Merged) => void;
  /** The coordinator's `decodeRows`: more than one interface. */
  decodeRows?: boolean;
  /** Shards send each frame's tree too (the equality test); the real Worker does not. Default true. */
  withTrees?: boolean;
  /** Broadcast this table once the frames before `at` are dispatched. */
  table?: TableAt;
  /** Broadcast a table and then `flowsClear` before any frame. */
  clearTable?: Table;
}

/** The coordinator and its shards, every message through a structured clone, delivered shuffled. */
export function drive(capture: Capture, config: Config, options: DriveOptions): Stats {
  const random = rng(capture.inputs.length * 31 + config.shards);
  const shardInbox: { message: ToShard }[][] = Array.from({ length: config.shards }, () => []);
  const coordInbox: { shard: number; message: FromShard }[] = [];
  let packs = 0;
  let needsRowResults = 0;
  const shards = Array.from({ length: config.shards }, (_, s) => new Shard((message, transfer) => {
    if (message.type === 'results') {
      if (message.pack !== null) packs++;
      for (const result of message.results) if (result.side?.needsRow) needsRowResults++;
    }
    coordInbox.push({ shard: s, message: structuredClone(message, { transfer: transfer as ArrayBuffer[] }) });
  }, { shards: config.shards, cacheFrames: 64, env: FIXED_ENV, withTrees: options.withTrees ?? true }));

  const sequencer = new Sequencer(new WatchedTcpOrder());
  const coordinator = new Coordinator({
    shards: config.shards,
    route: config.route,
    ...(config.assign ? { assign: config.assign() } : {}),
    trackers: trackers(sequencer),
    sequencer,
    env: shardEnv(FIXED_ENV, config.shards),
    ifaceOf: () => undefined,
    withTrees: options.withTrees ?? true,
    send: (shard, message, transfer) => {
      shardInbox[shard].push({ message: structuredClone(message, { transfer: transfer as ArrayBuffer[] }) });
    },
    emit: options.emit,
  });
  coordinator.decodeRows = options.decodeRows ?? false;
  coordinator.lane0.host = capture.host ?? coordinator.lane0.host;
  if (capture.host) {
    coordinator.broadcast({
      type: 'host', macs: [...capture.host.macs], addresses: [...capture.host.addresses],
      inferred: capture.host.inferred, confidence: capture.host.confidence, basis: capture.host.basis,
    });
  }

  const step = (): boolean => {
    const ready: number[] = [];
    for (let s = 0; s < config.shards; s++) if (shardInbox[s].length > 0) ready.push(s);
    if (coordInbox.length > 0) ready.push(-1);
    if (ready.length === 0) return false;
    const pick = ready[Math.floor(random() * ready.length)];
    if (pick === -1) {
      // Results from shards come back in any interleaving, but each shard's in its own order.
      const from = coordInbox[Math.floor(random() * coordInbox.length)].shard;
      const at = coordInbox.findIndex((m) => m.shard === from);
      const [{ shard, message }] = coordInbox.splice(at, 1);
      coordinator.receive(shard, message);
    } else {
      shards[pick].handle(shardInbox[pick].shift()!.message);
    }
    return true;
  };

  const t0 = performance.now();
  const CHUNK = 257;
  let tableSent = false;
  if (options.clearTable !== undefined) {
    // Told, then told to forget: no frame may be annotated.
    coordinator.broadcast({ type: 'flows', table: options.clearTable, nowUs: 0 });
    coordinator.broadcast({ type: 'flowsClear' });
  }
  const total = capture.inputs.length;
  const tableAt = options.table?.at ?? -1;
  for (let i = 0; i < total;) {
    // A chunk never straddles the table: the frames before it are dispatched, then it is broadcast.
    let end = Math.min(i + CHUNK, total);
    if (!tableSent && i < tableAt && tableAt < end) end = tableAt;
    if (!tableSent && options.table !== undefined && i === tableAt) {
      coordinator.broadcast({ type: 'flows', table: options.table.table, nowUs: 0 });
      tableSent = true;
    }
    const chunk: CoordFrame[] = capture.inputs.slice(i, end).map((input) => ({ ...input, bytes: input.bytes.slice() }));
    coordinator.dispatch(chunk);
    const steps = Math.floor(random() * 6);
    for (let k = 0; k < steps; k++) if (!step()) break;
    i = end;
  }
  while (step()) { /* until every message is delivered */ }
  let idle = false;
  coordinator.whenIdle(() => { idle = true; });
  if (!idle) throw new Error(`${config.label}: the coordinator never went idle (backlog ${coordinator.backlog})`);
  return {
    lanes: [...coordinator.perLane], crossLane: coordinator.crossLane,
    barrierMismatch: coordinator.barrierMismatch, ms: performance.now() - t0,
    packsDecoded: coordinator.packsDecoded, packs, needsRowResults,
  };
}

/** Every new connection to the next shard in turn. */
export function scatter(): (key: string, shards: number) => number {
  const seen = new Map<string, number>();
  return (key, shards) => {
    let shard = seen.get(key);
    if (shard === undefined) {
      shard = seen.size % shards;
      seen.set(key, shard);
    }
    return shard;
  };
}

/** Everything on one shard, but the first connection. */
export function lopsided(): (key: string, shards: number) => number {
  let first: string | undefined;
  return (key) => {
    first ??= key;
    return key === first ? 1 : 0;
  };
}

export const CONFIGS: Config[] = [
  { label: 'N=1 by pair', shards: 1, route: 'pair' },
  { label: 'N=2 by pair', shards: 2, route: 'pair' },
  { label: 'N=7 by pair', shards: 7, route: 'pair' },
  { label: 'N=2 by connection', shards: 2, route: 'connection' },
  { label: 'N=7 by connection', shards: 7, route: 'connection' },
  { label: 'N=7, each connection to the next shard', shards: 7, route: 'connection', assign: scatter },
  { label: 'N=2, all but the first connection on one shard', shards: 2, route: 'connection', assign: lopsided },
];
