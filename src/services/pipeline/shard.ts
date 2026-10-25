/**
 * A TCP shard: one core's share of the capture's TCP connections, dissected in
 * frame order with trackers of its own (ADR 0053 phase 3).
 *
 * Everything numbered across connections arrives with each frame, already
 * decided by the coordinator, and is handed to these trackers through
 * `ShardSequencer` - so the dissector code is the single Worker's, unchanged,
 * and a frame's row, record and tree are what one core would have built.
 * `scripts/pipeline/parallel.ts` holds that, frame for frame.
 *
 * Plain TypeScript with no Worker API in it: the nested Worker
 * (`workers/pipeline.worker.ts`, in its shard role) is a thin adapter, and the
 * equality test drives this class directly.
 *
 * **The trees stay here.** A tree is ten times a frame's row, so the cache a
 * click on a recent frame is answered from is kept by the shard that built it,
 * and the coordinator asks for one tree when one is wanted (`detail`).
 */
import { TcpStreamTracker } from '../tcpStreamTracker';
import { IcmpEchoTracker } from '../icmpEchoTracker';
import { QuicFlowTracker } from '../quicFlowTracker';
import { DnsTracker } from '../dnsTracker';
import { L3Tracker } from '../l3Tracker';
import { LIVE_ENV, MAX_TOTAL_BODY_BYTES, type DissectEnv } from '../dissect/dissectEnv';
import { ShardSequencer, settleTreeTls } from '../dissect/shardNumbering';
import { applyInfoPatch } from '../dissect/infoPatch';
import { keyLog } from '../tls/keyLog';
import { FlowAnnotationStore } from '../flowAnnotations';
import { FrameDissector } from './frameDissector';
import { FifoMap } from './fifoMap';
import { packRows } from './rowPack';
import { rowSide, shardRowSteps } from './rowSteps';
import {
  OP_FORGET, OP_FRAGMENT, OP_TCP, readOps,
  type FromShard, type ShardInterface, type ShardResult, type ToShard, type WireFrame,
} from './shardProtocol';
import type { Packet, ProtocolLayer } from '../../types/packet';

export interface ShardOptions {
  /** How many shards share the capture: HTTP/1's body budget is split between them. */
  shards: number;
  /** Trees kept for the detail pane. */
  cacheFrames: number;
  /** The environment arrival reads; the live one when absent. */
  env?: DissectEnv;
  /** Send each frame's tree back with its row - the equality test only. */
  withTrees?: boolean;
}

/**
 * HTTP/1's shared body budget, split between the shards. ADR 0053 accepts it:
 * the budget only binds when more than 32 MB of bodies are being collected at
 * once, and each shard's share is recorded with its frames like the whole one
 * was, so a revisit agrees with arrival.
 */
export function shardEnv(base: DissectEnv, shards: number): DissectEnv {
  if (shards <= 1) return base;
  const withheld = MAX_TOTAL_BODY_BYTES - Math.floor(MAX_TOTAL_BODY_BYTES / shards);
  return {
    ...base,
    sharedBodyRoom: (atMost) => Math.min(atMost, base.sharedBodyRoom(MAX_TOTAL_BODY_BYTES) - withheld),
  };
}

export class Shard {
  private sequencer = new ShardSequencer();
  private dissector: FrameDissector;
  private epoch = 0;
  private readonly trees: FifoMap<ProtocolLayer[]>;
  private interfaces = new Map<number, ShardInterface>();
  /** Each adapter's clock, where the Worker knows it (`ShardInterface.tsPrecision`). */
  private precision = new Map<number, number>();
  private readonly env: DissectEnv;
  /**
   * The shard's copy of the Worker's socket table, so it annotates a row before
   * packing it (`rowSteps.ts`). Told by `flows`, emptied by `flowsClear`; a
   * capture's `reset` leaves it alone, because the Worker clears its own store
   * beside it and says so.
   */
  private readonly annotations = new FlowAnnotationStore();

  constructor(
    private readonly post: (message: FromShard, transfer: Transferable[]) => void,
    private readonly options: ShardOptions,
  ) {
    this.env = shardEnv(options.env ?? LIVE_ENV, options.shards);
    this.trees = new FifoMap(Math.max(1, options.cacheFrames));
    this.dissector = this.build();
  }

  private build(): FrameDissector {
    const sequencer = this.sequencer;
    return new FrameDissector({
      tcp: new TcpStreamTracker(sequencer),
      icmp: new IcmpEchoTracker(),
      quic: new QuicFlowTracker(),
      dns: new DnsTracker(),
      l3: new L3Tracker(sequencer),
    }, this.env, sequencer.tcp.tls);
  }

  handle(message: ToShard): void {
    switch (message.type) {
      case 'init':
        return;
      case 'batch':
        if (message.epoch !== this.epoch) {
          // Work for a capture since cleared: answered, so the coordinator's
          // count of what is in flight still comes back to zero.
          this.post({ type: 'results', epoch: message.epoch, results: [], pack: null }, []);
          return;
        }
        this.batch(message);
        return;
      case 'reset': {
        this.epoch = message.epoch;
        this.sequencer = new ShardSequencer();
        const host = this.dissector.host;
        this.dissector = this.build();
        this.dissector.host = host;
        this.trees.clear();
        return;
      }
      case 'host':
        this.dissector.host = {
          macs: new Set(message.macs), addresses: new Set(message.addresses),
          inferred: message.inferred, confidence: message.confidence, basis: message.basis,
        };
        return;
      case 'interfaces':
        // The record the dissector is handed is the single Worker's, name and
        // label; the clock is kept beside it.
        this.interfaces = new Map(message.interfaces.map(([id, { name, label }]) => [id, { name, label }]));
        this.precision = new Map(message.interfaces.flatMap(([id, { tsPrecision }]) =>
          (tsPrecision === undefined ? [] : [[id, tsPrecision] as const])));
        return;
      case 'keylog':
        keyLog.add(message.text);
        return;
      case 'keylogClear':
        keyLog.clear();
        // A cached tree can hold what the key log opened.
        this.trees.clear();
        return;
      case 'flows':
        // The Worker's clock, not this thread's: lives are stamped by it.
        this.annotations.apply(message.table, message.nowUs);
        return;
      case 'flowsClear':
        this.annotations.clear();
        return;
      case 'detail': {
        const tree = this.trees.get(message.id) ?? null;
        if (tree !== null) settleTreeTls(tree, (p) => this.sequencer.tcp.tls.resolve(p));
        this.post({ type: 'detail', requestId: message.requestId, layers: tree }, []);
        return;
      }
    }
  }

  private batch(message: Extract<ToShard, { type: 'batch' }>): void {
    const tls = this.sequencer.tcp.tls;
    for (const [placeholder, real] of message.settle ?? []) tls.settle(placeholder, real);
    for (const [id, rows] of message.rows ?? []) {
      const frame = this.trees.get(id)?.find((layer) => layer.name === 'Frame');
      if (frame) frame.fields.push(...rows);
    }
    for (const patch of message.patches ?? []) this.patchTree(patch);

    const results: ShardResult[] = [];
    // The batch's rows, in result order, and how long each one's bytes were.
    const rows: Packet[] = [];
    const capLengths: number[] = [];
    const transfer = new Set<ArrayBuffer>();
    for (const op of message.ops === null ? [] : readOps(message.ops)) {
      if (op.kind === OP_FORGET) {
        this.sequencer.tcp.drop(op.key!);
        this.dissector.trackers.tcp.forget(op.key!);
        continue;
      }
      const conversations = this.sequencer.conversations;
      conversations.eth.give(op.eth!.a, op.eth!.b, op.eth!.facts);
      conversations[op.family!].give(op.ip!.a, op.ip!.b, op.ip!.facts);
      if (op.kind === OP_TCP) this.sequencer.tcp.numbered(op.key!, op.streamId!);
      else this.sequencer.tcp.fragment(op.hint!);
      const [result, packet] = this.dissect(op.frame!);
      const report = this.sequencer.tcp.done();
      if (op.kind === OP_FRAGMENT) result.barrier = report ?? { created: false, streamAsked: false };
      conversations.clear();
      if (packet !== undefined) {
        // The bytes ride beside the pack, not in it: the row is packed without them.
        const bytes = packet.rawBytes;
        result.bytes = bytes;
        capLengths.push(bytes.length);
        packet.rawBytes = new Uint8Array(0);
        result.row = rows.length;
        rows.push(packet);
      }
      results.push(result);
      collect(result, transfer);
    }
    // One batch is at most MAX_BATCH frames, under the codec's cap. The pack's
    // key is the coordinator's to give: a shard does not know its own index.
    const pack = rows.length === 0 ? null : packRows(0, rows, capLengths);
    if (pack !== null) {
      for (const view of [pack.prefix, pack.summary]) whole(view, transfer);
    }
    this.post({ type: 'results', epoch: this.epoch, results, pack }, [...transfer]);
  }

  /** The frame's result, and its row (with its bytes, no tree) when it dissected. */
  private dissect(frame: WireFrame): [ShardResult, Packet?] {
    const id = frame.id;
    let result: ShardResult;
    let row: Packet | undefined;
    try {
      const d = this.dissector.dissect({
        id, bytes: frame.bytes, tsUs: frame.tsUs, relativeTime: frame.relativeTime, timeDelta: frame.timeDelta,
        origLen: frame.origLen, linktype: frame.linktype,
        iface: frame.iface === undefined ? undefined : this.interfaces.get(frame.iface),
        facts: frame.facts,
      });
      const packet = d.packet;
      const layers = packet.layers;
      // The clock `emitMerged` writes, by its rule - the adapter's, or 6 where
      // the Worker did not say (a miss in its table, and a frame with no
      // adapter, are both 6) - written here so it rides in the pack rather than
      // in an overlay on every row.
      const precision = (frame.iface === undefined ? undefined : this.precision.get(frame.iface)) ?? 6;
      packet.tsPrecision = precision;
      if (precision > 6) packet.tsNanos = BigInt(frame.tsUs) * 1000n + BigInt(frame.facts?.nanosRemainder ?? 0);
      // What `ingest` does next, on the tree still in hand: the process row and
      // a gap mark land in the cached tree and in the row about to be packed.
      shardRowSteps(packet, this.annotations, frame.facts?.holeBefore);
      const side = rowSide(packet, this.dissector.host);
      result = {
        id, record: d.record, derived: d.derived,
        ...(side !== undefined ? { side } : {}),
        ...(d.deferredAt.length > 0 ? { deferredAt: d.deferredAt } : {}),
        ...(d.icmpMatchedRequestFrameId !== undefined ? { icmpMatchedRequestFrameId: d.icmpMatchedRequestFrameId } : {}),
        ...(d.infoPatches ? { infoPatches: d.infoPatches } : {}),
        // After the steps, so the copy holds the rows they wrote.
        ...(this.options.withTrees ? { layers: structuredClone(layers) } : {}),
      };
      this.cache(id, layers);
      packet.layers = [];
      row = packet;
      // A tree still cached here gains the links this frame wrote, as the
      // single Worker's cache does.
      for (const patch of d.infoPatches ?? []) this.patchTree(patch);
    } catch (err) {
      result = { id, error: `failed to dissect a captured frame: ${String(err)}` };
    }
    const tls = this.dissector.takeTls();
    if (tls.length > 0) result.tls = tls;
    return [result, row];
  }

  private patchTree(patch: { frameId: number; links?: Record<string, number>; responseInFrame?: number }): void {
    const cached = this.trees.get(patch.frameId);
    if (cached !== undefined && (patch.links !== undefined || patch.responseInFrame !== undefined)) {
      applyInfoPatch({ layers: cached, info: '', fields: {} } as unknown as Packet, { ...patch, suffix: undefined });
    }
  }

  private cache(id: number, layers: ProtocolLayer[]): void {
    this.trees.set(id, layers);
  }
}

/** A result's buffers, for the transfer list: never one twice, never a view into a bigger one. */
export function collect(
  result: { bytes?: Uint8Array; record?: Uint8Array; derived?: Uint8Array | null },
  transfer: Set<ArrayBuffer>,
): void {
  for (const bytes of [result.bytes, result.record, result.derived]) whole(bytes, transfer);
}

/** A view's buffer, only when the view is all of it; any other is copied by the clone. */
function whole(bytes: Uint8Array | null | undefined, transfer: Set<ArrayBuffer>): void {
  if (!bytes || bytes.byteLength === 0) return;
  const buffer = bytes.buffer as ArrayBuffer;
  if (bytes.byteOffset !== 0 || bytes.byteLength !== buffer.byteLength) return;
  transfer.add(buffer);
}
