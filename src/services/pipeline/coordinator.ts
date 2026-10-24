/**
 * Dissection on several cores: the coordinator (ADR 0053 phase 3).
 *
 * The live capture's frames arrive in order on one Worker. This splits them:
 *
 *   - a plain TCP segment goes to a **shard**, chosen by its connection's
 *     routing key, which keeps every frame of one connection on one shard -
 *     that connection's state never has to be shared;
 *   - everything else is dissected **here**, on lane 0, by exactly the code
 *     the single Worker runs, with the real trackers.
 *
 * What makes the shards' output the single Worker's, frame for frame, is that
 * nothing a shard dissects is numbered by the shard. Everything counted across
 * conversations - `eth.stream`, `ip.stream`, `tcp.stream` and which
 * connection is forgotten past the cap - lives in the one `Sequencer` here,
 * and is numbered for every frame in frame order as it is dispatched; a shard
 * receives the numbers with the frame (`ShardSequencer`). Lane 0's own frames
 * number through the same Sequencer as they are dissected, which is also in
 * frame order, because lane 0 is dissected as it is dispatched.
 *
 * Three things cannot be numbered ahead, and each has its own rule:
 *
 *   - **`tls.stream`**, which a connection takes on its first TLS record:
 *     every lane hands out placeholders and the merge numbers them in frame
 *     order (`DeferredTlsNumbers`), correcting the field, the record and the
 *     cached tree of any frame dissected before the answer came back.
 *   - **An IP fragment of a TCP datagram**, whose connection is known only
 *     when the datagram reassembles. It goes to the shard holding the
 *     connection its first fragment names, as a barrier: nothing after it is
 *     numbered until that shard reports what its dissection did to the TCP
 *     order, and the coordinator then does the same.
 *   - **A connection lane 0 meets first** - a segment inside a tunnel, or one
 *     the header parse leaves sequential. It stays on lane 0 for good
 *     (`keyHome`), so its state is never split; the opposite case, a sharded
 *     connection that lane 0 later meets, is counted (`crossLane`) as the one
 *     way this build can differ from one core.
 *
 * Output is merged back into strict frame order before anything sees it, so
 * the records, patches and rows downstream are in the order they always were.
 *
 * Plain TypeScript, no Worker API: `send` and `receive` are the transport,
 * which is a nested Worker in the app and a function call in the equality
 * test (`scripts/pipeline/parallel.ts`).
 */
import { TcpOrder, DeferredTlsNumbers, type Sequencer } from '../dissect/sequencer';
import { frameLane, isTcpFragment, type TcpFragmentLane, type TcpLane } from '../dissect/frameLane';
import { settleTreeTls, type BarrierHint, type BarrierReport } from '../dissect/shardNumbering';
import { settleDeferredAnswers } from '../dissect/frameRecord';
import type { DissectEnv } from '../dissect/dissectEnv';
import { FrameDissector, type Dissected, type LaneTrackers } from './frameDissector';
import { OpWriter, type FromShard, type OpBatch, type ShardResult, type ToShard, type WireFrame } from './shardProtocol';
import { unpackRows, type RowPack } from './rowPack';
import { overlayMark, type OverlayMark, type RowOverlay } from './rowOverlay';
import type { RowSide } from './rowSteps';
import type { InfoPatch } from '../dissect/types';
import type { Packet, ProtocolField, ProtocolLayer } from '../../types/packet';

/** A frame handed to the coordinator, in id order. */
export interface CoordFrame extends WireFrame {
  /** The caller's own facts about the frame, handed back with it at the merge. */
  meta?: unknown;
}

/** One frame, merged back into order. */
export interface Merged {
  id: number;
  /** 0 for the coordinator's own lane, 1..N for the shards. */
  lane: number;
  meta: unknown;
  /** Absent when the frame failed to dissect. Lane 0's packet still has its tree. */
  packet?: Packet;
  record?: Uint8Array;
  derived?: Uint8Array | null;
  icmpMatchedRequestFrameId?: number;
  infoPatches?: InfoPatch[];
  error?: string;
  /** A shard frame's tree, for the equality test only (`withTrees`). */
  layers?: ProtocolLayer[];
  /**
   * A shard frame's row as the shard packed it: which pack, where in it, and
   * the covered keys as they were on unpacking. The mark is taken here, not in
   * the Worker, because `settleField` writes `tls.stream` before the Worker
   * sees the frame.
   */
  packed?: PackedRef;
  /**
   * A light shard row: `packet` is absent, the row stays in its pack. Its
   * bytes, its side record for the merge's order-dependent steps, and the
   * overlay the coordinator has already built - the settled `tls.stream`.
   */
  bytes?: Uint8Array;
  side?: RowSide;
  overlay?: RowOverlay;
}

export interface PackedRef {
  pack: RowPack;
  index: number;
  /** Absent for a light row, which was never decoded here: it has no covered values to compare. */
  mark?: OverlayMark;
}

/**
 * The routing key a connection is sharded by.
 *
 * `pair` is ADR 0053's: every connection between two addresses on one shard.
 * `connection` is each connection on its own, which spreads a download that
 * opens several connections to one server - most of a real burst - across
 * the shards instead of onto one.
 */
export type ShardRoute = 'pair' | 'connection';

export interface CoordinatorOptions {
  shards: number;
  route?: ShardRoute;
  /** Which shard a routing key goes to; a hash unless a test says otherwise. */
  assign?: (routeKey: string, shards: number) => number;
  /** Lane 0's trackers: the real ones, sharing `sequencer`, whose `tcp` must be a `WatchedTcpOrder`. */
  trackers: LaneTrackers;
  sequencer: Sequencer;
  /** The environment lane 0 dissects in; the live one when absent. */
  env?: DissectEnv;
  /** The adapter record lane 0 dissects a frame with. */
  ifaceOf: (iface: number | undefined) => { name: string; label: string } | undefined;
  send: (shard: number, message: ToShard, transfer: Transferable[]) => void;
  emit: (merged: Merged) => void;
  /** Batches a shard may hold at once (ADR 0053: two). */
  maxInFlight?: number;
  /** Ask shards for each frame's tree as it was dissected - the equality test. */
  withTrees?: boolean;
}

/** FNV-1a over a string: the default assignment. */
export function hashShard(routeKey: string, shards: number): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < routeKey.length; i++) {
    h ^= routeKey.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0) % shards;
}

/**
 * The real TCP order, watched: the lookups lane 0's own trackers make are
 * where the coordinator learns which connections live on lane 0, and which
 * connections a lane-0 lookup forgot that a shard holds.
 */
export class WatchedTcpOrder extends TcpOrder {
  /** Set by the coordinator; null while it numbers a shard's frame itself. */
  watcher: ((key: string, forgotten: readonly string[]) => void) | null = null;

  override locate(key: string): readonly string[] {
    const forgotten = super.locate(key);
    this.watcher?.(key, forgotten);
    return forgotten;
  }
}

interface Entry {
  lane: number;
  meta: unknown;
  done: boolean;
  d?: Dissected;
  result?: ShardResult;
  /** The shard's row for this frame, decoded when it had to be, and the pack it came from. */
  packet?: Packet;
  packed?: PackedRef;
  /** A light row's bytes and side record, from its result. */
  bytes?: Uint8Array;
  side?: RowSide;
  error?: string;
  tls?: number[];
}

/** How many datagrams' first fragments are remembered for their connection. */
const MAX_DATAGRAMS = 2048;
/** How far ahead a fragment that arrived before its first one is looked for. */
const LOOKAHEAD_FRAMES = 4096;

export class Coordinator {
  private readonly shards: number;
  private readonly route: ShardRoute;
  private readonly assign: ((routeKey: string, shards: number) => number) | null;
  /** Frames lately sent to each shard, halved every `LOAD_HALF_LIFE`: the assignment by load. */
  private readonly recent: number[];
  private sinceDecay = 0;
  private nextTurn = 0;
  private readonly maxInFlight: number;
  private order: WatchedTcpOrder;
  private sequencer: Sequencer;
  private readonly lane0Tls: DeferredTlsNumbers;
  /** Lane 0's dissection: the single Worker's, frame for frame. Its `host` is the caller's to set. */
  lane0: FrameDissector;

  private epoch = 0;
  /** Frames not yet routed, and the messages that go to the shards between them (`broadcast`). */
  private held: (CoordFrame | { marker: ToShard })[] = [];
  private heldFrom = 0;
  private barrier: { id: number; shard: number; hint: BarrierHint } | null = null;
  private readonly entries = new Map<number, Entry>();
  private nextEmit: number | null = null;
  /** Each shard's open batch, and the sealed ones waiting to be sent. */
  private writers: OpWriter[];
  /** Sealed batches, and the ordered messages that wait between them. */
  private ready: (OpBatch | ToShard)[][];
  private inFlight: number[];
  private settles: [number, number][][];
  private rows: [number, ProtocolField[]][][];
  private patches: InfoPatch[][];
  private readonly dead = new Set<number>();
  /** Which lane holds each connection: 0, or a shard's lane (shard + 1). */
  private readonly keyHome = new Map<string, number>();
  private readonly datagramKey = new Map<string, string>();
  private readonly datagramShard = new Map<string, number>();
  /** Placeholder to real `tls.stream`, per shard lane. */
  private tlsMaps: Map<number, number>[];
  private nextTls = 0;
  /** The next pack's key; never reset, so no two packs of one coordinator share one. */
  private nextPackKey = 0;
  /** Which shard lane holds a recent frame's tree, for `detail`. */
  private readonly treeLane: IdRing;
  private idleWaiters: (() => void)[] = [];

  /**
   * Decode every shard pack on arrival. Off, a pack is decoded only when a
   * result in it says `needsRow`, and every other shard row stays in its pack
   * for the merge to work from its side record. The Worker turns it on with
   * more than one interface, where `duplicates.scan` reads every row.
   */
  decodeRows = false;
  private decoded = 0;
  /** Connections a lane-0 lookup found already living on a shard: the one divergence. */
  crossLane = 0;
  /** Barrier reports that disagreed with what the coordinator's order said. */
  barrierMismatch = 0;
  /** Frames dissected on each lane, lane 0 first. */
  readonly perLane: number[];

  constructor(private readonly options: CoordinatorOptions) {
    this.shards = options.shards;
    this.route = options.route ?? 'pair';
    this.assign = options.assign ?? (this.route === 'pair' ? hashShard : null);
    this.recent = new Array(options.shards).fill(0);
    this.maxInFlight = options.maxInFlight ?? 2;
    this.lane0Tls = new DeferredTlsNumbers();
    [this.sequencer, this.order, this.lane0] = this.adopt(options.trackers, options.sequencer);
    this.writers = Array.from({ length: this.shards }, () => new OpWriter());
    this.ready = Array.from({ length: this.shards }, () => []);
    this.inFlight = new Array(this.shards).fill(0);
    this.settles = Array.from({ length: this.shards }, () => []);
    this.rows = Array.from({ length: this.shards }, () => []);
    this.patches = Array.from({ length: this.shards }, () => []);
    this.tlsMaps = Array.from({ length: this.shards + 1 }, () => new Map());
    this.perLane = new Array(this.shards + 1).fill(0);
    this.treeLane = new IdRing(8192 * (this.shards + 1));
  }

  /** Lane 0's trackers and the Sequencer they share, hooked up. */
  private adopt(trackers: LaneTrackers, sequencer: Sequencer): [Sequencer, WatchedTcpOrder, FrameDissector] {
    const order = sequencer.tcp;
    if (!(order instanceof WatchedTcpOrder)) throw new Error('coordinator: the sequencer needs a WatchedTcpOrder');
    order.deferredTls = this.lane0Tls;
    order.watcher = (key, forgotten) => this.laneZeroLookup(key, forgotten);
    const lane0 = new FrameDissector(trackers, this.options.env, this.lane0Tls);
    lane0.host = this.lane0?.host ?? lane0.host;
    return [sequencer, order, lane0];
  }

  /** The Sequencer lane 0 numbers through, whose clock the caller reads. */
  get clock(): Sequencer['clock'] {
    return this.sequencer.clock;
  }

  /** Packs decoded here since the start - the cost a light run avoids (`decodeRows`). */
  get packsDecoded(): number {
    return this.decoded;
  }

  /** Frames dispatched, or waiting to be, that have not been merged. */
  get backlog(): number {
    return this.held.length - this.heldFrom + this.entries.size;
  }

  /** Hands frames over, in ascending contiguous id order. */
  dispatch(frames: readonly CoordFrame[]): void {
    for (const frame of frames) this.held.push(frame);
    this.advance();
    this.pump();
  }

  /** A message from shard `shard`. */
  receive(shard: number, message: FromShard): void {
    if (message.type !== 'results') return;
    if (message.epoch !== this.epoch) return;
    this.inFlight[shard] = Math.max(0, this.inFlight[shard] - 1);
    let barrierCleared = false;
    // Decoded once for the whole message, and only when the merge has to read
    // the rows (`decodeRows`, or a result whose protocols `networkFacts` reads
    // whole). A pack with one such row is decoded entire, and each row of it
    // then takes the decoded path: its side record is ignored, so nothing is
    // counted twice. The key is the coordinator's to give: a shard does not
    // know its own index, and it must not repeat across epochs.
    let rows: Packet[] | null = null;
    let pack: RowPack | null = null;
    if (message.pack !== null) {
      pack = message.pack;
      pack.key = this.nextPackKey++;
      if (this.decodeRows || message.results.some((result) => result.side?.needsRow)) {
        rows = unpackRows(pack);
        this.decoded += 1;
      }
    }
    for (const result of message.results) {
      const entry = this.entries.get(result.id);
      if (entry === undefined) continue;
      entry.result = result;
      if (result.row !== undefined && pack !== null) {
        if (rows !== null) {
          const packet = rows[result.row];
          packet.rawBytes = result.bytes ?? new Uint8Array(0);
          entry.packet = packet;
          entry.packed = { pack, index: result.row, mark: overlayMark(packet) };
        } else {
          // Light: the row stays where the shard put it.
          entry.packed = { pack, index: result.row };
          entry.bytes = result.bytes ?? new Uint8Array(0);
          if (result.side !== undefined) entry.side = result.side;
        }
      }
      entry.done = true;
      if (this.barrier !== null && this.barrier.id === result.id) {
        this.settleBarrier(result.barrier);
        barrierCleared = true;
      }
    }
    this.drain();
    if (barrierCleared) this.advance();
    this.pump();
    this.checkIdle();
  }

  /** A shard died: its frames fail, and its connections start again on lane 0. */
  shardFailed(shard: number, reason: string): void {
    if (this.dead.has(shard)) return;
    this.dead.add(shard);
    const lane = shard + 1;
    for (const [key, home] of this.keyHome) if (home === lane) this.keyHome.set(key, 0);
    this.writers[shard] = new OpWriter();
    this.ready[shard] = [];
    this.inFlight[shard] = 0;
    this.recent[shard] = 0;
    for (const entry of this.entries.values()) {
      if (entry.lane === lane && !entry.done) {
        entry.done = true;
        entry.error = `failed to dissect a captured frame: shard ${shard} stopped (${reason})`;
      }
    }
    if (this.barrier !== null && this.barrier.shard === shard) this.barrier = null;
    this.drain();
    this.advance();
    this.pump();
    this.checkIdle();
  }

  /** Called once nothing is held, in flight or waiting to merge. */
  whenIdle(callback: () => void): void {
    this.idleWaiters.push(callback);
    this.checkIdle();
  }

  /**
   * Everything forgotten: a new capture, with lane 0's trackers and Sequencer
   * new too. Shards are told to start again.
   */
  reset(lane0: { trackers: LaneTrackers; sequencer: Sequencer }): void {
    this.epoch += 1;
    this.lane0Tls.reset();
    [this.sequencer, this.order, this.lane0] = this.adopt(lane0.trackers, lane0.sequencer);
    this.held = [];
    this.heldFrom = 0;
    this.barrier = null;
    this.entries.clear();
    this.nextEmit = null;
    for (let s = 0; s < this.shards; s++) {
      this.writers[s] = new OpWriter();
      this.ready[s] = [];
      this.inFlight[s] = 0;
      this.recent[s] = 0;
      this.settles[s] = [];
      this.rows[s] = [];
      this.patches[s] = [];
      if (!this.dead.has(s)) this.options.send(s, { type: 'reset', epoch: this.epoch }, []);
    }
    this.keyHome.clear();
    this.datagramKey.clear();
    this.datagramShard.clear();
    this.tlsMaps = Array.from({ length: this.shards + 1 }, () => new Map());
    this.nextTls = 0;
    this.treeLane.clear();
    this.lane0Tls.reset();
    this.crossLane = 0;
    this.barrierMismatch = 0;
    this.perLane.fill(0);
    this.checkIdle();
  }

  /** Something every shard must hear: the key log, the host, the adapters. */
  broadcast(message: ToShard): void {
    if (message.type !== 'flows') {
      for (let s = 0; s < this.shards; s++) if (!this.dead.has(s)) this.options.send(s, message, []);
      return;
    }
    // A socket table has a place in the frame order: a shard must annotate a
    // frame dispatched before it without it, and one dispatched after with it,
    // as the single Worker does. So it waits behind the frames not yet routed,
    // and then behind every batch already queued for a shard.
    if (this.heldFrom < this.held.length) this.held.push({ marker: message });
    else this.sendOrdered(message);
    this.pump();
  }

  /** `message`, to every shard, behind each frame routed to it so far and ahead of any routed later. */
  private sendOrdered(message: ToShard): void {
    for (let s = 0; s < this.shards; s++) {
      if (this.dead.has(s)) continue;
      if (!this.writers[s].empty) this.sealWriter(s);
      if (this.ready[s].length === 0) this.options.send(s, message, []);
      else this.ready[s].push(message);
    }
  }

  /** The shard (0-based) holding a recent frame's tree, or null for lane 0 or a frame no longer known. */
  treeShard(id: number): number | null {
    const lane = this.treeLane.get(id);
    return lane === undefined ? null : lane - 1;
  }

  /** Before a request to a shard that must see what the merge has sent it. */
  flushSide(shard: number): void {
    this.sendBatch(shard, null);
  }

  /** Rows the merge added to a shard frame's Frame layer. */
  frameRows(lane: number, id: number, rows: ProtocolField[]): void {
    if (lane === 0 || rows.length === 0) return;
    this.rows[lane - 1].push([id, rows]);
  }

  /**
   * Later frames' links into earlier trees, sent to whichever lane caches the
   * earlier one. A shard has already applied its own frames' links to its own
   * trees; lane 0's are applied by `local`.
   */
  routePatches(fromLane: number, patches: readonly InfoPatch[], local: (patch: InfoPatch) => void): void {
    for (const patch of patches) {
      if (patch.links === undefined && patch.responseInFrame === undefined) continue;
      const lane = this.treeLane.get(patch.frameId) ?? 0;
      if (lane === fromLane && lane !== 0) continue;
      if (lane === 0) local(patch);
      else this.patches[lane - 1].push({ ...patch, suffix: undefined });
    }
  }

  /** The real number for one of lane 0's placeholders, for a cached tree. */
  resolveLaneZero(placeholder: number): number {
    return this.lane0Tls.resolve(placeholder);
  }

  // --- dispatch -------------------------------------------------------------

  private advance(): void {
    while (this.barrier === null && this.heldFrom < this.held.length) {
      const frame = this.held[this.heldFrom++];
      if ('marker' in frame) {
        this.sendOrdered(frame.marker);
        continue;
      }
      if (this.nextEmit === null) this.nextEmit = frame.id;
      const lane = frameLane(frame.bytes, frame.linktype);
      if (lane.lane === 'tcp') this.routeSegment(frame, lane);
      else if (isTcpFragment(lane)) this.routeFragment(frame, lane);
      else this.dissectHere(frame);
    }
    if (this.heldFrom === this.held.length) {
      this.held = [];
      this.heldFrom = 0;
    } else if (this.heldFrom > 4096) {
      this.held = this.held.slice(this.heldFrom);
      this.heldFrom = 0;
    }
  }

  /**
   * The shard a connection with no home yet goes to, or null to keep it here.
   *
   * By connection, it is the shard that has lately been sent the fewest frames,
   * the next in turn on a tie - which spreads a download's connections, opened
   * together, one to a shard, and sends one opened later to whichever shard the
   * heavy ones left. Measured on the burst ADR 0053 was written for, where six
   * connections carried 94% of it: a hash put the two heaviest on one shard of
   * seven, 44% of the capture. Which shard is never an answer anyone reads -
   * every arrangement dissects to the same output (`scripts/pipeline/parallel.ts`).
   */
  private shardFor(routeKey: string): number | null {
    let shard: number;
    if (this.assign !== null) {
      shard = this.assign(routeKey, this.shards);
    } else {
      let best = -1;
      for (let i = 0; i < this.shards; i++) {
        const candidate = (this.nextTurn + i) % this.shards;
        if (this.dead.has(candidate)) continue;
        if (best === -1 || this.recent[candidate] < this.recent[best]) best = candidate;
      }
      if (best === -1) return null;
      this.nextTurn = (best + 1) % this.shards;
      return best;
    }
    if (!this.dead.has(shard)) return shard;
    for (let i = 1; i < this.shards; i++) {
      shard = (shard + 1) % this.shards;
      if (!this.dead.has(shard)) return shard;
    }
    return null;
  }

  private routeSegment(frame: CoordFrame, lane: TcpLane): void {
    const home = this.keyHome.get(lane.key);
    const shard = home === undefined ? this.shardFor(this.route === 'pair' ? lane.pair : lane.key) : home - 1;
    if (shard === null || shard < 0) {
      this.dissectHere(frame);
      return;
    }
    const conversations = this.sequencer.conversations;
    const eth = conversations.eth.observe(lane.srcMac, lane.dstMac, frame.tsUs);
    const ip = conversations[lane.family].observe(lane.src, lane.dst, frame.tsUs);
    this.locateFor(lane.key, shard);
    const streamId = this.order.streamId(lane.key);
    this.writers[shard].tcp(frame, lane.family,
      { a: lane.srcMac, b: lane.dstMac, facts: eth }, { a: lane.src, b: lane.dst, facts: ip }, lane.key, streamId);
    this.queued(shard);
    this.entries.set(frame.id, { lane: shard + 1, meta: frame.meta, done: false });
  }

  private routeFragment(frame: CoordFrame, lane: TcpFragmentLane): void {
    if (lane.key !== undefined) this.rememberDatagram(lane.datagram, lane.key);
    const key = lane.key ?? this.datagramKey.get(lane.datagram) ?? this.lookAhead(lane.datagram);
    const home = key === undefined ? undefined : this.keyHome.get(key);
    // Every fragment of a datagram to one place, or it never reassembles: a
    // connection that is new has no home until the datagram completes, and an
    // assignment by load would answer each fragment differently.
    const shard = home !== undefined
      ? home - 1
      : this.datagramShard.get(lane.datagram)
        ?? this.shardFor(this.route === 'pair' || key === undefined ? lane.pair : key);
    if (shard !== null && shard >= 0) {
      this.datagramShard.set(lane.datagram, shard);
      if (this.datagramShard.size > MAX_DATAGRAMS) {
        // Small and short-lived: a datagram's fragments arrive together.
        const oldest = this.datagramShard.keys().next();
        if (!oldest.done) this.datagramShard.delete(oldest.value);
      }
    }
    if (shard === null || shard < 0) {
      this.dissectHere(frame);
      return;
    }
    const conversations = this.sequencer.conversations;
    const eth = conversations.eth.observe(lane.srcMac, lane.dstMac, frame.tsUs);
    const ip = conversations[lane.family].observe(lane.src, lane.dst, frame.tsUs);
    const hint: BarrierHint = { nextStreamId: this.order.nextStream, forgets: this.order.wouldForget() };
    this.writers[shard].fragment(frame, lane.family,
      { a: lane.srcMac, b: lane.dstMac, facts: eth }, { a: lane.src, b: lane.dst, facts: ip }, hint);
    this.queued(shard);
    this.entries.set(frame.id, { lane: shard + 1, meta: frame.meta, done: false });
    this.barrier = { id: frame.id, shard, hint };
  }

  private rememberDatagram(datagram: string, key: string): void {
    this.datagramKey.delete(datagram);
    this.datagramKey.set(datagram, key);
    if (this.datagramKey.size > MAX_DATAGRAMS) {
      const oldest = this.datagramKey.keys().next();
      if (!oldest.done) this.datagramKey.delete(oldest.value);
    }
  }

  /** A fragment that arrived before its first one: the first one's connection, if it is close behind. */
  private lookAhead(datagram: string): string | undefined {
    const end = Math.min(this.held.length, this.heldFrom + LOOKAHEAD_FRAMES);
    for (let i = this.heldFrom; i < end; i++) {
      const frame = this.held[i];
      if ('marker' in frame) continue;
      const lane = frameLane(frame.bytes, frame.linktype);
      if (isTcpFragment(lane) && lane.datagram === datagram && lane.key !== undefined) return lane.key;
    }
    return undefined;
  }

  /** The coordinator's own lookup for a shard's frame: placed, and anything it forgot forgotten where it lives. */
  private locateFor(key: string, shard: number): readonly string[] {
    const order = this.order;
    const watcher = order.watcher;
    order.watcher = null;
    const forgotten = order.locate(key);
    order.watcher = watcher;
    for (const gone of forgotten) this.forgetEverywhere(gone);
    if (!this.keyHome.has(key)) this.keyHome.set(key, shard + 1);
    return forgotten;
  }

  private forgetEverywhere(key: string): void {
    const home = this.keyHome.get(key);
    this.keyHome.delete(key);
    if (home === undefined || home === 0) this.lane0.trackers.tcp.forget(key);
    else if (!this.dead.has(home - 1)) this.writers[home - 1].forget(key);
  }

  /** A lookup lane 0's trackers made on the real order. */
  private laneZeroLookup(key: string, forgotten: readonly string[]): void {
    for (const gone of forgotten) {
      const home = this.keyHome.get(gone);
      this.keyHome.delete(gone);
      // Lane 0's tracker forgets its own as part of this same lookup.
      if (home !== undefined && home !== 0 && !this.dead.has(home - 1)) this.writers[home - 1].forget(gone);
    }
    const home = this.keyHome.get(key);
    if (home === undefined) this.keyHome.set(key, 0);
    else if (home !== 0) this.crossLane += 1;
  }

  private settleBarrier(report: BarrierReport | undefined): void {
    const barrier = this.barrier!;
    this.barrier = null;
    if (report?.key === undefined) return;
    const home = this.keyHome.get(report.key);
    if (home !== undefined && home !== barrier.shard + 1) this.barrierMismatch += 1;
    const wasNew = !this.order.has(report.key);
    const forgotten = this.locateFor(report.key, barrier.shard);
    if (report.created !== wasNew) this.barrierMismatch += 1;
    if (wasNew && (forgotten[0] ?? null) !== barrier.hint.forgets) this.barrierMismatch += 1;
    if (report.streamAsked && this.order.streamId(report.key) !== barrier.hint.nextStreamId) this.barrierMismatch += 1;
  }

  private dissectHere(frame: CoordFrame): void {
    const lane0 = this.lane0;
    const entry: Entry = { lane: 0, meta: frame.meta, done: true };
    try {
      entry.d = lane0.dissect({
        id: frame.id, bytes: frame.bytes, tsUs: frame.tsUs, relativeTime: frame.relativeTime,
        timeDelta: frame.timeDelta, origLen: frame.origLen, linktype: frame.linktype,
        iface: this.options.ifaceOf(frame.iface), facts: frame.facts,
      });
    } catch (err) {
      entry.error = `failed to dissect a captured frame: ${String(err)}`;
    }
    const tls = lane0.takeTls();
    if (tls.length > 0) entry.tls = tls;
    this.entries.set(frame.id, entry);
    this.drain();
  }

  /** A frame was written to `shard`'s batch: count it, and seal the batch when full. */
  private queued(shard: number): void {
    this.recent[shard] += 1;
    if (++this.sinceDecay >= LOAD_HALF_LIFE) {
      this.sinceDecay = 0;
      for (let s = 0; s < this.shards; s++) this.recent[s] /= 2;
    }
    if (this.writers[shard].frames >= MAX_BATCH) this.sealWriter(shard);
  }

  private sealWriter(shard: number): void {
    this.ready[shard].push(this.writers[shard].seal());
    this.writers[shard] = new OpWriter();
  }

  /**
   * Hands each shard its queued work, a batch of at most `MAX_BATCH` frames at
   * a time and `maxInFlight` batches ahead of it. Small batches are the point:
   * a shard answers once a batch, so one batch of everything queued would
   * leave the merge waiting on its slowest frame and the shard idle while it
   * waited.
   */
  private pump(): void {
    for (let s = 0; s < this.shards; s++) {
      if (this.dead.has(s)) continue;
      while (this.inFlight[s] < this.maxInFlight) {
        if (this.ready[s].length === 0 && !this.writers[s].empty) this.sealWriter(s);
        const next = this.ready[s].shift();
        if (next === undefined) break;
        // An ordered message goes out as it comes up: it is not work in flight.
        if ('type' in next) this.options.send(s, next, []);
        else this.sendBatch(s, next);
      }
      if (this.ready[s].length === 0 && this.writers[s].empty) this.sendBatch(s, null);
    }
  }

  /** `batch` null: only what the merge owes the shard, and only if there is any. */
  private sendBatch(shard: number, batch: OpBatch | null): void {
    const settle = this.settles[shard];
    const rows = this.rows[shard];
    const patches = this.patches[shard];
    if (batch === null && settle.length === 0 && rows.length === 0 && patches.length === 0) return;
    if (this.dead.has(shard)) return;
    const transfer: ArrayBuffer[] = [];
    if (batch !== null) {
      transfer.push(batch.nums.buffer as ArrayBuffer);
      for (const bytes of batch.bytes) {
        if (bytes.byteLength > 0 && bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
          transfer.push(bytes.buffer as ArrayBuffer);
        }
      }
    }
    this.settles[shard] = [];
    this.rows[shard] = [];
    this.patches[shard] = [];
    this.inFlight[shard] += 1;
    this.options.send(shard, {
      type: 'batch', epoch: this.epoch, ops: batch,
      ...(settle.length > 0 ? { settle } : {}),
      ...(rows.length > 0 ? { rows } : {}),
      ...(patches.length > 0 ? { patches } : {}),
    }, transfer);
  }

  // --- merge ----------------------------------------------------------------

  private drain(): void {
    if (this.nextEmit === null) return;
    for (;;) {
      const id: number = this.nextEmit;
      const entry = this.entries.get(id);
      if (entry === undefined || !entry.done) return;
      this.entries.delete(id);
      this.nextEmit = id + 1;
      this.emit(id, entry);
    }
  }

  private emit(id: number, entry: Entry): void {
    const lane = entry.lane;
    const result = entry.result;
    const placeholders = entry.tls ?? result?.tls;
    if (placeholders !== undefined) {
      for (const placeholder of placeholders) {
        const real = this.nextTls++;
        if (lane === 0) this.lane0Tls.settle(placeholder, real);
        else {
          this.tlsMaps[lane].set(placeholder, real);
          this.settles[lane - 1].push([placeholder, real]);
        }
      }
    }
    const resolve = lane === 0
      ? (p: number) => this.lane0Tls.resolve(p)
      : (p: number) => this.tlsMaps[lane].get(p) ?? p;

    this.perLane[lane] += 1;
    const merged: Merged = { id, lane, meta: entry.meta };
    const d = entry.d;
    const error = entry.error ?? result?.error;
    if (error !== undefined) {
      merged.error = error;
    } else if (d !== undefined) {
      merged.packet = d.packet;
      merged.record = settleDeferredAnswers(d.record, d.deferredAt, resolve);
      merged.derived = d.derived;
      if (d.icmpMatchedRequestFrameId !== undefined) merged.icmpMatchedRequestFrameId = d.icmpMatchedRequestFrameId;
      if (d.infoPatches) merged.infoPatches = d.infoPatches;
      if (settleField(d.packet, resolve)) settleTreeTls(d.packet.layers, resolve);
    } else if (result !== undefined && (entry.packet !== undefined || entry.packed !== undefined)) {
      const packet = entry.packet;
      if (packet !== undefined) merged.packet = packet;
      if (entry.packed !== undefined) merged.packed = entry.packed;
      merged.record = result.record === undefined
        ? undefined : settleDeferredAnswers(result.record, result.deferredAt ?? NO_OFFSETS, resolve);
      merged.derived = result.derived ?? null;
      if (result.icmpMatchedRequestFrameId !== undefined) merged.icmpMatchedRequestFrameId = result.icmpMatchedRequestFrameId;
      if (result.infoPatches) merged.infoPatches = result.infoPatches;
      if (packet !== undefined) {
        settleField(packet, resolve);
      } else {
        // A light row: the placeholder it took is settled in an overlay, not in a row nobody decoded.
        merged.bytes = entry.bytes;
        if (entry.side !== undefined) {
          merged.side = entry.side;
          if (entry.side.tlsStream !== undefined) {
            merged.overlay = { fields: { 'tls.stream': resolve(entry.side.tlsStream) } };
          }
        }
      }
      if (result.layers) {
        settleTreeTls(result.layers, resolve);
        merged.layers = result.layers;
      }
      this.treeLane.set(id, lane);
    }
    this.options.emit(merged);
  }

  private checkIdle(): void {
    if (this.idleWaiters.length === 0) return;
    if (this.backlog > 0) return;
    const waiters = this.idleWaiters;
    this.idleWaiters = [];
    for (const waiter of waiters) waiter();
  }
}

/**
 * A number per recent frame id, in a ring: the last `size` ids are answered,
 * older ones are not.
 *
 * **Not a Map evicted from its front**, which is what it was, and what it cost
 * is the reason this exists: `map.keys().next()` walks every slot a delete has
 * emptied since the table was last rebuilt, so a Map that drops its oldest key
 * on every insert spends a scan of up to its whole capacity per frame. At the
 * 40,960 entries this holds it was 11 us a frame - more than the coordinator's
 * whole job - measured by `scripts/perf/parallel-threads.ts`.
 */
export class IdRing {
  private readonly ids: Float64Array;
  private readonly values: Uint8Array;

  constructor(private readonly size: number) {
    this.ids = new Float64Array(size).fill(-1);
    this.values = new Uint8Array(size);
  }

  set(id: number, value: number): void {
    const at = id % this.size;
    this.ids[at] = id;
    this.values[at] = value;
  }

  get(id: number): number | undefined {
    const at = id % this.size;
    return this.ids[at] === id ? this.values[at] : undefined;
  }

  clear(): void {
    this.ids.fill(-1);
  }
}

/** Frames in one batch to a shard; see `pump`. */
const MAX_BATCH = 384;
/** Frames over which a shard's recent load halves; see `shardFor`. */
const LOAD_HALF_LIFE = 8192;
const NO_OFFSETS: readonly number[] = [];

/** A frame's `tls.stream` field, settled in place; true when it held a placeholder. */
export function settleField(packet: Packet, resolve: (placeholder: number) => number): boolean {
  const value = packet.fields?.['tls.stream'];
  if (typeof value !== 'number' || value >= 0) return false;
  packet.fields!['tls.stream'] = resolve(value);
  return true;
}
