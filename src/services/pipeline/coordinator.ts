/**
 * Dissection on several cores: the coordinator (ADR 0053 phases 3 and 5).
 *
 * The live capture's frames arrive in order on one Worker. This splits them:
 *
 *   - a plain TCP segment goes to a **shard**, chosen by its connection's
 *     routing key, which keeps every frame of one connection on one shard -
 *     that connection's state never has to be shared;
 *   - a plain UDP datagram that QUIC takes goes to a shard too, by its QUIC
 *     flow, with the answers its dissection will ask of the QUIC order shipped
 *     beside it (`routeQuic`, `quicRoute.ts`);
 *   - everything else is dissected **here**, on lane 0, by exactly the code
 *     the single Worker runs, with the real trackers.
 *
 * What makes the shards' output the single Worker's, frame for frame, is that
 * nothing a shard dissects is numbered by the shard. Everything counted across
 * conversations - `eth.stream`, `ip.stream`, `udp.stream`, `tcp.stream`, which
 * connection is forgotten past the cap, and QUIC's flow registry, connection
 * numbers and forgotten flows - lives in the one `Sequencer` here,
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
 *     way this build can differ from one core. Lane 0 then holds a half of
 *     that connection, forgotten with the shard's (`laneZeroMetConnections`).
 *     A QUIC flow is the same
 *     (`quicHome`): one lane 0 meets first stays on lane 0, and a sharded
 *     flow's datagram that reaches lane 0 finds no keys there and is counted too.
 *
 * Output is merged back into strict frame order before anything sees it, so
 * the records, patches and rows downstream are in the order they always were.
 *
 * Plain TypeScript, no Worker API: `send` and `receive` are the transport,
 * which is a nested Worker in the app and a function call in the equality
 * test (`scripts/pipeline/parallel.ts`).
 */
import { NO_KEYS, QuicOrder, Sequencer, TcpOrder, DeferredTlsNumbers, type QuicNoted } from '../dissect/sequencer';
import { frameLane, isTcpFragment, type QuicLane, type TcpFragmentLane, type TcpLane } from '../dissect/frameLane';
import { readQuicRoute } from '../dissect/quicRoute';
import { settleTreeTls, type BarrierHint, type BarrierReport } from '../dissect/shardNumbering';
import { settleDeferredAnswers } from '../dissect/frameRecord';
import type { DissectEnv } from '../dissect/dissectEnv';
import { FrameDissector, type Dissected, type LaneTrackers } from './frameDissector';
import { TcpStreamTracker } from '../tcpStreamTracker';
import { IcmpEchoTracker } from '../icmpEchoTracker';
import { QuicFlowTracker, quicLimits } from '../quicFlowTracker';
import { DnsTracker } from '../dnsTracker';
import { L3Tracker } from '../l3Tracker';
import { OpWriter, type FromShard, type OpBatch, type ShardResult, type ToShard, type WireFrame } from './shardProtocol';
import { PackKeys, unpackRows, type RowPack } from './rowPack';
import { overlayMark, type OverlayMark, type RowOverlay } from './rowOverlay';
import type { RowSide } from './rowSteps';
import { HeldQueue } from './heldQueue';
import type { InfoPatch } from '../dissect/types';
import type { Packet, ProtocolLayer } from '../../types/packet';

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
  /**
   * Lane 0's trackers: the real ones, sharing `sequencer`, whose `tcp` must be a
   * `WatchedTcpOrder` and `quic` a `WatchedQuicOrder` (`coordinatorSequencer`).
   */
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
  /** The shards send each frame's tree back (`ShardOptions.withTrees`) - the equality test; the coordinator does not read it. */
  withTrees?: boolean;
  /** The first pack key; 0 unless a test starts the counter near its edge (`PackKeys`). */
  firstPackKey?: number;
}

/**
 * Frames in flight past which the Worker's flush stops handing the coordinator
 * more: a cap, not the bound. It bounds the entry map, the frames held for
 * routing and the shards' queued batches when frames are tiny, where
 * `PARALLEL_BACKLOG_BYTES` would admit almost a million.
 *
 * What binds then is the heap each entry holds, not its bytes: a frame answered
 * and waiting behind the hot shard held 643-756 bytes (2026-11-02), so at this
 * cap tiny frames hold about 120 MB. It is the burst's 135,000 frames under
 * `PARALLEL_BACKLOG_BYTES` with room to spare; 262,144 allowed 190 MB.
 */
export const PARALLEL_BACKLOG_FRAMES = 163_840;

/**
 * Estimated bytes (`inFlightCost`) in flight past which the flush stops: the
 * bound on what the frames dispatched and not yet merged hold.
 *
 * **A frame count made one connection the limit.** On a 300,000-frame burst a
 * single connection is 22% of the frames and one shard's work; at 65,536
 * frames in flight its frames alone filled the allowance, and the other shards
 * waited for it. At 131,072 the 6-shard throughput rose from 54-64k to 71-72k
 * frames a second (ADR 0053, "Shard skew"). 160 MiB is the smallest multiple
 * of 16 MiB that admits 131,072 frames of that burst's mean size (1,114 bytes
 * captured, plus `IN_FLIGHT_FRAME_OVERHEAD`).
 *
 * **The bound is on one copy of the bytes; the coordinator holds about two.**
 * A shard frame's own bytes stay on its entry (`Entry.bytes`, a view into the
 * agent's batch, which keeps that whole batch alive) and a second copy sits in
 * the batch slab built for its shard (`OpWriter`), until the batch is sent and
 * transferred. `inFlightCost` counts the first only, so what the coordinator
 * holds of captured bytes in flight is up to about twice this bound, 320 MiB,
 * plus about 260 bytes of op row a frame. Counting both would halve the
 * frames admitted and undo the throughput this constant was chosen for (ADR
 * 0053, "Shard skew"), so the bound is recorded here and not tightened; a
 * single accounting site cannot fix it, only a change to who holds the bytes.
 */
export const PARALLEL_BACKLOG_BYTES = 160 * 1024 * 1024;

/**
 * What a frame in flight holds beyond its captured bytes, on the V8 heap,
 * **before its shard answers**.
 *
 * Measured 2026-11-02 on the first 100,000 frames of the burst, 6 shards, with
 * every message to a shard dropped so that nothing merged (`heapUsed` after
 * `gc()` before and after, divided by 100,000): 122.5 bytes a frame (the entry
 * and what hangs from it), rounded up to the next 64. The frame's bytes are a
 * view into the agent's batch and are not in it.
 *
 * **An answered frame waiting to merge holds more**: its result, side record
 * and a share of its pack, about 0.4 kB more (measured with each frame its own
 * buffer, 643-756 bytes answered against 289-381 not). Under skew most frames
 * in flight are in that state; at the burst's frame size that is about 60 MB
 * of heap the estimate leaves out, against the bytes it counts off the heap. A
 * decoded row holds more again and is counted (`DECODED_ROW_COST`).
 *
 * **Not in it either:** a batch still waiting for its shard holds a copy of
 * each frame's bytes and about 260 bytes of op row, as typed arrays, which
 * are off the V8 heap (`arrayBuffers` rose by 1.35 kB a frame for frames of
 * 1,094 bytes). That is a second `capturedLength` the estimate does not count.
 */
export const IN_FLIGHT_FRAME_OVERHEAD = 128;

/** What a frame in flight is estimated to hold, from dispatch until it merges. */
export function inFlightCost(capturedLength: number): number {
  return capturedLength + IN_FLIGHT_FRAME_OVERHEAD;
}

/**
 * Estimated bytes of lane-0 results waiting to merge past which the flush
 * stops too (`laneZeroWaiting`).
 *
 * **A frame count did not bound memory.** Lane 0 dissects as frames arrive
 * and keeps each whole result - tree, field bag, record - until every shard
 * frame before it has merged. QUIC is lane 0's, and with shards behind on TCP
 * the measured drive held 33-38k lane-0 results of the 65,536 frames the
 * frame-count bound then allowed, at 41 kB each, and the renderer died out of heap
 * at 60k frames a second (ADR 0053, phase 5). Past this the frames wait in the
 * Worker undissected, at their wire size, which main's credit bounds and
 * sheds with a count that catch-up reads back.
 */
export const LANE_ZERO_WAITING_BYTES = 256 * 1024 * 1024;

/**
 * What a lane-0 result is estimated to hold until it merges.
 *
 * Measured on the QUIC fixture once long hex was built flat: 15.5 kB a QUIC
 * frame at 942 bytes on the wire, 16.3 kB for the rest at 292, 18 kB for TCP
 * with its tree - a cost mostly per frame, not per byte. The per-byte term is
 * the payload's hex, three characters a byte, which a frame with a long
 * undissected payload carries.
 */
export function laneZeroCost(capturedLength: number): number {
  return 14 * 1024 + 4 * capturedLength;
}

/**
 * What a shard row decoded at the merge holds beyond a light one, while it
 * waits to merge: the `Packet` and its field bag. Counted with lane 0's
 * results (`laneZeroWaiting`), which are the same thing - dissected and
 * waiting - from the other lane.
 *
 * A row is decoded with more than one interface (`decodeRows`) or for a
 * `needsRow` result. Under skew most frames in flight are answered and waiting
 * behind the hot shard, and decoded each held 3,807-3,860 bytes of V8 heap
 * against 643-756 light (2026-11-02, two shards, one never answering, 60,000
 * frames of 60 and 1,114 bytes): 3,104-3,164 more, rounded up to the next 64.
 * Uncounted, the frame cap let a capture on two adapters hold about 1 GB.
 */
export const DECODED_ROW_COST = 3200;

/** What the flush reads of the coordinator. */
type Load = Pick<Coordinator, 'backlog' | 'laneZeroWaiting' | 'inFlightBytes'>;

/**
 * How many of `want` frames the flush may hand the coordinator now: none once
 * the bytes in flight or lane 0's waiting results are at their bound, else
 * what the frame cap leaves. A slice's bytes are known only once it is handed
 * over, so the bytes can overshoot by one slice.
 */
export function parallelRoom(want: number, coordinator: Load): number {
  if (coordinator.laneZeroWaiting >= LANE_ZERO_WAITING_BYTES) return 0;
  if (coordinator.inFlightBytes >= PARALLEL_BACKLOG_BYTES) return 0;
  return Math.max(0, Math.min(want, PARALLEL_BACKLOG_FRAMES - coordinator.backlog));
}

/**
 * How many of the `waiting` released frames one flush dissects.
 *
 * Capturing, a slice, and none while the store or the window is behind
 * (`behind`). Stopped, the store no longer holds it back: the stop path is
 * waiting for its last rows. Without shards that is everything at once, as it
 * always was. **With shards it is still a slice, inside both bounds**: frames
 * past the lane-0 bound wait in `released`, up to main's credit, and handing
 * them all over at Stop dissected every lane-0 frame in one synchronous call,
 * with the shard frame before them unanswered - the same out-of-heap crash,
 * moved to Stop. The drain takes slices until `released` is empty.
 */
export function flushTake(
  waiting: number, slice: number, state: { capturing: boolean; behind: boolean },
  coordinator: Load | null,
): number {
  if (state.capturing && state.behind) return 0;
  if (coordinator === null) return state.capturing ? Math.min(waiting, slice) : waiting;
  return parallelRoom(Math.min(waiting, slice), coordinator);
}

/**
 * Whether a merge brought the coordinator low enough to ask for another flush:
 * half of each limit, so it is not asked for one frame at a time.
 */
export function parallelRoomAgain(coordinator: Load): boolean {
  return coordinator.backlog < PARALLEL_BACKLOG_FRAMES / 2
    && coordinator.inFlightBytes < PARALLEL_BACKLOG_BYTES / 2
    && coordinator.laneZeroWaiting < LANE_ZERO_WAITING_BYTES / 2;
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

/**
 * The real QUIC order, watched, as `WatchedTcpOrder` is: the long headers and
 * numberings lane 0's own trackers make are where the coordinator learns which
 * flows live on lane 0, which are met on a lane that does not hold them, and
 * which flows a lane-0 long header forgot that a shard holds.
 */
export class WatchedQuicOrder extends QuicOrder {
  /** Set by the coordinator; null while it numbers a shard's datagram itself. */
  watcher: ((flow: string, forgotten: readonly string[]) => void) | null = null;

  override noteLongHeader(flow: string, connectionIds: readonly string[], emptyDcid: boolean): QuicNoted {
    const noted = super.noteLongHeader(flow, connectionIds, emptyDcid);
    this.watcher?.(flow, noted.forgotten);
    return noted;
  }

  override connectionForFlow(flow: string, connectionId: string | undefined): number | undefined {
    const number = super.connectionForFlow(flow, connectionId);
    this.watcher?.(flow, NO_KEYS);
    return number;
  }
}

/** The Sequencer the coordinator numbers through: both its orders watched. */
export function coordinatorSequencer(): Sequencer {
  return new Sequencer(new WatchedTcpOrder(), new WatchedQuicOrder());
}

/**
 * Lane 0's trackers for a new capture, numbering through watched TCP and QUIC
 * orders. Lane 0's QUIC keeps the whole budget, not a shard's share: QUIC that
 * cannot reach the shards (QinQ, a fragment, a port other than 443) is all held here.
 */
export function laneZero(): { trackers: LaneTrackers; sequencer: Sequencer } {
  const fresh = coordinatorSequencer();
  return {
    sequencer: fresh,
    trackers: {
      tcp: new TcpStreamTracker(fresh), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(fresh, quicLimits(1)),
      dns: new DnsTracker(), l3: new L3Tracker(fresh),
    },
  };
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
  /**
   * A shard frame's own bytes, kept from the moment it was routed: the shard
   * was given a copy, and sends none back. They go on the row it returns, and
   * on a light row, whose pack has none. Absent for a frame dissected here,
   * whose bytes are `d.packet.rawBytes`.
   */
  bytes?: Uint8Array;
  /** A light row's side record, from its result. */
  side?: RowSide;
  error?: string;
  tls?: number[];
  /** A lane-0 result's `laneZeroCost`, counted in `laneZeroWaiting` until it merges. */
  cost?: number;
  /** The frame's `inFlightCost`, counted in `inFlightBytes` from dispatch until it merges. */
  held: number;
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
  private quicOrder: WatchedQuicOrder;
  private sequencer: Sequencer;
  private readonly lane0Tls: DeferredTlsNumbers;
  /** Lane 0's dissection: the single Worker's, frame for frame. Its `host` is the caller's to set. */
  lane0: FrameDissector;

  private epoch = 0;
  /**
   * Frames not yet routed, and the messages that go to the shards between them
   * (`broadcast`), each with its `inFlightCost` taken at dispatch (a marker's
   * is 0; `heldQueue.ts` says why it is kept).
   */
  private readonly held = new HeldQueue<CoordFrame | { marker: ToShard }>();
  /** The cost of the frame `advance` is routing, for the entry it makes. */
  private routingCost = 0;
  private barrier: { id: number; shard: number; hint: BarrierHint } | null = null;
  private readonly entries = new Map<number, Entry>();
  private nextEmit: number | null = null;
  /** Each shard's open batch, and the sealed ones waiting to be sent. */
  private writers: OpWriter[];
  /** Sealed batches, and the ordered messages that wait between them. */
  private ready: (OpBatch | ToShard)[][];
  private inFlight: number[];
  private settles: [number, number][][];
  private readonly dead = new Set<number>();
  /** Which lane holds each connection: 0, or a shard's lane (shard + 1). */
  private readonly keyHome = new Map<string, number>();
  /**
   * Which lane holds each QUIC flow, as `keyHome` does for connections: 0, or a
   * shard's lane. A map of its own, because a TCP key and a QUIC flow can be the
   * same string.
   *
   * **`quicOrder.isKnown(f)` holds exactly when `quicHome.has(f)`**, outside a
   * dead shard (whose flows are re-homed to lane 0 with their state gone): a
   * flow enters the order through a long header, which is numbered either here
   * for a shard (`routeQuic`) or by lane 0's own tracker (`laneZeroQuic`), and
   * leaves it only through a `forgotten` list, both of which clear the home.
   * That is what lets a short header be sent to its flow's shard knowing the
   * long header it needs is ahead of it there.
   */
  private readonly quicHome = new Map<string, number>();
  /**
   * Connections and flows homed on a shard that lane 0 met too (`crossLane`):
   * lane 0's tracker holds a half of each, which the forget sent to the shard
   * would not reach. Two sets, as `keyHome` and `quicHome` are two maps.
   */
  private readonly laneZeroMetConnections = new Set<string>();
  private readonly laneZeroMetFlows = new Set<string>();
  private readonly datagramKey = new Map<string, string>();
  private readonly datagramShard = new Map<string, number>();
  /** Placeholder to real `tls.stream`, per shard lane. */
  private tlsMaps: Map<number, number>[];
  private nextTls = 0;
  /** The packs' keys: never reset, so no two live packs of one coordinator share one. */
  private readonly packKeys: PackKeys;
  private idleWaiters: (() => void)[] = [];
  private waitingCost = 0;
  /** `inFlightCost` summed over frames dispatched and not yet merged. */
  private heldCost = 0;

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
  /** Results whose QUIC number was never asked: the shard's dissection did not do what `readQuicRoute` said. */
  quicMismatch = 0;
  /** Frames dissected on each lane, lane 0 first. */
  readonly perLane: number[];

  constructor(private readonly options: CoordinatorOptions) {
    this.shards = options.shards;
    this.packKeys = new PackKeys(options.firstPackKey);
    this.route = options.route ?? 'pair';
    this.assign = options.assign ?? (this.route === 'pair' ? hashShard : null);
    this.recent = new Array(options.shards).fill(0);
    this.maxInFlight = options.maxInFlight ?? 2;
    this.lane0Tls = new DeferredTlsNumbers();
    [this.sequencer, this.order, this.quicOrder, this.lane0] = this.adopt(options.trackers, options.sequencer);
    this.writers = Array.from({ length: this.shards }, () => new OpWriter());
    this.ready = Array.from({ length: this.shards }, () => []);
    this.inFlight = new Array(this.shards).fill(0);
    this.settles = Array.from({ length: this.shards }, () => []);
    this.tlsMaps = Array.from({ length: this.shards + 1 }, () => new Map());
    this.perLane = new Array(this.shards + 1).fill(0);
  }

  /** Lane 0's trackers and the Sequencer they share, hooked up. */
  private adopt(
    trackers: LaneTrackers, sequencer: Sequencer,
  ): [Sequencer, WatchedTcpOrder, WatchedQuicOrder, FrameDissector] {
    const order = sequencer.tcp;
    if (!(order instanceof WatchedTcpOrder)) throw new Error('coordinator: the sequencer needs a WatchedTcpOrder');
    const quicOrder = sequencer.quic;
    if (!(quicOrder instanceof WatchedQuicOrder)) throw new Error('coordinator: the sequencer needs a WatchedQuicOrder');
    order.deferredTls = this.lane0Tls;
    order.watcher = (key, forgotten) => this.laneZeroLookup(key, forgotten);
    quicOrder.watcher = (flow, forgotten) => this.laneZeroQuic(flow, forgotten);
    const lane0 = new FrameDissector(trackers, this.options.env, this.lane0Tls);
    lane0.host = this.lane0?.host ?? lane0.host;
    return [sequencer, order, quicOrder, lane0];
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
    return this.held.size + this.entries.size;
  }

  /**
   * Estimated bytes of results dissected and not yet merged
   * (`LANE_ZERO_WAITING_BYTES`): lane 0's, and shard rows decoded here
   * (`DECODED_ROW_COST`).
   */
  get laneZeroWaiting(): number {
    return this.waitingCost;
  }

  /**
   * Estimated bytes of the frames dispatched and not yet merged, those waiting
   * to be routed included (`PARALLEL_BACKLOG_BYTES`). A message between frames
   * is not counted.
   */
  get inFlightBytes(): number {
    return this.heldCost;
  }

  /** Hands frames over, in ascending contiguous id order. */
  dispatch(frames: readonly CoordFrame[]): void {
    for (const frame of frames) {
      const cost = inFlightCost(frame.bytes.length);
      this.held.push(frame, cost);
      this.heldCost += cost;
    }
    this.advance();
    this.pump();
  }

  /** A message from shard `shard`. */
  receive(shard: number, message: FromShard): void {
    if (message.type !== 'results') return;
    if (message.epoch !== this.epoch) return;
    // A dead shard's answer that was already on its way: its frames failed in
    // `shardFailed`, and nothing of it is used. Past this line it would take a
    // pack key and decode a pack no row of which is ever read.
    if (this.dead.has(shard)) return;
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
      pack.key = this.packKeys.take();
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
          packet.rawBytes = entry.bytes ?? new Uint8Array(0);
          entry.packet = packet;
          entry.packed = { pack, index: result.row, mark: overlayMark(packet) };
          entry.cost = (entry.cost ?? 0) + DECODED_ROW_COST;
          this.waitingCost += DECODED_ROW_COST;
        } else {
          // Light: the row stays where the shard put it.
          entry.packed = { pack, index: result.row };
          if (result.side !== undefined) entry.side = result.side;
        }
      }
      entry.done = true;
      if (result.quicUnasked) this.quicMismatch += 1;
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
    // Its flows' state is gone with it: they start again on lane 0, without keys.
    for (const [flow, home] of this.quicHome) if (home === lane) this.quicHome.set(flow, 0);
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
    [this.sequencer, this.order, this.quicOrder, this.lane0] = this.adopt(lane0.trackers, lane0.sequencer);
    this.held.clear();
    this.barrier = null;
    this.entries.clear();
    this.waitingCost = 0;
    this.heldCost = 0;
    this.nextEmit = null;
    for (let s = 0; s < this.shards; s++) {
      this.writers[s] = new OpWriter();
      this.ready[s] = [];
      this.inFlight[s] = 0;
      this.recent[s] = 0;
      this.settles[s] = [];
      if (!this.dead.has(s)) this.options.send(s, { type: 'reset', epoch: this.epoch }, []);
    }
    this.keyHome.clear();
    this.quicHome.clear();
    this.laneZeroMetConnections.clear();
    this.laneZeroMetFlows.clear();
    this.datagramKey.clear();
    this.datagramShard.clear();
    this.tlsMaps = Array.from({ length: this.shards + 1 }, () => new Map());
    this.nextTls = 0;
    this.lane0Tls.reset();
    this.crossLane = 0;
    this.barrierMismatch = 0;
    this.quicMismatch = 0;
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
    if (this.held.size > 0) this.held.push({ marker: message }, 0);
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

  /** The real number for one of lane 0's placeholders, for a cached tree. */
  resolveLaneZero(placeholder: number): number {
    return this.lane0Tls.resolve(placeholder);
  }

  // --- dispatch -------------------------------------------------------------

  private advance(): void {
    while (this.barrier === null && this.held.size > 0) {
      const frame = this.held.shift()!;
      this.routingCost = this.held.shiftedCost;
      if ('marker' in frame) {
        this.sendOrdered(frame.marker);
        continue;
      }
      if (this.nextEmit === null) this.nextEmit = frame.id;
      const lane = frameLane(frame.bytes, frame.linktype);
      if (lane.lane === 'tcp') this.routeSegment(frame, lane);
      else if (lane.lane === 'quic') this.routeQuic(frame, lane);
      else if (isTcpFragment(lane)) this.routeFragment(frame, lane);
      else this.dissectHere(frame);
    }
    this.held.compact();
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

  /** The entry for a frame routed to `shard`, waiting for its answer. */
  private shardEntry(frame: CoordFrame, shard: number): Entry {
    return { lane: shard + 1, meta: frame.meta, done: false, bytes: frame.bytes, held: this.routingCost };
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
    this.entries.set(frame.id, this.shardEntry(frame, shard));
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
    this.entries.set(frame.id, this.shardEntry(frame, shard));
    this.barrier = { id: frame.id, shard, hint };
  }

  /**
   * A UDP datagram QUIC takes (`QuicLane`): to the shard holding its flow, with
   * the answers its dissection will ask of the QUIC order.
   *
   * Everything the dissection asks is answered here, in frame order, and shipped
   * with the frame: whether the flow had a long header before (`known`), which
   * id the resolver matches, and the connection's number. A short header
   * dispatched behind its long header, still queued on the same shard, is
   * therefore known and matched as the single Worker would have found it.
   *
   * **A forget goes to whichever lane holds the flow, and ahead of the frame
   * that caused it - the frame's own shard included.** The single Worker forgets
   * inside `noteLongHeader`, which `udpTransport` calls after the datagram is
   * decrypted and its CRYPTO fragments are added, and before `readStreams`; of
   * those only `readStreams` reads state across flows (`streams`,
   * `totalPendingBytes`), and the forgotten flow is never this datagram's own.
   * So a shard that forgets before it dissects, rather than inside, leaves the
   * dissection reading the same things (`scripts/pipeline/quic-shards.ts`).
   */
  private routeQuic(frame: CoordFrame, lane: QuicLane): void {
    const home = this.quicHome.get(lane.flow);
    // A flow lane 0 met first stays there, its state in one place.
    if (home === 0) {
      this.dissectHere(frame);
      return;
    }
    // What the dissection will ask, read without changing the order. Null:
    // QUIC will not claim it, so it is plain UDP, which lane 0 dissects and
    // asks the real order for itself.
    const route = readQuicRoute(frame.bytes, lane, this.quicOrder);
    if (route === null) {
      this.dissectHere(frame);
      return;
    }
    const shard = home !== undefined ? home - 1 : this.shardFor(this.route === 'pair' ? lane.pair : lane.flow);
    if (shard === null || shard < 0) {
      this.dissectHere(frame);
      return;
    }
    // The coordinator's own numbering, on behalf of the shard: not lane 0's
    // lookup, so it is not watched.
    const order = this.quicOrder;
    const watcher = order.watcher;
    order.watcher = null;
    let number: number | undefined;
    try {
      if (route.walk.long) {
        const noted = order.noteLongHeader(lane.flow, route.walk.connectionIds, route.walk.emptyDcid);
        for (const gone of noted.forgotten) this.forgetQuicEverywhere(gone);
        number = noted.number;
      } else {
        number = order.connectionForFlow(lane.flow, route.matched);
      }
    } finally {
      order.watcher = watcher;
    }
    if (!this.quicHome.has(lane.flow)) this.quicHome.set(lane.flow, shard + 1);
    const conversations = this.sequencer.conversations;
    const eth = conversations.eth.observe(lane.srcMac, lane.dstMac, frame.tsUs);
    const ip = conversations[lane.family].observe(lane.src, lane.dst, frame.tsUs);
    const udpA = `${lane.src}:${lane.srcPort}`;
    const udpB = `${lane.dst}:${lane.dstPort}`;
    const udp = conversations.udp.observe(udpA, udpB, frame.tsUs);
    this.writers[shard].quic(frame, lane.family,
      { a: lane.srcMac, b: lane.dstMac, facts: eth }, { a: lane.src, b: lane.dst, facts: ip },
      { a: udpA, b: udpB, facts: udp },
      { flow: lane.flow, known: route.known, resolveAt: route.walk.resolveAt, matched: route.matched, long: route.walk.long, number });
    this.queued(shard);
    this.entries.set(frame.id, this.shardEntry(frame, shard));
  }

  /** A flow the QUIC order forgot: dropped from the lane that holds it, ahead of whatever is queued next. */
  private forgetQuicEverywhere(flow: string): void {
    const home = this.quicHome.get(flow);
    this.quicHome.delete(flow);
    const met = this.laneZeroMetFlows.delete(flow);
    if (home === undefined || home === 0 || met) this.lane0.trackers.quic.forget(flow);
    if (home !== undefined && home !== 0 && !this.dead.has(home - 1)) this.writers[home - 1].quicForget(flow);
  }

  /** A long header or numbering lane 0's trackers made on the real QUIC order. */
  private laneZeroQuic(flow: string, forgotten: readonly string[]): void {
    for (const gone of forgotten) {
      const home = this.quicHome.get(gone);
      this.quicHome.delete(gone);
      this.laneZeroMetFlows.delete(gone);
      // Lane 0's tracker forgets its own as part of this same call.
      if (home !== undefined && home !== 0 && !this.dead.has(home - 1)) this.writers[home - 1].quicForget(gone);
    }
    const home = this.quicHome.get(flow);
    if (home === undefined) this.quicHome.set(flow, 0);
    else if (home !== 0) {
      this.crossLane += 1;
      this.laneZeroMetFlows.add(flow);
    }
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
    const end = Math.min(this.held.size, LOOKAHEAD_FRAMES);
    for (let i = 0; i < end; i++) {
      const frame = this.held.peek(i)!;
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
    const met = this.laneZeroMetConnections.delete(key);
    if (home === undefined || home === 0 || met) this.lane0.trackers.tcp.forget(key);
    if (home !== undefined && home !== 0 && !this.dead.has(home - 1)) this.writers[home - 1].forget(key);
  }

  /** A lookup lane 0's trackers made on the real order. */
  private laneZeroLookup(key: string, forgotten: readonly string[]): void {
    for (const gone of forgotten) {
      const home = this.keyHome.get(gone);
      this.keyHome.delete(gone);
      this.laneZeroMetConnections.delete(gone);
      // Lane 0's tracker forgets its own as part of this same lookup.
      if (home !== undefined && home !== 0 && !this.dead.has(home - 1)) this.writers[home - 1].forget(gone);
    }
    const home = this.keyHome.get(key);
    if (home === undefined) this.keyHome.set(key, 0);
    else if (home !== 0) {
      this.crossLane += 1;
      this.laneZeroMetConnections.add(key);
    }
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
    const entry: Entry = {
      lane: 0, meta: frame.meta, done: true, cost: laneZeroCost(frame.bytes.length), held: this.routingCost,
    };
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
    this.waitingCost += entry.cost!;
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
    if (batch === null && settle.length === 0) return;
    if (this.dead.has(shard)) return;
    // A batch is three buffers, each its own: the slab is a copy of the frames,
    // which this thread still holds (`Entry.bytes`). An empty slab is a legal
    // transfer, so a batch of empty frames needs no case of its own.
    const transfer: ArrayBuffer[] = [];
    if (batch !== null) {
      transfer.push(batch.nums.buffer as ArrayBuffer, batch.bytes.buffer as ArrayBuffer, batch.ends.buffer as ArrayBuffer);
    }
    this.settles[shard] = [];
    this.inFlight[shard] += 1;
    this.options.send(shard, {
      type: 'batch', epoch: this.epoch, ops: batch,
      ...(settle.length > 0 ? { settle } : {}),
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
      this.heldCost -= entry.held;
      if (entry.cost !== undefined) this.waitingCost -= entry.cost;
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
 *
 * Nothing in the app uses it now: it was the coordinator's map from a frame to
 * the shard holding its tree, which ADR 0072 removed. `scripts/pipeline/fifo-map.ts` still asserts it.
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
