/**
 * One summary per TCP stream, UDP flow and QUIC connection, folded from rows
 * (ADR 0055).
 *
 * The capture store owns one of these. Rows reach it from a live capture after
 * the shards' merge and from an import alike, in id order, so this is the one
 * place every row of every capture is seen exactly once. It reads only what a
 * row already carries, so it needs nothing new from any dissector and is held
 * to the same rows the list shows.
 *
 * TCP is keyed by `tcp.stream`, UDP by `udp.stream` and QUIC by
 * `quic.connection.number`, in three maps; a row is folded into at most one.
 * The UDP and QUIC steps are in `flowSummary.ts`.
 *
 * Derived data: `snapshot()` is what the store persists, and a capture whose
 * snapshot is missing or stale is folded again from its rows.
 */
import type { Packet } from '../../types/packet';
import { fieldValue } from '../dissect/fieldAccess';
import { chooseClient, type ClientEndBasis, type Endpoint } from './clientSide';
import {
  TcpStateMachine, outcomeOf, type Side, type TcpMachineState, type TcpOutcome,
  type TcpSegment, type TcpState, type TcpTransition,
} from './tcpStates';
import {
  flowKeyOf, foldQuic, foldUdp, openQuic, openUdp, type QuicSummary, type UdpSummary,
} from './flowSummary';

export interface DirectionTotals {
  packets: number;
  bytes: number;
  /** Seconds since the capture started; null for a direction that never spoke. */
  first: number | null;
  last: number | null;
}

export interface StreamStep extends TcpTransition {
  frameId: number;
  time: number;
}

export interface StreamSummary {
  streamId: number;
  client: Endpoint;
  server: Endpoint;
  clientBasis: ClientEndBasis;
  toServer: DirectionTotals;
  toClient: DirectionTotals;
  firstId: number;
  lastId: number;
  /** Earliest and latest by time, not arrival, as `ConversationTable` takes them. */
  start: number;
  end: number;
  protocol: string;
  state: { client: TcpState; server: TcpState };
  steps: StreamStep[];
  /** Steps past `MAX_STEPS`, counted rather than kept. */
  stepsDropped: number;
  retransmissions: number;
  lostSegments: number;
  zeroWindows: number;
  joinedMidStream: boolean;
  /**
   * A rebuild folded this stream from the ring's floor and its first frame
   * there has no SYN: the start was probably captured and then expired, not
   * missed. Set with `joinedMidStream`, which it overrides in the words. Absent
   * in older snapshots, which reads as false.
   */
  startExpired?: boolean;
  outcome: TcpOutcome;
  /** The digest's version when this summary last changed. */
  version: number;
}

/**
 * A stream's steps are its handful of state changes. Port reuse or a storm of
 * RSTs could make it more, and a summary is sent whole on every change.
 */
export const MAX_STEPS = 64;
/**
 * Frame ids remembered for `relabel`: at least the writer's patch horizon in
 * frames (`DEFAULT_HORIZON_FRAMES`), which a fast link reaches before its
 * two seconds. A power of two.
 */
export const RECENT_FRAMES = 131_072;

const RETRANSMISSIONS = new Set(['retransmission', 'fast_retransmission', 'spurious_retransmission']);

export function segmentOf(row: Packet, from: Side): TcpSegment {
  const num = (abbrev: string): number | undefined => {
    const v = fieldValue(row, abbrev);
    return typeof v === 'number' ? v : undefined;
  };
  const seq = num('tcp.seq');
  const len = num('tcp.len');
  const ackNo = num('tcp.ack');
  const rawSeq = num('tcp.seq_raw');
  return {
    from,
    syn: fieldValue(row, 'tcp.flags.syn') === 1,
    ack: fieldValue(row, 'tcp.flags.ack') === 1,
    fin: fieldValue(row, 'tcp.flags.fin') === 1,
    rst: fieldValue(row, 'tcp.flags.reset') === 1,
    ...(seq !== undefined ? { seq } : {}),
    ...(len !== undefined ? { len } : {}),
    ...(ackNo !== undefined ? { ackNo } : {}),
    ...(rawSeq !== undefined ? { rawSeq } : {}),
    ...(row.analysisFlags?.includes('reused_ports') ? { reused: true } : {}),
  };
}

export interface DigestEntry { summary: StreamSummary; machine: TcpMachineState }
type Entry = DigestEntry;

/** One snapshot entry, tagged by kind (snapshot format 3). */
export type TaggedEntry =
  | { kind: 'tcp'; entry: DigestEntry }
  | { kind: 'udp'; summary: UdpSummary }
  | { kind: 'quic'; summary: QuicSummary };

export type FlowKind = 'udp' | 'quic';
/** What `changedSince` answers: every summary of each kind changed after a version. */
export interface DigestChanges { tcp: StreamSummary[]; udp: UdpSummary[]; quic: QuicSummary[] }

const KIND_TCP = 0;
const KIND_UDP = 1;
const KIND_QUIC = 2;

/**
 * What `encodeDigest` takes. `entries` is any iterable, so a caller with
 * hundreds of thousands of streams need not materialise them first.
 */
export interface DigestSnapshotData {
  throughId: number;
  version: number;
  /** The largest `relativeTime` of any row folded: what "went quiet" is measured against. */
  captureEnd: number;
  entries: Iterable<TaggedEntry>;
}

/** What `snapshot()` returns and `decodeDigest` reads back, and `restore` takes. */
export interface DigestSnapshot extends DigestSnapshotData {
  entries: TaggedEntry[];
}

const emptyTotals = (): DirectionTotals => ({ packets: 0, bytes: 0, first: null, last: null });

export class StreamDigest {
  private readonly streams = new Map<number, Entry>();
  private readonly udps = new Map<number, UdpSummary>();
  private readonly quics = new Map<number, QuicSummary>();
  /**
   * The last `RECENT_FRAMES` ids folded and the stream each was in, as three
   * rings: ids ascend, so a lookup is a binary search, and a fold costs three
   * stores where a Map's insert and delete were most of `feed`. A key is only
   * unique within its kind, so the kind rides beside it.
   */
  private readonly recentIds = new Float64Array(RECENT_FRAMES);
  private readonly recentKeys = new Int32Array(RECENT_FRAMES);
  private readonly recentKinds = new Uint8Array(RECENT_FRAMES);
  /** The next slot written: the oldest, once the ring is full. */
  private recentAt = 0;
  private recentCount = 0;
  private through = 0;
  private versionValue = 0;
  private captureEndValue = 0;

  /** The highest frame id folded. A row at or below it is a repeat and is ignored. */
  get throughId(): number { return this.through; }
  get version(): number { return this.versionValue; }
  get size(): number { return this.streams.size; }
  /** The largest `relativeTime` of every row fed, whatever its kind. */
  get captureEnd(): number { return this.captureEndValue; }

  get(streamId: number): StreamSummary | undefined {
    return this.streams.get(streamId)?.summary;
  }

  getFlow(kind: FlowKind, key: number): UdpSummary | QuicSummary | undefined {
    return kind === 'udp' ? this.udps.get(key) : this.quics.get(key);
  }

  feed(row: Packet): void {
    if (row.id <= this.through) return;
    this.through = row.id;
    if (row.relativeTime > this.captureEndValue) this.captureEndValue = row.relativeTime;
    const protocols = row.frameProtocols;
    if (protocols === undefined) return;
    if (protocols.includes('tcp')) { this.feedTcp(row); return; }
    const flow = flowKeyOf(row);
    if (flow === null) return;
    if (flow.kind === 'quic') this.feedQuic(row, flow.key);
    else this.feedUdp(row, flow.key);
  }

  private feedUdp(row: Packet, key: number): void {
    let s = this.udps.get(key);
    if (s === undefined) { s = openUdp(row, key); this.udps.set(key, s); }
    foldUdp(s, row);
    s.version = ++this.versionValue;
    this.remember(row.id, key, KIND_UDP);
  }

  private feedQuic(row: Packet, key: number): void {
    let s = this.quics.get(key);
    if (s === undefined) { s = openQuic(row, key); this.quics.set(key, s); }
    foldQuic(s, row);
    s.version = ++this.versionValue;
    this.remember(row.id, key, KIND_QUIC);
  }

  private remember(id: number, key: number, kind: number): void {
    const slot = this.recentAt;
    this.recentIds[slot] = id;
    this.recentKeys[slot] = key;
    this.recentKinds[slot] = kind;
    this.recentAt = (slot + 1) & (RECENT_FRAMES - 1);
    if (this.recentCount < RECENT_FRAMES) this.recentCount++;
  }

  private feedTcp(row: Packet): void {
    const streamId = row.streamId;
    if (streamId === undefined || row.sourcePort === undefined || row.destPort === undefined) return;

    let entry = this.streams.get(streamId);
    if (entry === undefined) {
      entry = this.open(row, streamId);
      this.streams.set(streamId, entry);
    }
    const s = entry.summary;
    const fromClient = row.source === s.client.address && row.sourcePort === s.client.port;
    const side: Side = fromClient ? 'client' : 'server';

    const totals = fromClient ? s.toServer : s.toClient;
    totals.packets++;
    totals.bytes += row.length;
    totals.first = Math.min(totals.first ?? row.relativeTime, row.relativeTime);
    totals.last = Math.max(totals.last ?? row.relativeTime, row.relativeTime);
    s.lastId = row.id;
    s.start = Math.min(s.start, row.relativeTime);
    s.end = Math.max(s.end, row.relativeTime);

    const label = row.protocolLabel ?? row.protocol;
    if (label !== 'TCP' && label !== 'UDP') s.protocol = label;

    for (const flag of row.analysisFlags ?? []) {
      if (RETRANSMISSIONS.has(flag)) s.retransmissions++;
      else if (flag === 'lost_segment') s.lostSegments++;
      else if (flag === 'zero_window') s.zeroWindows++;
    }

    const machine = new TcpStateMachine(entry.machine);
    for (const t of machine.apply(segmentOf(row, side))) {
      if (s.steps.length < MAX_STEPS) s.steps.push({ ...t, frameId: row.id, time: row.relativeTime });
      else s.stepsDropped++;
    }
    s.state = { client: entry.machine.client, server: entry.machine.server };
    s.joinedMidStream = entry.machine.joined;
    s.outcome = outcomeOf(entry.machine);
    s.version = ++this.versionValue;

    this.remember(row.id, streamId, KIND_TCP);
  }

  /** The ring slot a recently folded frame was written to, or -1. */
  private recentSlot(frameId: number): number {
    const oldest = this.recentCount < RECENT_FRAMES ? 0 : this.recentAt;
    let lo = 0;
    let hi = this.recentCount - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const slot = (oldest + mid) & (RECENT_FRAMES - 1);
      const id = this.recentIds[slot];
      if (id === frameId) return slot;
      if (id < frameId) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  }

  /**
   * After a rebuild that began above the capture's first frame: a stream that
   * folded as joined mid-stream and first appears no later than `floorLastId`,
   * the newest id of the oldest chunk held, most likely lost its start to the
   * ring rather than never having one. The chunk is the evidence available - a
   * stream first heard further in is as likely to have joined late.
   */
  markExpiredStarts(floorLastId: number): void {
    for (const { summary } of this.streams.values()) {
      if (!summary.joinedMidStream || summary.startExpired === true || summary.firstId > floorLastId) continue;
      summary.startExpired = true;
      summary.version = ++this.versionValue;
    }
  }

  /** An `InfoPatch.protocolLabel` for a frame already folded. */
  relabel(frameId: number, label: string): void {
    if (label === 'TCP' || label === 'UDP') return;
    const slot = this.recentSlot(frameId);
    if (slot < 0) return;
    const key = this.recentKeys[slot];
    const kind = this.recentKinds[slot];
    const s = kind === KIND_TCP ? this.streams.get(key)?.summary
      : kind === KIND_UDP ? this.udps.get(key) : this.quics.get(key);
    if (s === undefined) return;
    s.protocol = label;
    s.version = ++this.versionValue;
  }

  /** Every summary changed after `version`, for a poll. */
  changedSince(version: number): DigestChanges {
    const tcp: StreamSummary[] = [];
    for (const { summary } of this.streams.values()) if (summary.version > version) tcp.push(summary);
    const udp: UdpSummary[] = [];
    for (const s of this.udps.values()) if (s.version > version) udp.push(s);
    const quic: QuicSummary[] = [];
    for (const s of this.quics.values()) if (s.version > version) quic.push(s);
    return { tcp, udp, quic };
  }

  /**
   * The digest's own entries, not copies. `encodeDigest` reads them
   * synchronously (`CaptureHost.writeSnapshot`), so nothing folds in between;
   * a caller that holds the result across a `feed` holds a moving target. The
   * copy this used to make was 2.4 s and 239 MB at 100k streams (ADR 0055,
   * final review I3).
   */
  snapshot(): DigestSnapshot {
    const entries: TaggedEntry[] = [];
    for (const entry of this.streams.values()) entries.push({ kind: 'tcp', entry });
    for (const summary of this.udps.values()) entries.push({ kind: 'udp', summary });
    for (const summary of this.quics.values()) entries.push({ kind: 'quic', summary });
    return { throughId: this.through, version: this.versionValue, captureEnd: this.captureEndValue, entries };
  }

  /**
   * Adopts `data`'s entries: `feed` goes on to mutate them, so the caller
   * hands over what `decodeDigest` just built and keeps no hold on it. The
   * copy this used to make was most of a reopen's time, 6 s of 8 at 500k
   * streams.
   */
  static restore(data: DigestSnapshot): StreamDigest {
    const d = new StreamDigest();
    d.through = data.throughId;
    d.versionValue = data.version;
    d.captureEndValue = data.captureEnd;
    for (const tagged of data.entries) {
      if (tagged.kind === 'tcp') d.streams.set(tagged.entry.summary.streamId, tagged.entry);
      else if (tagged.kind === 'udp') d.udps.set(tagged.summary.key, tagged.summary);
      else d.quics.set(tagged.summary.key, tagged.summary);
    }
    return d;
  }

  private open(row: Packet, streamId: number): Entry {
    const { client, server, basis } = chooseClient(
      { address: row.source, port: row.sourcePort! },
      { address: row.destination, port: row.destPort! },
      row,
    );
    const machine = new TcpStateMachine();
    return {
      machine: machine.state,
      summary: {
        streamId, client, server, clientBasis: basis,
        toServer: emptyTotals(), toClient: emptyTotals(),
        firstId: row.id, lastId: row.id, start: row.relativeTime, end: row.relativeTime,
        protocol: row.protocolLabel ?? row.protocol,
        state: { client: 'UNKNOWN', server: 'UNKNOWN' },
        steps: [], stepsDropped: 0, retransmissions: 0, lostSegments: 0, zeroWindows: 0,
        joinedMidStream: false, outcome: 'open', version: 0,
      },
    };
  }
}
