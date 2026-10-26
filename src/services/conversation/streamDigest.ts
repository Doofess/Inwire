/**
 * One summary per TCP stream, folded from rows (ADR 0055).
 *
 * The capture store owns one of these. Rows reach it from a live capture after
 * the shards' merge and from an import alike, in id order, so this is the one
 * place every row of every capture is seen exactly once. It reads only what a
 * row already carries, so it needs nothing new from any dissector and is held
 * to the same rows the list shows.
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

/**
 * What `encodeDigest` takes. `entries` is any iterable, so a caller with
 * hundreds of thousands of streams need not materialise them first.
 */
export interface DigestSnapshotData {
  throughId: number;
  version: number;
  entries: Iterable<DigestEntry>;
}

/** What `snapshot()` returns and `decodeDigest` reads back, and `restore` takes. */
export interface DigestSnapshot extends DigestSnapshotData {
  entries: DigestEntry[];
}

const emptyTotals = (): DirectionTotals => ({ packets: 0, bytes: 0, first: null, last: null });

export class StreamDigest {
  private readonly streams = new Map<number, Entry>();
  /**
   * The last `RECENT_FRAMES` ids folded and the stream each was in, as two
   * rings: ids ascend, so a lookup is a binary search, and a fold costs two
   * stores where a Map's insert and delete were most of `feed`.
   */
  private readonly recentIds = new Float64Array(RECENT_FRAMES);
  private readonly recentKeys = new Int32Array(RECENT_FRAMES);
  /** The next slot written: the oldest, once the ring is full. */
  private recentAt = 0;
  private recentCount = 0;
  private through = 0;
  private versionValue = 0;

  /** The highest frame id folded. A row at or below it is a repeat and is ignored. */
  get throughId(): number { return this.through; }
  get version(): number { return this.versionValue; }
  get size(): number { return this.streams.size; }

  get(streamId: number): StreamSummary | undefined {
    return this.streams.get(streamId)?.summary;
  }

  feed(row: Packet): void {
    if (row.id <= this.through) return;
    this.through = row.id;
    const streamId = row.streamId;
    if (streamId === undefined || row.sourcePort === undefined || row.destPort === undefined) return;
    if (!row.frameProtocols?.includes('tcp')) return;

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

    const slot = this.recentAt;
    this.recentIds[slot] = row.id;
    this.recentKeys[slot] = streamId;
    this.recentAt = (slot + 1) & (RECENT_FRAMES - 1);
    if (this.recentCount < RECENT_FRAMES) this.recentCount++;
  }

  /** The stream a recently folded frame was in, or undefined. */
  private recentStream(frameId: number): number | undefined {
    const oldest = this.recentCount < RECENT_FRAMES ? 0 : this.recentAt;
    let lo = 0;
    let hi = this.recentCount - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const slot = (oldest + mid) & (RECENT_FRAMES - 1);
      const id = this.recentIds[slot];
      if (id === frameId) return this.recentKeys[slot];
      if (id < frameId) lo = mid + 1;
      else hi = mid - 1;
    }
    return undefined;
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
    const streamId = this.recentStream(frameId);
    if (streamId === undefined) return;
    const s = this.streams.get(streamId)?.summary;
    if (s === undefined || label === 'TCP' || label === 'UDP') return;
    s.protocol = label;
    s.version = ++this.versionValue;
  }

  /** Every summary changed after `version`, for a poll. */
  changedSince(version: number): StreamSummary[] {
    const out: StreamSummary[] = [];
    for (const { summary } of this.streams.values()) if (summary.version > version) out.push(summary);
    return out;
  }

  /**
   * The digest's own entries, not copies. `encodeDigest` reads them
   * synchronously (`CaptureHost.writeSnapshot`), so nothing folds in between;
   * a caller that holds the result across a `feed` holds a moving target. The
   * copy this used to make was 2.4 s and 239 MB at 100k streams (ADR 0055,
   * final review I3).
   */
  snapshot(): DigestSnapshot {
    return { throughId: this.through, version: this.versionValue, entries: [...this.streams.values()] };
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
    for (const entry of data.entries) d.streams.set(entry.summary.streamId, entry);
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
