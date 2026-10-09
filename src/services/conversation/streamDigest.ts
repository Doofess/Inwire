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
  outcome: TcpOutcome;
  /** The digest's version when this summary last changed. */
  version: number;
}

/**
 * A stream's steps are its handful of state changes. Port reuse or a storm of
 * RSTs could make it more, and a summary is sent whole on every change.
 */
export const MAX_STEPS = 64;
/** Frame ids remembered for `relabel`. The patch horizon is two seconds. */
const RECENT_FRAMES = 65_536;

const RETRANSMISSIONS = new Set(['retransmission', 'fast_retransmission', 'spurious_retransmission']);

export function segmentOf(row: Packet, from: Side): TcpSegment {
  const num = (abbrev: string): number | undefined => {
    const v = fieldValue(row, abbrev);
    return typeof v === 'number' ? v : undefined;
  };
  const seq = num('tcp.seq');
  const len = num('tcp.len');
  const ackNo = num('tcp.ack');
  return {
    from,
    syn: fieldValue(row, 'tcp.flags.syn') === 1,
    ack: fieldValue(row, 'tcp.flags.ack') === 1,
    fin: fieldValue(row, 'tcp.flags.fin') === 1,
    rst: fieldValue(row, 'tcp.flags.reset') === 1,
    ...(seq !== undefined ? { seq } : {}),
    ...(len !== undefined ? { len } : {}),
    ...(ackNo !== undefined ? { ackNo } : {}),
  };
}

interface Entry { summary: StreamSummary; machine: TcpMachineState }

export interface DigestSnapshotData {
  throughId: number;
  version: number;
  entries: Entry[];
}

const emptyTotals = (): DirectionTotals => ({ packets: 0, bytes: 0, first: null, last: null });

export class StreamDigest {
  private readonly streams = new Map<number, Entry>();
  private readonly recent = new Map<number, number>();
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

    this.recent.set(row.id, streamId);
    if (this.recent.size > RECENT_FRAMES) {
      const oldest = this.recent.keys().next();
      if (!oldest.done) this.recent.delete(oldest.value);
    }
  }

  /** An `InfoPatch.protocolLabel` for a frame already folded. */
  relabel(frameId: number, label: string): void {
    const streamId = this.recent.get(frameId);
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

  snapshot(): DigestSnapshotData {
    // Copied: the store serialises this later while the digest keeps folding.
    return { throughId: this.through, version: this.versionValue, entries: structuredClone([...this.streams.values()]) };
  }

  static restore(data: DigestSnapshotData): StreamDigest {
    const d = new StreamDigest();
    d.through = data.throughId;
    d.versionValue = data.version;
    // Copied: the caller keeps its data, and feed mutates what it adopts.
    for (const entry of structuredClone(data.entries)) d.streams.set(entry.summary.streamId, entry);
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
