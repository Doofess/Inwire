/**
 * UDP flows and QUIC connections, folded from rows (ADR 0055, stage 2).
 *
 * Beside the TCP summaries and not inside them: TCP's ladder, state map and
 * tests are untouched, and only these two kinds' code is new (ruling S2-4).
 * Pure steps over a summary and a row; `StreamDigest` owns the maps, the
 * versions and the rings.
 *
 * Everything here is inferred from what a row carries. A QUIC close is read
 * only from a decrypted CONNECTION_CLOSE, so a capture with no keys can show a
 * connection as established or unfinished and never as closed.
 */
import type { Packet } from '../../types/packet';
import { fieldValue } from '../dissect/fieldAccess';
import { chooseClient, type ClientEndBasis, type Endpoint } from './clientSide';
import type { Side } from './tcpStates';
import type { DirectionTotals } from './streamDigest';

export type UdpOutcome = 'one-way' | 'request/response' | 'two-way';
export type QuicOutcome = 'no reply' | 'handshake unfinished' | 'established' | 'closed by client' | 'closed by server';

interface FlowBase {
  /** `udp.stream` for a UDP flow, `quic.connection.number` for a QUIC connection. */
  key: number;
  client: Endpoint;
  server: Endpoint;
  clientBasis: ClientEndBasis;
  toServer: DirectionTotals;
  toClient: DirectionTotals;
  firstId: number;
  lastId: number;
  /** Earliest and latest by time, as the TCP summaries take them. */
  start: number;
  end: number;
  protocol: string;
  /** The digest's version when this summary last changed. */
  version: number;
}

export interface UdpSummary extends FlowBase { kind: 'udp'; outcome: UdpOutcome }

export interface QuicPhaseStep { phase: 'initial' | 'handshake' | '1-rtt' | 'closed'; side: Side; frameId: number; time: number }

export interface QuicSummary extends FlowBase {
  kind: 'quic';
  outcome: QuicOutcome;
  /** The first non-zero `quic.version` seen, or null. */
  quicVersion: number | null;
  phases: QuicPhaseStep[];
  joinedMidStream: boolean;
  /** A row's address or port pair differed from both of the first pair's ends (ruling S2-5). */
  migrated: boolean;
}

export const QUIC_V2 = 0x6b3343cf;

/** A UDP flow that was a one-off exchange: neither direction sent more than this. */
const REQUEST_RESPONSE_MAX = 2;

const emptyTotals = (): DirectionTotals => ({ packets: 0, bytes: 0, first: null, last: null });

/**
 * The UDP flow a row counts in, or null: its `udp.stream`. Every UDP row with
 * one counts, a QUIC datagram included (Wireshark's UDP tab and Endpoints →
 * UDP do the same). A row with no `udp.stream` is in no flow - folding it
 * under 0 would merge every such datagram into one. Needs both ports.
 */
export function udpKeyOf(row: Packet): number | null {
  const protocols = row.frameProtocols;
  if (protocols === undefined || protocols.includes('tcp') || !protocols.includes('udp')) return null;
  if (row.sourcePort === undefined || row.destPort === undefined) return null;
  const stream = fieldValue(row, 'udp.stream');
  return typeof stream === 'number' ? stream : null;
}

/**
 * The QUIC connection a row also counts in, or null: its
 * `quic.connection.number`. No `udp.stream` is needed. Needs both ports.
 */
export function quicKeyOf(row: Packet): number | null {
  const protocols = row.frameProtocols;
  if (protocols === undefined || protocols.includes('tcp') || !protocols.includes('udp') || !protocols.includes('quic')) return null;
  if (row.sourcePort === undefined || row.destPort === undefined) return null;
  const connection = fieldValue(row, 'quic.connection.number');
  return typeof connection === 'number' ? connection : null;
}

/**
 * Whether a row is in UDP flow or QUIC connection `key`: the one membership
 * test. `StreamDigest.feed` folds by the same two keys, the store's
 * `flowOrdinals` matches with this and Follow Stream's RAM tail filters with
 * it, so the three cannot disagree.
 */
export function inFlow(row: Packet, kind: 'udp' | 'quic', key: number): boolean {
  return kind === 'udp' ? udpKeyOf(row) === key : quicKeyOf(row) === key;
}

/**
 * The flow a frame opens Follow Stream as, or null: its QUIC connection if it
 * has one, else its UDP flow. Not a membership rule (a QUIC frame is in both;
 * see `inFlow`), only which of the two a click on the frame shows.
 */
export function flowKeyOf(row: Packet): { kind: 'udp' | 'quic'; key: number } | null {
  const connection = quicKeyOf(row);
  if (connection !== null) return { kind: 'quic', key: connection };
  const stream = udpKeyOf(row);
  return stream !== null ? { kind: 'udp', key: stream } : null;
}

/** Ruling S2-2. */
export function udpOutcome(s: UdpSummary): UdpOutcome {
  if (s.toServer.packets === 0 || s.toClient.packets === 0) return 'one-way';
  return s.toServer.packets <= REQUEST_RESPONSE_MAX && s.toClient.packets <= REQUEST_RESPONSE_MAX
    ? 'request/response' : 'two-way';
}

/** Closed if a CONNECTION_CLOSE was read, else established, unfinished or unanswered. */
export function quicOutcome(s: QuicSummary): QuicOutcome {
  const closed = s.phases.find((p) => p.phase === 'closed');
  if (closed !== undefined) return closed.side === 'client' ? 'closed by client' : 'closed by server';
  if (s.phases.some((p) => p.phase === '1-rtt')) return 'established';
  if (s.phases.some((p) => p.side === 'server')) return 'handshake unfinished';
  return 'no reply';
}

function num(row: Packet, abbrev: string): number | undefined {
  const v = fieldValue(row, abbrev);
  return typeof v === 'number' ? v : undefined;
}

/** Folds one row's size, times and label into a flow, into the direction it went. */
function foldTotals(s: FlowBase, row: Packet, fromClient: boolean): void {
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
}

function openBase(row: Packet, key: number, client: Endpoint, server: Endpoint, basis: ClientEndBasis): FlowBase {
  return {
    key, client, server, clientBasis: basis,
    toServer: emptyTotals(), toClient: emptyTotals(),
    firstId: row.id, lastId: row.id, start: row.relativeTime, end: row.relativeTime,
    protocol: row.protocolLabel ?? row.protocol, version: 0,
  };
}

export function openUdp(row: Packet, key: number): UdpSummary {
  const { client, server, basis } = chooseClient(
    { address: row.source, port: row.sourcePort! },
    { address: row.destination, port: row.destPort! },
    row,
  );
  return { ...openBase(row, key, client, server, basis), kind: 'udp', outcome: 'one-way' };
}

/** Folds a row into its UDP flow. The caller has checked the ports and the key. */
export function foldUdp(s: UdpSummary, row: Packet): void {
  foldTotals(s, row, row.source === s.client.address && row.sourcePort === s.client.port);
  s.outcome = udpOutcome(s);
}

/**
 * What a long header's two type bits are, by the version: v1 Initial 0,
 * 0-RTT 1, Handshake 2, Retry 3; v2 Initial 1, 0-RTT 2, Handshake 3, Retry 0.
 * Only an Initial and a Handshake are phases.
 */
function longPhase(version: number | null, bits: number): 'initial' | 'handshake' | null {
  const initial = version === QUIC_V2 ? 1 : 0;
  const handshake = version === QUIC_V2 ? 3 : 2;
  if (bits === initial) return 'initial';
  if (bits === handshake) return 'handshake';
  return null;
}

/**
 * The phase a row shows: a long header by its type bits (and none for a
 * Version Negotiation, version 0), a row with no long header type as 1-RTT.
 */
function rowPhase(row: Packet, version: number | null): 'initial' | 'handshake' | '1-rtt' | null {
  const bits = num(row, 'quic.long.packet_type');
  if (bits === undefined) return '1-rtt';
  if (num(row, 'quic.version') === 0) return null;
  return longPhase(version, bits);
}

export function openQuic(row: Packet, key: number): QuicSummary {
  const a = { address: row.source, port: row.sourcePort! };
  const b = { address: row.destination, port: row.destPort! };
  const version = num(row, 'quic.version');
  const bits = num(row, 'quic.long.packet_type');
  const opens = bits !== undefined && version !== 0 && longPhase(version ?? null, bits) === 'initial';
  // A well-known port outranks the Initial, as it outranks a SYN for TCP: a
  // server's Initial heard first means the client's was missed.
  const byPort = chooseClient(a, b, row);
  const chosen = opens && byPort.basis !== 'well-known-port'
    ? { client: a, server: b, basis: 'syn' as ClientEndBasis } : byPort;
  const heardOpen = opens && chosen.client.address === a.address && chosen.client.port === a.port;
  return {
    ...openBase(row, key, chosen.client, chosen.server, chosen.basis),
    kind: 'quic', outcome: 'no reply', quicVersion: null, phases: [],
    joinedMidStream: !heardOpen, migrated: false,
  };
}

/** Folds a row into its QUIC connection. The caller has checked the ports and the key. */
export function foldQuic(s: QuicSummary, row: Packet): void {
  const sender = { address: row.source, port: row.sourcePort! };
  const receiver = { address: row.destination, port: row.destPort! };
  const fromServer = sender.address === s.server.address && sender.port === s.server.port;
  const side: Side = fromServer ? 'server' : 'client';
  foldTotals(s, row, !fromServer);

  const isEnd = (e: Endpoint): boolean =>
    (e.address === s.client.address && e.port === s.client.port) || (e.address === s.server.address && e.port === s.server.port);
  if (!s.migrated && !(isEnd(sender) && isEnd(receiver))) s.migrated = true;

  const version = num(row, 'quic.version');
  if (s.quicVersion === null && version !== undefined && version !== 0) s.quicVersion = version;

  const push = (phase: QuicPhaseStep['phase']): void => {
    if (s.phases.some((p) => p.phase === phase && p.side === side)) return;
    s.phases.push({ phase, side, frameId: row.id, time: row.relativeTime });
  };
  const phase = rowPhase(row, s.quicVersion);
  // A coalesced Initial+Handshake datagram shows its last packet, so a
  // Handshake row stands for an Initial from the same side before it.
  if (phase === 'handshake') push('initial');
  if (phase !== null) push(phase);
  const frame = num(row, 'quic.frame_type');
  if (frame === 0x1c || frame === 0x1d) push('closed');
  s.outcome = quicOutcome(s);
}
