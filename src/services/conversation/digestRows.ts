/**
 * A stream digest summary as the conversation table's row (ADR 0055).
 *
 * The store chose the client once, on the evidence `clientSide.ts` names, and
 * the row carries that choice: A is the client, B the server, whichever end
 * the capture happened to hear first. `Conversation` is what the table already
 * draws, so a digest row needs no second table; the fields past it are
 * what the digest knows and a pair count does not.
 *
 * TCP, UDP and QUIC all come through here. A UDP or QUIC row's `streamId` is
 * the flow's `key` (`udp.stream`, `quic.connection.number`).
 */
import type { Conversation, ConversationKind } from '../statistics';
import type { StreamSummary } from './streamDigest';
import { DNS_WAIT_SECONDS, type DnsTally, type QuicOutcome, type QuicSummary, type UdpOutcome, type UdpSummary } from './flowSummary';
import type { TcpOutcome } from './tcpStates';
import { tlsNote, type TlsSummary } from './tlsSummary';

/** A flow with no frame this long before the capture's last frame has gone quiet. */
export const QUIET_SECONDS = 30;

export type DigestKind = 'tcp' | 'udp' | 'quic';

export interface DigestConversation extends Conversation {
  kind: DigestKind;
  outcome: TcpOutcome | UdpOutcome | QuicOutcome;
  joinedMidStream: boolean;
  /** QUIC only: a later address or port than the first pair's (ruling S2-5). */
  migrated?: boolean;
  /** The flow's last frame time, for "went quiet" against the capture's end. */
  end: number;
  startExpired?: boolean;
  summary: StreamSummary | UdpSummary | QuicSummary;
  /** TCP only: the stream's TLS phases, when the digest read any. */
  tls?: TlsSummary;
}

/** A digest summary as the conversation table's row, client as A (ADR 0055). */
export function digestConversation(s: StreamSummary | UdpSummary | QuicSummary): DigestConversation {
  const kind: DigestKind = 'kind' in s ? s.kind : 'tcp';
  const id = 'key' in s ? s.key : s.streamId;
  return {
    key: `${kind}:${id}`,
    kind,
    addressA: s.client.address, portA: s.client.port,
    addressB: s.server.address, portB: s.server.port,
    packetsAtoB: s.toServer.packets, bytesAtoB: s.toServer.bytes,
    packetsBtoA: s.toClient.packets, bytesBtoA: s.toClient.bytes,
    firstAtoB: s.toServer.first, lastAtoB: s.toServer.last,
    firstBtoA: s.toClient.first, lastBtoA: s.toClient.last,
    packets: s.toServer.packets + s.toClient.packets,
    bytes: s.toServer.bytes + s.toClient.bytes,
    startRel: s.start, duration: s.end - s.start, end: s.end,
    streamId: id, protocol: s.protocol, firstFrame: s.firstId,
    outcome: s.outcome,
    joinedMidStream: 'joinedMidStream' in s ? s.joinedMidStream : false,
    ...('migrated' in s && s.migrated ? { migrated: true } : {}),
    ...('startExpired' in s && s.startExpired === true ? { startExpired: true } : {}),
    summary: s,
  };
}

/** What the digest holds, as the hook hands it over. */
export interface DigestMaps {
  summaries: ReadonlyMap<number, StreamSummary>;
  udp: ReadonlyMap<number, UdpSummary>;
  quic: ReadonlyMap<number, QuicSummary>;
  tls: ReadonlyMap<number, TlsSummary>;
}

function mapFor(kind: ConversationKind, digest: DigestMaps): ReadonlyMap<number, StreamSummary | UdpSummary | QuicSummary> | null {
  switch (kind) {
    case 'tcp': return digest.summaries;
    case 'udp': return digest.udp;
    case 'quic': return digest.quic;
    default: return null;
  }
}

/**
 * The conversation table's rows for a level, when the digest answers it: TCP,
 * UDP and QUIC, and only once the store has summarised something at that
 * level. Null leaves the level to the buffer's own count, which is every other
 * level and a digest level with nothing in it yet.
 */
export function conversationRows(kind: ConversationKind, digest: DigestMaps): DigestConversation[] | null {
  const map = mapFor(kind, digest);
  if (map === null || map.size === 0) return null;
  if (kind !== 'tcp') return [...map.values()].map(digestConversation);
  return [...map.values()].map((s) => {
    const row = digestConversation(s);
    const tls = digest.tls.get(row.streamId!);
    return tls === undefined ? row : { ...row, tls };
  });
}

/**
 * Which part of the capture a digest level answers for (ADR 0055: the pane says
 * which scope it is showing). Null when the digest has nothing to say, so the
 * buffer's own "Frames X-Y only" note is the one that stands.
 */
export function digestScopeNote(
  kind: ConversationKind, digest: DigestMaps, rebuilding: { done: number; total: number } | null,
  partial = false,
): string | null {
  const map = mapFor(kind, digest);
  if (map === null) return null;
  if (rebuilding !== null) return `Rebuilding the stream digest: ${rebuilding.done} of ${rebuilding.total} chunks`;
  if (map.size === 0) return null;
  return partial
    ? 'Not the whole capture: the stream digest missed some frames while rebuilding. Reopen the capture to rebuild it'
    : 'Whole capture';
}

function dnsTallyOf(summary: unknown): DnsTally | undefined {
  return typeof summary === 'object' && summary !== null && 'dns' in summary
    ? (summary as { dns?: DnsTally }).dns : undefined;
}

/**
 * A DNS flow's answers in words: answered, errors, unanswered, waiting, zeros
 * left out. A query open for `DNS_WAIT_SECONDS` of the capture's end is
 * unanswered, decided here against the moving end. Empty when all are zero.
 */
export function dnsOutcomeText(t: DnsTally, captureEnd: number): string {
  const stale = t.open.filter((q) => captureEnd - q.time >= DNS_WAIT_SECONDS).length;
  const unanswered = t.evictedUnanswered + stale;
  const waiting = t.open.length - stale;
  return [
    t.answered > 0 ? `${t.answered} answered` : '',
    t.errors > 0 ? `${t.errors} ${t.errors === 1 ? 'error' : 'errors'}` : '',
    unanswered > 0 ? `${unanswered} unanswered` : '',
    waiting > 0 ? `${waiting} waiting` : '',
  ].filter((p) => p !== '').join(' · ');
}

/**
 * The outcome in the ADR's words, with its modifiers. A UDP or QUIC row also
 * says when it went quiet: its last frame is `QUIET_SECONDS` or more before the
 * capture's last one. TCP has its own endings and never says it.
 */
export function outcomeText(
  r: {
    outcome: string; joinedMidStream: boolean; startExpired?: boolean;
    kind?: DigestKind; migrated?: boolean; end?: number; tls?: TlsSummary;
    summary?: unknown;
  },
  captureEnd = 0,
): string {
  // A DNS flow's text is its tally alone (S3-5): no modifier, no went quiet.
  const tally = r.kind === 'udp' ? dnsTallyOf(r.summary) : undefined;
  if (tally !== undefined) {
    const dns = dnsOutcomeText(tally, captureEnd);
    if (dns !== '') return dns;
  }
  let text: string = r.outcome;
  if (r.joinedMidStream) {
    text += r.startExpired === true ? ' · start removed by the ring' : ' · joined mid-stream';
  }
  if (r.kind === 'quic' && r.migrated === true) text += ' · migrated';
  if ((r.kind === 'udp' || r.kind === 'quic') && r.end !== undefined && captureEnd - r.end >= QUIET_SECONDS) {
    text += ' · went quiet';
  }
  if (r.kind === 'tcp') text += tlsNote(r.tls, r.outcome as TcpOutcome);
  return text;
}
