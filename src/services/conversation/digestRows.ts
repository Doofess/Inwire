/**
 * A stream digest summary as the conversation table's row (ADR 0055).
 *
 * The store chose the client once, on the evidence `clientSide.ts` names, and
 * the row carries that choice: A is the client, B the server, whichever end
 * the capture happened to hear first. `Conversation` is what the table already
 * draws, so a digest row needs no second table; the three fields past it are
 * what the digest knows and a pair count does not.
 */
import type { Conversation, ConversationKind } from '../statistics';
import type { StreamSummary } from './streamDigest';
import type { TcpOutcome } from './tcpStates';

export interface DigestConversation extends Conversation {
  outcome: TcpOutcome;
  joinedMidStream: boolean;
  startExpired?: boolean;
  summary: StreamSummary;
}

/** A digest summary as the conversation table's row, client as A (ADR 0055). */
export function digestConversation(s: StreamSummary): DigestConversation {
  return {
    key: `tcp:${s.streamId}`,
    addressA: s.client.address, portA: s.client.port,
    addressB: s.server.address, portB: s.server.port,
    packetsAtoB: s.toServer.packets, bytesAtoB: s.toServer.bytes,
    packetsBtoA: s.toClient.packets, bytesBtoA: s.toClient.bytes,
    firstAtoB: s.toServer.first, lastAtoB: s.toServer.last,
    firstBtoA: s.toClient.first, lastBtoA: s.toClient.last,
    packets: s.toServer.packets + s.toClient.packets,
    bytes: s.toServer.bytes + s.toClient.bytes,
    startRel: s.start, duration: s.end - s.start,
    streamId: s.streamId, protocol: s.protocol, firstFrame: s.firstId,
    outcome: s.outcome, joinedMidStream: s.joinedMidStream,
    ...(s.startExpired === true ? { startExpired: true } : {}), summary: s,
  };
}

/**
 * The conversation table's rows for a level, when the digest answers it: TCP
 * only, and only once the store has summarised a stream. Null leaves the level
 * to the buffer's own count, which is every other level and a TCP level with
 * no digest yet.
 */
export function conversationRows(
  kind: ConversationKind, summaries: ReadonlyMap<number, StreamSummary>,
): DigestConversation[] | null {
  if (kind !== 'tcp' || summaries.size === 0) return null;
  return [...summaries.values()].map(digestConversation);
}

/**
 * Which part of the capture the TCP level answers for (ADR 0055: the pane says
 * which scope it is showing). Null when the digest has nothing to say, so the
 * buffer's own "Frames X-Y only" note is the one that stands.
 */
export function tcpScopeNote(
  summaries: ReadonlyMap<number, StreamSummary>, rebuilding: { done: number; total: number } | null,
  partial = false,
): string | null {
  if (rebuilding !== null) return `Rebuilding the stream digest: ${rebuilding.done} of ${rebuilding.total} chunks`;
  if (summaries.size === 0) return null;
  return partial
    ? 'Not the whole capture: the stream digest missed some frames while rebuilding. Reopen the capture to rebuild it'
    : 'Whole capture';
}

/** The outcome in the ADR's words, with its one modifier. */
export function outcomeText(r: { outcome: TcpOutcome; joinedMidStream: boolean; startExpired?: boolean }): string {
  if (!r.joinedMidStream) return r.outcome;
  return r.startExpired === true ? `${r.outcome} · start removed by the ring` : `${r.outcome} · joined mid-stream`;
}
