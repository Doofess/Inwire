/**
 * A stream digest summary as the conversation table's row (ADR 0055).
 *
 * The store chose the client once, on the evidence `clientSide.ts` names, and
 * the row carries that choice: A is the client, B the server, whichever end
 * the capture happened to hear first. `Conversation` is what the table already
 * draws, so a digest row needs no second table; the three fields past it are
 * what the digest knows and a pair count does not.
 */
import type { Conversation } from '../statistics';
import type { StreamSummary } from './streamDigest';
import type { TcpOutcome } from './tcpStates';

export interface DigestConversation extends Conversation {
  outcome: TcpOutcome;
  joinedMidStream: boolean;
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
    outcome: s.outcome, joinedMidStream: s.joinedMidStream, summary: s,
  };
}

/** The outcome in the ADR's words, with its one modifier. */
export function outcomeText(r: { outcome: TcpOutcome; joinedMidStream: boolean }): string {
  return r.joinedMidStream ? `${r.outcome} · joined mid-stream` : r.outcome;
}
