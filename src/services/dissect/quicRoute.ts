/**
 * What a QUIC datagram's dissection will ask the QUIC order, read without
 * changing it (ADR 0053 phase 5).
 *
 * The coordinator answers those questions in frame order and ships the answers
 * with the frame, so a shard's dissection finds them where it would have asked.
 * `frameLane` says the dissection reaches the QUIC branch; this says what the
 * branch will do there, with the gate `udpTransport` puts in front of it: a
 * short header on a flow with no long header yet is plain UDP and asks nothing
 * more.
 *
 * Read-only on purpose. `isKnown` and `match` are the order's pure questions;
 * nothing here notes a long header or numbers a connection, which is the
 * coordinator's to do once, in order, with what this returns.
 */
import type { QuicOrderApi } from './sequencer';
import type { QuicLane } from './frameLane';
import { walkQuicDatagram, type QuicWalk } from '../dissectors/quic';

export interface QuicRouted {
  /** The flow had carried a long header before this datagram. */
  known: boolean;
  /** What the headers say. */
  walk: QuicWalk;
  /** The id the resolver will match at `walk.resolveAt` on the flow as it is now, if any. */
  matched: string | undefined;
}

/**
 * What this datagram's dissection will ask the QUIC order, or null when QUIC
 * will not claim it - then it is plain UDP and asks the order nothing but
 * `isKnown`. The resolver's answer is read BEFORE this datagram's own ids are
 * noted, as the dissector's is.
 */
export function readQuicRoute(
  bytes: Uint8Array, lane: QuicLane, order: Pick<QuicOrderApi, 'isKnown' | 'match'>,
): QuicRouted | null {
  const shortFirst = lane.payloadStart < bytes.length && (bytes[lane.payloadStart] & 0x80) === 0;
  const known = order.isKnown(lane.flow);
  if (shortFirst && !known) return null;
  const walk = walkQuicDatagram(bytes, lane.payloadStart, lane.payloadEnd);
  if (!walk.claimed) return null;
  const matched = walk.resolveAt < 0 ? undefined : order.match(lane.flow, bytes, walk.resolveAt);
  return { known, walk, matched };
}
