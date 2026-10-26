/**
 * Which frames belong to one stream, and which way each of them was going.
 *
 * The follower used to take a TCP stream index and filter on `packet.streamId`.
 * That worked for TCP and for nothing else: the tracker numbers TCP
 * conversations only, so a DNS exchange or a QUIC connection had no id and
 * Follow Stream was simply not offered on them - which is most of a modern
 * capture.
 *
 * A stream is identified by its five-tuple instead. For TCP that selects the
 * same frames the stream index did, retransmissions included, and for UDP it
 * needs no numbering to exist. The TCP stream index is carried along anyway,
 * because it is what the view's own heading should say.
 */

import { Packet } from '../types/packet';
import { chooseClient, type ClientEndBasis, type Endpoint } from './conversation/clientSide';
import { flowKeyOf } from './conversation/flowSummary';
import { fieldValue } from './dissect/fieldAccess';

export interface StreamTarget {
  /**
   * Which transport, so a UDP flow on the same ports as a TCP one stays apart.
   * A QUIC connection is its own kind: it is named by its connection number
   * and survives a change of address, which a five-tuple does not.
   */
  kind: 'tcp' | 'udp' | 'quic';
  addressA: string;
  portA: number;
  addressB: string;
  portB: number;
  /**
   * The key the digest holds this stream under: the tracker's index for TCP,
   * `udp.stream` for UDP, the connection number for QUIC. Absent when the frame
   * carries none (a UDP frame an older build imported).
   */
  streamId?: number;
}

/** The stream a frame belongs to, or null when it is not on one. */
export function targetForPacket(packet: Packet): StreamTarget | null {
  const layers = packet.frameProtocols;
  if (packet.sourcePort === undefined || packet.destPort === undefined) return null;
  const ends = {
    addressA: packet.source,
    portA: packet.sourcePort,
    addressB: packet.destination,
    portB: packet.destPort,
  };
  if (layers?.includes('tcp')) return { kind: 'tcp', ...ends, streamId: packet.streamId };
  // The digest's routing: a QUIC datagram with a connection number is that
  // connection's, any other UDP row is its udp.stream's.
  const flow = flowKeyOf(packet);
  if (flow !== null) return { kind: flow.kind, ...ends, streamId: flow.key };
  if (layers?.includes('udp')) return { kind: 'udp', ...ends, streamId: packet.streamId };
  return null;
}

/** Every frame on the stream, in capture order. */
export function streamPackets(packets: readonly Packet[], target: StreamTarget): Packet[] {
  if (target.kind === 'quic') {
    // By connection, not five-tuple: a migrated connection keeps its frames.
    return packets.filter((p) => p.frameProtocols?.includes('quic')
      && fieldValue(p, 'quic.connection.number') === target.streamId);
  }
  return packets.filter((p) => {
    if (!p.frameProtocols?.includes(target.kind)) return false;
    const forward = p.source === target.addressA && p.sourcePort === target.portA
      && p.destination === target.addressB && p.destPort === target.portB;
    const reverse = p.source === target.addressB && p.sourcePort === target.portB
      && p.destination === target.addressA && p.destPort === target.portA;
    return forward || reverse;
  });
}

export type { ClientEndBasis } from './conversation/clientSide';

export interface ClientEnd {
  address: string;
  port: number;
  basis: ClientEndBasis;
}

/**
 * Which end is the client, and on what evidence.
 *
 * Three pieces, in order of how much they prove. A well-known port on exactly
 * one end is close to conclusive - nothing dials out FROM 443 - and it keeps
 * working on a capture that started in the middle of a connection, where the
 * first frame belongs to whichever side happened to speak next. Failing that,
 * a first frame carrying SYN and not ACK is the connection being opened, and
 * its sender is the client by definition.
 *
 * What is left is the guess, and it is returned as one. The decision itself
 * lives in `conversation/clientSide.ts`, shared with the stream digest.
 */
export function clientEnd(
  frames: readonly Packet[],
  target: StreamTarget,
): ClientEnd {
  const { client, basis } = chooseClient(
    { address: target.addressA, port: target.portA },
    { address: target.addressB, port: target.portB },
    frames[0],
  );
  return { ...client, basis };
}

/** True when this frame travelled from the client to the server. */
export function isFromClient(packet: Packet, client: { address: string; port: number }): boolean {
  return packet.source === client.address && packet.sourcePort === client.port;
}

/**
 * True when a stream digest summary describes this target's conversation.
 *
 * The digest is looked up by the tracker's stream index, and an index is only
 * unique within one capture: a new capture numbers its first connection 0 as
 * well, and a target that outlives the capture it came from would otherwise be
 * handed another conversation's summary under its own number. The five-tuple
 * is the check, either way round, because the summary names its ends by role
 * and the target names them by which was selected.
 */
export function summaryIsTarget(
  summary: { client: Endpoint; server: Endpoint }, target: StreamTarget,
): boolean {
  if (target.kind !== 'tcp' || target.streamId === undefined) return false;
  const is = (end: Endpoint, address: string, port: number): boolean =>
    end.address === address && end.port === port;
  return (is(summary.client, target.addressA, target.portA) && is(summary.server, target.addressB, target.portB))
    || (is(summary.client, target.addressB, target.portB) && is(summary.server, target.addressA, target.portA));
}

/**
 * True when a UDP flow's or QUIC connection's summary describes this target.
 *
 * The same check as `summaryIsTarget`, for the same reason: the digest is
 * looked up by a key that is unique within one capture only. The kind must
 * match, and both ends must be the summary's, either way round. A QUIC
 * summary names its first five-tuple, so a target taken from a frame after the
 * connection moved does not match it, and the pane shows what the buffer holds.
 */
export function flowSummaryIsTarget(
  summary: { kind: 'udp' | 'quic'; client: Endpoint; server: Endpoint }, target: StreamTarget,
): boolean {
  if (target.kind !== summary.kind || target.streamId === undefined) return false;
  const is = (end: Endpoint, address: string, port: number): boolean =>
    end.address === address && end.port === port;
  return (is(summary.client, target.addressA, target.portA) && is(summary.server, target.addressB, target.portB))
    || (is(summary.client, target.addressB, target.portB) && is(summary.server, target.addressA, target.portA));
}
