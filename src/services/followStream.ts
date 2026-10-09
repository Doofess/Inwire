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
import { chooseClient, type ClientEndBasis } from './conversation/clientSide';

export interface StreamTarget {
  /** Which transport, so a UDP flow on the same ports as a TCP one stays apart. */
  kind: 'tcp' | 'udp';
  addressA: string;
  portA: number;
  addressB: string;
  portB: number;
  /** The tracker's index, for the title. Absent for UDP, which has none. */
  streamId?: number;
}

/** The stream a frame belongs to, or null when it is not on one. */
export function targetForPacket(packet: Packet): StreamTarget | null {
  const layers = packet.frameProtocols;
  const kind = layers?.includes('tcp') ? 'tcp' : layers?.includes('udp') ? 'udp' : null;
  if (!kind) return null;
  if (packet.sourcePort === undefined || packet.destPort === undefined) return null;
  return {
    kind,
    addressA: packet.source,
    portA: packet.sourcePort,
    addressB: packet.destination,
    portB: packet.destPort,
    streamId: packet.streamId,
  };
}

/** Every frame on the stream, in capture order. */
export function streamPackets(packets: readonly Packet[], target: StreamTarget): Packet[] {
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
