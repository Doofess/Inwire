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
 * because it is what the window's title should say.
 */

import { Packet } from '../types/packet';
import { isWellKnownPort } from './portServices';

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

/**
 * Which end is the client.
 *
 * Two pieces of evidence, in order of how much they prove. A well-known port
 * on exactly one end is close to conclusive - nothing dials out FROM 443 -
 * and it keeps working on a capture that started in the middle of a
 * connection, where the first frame belongs to whichever side happened to
 * speak next. The first frame is the fallback: on a complete TCP conversation
 * it is the SYN, and its sender is the client by definition.
 *
 * Getting this backwards mislabels the whole conversation and reverses its
 * colours, which is the kind of wrong that reads as a fact.
 */
export function clientEnd(
  frames: readonly Packet[],
  target: StreamTarget,
): { address: string; port: number } {
  const a = { address: target.addressA, port: target.portA };
  const b = { address: target.addressB, port: target.portB };

  const aWellKnown = isWellKnownPort(target.portA);
  const bWellKnown = isWellKnownPort(target.portB);
  if (aWellKnown !== bWellKnown) return aWellKnown ? b : a;

  // Neither end or both ends look like a server: fall back to who spoke first.
  const first = frames[0];
  if (first?.sourcePort !== undefined) {
    return { address: first.source, port: first.sourcePort };
  }
  // A conversation with no frames has no client; A keeps the label so the
  // window still renders rather than throwing.
  return a;
}

/** True when this frame travelled from the client to the server. */
export function isFromClient(packet: Packet, client: { address: string; port: number }): boolean {
  return packet.source === client.address && packet.sourcePort === client.port;
}
