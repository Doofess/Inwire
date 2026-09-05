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
 * How well the client end is known.
 *
 *  - `well-known-port` - one end is a port nothing dials out FROM. Close to
 *    conclusive, and it holds on a capture that started mid-connection.
 *  - `syn` - the first frame on the stream is a SYN, so its sender opened the
 *    connection and is the client by definition.
 *  - `first-speaker` - neither of the above. This is a **guess**: whoever
 *    happened to speak first in what was captured, which is the client only if
 *    the capture caught the start.
 *
 * The distinction is the point. Getting the ends backwards mislabels the whole
 * conversation and reverses its colours - the module's own comment calls it
 * "the kind of wrong that reads as a fact" - and the only defence against that
 * is for the guess to be labelled as one where it is shown.
 */
export type ClientEndBasis = 'well-known-port' | 'syn' | 'first-speaker';

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
 * What is left is the guess, and it is returned as one.
 */
export function clientEnd(
  frames: readonly Packet[],
  target: StreamTarget,
): ClientEnd {
  const a = { address: target.addressA, port: target.portA };
  const b = { address: target.addressB, port: target.portB };

  const aWellKnown = isWellKnownPort(target.portA);
  const bWellKnown = isWellKnownPort(target.portB);
  if (aWellKnown !== bWellKnown) {
    return { ...(aWellKnown ? b : a), basis: 'well-known-port' };
  }

  // Neither end or both ends look like a server: fall back to who spoke first,
  // and say whether that was the handshake or merely the earliest frame left.
  const first = frames[0];
  if (first?.sourcePort !== undefined) {
    // SYN without ACK is the opening of a connection rather than the answer to
    // one, which is what makes its sender the client rather than the server.
    const opensConnection = first.fields?.['tcp.flags.syn'] === 1
      && first.fields?.['tcp.flags.ack'] !== 1;
    return {
      address: first.source,
      port: first.sourcePort,
      basis: opensConnection ? 'syn' : 'first-speaker',
    };
  }
  // A conversation with no frames has no client; A keeps the label so the
  // window still renders rather than throwing.
  return { ...a, basis: 'first-speaker' };
}

/** True when this frame travelled from the client to the server. */
export function isFromClient(packet: Packet, client: { address: string; port: number }): boolean {
  return packet.source === client.address && packet.sourcePort === client.port;
}
