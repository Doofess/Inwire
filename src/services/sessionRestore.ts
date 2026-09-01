import { Packet, ProtocolType } from '../types/packet';
import { decodeRawEthernetPacket } from './pcapParser';
import { TcpStreamTracker } from './tcpStreamTracker';
import { IcmpEchoTracker } from './icmpEchoTracker';
import { QuicFlowTracker } from './quicFlowTracker';
import { StoredFrame } from './sessionStore';

/**
 * Rebuilding live Packets from the frames a previous session stored.
 *
 * The rule this module exists to keep: a restored packet must be
 * indistinguishable from the one that was originally captured. That is why it
 * decodes through `decodeRawEthernetPacket` - the same function live capture
 * and pcap import both use - rather than reconstructing anything of its own.
 */

/**
 * The Packet built when the agent sent metadata but no bytes.
 *
 * Shared by live ingest and restore so the two cannot drift. Byte data is left
 * genuinely empty rather than fabricated: a frame with no captured bytes has
 * no hex dump, and inventing one would be worse than showing none.
 */
export function buildFallbackPacket(fields: {
  id: number;
  timestamp: number;
  relativeTime: number;
  timeDelta: number;
  length: number;
  source?: string;
  destination?: string;
  sourcePort?: number;
  destPort?: number;
  protocol?: string;
  info?: string;
}): Packet {
  const length = fields.length || 0;
  return {
    id: fields.id,
    timestamp: fields.timestamp,
    relativeTime: fields.relativeTime,
    timeDelta: fields.timeDelta,
    source: fields.source || '0.0.0.0',
    destination: fields.destination || '0.0.0.0',
    sourcePort: fields.sourcePort,
    destPort: fields.destPort,
    protocol: (fields.protocol || 'TCP') as ProtocolType,
    length,
    info: fields.info || 'Traffic',
    status: 'ok',
    layers: [
      {
        name: 'Frame',
        summary: `Frame ${fields.id}: ${length} bytes (no raw capture data was available)`,
        fields: [
          { name: 'Interface', value: 'Live Agent' },
          { name: 'Length', value: `${length} bytes` },
        ],
      },
    ],
    rawBytes: new Uint8Array(0),
    interfaceName: 'Live Agent',
  };
}

export interface RestoreTrackers {
  tcpTracker: TcpStreamTracker;
  icmpTracker: IcmpEchoTracker;
  quicTracker: QuicFlowTracker;
}

/**
 * Decodes one batch of stored frames.
 *
 * Must be called in ascending id order across the whole restore, and with the
 * same tracker instances throughout: the TCP, ICMP and QUIC trackers are
 * stateful and order-dependent, so stream ids, retransmission flags and
 * request/reply pairings only come out matching the original capture if the
 * frames are replayed in the order they arrived. Batching exists to let the
 * caller yield to the browser between batches, not to reorder anything.
 *
 * Returns the packets plus any ICMP reply pairings found, which the caller
 * applies to already-restored packets the same way live ingest does.
 */
export function restoreBatch(
  frames: StoredFrame[],
  trackers: RestoreTrackers,
  /**
   * Adapter label -> adapter id, from the session's interface table.
   *
   * A stored frame remembers the label it was captured on; the Frame layer
   * also shows the id, and only this table can map back to it. Without it a
   * restored frame reports itself as an imported capture on "eth0" - which is
   * what the detail window surfaced.
   */
  interfaceIdByLabel?: Map<string, string>,
): { packets: Packet[]; icmpReplies: { requestFrameId: number; replyId: number }[] } {
  const packets: Packet[] = [];
  const icmpReplies: { requestFrameId: number; replyId: number }[] = [];

  for (const frame of frames) {
    // Only claim an adapter the session's own table can actually identify.
    //
    // A looser rule - trust `frame.interfaceName` whenever it is set - is
    // wrong, and measurably so: `Packet.interfaceName` falls back to the
    // literal string "eth0" when a frame had no capture interface, which is
    // indistinguishable from a real adapter label. Trusting it turned every
    // interface-less frame into one captured on an adapter named "eth0" and
    // broke the round-trip equality this module exists to guarantee.
    const interfaceId = frame.interfaceName ? interfaceIdByLabel?.get(frame.interfaceName) : undefined;
    const captureInterface = interfaceId !== undefined && frame.interfaceName
      ? { name: interfaceId, label: frame.interfaceName }
      : undefined;

    if (frame.raw && frame.raw.length > 0) {
      const decoded = decodeRawEthernetPacket(
        frame.raw,
        frame.id,
        frame.timestamp,
        frame.relativeTime,
        frame.timeDelta,
        frame.length,
        trackers.tcpTracker,
        trackers.icmpTracker,
        trackers.quicTracker,
        captureInterface,
      );
      packets.push(decoded.packet);
      if (decoded.icmpMatchedRequestFrameId !== undefined) {
        icmpReplies.push({ requestFrameId: decoded.icmpMatchedRequestFrameId, replyId: frame.id });
      }
    } else {
      packets.push(
        buildFallbackPacket({
          id: frame.id,
          timestamp: frame.timestamp,
          relativeTime: frame.relativeTime,
          timeDelta: frame.timeDelta,
          length: frame.length,
          ...frame.fallback,
        }),
      );
    }
  }

  return { packets, icmpReplies };
}

/**
 * Applies ICMP reply pairings to packets already in the buffer.
 *
 * A reply names a request that arrived earlier, so during a chunked restore
 * the request is usually in a batch that has already been committed. Returns
 * the same array unchanged when nothing matched, so React can skip the update.
 */
export function applyIcmpReplies(
  packets: Packet[],
  replies: { requestFrameId: number; replyId: number }[],
): Packet[] {
  if (replies.length === 0) return packets;
  const replyByFrameId = new Map(replies.map((r) => [r.requestFrameId, r.replyId]));
  let changed = false;
  const next = packets.map((p) => {
    const replyId = replyByFrameId.get(p.id);
    if (replyId === undefined) return p;
    changed = true;
    return { ...p, info: `${p.info} (reply in ${replyId})` };
  });
  return changed ? next : packets;
}
