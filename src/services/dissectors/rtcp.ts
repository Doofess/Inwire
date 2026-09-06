/**
 * RTCP (RFC 3550), the control channel beside an RTP media stream.
 *
 *   Sender Report
 *   Sender Report   Source description
 *
 * It has no assigned port - it runs on whatever SIP or ICE negotiated, usually
 * one above the media - so it is found by content or not at all.
 *
 * **RTP itself is deliberately not dissected here**, and that is the more
 * interesting half. An RTP packet's only fingerprint is two version bits and a
 * payload type in a wide range, which is far too weak to claim a payload on:
 * Wireshark ships its own `rtp.heuristic_rtp` preference **off** for exactly
 * that reason, and shows a bare RTP packet as `UDP`. Verified, not assumed -
 * `tshark -o rtp.heuristic_rtp:TRUE` names the same frames RTP and without it
 * they are UDP. Claiming them would break agreement with the reference
 * analyzer on every capture containing media, in exchange for a label that is
 * a guess. RTCP is different and is what makes the pair findable anyway: its
 * packet types are a narrow, reserved range, and Wireshark reads it by default.
 *
 * The specificity rule is Wireshark's, and it is narrower than RFC 3550 §6.1's
 * "must begin with SR or RR": see `MAY_LEAD`. A lone Source Description is not
 * claimed - tshark shows it as UDP - because its payload is mostly free text
 * and the shape alone is not distinctive.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';

export interface RtcpResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

const SR = 200, RR = 201, SDES = 202, BYE = 203, APP = 204;

/** Wireshark's spelling, which is not consistently capitalised - copied as is. */
const TYPE_NAMES: Record<number, string> = {
  192: 'Full Intra-frame Request (H261)',
  193: 'Negative Acknowledgement (H261)',
  [SR]: 'Sender Report',
  [RR]: 'Receiver Report',
  [SDES]: 'Source description',
  [BYE]: 'Goodbye',
  [APP]: 'Application specific',
  205: 'Generic RTP Feedback',
  206: 'Payload-specific Feedback',
  207: 'Extended report (RFC 3611)',
};

/** The lowest and highest packet type this recognises at all. */
const MIN_TYPE = 192, MAX_TYPE = 223;

/**
 * The packet types a datagram may OPEN with.
 *
 * Not the same as the types it may contain, and not simply "SR or RR" as
 * RFC 3550 §6.1 requires - established by asking tshark one type at a time:
 * 200, 201 and 203 through 207 lead; 202 (Source Description), 192 and 193
 * (the legacy H.261 types) and anything above 207 do not. A lone SDES comes
 * back from tshark as `UDP`, so accepting one would make this eager where the
 * reference analyzer is careful, on a payload that is mostly free text.
 */
const MAY_LEAD = new Set([200, 201, 203, 204, 205, 206, 207]);

interface RtcpPacket {
  version: number;
  padding: boolean;
  count: number;
  type: number;
  /** Length in 32-bit words, not counting the first - so bytes are 4*(len+1). */
  words: number;
  start: number;
  end: number;
}

function readPacket(bytes: Uint8Array, offset: number, end: number): RtcpPacket | null {
  if (offset + 4 > end) return null;
  const first = bytes[offset];
  const version = first >> 6;
  if (version !== 2) return null;
  const type = bytes[offset + 1];
  if (type < MIN_TYPE || type > MAX_TYPE) return null;
  const words = (bytes[offset + 2] << 8) | bytes[offset + 3];
  const packetEnd = offset + 4 * (words + 1);
  if (packetEnd > end || packetEnd <= offset) return null;
  return {
    version,
    padding: (first & 0x20) !== 0,
    count: first & 0x1f,
    type,
    words,
    start: offset,
    end: packetEnd,
  };
}

/** Every packet in a compound datagram, or null if the framing does not add up. */
function readCompound(bytes: Uint8Array, start: number, end: number): RtcpPacket[] | null {
  const out: RtcpPacket[] = [];
  let p = start;
  while (p < end) {
    const packet = readPacket(bytes, p, end);
    if (packet === null) return null;
    out.push(packet);
    p = packet.end;
    if (out.length > 16) return null;   // a compound packet is a handful, not a stream
  }
  // The lengths must tile the datagram exactly. That is the strongest part of
  // the fingerprint: random bytes will not describe their own size correctly
  // several times in a row.
  return out.length > 0 && p === end ? out : null;
}

/**
 * True when these bytes are RTCP.
 *
 * Version 2, self-describing lengths that tile the datagram exactly, and a
 * first packet whose type `MAY_LEAD`. The tiling is the strongest part: random
 * bytes do not describe their own size correctly several times in a row.
 */
export function looksLikeRtcp(bytes: Uint8Array, start: number, end: number): boolean {
  const packets = readCompound(bytes, start, end);
  return packets !== null && MAY_LEAD.has(packets[0].type);
}

export function dissectRtcp(bytes: Uint8Array, start: number, end: number): RtcpResult | null {
  const packets = readCompound(bytes, start, end);
  if (packets === null) return null;
  const first = packets[0];

  const fields: Record<string, string | number> = {
    'rtcp.version': first.version,
    'rtcp.pt': first.type,
  };

  const layers: ProtocolField[] = [];
  const infoParts: string[] = [];

  for (const packet of packets) {
    const typeName = TYPE_NAMES[packet.type] ?? `Unknown (${packet.type})`;
    // Wireshark writes each packet's name followed by three spaces, and
    // concatenates them for a compound datagram.
    infoParts.push(`${typeName}   `);

    const rows: ProtocolField[] = [
      { name: 'Version', value: `RFC 1889 Version (${packet.version})`, abbrev: 'rtcp.version',
        rawBytesRange: [packet.start, packet.start] },
      { name: 'Padding', value: packet.padding ? 'True' : 'False', abbrev: 'rtcp.padding' },
      { name: packet.type === SDES ? 'Source count' : 'Reception report count', value: packet.count },
      { name: 'Packet type', value: `${typeName} (${packet.type})`, abbrev: 'rtcp.pt',
        rawBytesRange: [packet.start + 1, packet.start + 1] },
      { name: 'Length', value: `${packet.words} (${4 * (packet.words + 1)} bytes)`,
        abbrev: 'rtcp.length', rawBytesRange: [packet.start + 2, packet.start + 3] },
    ];

    // Every type but APP opens its body with the sender's SSRC, which is what
    // ties a control packet to the media stream it describes.
    if (packet.start + 8 <= packet.end) {
      const ssrc = ((bytes[packet.start + 4] << 24) | (bytes[packet.start + 5] << 16)
        | (bytes[packet.start + 6] << 8) | bytes[packet.start + 7]) >>> 0;
      rows.push({
        name: packet.type === SDES ? 'Chunk SSRC' : 'Sender SSRC',
        value: `0x${ssrc.toString(16).padStart(8, '0')} (${ssrc})`,
        abbrev: 'rtcp.senderssrc',
        rawBytesRange: [packet.start + 4, packet.start + 7],
      });
      fields['rtcp.senderssrc'] ??= ssrc;
    }

    if (packet.type === SR && packet.start + 28 <= packet.end) {
      const u32 = (at: number) => ((bytes[at] << 24) | (bytes[at + 1] << 16)
        | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
      rows.push(
        { name: 'Timestamp, MSW', value: u32(packet.start + 8) },
        { name: 'Timestamp, LSW', value: u32(packet.start + 12) },
        { name: 'RTP timestamp', value: u32(packet.start + 16), abbrev: 'rtcp.timestamp.rtp' },
        { name: "Sender's packet count", value: u32(packet.start + 20), abbrev: 'rtcp.sender.packetcount' },
        { name: "Sender's octet count", value: u32(packet.start + 24), abbrev: 'rtcp.sender.octetcount' },
      );
      fields['rtcp.timestamp.rtp'] = u32(packet.start + 16);
      fields['rtcp.sender.packetcount'] = u32(packet.start + 20);
      fields['rtcp.sender.octetcount'] = u32(packet.start + 24);
    }

    layers.push({ name: typeName, value: '', rawBytesRange: [packet.start, packet.end - 1], children: rows });
  }

  return {
    protocolLabel: 'RTCP',
    info: infoParts.join(''),
    fields,
    layer: {
      name: 'Real-time Transport Control Protocol',
      summary: `Real-time Transport Control Protocol (${TYPE_NAMES[first.type] ?? first.type})`,
      rawBytesRange: [start, Math.max(start, end - 1)],
      // A single packet's rows sit directly under the layer, as Wireshark
      // shows them; a compound one gets a node each, which is the only way to
      // tell whose SSRC is whose.
      fields: packets.length === 1 ? layers[0].children ?? [] : layers,
    },
  };
}
