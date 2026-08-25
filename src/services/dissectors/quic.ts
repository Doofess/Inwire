/**
 * QUIC header dissection.
 *
 * Everything QUIC carries beyond the header is encrypted, but the header
 * itself is not, and it is what the Protocol and most of the Info column are
 * built from:
 *
 *   Initial, DCID=9635b6f53a7cb323, PKN: 1, CRYPTO, CRYPTO, PING
 *   0-RTT, DCID=9635b6f53a7cb323
 *   Handshake, DCID=f635b6f53a7cb323
 *
 * The "PKN: n" and frame-type tail requires removing header protection and
 * decrypting the payload. Initial packets *can* be decrypted - their keys
 * derive from the connection ID via HKDF - but 0-RTT and Handshake packets
 * cannot without the TLS session secrets, which is why Wireshark shows no tail
 * for those either. Only the unprotected header is parsed here; see the
 * project notes for the decryption follow-up.
 */

/** Long-header packet types for QUIC v1 (RFC 9000). */
const LONG_PACKET_TYPES_V1: Record<number, string> = {
  0: 'Initial',
  1: '0-RTT',
  2: 'Handshake',
  3: 'Retry',
};

/** Long-header packet types renumbered by QUIC v2 (RFC 9369). */
const LONG_PACKET_TYPES_V2: Record<number, string> = {
  0: 'Retry',
  1: 'Initial',
  2: '0-RTT',
  3: 'Handshake',
};

export interface QuicDissectorResult {
  info: string;
  /** Connection IDs this header advertised, hex-encoded; empty for short headers. */
  connectionIds: string[];
  isLongHeader: boolean;
  /** Where the next coalesced packet starts, or `end` if this was the last. */
  nextPacketOffset: number;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Reads a QUIC variable-length integer (RFC 9000 §16). The top two bits of the
 * first byte give the encoded length: 1, 2, 4, or 8 bytes, with the remaining
 * bits forming the value.
 */
function readVarint(bytes: Uint8Array, offset: number, end: number): { value: number; nextOffset: number } | null {
  if (offset >= end) return null;
  const prefix = bytes[offset] >> 6;
  const length = 1 << prefix;
  if (offset + length > end) return null;

  let value = bytes[offset] & 0x3f;
  for (let i = 1; i < length; i++) {
    value = value * 256 + bytes[offset + i];
  }
  return { value, nextOffset: offset + length };
}

/**
 * Dissects a QUIC packet's header. Returns null when the bytes don't look like
 * QUIC, so a non-QUIC datagram on port 443 still falls back to a plain UDP
 * summary rather than being mislabeled.
 *
 * `knownConnectionId` is supplied by the caller for short-header packets: it
 * is the connection ID this flow's handshake advertised, if the bytes after
 * the first one match it. Short headers carry no version and no length prefix
 * on their connection ID, so without prior flow state they are not
 * identifiable - the caller must decline to call this for an unknown flow.
 */
export function dissectQuic(
  bytes: Uint8Array,
  start: number,
  end: number,
  knownConnectionId?: string
): QuicDissectorResult | null {
  if (start >= end) return null;

  const firstByte = bytes[start];
  const isLongHeader = (firstByte & 0x80) !== 0;

  // Fixed Bit must be set on every QUIC packet other than the deliberately
  // disguised ones, and is the cheapest way to reject non-QUIC UDP traffic.
  if ((firstByte & 0x40) === 0) return null;

  if (!isLongHeader) {
    // The key phase bit lives under header protection along with the reserved
    // bits and the packet-number length, so it cannot be read without the
    // keys. Wireshark reports KP0 for a packet it hasn't decrypted, and so do
    // we - reading the masked bit directly reports a random phase.
    return {
      info: knownConnectionId
        ? `Protected Payload (KP0), DCID=${knownConnectionId}`
        : 'Protected Payload (KP0)',
      connectionIds: [],
      isLongHeader: false,
      /** A short header runs to the end of the datagram; nothing follows it. */
      nextPacketOffset: end,
    };
  }

  if (start + 6 > end) return null;

  const version =
    ((bytes[start + 1] << 24) | (bytes[start + 2] << 16) | (bytes[start + 3] << 8) | bytes[start + 4]) >>> 0;

  // Version 0 means Version Negotiation, which has no packet-type field.
  if (version === 0) {
    return { info: 'Version Negotiation', connectionIds: [], isLongHeader: true, nextPacketOffset: end };
  }

  const dcidLen = bytes[start + 5];
  if (dcidLen > 20 || start + 6 + dcidLen > end) return null;
  const dcid = bytes.subarray(start + 6, start + 6 + dcidLen);

  const scidLenOffset = start + 6 + dcidLen;
  if (scidLenOffset >= end) return null;
  const scidLen = bytes[scidLenOffset];
  if (scidLen > 20 || scidLenOffset + 1 + scidLen > end) return null;
  const scid = bytes.subarray(scidLenOffset + 1, scidLenOffset + 1 + scidLen);

  const isV2 = version === 0x6b3343cf;
  const typeBits = (firstByte >> 4) & 0x03;
  const packetType = (isV2 ? LONG_PACKET_TYPES_V2 : LONG_PACKET_TYPES_V1)[typeBits] ?? 'Unknown';

  // Wireshark names whichever connection ID is non-empty, preferring the
  // destination - a server's reply carries only its own source CID.
  const dcidHex = toHex(dcid);
  const scidHex = toHex(scid);
  const parts = [packetType];
  if (dcidLen > 0) parts.push(`DCID=${dcidHex}`);
  else if (scidLen > 0) parts.push(`SCID=${scidHex}`);

  // Locate the next coalesced packet. Initial, 0-RTT and Handshake packets all
  // carry an explicit Length covering their packet number and payload, which
  // is precisely so a receiver can find the packet after them in the same
  // datagram. Retry and Version Negotiation have no Length and run to the end.
  let nextPacketOffset = end;
  if (packetType !== 'Retry') {
    let cursor = scidLenOffset + 1 + scidLen;
    if (packetType === 'Initial') {
      // Initial packets prepend a token, itself length-prefixed.
      const tokenLength = readVarint(bytes, cursor, end);
      if (!tokenLength) return null;
      cursor = tokenLength.nextOffset + tokenLength.value;
    }
    const payloadLength = readVarint(bytes, cursor, end);
    if (payloadLength) {
      const candidate = payloadLength.nextOffset + payloadLength.value;
      if (candidate > cursor && candidate <= end) nextPacketOffset = candidate;
    }
  }

  return {
    info: parts.join(', '),
    connectionIds: [dcidHex, scidHex].filter(id => id.length > 0),
    isLongHeader: true,
    nextPacketOffset,
  };
}

/**
 * Dissects every QUIC packet coalesced into one UDP datagram.
 *
 * A datagram may carry several packets back to back - typically a Handshake
 * followed by a 1-RTT packet - and Wireshark summarizes the datagram with the
 * *last* one, so that is what `info` reports. Connection IDs are collected
 * across all of them, since any long header in the datagram teaches us an ID
 * that later short headers will use.
 */
export function dissectQuicDatagram(
  bytes: Uint8Array,
  start: number,
  end: number,
  knownConnectionId?: string
): QuicDissectorResult | null {
  let offset = start;
  let last: QuicDissectorResult | null = null;
  const connectionIds: string[] = [];
  let sawLongHeader = false;

  // Bounded so a packet that fails to advance can't spin; real datagrams
  // coalesce a handful of packets at most.
  for (let packets = 0; packets < 8 && offset < end; packets++) {
    const result = dissectQuic(bytes, offset, end, knownConnectionId);
    if (!result) break;

    last = result;
    connectionIds.push(...result.connectionIds);
    sawLongHeader = sawLongHeader || result.isLongHeader;

    if (result.nextPacketOffset <= offset) break;
    offset = result.nextPacketOffset;
  }

  return last ? { ...last, connectionIds, isLongHeader: sawLongHeader } : null;
}
