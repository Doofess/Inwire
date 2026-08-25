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
 * The "PKN: n" and frame-type tail needs the payload decrypted, which is only
 * possible for Initial packets: their keys derive from the connection ID via
 * HKDF, and that is on the wire in the clear. See quicCrypto.ts. 0-RTT,
 * Handshake and 1-RTT packets need the TLS session secrets, so they carry no
 * tail here - and none in Wireshark either.
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

/**
 * Frame type names (RFC 9000 §12.4). Several types occupy a range because
 * their low bits carry flags: ACK's bit 0 signals ECN counts, and STREAM's
 * low three bits signal which of offset/length/fin are present.
 */
function frameTypeName(type: number): string {
  if (type >= 0x08 && type <= 0x0f) return 'STREAM';
  if (type === 0x02 || type === 0x03) return 'ACK';
  if (type === 0x12 || type === 0x13) return 'MAX_STREAMS';
  if (type === 0x16 || type === 0x17) return 'STREAMS_BLOCKED';
  if (type === 0x1c || type === 0x1d) return 'CONNECTION_CLOSE';
  return {
    0x00: 'PADDING', 0x01: 'PING', 0x04: 'RESET_STREAM', 0x05: 'STOP_SENDING',
    0x06: 'CRYPTO', 0x07: 'NEW_TOKEN', 0x10: 'MAX_DATA', 0x11: 'MAX_STREAM_DATA',
    0x14: 'DATA_BLOCKED', 0x15: 'STREAM_DATA_BLOCKED', 0x18: 'NEW_CONNECTION_ID',
    0x19: 'RETIRE_CONNECTION_ID', 0x1a: 'PATH_CHALLENGE', 0x1b: 'PATH_RESPONSE',
    0x1e: 'HANDSHAKE_DONE',
  }[type] ?? `Unknown (0x${type.toString(16)})`;
}

/**
 * Walks the frames in a decrypted packet payload and names them in order.
 *
 * Runs of PADDING collapse to a single entry - a packet padded out to the
 * 1200-byte minimum contains hundreds of them, and listing each would bury
 * everything else. Wireshark does the same, which is why its Info reads
 * "PADDING, PING, PADDING" rather than one PADDING per byte.
 */
function summarizeFrames(payload: Uint8Array): string[] {
  const names: string[] = [];
  const end = payload.length;
  let offset = 0;

  while (offset < end) {
    const typeVarint = readVarint(payload, offset, end);
    if (!typeVarint) break;
    const type = typeVarint.value;
    let cursor = typeVarint.nextOffset;

    const name = frameTypeName(type);
    if (name !== 'PADDING' || names[names.length - 1] !== 'PADDING') names.push(name);

    // Skip the frame body so the next frame type is read from the right place.
    // A frame whose body doesn't parse means the rest of the payload can't be
    // trusted either, so parsing stops rather than emitting noise.
    const skipVarints = (count: number): boolean => {
      for (let i = 0; i < count; i++) {
        const value = readVarint(payload, cursor, end);
        if (!value) return false;
        cursor = value.nextOffset;
      }
      return true;
    };
    const skipLengthPrefixed = (): boolean => {
      const length = readVarint(payload, cursor, end);
      if (!length) return false;
      cursor = length.nextOffset + length.value;
      return cursor <= end;
    };

    let ok = true;
    switch (true) {
      case type === 0x00 || type === 0x01 || type === 0x1e:
        break; // PADDING, PING, HANDSHAKE_DONE carry no body
      case type === 0x02 || type === 0x03: {
        // Largest Acknowledged, ACK Delay, then a count of additional ranges,
        // the first range, and finally that many (gap, length) pairs. The
        // 0x03 variant appends three ECN counters.
        if (!skipVarints(2)) { ok = false; break; }
        const rangeCount = readVarint(payload, cursor, end);
        if (!rangeCount || rangeCount.value > 1000) { ok = false; break; }
        cursor = rangeCount.nextOffset;
        ok = skipVarints(1 + rangeCount.value * 2);
        if (ok && type === 0x03) ok = skipVarints(3);
        break;
      }
      case type === 0x04: ok = skipVarints(3); break; // RESET_STREAM
      case type === 0x05: ok = skipVarints(2); break; // STOP_SENDING
      case type === 0x06: ok = skipVarints(1) && skipLengthPrefixed(); break; // CRYPTO: offset, then data
      case type === 0x07: ok = skipLengthPrefixed(); break; // NEW_TOKEN
      case type >= 0x08 && type <= 0x0f: {
        ok = skipVarints(1); // stream id
        if (ok && (type & 0x04) !== 0) ok = skipVarints(1); // offset
        if (!ok) break;
        if ((type & 0x02) !== 0) ok = skipLengthPrefixed();
        else cursor = end; // no length means the frame runs to the packet's end
        break;
      }
      case type === 0x10 || type === 0x14 || type === 0x19: ok = skipVarints(1); break;
      case type === 0x11 || type === 0x15: ok = skipVarints(2); break;
      case type === 0x12 || type === 0x13 || type === 0x16 || type === 0x17: ok = skipVarints(1); break;
      case type === 0x18: { // NEW_CONNECTION_ID
        ok = skipVarints(2);
        if (!ok || cursor >= end) { ok = false; break; }
        cursor += 1 + payload[cursor] + 16; // length byte, connection id, reset token
        ok = cursor <= end;
        break;
      }
      case type === 0x1a || type === 0x1b: cursor += 8; ok = cursor <= end; break;
      case type === 0x1c: ok = skipVarints(2) && skipLengthPrefixed(); break;
      case type === 0x1d: ok = skipVarints(1) && skipLengthPrefixed(); break;
      default: ok = false;
    }

    if (!ok || cursor <= offset) break;
    offset = cursor;
  }

  return names;
}

/**
 * Decrypts one Initial packet, given where its packet number starts and where
 * the packet ends. Supplied by the caller because key derivation and
 * packet-number tracking are per-connection state that outlives one datagram.
 * Returns null when the packet cannot be decrypted, which is the normal answer
 * for a connection whose first Initial was not captured.
 */
export type InitialDecryptor = (
  packetStart: number,
  packetNumberOffset: number,
  packetEnd: number,
  version: number,
  destinationConnectionId: Uint8Array
) => { packetNumber: number; payload: Uint8Array } | null;

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
  knownConnectionId?: string,
  decryptInitial?: InitialDecryptor
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
  let packetNumberOffset = -1;
  if (packetType !== 'Retry') {
    let cursor = scidLenOffset + 1 + scidLen;
    if (packetType === 'Initial') {
      // Initial packets prepend a token, itself length-prefixed.
      const tokenLength = readVarint(bytes, cursor, end);
      if (!tokenLength) return null;
      cursor = tokenLength.nextOffset + tokenLength.value;
    }
    const payloadLength = readVarint(bytes, cursor, end);
    if (payloadLength) packetNumberOffset = payloadLength.nextOffset;
    if (payloadLength) {
      const candidate = payloadLength.nextOffset + payloadLength.value;
      if (candidate > cursor && candidate <= end) nextPacketOffset = candidate;
    }
  }

  // Initial packets are the only ones a passive observer can read: their keys
  // derive from the client's original Destination Connection ID, which is on
  // the wire in the clear. Everything else needs the TLS session secrets.
  if (packetType === 'Initial' && decryptInitial && packetNumberOffset > 0) {
    const decrypted = decryptInitial(start, packetNumberOffset, nextPacketOffset, version, dcid);
    if (decrypted) {
      parts.push(`PKN: ${decrypted.packetNumber}`);
      parts.push(...summarizeFrames(decrypted.payload));
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
  knownConnectionId?: string,
  decryptInitial?: InitialDecryptor
): QuicDissectorResult | null {
  let offset = start;
  let last: QuicDissectorResult | null = null;
  const connectionIds: string[] = [];
  let sawLongHeader = false;

  // Bounded so a packet that fails to advance can't spin; real datagrams
  // coalesce a handful of packets at most.
  for (let packets = 0; packets < 8 && offset < end; packets++) {
    const result = dissectQuic(bytes, offset, end, knownConnectionId, decryptInitial);
    if (!result) break;

    last = result;
    connectionIds.push(...result.connectionIds);
    sawLongHeader = sawLongHeader || result.isLongHeader;

    if (result.nextPacketOffset <= offset) break;
    offset = result.nextPacketOffset;
  }

  return last ? { ...last, connectionIds, isLongHeader: sawLongHeader } : null;
}
