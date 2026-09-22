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
 * tail here - and none in the reference analyzer either.
 */
import { toHex } from '../addressFormat';
import type { ProtocolField, ProtocolLayer } from '../../types/packet';

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
 * everything else. The reference analyzer does the same, which is why its Info reads
 * "PADDING, PING, PADDING" rather than one PADDING per byte.
 */
function summarizeFrames(payload: Uint8Array): {
  names: string[];
  crypto: CryptoFragment[];
  streams: StreamFragment[];
  records: QuicFrameRecord[];
} {
  const names: string[] = [];
  const crypto: CryptoFragment[] = [];
  const streams: StreamFragment[] = [];
  // One record per NAME, not per frame on the wire: a run of PADDING collapses
  // to a single entry below, and the tree has to agree with the Info column
  // about how many frames a packet carried. Wireshark draws one PADDING row per
  // run too, with the run's length on it.
  const records: QuicFrameRecord[] = [];
  const end = payload.length;
  let offset = 0;

  while (offset < end) {
    const typeVarint = readVarint(payload, offset, end);
    if (!typeVarint) break;
    const type = typeVarint.value;
    let cursor = typeVarint.nextOffset;

    const name = frameTypeName(type);
    if (name !== 'PADDING' || names[names.length - 1] !== 'PADDING') {
      names.push(name);
      records.push({ type, name });
    }

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
      case type === 0x06: {
        // CRYPTO: offset, then length-prefixed handshake bytes. The bytes are
        // kept, not just skipped: reassembled across frames and packets they
        // are the TLS ClientHello, which is where a QUIC connection's SNI,
        // ALPN and fingerprint live. A hello with a post-quantum key share
        // does not fit one Initial packet, so this is the only way to read it.
        const offsetVarint = readVarint(payload, cursor, end);
        if (!offsetVarint) { ok = false; break; }
        const lengthVarint = readVarint(payload, offsetVarint.nextOffset, end);
        if (!lengthVarint) { ok = false; break; }
        const dataStart = lengthVarint.nextOffset;
        const dataEnd = dataStart + lengthVarint.value;
        if (dataEnd > end) { ok = false; break; }
        crypto.push({ offset: offsetVarint.value, data: payload.slice(dataStart, dataEnd) });
        const record = records[records.length - 1];
        record.cryptoOffset = offsetVarint.value;
        record.cryptoLength = lengthVarint.value;
        record.cryptoData = hexOfRange(payload, dataStart, dataEnd);
        cursor = dataEnd;
        break;
      }
      case type === 0x07: ok = skipLengthPrefixed(); break; // NEW_TOKEN
      case type >= 0x08 && type <= 0x0f: {
        // STREAM: the low three bits of the type say which optional fields are
        // present - OFF (0x04), LEN (0x02) and FIN (0x01). The data is kept
        // rather than skipped: over a 1-RTT packet it is HTTP/3, and the
        // offset is what lets a stream be put back together across packets
        // that QUIC is free to deliver in any order.
        const idVarint = readVarint(payload, cursor, end);
        if (!idVarint) { ok = false; break; }
        cursor = idVarint.nextOffset;

        let streamOffset = 0;
        if ((type & 0x04) !== 0) {
          const offsetVarint = readVarint(payload, cursor, end);
          if (!offsetVarint) { ok = false; break; }
          streamOffset = offsetVarint.value;
          cursor = offsetVarint.nextOffset;
        }

        let dataStart = cursor;
        let dataEnd = end;
        if ((type & 0x02) !== 0) {
          const lengthVarint = readVarint(payload, cursor, end);
          if (!lengthVarint) { ok = false; break; }
          dataStart = lengthVarint.nextOffset;
          dataEnd = dataStart + lengthVarint.value;
          if (dataEnd > end) { ok = false; break; }
        }
        streams.push({
          streamId: idVarint.value, offset: streamOffset,
          data: payload.slice(dataStart, dataEnd), fin: (type & 0x01) !== 0,
        });
        const record = records[records.length - 1];
        record.streamId = idVarint.value;
        record.streamOffset = streamOffset;
        record.streamLength = dataEnd - dataStart;
        record.streamFin = (type & 0x01) !== 0;
        cursor = dataEnd;
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

  return { names, crypto, streams, records };
}

/**
 * Decrypts one Initial packet, given where its packet number starts and where
 * the packet ends. Supplied by the caller because key derivation and
 * packet-number tracking are per-connection state that outlives one datagram.
 * Returns null when the packet cannot be decrypted, which is the normal answer
 * for a connection whose first Initial was not captured.
 */
/** Which packet-number space and which keys a packet belongs to. */
export type QuicPacketKind = 'initial' | '0rtt' | 'handshake' | '1rtt';

export type PacketDecryptor = (
  packetStart: number,
  packetNumberOffset: number,
  packetEnd: number,
  version: number,
  destinationConnectionId: Uint8Array,
  kind: QuicPacketKind
) => { packetNumber: number; payload: Uint8Array; firstByte: number; packetNumberLength: number } | null;

/** One STREAM frame's contribution to a QUIC stream. */
export interface StreamFragment {
  streamId: number;
  offset: number;
  data: Uint8Array;
  fin: boolean;
}

/** One CRYPTO frame's contribution to the handshake stream. */
export interface CryptoFragment {
  offset: number;
  data: Uint8Array;
}

/**
 * One frame inside a decrypted packet payload, for the tree.
 *
 * Separate from `CryptoFragment`/`StreamFragment`, which are what the *tracker*
 * consumes to reassemble across packets. This is what the *detail pane* draws,
 * so it keeps lengths and offsets rather than bytes - a CRYPTO frame's bytes
 * are already carried by the fragment beside it and copying them twice per
 * frame is exactly the per-frame cost ADRs 0016-0018 exist to hold down.
 */
export interface QuicFrameRecord {
  type: number;
  name: string;
  cryptoOffset?: number;
  cryptoLength?: number;
  /** The frame's data bytes, hex. The reference names these and this did not. */
  cryptoData?: string;
  streamId?: number;
  streamOffset?: number;
  streamLength?: number;
  streamFin?: boolean;
}

/**
 * One QUIC packet's header, as read rather than as rendered.
 *
 * **The Info string is not built from this and must not be.** `info` is held to
 * the reference analyzer frame for frame by `scripts/parity/parity-check.ts`
 * (the Info floors) and by the `quicRows` counts in
 * `test/fixtures/acceptance.json`, so it is assembled exactly where it always
 * was. This record is the same facts kept rather than discarded, which is what
 * the tree and the field bag are built from (ADR 0039).
 *
 * Every member is optional past `headerForm` and `typeName` because a QUIC
 * header is not one shape: a short header has no version and no connection-id
 * length, Version Negotiation has no packet type, and Retry has no Length. A
 * row is drawn only where the fact was actually read, which is the same rule
 * the status bar keeps - never show a zero that was never measured.
 */
/**
 * `toHex` over a slice, clamped, colon-separated.
 *
 * Colons because the reference's `show` carries them for every FT_BYTES, and
 * `show` is what `tree-coverage.ts` compares - its `showname` runs the same
 * bytes together, so reading the human-facing line produces a mismatch on
 * every frame. The clamp is not decoration: these offsets are derived from
 * length fields an adversary writes.
 */
function hexOfRange(bytes: Uint8Array, from: number, to: number): string {
  const start = Math.max(0, Math.min(from, bytes.length));
  const stop = Math.max(start, Math.min(to, bytes.length));
  let out = '';
  for (let i = start; i < stop; i++) {
    if (out.length > 0) out += ':';
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export interface QuicPacketRecord {
  headerForm: 'long' | 'short';
  /** `Initial`, `Handshake`, `Protected Payload (KP0)`, ... */
  typeName: string;
  /** The long header's 2-bit type field, as it sits on the wire. */
  longPacketType?: number;
  version?: number;
  dcid?: string;
  dcidLength?: number;
  scid?: string;
  scidLength?: number;
  tokenLength?: number;
  /** The header's own Length field: packet number plus protected payload. */
  payloadLength?: number;
  /** Only ever present when the packet could be decrypted. */
  packetNumber?: number;
  frames: QuicFrameRecord[];
  /**
   * The first byte's Fixed Bit, and - on a short header - its Spin Bit.
   *
   * Both are readable without keys, which is the whole reason they are here
   * and the reserved bits are not: RFC 9001 protects the low four bits of a
   * long header and the low five of a short one, so the reserved bits and the
   * packet-number length cannot be read on a packet this build could not
   * decrypt, and the spin bit at 0x20 can.
   */
  fixedBit: boolean;
  spinBit?: boolean;
  /** This packet's length within the datagram, coalesced packets counted apart. */
  packetLength?: number;
  /**
   * The long header's two reserved bits, present only once the header has been
   * unprotected - which means only on a packet that decrypted.
   */
  reserved?: number;
  /** The packet-number length field's raw 2-bit value; the byte count is it plus one. */
  packetNumberLengthField?: number;
  /**
   * The protected payload, hex, on a packet that DID decrypt: everything after
   * the packet number to the end of the packet.
   *
   * The reference draws these bytes and the frames it read out of them, which
   * looks redundant and is not - the bytes are what a reader compares against
   * another capture, and the frames are this build's interpretation of them.
   */
  payloadHex?: string;
  /**
   * The same region on a packet that did NOT decrypt, which the reference
   * names differently and measures differently: from the end of the Length
   * field rather than from the end of the packet number, because without
   * header protection removed nobody knows how long the packet number is.
   */
  remainingPayloadHex?: string;
}

export interface QuicDissectorResult {
  info: string;
  /** CRYPTO frames decrypted out of this datagram's Initial packets. */
  cryptoFragments: CryptoFragment[];
  /** STREAM frames decrypted out of this datagram's Handshake and 1-RTT packets. */
  streamFragments: StreamFragment[];
  /** Connection IDs this header advertised, hex-encoded; empty for short headers. */
  connectionIds: string[];
  isLongHeader: boolean;
  /**
   * Every packet coalesced into this datagram, in wire order.
   *
   * `info` summarizes the datagram with the LAST packet, which is what the
   * reference analyzer does; the tree draws all of them, which is also what it
   * does. Both readings come from here now rather than one of them being the
   * only one kept.
   */
  packets: QuicPacketRecord[];
  /** Where the next coalesced packet starts, or `end` if this was the last. */
  nextPacketOffset: number;
}


/**
 * Reads a QUIC variable-length integer (RFC 9000 §16). The top two bits of the
 * first byte give the encoded length: 1, 2, 4, or 8 bytes, with the remaining
 * bits forming the value.
 *
 * Exported because HTTP/3 uses this exact encoding for its own frame types,
 * lengths and settings (RFC 9114 §7), and `dissectors/http3.ts` had a second
 * copy of it. The import runs http3 -> quic, which is the way the layering
 * already points; there is no cycle. `quic.ts`'s only other imports are
 * `addressFormat` and a TYPE-only one from `types/packet`, which `buildQuicLayer`
 * below needs and which erases at compile time.
 * `qpack.ts`'s prefix integer is a DIFFERENT encoding (HPACK's, RFC 7541 §5.1)
 * and must not be folded in here.
 */
export function readVarint(bytes: Uint8Array, offset: number, end: number): { value: number; nextOffset: number } | null {
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
function dissectQuic(
  bytes: Uint8Array,
  start: number,
  end: number,
  knownConnectionId?: string,
  decryptPacket?: PacketDecryptor
): QuicDissectorResult | null {
  if (start >= end) return null;

  const firstByte = bytes[start];
  const isLongHeader = (firstByte & 0x80) !== 0;

  // Fixed Bit must be set on every QUIC packet other than the deliberately
  // disguised ones, and is the cheapest way to reject non-QUIC UDP traffic.
  if ((firstByte & 0x40) === 0) return null;

  if (!isLongHeader) {
    // A short header carries no length and no connection-id length: it runs to
    // the end of the datagram, and where its packet number begins depends
    // entirely on how long the connection id is - which only the flow's own
    // history says. A flow whose handshake was not captured is unreadable for
    // this reason alone, keys or no keys.
    const dcidLength = knownConnectionId ? knownConnectionId.length / 2 : 0;
    const decrypted = decryptPacket
      ? decryptPacket(start, start + 1 + dcidLength, end, 0, new Uint8Array(0), '1rtt')
      : null;

    if (decrypted) {
      const frames = summarizeFrames(decrypted.payload);
      const parts = ['Protected Payload (KP0)'];
      if (knownConnectionId) parts.push(`DCID=${knownConnectionId}`);
      parts.push(`PKN: ${decrypted.packetNumber}`, ...frames.names);
      return {
        info: parts.join(', '),
        cryptoFragments: frames.crypto,
        streamFragments: frames.streams,
        connectionIds: [],
        isLongHeader: false,
        packets: [{
          headerForm: 'short',
          typeName: 'Protected Payload (KP0)',
          ...(knownConnectionId ? { dcid: knownConnectionId, dcidLength: dcidLength } : {}),
          packetNumber: decrypted.packetNumber,
          packetNumberLengthField: decrypted.firstByte & 0x03,
          payloadHex: hexOfRange(bytes, start + 1 + dcidLength + decrypted.packetNumberLength, end),
          frames: frames.records,
          fixedBit: true,
          spinBit: (firstByte & 0x20) !== 0,
          packetLength: end - start,
        }],
        nextPacketOffset: end,
      };
    }

    // The key phase bit lives under header protection along with the reserved
    // bits and the packet-number length, so it cannot be read without the
    // keys. The reference analyzer reports KP0 for a packet it hasn't decrypted, and so do
    // we - reading the masked bit directly reports a random phase.
    return {
      info: knownConnectionId
        ? `Protected Payload (KP0), DCID=${knownConnectionId}`
        : 'Protected Payload (KP0)',
      cryptoFragments: [],
      streamFragments: [],
      connectionIds: [],
      isLongHeader: false,
      packets: [{
        headerForm: 'short',
        typeName: 'Protected Payload (KP0)',
        ...(knownConnectionId ? { dcid: knownConnectionId, dcidLength: dcidLength } : {}),
        frames: [],
        fixedBit: true,
        spinBit: (firstByte & 0x20) !== 0,
        packetLength: end - start,
        // Everything past the first byte and the connection id. The packet
        // number is in there and is not separated out, because its length is
        // under the protection this packet could not remove.
        remainingPayloadHex: hexOfRange(bytes, start + 1 + dcidLength, end),
      }],
      /** A short header runs to the end of the datagram; nothing follows it. */
      nextPacketOffset: end,
    };
  }

  if (start + 6 > end) return null;

  const version =
    ((bytes[start + 1] << 24) | (bytes[start + 2] << 16) | (bytes[start + 3] << 8) | bytes[start + 4]) >>> 0;

  // Version 0 means Version Negotiation, which has no packet-type field.
  if (version === 0) {
    return {
      info: 'Version Negotiation',
      cryptoFragments: [], streamFragments: [], connectionIds: [], isLongHeader: true,
      packets: [{ headerForm: 'long', typeName: 'Version Negotiation', version: 0, frames: [], fixedBit: true }],
      nextPacketOffset: end,
    };
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

  // The reference analyzer names whichever connection ID is non-empty, preferring the
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
  // Hoisted out of the block below because the tree draws them. They stay
  // `null` rather than 0 where the header has no such field at all - Retry
  // carries neither, and only Initial carries a token.
  let tokenLength: number | null = null;
  let headerPayloadLength: number | null = null;
  if (packetType !== 'Retry') {
    let cursor = scidLenOffset + 1 + scidLen;
    if (packetType === 'Initial') {
      // Initial packets prepend a token, itself length-prefixed.
      const token = readVarint(bytes, cursor, end);
      if (!token) return null;
      tokenLength = token.value;
      cursor = token.nextOffset + token.value;
    }
    const payloadLength = readVarint(bytes, cursor, end);
    if (payloadLength) {
      packetNumberOffset = payloadLength.nextOffset;
      headerPayloadLength = payloadLength.value;
      const candidate = payloadLength.nextOffset + payloadLength.value;
      if (candidate > cursor && candidate <= end) nextPacketOffset = candidate;
    }
  }

  // Initial packets are the only ones a passive observer can read unaided:
  // their keys derive from the client's original Destination Connection ID,
  // which is on the wire in the clear. Handshake and 0-RTT packets need the
  // TLS session secrets, so they are attempted only when a key log supplied
  // them - the decryptor answers null otherwise, and the packet stays a name.
  const cryptoFragments: CryptoFragment[] = [];
  const streamFragments: StreamFragment[] = [];
  const record: QuicPacketRecord = {
    headerForm: 'long',
    typeName: packetType,
    longPacketType: typeBits,
    version,
    dcid: dcidHex,
    dcidLength: dcidLen,
    scid: scidHex,
    scidLength: scidLen,
    ...(tokenLength === null ? {} : { tokenLength }),
    ...(headerPayloadLength === null ? {} : { payloadLength: headerPayloadLength }),
    frames: [],
    fixedBit: true,
    // A long header may be one of several packets coalesced into one
    // datagram, so its length is where the next one starts - not the end of
    // the UDP payload.
    packetLength: nextPacketOffset - start,
  };
  const kind: QuicPacketKind | null =
    packetType === 'Initial' ? 'initial'
      : packetType === 'Handshake' ? 'handshake'
        : packetType === '0-RTT' ? '0rtt'
          : null;
  if (kind !== null && decryptPacket && packetNumberOffset > 0) {
    const decrypted = decryptPacket(start, packetNumberOffset, nextPacketOffset, version, dcid, kind);
    if (decrypted) {
      parts.push(`PKN: ${decrypted.packetNumber}`);
      const frames = summarizeFrames(decrypted.payload);
      parts.push(...frames.names);
      cryptoFragments.push(...frames.crypto);
      streamFragments.push(...frames.streams);
      record.packetNumber = decrypted.packetNumber;
      record.frames = frames.records;
      // Readable only now. `firstByte` arrives unprotected from the decryptor
      // because these two fields live under exactly the mask it removes.
      record.reserved = (decrypted.firstByte >> 2) & 0x03;
      record.packetNumberLengthField = decrypted.firstByte & 0x03;
      record.payloadHex = hexOfRange(
        bytes, packetNumberOffset + decrypted.packetNumberLength, nextPacketOffset,
      );
    }
  }
  // Undecrypted, so the payload is named `remaining` and measured from the end
  // of the Length field - the packet number is inside it and unmeasurable.
  if (record.packetNumber === undefined && packetNumberOffset > 0) {
    record.remainingPayloadHex = hexOfRange(bytes, packetNumberOffset, nextPacketOffset);
  }

  return {
    info: parts.join(', '),
    cryptoFragments,
    streamFragments,
    connectionIds: [dcidHex, scidHex].filter(id => id.length > 0),
    isLongHeader: true,
    packets: [record],
    nextPacketOffset,
  };
}

/**
 * Matches a short header's connection id against the ones a flow has shown.
 *
 * A short header writes the id with no length before it, so its length is only
 * knowable from what the flow has already used - which is state the tracker
 * holds and this module deliberately does not.
 */
export type ConnectionIdResolver = (bytes: Uint8Array, offset: number) => string | undefined;

/**
 * Dissects every QUIC packet coalesced into one UDP datagram.
 *
 * A datagram may carry several packets back to back - typically a Handshake
 * followed by a 1-RTT packet - and the reference analyzer summarizes the datagram with the
 * *last* one, so that is what `info` reports. Connection IDs are collected
 * across all of them, since any long header in the datagram teaches us an ID
 * that later short headers will use.
 */
export function dissectQuicDatagram(
  bytes: Uint8Array,
  start: number,
  end: number,
  resolveConnectionId?: ConnectionIdResolver,
  decryptPacket?: PacketDecryptor
): QuicDissectorResult | null {
  let offset = start;
  let last: QuicDissectorResult | null = null;
  const connectionIds: string[] = [];
  const cryptoFragments: CryptoFragment[] = [];
  const streamFragments: StreamFragment[] = [];
  const packets: QuicPacketRecord[] = [];
  let sawLongHeader = false;

  // Bounded so a packet that fails to advance can't spin; real datagrams
  // coalesce a handful of packets at most.
  for (let seen = 0; seen < 8 && offset < end; seen++) {
    // Resolved per PACKET, not per datagram. A short header carries a
    // connection id with no length in front of it, so it can only be read by
    // matching against the ids this flow has already shown - and in a
    // coalesced datagram the short header is not at the start, so a lookup
    // done once on the datagram's first byte answers for the wrong packet.
    // That is what left a 1-RTT packet behind a Handshake with no `DCID=`.
    const isShortHeader = offset < end && (bytes[offset] & 0x80) === 0;
    const knownConnectionId = isShortHeader
      ? resolveConnectionId?.(bytes, offset + 1)
      : undefined;
    const result = dissectQuic(bytes, offset, end, knownConnectionId, decryptPacket);
    if (!result) break;

    last = result;
    connectionIds.push(...result.connectionIds);
    cryptoFragments.push(...result.cryptoFragments);
    streamFragments.push(...result.streamFragments);
    packets.push(...result.packets);
    sawLongHeader = sawLongHeader || result.isLongHeader;

    if (result.nextPacketOffset <= offset) break;
    offset = result.nextPacketOffset;
  }

  return last
    ? { ...last, connectionIds, cryptoFragments, streamFragments, packets, isLongHeader: sawLongHeader }
    : null;
}

/**
 * The QUIC layer for the detail tree, and the fields a filter can read.
 *
 * **This is what ADR 0039's tree coverage found missing.** Until it existed
 * this dissector parsed every header field, decrypted what it could, named the
 * Protocol column and wrote the Info string - and published *not one* `quic.*`
 * abbrev on either surface, against 40 the reference emits on the `inwire`
 * fixture. `test/fixtures/acceptance.json` recorded that under `unimplemented`
 * rather than floored at 0, which is what a measurement is for.
 *
 * One layer per datagram with a subtree per packet, for the reason
 * `buildHttp3Layer` groups by stream: `frameProtocols` is derived from the
 * layer NAMES in order (`pcapParser.ts`), so a datagram coalescing a Handshake
 * and a 1-RTT packet would otherwise put two `quic` tokens in the hierarchy,
 * where a repeated token reads as a protocol nested inside itself.
 *
 * The layer name is the reference's, so `PROTOCOL_NAME_MAP` can map it back to
 * the `quic` token that `protocolTokens` already pushes - the splice in
 * `pcapParser.ts` filters a token a layer already supplies, so the bareword
 * does not double.
 */
export function buildQuicLayer(
  packets: readonly QuicPacketRecord[],
  summary: string,
  connectionNumber?: number
): { layer: ProtocolLayer; fields: Record<string, string | number> } | null {
  if (packets.length === 0) return null;

  const rows: ProtocolField[] = [];
  const fields: Record<string, string | number> = {};

  for (const packet of packets) {
    const children: ProtocolField[] = [
      // First, where the reference puts it: a generated row naming which
      // connection this packet belongs to, before anything read off the wire.
      ...(connectionNumber === undefined ? [] : [{
        name: 'Connection Number', value: connectionNumber,
        abbrev: 'quic.connection.number', generated: true,
      }]),
      {
        name: 'Header Form',
        value: packet.headerForm === 'long' ? 'Long Header (1)' : 'Short Header (0)',
        abbrev: 'quic.header_form',
      },
      // Set on every QUIC packet that is not deliberately disguised, which is
      // what makes it the cheapest test for "is this UDP payload QUIC at all"
      // - and the row that says so was the one thing this dissector checked
      // and never showed.
      {
        name: 'Fixed Bit', value: packet.fixedBit ? 'True' : 'False',
        abbrev: 'quic.fixed_bit',
      },
    ];

    // Readable without keys, unlike the reserved bits and the packet-number
    // length beside it: RFC 9001 protects the low five bits of a short
    // header, and the spin bit sits at 0x20. It is a latency signal - it
    // flips once per round trip - so a passive observer can measure RTT on a
    // connection it cannot read a byte of.
    if (packet.spinBit !== undefined) {
      children.push({
        name: 'Spin Bit', value: packet.spinBit ? 'True' : 'False',
        abbrev: 'quic.spin_bit',
      });
    }
    if (packet.packetLength !== undefined) {
      children.push({
        name: 'Packet Length', value: packet.packetLength,
        abbrev: 'quic.packet_length', generated: true,
      });
    }

    if (packet.longPacketType !== undefined) {
      children.push({
        name: 'Packet Type',
        value: `${packet.typeName} (${packet.longPacketType})`,
        abbrev: 'quic.long.packet_type',
      });
      fields['quic.long.packet_type'] = packet.longPacketType;
    }
    // Both sit under header protection, so both exist only on a packet that
    // decrypted - drawn where they were read, never as a zero.
    if (packet.reserved !== undefined) {
      children.push({ name: 'Reserved', value: packet.reserved, abbrev: 'quic.long.reserved' });
    }
    if (packet.packetNumberLengthField !== undefined) {
      children.push({
        name: 'Packet Number Length',
        value: `${packet.packetNumberLengthField + 1} bytes (${packet.packetNumberLengthField})`,
        abbrev: 'quic.packet_number_length',
      });
    }
    if (packet.version !== undefined) {
      children.push({
        name: 'Version',
        value: `0x${packet.version.toString(16).padStart(8, '0')}`,
        abbrev: 'quic.version',
      });
      fields['quic.version'] = packet.version;
    }
    if (packet.dcidLength !== undefined) {
      children.push({ name: 'Destination Connection ID Length', value: packet.dcidLength, abbrev: 'quic.dcil' });
    }
    if (packet.dcid !== undefined && packet.dcid.length > 0) {
      children.push({ name: 'Destination Connection ID', value: packet.dcid, abbrev: 'quic.dcid' });
      fields['quic.dcid'] = packet.dcid;
    }
    if (packet.scidLength !== undefined) {
      children.push({ name: 'Source Connection ID Length', value: packet.scidLength, abbrev: 'quic.scil' });
    }
    if (packet.scid !== undefined && packet.scid.length > 0) {
      children.push({ name: 'Source Connection ID', value: packet.scid, abbrev: 'quic.scid' });
      fields['quic.scid'] = packet.scid;
    }
    if (packet.tokenLength !== undefined) {
      children.push({ name: 'Token Length', value: packet.tokenLength, abbrev: 'quic.token_length' });
    }
    if (packet.payloadLength !== undefined) {
      children.push({ name: 'Length', value: packet.payloadLength, abbrev: 'quic.length' });
    }
    if (packet.packetNumber !== undefined) {
      children.push({ name: 'Packet Number', value: packet.packetNumber, abbrev: 'quic.packet_number' });
      fields['quic.packet_number'] = packet.packetNumber;
    }
    // **The bytes AND the frames read out of them**, which is what the
    // reference draws and only looks redundant: the frames below are this
    // build's reading, and these are what a reader diffs against another
    // capture when the reading is in doubt.
    if (packet.payloadHex !== undefined && packet.payloadHex.length > 0) {
      children.push({ name: 'Payload', value: packet.payloadHex, abbrev: 'quic.payload' });
    }
    if (packet.remainingPayloadHex !== undefined && packet.remainingPayloadHex.length > 0) {
      children.push({
        name: 'Remaining Payload', value: packet.remainingPayloadHex, abbrev: 'quic.remaining_payload',
      });
    }

    for (const frame of packet.frames) {
      const frameRows: ProtocolField[] = [
        { name: 'Frame Type', value: `${frame.name} (0x${frame.type.toString(16)})`, abbrev: 'quic.frame_type' },
      ];
      if (frame.cryptoOffset !== undefined) {
        frameRows.push({ name: 'Offset', value: frame.cryptoOffset, abbrev: 'quic.crypto.offset' });
      }
      if (frame.cryptoLength !== undefined) {
        frameRows.push({ name: 'Length', value: frame.cryptoLength, abbrev: 'quic.crypto.length' });
      }
      if (frame.cryptoData !== undefined) {
        frameRows.push({ name: 'Crypto Data', value: frame.cryptoData, abbrev: 'quic.crypto.crypto_data' });
      }
      if (frame.streamId !== undefined) {
        frameRows.push({ name: 'Stream ID', value: frame.streamId, abbrev: 'quic.stream.stream_id' });
      }
      if (frame.streamOffset !== undefined) {
        frameRows.push({ name: 'Offset', value: frame.streamOffset, abbrev: 'quic.stream.offset' });
      }
      if (frame.streamLength !== undefined) {
        frameRows.push({ name: 'Length', value: frame.streamLength, abbrev: 'quic.stream.length' });
      }
      if (frame.streamFin !== undefined) {
        frameRows.push({ name: 'Fin', value: frame.streamFin, abbrev: 'quic.stream.fin' });
      }
      children.push({ name: frame.name, value: '', abbrev: 'quic.frame', isExpanded: true, children: frameRows });
      fields['quic.frame_type'] = frame.type;
    }

    // **A short header's node carries a name of its own; a long header's does
    // not.** The reference has `quic.short` for "QUIC Short Header" and no
    // counterpart for the long form, which reads like an oversight and is
    // consistent across every frame of both fixtures - so it is matched rather
    // than tidied, the same call the IEEE 1905 media-type names got.
    rows.push(packet.headerForm === 'short'
      ? { name: 'QUIC Short Header', value: '', abbrev: 'quic.short', isExpanded: true, children }
      : { name: packet.typeName, value: '', isExpanded: true, children });
  }

  return { layer: { name: 'QUIC IETF', summary, fields: rows }, fields };
}
