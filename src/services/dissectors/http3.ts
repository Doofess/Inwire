/**
 * HTTP/3 (RFC 9114) framing over QUIC streams.
 *
 * HTTP/3 is HTTP/2's semantics with the multiplexing taken out and given to
 * QUIC, so what is left here is small: a frame is a varint type, a varint
 * length and a payload, and there is no stream identifier in it because the
 * QUIC stream *is* the identifier. That has one consequence worth stating,
 * because it is why this file is shaped the way it is: a request lives on its
 * own bidirectional stream, and everything about the connection - the
 * settings, the QPACK table - lives on separate unidirectional streams whose
 * first byte is a type nothing repeats. So state is per stream, and a stream
 * begun before the capture started can never be read, only recognised.
 *
 * Reaching this code at all requires the QUIC packets to have been decrypted,
 * which requires a key log: unlike TLS over TCP, where the record layer is
 * visible even when its contents are not, a QUIC packet is protected header
 * and all.
 */
import { qpackDecode } from './qpack';
// HTTP/3 frame types, lengths and settings are QUIC varints (RFC 9114 §7), so
// the reader is QUIC's rather than a second copy of it. See `quic.ts`.
import { readVarint } from './quic';
import type { HeaderField } from './hpack';
import type { ProtocolField, ProtocolLayer } from '../../types/packet';

const FRAME_TYPE_NAMES: Record<number, string> = {
  0x00: 'DATA',
  0x01: 'HEADERS',
  0x03: 'CANCEL_PUSH',
  0x04: 'SETTINGS',
  0x05: 'PUSH_PROMISE',
  0x07: 'GOAWAY',
  0x0d: 'MAX_PUSH_ID',
};

const SETTING_NAMES: Record<number, string> = {
  0x01: 'QPACK_MAX_TABLE_CAPACITY',
  0x06: 'MAX_FIELD_SECTION_SIZE',
  0x07: 'QPACK_BLOCKED_STREAMS',
  0x08: 'ENABLE_CONNECT_PROTOCOL',
  0x33: 'H3_DATAGRAM',
};

const UNI_STREAM_TYPE_NAMES: Record<number, string> = {
  0x00: 'Control Stream',
  0x01: 'Push Stream',
  0x02: 'QPACK Encoder Stream',
  0x03: 'QPACK Decoder Stream',
};

/** A frame larger than this is not one; the stream is not HTTP/3, or is lost. */
const MAX_FRAME_PAYLOAD = 16 * 1024 * 1024;

export interface Http3Frame {
  type: number;
  typeName: string;
  length: number;
  summary: string;
  headers?: HeaderField[];
  qpackError?: string;
  settings?: { id: number; name: string; value: number }[];
  pushId?: number;
  goawayId?: number;
  dataLength?: number;
}

/** One QUIC stream's HTTP/3 state. */
export interface Http3Stream {
  /** Bytes of a frame not yet complete. */
  pending: Uint8Array;
  /** For a unidirectional stream, the type its first varint declared. */
  uniType?: number;
  /** True once the stream type has been read (or the stream is bidirectional). */
  typeKnown: boolean;
}

export function freshHttp3Stream(bidirectional: boolean): Http3Stream {
  return { pending: new Uint8Array(0), typeKnown: bidirectional };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

/** The request or response line a field section describes, for the Info column. */
function describeHeaders(headers: HeaderField[]): string {
  const find = (name: string) => headers.find((h) => h.name === name)?.value;
  const method = find(':method');
  if (method !== undefined) {
    const authority = find(':authority') ?? '';
    return `${method} ${authority}${find(':path') ?? ''}`;
  }
  return find(':status') ?? '';
}

export interface Http3Result {
  frames: Http3Frame[];
  /** Set on the arrival that read a unidirectional stream's type byte. */
  streamTypeName?: string;
}

/**
 * Reads whole frames out of one stream's newly arrived bytes.
 *
 * `bidirectional` decides whether the stream opens with a type varint: only
 * unidirectional streams carry one, and reading a request stream's first frame
 * type as a stream type would consume it.
 */
export function dissectHttp3Stream(
  data: Uint8Array,
  stream: Http3Stream,
  bidirectional: boolean
): Http3Result {
  const bytes = concat(stream.pending, data);
  const frames: Http3Frame[] = [];
  let streamTypeName: string | undefined;
  let p = 0;

  if (!bidirectional && !stream.typeKnown) {
    const type = readVarint(bytes, 0, bytes.length);
    if (type === null) { stream.pending = bytes.slice(); return { frames }; }
    stream.uniType = type.value;
    stream.typeKnown = true;
    streamTypeName = UNI_STREAM_TYPE_NAMES[type.value] ?? `Reserved Stream (0x${type.value.toString(16)})`;
    p = type.nextOffset;

    // The QPACK streams carry table instructions, not frames, and the push
    // stream carries a push id before its frames. Neither is read further:
    // saying which stream it is is the useful part, and inventing a frame
    // boundary in a stream that has none would be worse than stopping.
    if (type.value !== 0x00) { stream.pending = bytes.subarray(p).slice(); return { frames, streamTypeName }; }
  }

  if (!bidirectional && stream.uniType !== 0x00) {
    stream.pending = new Uint8Array(0);
    return { frames, streamTypeName };
  }

  for (;;) {
    const type = readVarint(bytes, p, bytes.length);
    if (type === null) break;
    const length = readVarint(bytes, type.nextOffset, bytes.length);
    if (length === null) break;
    if (length.value > MAX_FRAME_PAYLOAD) { stream.pending = new Uint8Array(0); return { frames, streamTypeName }; }
    if (length.nextOffset + length.value > bytes.length) break;

    const payload = bytes.subarray(length.nextOffset, length.nextOffset + length.value);
    p = length.nextOffset + length.value;

    // Grease frame types (RFC 9114 §7.2.8) exist to keep implementations from
    // hard-coding the list; they are ignorable by design, so they are named
    // rather than treated as an error.
    const isGrease = type.value >= 0x21 && (type.value - 0x21) % 0x1f === 0;
    const typeName = FRAME_TYPE_NAMES[type.value]
      ?? (isGrease ? 'Reserved (grease)' : `Unknown (0x${type.value.toString(16)})`);
    const frame: Http3Frame = { type: type.value, typeName, length: length.value, summary: typeName };

    switch (type.value) {
      case 0x00:
        frame.dataLength = payload.length;
        break;
      case 0x01: {
        const decoded = qpackDecode(payload);
        frame.headers = decoded.headers;
        if (decoded.error !== undefined) frame.qpackError = decoded.error;
        break;
      }
      case 0x04: {
        const settings: { id: number; name: string; value: number }[] = [];
        for (let q = 0; q < payload.length;) {
          const id = readVarint(payload, q, payload.length);
          if (id === null) break;
          const value = readVarint(payload, id.nextOffset, payload.length);
          if (value === null) break;
          settings.push({ id: id.value, name: SETTING_NAMES[id.value] ?? `Reserved (0x${id.value.toString(16)})`, value: value.value });
          q = value.nextOffset;
        }
        frame.settings = settings;
        break;
      }
      case 0x03:
      case 0x0d: {
        const id = readVarint(payload, 0, payload.length);
        if (id !== null) frame.pushId = id.value;
        break;
      }
      case 0x07: {
        const id = readVarint(payload, 0, payload.length);
        if (id !== null) frame.goawayId = id.value;
        break;
      }
      default:
        break;
    }

    frame.summary = summarise(frame);
    frames.push(frame);
  }

  stream.pending = bytes.subarray(p).slice();
  if (stream.pending.length > MAX_FRAME_PAYLOAD) stream.pending = new Uint8Array(0);
  return { frames, streamTypeName };
}

function summarise(frame: Http3Frame): string {
  switch (frame.type) {
    case 0x00:
      return `DATA (${frame.dataLength ?? 0} bytes)`;
    case 0x01: {
      if (frame.qpackError !== undefined && (frame.headers?.length ?? 0) === 0) return 'HEADERS: [QPACK dynamic table]';
      const line = describeHeaders(frame.headers ?? []);
      return line.length > 0 ? `HEADERS: ${line}` : 'HEADERS';
    }
    case 0x07:
      return `GOAWAY: ${frame.goawayId ?? 0}`;
    case 0x0d:
      return `MAX_PUSH_ID: ${frame.pushId ?? 0}`;
    case 0x03:
      return `CANCEL_PUSH: ${frame.pushId ?? 0}`;
    default:
      return frame.typeName;
  }
}

// --- the tree -------------------------------------------------------------------

export interface Http3StreamResult {
  streamId: number;
  frames: Http3Frame[];
  streamTypeName?: string;
}

/**
 * One layer for the datagram, with a subtree per stream.
 *
 * A QUIC datagram can carry frames from several streams at once - that is the
 * whole point of it - so grouping by stream is what makes the tree readable,
 * and it is also what keeps `frameProtocols` from listing `http3` once per
 * stream, where a repeated token reads as nesting.
 */
export function buildHttp3Layer(streams: Http3StreamResult[]): {
  layer: ProtocolLayer;
  info: string[];
  fields: Record<string, string | number>;
} | null {
  if (streams.length === 0) return null;

  const info: string[] = [];
  const rows: ProtocolField[] = [];
  const fields: Record<string, string | number> = {};

  for (const stream of streams) {
    const summaries = stream.frames.map((f) => f.summary);
    const label = stream.streamTypeName !== undefined
      ? `Stream ${stream.streamId}: ${stream.streamTypeName}`
      : `Stream ${stream.streamId}`;
    if (stream.streamTypeName !== undefined) info.push(stream.streamTypeName);
    info.push(...summaries);

    const children: ProtocolField[] = [{ name: 'Stream ID', value: stream.streamId, abbrev: 'http3.frame_streamid' }];
    for (const frame of stream.frames) {
      const frameRows: ProtocolField[] = [
        { name: 'Type', value: `${frame.typeName} (0x${frame.type.toString(16)})`, abbrev: 'http3.frame_type' },
        { name: 'Length', value: frame.length },
      ];
      if (frame.headers !== undefined && frame.headers.length > 0) {
        frameRows.push({
          name: 'Header Block',
          value: `${frame.headers.length} header${frame.headers.length === 1 ? '' : 's'}`,
          isExpanded: true,
          children: frame.headers.map((header) => {
            const field: ProtocolField = { name: header.name, value: header.value };
            switch (header.name) {
              case ':method': field.abbrev = 'http3.headers.method'; fields['http3.headers.method'] = header.value; break;
              case ':path': field.abbrev = 'http3.headers.path'; fields['http3.headers.path'] = header.value; break;
              case ':authority': field.abbrev = 'http3.headers.authority'; fields['http3.headers.authority'] = header.value; break;
              case ':status': field.abbrev = 'http3.headers.status'; fields['http3.headers.status'] = Number.parseInt(header.value, 10) || 0; break;
              default: break;
            }
            return field;
          }),
        });
      }
      if (frame.qpackError !== undefined) {
        frameRows.push({
          name: 'QPACK', value: frame.qpackError,
          description: "QPACK's dynamic table is filled by a separate unidirectional stream, so a field section that indexes it cannot be read from this frame alone",
        });
      }
      if (frame.settings !== undefined) {
        frameRows.push({
          name: 'Settings', value: `${frame.settings.length}`, isExpanded: true,
          children: frame.settings.map((setting) => ({ name: setting.name, value: setting.value })),
        });
      }
      if (frame.dataLength !== undefined) frameRows.push({ name: 'Data', value: `${frame.dataLength} bytes` });
      if (frame.goawayId !== undefined) frameRows.push({ name: 'Stream ID', value: frame.goawayId });
      if (frame.pushId !== undefined) frameRows.push({ name: 'Push ID', value: frame.pushId });

      children.push({ name: frame.summary, value: '', isExpanded: true, children: frameRows });
      fields['http3.frame_type'] = frame.type;
    }

    fields['http3.frame_streamid'] = stream.streamId;
    rows.push({ name: label, value: '', isExpanded: true, children });
  }

  return {
    layer: { name: 'HyperText Transfer Protocol Version 3', summary: info.join(', '), fields: rows },
    info,
    fields,
  };
}
