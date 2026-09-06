/**
 * HTTP/2 (RFC 9113) framing over a byte stream.
 *
 * The stream this reads is usually TLS plaintext, so it only exists when a key
 * log has opened the connection; `h2c` on port 80 and prior-knowledge HTTP/2
 * go through exactly the same code. What arrives is a byte stream, not a
 * message boundary: one TLS record can hold six frames and one frame can span
 * four records, so this consumes whole frames and hands back the remainder for
 * the next arrival - the same shape as the TLS record cursor a layer below.
 *
 * Two pieces of state make HTTP/2 order-dependent, and both live with the
 * connection rather than the frame:
 *
 *  - the HPACK table per direction (see hpack.ts), without which a HEADERS
 *    frame may be undecodable on its own;
 *  - the CONTINUATION rule: a header block may be split across frames and no
 *    other frame may come between, so a HEADERS frame without END_HEADERS is
 *    incomplete until the run finishes.
 */
import { hpackDecode, HpackTable, type HeaderField } from './hpack';

/**
 * One decoder, not one per call. `new TextDecoder()` is not free, and these
 * sites are per-field / per-frame - a CPU profile put TextDecoder construction
 * at 8% of a dissection run. It carries no state across `decode()` calls unless
 * `{stream: true}` is used, which nothing here does, so a shared instance is
 * exactly equivalent. `new TextDecoder()` and
 * `new TextDecoder('utf-8', {fatal: false})` are the same thing: utf-8,
 * non-fatal, is the default.
 */
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

export const HTTP2_PREFACE = new TextEncoder().encode('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');

const FRAME_HEADER_BYTES = 9;
/** RFC 9113 §4.2: 16 KB is the default maximum and 16 MB the ceiling a peer may raise it to. */
const MAX_FRAME_PAYLOAD = 16 * 1024 * 1024;

export const FRAME_TYPE_NAMES: Record<number, string> = {
  0: 'DATA', 1: 'HEADERS', 2: 'PRIORITY', 3: 'RST_STREAM', 4: 'SETTINGS',
  5: 'PUSH_PROMISE', 6: 'PING', 7: 'GOAWAY', 8: 'WINDOW_UPDATE', 9: 'CONTINUATION',
  // RFC 7838 and RFC 8441, both common in the wild.
  10: 'ALTSVC', 12: 'ORIGIN', 16: 'PRIORITY_UPDATE',
};

const SETTING_NAMES: Record<number, string> = {
  1: 'HEADER_TABLE_SIZE', 2: 'ENABLE_PUSH', 3: 'MAX_CONCURRENT_STREAMS',
  4: 'INITIAL_WINDOW_SIZE', 5: 'MAX_FRAME_SIZE', 6: 'MAX_HEADER_LIST_SIZE',
  8: 'ENABLE_CONNECT_PROTOCOL', 9: 'NO_RFC7540_PRIORITIES',
};

const ERROR_NAMES: Record<number, string> = {
  0: 'NO_ERROR', 1: 'PROTOCOL_ERROR', 2: 'INTERNAL_ERROR', 3: 'FLOW_CONTROL_ERROR',
  4: 'SETTINGS_TIMEOUT', 5: 'STREAM_CLOSED', 6: 'FRAME_SIZE_ERROR', 7: 'REFUSED_STREAM',
  8: 'CANCEL', 9: 'COMPRESSION_ERROR', 10: 'CONNECT_ERROR', 11: 'ENHANCE_YOUR_CALM',
  12: 'INADEQUATE_SECURITY', 13: 'HTTP_1_1_REQUIRED',
};

const FLAG_END_HEADERS = 0x04;
const FLAG_PADDED = 0x08;
const FLAG_PRIORITY = 0x20;
/** On SETTINGS and PING the 0x01 bit means ACK instead of END_STREAM. */
const FLAG_ACK = 0x01;

export interface Http2Frame {
  type: number;
  typeName: string;
  flags: number;
  streamId: number;
  length: number;
  /** Short form for the Info column, e.g. "HEADERS[1]: GET /index.html". */
  summary: string;
  headers?: HeaderField[];
  hpackError?: string;
  settings?: { id: number; name: string; value: number }[];
  errorCode?: number;
  promisedStreamId?: number;
  windowIncrement?: number;
  goawayLastStream?: number;
  goawayDebug?: string;
  pingData?: Uint8Array;
  /** DATA payload with padding removed. */
  data?: Uint8Array;
}

/** One direction's HTTP/2 state. Lives with the connection. */
export interface Http2Direction {
  table: HpackTable;
  /** Bytes of a frame not yet completed. */
  pending: Uint8Array;
  /** Header block fragments collected across CONTINUATION frames. */
  headerFragments: Uint8Array[];
  headerStreamId: number;
  headerFrameType: number;
  prefaceSeen: boolean;
}

export function freshHttp2Direction(): Http2Direction {
  return {
    table: new HpackTable(), pending: new Uint8Array(0),
    headerFragments: [], headerStreamId: 0, headerFrameType: -1, prefaceSeen: false,
  };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function u24(b: Uint8Array, p: number): number { return (b[p] << 16) | (b[p + 1] << 8) | b[p + 2]; }
function u32(b: Uint8Array, p: number): number { return ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0; }

function startsWith(bytes: Uint8Array, prefix: Uint8Array): boolean {
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (bytes[i] !== prefix[i]) return false;
  return true;
}

/**
 * A HEADERS or PUSH_PROMISE frame is only a header block once its
 * CONTINUATION run has finished, so the decode happens here rather than where
 * the first frame was read.
 */
function finishHeaderBlock(direction: Http2Direction, frame: Http2Frame): void {
  let total = 0;
  for (const part of direction.headerFragments) total += part.length;
  const block = new Uint8Array(total);
  let p = 0;
  for (const part of direction.headerFragments) { block.set(part, p); p += part.length; }
  direction.headerFragments = [];

  const result = hpackDecode(block, direction.table);
  frame.headers = result.headers;
  if (result.error !== undefined) frame.hpackError = result.error;
}

/**
 * The reason phrases HTTP/2 does not send.
 *
 * A status line in HTTP/2 is the number alone - the phrase was dropped as
 * redundant - but the reference analyzer prints one anyway, because "200" on
 * its own reads as a length or an id. Only the codes worth naming are here; an
 * unlisted one shows as the bare number, which is what it was.
 */
const STATUS_TEXT: Record<string, string> = {
  '100': 'Continue', '101': 'Switching Protocols', '103': 'Early Hints',
  '200': 'OK', '201': 'Created', '202': 'Accepted', '204': 'No Content', '206': 'Partial Content',
  '301': 'Moved Permanently', '302': 'Found', '303': 'See Other', '304': 'Not Modified',
  '307': 'Temporary Redirect', '308': 'Permanent Redirect',
  '400': 'Bad Request', '401': 'Unauthorized', '403': 'Forbidden', '404': 'Not Found',
  '405': 'Method Not Allowed', '408': 'Request Timeout', '409': 'Conflict', '410': 'Gone',
  '413': 'Payload Too Large', '415': 'Unsupported Media Type', '418': "I'm a teapot",
  '421': 'Misdirected Request', '425': 'Too Early', '429': 'Too Many Requests',
  '500': 'Internal Server Error', '501': 'Not Implemented', '502': 'Bad Gateway',
  '503': 'Service Unavailable', '504': 'Gateway Timeout',
};

/**
 * The request or response line a header block describes, for the Info column.
 *
 * Method and path only - not the authority, however much a reader might want
 * it there. The Info column is held to the reference analyzer's wording, and
 * the authority is one click away in the tree along with every other header.
 */
function describeHeaders(headers: HeaderField[]): string {
  const find = (name: string) => headers.find((h) => h.name === name)?.value;
  const method = find(':method');
  if (method !== undefined) return `${method} ${find(':path') ?? ''}`;
  const status = find(':status');
  if (status === undefined) return '';
  const text = STATUS_TEXT[status];
  return text === undefined ? status : `${status} ${text}`;
}

/**
 * Reads whole frames out of `data`, leaving any partial frame for next time.
 *
 * `fromClient` decides only whether the connection preface is expected, since
 * the preface is a client-only string that is not a frame.
 */
export function dissectHttp2(
  data: Uint8Array,
  direction: Http2Direction,
  fromClient: boolean
): { frames: Http2Frame[]; sawPreface: boolean } {
  let bytes = concat(direction.pending, data);
  const frames: Http2Frame[] = [];
  let sawPreface = false;
  let p = 0;

  if (fromClient && !direction.prefaceSeen && startsWith(bytes.subarray(p), HTTP2_PREFACE)) {
    direction.prefaceSeen = true;
    sawPreface = true;
    p += HTTP2_PREFACE.length;
  }

  while (bytes.length - p >= FRAME_HEADER_BYTES) {
    const length = u24(bytes, p);
    if (length > MAX_FRAME_PAYLOAD) {
      // Not HTTP/2, or the stream is out of step. Consuming everything is the
      // honest answer: we cannot resynchronise a length-prefixed framing.
      direction.pending = new Uint8Array(0);
      return { frames, sawPreface };
    }
    if (bytes.length - p < FRAME_HEADER_BYTES + length) break;

    const type = bytes[p + 3];
    const flags = bytes[p + 4];
    const streamId = u32(bytes, p + 5) & 0x7fffffff;
    const payload = bytes.subarray(p + FRAME_HEADER_BYTES, p + FRAME_HEADER_BYTES + length);
    p += FRAME_HEADER_BYTES + length;

    const typeName = FRAME_TYPE_NAMES[type] ?? `Unknown (${type})`;
    const frame: Http2Frame = { type, typeName, flags, streamId, length, summary: `${typeName}[${streamId}]` };

    switch (type) {
      case 0: { // DATA
        let start = 0;
        let end = payload.length;
        if ((flags & FLAG_PADDED) !== 0 && payload.length >= 1) { start = 1; end = payload.length - payload[0]; }
        frame.data = end >= start ? payload.subarray(start, end) : payload.subarray(start);
        break;
      }
      case 1: { // HEADERS
        let q = 0;
        let padding = 0;
        if ((flags & FLAG_PADDED) !== 0 && payload.length >= 1) { padding = payload[0]; q = 1; }
        // The priority fields sit between the padding length and the block.
        if ((flags & FLAG_PRIORITY) !== 0) q += 5;
        const end = Math.max(q, payload.length - padding);
        direction.headerFragments = [payload.subarray(q, end)];
        direction.headerStreamId = streamId;
        direction.headerFrameType = type;
        if ((flags & FLAG_END_HEADERS) !== 0) finishHeaderBlock(direction, frame);
        break;
      }
      case 5: { // PUSH_PROMISE
        let q = 0;
        let padding = 0;
        if ((flags & FLAG_PADDED) !== 0 && payload.length >= 1) { padding = payload[0]; q = 1; }
        if (payload.length >= q + 4) {
          frame.promisedStreamId = u32(payload, q) & 0x7fffffff;
          q += 4;
        }
        const end = Math.max(q, payload.length - padding);
        direction.headerFragments = [payload.subarray(q, end)];
        direction.headerStreamId = streamId;
        direction.headerFrameType = type;
        if ((flags & FLAG_END_HEADERS) !== 0) finishHeaderBlock(direction, frame);
        break;
      }
      case 9: { // CONTINUATION
        direction.headerFragments.push(payload);
        if ((flags & FLAG_END_HEADERS) !== 0) finishHeaderBlock(direction, frame);
        break;
      }
      case 3: // RST_STREAM
        if (payload.length >= 4) frame.errorCode = u32(payload, 0);
        break;
      case 4: { // SETTINGS
        if ((flags & FLAG_ACK) === 0) {
          const settings: { id: number; name: string; value: number }[] = [];
          for (let q = 0; q + 6 <= payload.length; q += 6) {
            const id = (payload[q] << 8) | payload[q + 1];
            settings.push({ id, name: SETTING_NAMES[id] ?? `Unknown (${id})`, value: u32(payload, q + 2) });
            // The peer's table size limit is ours to honour when decoding what
            // it sends us; the table it applies to is the *other* direction's.
          }
          frame.settings = settings;
        }
        break;
      }
      case 6: // PING
        frame.pingData = payload.subarray(0, 8);
        break;
      case 7: // GOAWAY
        if (payload.length >= 8) {
          frame.goawayLastStream = u32(payload, 0) & 0x7fffffff;
          frame.errorCode = u32(payload, 4);
          if (payload.length > 8) {
            frame.goawayDebug = utf8Decoder.decode(payload.subarray(8, Math.min(payload.length, 8 + 256)));
          }
        }
        break;
      case 8: // WINDOW_UPDATE
        if (payload.length >= 4) frame.windowIncrement = u32(payload, 0) & 0x7fffffff;
        break;
      default:
        break;
    }

    frame.summary = summarise(frame);
    frames.push(frame);
  }

  direction.pending = bytes.subarray(p);
  // Hold nothing unbounded: a stream that never yields a frame boundary is not
  // HTTP/2, and keeping its bytes would grow without limit.
  if (direction.pending.length > MAX_FRAME_PAYLOAD) direction.pending = new Uint8Array(0);
  else if (direction.pending.length > 0) direction.pending = direction.pending.slice();
  bytes = new Uint8Array(0);

  return { frames, sawPreface };
}

/**
 * The Info column's form for one frame: `TYPE[stream]`, with a request or
 * status line after a colon on HEADERS and PUSH_PROMISE and nothing after it
 * anywhere else.
 *
 * Deliberately less than this file knows. The error code a RST_STREAM carries
 * and the increment a WINDOW_UPDATE carries are both in the tree, one row
 * down; putting them in the Info column as well would make the column read
 * differently from every other analyzer for no information gained.
 */
function summarise(frame: Http2Frame): string {
  const base = `${frame.typeName}[${frame.streamId}]`;
  if (frame.type !== 1 && frame.type !== 5) return base;
  if (frame.hpackError !== undefined) return `${base}: [${frame.hpackError}]`;
  if (frame.headers === undefined) return base;
  const line = describeHeaders(frame.headers);
  return line.length > 0 ? `${base}: ${line}` : base;
}

export function http2ErrorName(code: number): string {
  return ERROR_NAMES[code] ?? `Unknown (${code})`;
}
