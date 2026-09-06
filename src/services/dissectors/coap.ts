/**
 * CoAP (RFC 7252), UDP 5683/5684 - HTTP's shape for things too small to run HTTP.
 *
 *   CON, MID:4660, GET, /temp
 *   ACK, MID:4660, 2.05 Content
 *
 * The application protocol of the small-device internet: sensors, lightbulbs,
 * building controls. It matters to an analyzer for a reason the traffic volume
 * does not suggest - these are the devices nobody can log into. There is no
 * shell on a thermostat, so the capture is the only account of what it did.
 *
 * Three things shape the decode. The **code** is one byte read as `class.detail`,
 * so 69 is `2.05 Content` and 132 is `4.04 Not Found` - printing it as 69 would
 * be technically true and unreadable. **Options are delta-encoded**: each one
 * carries the difference from the previous option's number, so they must be
 * walked in order and a single unreadable option ends the walk rather than
 * shifting every option after it. And the **Uri-Path is split across options**,
 * one per segment, which is why the path is assembled here rather than read.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';

export interface CoapResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

const TYPE_NAMES = ['CON', 'NON', 'ACK', 'RST'];

/** RFC 7252 §12.1.1 requests and §5.9 responses, by `class * 32 + detail`. */
const CODE_NAMES: Record<number, string> = {
  1: 'GET', 2: 'POST', 3: 'PUT', 4: 'DELETE',
  5: 'FETCH', 6: 'PATCH', 7: 'iPATCH',
  65: 'Created', 66: 'Deleted', 67: 'Valid', 68: 'Changed', 69: 'Content',
  95: 'Continue',
  128: 'Bad Request', 129: 'Unauthorized', 130: 'Bad Option', 131: 'Forbidden',
  132: 'Not Found', 133: 'Method Not Allowed', 134: 'Not Acceptable',
  136: 'Request Entity Incomplete', 140: 'Precondition Failed',
  141: 'Request Entity Too Large', 143: 'Unsupported Content-Format',
  160: 'Internal Server Error', 161: 'Not Implemented', 162: 'Bad Gateway',
  163: 'Service Unavailable', 164: 'Gateway Timeout', 165: 'Proxying Not Supported',
};

/** RFC 7252 §5.10 and the observe/block extensions that turn up beside them. */
const OPTION_NAMES: Record<number, string> = {
  1: 'If-Match', 3: 'Uri-Host', 4: 'ETag', 5: 'If-None-Match',
  6: 'Observe', 7: 'Uri-Port', 8: 'Location-Path', 11: 'Uri-Path',
  12: 'Content-Format', 14: 'Max-Age', 15: 'Uri-Query', 17: 'Accept',
  20: 'Location-Query', 23: 'Block2', 27: 'Block1', 28: 'Size2',
  35: 'Proxy-Uri', 39: 'Proxy-Scheme', 60: 'Size1',
};

const URI_PATH = 11, URI_QUERY = 15;

/** The option numbers whose value is text rather than an opaque byte string. */
const TEXT_OPTIONS = new Set([3, 8, 11, 15, 20, 35, 39]);

/** A nibble of 13 or 14 means the real value follows in 1 or 2 extra bytes. */
const EXTEND_8 = 13, EXTEND_16 = 14, RESERVED = 15;

const utf8 = new TextDecoder('utf-8', { fatal: false });

/** `2.05`, which is how every CoAP code is written and never as 69. */
function codeString(code: number): string {
  return `${code >> 5}.${(code & 0x1f).toString().padStart(2, '0')}`;
}

/** Reads a delta/length nibble and its extension bytes. */
function extended(nibble: number, bytes: Uint8Array, at: number, end: number):
  { value: number; after: number } | null {
  if (nibble < EXTEND_8) return { value: nibble, after: at };
  if (nibble === EXTEND_8) {
    if (at + 1 > end) return null;
    return { value: bytes[at] + 13, after: at + 1 };
  }
  if (nibble === EXTEND_16) {
    if (at + 2 > end) return null;
    return { value: ((bytes[at] << 8) | bytes[at + 1]) + 269, after: at + 2 };
  }
  return null;   // 15 is reserved and only legal as the payload marker
}

export function dissectCoap(bytes: Uint8Array, start: number, end: number): CoapResult | null {
  if (start + 4 > end) return null;
  const version = bytes[start] >> 6;
  if (version !== 1) return null;
  const type = (bytes[start] >> 4) & 0x03;
  const tokenLength = bytes[start] & 0x0f;
  // RFC 7252 §3: lengths 9-15 are reserved and MUST be treated as a format
  // error, which is most of what stops this claiming arbitrary UDP.
  if (tokenLength > 8) return null;
  const code = bytes[start + 1];
  const messageId = (bytes[start + 2] << 8) | bytes[start + 3];
  if (start + 4 + tokenLength > end) return null;

  const typeName = TYPE_NAMES[type];
  const fields: Record<string, string | number> = {
    'coap.version': version,
    'coap.type': type,
    'coap.token_len': tokenLength,
    'coap.code': code,
    'coap.mid': messageId,
  };

  const rows: ProtocolField[] = [
    { name: 'Version', value: version, abbrev: 'coap.version', rawBytesRange: [start, start] },
    { name: 'Type', value: `${typeName} (${type})`, abbrev: 'coap.type',
      rawBytesRange: [start, start] },
    { name: 'Token Length', value: tokenLength, abbrev: 'coap.token_len',
      rawBytesRange: [start, start] },
    { name: 'Code', value: code === 0 ? 'Empty Message (0)'
        : `${codeString(code)} ${CODE_NAMES[code] ?? 'Unknown'} (${code})`,
      abbrev: 'coap.code', rawBytesRange: [start + 1, start + 1] },
    { name: 'Message ID', value: messageId, abbrev: 'coap.mid',
      rawBytesRange: [start + 2, start + 3] },
  ];

  // The token is written space-separated in both the tree and the Info line -
  // it is read by eye when matching a response to a request that was not a
  // piggybacked acknowledgement, and eight run-together hex digits are not.
  let token = '';
  if (tokenLength > 0) {
    token = [...bytes.subarray(start + 4, start + 4 + tokenLength)]
      .map((b) => b.toString(16).padStart(2, '0')).join(' ');
    fields['coap.token'] = token;
    rows.push({ name: 'Token', value: token, abbrev: 'coap.token',
      rawBytesRange: [start + 4, start + 4 + tokenLength - 1] });
  }

  // --- options, which are deltas and so must be walked in order ---------------
  const pathSegments: string[] = [];
  const querySegments: string[] = [];
  let optionNumber = 0;
  let p = start + 4 + tokenLength;
  let payloadStart = end;
  while (p < end) {
    if (bytes[p] === 0xff) { payloadStart = p + 1; break; }
    const deltaNibble = bytes[p] >> 4;
    const lengthNibble = bytes[p] & 0x0f;
    if (deltaNibble === RESERVED || lengthNibble === RESERVED) return null;
    const delta = extended(deltaNibble, bytes, p + 1, end);
    if (delta === null) return null;
    const length = extended(lengthNibble, bytes, delta.after, end);
    if (length === null) return null;
    const valueStart = length.after;
    if (valueStart + length.value > end) return null;

    optionNumber += delta.value;
    const optionName = OPTION_NAMES[optionNumber] ?? `Unknown (${optionNumber})`;
    const raw = bytes.subarray(valueStart, valueStart + length.value);
    const text = TEXT_OPTIONS.has(optionNumber)
      ? utf8.decode(raw)
      : [...raw].map((b) => b.toString(16).padStart(2, '0')).join('');
    if (optionNumber === URI_PATH) pathSegments.push(text);
    if (optionNumber === URI_QUERY) querySegments.push(text);
    rows.push({ name: `Opt Name: #${optionNumber}: ${optionName}`, value: text,
      rawBytesRange: [p, valueStart + length.value - 1] });
    p = valueStart + length.value;
  }

  const path = pathSegments.length > 0 ? `/${pathSegments.join('/')}` : '';
  if (path) fields['coap.opt.uri_path'] = path;
  const query = querySegments.length > 0 ? `?${querySegments.join('&')}` : '';
  if (query) fields['coap.opt.uri_query'] = querySegments.join('&');
  if (payloadStart < end) {
    rows.push({ name: 'Payload', value: `${end - payloadStart} bytes`,
      rawBytesRange: [payloadStart, end - 1] });
    fields['coap.payload_length'] = end - payloadStart;
  }

  // The Info line is a comma-separated list of elements rather than a
  // sentence, which is why it is assembled and not interpolated: a message
  // with no token and no path must not leave an empty element behind.
  //
  // A code of 0 is an empty message - an acknowledgement or a reset carrying
  // nothing but the message id - and it names no method and no status.
  const elements = [typeName, `MID:${messageId}`];
  elements.push(code === 0
    ? 'Empty Message'
    : code < 32
      ? CODE_NAMES[code] ?? codeString(code)
      : `${codeString(code)} ${CODE_NAMES[code] ?? 'Unknown'}`);
  if (token) elements.push(`TKN:${token}`);
  if (path || query) elements.push(`${path}${query}`);

  return {
    protocolLabel: 'CoAP',
    info: elements.join(', '),
    fields,
    layer: {
      name: 'Constrained Application Protocol',
      summary: `Constrained Application Protocol, ${typeName}, MID:${messageId}`,
      rawBytesRange: [start, Math.max(start, end - 1)],
      fields: rows,
    },
  };
}
