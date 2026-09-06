/**
 * SIP (RFC 3261), UDP/TCP 5060 and 5061.
 *
 *   Request: INVITE sip:bob@example.com |
 *   Status: 200 OK (INVITE) |
 *
 * Who called whom, and what happened. On a capture from anything carrying
 * voice this is the whole story - the media itself is RTP on ports SIP
 * negotiates, which is why the two belong together and why RTP has to be found
 * by content rather than by port.
 *
 * The wire format is HTTP's, near enough that the start line and header
 * parsing read the same way (`dissectors/http1.ts`), with three differences
 * that matter here:
 *
 *   - **The version token comes last on a request and first on a response**,
 *     exactly as in HTTP, but the version is `SIP/2.0` - so a stream is told
 *     apart from HTTP by that token and not by the method, since `OPTIONS` is
 *     a method in both.
 *   - **A response names the request it answers.** Wireshark writes
 *     `Status: 200 OK (INVITE)`, and that method comes from the CSeq header
 *     rather than from any transaction state, which is what makes it readable
 *     one datagram at a time.
 *   - **It is a datagram protocol first.** One message per UDP datagram, so
 *     none of HTTP's body-framing state machine is needed here; a
 *     Content-Length is read for the tree and nothing hangs on it.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';

export interface SipResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** RFC 3261 §7.1 plus the extension methods that turn up on any real capture. */
const METHODS = new Set([
  'INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'REGISTER',
  'PRACK', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'INFO', 'REFER', 'MESSAGE', 'UPDATE',
]);

/** The headers worth a named row and a field. */
const INTERESTING = new Set([
  'from', 'to', 'call-id', 'cseq', 'via', 'contact', 'user-agent',
  'content-type', 'content-length', 'max-forwards', 'expires',
]);

const utf8 = new TextDecoder('utf-8', { fatal: false });

/** A message longer than this is not one datagram's worth of SIP. */
const MAX_MESSAGE = 64 * 1024;

interface SipHeader { name: string; value: string }

interface SipMessage {
  kind: 'request' | 'response';
  method?: string;
  uri?: string;
  status?: number;
  reason?: string;
  headers: SipHeader[];
}

/** The longest method above, which is what bounds the prefilter's scan. */
const LONGEST_METHOD = 9;   // SUBSCRIBE

/**
 * Can the first token possibly open a SIP message?
 *
 * A cheap gate in front of `parseStartLine`, and the reason it exists is that
 * this runs on **every UDP payload no port claimed** - which is mostly QUIC,
 * mostly not text, and never SIP. `parseStartLine` scans for a line ending,
 * decodes what it finds to a string and splits it on spaces; on binary a stray
 * `0x0a` turns up within a few hundred bytes, so the whole of that work happens
 * to conclude "not SIP". Measured at **938 ns a payload, 95% of the entire
 * heuristic chain**, against 6 ns for the next detector.
 *
 * Nothing here is a new rule. A response's first token starts `SIP/`, and a
 * request's IS the method, so both are decided by the first ten bytes: this
 * rejects strictly less than `parseStartLine` does, and only sooner.
 */
function couldOpenSip(bytes: Uint8Array, start: number, end: number): boolean {
  if (start + 4 > end) return false;
  // A response: `SIP/2.0 200 OK`.
  if (bytes[start] === 0x53 && bytes[start + 1] === 0x49
    && bytes[start + 2] === 0x50 && bytes[start + 3] === 0x2f) return true;
  // A request: the method, then a space. Every method is upper-case ASCII, so
  // one byte outside A-Z settles it without looking any further.
  const limit = Math.min(end, start + LONGEST_METHOD + 1);
  for (let p = start; p < limit; p++) {
    if (bytes[p] === 0x20 /* space */) return p > start;
    if (bytes[p] < 0x41 || bytes[p] > 0x5a) return false;
  }
  return false;
}

/**
 * True when these bytes open a SIP message.
 *
 * The `SIP/2.0` token is the test, on either end of the start line. Checking
 * the method alone would claim HTTP, which shares `OPTIONS`; checking for
 * colon-separated headers alone would claim most text protocols.
 */
export function looksLikeSip(bytes: Uint8Array, start: number, end: number): boolean {
  return couldOpenSip(bytes, start, end) && parseStartLine(bytes, start, end) !== null;
}

function firstLine(bytes: Uint8Array, start: number, end: number): { text: string; after: number } | null {
  const limit = Math.min(end, start + MAX_MESSAGE);
  for (let p = start; p < limit; p++) {
    if (bytes[p] === 0x0a /* LF */) {
      const lineEnd = p > start && bytes[p - 1] === 0x0d /* CR */ ? p - 1 : p;
      return { text: utf8.decode(bytes.subarray(start, lineEnd)), after: p + 1 };
    }
  }
  return null;
}

function parseStartLine(bytes: Uint8Array, start: number, end: number): SipMessage | null {
  const line = firstLine(bytes, start, end);
  if (line === null) return null;
  const parts = line.text.split(' ');
  if (parts.length < 3) return null;

  if (parts[0].startsWith('SIP/')) {
    const status = Number(parts[1]);
    if (!Number.isInteger(status) || status < 100 || status > 699) return null;
    return { kind: 'response', status, reason: parts.slice(2).join(' '), headers: [] };
  }
  if (!METHODS.has(parts[0])) return null;
  // The version is the last token, not the third: a Request-URI may contain a
  // space in practice even though it should not.
  if (!parts[parts.length - 1].startsWith('SIP/')) return null;
  return { kind: 'request', method: parts[0], uri: parts.slice(1, -1).join(' '), headers: [] };
}

export function dissectSip(bytes: Uint8Array, start: number, end: number): SipResult | null {
  const message = parseStartLine(bytes, start, end);
  if (message === null) return null;

  const startLine = firstLine(bytes, start, end)!;
  let p = startLine.after;
  // Headers to the blank line. A datagram that is all headers and no body is
  // normal, so running out of bytes is an end and not an error.
  while (p < end) {
    const line = firstLine(bytes, p, end);
    if (line === null || line.text.length === 0) break;
    const colon = line.text.indexOf(':');
    if (colon > 0) {
      message.headers.push({
        name: line.text.slice(0, colon).trim(),
        value: line.text.slice(colon + 1).trim(),
      });
    }
    p = line.after;
  }

  const header = (name: string): string | undefined =>
    message.headers.find((h) => h.name.toLowerCase() === name)?.value;

  const fields: Record<string, string | number> = {};
  const set = (key: string, value: string | undefined) => {
    if (value !== undefined && value.length > 0) fields[key] = value;
  };
  set('sip.From', header('from'));
  set('sip.To', header('to'));
  set('sip.Call-ID', header('call-id'));
  set('sip.User-Agent', header('user-agent'));

  // The CSeq is `<number> <METHOD>`, and its method is what lets a response
  // name the request it answers without any transaction state.
  const cseq = header('cseq');
  const cseqMethod = cseq?.trim().split(/\s+/)[1];
  if (cseq) fields['sip.CSeq'] = cseq;

  if (message.kind === 'request') {
    fields['sip.Method'] = message.method!;
    if (message.uri) fields['sip.r-uri'] = message.uri;
  } else {
    fields['sip.Status-Code'] = message.status!;
    if (message.reason) fields['sip.Reason-Phrase'] = message.reason;
  }

  const headerRows: ProtocolField[] = message.headers.map((h) => ({
    name: `${h.name}: ${h.value}`,
    value: '',
    ...(INTERESTING.has(h.name.toLowerCase())
      ? { abbrev: headerAbbrev(h.name.toLowerCase()) }
      : {}),
  }));

  const startRow: ProtocolField = message.kind === 'request'
    ? {
        name: 'Request-Line',
        value: startLine.text,
        children: [
          { name: 'Method', value: message.method!, abbrev: 'sip.Method' },
          { name: 'Request-URI', value: message.uri ?? '', abbrev: 'sip.r-uri' },
        ],
      }
    : {
        name: 'Status-Line',
        value: startLine.text,
        children: [
          { name: 'Status-Code', value: message.status!, abbrev: 'sip.Status-Code' },
          { name: 'Reason-Phrase', value: message.reason ?? '', abbrev: 'sip.Reason-Phrase' },
        ],
      };

  return {
    protocolLabel: 'SIP',
    info: infoLine(message, cseqMethod, header,
      message.headers.filter((h) => h.name.toLowerCase() === 'contact').map((h) => h.value)),
    fields,
    layer: {
      name: 'Session Initiation Protocol',
      summary: `Session Initiation Protocol (${message.kind === 'request' ? message.method : message.status})`,
      rawBytesRange: [start, Math.max(start, end - 1)],
      fields: [
        startRow,
        { name: 'Message Header', value: '', children: headerRows },
      ],
    },
  };
}

/** Which registry name a header publishes under, for the rows that have one. */
function headerAbbrev(lower: string): string | undefined {
  switch (lower) {
    case 'from': return 'sip.From';
    case 'to': return 'sip.To';
    case 'call-id': return 'sip.Call-ID';
    case 'cseq': return 'sip.CSeq';
    case 'user-agent': return 'sip.User-Agent';
    default: return undefined;
  }
}

/**
 * The Info column.
 *
 * Three details, each established by asking tshark rather than by reading the
 * RFC, because none of them is in the RFC:
 *
 *   - Both forms end `" | "` - space, pipe, space - and the trailing space is
 *     part of the format, not an artefact of joining. Wireshark writes the
 *     separator even with nothing after it to summarise.
 *   - A response names the request it answers **only when the status is
 *     exactly 200**. Not 2xx: a 202 Accepted carries no method, and neither
 *     does 180 or 404. The method comes from CSeq, so one datagram is enough.
 *   - A REGISTER carries a binding summary, after **two** spaces. It is the
 *     one place the Info column says what the message DOES rather than what it
 *     is: no Contact is a query for existing bindings, `Contact: *` with
 *     `Expires: 0` wipes them, and anything else registers what it lists.
 */
function infoLine(
  message: SipMessage,
  cseqMethod: string | undefined,
  header: (name: string) => string | undefined,
  contacts: string[],
): string {
  const bindings = bindingSummary(message, cseqMethod, header, contacts);
  if (message.kind === 'request') {
    return `Request: ${message.method} ${message.uri ?? ''}${bindings} | `;
  }
  // 200 exactly, not 2xx - see above.
  const answering = message.status === 200 && cseqMethod ? ` (${cseqMethod})` : '';
  return `Status: ${message.status} ${message.reason ?? ''}${answering}${bindings} | `;
}

/** `  (fetch bindings)`, `  (1 binding)`, `  (remove all bindings)`, or nothing. */
function bindingSummary(
  message: SipMessage,
  cseqMethod: string | undefined,
  header: (name: string) => string | undefined,
  contacts: string[],
): string {
  const isRegister = message.kind === 'request'
    ? message.method === 'REGISTER'
    : message.status === 200 && cseqMethod === 'REGISTER';
  if (!isRegister) return '';

  if (contacts.length === 0) {
    // A response to a REGISTER lists what is now bound, so none means none; a
    // request with no Contact is asking rather than telling.
    return message.kind === 'request' ? '  (fetch bindings)' : '  (0 bindings)';
  }
  if (contacts.length === 1 && contacts[0].trim() === '*' && header('expires')?.trim() === '0') {
    return '  (remove all bindings)';
  }
  return `  (${contacts.length} binding${contacts.length === 1 ? '' : 's'})`;
}
