/**
 * An HTTP message as tree rows and filterable fields, for the two dissectors
 * that both produce one.
 *
 * **The reference files SSDP under HTTP's field names**, and that is not a
 * quirk to work around - it is the right model. SSDP is HTTP/1.1 syntax over
 * UDP multicast, so `http.host` on an M-SEARCH means exactly what it means on
 * a GET, and a filter learnt on one answers the other. `tree-coverage.ts`
 * records the same thing from the other side: its `REATTRIBUTE` rule moves the
 * reference's `http.*` names into our `ssdp` layer, because they are the same
 * names.
 *
 * So this module is what both call, and the measurement that produced it is
 * blunt: **neither parity fixture contains a single frame of real HTTP.** Both
 * were captured on machines whose browsing is entirely HTTPS, so all 13
 * `http.*` names the reference emits on inwire and all 7 on bulk come from
 * SSDP on UDP/1900 - and this build answered with an Info string and no layer
 * at all. `ssdp 0/13` was the whole of it.
 *
 * ## Three things about the shape, each taken from the reference's own PDML
 *
 * **A header line is one row.** Its field is the specific name when HTTP has
 * one (`http.host`, `http.server`) and `http.unknown_header` when it does not
 * - and in that second case the value is the WHOLE raw line rather than the
 * part after the colon, which is what the reference shows and is the only
 * thing that makes `http.unknown_header contains "NTS:"` work.
 *
 * **`http.request.line` is every header line's raw text**, emitted beside the
 * named field and hidden by the reference when there is one. A tree with no
 * hidden rows cannot do that at the same level without drawing every header
 * twice, so the raw line becomes a CHILD of the row it was parsed from. That
 * reads as what it is, and it keeps the name filterable.
 *
 * **The start line is a parent with the parsed pieces under it**, which is
 * where the URI decomposes: path, query, and one row per query parameter.
 */
import type { ProtocolField } from '../../types/packet';
import type { Http1Header, Http1Message } from './http1';

/**
 * Header names HTTP has a field of its own for, lower-cased.
 *
 * Every entry was checked against `tshark -G fields` rather than guessed -
 * `http.content_length_header` is the raw header where `http.content_length`
 * is the parsed number, and `http.accept_encoding` has no underscore where
 * `http.x_forwarded_for` has two. `scripts/dissect/wireshark-abbrevs.ts` holds
 * the whole table to the reference's dictionary, which is why the awkward
 * spellings are kept rather than tidied.
 */
const HEADER_ABBREV: Record<string, string> = {
  'accept': 'http.accept',
  'accept-encoding': 'http.accept_encoding',
  'accept-language': 'http.accept_language',
  'authorization': 'http.authorization',
  'cache-control': 'http.cache_control',
  'connection': 'http.connection',
  'content-encoding': 'http.content_encoding',
  'content-length': 'http.content_length_header',
  'content-range': 'http.content_range',
  'content-type': 'http.content_type',
  'cookie': 'http.cookie',
  'date': 'http.date',
  'host': 'http.host',
  'last-modified': 'http.last_modified',
  'location': 'http.location',
  'proxy-authenticate': 'http.proxy_authenticate',
  'proxy-authorization': 'http.proxy_authorization',
  'range': 'http.range',
  'referer': 'http.referer',
  'sec-websocket-accept': 'http.sec_websocket_accept',
  'sec-websocket-extensions': 'http.sec_websocket_extensions',
  'sec-websocket-key': 'http.sec_websocket_key',
  'sec-websocket-protocol': 'http.sec_websocket_protocol',
  'sec-websocket-version': 'http.sec_websocket_version',
  'server': 'http.server',
  'set-cookie': 'http.set_cookie',
  'transfer-encoding': 'http.transfer_encoding',
  'upgrade': 'http.upgrade',
  'user-agent': 'http.user_agent',
  'www-authenticate': 'http.www_authenticate',
  'x-forwarded-for': 'http.x_forwarded_for',
};

/** The status classes, as the reference's `http.response.code.desc` names them. */
const STATUS_CLASS: Record<number, string> = {
  1: 'Informational', 2: 'Success', 3: 'Redirection', 4: 'Client Error', 5: 'Server Error',
};

function headerValue(headers: Http1Header[], name: string): string | undefined {
  return headers.find((h) => h.name.toLowerCase() === name)?.value;
}

/**
 * The request target, split the way the reference splits it.
 *
 * `*` and an absolute-form target (`http://host/path`) both occur in the wild -
 * the first on OPTIONS and on every SSDP M-SEARCH, the second on a request to
 * a proxy - and neither is a path with a query. Splitting on the first `?` and
 * nothing else is what the reference does, and it is right for all three.
 */
function uriRows(target: string): ProtocolField[] {
  // **`*` is a request-target form, not a path** (RFC 9112 3.2.4), and it is
  // what every OPTIONS and every SSDP M-SEARCH sends. Decomposing it produced
  // `http.request.uri.path: *` and a path SEGMENT of `*` on 53 inwire frames,
  // which the reference emits for neither - and it was caught by the coverage
  // tool's INWIRE-ONLY list rather than by reading the RFC, which is the
  // direction that list is useful in.
  if (target === '*' || target.length === 0) return [];
  const rows: ProtocolField[] = [];
  const mark = target.indexOf('?');
  const path = mark === -1 ? target : target.slice(0, mark);
  rows.push({ name: 'Request URI Path', value: path, abbrev: 'http.request.uri.path' });
  // The leading slash makes an empty first segment, which is not one.
  for (const segment of path.split('/').filter((s) => s.length > 0)) {
    rows.push({ name: 'Request URI Path Segment', value: segment, abbrev: 'http.request.uri.path.segment' });
  }
  if (mark !== -1) {
    const query = target.slice(mark + 1);
    rows.push({ name: 'Request URI Query', value: query, abbrev: 'http.request.uri.query' });
    // **Split on `&` AND `+`, which is the reference's rule and not the
    // obvious one.** `+` is an encoded space inside a value, so
    // `?q=packet+capture` is one parameter by any reading of RFC 3986 - and
    // the reference emits three for `?q=packet+capture&safe=off`: `q=packet`,
    // `capture`, `safe=off`. Measured on its own output rather than assumed
    // (`scripts/http/dissect.ts`), and matched, because the registry's promise
    // is that a filter learnt in Wireshark answers the same here - which is a
    // promise about values wherever a field is one a user types a literal into.
    //
    // A parameter whose VALUE contains an `=` is legal and common (base64
    // padding), so the whole `name=value` pair is what the field carries
    // rather than either half.
    for (const parameter of query.split(/[&+]/).filter((p) => p.length > 0)) {
      rows.push({ name: 'Request URI Query Parameter', value: parameter, abbrev: 'http.request.uri.query.parameter' });
    }
  }
  return rows;
}

/**
 * `http://host/path`, which is the one field that needs to know where the
 * message was going rather than only what it said.
 *
 * The Host header carries the authority and the start line carries the rest,
 * so neither alone is the URI the user typed. A request with no Host - HTTP/1.0,
 * and still seen - has no full URI to report, and reporting the target alone
 * would be a different fact wearing this field's name.
 */
function fullRequestUri(message: Http1Message, scheme: string): string | undefined {
  const target = message.target ?? '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) return target;
  const host = headerValue(message.headers, 'host');
  if (host === undefined) return undefined;
  return `${scheme}://${host}${target}`;
}

export interface HttpRowOptions {
  /**
   * `http` or `https`, for the full request URI. It is the caller's to decide
   * because only the caller knows whether the bytes arrived through TLS.
   */
  scheme?: string;
  /**
   * Draw `[Notification: True]` rather than `[Request: True]`.
   *
   * SSDP's NOTIFY is a request by syntax and an announcement by intent - it
   * answers nobody and expects no reply - and the reference marks it with a
   * field of its own for exactly that reason.
   */
  notification?: boolean;
  /**
   * The message arrived whole in one datagram, so there is no body framing to
   * report - see the row it suppresses.
   */
  datagram?: boolean;
  /**
   * The request this response answers, and how long it waited.
   *
   * Only a response has one, and only when the request was seen: a capture
   * started mid-connection has responses whose requests are not in it, and the
   * honest answer there is no row rather than a zero.
   */
  answers?: { frameId: number; elapsedUs: number };
}

/** One message's rows, in the reference's order. */
export function httpMessageRows(message: Http1Message, options: HttpRowOptions = {}): ProtocolField[] {
  const rows: ProtocolField[] = [];
  const isRequest = message.kind === 'request';

  const startLine: ProtocolField[] = [];
  if (isRequest) {
    startLine.push(
      { name: 'Request Method', value: message.method ?? '', abbrev: 'http.request.method' },
      { name: 'Request URI', value: message.target ?? '', abbrev: 'http.request.uri', children: uriRows(message.target ?? '') },
      { name: 'Request Version', value: message.version, abbrev: 'http.request.version' },
    );
  } else {
    const status = message.status ?? 0;
    startLine.push(
      { name: 'Response Version', value: message.version, abbrev: 'http.response.version' },
      {
        name: 'Status Code',
        value: status,
        abbrev: 'http.response.code',
        children: [{
          name: 'Status Code Description',
          value: STATUS_CLASS[Math.floor(status / 100)] ?? 'Unknown',
          generated: true,
          abbrev: 'http.response.code.desc',
        }],
      },
    );
    if (message.reason) startLine.push({ name: 'Response Phrase', value: message.reason, abbrev: 'http.response.phrase' });
  }
  rows.push({ name: message.summary, value: '', isExpanded: true, children: startLine });

  const rawLineAbbrev = isRequest ? 'http.request.line' : 'http.response.line';
  for (const header of message.headers) {
    const named = HEADER_ABBREV[header.name.toLowerCase()];
    const raw = `${header.name}: ${header.value}`;
    rows.push({
      name: header.name,
      // **The reference's `http.unknown_header` carries the whole raw line and
      // this one carries the value.** Its tree row and its field are one thing
      // here - the text drawn IS the value filtered on - so matching the
      // reference would draw `MAN: MAN: "ssdp:discover"`, the header name
      // twice, on every header HTTP has no name for. Recorded rather than
      // hidden: `http.unknown_header contains "ssdp:discover"` answers the
      // same on both, and only a filter written against the name half differs
      // - which is what the row's own name is for.
      value: header.value,
      abbrev: named ?? 'http.unknown_header',
      // The raw line, which the reference emits beside every named header and
      // hides. Nesting it is how a tree with no hidden rows keeps the name
      // filterable without drawing each header twice at the same level.
      ...(named ? { children: [{ name: 'Raw line', value: raw, abbrev: rawLineAbbrev }] } : {}),
    });
  }

  if (isRequest) {
    // The reference hides these two and they are both real filters: `http.request`
    // is how you ask for requests without naming a method, and the full URI is
    // the only place the authority and the target appear together.
    rows.push(options.notification
      ? { name: '[Notification]', value: true, generated: true, abbrev: 'http.notification' }
      : { name: '[Request]', value: true, generated: true, abbrev: 'http.request' });
    const full = fullRequestUri(message, options.scheme ?? 'http');
    if (full !== undefined) {
      rows.push({ name: '[Full request URI]', value: full, generated: true, abbrev: 'http.request.full_uri' });
    }
  } else {
    rows.push({ name: '[Response]', value: true, generated: true, abbrev: 'http.response' });
    if (options.answers !== undefined) {
      // The two numbers that answer "was the server slow, or did it never
      // reply at all" - which is the question anyone opens an HTTP capture
      // with, and which this build could not answer at all.
      rows.push({
        name: '[Request in frame]',
        value: options.answers.frameId,
        generated: true,
        abbrev: 'http.request_in',
        linkToFrame: options.answers.frameId,
      });
      rows.push({
        name: '[Time since request]',
        value: `${(options.answers.elapsedUs / 1_000_000).toFixed(9)} seconds`,
        generated: true,
        abbrev: 'http.time',
      });
    }
  }

  // How the body is delimited, which is a fact about a STREAM: it is what
  // tells the next message from this one's payload. A datagram protocol has
  // no next message, so SSDP passes `datagram` and the row is not drawn.
  if (!options.datagram) {
    rows.push({ name: 'Body', value: message.bodyFraming, description: 'How the message says its body is delimited' });
  }
  return rows;
}

/**
 * The filterable half.
 *
 * Deliberately a SUBSET of what the rows carry, and the rule is per-frame
 * cost: the bag is built for every frame and kept for as long as the frame is,
 * where a tree is built on demand and thrown away with the pane (ADR 0007). So
 * the headers that a filter is actually reached for go in - the ones a colour
 * rule or a saved filter names - and the raw line of every header does not.
 */
export function httpMessageFields(
  message: Http1Message, options: HttpRowOptions = {},
): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  if (message.kind === 'request') {
    out['http.request.method'] = message.method ?? '';
    out['http.request.uri'] = message.target ?? '';
    out['http.request.version'] = message.version;
    if (options.notification) out['http.notification'] = 1;
    else out['http.request'] = 1;
    const target = message.target ?? '';
    // See `uriRows`: the asterisk form has no path to report.
    if (target !== '*' && target.length > 0) {
      const mark = target.indexOf('?');
      out['http.request.uri.path'] = mark === -1 ? target : target.slice(0, mark);
      if (mark !== -1) out['http.request.uri.query'] = target.slice(mark + 1);
    }
    const full = fullRequestUri(message, options.scheme ?? 'http');
    if (full !== undefined) out['http.request.full_uri'] = full;
  } else {
    out['http.response'] = 1;
    out['http.response.code'] = message.status ?? 0;
    if (options.answers !== undefined) {
      out['http.request_in'] = options.answers.frameId;
      // Seconds, because that is the unit the reference's FT_RELATIVE_TIME
      // filters in - `http.time > 1` is one second there and must be here.
      out['http.time'] = options.answers.elapsedUs / 1_000_000;
    }
    out['http.response.version'] = message.version;
    if (message.reason) out['http.response.phrase'] = message.reason;
  }

  for (const header of message.headers) {
    const named = HEADER_ABBREV[header.name.toLowerCase()];
    // One key holds one value, so a header sent twice keeps the FIRST - which
    // is what a filter written against a capture would have matched when the
    // author read it in the tree.
    if (named !== undefined && !(named in out)) out[named] = header.value;
  }
  return out;
}
