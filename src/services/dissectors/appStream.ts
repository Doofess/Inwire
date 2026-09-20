/**
 * What to do with a decrypted (or plaintext) application byte stream.
 *
 * One place decides between HTTP/1.1 and HTTP/2 and holds each direction's
 * per-connection state, because both are stateful across frames and both can
 * arrive either in the clear or out of a TLS record that a key log opened. The
 * choice is made by ALPN when there is one - the connection said what it was
 * going to speak, and that is better evidence than anything in the first bytes
 * - and by content when there is not, which is the ordinary case on port 80.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { httpMessageFields, httpMessageRows } from './httpFields';
import { dissectHttp1, freshHttp1Direction, looksLikeHttp1, type Http1Direction } from './http1';
import {
  dissectHttp2, freshHttp2Direction, http2ErrorName, HTTP2_PREFACE,
  type Http2Direction, type Http2Frame,
} from './http2';

export type AppProtocol = 'unknown' | 'http/1.1' | 'h2';

/** One direction's application-layer state, held with the connection. */
export interface AppDirection {
  protocol: AppProtocol;
  http1: Http1Direction;
  http2: Http2Direction;
  /** The method of the last request, so a response to HEAD is framed correctly. */
  lastMethod?: string;
  /**
   * Requests this direction has sent and not yet seen answered, oldest first.
   *
   * **HTTP/1.1 needs no tracker and no key**, which is what separates this
   * from `DnsTracker` and `IcmpEchoTracker`: responses on one connection come
   * back in the order the requests went out - that is what pipelining IS, and
   * it is the only rule RFC 9112 gives for matching them. So the pairing is a
   * queue held with the connection, and a response takes the head of its
   * peer's.
   *
   * Bounded, because a client that pipelines against a server that never
   * answers would otherwise grow one entry per request for the life of the
   * capture. Losing the oldest is right for the same reason it is right in
   * `IcmpEchoTracker`: the response it was waiting for is the one least likely
   * to still be coming.
   */
  pendingRequests: { frameId: number; tsUs: number }[];
}

/** Outstanding requests kept per direction. */
const MAX_PENDING_REQUESTS = 64;

export function freshAppDirection(): AppDirection {
  return {
    protocol: 'unknown', http1: freshHttp1Direction(), http2: freshHttp2Direction(),
    pendingRequests: [],
  };
}

export interface AppStreamResult {
  /** "HTTP", "HTTP2" - the Protocol column, or null when nothing was recognised. */
  protocolLabel: string | null;
  /** Info fragments, in order. */
  info: string[];
  /**
   * One layer, however many messages the segment carried.
   *
   * Wireshark opens a separate top-level tree per HTTP/2 frame; here they are
   * children of one, because `frameProtocols` is derived from the layer names
   * in order and six HTTP/2 frames in one TCP segment would otherwise put six
   * `http2` tokens in the protocol hierarchy - where a repeated token reads as
   * a protocol nested inside itself.
   */
  layers: ProtocolLayer[];
  fields: Record<string, string | number>;
}

const EMPTY: AppStreamResult = { protocolLabel: null, info: [], layers: [], fields: {} };

function startsWith(bytes: Uint8Array, prefix: Uint8Array): boolean {
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (bytes[i] !== prefix[i]) return false;
  return true;
}

/**
 * Reads a stretch of plaintext.
 *
 * `alpn` is what the handshake negotiated, when it is known; `fromClient`
 * decides which side of the conversation this is, which HTTP/2 needs for the
 * connection preface and HTTP/1.1 for telling a request from a response when
 * the capture started mid-stream.
 */
export function dissectAppStream(
  plaintext: Uint8Array,
  direction: AppDirection,
  fromClient: boolean,
  alpn: string | undefined,
  peer: AppDirection | undefined,
  /**
   * Which frame these bytes arrived in, for `http.request_in` and
   * `http.time`. Optional because a caller that does not know - and the
   * decrypted-TLS path did not, until this - gets the tree without those two
   * rows rather than with a made-up number in them.
   */
  frame?: { id: number; tsUs: number },
): AppStreamResult {
  if (plaintext.length === 0) return EMPTY;

  if (direction.protocol === 'unknown') {
    if (alpn === 'h2' || alpn === 'h2c') direction.protocol = 'h2';
    else if (alpn === 'http/1.1' || alpn === 'http/1.0') direction.protocol = 'http/1.1';
    else if (startsWith(plaintext, HTTP2_PREFACE)) direction.protocol = 'h2';
    else if (looksLikeHttp1(plaintext, 0, plaintext.length)) direction.protocol = 'http/1.1';
    else if (!fromClient && peer?.protocol === 'h2') direction.protocol = 'h2';
    else return EMPTY;
  }

  return direction.protocol === 'h2'
    ? readHttp2(plaintext, direction, fromClient)
    : readHttp1(plaintext, direction, fromClient, peer, frame);
}

// --- HTTP/1.1 -----------------------------------------------------------------

function readHttp1(
  plaintext: Uint8Array,
  direction: AppDirection,
  fromClient: boolean,
  peer: AppDirection | undefined,
  frame?: { id: number; tsUs: number },
): AppStreamResult {
  const result = dissectHttp1(plaintext, direction.http1, peer?.lastMethod);
  if (result.messages.length === 0) {
    // Body bytes with no start line: the frame is part of a message whose head
    // was in an earlier one.
    if (result.bodyBytes === 0) return EMPTY;
    return {
      protocolLabel: 'HTTP', info: ['Continuation'],
      layers: [{
        name: 'Hypertext Transfer Protocol',
        summary: `Continuation (${result.bodyBytes} bytes)`,
        fields: [{ name: 'Body', value: `${result.bodyBytes} bytes of a message that began in an earlier frame` }],
      }],
      fields: {},
    };
  }

  const info: string[] = [];
  const rows: ProtocolField[] = [];
  const fields: Record<string, string | number> = {};

  for (const message of result.messages) {
    // The reference analyzer's HTTP dissector puts a trailing space after each
    // start line and appends the media type in brackets, and pipelined
    // messages run together with no separator between them - so two requests
    // in one segment read "GET /one HTTP/1.1 GET /two HTTP/1.1 ". Matched
    // exactly, because the column text is the contract.
    const type = message.kind === 'response'
      ? message.headers.find((h) => h.name.toLowerCase() === 'content-type')?.value
      : undefined;
    const mediaType = type === undefined ? '' : ` (${type.split(';')[0].trim()})`;
    info.push(`${message.summary} ${mediaType}`);

    let answers: { frameId: number; elapsedUs: number } | undefined;
    if (message.kind === 'request') {
      if (fromClient) direction.lastMethod = message.method;
      if (frame !== undefined) {
        direction.pendingRequests.push({ frameId: frame.id, tsUs: frame.tsUs });
        if (direction.pendingRequests.length > MAX_PENDING_REQUESTS) direction.pendingRequests.shift();
      }
    } else if (frame !== undefined && peer !== undefined) {
      // The head of the peer's queue, consumed: a second response cannot claim
      // the same request, and a response with no request left to claim is
      // itself worth seeing as one.
      const asked = peer.pendingRequests.shift();
      if (asked !== undefined) answers = { frameId: asked.frameId, elapsedUs: frame.tsUs - asked.tsUs };
    }

    rows.push(...httpMessageRows(message, { answers }));
    Object.assign(fields, httpMessageFields(message, { answers }));
  }

  const line = info.join('');
  return {
    protocolLabel: 'HTTP',
    // One entry, already joined: pipelined messages are concatenated, not
    // comma-separated, so the caller must not put a separator between them.
    info: [line],
    layers: [{ name: 'Hypertext Transfer Protocol', summary: line.trim(), fields: rows }],
    fields,
  };
}

// --- HTTP/2 --------------------------------------------------------------------

function readHttp2(plaintext: Uint8Array, direction: AppDirection, fromClient: boolean): AppStreamResult {
  const { frames, sawPreface } = dissectHttp2(plaintext, direction.http2, fromClient);
  if (frames.length === 0 && !sawPreface) return EMPTY;

  const info: string[] = [];
  const rows: ProtocolField[] = [];
  const fields: Record<string, string | number> = {};

  if (sawPreface) {
    info.push('Magic');
    rows.push({
      name: 'Magic', value: 'PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n',
      description: 'The connection preface, which is how a client says it is speaking HTTP/2 before any frame',
    });
  }

  for (const frame of frames) {
    info.push(frame.summary);
    rows.push(http2Row(frame));
    fields['http2.type'] = frame.type;
    fields['http2.streamid'] = frame.streamId;
    if (frame.headers !== undefined) {
      for (const header of frame.headers) {
        switch (header.name) {
          case ':method': fields['http2.headers.method'] = header.value; if (fromClient) direction.lastMethod = header.value; break;
          case ':path': fields['http2.headers.path'] = header.value; break;
          case ':authority': fields['http2.headers.authority'] = header.value; break;
          case ':status': fields['http2.headers.status'] = Number.parseInt(header.value, 10) || 0; break;
          case 'user-agent': fields['http2.headers.user_agent'] = header.value; break;
          case 'content-type': fields['http2.headers.content_type'] = header.value; break;
          default: break;
        }
      }
    }
  }

  return {
    protocolLabel: 'HTTP2',
    info,
    layers: [{ name: 'HyperText Transfer Protocol 2', summary: info.join(', '), fields: rows }],
    fields,
  };
}

function http2Row(frame: Http2Frame): ProtocolField {
  const fields: ProtocolField[] = [
    { name: 'Length', value: frame.length },
    { name: 'Type', value: `${frame.typeName} (${frame.type})`, abbrev: 'http2.type' },
    { name: 'Flags', value: `0x${frame.flags.toString(16).padStart(2, '0')}` },
    { name: 'Stream Identifier', value: frame.streamId, abbrev: 'http2.streamid' },
  ];

  if (frame.headers !== undefined) {
    const headerFields: ProtocolField[] = frame.headers.map((header) => {
      const field: ProtocolField = { name: header.name, value: header.value };
      switch (header.name) {
        case ':method': field.abbrev = 'http2.headers.method'; break;
        case ':path': field.abbrev = 'http2.headers.path'; break;
        case ':authority': field.abbrev = 'http2.headers.authority'; break;
        case ':status': field.abbrev = 'http2.headers.status'; break;
        case 'user-agent': field.abbrev = 'http2.headers.user_agent'; break;
        case 'content-type': field.abbrev = 'http2.headers.content_type'; break;
        default: break;
      }
      return field;
    });
    fields.push({ name: 'Header Block', value: `${frame.headers.length} header${frame.headers.length === 1 ? '' : 's'}`, children: headerFields, isExpanded: true });
  }
  if (frame.hpackError !== undefined) {
    fields.push({
      name: 'HPACK', value: frame.hpackError,
      description: 'The dynamic table this frame indexes into was built by frames this capture does not contain',
    });
  }
  if (frame.settings !== undefined) {
    fields.push({
      name: 'Settings', value: `${frame.settings.length}`,
      children: frame.settings.map((s) => ({ name: s.name, value: s.value })),
      isExpanded: true,
    });
  }
  if (frame.errorCode !== undefined) {
    fields.push({ name: 'Error', value: `${http2ErrorName(frame.errorCode)} (${frame.errorCode})` });
  }
  if (frame.goawayLastStream !== undefined) {
    fields.push({ name: 'Last Stream ID', value: frame.goawayLastStream });
    if (frame.goawayDebug) fields.push({ name: 'Debug Data', value: frame.goawayDebug });
  }
  if (frame.promisedStreamId !== undefined) {
    fields.push({ name: 'Promised Stream ID', value: frame.promisedStreamId });
  }
  if (frame.windowIncrement !== undefined) {
    fields.push({ name: 'Window Size Increment', value: frame.windowIncrement });
  }
  if (frame.data !== undefined) {
    fields.push({ name: 'Data', value: `${frame.data.length} bytes` });
  }

  return { name: `Stream: ${frame.summary}`, value: '', isExpanded: true, children: fields };
}
