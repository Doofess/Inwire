/**
 * HTTP/1.0 and HTTP/1.1 over a byte stream.
 *
 * Until now a frame on port 80 was labelled "HTTP" on the strength of the port
 * number alone and nothing was read out of it - the Info column showed TCP
 * flags for a request the bytes spelled out in plain text. This reads the
 * start line and the headers, and follows the body framing well enough to know
 * where the *next* message begins, which is the part that cannot be done one
 * frame at a time: Content-Length and chunked encoding are both stateful, and
 * a dissector that guesses at a message boundary will find a "request" in the
 * middle of a response body sooner or later.
 *
 * The same code reads a TLS-decrypted stream whose ALPN was `http/1.1`.
 *
 * **Bodies are reassembled here and decoded in `httpBody.ts`.** A body is
 * collected across as many arrivals as it takes and handed back on the
 * segment that COMPLETES it, which is not necessarily the one that carried
 * the head - that is what `Http1Result.bodies` is for, and it is why a
 * finished body carries the message it belongs to rather than the caller
 * having to remember.
 */
import { dissectEnv, liveHttp1BodyBytes } from '../dissect/dissectEnv';

const CR = 0x0d;
const LF = 0x0a;
/** A start line longer than this is not one; the stream is something else. */
const MAX_START_LINE = 8 * 1024;
/** Header block ceiling, matching what servers commonly enforce. */
const MAX_HEADER_BLOCK = 64 * 1024;

/**
 * How much of one message's body is kept.
 *
 * A megabyte is far past the point where reading a body in a detail pane
 * stops being how anyone works, and it is the whole of almost every API
 * response and HTML page. Past it the tree says how much was dropped, which
 * is a different thing from a body that was never collected.
 */
const MAX_BODY_BYTES = 1024 * 1024;

/**
 * How many separate pieces one body may be collected in.
 *
 * Not a size bound - `MAX_BODY_BYTES` is that. This one exists because a
 * chunked body may legally be sent one byte per chunk, and a million-element
 * array of one-byte views costs far more than the megabyte it holds.
 */
const MAX_BODY_PIECES = 2048;

/**
 * The ceiling across every body being collected at once, anywhere, lives in
 * `dissect/dissectEnv.ts` with the counter it bounds.
 *
 * **It is the bound that actually binds.** The per-message cap multiplied by
 * `tcpStreamTracker.ts`'s 16,384 connections and two directions each is
 * 32 GiB of headroom, so the per-message cap alone is not a bound on the
 * process at all. Everything in flight shares that one instead - which also
 * makes it the one piece of HTTP state shared ACROSS connections, and why it
 * is read through the environment rather than a module counter: a tree
 * rebuilt later must see the room arrival saw, not the room there is now.
 */

/** For an assertion script, which needs to see the counter return to zero. */
export function http1LiveBodyBytes(): number {
  return liveHttp1BodyBytes();
}

/** Why a body is shorter than the sender said it would be. */
export type BodyTruncation = 'message' | 'pieces' | 'total' | 'framing';

export interface Http1Body {
  /** The message this is the body of, whichever frame its head arrived in. */
  message: Http1Message;
  /** The bytes as they were on the wire - still compressed, if they were. */
  bytes: Uint8Array;
  /** How many body bytes passed by, including any this did not keep. */
  observed: number;
  /** Null when the whole body is here. */
  truncated: BodyTruncation | null;
  /** Each chunk's size and where its data sat, for a chunked body. */
  chunks: { size: number; at: number }[];
}

const METHODS = new Set([
  'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH',
  // WebDAV and friends, which appear on captures of anything with a calendar.
  'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'REPORT',
  'SEARCH', 'MKCALENDAR', 'ACL', 'BIND', 'UNBIND', 'REBIND', 'NOTIFY', 'SUBSCRIBE',
  // SSDP, which is HTTP/1.1 syntax over UDP multicast and is read by this same
  // parser - the reference does the same thing, filing it under HTTP's field
  // names. `NOTIFY` above is SSDP's other verb and was already here for WebDAV.
  'M-SEARCH',
]);

export interface Http1Header { name: string; value: string }

export interface Http1Message {
  kind: 'request' | 'response';
  method?: string;
  target?: string;
  version: string;
  status?: number;
  reason?: string;
  headers: Http1Header[];
  /** What the framing says the body is, for the tree. */
  bodyFraming: string;
  summary: string;
}

export interface Http1Direction {
  /** Bytes of an incomplete header block. */
  pending: Uint8Array;
  /** Body bytes still to pass over before the next message can start. */
  bodyRemaining: number;
  /** True while a chunked body is being walked. */
  chunked: boolean;
  /**
   * True between the zero-length chunk and the blank line that ends the
   * trailer section. Its own flag because the trailers may be split across
   * arrivals like anything else, and a chunked body is not over until the
   * blank line - a decoder that stops at the `0` finds the next message two
   * bytes early and reads a stray CRLF as a start line.
   */
  trailer: boolean;
  /** True once the body runs to connection close, so nothing after it is a message. */
  untilClose: boolean;
  /** True once this direction has shown a start line, so a mid-stream capture is known as such. */
  seenStart: boolean;

  /**
   * The message whose body is being collected, or null when none is.
   *
   * Held rather than passed because a body routinely finishes in a frame that
   * carries no head at all, and the row it produces has to say which message
   * it belongs to.
   */
  bodyOwner: Http1Message | null;
  /** Collected pieces, oldest first. Joined once, in `finishBody`. */
  body: Uint8Array[];
  bodyLength: number;
  bodyObserved: number;
  bodyTruncated: BodyTruncation | null;
  /** Chunk sizes and their offsets within the collected body. */
  bodyChunks: { size: number; at: number }[];
  /**
   * Bytes of the CURRENT chunk's DATA still to copy.
   *
   * **A second counter beside `bodyRemaining`, and the reason is the one bug
   * this whole feature is most likely to ship with.** `walkChunks` sets
   * `bodyRemaining = size + 2`, folding the CRLF that closes every chunk into
   * the same number so that a body split anywhere resumes from one value.
   * That is right for FRAMING and wrong for COPYING: taking `bodyRemaining`
   * bytes appends the terminator too, two stray bytes per chunk, and the
   * result is a JSON body that fails to parse in a way that looks exactly
   * like a decompression bug. Data always precedes the terminator inside a
   * chunk, so the first `chunkDataRemaining` of any span is body and the rest
   * is not.
   */
  chunkDataRemaining: number;
  /** Set when a chunk header did not parse, so the finished body says so. */
  bodyFramingLost: boolean;
}

export function freshHttp1Direction(): Http1Direction {
  return {
    pending: new Uint8Array(0), bodyRemaining: 0, chunked: false, trailer: false,
    untilClose: false, seenStart: false,
    bodyOwner: null, body: [], bodyLength: 0, bodyObserved: 0, bodyTruncated: null,
    bodyChunks: [], chunkDataRemaining: 0, bodyFramingLost: false,
  };
}

/**
 * Gives a half-collected body's bytes back to the shared budget.
 *
 * Called when the connection holding this direction is forgotten, which is
 * the one way a body stops being collected without finishing. See
 * `dissect/dissectEnv.ts`.
 */
export function releaseHttp1Body(direction: Http1Direction): void {
  dissectEnv().releaseBodyBytes(direction.bodyLength);
  direction.body = [];
  direction.bodyLength = 0;
  direction.bodyOwner = null;
}

/** Begins collecting the body of `message`, dropping anything half-collected. */
function startBody(direction: Http1Direction, message: Http1Message): void {
  releaseHttp1Body(direction);
  direction.bodyOwner = message;
  direction.bodyObserved = 0;
  direction.bodyTruncated = null;
  direction.bodyChunks = [];
}

/** Keeps as much of `piece` as the three bounds allow. */
function appendBody(direction: Http1Direction, piece: Uint8Array): void {
  direction.bodyObserved += piece.length;
  if (direction.bodyOwner === null || piece.length === 0) return;
  if (direction.bodyTruncated !== null) return;
  if (direction.body.length >= MAX_BODY_PIECES) { direction.bodyTruncated = 'pieces'; return; }

  const perMessage = MAX_BODY_BYTES - direction.bodyLength;
  // Asked for no more than one message may hold: past that the answer changes
  // nothing here, and asking for less keeps it independent of how many other
  // connections are collecting (`DissectEnv.sharedBodyRoom`).
  const shared = dissectEnv().sharedBodyRoom(MAX_BODY_BYTES);
  const room = Math.min(perMessage, shared);
  if (room <= 0) {
    direction.bodyTruncated = perMessage <= 0 ? 'message' : 'total';
    return;
  }
  const take = Math.min(room, piece.length);
  // `slice`, not `subarray`: the caller's buffer is the segment, and holding a
  // view of it would pin the whole segment for as long as the body lives.
  direction.body.push(piece.slice(0, take));
  direction.bodyLength += take;
  dissectEnv().takeBodyBytes(take);
  if (take < piece.length) direction.bodyTruncated = perMessage <= shared ? 'message' : 'total';
}

/** Joins the collected pieces and hands the budget back. */
function finishBody(direction: Http1Direction, truncation: BodyTruncation | null = null): Http1Body | null {
  const message = direction.bodyOwner;
  if (message === null) return null;
  const bytes = new Uint8Array(direction.bodyLength);
  let at = 0;
  for (const piece of direction.body) { bytes.set(piece, at); at += piece.length; }
  const body: Http1Body = {
    message, bytes, observed: direction.bodyObserved,
    truncated: truncation ?? direction.bodyTruncated,
    chunks: direction.bodyChunks,
  };
  releaseHttp1Body(direction);
  direction.bodyChunks = [];
  direction.bodyTruncated = null;
  direction.bodyObserved = 0;
  return body;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

/** Index of the CRLF CRLF (or LF LF) that ends a header block, or -1. */
function endOfHeaders(bytes: Uint8Array, from: number): { at: number; skip: number } | null {
  for (let i = from; i + 1 < bytes.length; i++) {
    if (bytes[i] === LF && bytes[i + 1] === LF) return { at: i, skip: 2 };
    if (bytes[i] === CR && bytes[i + 1] === LF && i + 3 < bytes.length
      && bytes[i + 2] === CR && bytes[i + 3] === LF) return { at: i, skip: 4 };
  }
  return null;
}

const decoder = new TextDecoder('utf-8', { fatal: false });

/**
 * Whether a stream that has not yet shown a message starts one here.
 *
 * Deliberately strict: a method name followed by a space, or `HTTP/`. Reading
 * anything else as HTTP is how a binary protocol on an unusual port ends up
 * labelled with a "request" assembled out of its payload.
 */
export function looksLikeHttp1(bytes: Uint8Array, start: number, end: number): boolean {
  if (end - start < 5) return false;
  const head = decoder.decode(bytes.subarray(start, Math.min(end, start + 20)));
  if (head.startsWith('HTTP/1.')) return true;
  const space = head.indexOf(' ');
  if (space <= 0) return false;
  return METHODS.has(head.slice(0, space));
}

function parseHeaders(text: string): Http1Header[] {
  const out: Http1Header[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.replace(/\r$/, '');
    if (trimmed.length === 0) continue;
    const colon = trimmed.indexOf(':');
    if (colon <= 0) continue;
    out.push({ name: trimmed.slice(0, colon).trim(), value: trimmed.slice(colon + 1).trim() });
  }
  return out;
}

function headerValue(headers: Http1Header[], name: string): string | undefined {
  const lower = name.toLowerCase();
  return headers.find((h) => h.name.toLowerCase() === lower)?.value;
}

/**
 * Decides how long the body is (RFC 9112 §6.3), which is what tells the next
 * message from this one's payload. Transfer-Encoding wins over Content-Length
 * whenever both are present - a rule that exists because disagreeing on it is
 * the whole of request smuggling.
 */
function bodyFraming(
  message: Http1Message,
  requestMethod: string | undefined
): { length: number; chunked: boolean; untilClose: boolean; description: string } {
  const transferEncoding = headerValue(message.headers, 'transfer-encoding');
  if (transferEncoding !== undefined && /chunked/i.test(transferEncoding)) {
    return { length: 0, chunked: true, untilClose: false, description: 'chunked' };
  }

  if (message.kind === 'response') {
    const status = message.status ?? 0;
    // 1xx, 204 and 304 never have a body, and neither does the response to a
    // HEAD however much its Content-Length claims.
    if ((status >= 100 && status < 200) || status === 204 || status === 304 || requestMethod === 'HEAD') {
      return { length: 0, chunked: false, untilClose: false, description: 'no body' };
    }
  }

  const contentLength = headerValue(message.headers, 'content-length');
  if (contentLength !== undefined) {
    const length = Number.parseInt(contentLength, 10);
    if (Number.isFinite(length) && length >= 0) {
      return { length, chunked: false, untilClose: false, description: `${length} bytes` };
    }
  }

  // A response with neither runs until the connection closes; a request with
  // neither has no body at all.
  return message.kind === 'response'
    ? { length: 0, chunked: false, untilClose: true, description: 'until connection close' }
    : { length: 0, chunked: false, untilClose: false, description: 'no body' };
}

export interface Http1Result {
  messages: Http1Message[];
  /** Bytes of body this segment carried, for the "Continuation" case. */
  bodyBytes: number;
  /**
   * Bodies that FINISHED in this segment.
   *
   * Usually empty, and not parallel to `messages`: a body that spans ten
   * frames is reported once, on the tenth, and the message it belongs to had
   * its head in the first.
   */
  bodies: Http1Body[];
}

/**
 * Reads whole messages out of `data`.
 *
 * `lastRequestMethod` is the method of the request this direction is answering,
 * needed because a response to HEAD has the Content-Length of the body it is
 * not sending.
 */
export function dissectHttp1(
  data: Uint8Array,
  direction: Http1Direction,
  lastRequestMethod?: string
): Http1Result {
  let bytes = concat(direction.pending, data);
  direction.pending = new Uint8Array(0);
  const messages: Http1Message[] = [];
  const bodies: Http1Body[] = [];
  let bodyBytes = 0;
  let p = 0;

  for (;;) {
    if (direction.untilClose) { bodyBytes += bytes.length - p; return { messages, bodyBytes, bodies }; }

    if (direction.chunked) {
      const before = direction.chunked;
      const consumed = walkChunks(bytes, p, direction);
      bodyBytes += consumed - p;
      p = consumed;
      if (direction.chunked) { direction.pending = bytes.subarray(p).slice(); return { messages, bodyBytes, bodies }; }
      // `walkChunks` clears `chunked` two ways: the trailer ended, or a chunk
      // header did not parse. The second leaves a body that is missing its
      // tail, and saying which is what `bodyFramingLost` is for.
      if (before) {
        const done = finishBody(direction, direction.bodyFramingLost ? 'framing' : null);
        direction.bodyFramingLost = false;
        if (done !== null) bodies.push(done);
      }
      continue;
    }

    if (direction.bodyRemaining > 0) {
      const take = Math.min(direction.bodyRemaining, bytes.length - p);
      appendBody(direction, bytes.subarray(p, p + take));
      direction.bodyRemaining -= take;
      bodyBytes += take;
      p += take;
      if (direction.bodyRemaining > 0) return { messages, bodyBytes, bodies };
      const done = finishBody(direction);
      if (done !== null) bodies.push(done);
      continue;
    }

    if (p >= bytes.length) break;

    if (!direction.seenStart && !looksLikeHttp1(bytes, p, bytes.length)) {
      // Not a message start and this direction has never shown one, so this is
      // not HTTP - or is the tail of a message whose head we never captured.
      return { messages, bodyBytes, bodies };
    }

    const boundary = endOfHeaders(bytes, p);
    if (boundary === null) {
      if (bytes.length - p > MAX_HEADER_BLOCK) return { messages, bodyBytes, bodies };
      direction.pending = bytes.subarray(p).slice();
      return { messages, bodyBytes, bodies };
    }

    const block = decoder.decode(bytes.subarray(p, boundary.at));
    const newlineIndex = block.indexOf('\n');
    const startLine = (newlineIndex === -1 ? block : block.slice(0, newlineIndex)).replace(/\r$/, '');
    if (startLine.length > MAX_START_LINE) return { messages, bodyBytes, bodies };
    const headers = parseHeaders(newlineIndex === -1 ? '' : block.slice(newlineIndex + 1));

    const message = parseStartLine(startLine, headers);
    if (message === null) return { messages, bodyBytes, bodies };

    const framing = bodyFraming(message, message.kind === 'response' ? lastRequestMethod : undefined);
    message.bodyFraming = framing.description;
    messages.push(message);
    direction.seenStart = true;

    p = boundary.at + boundary.skip;
    direction.bodyRemaining = framing.length;
    direction.chunked = framing.chunked;
    direction.untilClose = framing.untilClose;
    direction.chunkDataRemaining = 0;
    // **A body that runs until the connection closes is deliberately not
    // collected.** There is no completion event on that path - the framing IS
    // "until FIN" - so the bytes would be held for the life of the connection
    // with nothing able to release them, which is the shape of a leak rather
    // than of a bound.
    if (framing.length > 0 || framing.chunked) startBody(direction, message);
    else releaseHttp1Body(direction);
  }

  return { messages, bodyBytes, bodies };
}

function parseStartLine(line: string, headers: Http1Header[]): Http1Message | null {
  if (line.startsWith('HTTP/')) {
    const parts = line.split(' ');
    const status = Number.parseInt(parts[1] ?? '', 10);
    if (!Number.isFinite(status)) return null;
    const reason = parts.slice(2).join(' ');
    return {
      kind: 'response', version: parts[0], status, reason, headers, bodyFraming: '',
      summary: `${parts[0]} ${status}${reason.length > 0 ? ` ${reason}` : ''}`,
    };
  }

  const parts = line.split(' ');
  if (parts.length < 2 || !METHODS.has(parts[0])) return null;
  const version = parts.length >= 3 ? parts[2] : 'HTTP/0.9';
  return {
    kind: 'request', method: parts[0], target: parts[1], version, headers, bodyFraming: '',
    summary: `${parts[0]} ${parts[1]} ${version}`,
  };
}

/** Index of the next LF at or after `from`, or -1. */
function nextLine(bytes: Uint8Array, from: number): number {
  for (let i = from; i < bytes.length; i++) if (bytes[i] === LF) return i;
  return -1;
}

/**
 * Walks a chunked body far enough to find its end. The chunk data itself is
 * skipped, not kept - reassembling and de-gzipping bodies is a different
 * feature, and this only has to know where the next message starts.
 *
 * Every branch may run out of bytes half way, since a chunk boundary has
 * nothing to do with a segment boundary; each of them leaves the state so that
 * the next arrival resumes where this one stopped.
 */
function walkChunks(bytes: Uint8Array, from: number, direction: Http1Direction): number {
  let p = from;
  for (;;) {
    if (direction.trailer) {
      // Zero or more trailer lines, then a blank one.
      for (;;) {
        const lineEnd = nextLine(bytes, p);
        if (lineEnd === -1) return p;
        const blank = lineEnd === p || (lineEnd === p + 1 && bytes[p] === CR);
        p = lineEnd + 1;
        if (blank) { direction.trailer = false; direction.chunked = false; return p; }
      }
    }

    if (direction.bodyRemaining > 0) {
      const take = Math.min(direction.bodyRemaining, bytes.length - p);
      // Of the bytes taken here, the first `chunkDataRemaining` are the
      // chunk's data and anything after them is its CRLF. Copying `take` of
      // them would append the terminator - see `chunkDataRemaining`, where
      // the whole of this is written down, and the assertion in
      // `scripts/http/dissect.ts` that splits a body between its last data
      // byte and that CRLF.
      const dataTake = Math.min(direction.chunkDataRemaining, take);
      if (dataTake > 0) appendBody(direction, bytes.subarray(p, p + dataTake));
      direction.chunkDataRemaining -= dataTake;
      direction.bodyRemaining -= take;
      p += take;
      if (direction.bodyRemaining > 0) return p;
      continue;
    }

    // Chunk size line: hex, optionally with extensions after a semicolon.
    const lineEnd = nextLine(bytes, p);
    if (lineEnd === -1) return p;

    const sizeText = decoder.decode(bytes.subarray(p, lineEnd)).split(';')[0].trim();
    const size = Number.parseInt(sizeText, 16);
    if (!Number.isFinite(size) || size < 0) {
      // Not a chunk header. The framing is lost, and guessing at where the
      // next message starts would be worse than admitting it.
      direction.chunked = false;
      direction.bodyFramingLost = true;
      return bytes.length;
    }
    p = lineEnd + 1;

    if (size === 0) { direction.trailer = true; continue; }
    direction.bodyChunks.push({ size, at: direction.bodyLength });
    // The CRLF that closes every chunk is counted with the chunk, so a body
    // split anywhere - including between the data and its terminator - resumes
    // from one number rather than from a position in a two-step dance.
    direction.bodyRemaining = size + 2;
    direction.chunkDataRemaining = size;
  }
}
