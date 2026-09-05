/**
 * QPACK (RFC 9204), the header compression HTTP/3 uses.
 *
 * QPACK is HPACK rebuilt for a transport that can deliver streams out of
 * order. The dynamic table is filled by a *separate* unidirectional stream
 * rather than by the header blocks themselves, so a request's headers can
 * arrive before the instruction that inserted the entry they index - which
 * HPACK's design made impossible and QUIC's made unavoidable. The field
 * section's prefix says how far the table must have been filled ("Required
 * Insert Count") precisely so a decoder can tell "not yet" from "never".
 *
 * The Huffman code is HPACK's, unchanged, so it is imported rather than
 * duplicated. The static table is not: QPACK's is its own, 99 entries chosen
 * from what the web actually sends, and it is indexed from zero where HPACK's
 * is indexed from one.
 *
 * What this does not do is track the encoder stream's dynamic table across
 * QUIC streams. A block that indexes into it is reported as unresolvable
 * rather than guessed at, the same way an HPACK block is when the capture
 * began mid-connection - and for the same reason, that a header name invented
 * by a decoder is worse than one it admits it does not have.
 */
import { huffmanDecode, type HeaderField } from './hpack';

/** RFC 9204 Appendix A. Indexed from zero, unlike HPACK's. */
const STATIC_TABLE: HeaderField[] = [
  { name: ':authority', value: '' },
  { name: ':path', value: '/' },
  { name: 'age', value: '0' },
  { name: 'content-disposition', value: '' },
  { name: 'content-length', value: '0' },
  { name: 'cookie', value: '' },
  { name: 'date', value: '' },
  { name: 'etag', value: '' },
  { name: 'if-modified-since', value: '' },
  { name: 'if-none-match', value: '' },
  { name: 'last-modified', value: '' },
  { name: 'link', value: '' },
  { name: 'location', value: '' },
  { name: 'referer', value: '' },
  { name: 'set-cookie', value: '' },
  { name: ':method', value: 'CONNECT' },
  { name: ':method', value: 'DELETE' },
  { name: ':method', value: 'GET' },
  { name: ':method', value: 'HEAD' },
  { name: ':method', value: 'OPTIONS' },
  { name: ':method', value: 'POST' },
  { name: ':method', value: 'PUT' },
  { name: ':scheme', value: 'http' },
  { name: ':scheme', value: 'https' },
  { name: ':status', value: '103' },
  { name: ':status', value: '200' },
  { name: ':status', value: '304' },
  { name: ':status', value: '404' },
  { name: ':status', value: '503' },
  { name: 'accept', value: '*/*' },
  { name: 'accept', value: 'application/dns-message' },
  { name: 'accept-encoding', value: 'gzip, deflate, br' },
  { name: 'accept-ranges', value: 'bytes' },
  { name: 'access-control-allow-headers', value: 'cache-control' },
  { name: 'access-control-allow-headers', value: 'content-type' },
  { name: 'access-control-allow-origin', value: '*' },
  { name: 'cache-control', value: 'max-age=0' },
  { name: 'cache-control', value: 'max-age=2592000' },
  { name: 'cache-control', value: 'max-age=604800' },
  { name: 'cache-control', value: 'no-cache' },
  { name: 'cache-control', value: 'no-store' },
  { name: 'cache-control', value: 'public, max-age=31536000' },
  { name: 'content-encoding', value: 'br' },
  { name: 'content-encoding', value: 'gzip' },
  { name: 'content-type', value: 'application/dns-message' },
  { name: 'content-type', value: 'application/javascript' },
  { name: 'content-type', value: 'application/json' },
  { name: 'content-type', value: 'application/x-www-form-urlencoded' },
  { name: 'content-type', value: 'image/gif' },
  { name: 'content-type', value: 'image/jpeg' },
  { name: 'content-type', value: 'image/png' },
  { name: 'content-type', value: 'text/css' },
  { name: 'content-type', value: 'text/html; charset=utf-8' },
  { name: 'content-type', value: 'text/plain' },
  { name: 'content-type', value: 'text/plain;charset=utf-8' },
  { name: 'range', value: 'bytes=0-' },
  { name: 'strict-transport-security', value: 'max-age=31536000' },
  { name: 'strict-transport-security', value: 'max-age=31536000; includesubdomains' },
  { name: 'strict-transport-security', value: 'max-age=31536000; includesubdomains; preload' },
  { name: 'vary', value: 'accept-encoding' },
  { name: 'vary', value: 'origin' },
  { name: 'x-content-type-options', value: 'nosniff' },
  { name: 'x-xss-protection', value: '1; mode=block' },
  { name: ':status', value: '100' },
  { name: ':status', value: '204' },
  { name: ':status', value: '206' },
  { name: ':status', value: '302' },
  { name: ':status', value: '400' },
  { name: ':status', value: '403' },
  { name: ':status', value: '421' },
  { name: ':status', value: '425' },
  { name: ':status', value: '500' },
  { name: 'accept-language', value: '' },
  { name: 'access-control-allow-credentials', value: 'FALSE' },
  { name: 'access-control-allow-credentials', value: 'TRUE' },
  { name: 'access-control-allow-headers', value: '*' },
  { name: 'access-control-allow-methods', value: 'get' },
  { name: 'access-control-allow-methods', value: 'get, post, options' },
  { name: 'access-control-allow-methods', value: 'options' },
  { name: 'access-control-expose-headers', value: 'content-length' },
  { name: 'access-control-request-headers', value: 'content-type' },
  { name: 'access-control-request-method', value: 'get' },
  { name: 'access-control-request-method', value: 'post' },
  { name: 'alt-svc', value: 'clear' },
  { name: 'authorization', value: '' },
  { name: 'content-security-policy', value: "script-src 'none'; object-src 'none'; base-uri 'none'" },
  { name: 'early-data', value: '1' },
  { name: 'expect-ct', value: '' },
  { name: 'forwarded', value: '' },
  { name: 'if-range', value: '' },
  { name: 'origin', value: '' },
  { name: 'purpose', value: 'prefetch' },
  { name: 'server', value: '' },
  { name: 'timing-allow-origin', value: '*' },
  { name: 'upgrade-insecure-requests', value: '1' },
  { name: 'user-agent', value: '' },
  { name: 'x-forwarded-for', value: '' },
  { name: 'x-frame-options', value: 'deny' },
  { name: 'x-frame-options', value: 'sameorigin' },
];

export const QPACK_STATIC_ENTRIES = STATIC_TABLE.length;

export function qpackStaticEntry(index: number): HeaderField | null {
  return index >= 0 && index < STATIC_TABLE.length ? STATIC_TABLE[index] : null;
}

class Reader {
  public position = 0;
  constructor(public readonly bytes: Uint8Array) {}

  public get remaining(): number { return this.bytes.length - this.position; }

  /** The same prefix-coded integer HPACK uses (RFC 7541 §5.1). */
  public integer(prefixBits: number): number | null {
    if (this.remaining < 1) return null;
    const mask = (1 << prefixBits) - 1;
    let value = this.bytes[this.position++] & mask;
    if (value < mask) return value;

    let shift = 0;
    for (;;) {
      if (this.remaining < 1) return null;
      const byte = this.bytes[this.position++];
      value += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) break;
      shift += 7;
      if (shift > 28) return null;
    }
    return value;
  }

  public string(prefixBits: number): string | null {
    if (this.remaining < 1) return null;
    const huffman = (this.bytes[this.position] & (1 << prefixBits)) !== 0;
    const length = this.integer(prefixBits);
    if (length === null || length > this.remaining) return null;
    const raw = this.bytes.subarray(this.position, this.position + length);
    this.position += length;
    return huffman ? huffmanDecode(raw) : new TextDecoder('utf-8', { fatal: false }).decode(raw);
  }
}

export interface QpackResult {
  headers: HeaderField[];
  /** Set when the section referenced dynamic-table state, or was malformed. */
  error?: string;
}

/**
 * Decodes one encoded field section.
 *
 * The prefix is read and discarded except for one thing: a non-zero Required
 * Insert Count means the section depends on the dynamic table, and this
 * decoder does not have it. Saying so once, up front, is more useful than
 * reporting each dynamic reference separately.
 */
export function qpackDecode(section: Uint8Array): QpackResult {
  const reader = new Reader(section);
  const headers: HeaderField[] = [];

  const requiredInsertCount = reader.integer(8);
  if (requiredInsertCount === null) return { headers, error: 'truncated field section prefix' };
  // Delta Base: a sign bit and a seven-bit prefix. Only meaningful with a
  // dynamic table, so it is read to advance the cursor and then dropped.
  if (reader.integer(7) === null) return { headers, error: 'truncated field section prefix' };

  const needsDynamic = requiredInsertCount !== 0;

  while (reader.remaining > 0) {
    const first = reader.bytes[reader.position];

    if ((first & 0x80) !== 0) {
      // Indexed Field Line. The T bit says static (1) or dynamic (0).
      const isStatic = (first & 0x40) !== 0;
      const index = reader.integer(6);
      if (index === null) return { headers, error: 'malformed indexed field line' };
      if (!isStatic) return { headers, error: qpackDynamicNote(needsDynamic) };
      const entry = qpackStaticEntry(index);
      if (entry === null) return { headers, error: `static index ${index} does not exist` };
      headers.push(entry);
      continue;
    }

    if ((first & 0x40) !== 0) {
      // Literal Field Line with Name Reference: 0 1 N T index(4+).
      const isStatic = (first & 0x10) !== 0;
      const index = reader.integer(4);
      if (index === null) return { headers, error: 'malformed literal field line' };
      if (!isStatic) return { headers, error: qpackDynamicNote(needsDynamic) };
      const entry = qpackStaticEntry(index);
      if (entry === null) return { headers, error: `static index ${index} does not exist` };
      const value = reader.string(7);
      if (value === null) return { headers, error: 'undecodable header value' };
      headers.push({ name: entry.name, value });
      continue;
    }

    if ((first & 0x20) !== 0) {
      // Literal Field Line with Literal Name: 0 0 1 N H namelen(3+).
      const name = reader.string(3);
      if (name === null) return { headers, error: 'undecodable header name' };
      const value = reader.string(7);
      if (value === null) return { headers, error: 'undecodable header value' };
      headers.push({ name, value });
      continue;
    }

    // The remaining two forms - indexed and literal with a post-base index -
    // both name the dynamic table, so neither is resolvable here.
    return { headers, error: qpackDynamicNote(needsDynamic) };
  }

  return { headers };
}

function qpackDynamicNote(needsDynamic: boolean): string {
  return needsDynamic
    ? "this field section indexes QPACK's dynamic table, which is filled by a separate stream"
    : 'a dynamic table reference appeared in a section whose prefix said there was none';
}
