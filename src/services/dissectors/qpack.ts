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
 * The dynamic table IS tracked, per connection and per direction, by reading
 * the encoder stream (`qpackReadEncoderStream`). What it cannot do is invent
 * state it never saw: a capture that began mid-connection, or one missing the
 * datagram that carried an insertion, leaves entries this decoder does not
 * have. Those are still reported as unresolvable rather than guessed at, for
 * the reason the HPACK decoder gives - a header name invented by a decoder is
 * worse than one it admits it does not have.
 *
 * Two index spaces, and confusing them is the whole hazard here. Entries have
 * an *absolute* index that never changes and never repeats. Everything on the
 * wire is *relative*: to the insert count on the encoder stream, and to the
 * section's own Base inside a field section - where an index may also run
 * forwards from the Base ("post-base") because a section is allowed to
 * reference entries inserted after it was encoded. Getting the arithmetic
 * wrong does not throw; it returns a real header with the wrong name.
 */
import { huffmanDecode, type HeaderField } from './hpack';

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
    return huffman ? huffmanDecode(raw) : utf8Decoder.decode(raw);
  }
}

/** RFC 9204 §3.2.1: an entry costs its two strings plus a flat 32. */
const ENTRY_OVERHEAD = 32;

/**
 * One direction's QPACK dynamic table.
 *
 * Unlike HPACK's, this is filled by a *separate* unidirectional stream rather
 * than by the header blocks themselves - so it is held per connection and per
 * direction, and a field section can legitimately reference an entry whose
 * insertion has not arrived yet.
 *
 * Entries are kept oldest-first with `dropped` counting those evicted, because
 * the wire's absolute index is a count of every insertion ever made. Storing
 * them newest-first the way `HpackTable` does would mean recomputing an offset
 * on every lookup against a number that changes on every insert.
 */
export class QpackTable {
  private entries: HeaderField[] = [];
  /** Insertions evicted; `dropped + entries.length` is the insert count. */
  private dropped = 0;
  private size = 0;
  private capacity = 0;
  /**
   * The largest capacity the encoder ever set, which is what `MaxEntries` in
   * the Required Insert Count decoding is defined against - not the current
   * capacity, which an encoder may lower at any time.
   */
  private maxCapacitySeen = 0;
  /** True once a lookup failed, so the caller can say so rather than guess. */
  public desynchronised = false;

  /** Insertions made so far. The next entry's absolute index. */
  public get insertCount(): number { return this.dropped + this.entries.length; }

  public setCapacity(capacity: number): void {
    this.capacity = capacity;
    if (capacity > this.maxCapacitySeen) this.maxCapacitySeen = capacity;
    this.evict();
  }

  public get maxEntries(): number { return Math.floor(this.maxCapacitySeen / ENTRY_OVERHEAD); }

  public insert(field: HeaderField): void {
    const cost = field.name.length + field.value.length + ENTRY_OVERHEAD;
    // An entry too large for the table empties it and is not stored. RFC 9204
    // §3.2.2 - the spec's rule, not an error.
    if (cost > this.capacity) {
      this.dropped += this.entries.length;
      this.entries = [];
      this.size = 0;
      return;
    }
    this.entries.push(field);
    this.size += cost;
    this.evict();
  }

  private evict(): void {
    while (this.size > this.capacity && this.entries.length > 0) {
      const oldest = this.entries.shift()!;
      this.size -= oldest.name.length + oldest.value.length + ENTRY_OVERHEAD;
      this.dropped++;
    }
  }

  /** By absolute index - the count of insertions before this one. */
  public absolute(index: number): HeaderField | null {
    const at = index - this.dropped;
    if (at < 0 || at >= this.entries.length) { this.desynchronised = true; return null; }
    return this.entries[at];
  }

  public get count(): number { return this.entries.length; }
  public get bytes(): number { return this.size; }
}

export interface QpackEncoderStreamResult {
  /** Insertions this call made, for the tree to show. */
  inserted: HeaderField[];
  /** Set when an instruction could not be read; the stream is then unusable. */
  error?: string;
}

/**
 * Applies one direction's encoder-stream bytes to its table (RFC 9204 §4.3).
 *
 * Four instructions, distinguished by a prefix of the first byte. The two that
 * name an existing entry use an index *relative to the current insert count*,
 * newest first - so absolute = insertCount - 1 - relative, computed before the
 * insertion this instruction is about to make.
 *
 * Returns the number of bytes consumed in `used`: the caller keeps the rest,
 * because an instruction may be split across QUIC datagrams and half of one is
 * not an error.
 */
export function qpackReadEncoderStream(
  bytes: Uint8Array, table: QpackTable
): QpackEncoderStreamResult & { used: number } {
  const reader = new Reader(bytes);
  const inserted: HeaderField[] = [];

  while (reader.remaining > 0) {
    const start = reader.position;
    const first = reader.bytes[reader.position];

    if ((first & 0x80) !== 0) {
      // Insert With Name Reference: 1 T index(6+) then the value.
      const isStatic = (first & 0x40) !== 0;
      const index = reader.integer(6);
      if (index === null) return { inserted, used: start };
      const entry = isStatic ? qpackStaticEntry(index) : table.absolute(table.insertCount - 1 - index);
      const value = reader.string(7);
      if (value === null) return { inserted, used: start };
      if (entry === null) {
        // The name is genuinely unknown, and inserting a placeholder would put
        // every later absolute index one out. Insert it unnamed so the count
        // stays right, and let the lookup report it.
        table.insert({ name: '', value });
        inserted.push({ name: '', value });
        continue;
      }
      table.insert({ name: entry.name, value });
      inserted.push({ name: entry.name, value });
      continue;
    }

    if ((first & 0x40) !== 0) {
      // Insert With Literal Name: 0 1 H namelen(5+) then the value.
      const name = reader.string(5);
      if (name === null) return { inserted, used: start };
      const value = reader.string(7);
      if (value === null) return { inserted, used: start };
      table.insert({ name, value });
      inserted.push({ name, value });
      continue;
    }

    if ((first & 0x20) !== 0) {
      // Set Dynamic Table Capacity: 0 0 1 capacity(5+).
      const capacity = reader.integer(5);
      if (capacity === null) return { inserted, used: start };
      table.setCapacity(capacity);
      continue;
    }

    // Duplicate: 0 0 0 index(5+), relative to the insert count as above.
    const index = reader.integer(5);
    if (index === null) return { inserted, used: start };
    const entry = table.absolute(table.insertCount - 1 - index);
    if (entry === null) return { inserted, used: reader.position, error: 'duplicate of an entry this capture does not have' };
    table.insert(entry);
    inserted.push(entry);
  }

  return { inserted, used: reader.position };
}

export interface QpackResult {
  headers: HeaderField[];
  /** Set when the section referenced dynamic-table state, or was malformed. */
  error?: string;
}

/**
 * Recovers the Required Insert Count from its encoded form (RFC 9204 §4.5.1.1).
 *
 * It is sent modulo a window so it stays small, and unwrapping it needs the
 * table's own insert count - which is why this cannot be done without the
 * encoder stream. The formulas are the RFC's, kept in its variable names on
 * purpose: every one of them is off-by-one-shaped, and a version rewritten to
 * read more naturally is a version nobody can check against the document.
 */
function decodeRequiredInsertCount(
  encoded: number, totalInserts: number, maxEntries: number
): number | null {
  if (encoded === 0) return 0;
  if (maxEntries === 0) return null;
  const fullRange = 2 * maxEntries;
  if (encoded > fullRange) return null;
  const maxValue = totalInserts + maxEntries;
  const maxWrapped = Math.floor(maxValue / fullRange) * fullRange;
  let count = maxWrapped + encoded - 1;
  if (count > maxValue) {
    if (count <= fullRange) return null;
    count -= fullRange;
  }
  return count === 0 ? null : count;
}

/**
 * Decodes one encoded field section.
 *
 * With no table, or one that has not yet been filled far enough, a dynamic
 * reference is reported rather than guessed - the headers decoded up to that
 * point are still returned, because a partial answer with a note beats none.
 */
export function qpackDecode(section: Uint8Array, table?: QpackTable): QpackResult {
  const reader = new Reader(section);
  const headers: HeaderField[] = [];

  const encodedInsertCount = reader.integer(8);
  if (encodedInsertCount === null) return { headers, error: 'truncated field section prefix' };

  // Delta Base: a sign bit then a seven-bit prefix.
  if (reader.remaining < 1) return { headers, error: 'truncated field section prefix' };
  const negative = (reader.bytes[reader.position] & 0x80) !== 0;
  const deltaBase = reader.integer(7);
  if (deltaBase === null) return { headers, error: 'truncated field section prefix' };

  const needsDynamic = encodedInsertCount !== 0;

  // Base is where this section's relative indices are measured from. A section
  // encoded before an insertion it does not use has a Base below the insert
  // count, which is what the sign bit is for.
  let base = 0;
  let resolved = false;
  if (table !== undefined) {
    const required = decodeRequiredInsertCount(encodedInsertCount, table.insertCount, table.maxEntries);
    if (required !== null) {
      base = negative ? required - deltaBase - 1 : required + deltaBase;
      resolved = true;
    }
  }

  /** Absolute index, or null with the reason already decided. */
  const dynamicAt = (absolute: number): HeaderField | null =>
    table === undefined || !resolved ? null : table.absolute(absolute);

  while (reader.remaining > 0) {
    const first = reader.bytes[reader.position];

    if ((first & 0x80) !== 0) {
      // Indexed Field Line. The T bit says static (1) or dynamic (0).
      const isStatic = (first & 0x40) !== 0;
      const index = reader.integer(6);
      if (index === null) return { headers, error: 'malformed indexed field line' };
      const entry = isStatic ? qpackStaticEntry(index) : dynamicAt(base - index - 1);
      if (entry === null) {
        return { headers, error: isStatic ? `static index ${index} does not exist` : qpackDynamicNote(needsDynamic) };
      }
      headers.push(entry);
      continue;
    }

    if ((first & 0x40) !== 0) {
      // Literal Field Line with Name Reference: 0 1 N T index(4+).
      const isStatic = (first & 0x10) !== 0;
      const index = reader.integer(4);
      if (index === null) return { headers, error: 'malformed literal field line' };
      const entry = isStatic ? qpackStaticEntry(index) : dynamicAt(base - index - 1);
      if (entry === null) {
        return { headers, error: isStatic ? `static index ${index} does not exist` : qpackDynamicNote(needsDynamic) };
      }
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

    // The two post-base forms. Their indices run *forwards* from the Base
    // rather than backwards, because a section may reference entries inserted
    // after it was encoded.
    if ((first & 0x10) !== 0) {
      // Indexed Field Line With Post-Base Index: 0 0 0 1 index(4+).
      const index = reader.integer(4);
      if (index === null) return { headers, error: 'malformed post-base indexed field line' };
      const entry = dynamicAt(base + index);
      if (entry === null) return { headers, error: qpackDynamicNote(needsDynamic) };
      headers.push(entry);
      continue;
    }

    // Literal Field Line With Post-Base Name Reference: 0 0 0 0 N index(3+).
    const index = reader.integer(3);
    if (index === null) return { headers, error: 'malformed post-base literal field line' };
    const entry = dynamicAt(base + index);
    if (entry === null) return { headers, error: qpackDynamicNote(needsDynamic) };
    const value = reader.string(7);
    if (value === null) return { headers, error: 'undecodable header value' };
    headers.push({ name: entry.name, value });
  }

  return { headers };
}

function qpackDynamicNote(needsDynamic: boolean): string {
  return needsDynamic
    ? "this field section indexes QPACK's dynamic table, which is filled by a separate stream"
    : 'a dynamic table reference appeared in a section whose prefix said there was none';
}
