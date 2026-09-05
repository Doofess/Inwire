/**
 * HPACK (RFC 7541), the header compression HTTP/2 uses.
 *
 * HPACK is stateful in a way that matters for a packet analyzer: a HEADERS
 * frame is not self-describing. It may say only "index 62", meaning the header
 * a *previous* frame on this connection inserted into the dynamic table, so a
 * decoder that starts in the middle of a connection cannot read even one
 * header, and one that skips a frame is wrong from that point on rather than
 * for that frame alone. Both directions carry their own table.
 *
 * That is why the compression state lives with the connection (in the TCP
 * tracker, beside the TLS record cursor) and not with the frame, and why a
 * capture that began mid-connection reports "HPACK state not available"
 * instead of showing header names it inferred.
 *
 * The Huffman code (Appendix B) is canonical, so only the 257 code *lengths*
 * are written out here and the codes themselves are derived. That is not a
 * space saving - it is a correctness one: a transcription error in the lengths
 * breaks Kraft's equality, which the assertion script checks, whereas an error
 * in a table of hand-copied codes is invisible until some rare byte sequence
 * decodes to the wrong text.
 */

/**
 * One decoder, not one per call. `new TextDecoder()` is not free and these
 * sites are per-header - a CPU profile put TextDecoder construction at 8% of a
 * dissection run. It carries no state across `decode()` calls unless
 * `{stream: true}` is used, which nothing here does.
 */
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

/** Code length per symbol, 0-255 plus EOS at 256 (RFC 7541 Appendix B). */
const HUFFMAN_LENGTHS = [
  13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
  28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
  6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
  5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
  13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
  15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
  6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
  20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
  24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
  22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
  21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
  26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
  19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
  20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
  26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
  30,
];

const EOS_SYMBOL = 256;
const MAX_CODE_BITS = 30;

/** Canonical decode tables: for each code length, its first code and the symbols in order. */
const firstCode = new Array<number>(MAX_CODE_BITS + 1).fill(0);
const symbolsByLength: number[][] = Array.from({ length: MAX_CODE_BITS + 1 }, () => []);

(() => {
  const order = HUFFMAN_LENGTHS
    .map((length, symbol) => ({ length, symbol }))
    .sort((a, b) => a.length - b.length || a.symbol - b.symbol);

  let code = 0;
  let previousLength = order[0].length;
  for (const { length, symbol } of order) {
    // Canonical assignment: codes run consecutively within a length, and each
    // step up in length shifts the running code left by the difference.
    code *= 2 ** (length - previousLength);
    if (symbolsByLength[length].length === 0) firstCode[length] = code;
    symbolsByLength[length].push(symbol);
    previousLength = length;
    code += 1;
  }
})();

/**
 * Decodes an HPACK Huffman string. Returns null on a malformed one - a code
 * that is not in the table, an EOS symbol (which RFC 7541 §5.2 forbids in a
 * literal), or padding that is not all ones.
 */
export function huffmanDecode(bytes: Uint8Array): string | null {
  const out: number[] = [];
  let code = 0;
  let length = 0;

  for (let i = 0; i < bytes.length; i++) {
    for (let bit = 7; bit >= 0; bit--) {
      code = code * 2 + ((bytes[i] >> bit) & 1);
      length++;
      if (length > MAX_CODE_BITS) return null;

      const symbols = symbolsByLength[length];
      if (symbols.length === 0) continue;
      const index = code - firstCode[length];
      if (index < 0 || index >= symbols.length) continue;

      const symbol = symbols[index];
      if (symbol === EOS_SYMBOL) return null;
      out.push(symbol);
      code = 0;
      length = 0;
    }
  }

  // Whatever is left must be fewer than eight bits of the EOS code, which is
  // all ones. Anything else means the string was truncated or corrupt.
  if (length >= 8) return null;
  if (length > 0 && code !== 2 ** length - 1) return null;

  return utf8Decoder.decode(Uint8Array.from(out));
}

// --- the tables --------------------------------------------------------------

export interface HeaderField { name: string; value: string }

/** RFC 7541 Appendix A. Index 0 is unused so the array indexes as the spec numbers. */
const STATIC_TABLE: HeaderField[] = [
  { name: '', value: '' },
  { name: ':authority', value: '' },
  { name: ':method', value: 'GET' },
  { name: ':method', value: 'POST' },
  { name: ':path', value: '/' },
  { name: ':path', value: '/index.html' },
  { name: ':scheme', value: 'http' },
  { name: ':scheme', value: 'https' },
  { name: ':status', value: '200' },
  { name: ':status', value: '204' },
  { name: ':status', value: '206' },
  { name: ':status', value: '304' },
  { name: ':status', value: '400' },
  { name: ':status', value: '404' },
  { name: ':status', value: '500' },
  { name: 'accept-charset', value: '' },
  { name: 'accept-encoding', value: 'gzip, deflate' },
  { name: 'accept-language', value: '' },
  { name: 'accept-ranges', value: '' },
  { name: 'accept', value: '' },
  { name: 'access-control-allow-origin', value: '' },
  { name: 'age', value: '' },
  { name: 'allow', value: '' },
  { name: 'authorization', value: '' },
  { name: 'cache-control', value: '' },
  { name: 'content-disposition', value: '' },
  { name: 'content-encoding', value: '' },
  { name: 'content-language', value: '' },
  { name: 'content-length', value: '' },
  { name: 'content-location', value: '' },
  { name: 'content-range', value: '' },
  { name: 'content-type', value: '' },
  { name: 'cookie', value: '' },
  { name: 'date', value: '' },
  { name: 'etag', value: '' },
  { name: 'expect', value: '' },
  { name: 'expires', value: '' },
  { name: 'from', value: '' },
  { name: 'host', value: '' },
  { name: 'if-match', value: '' },
  { name: 'if-modified-since', value: '' },
  { name: 'if-none-match', value: '' },
  { name: 'if-range', value: '' },
  { name: 'if-unmodified-since', value: '' },
  { name: 'last-modified', value: '' },
  { name: 'link', value: '' },
  { name: 'location', value: '' },
  { name: 'max-forwards', value: '' },
  { name: 'proxy-authenticate', value: '' },
  { name: 'proxy-authorization', value: '' },
  { name: 'range', value: '' },
  { name: 'referer', value: '' },
  { name: 'refresh', value: '' },
  { name: 'retry-after', value: '' },
  { name: 'server', value: '' },
  { name: 'set-cookie', value: '' },
  { name: 'strict-transport-security', value: '' },
  { name: 'transfer-encoding', value: '' },
  { name: 'user-agent', value: '' },
  { name: 'vary', value: '' },
  { name: 'via', value: '' },
  { name: 'www-authenticate', value: '' },
];

const STATIC_ENTRIES = STATIC_TABLE.length - 1;
const DEFAULT_TABLE_SIZE = 4096;
/** RFC 7541 §4.1: every entry is charged 32 bytes of bookkeeping on top of its text. */
const ENTRY_OVERHEAD = 32;

/**
 * One direction's dynamic table.
 *
 * Newest first, which is what makes the index of an existing entry change
 * every time another is inserted - and why this cannot be reconstructed from a
 * single frame.
 */
export class HpackTable {
  private entries: HeaderField[] = [];
  private size = 0;
  private maxSize = DEFAULT_TABLE_SIZE;
  /**
   * True once a frame has referenced an index this table could not resolve.
   * From then on every header is suspect, so the dissector says so rather than
   * showing a plausible name it guessed.
   */
  public desynchronised = false;

  public setMaxSize(size: number): void {
    this.maxSize = size;
    this.evict();
  }

  public insert(field: HeaderField): void {
    const cost = field.name.length + field.value.length + ENTRY_OVERHEAD;
    // An entry larger than the whole table empties it and is not stored - the
    // spec's rule, and not an error.
    if (cost > this.maxSize) { this.entries = []; this.size = 0; return; }
    this.entries.unshift(field);
    this.size += cost;
    this.evict();
  }

  private evict(): void {
    while (this.size > this.maxSize && this.entries.length > 0) {
      const last = this.entries.pop()!;
      this.size -= last.name.length + last.value.length + ENTRY_OVERHEAD;
    }
  }

  public lookup(index: number): HeaderField | null {
    if (index >= 1 && index <= STATIC_ENTRIES) return STATIC_TABLE[index];
    const dynamic = index - STATIC_ENTRIES - 1;
    if (dynamic >= 0 && dynamic < this.entries.length) return this.entries[dynamic];
    this.desynchronised = true;
    return null;
  }

  public get count(): number { return this.entries.length; }
  public get bytes(): number { return this.size; }
}

// --- the decoder --------------------------------------------------------------

class Reader {
  public position = 0;
  constructor(public readonly bytes: Uint8Array) {}

  public get remaining(): number { return this.bytes.length - this.position; }

  /**
   * RFC 7541 §5.1: an integer in a prefix of `prefixBits`, continued in
   * seven-bit groups when the prefix is all ones.
   */
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
      // Nothing legitimate needs more than this, and an unbounded loop on a
      // corrupt stream is how a dissector hangs a tab.
      if (shift > 28) return null;
    }
    return value;
  }

  public string(): string | null {
    if (this.remaining < 1) return null;
    const huffman = (this.bytes[this.position] & 0x80) !== 0;
    const length = this.integer(7);
    if (length === null || length > this.remaining) return null;
    const raw = this.bytes.subarray(this.position, this.position + length);
    this.position += length;
    return huffman ? huffmanDecode(raw) : utf8Decoder.decode(raw);
  }
}

export interface HpackResult {
  headers: HeaderField[];
  /** Set when the block referenced state this decoder does not have, or was malformed. */
  error?: string;
}

/**
 * Decodes one header block against a direction's table, updating it.
 *
 * The update is the point: skipping this call for a frame the user never
 * selected would desynchronise every later frame on the connection, so it runs
 * in the summary pass like the TLS record cursor does.
 */
export function hpackDecode(block: Uint8Array, table: HpackTable): HpackResult {
  const reader = new Reader(block);
  const headers: HeaderField[] = [];

  while (reader.remaining > 0) {
    const first = reader.bytes[reader.position];

    if ((first & 0x80) !== 0) {
      // Indexed header field: the whole thing is one table reference.
      const index = reader.integer(7);
      if (index === null || index === 0) return { headers, error: 'malformed indexed header' };
      const entry = table.lookup(index);
      if (entry === null) return { headers, error: `index ${index} is not in this connection's HPACK table` };
      headers.push(entry);
      continue;
    }

    let prefixBits: 6 | 4 | 5;
    let indexed = false;
    if ((first & 0x40) !== 0) { prefixBits = 6; indexed = true; }
    else if ((first & 0x20) !== 0) {
      // Dynamic table size update, not a header at all.
      const size = reader.integer(5);
      if (size === null) return { headers, error: 'malformed table size update' };
      table.setMaxSize(size);
      continue;
    } else prefixBits = 4;

    const nameIndex = reader.integer(prefixBits);
    if (nameIndex === null) return { headers, error: 'truncated header block' };

    let name: string | null;
    if (nameIndex === 0) {
      name = reader.string();
    } else {
      const entry = table.lookup(nameIndex);
      if (entry === null) return { headers, error: `index ${nameIndex} is not in this connection's HPACK table` };
      name = entry.name;
    }
    if (name === null) return { headers, error: 'undecodable header name' };

    const value = reader.string();
    if (value === null) return { headers, error: 'undecodable header value' };

    const field = { name, value };
    headers.push(field);
    if (indexed) table.insert(field);
  }

  return { headers };
}
