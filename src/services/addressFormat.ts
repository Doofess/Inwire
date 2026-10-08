/**
 * Address rendering shared by the core dissection pass and the per-protocol
 * dissectors. Lives in its own module so `dissectors/*` can use it without
 * importing pcapParser, which imports them back.
 */

/**
 * Parses a dotted-quad into a 32-bit unsigned integer, or null if it isn't
 * four in-range octets.
 */
export function parseIpv4(text: string): number | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value * 256) + octet;
  }
  return value >>> 0;
}

/**
 * Parses an IPv6 address in any RFC 4291 textual form - including the "::"
 * zero-run shorthand and a trailing embedded IPv4 - into its 16 bytes.
 * Returns null when the text isn't a valid address.
 */
export function parseIpv6(text: string): Uint8Array | null {
  let input = text.trim().toLowerCase();
  if (input.includes('%')) input = input.slice(0, input.indexOf('%')); // strip zone id

  // A trailing dotted-quad (e.g. "::ffff:192.0.2.1") becomes two hex groups.
  const lastColon = input.lastIndexOf(':');
  if (input.includes('.')) {
    const v4 = parseIpv4(input.slice(lastColon + 1));
    if (v4 === null) return null;
    input = `${input.slice(0, lastColon + 1)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }

  const doubleColon = input.indexOf('::');
  if (doubleColon !== -1 && input.indexOf('::', doubleColon + 1) !== -1) return null;

  const headText = doubleColon === -1 ? input : input.slice(0, doubleColon);
  const tailText = doubleColon === -1 ? '' : input.slice(doubleColon + 2);
  const head = headText ? headText.split(':') : [];
  const tail = tailText ? tailText.split(':') : [];

  if (doubleColon === -1 && head.length !== 8) return null;
  if (head.length + tail.length > 8) return null;

  const groups: number[] = [];
  for (const group of head) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    groups.push(parseInt(group, 16));
  }
  for (let i = head.length + tail.length; i < 8; i++) groups.push(0);
  for (const group of tail) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    groups.push(parseInt(group, 16));
  }

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = groups[i] >> 8;
    bytes[i * 2 + 1] = groups[i] & 0xff;
  }
  return bytes;
}

/**
 * True when `address` falls inside `cidr` ("224.0.0.0/4", "ff00::/8").
 * Handles both families; a family mismatch is simply not a match.
 */
export function addressInCidr(address: string, cidr: string): boolean {
  const slash = cidr.lastIndexOf('/');
  if (slash === -1) return false;
  const network = cidr.slice(0, slash);
  const prefixLength = Number(cidr.slice(slash + 1));
  if (!Number.isInteger(prefixLength) || prefixLength < 0) return false;

  if (network.includes(':')) {
    const addressBytes = parseIpv6(address);
    const networkBytes = parseIpv6(network);
    if (!addressBytes || !networkBytes || prefixLength > 128) return false;
    for (let bit = 0; bit < prefixLength; bit += 8) {
      const byte = bit >> 3;
      const bitsHere = Math.min(8, prefixLength - bit);
      const mask = (0xff << (8 - bitsHere)) & 0xff;
      if ((addressBytes[byte] & mask) !== (networkBytes[byte] & mask)) return false;
    }
    return true;
  }

  const addressValue = parseIpv4(address);
  const networkValue = parseIpv4(network);
  if (addressValue === null || networkValue === null || prefixLength > 32) return false;
  // A /0 must not shift by 32, which in JS is a no-op rather than a zero mask.
  const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;
  return (addressValue & mask) === (networkValue & mask);
}

/** Formats 6 bytes as a lowercase colon-separated MAC address. */
/**
 * One string per distinct address, shared by every frame carrying it.
 *
 * These three functions build a fresh string per frame, and a capture talks to
 * a handful of addresses - so a million frames held a million copies of a few
 * dozen strings. Measured over the inwire fixture: 434 distinct string values
 * across every `Packet.fields` bag in the capture, and pooling them frees 82 B a
 * frame - 82 MB at a million (`scripts/perf/fields-cost.ts`,
 * `docs/decisions/0013`).
 *
 * The formatting still happens; only the result is shared. Memoising on the
 * *input* would need a key built from the bytes, which costs about what
 * formatting them costs - so this pools on the way out instead.
 *
 * Bounded, because a capture can legitimately see a great many addresses (a
 * scan, a busy transit link) and an unbounded pool would then be the leak it
 * exists to prevent. Past the cap it stops admitting new strings rather than
 * evicting: the entries already in it are the ones being asked for repeatedly.
 */
const addressPool = new Map<string, string>();
const ADDRESS_POOL_MAX = 65536;

function pooled(text: string): string {
  const existing = addressPool.get(text);
  if (existing !== undefined) return existing;
  if (addressPool.size < ADDRESS_POOL_MAX) addressPool.set(text, text);
  return text;
}

/** Forgets every pooled address. For a capture ending, and for tests. */
export function clearAddressPool(): void {
  addressPool.clear();
}

/**
 * Bytes as lowercase hex, no separator.
 *
 * There were six of these: an exported one in `tls/keyLog.ts`, private copies
 * in `lldp.ts` and `quic.ts`, a differently-named `hexOf` in `tls.ts`, and two
 * more written inline in `dhcp.ts` and `ipv4.ts`. All six produced identical
 * output by three different routes.
 *
 * This is the index-loop form rather than `Array.from(...).map(...).join('')`,
 * which was the commonest of the three: it allocates neither the intermediate
 * array nor the array of strings, and some of these callers run per frame.
 */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/** `00`..`ff`, built once: a MAC is formatted twice a frame. */
const HEX_BYTE: readonly string[] = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

/**
 * Bytes as colon-separated lowercase hex - `aa:bb:cc:dd:ee:ff` for a MAC.
 *
 * A table and a concatenation. It was `Array.from(...).map(toString(16)
 * .padStart).join(':')`, which `docs/decisions/0044` left alone because the
 * fixtures put it at 7-13 ms; on a 36,000 frame-a-second download it was 3.2%
 * of dissection with an array allocated per call, twice a frame.
 */
export function formatMac(bytes: Uint8Array): string {
  if (bytes.length === 0) return pooled('');
  let out = HEX_BYTE[bytes[0]];
  for (let i = 1; i < bytes.length; i++) out += ':' + HEX_BYTE[bytes[i]];
  return pooled(out);
}

/** The six bytes at `at` as a MAC, read in place rather than from a copy. */
export function formatMacAt(bytes: Uint8Array, at: number): string {
  return pooled(HEX_BYTE[bytes[at]] + ':' + HEX_BYTE[bytes[at + 1]] + ':' + HEX_BYTE[bytes[at + 2]]
    + ':' + HEX_BYTE[bytes[at + 3]] + ':' + HEX_BYTE[bytes[at + 4]] + ':' + HEX_BYTE[bytes[at + 5]]);
}

/** Formats 4 bytes at `offset` as dotted-quad IPv4. */
export function formatIpv4Address(bytes: Uint8Array, offset: number): string {
  return pooled(`${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`);
}

/**
 * Formats a 16-byte IPv6 address (starting at `offset` within `bytes`) in the
 * RFC 5952 canonical form the reference analyzer displays: leading zeros stripped from each
 * group, lowercase hex, and the *longest* run of two or more all-zero groups
 * collapsed to "::" (leftmost run wins a tie, and a single zero group is never
 * collapsed - "2001:db8:0:1:1:1:1:1" stays as-is).
 *
 * Without this an address renders as 39 characters of zero-padded groups,
 * which both diverges from the reference analyzer and overflows the address column.
 */
export function formatIpv6Address(bytes: Uint8Array, offset: number): string {
  const groups: number[] = [];
  for (let i = 0; i < 8; i++) {
    groups.push((bytes[offset + i * 2] << 8) | bytes[offset + i * 2 + 1]);
  }

  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && groups[i] === 0) {
      if (runStart === -1) runStart = i;
    } else if (runStart !== -1) {
      const runLen = i - runStart;
      // Strictly greater keeps the leftmost run when two are the same length.
      if (runLen > bestLen) {
        bestStart = runStart;
        bestLen = runLen;
      }
      runStart = -1;
    }
  }

  // An IPv4-mapped (`::ffff:`) or IPv4-compatible (`::`) address keeps its
  // IPv4 half dotted, as inet_ntop writes it - but only when that half's top
  // 16 bits are not zero, which is the reference's own condition: `::ffff:0:1`
  // and `::1` stay hex, `::ffff:10.0.0.0` and `::1.2.3.4` do not.
  if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0
    && (groups[5] === 0 || groups[5] === 0xffff) && groups[6] !== 0) {
    const v4 = `${bytes[offset + 12]}.${bytes[offset + 13]}.${bytes[offset + 14]}.${bytes[offset + 15]}`;
    return pooled(groups[5] === 0xffff ? `::ffff:${v4}` : `::${v4}`);
  }

  const hex = groups.map(g => g.toString(16));
  if (bestLen < 2) return pooled(hex.join(':'));

  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLen).join(':');
  return pooled(`${head}::${tail}`);
}
