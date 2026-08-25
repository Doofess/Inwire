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
export function formatMac(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(':');
}

/** Formats 4 bytes at `offset` as dotted-quad IPv4. */
export function formatIpv4Address(bytes: Uint8Array, offset: number): string {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

/**
 * Formats a 16-byte IPv6 address (starting at `offset` within `bytes`) in the
 * RFC 5952 canonical form Wireshark displays: leading zeros stripped from each
 * group, lowercase hex, and the *longest* run of two or more all-zero groups
 * collapsed to "::" (leftmost run wins a tie, and a single zero group is never
 * collapsed - "2001:db8:0:1:1:1:1:1" stays as-is).
 *
 * Without this an address renders as 39 characters of zero-padded groups,
 * which both diverges from Wireshark and overflows the address column.
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

  const hex = groups.map(g => g.toString(16));
  if (bestLen < 2) return hex.join(':');

  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}
