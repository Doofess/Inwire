/**
 * Address rendering shared by the core dissection pass and the per-protocol
 * dissectors. Lives in its own module so `dissectors/*` can use it without
 * importing pcapParser, which imports them back.
 */

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
