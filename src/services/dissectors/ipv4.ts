/**
 * The parts of the IPv4 header that were being read but not explained.
 *
 * Three gaps, all of the same kind - the bytes were parsed correctly and then
 * shown as raw numbers, which is a decode that stops one step short of being
 * useful:
 *
 *   * **DSCP and ECN** were printed as the integers 46 and 2. IPv6 has named
 *     them since Phase 6's first half; IPv4 had not, so the same traffic read
 *     differently depending on which version carried it.
 *   * **Options** were skipped entirely. `ip.hdr_len` was used to find the
 *     transport header and the bytes in between - Router Alert, Record Route,
 *     Timestamp - were never looked at. Every IGMP report on a normal network
 *     carries a Router Alert option, so this is not an exotic case.
 *   * **TTL** was a number with no context. A TTL of 57 means nothing on its
 *     own and means "seven hops away, from a host that starts at 64" the
 *     moment you know what initial values are used in practice.
 */
import type { ProtocolField } from '../../types/packet';

/** Wireshark's `dscp_vals`. */
const DSCP_NAMES: Record<number, string> = {
  0: 'CS0', 8: 'CS1', 10: 'AF11', 12: 'AF12', 14: 'AF13',
  16: 'CS2', 18: 'AF21', 20: 'AF22', 22: 'AF23',
  24: 'CS3', 26: 'AF31', 28: 'AF32', 30: 'AF33',
  32: 'CS4', 34: 'AF41', 36: 'AF42', 38: 'AF43',
  40: 'CS5', 44: 'Voice-Admit', 46: 'EF PHB',
  48: 'CS6', 56: 'CS7',
};

const ECN_NAMES = ['Not-ECT', 'ECT(1)', 'ECT(0)', 'CE'] as const;

export function dscpName(dscp: number): string {
  return DSCP_NAMES[dscp] ?? `Unknown (${dscp})`;
}

export function ecnName(ecn: number): string {
  return ECN_NAMES[ecn & 0x3];
}

/**
 * The initial TTL a packet was probably sent with, and how far it has come.
 *
 * Stacks pick one of a small set of initial values - 255 on routers and most
 * BSD-derived stacks, 128 on Windows, 64 nearly everywhere else, 32 on some
 * old embedded stacks - and every hop decrements by one. Rounding up to the
 * next of those recovers both numbers, and a distance in hops is a far more
 * useful thing to see beside an address than the raw counter is.
 *
 * It is a guess, and it is labelled as one: a host really can be configured
 * with any initial value, and a packet that crossed more than 32 hops below
 * the next boundary is indistinguishable from one that started lower. Both
 * rows are `generated`, which is how the tree already marks what it worked out
 * rather than read.
 */
export function inferTtl(ttl: number): { initial: number; hops: number } | null {
  if (ttl <= 0 || ttl > 255) return null;
  for (const initial of [32, 64, 128, 255]) {
    if (ttl <= initial) return { initial, hops: initial - ttl };
  }
  return null;
}

/** IPv4 option numbers, by the low five bits of the type byte. */
const OPTION_NAMES: Record<number, string> = {
  0: 'End of Option List (EOL)',
  1: 'No-Operation (NOP)',
  2: 'Security',
  3: 'Loose Source Route',
  4: 'Time Stamp',
  5: 'Extended Security',
  7: 'Record Route',
  8: 'Stream Identifier',
  9: 'Strict Source Route',
  11: 'MTU Probe',
  12: 'MTU Reply',
  18: 'Traceroute',
  20: 'Router Alert',
  25: 'Quick-Start',
};

const ROUTER_ALERT_VALUES: Record<number, string> = {
  0: 'Router shall examine packet',
};

const TIMESTAMP_FLAGS: Record<number, string> = {
  0: 'Time stamps only, in consecutive 32-bit words',
  1: 'Time stamp and address of registering entity',
  3: 'Time stamps prespecified for registering entities',
};

function ipv4At(bytes: Uint8Array, at: number): string {
  return `${bytes[at]}.${bytes[at + 1]}.${bytes[at + 2]}.${bytes[at + 3]}`;
}

/**
 * The options between the fixed 20-byte header and the transport header.
 *
 * Returns one row per option, each named and - for the four that carry
 * something worth reading - opened up. An option this does not understand is
 * still listed with its type, length and bytes rather than being silently
 * dropped, because "there is an option here I cannot read" and "there are no
 * options" are very different facts about a packet.
 */
export function dissectIpv4Options(bytes: Uint8Array, start: number, end: number): ProtocolField[] {
  const out: ProtocolField[] = [];
  let at = start;

  while (at < end && at < bytes.length) {
    const type = bytes[at];
    const copy = (type >> 7) & 1;
    const optClass = (type >> 5) & 0x3;
    const number = type & 0x1f;
    const name = OPTION_NAMES[number] ?? `Unknown (0x${type.toString(16).padStart(2, '0')})`;

    // EOL and NOP are single bytes with no length field of their own; every
    // other option carries its own total length, this byte included.
    if (number === 0 || number === 1) {
      out.push({
        name: `${name} (${type})`,
        value: '',
        rawBytesRange: [at, at],
      });
      at += 1;
      // End of Option List: everything after it is padding.
      if (number === 0) break;
      continue;
    }

    if (at + 1 >= bytes.length) break;
    const length = bytes[at + 1];
    // A length that does not advance would spin here forever, and a length
    // past the header is a malformed packet rather than a licence to read
    // beyond it.
    if (length < 2 || at + length > end || at + length > bytes.length) {
      out.push({
        name: `${name} (${type})`,
        value: `Malformed: length ${length}`,
        rawBytesRange: [at, Math.min(bytes.length, end) - 1],
        expertInfo: {
          category: 'Broken',
          message: `IPv4 option ${type} declares a length of ${length}, which does not fit the header`,
        },
      });
      break;
    }

    const children: ProtocolField[] = [
      { name: 'Copy on fragmentation', value: copy ? 'Yes' : 'No', rawBytesRange: [at, at] },
      { name: 'Class', value: optClass === 0 ? 'Control (0)' : optClass === 2 ? 'Debugging and measurement (2)' : `${optClass}`, rawBytesRange: [at, at] },
      { name: 'Number', value: number, rawBytesRange: [at, at] },
      { name: 'Length', value: length, rawBytesRange: [at + 1, at + 1] },
    ];
    let summary = '';

    if (number === 20 && length === 4) {
      // Router Alert: "every router on the path must look inside this packet",
      // which is what makes IGMP and RSVP work at all.
      const value = (bytes[at + 2] << 8) | bytes[at + 3];
      summary = ROUTER_ALERT_VALUES[value] ?? `Reserved (${value})`;
      children.push({ name: 'Router Alert', value: `${summary} (${value})`, rawBytesRange: [at + 2, at + 3] });
    } else if ((number === 7 || number === 3 || number === 9) && length >= 3) {
      // Record Route and the two source routes share a layout: a pointer, then
      // a list of addresses. The pointer says where the next one goes, so the
      // entries before it are filled in and the rest are empty slots.
      const pointer = bytes[at + 2];
      children.push({ name: 'Pointer', value: pointer, rawBytesRange: [at + 2, at + 2] });
      const routes: string[] = [];
      for (let p = at + 3; p + 4 <= at + length; p += 4) {
        const address = ipv4At(bytes, p);
        // The pointer is a 1-based offset into the option and points at where
        // the NEXT address will go, so a slot at or past it is still empty.
        const filled = p - at < pointer - 1;
        if (filled) routes.push(address);
        children.push({
          name: filled ? 'Address' : 'Empty slot',
          value: filled ? address : '-',
          rawBytesRange: [p, p + 3],
        });
      }
      summary = routes.join(', ');
    } else if (number === 4 && length >= 4) {
      const pointer = bytes[at + 2];
      const overflow = bytes[at + 3] >> 4;
      const flag = bytes[at + 3] & 0x0f;
      children.push(
        { name: 'Pointer', value: pointer, rawBytesRange: [at + 2, at + 2] },
        { name: 'Overflow', value: overflow, rawBytesRange: [at + 3, at + 3] },
        { name: 'Flag', value: `${TIMESTAMP_FLAGS[flag] ?? 'Unknown'} (${flag})`, rawBytesRange: [at + 3, at + 3] },
      );
      const stride = flag === 0 ? 4 : 8;
      for (let p = at + 4; p + stride <= at + length; p += stride) {
        if (stride === 8) {
          children.push({ name: 'Address', value: ipv4At(bytes, p), rawBytesRange: [p, p + 3] });
          children.push({
            name: 'Time stamp',
            value: ((bytes[p + 4] << 24) | (bytes[p + 5] << 16) | (bytes[p + 6] << 8) | bytes[p + 7]) >>> 0,
            rawBytesRange: [p + 4, p + 7],
          });
        } else {
          children.push({
            name: 'Time stamp',
            value: ((bytes[p] << 24) | (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3]) >>> 0,
            rawBytesRange: [p, p + 3],
          });
        }
      }
    } else if (number === 8 && length === 4) {
      const streamId = (bytes[at + 2] << 8) | bytes[at + 3];
      summary = String(streamId);
      children.push({ name: 'Stream Identifier', value: streamId, rawBytesRange: [at + 2, at + 3] });
    } else if (length > 2) {
      // Named but not understood: the bytes are shown so the option is still
      // evidence rather than a gap.
      const hex = Array.from(bytes.slice(at + 2, at + length))
        .map((b) => b.toString(16).padStart(2, '0')).join(':');
      summary = hex;
      children.push({ name: 'Data', value: hex, rawBytesRange: [at + 2, at + length - 1] });
    }

    out.push({
      name: `${name} (${length} bytes)`,
      value: summary,
      rawBytesRange: [at, at + length - 1],
      children,
    });
    at += length;
  }

  return out;
}
