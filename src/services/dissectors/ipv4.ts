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

/**
 * Option numbers by the low five bits of the type byte, in the reference's
 * words (`ipopt_type_number_vals`) - what the Number row reads.
 */
const OPTION_NUMBERS: Record<number, string> = {
  0: 'End of Option List (EOL)', 1: 'No-Operation (NOP)', 2: 'Security', 3: 'Loose source route',
  4: 'Time stamp', 5: 'Extended security', 6: 'Commercial IP security option', 7: 'Record route',
  8: 'Stream identifier', 9: 'Strict source route', 10: 'Experimental Measurement', 11: 'MTU probe',
  12: 'MTU Reply', 13: 'Experimental Flow Control', 14: 'Experimental Access Control', 15: 'Ask Estrin',
  16: 'IMI Traffic Descriptor', 17: 'Extended Internet Protocol', 18: 'Traceroute', 19: 'Address Extension',
  20: 'Router Alert', 21: 'Selective Directed Broadcast', 22: 'Unassigned', 23: 'Dynamic Packet State',
  24: 'Upstream Multicast Packet', 25: 'Quick-Start', 26: 'Cilium DSR', 30: 'RFC 3692-style experiment',
};

/**
 * The options the reference has a dissector for, by the WHOLE type byte - the
 * copy and class bits are part of the key - with the name it heads the row
 * with and the field that row is (`ip.options.*`).
 */
const OPTION_KINDS: Record<number, { name: string; abbrev: string }> = {
  0x82: { name: 'Security', abbrev: 'ip.options.security' },
  0x83: { name: 'Loose Source Route', abbrev: 'ip.options.route' },
  0x44: { name: 'Time Stamp', abbrev: 'ip.options.timestamp' },
  0x85: { name: 'Extended Security', abbrev: 'ip.options.ext_security' },
  0x86: { name: 'Commercial Security', abbrev: 'ip.options.cipso' },
  0x07: { name: 'Record Route', abbrev: 'ip.options.record_route' },
  0x88: { name: 'Stream ID', abbrev: 'ip.options.sid' },
  0x89: { name: 'Strict Source Route', abbrev: 'ip.options.source_route' },
  0x0b: { name: 'MTU Probe', abbrev: 'ip.options.mtu_probe' },
  0x0c: { name: 'MTU Reply', abbrev: 'ip.options.mtu_reply' },
  0x52: { name: 'Traceroute', abbrev: 'ip.options.traceroute' },
  0x94: { name: 'Router Alert', abbrev: 'ip.options.routeralert' },
  0x95: { name: 'Selective Directed Broadcast', abbrev: 'ip.options.sdb' },
  0x19: { name: 'Quick-Start', abbrev: 'ip.options.qs' },
  0x9a: { name: 'Cilium DSR', abbrev: 'ip.options.dsr' },
};

const OPTION_CLASSES = ['Control', 'Reserved for future use', 'Debugging and measurement', 'Reserved for future use'];

const TIMESTAMP_FLAGS: Record<number, string> = {
  0: 'Time stamps only',
  1: 'Time stamp and address',
  3: 'Time stamps for prespecified addresses',
};

function ipv4At(bytes: Uint8Array, at: number): string {
  return `${bytes[at]}.${bytes[at + 1]}.${bytes[at + 2]}.${bytes[at + 3]}`;
}

/** The Type row and its three parts, as `dissect_ipopt_type` draws them. */
function optionTypeRow(type: number, at: number): ProtocolField {
  const number = type & 0x1f;
  const bits = (bitOffset: number, bitLength: number) => ({ bitOffset, bitLength, totalBits: 8 });
  return {
    name: 'Type', value: type, abbrev: 'ip.opt.type', rawBytesRange: [at, at],
    children: [
      { name: 'Copy on fragmentation', value: type & 0x80 ? 'Yes' : 'No', abbrev: 'ip.opt.type.copy', rawBytesRange: [at, at], bitfield: bits(0, 1) },
      { name: 'Class', value: `${OPTION_CLASSES[(type >> 5) & 0x3]} (${(type >> 5) & 0x3})`, abbrev: 'ip.opt.type.class', rawBytesRange: [at, at], bitfield: bits(1, 2) },
      { name: 'Number', value: `${OPTION_NUMBERS[number] ?? 'Unknown'} (${number})`, abbrev: 'ip.opt.type.number', rawBytesRange: [at, at], bitfield: bits(3, 5) },
    ],
  };
}

/**
 * The options between the fixed 20-byte header and the transport header, as
 * the reference draws them: one row per option, headed `IP Option - <name>`
 * and naming the `ip.options.*` field it is, with the Type byte opened into
 * its copy, class and number, the Length, and what the option carries.
 *
 * An option this does not read field by field is still listed with its type,
 * length and bytes rather than being silently dropped, because "there is an
 * option here I cannot read" and "there are no options" are very different
 * facts about a packet.
 */
export function dissectIpv4Options(bytes: Uint8Array, start: number, end: number): ProtocolField[] {
  const out: ProtocolField[] = [];
  let at = start;

  while (at < end && at < bytes.length) {
    const type = bytes[at];

    // EOL and NOP are single bytes with no length field of their own; every
    // other option carries its own total length, this byte included.
    if (type === 0 || type === 1) {
      out.push({
        name: type === 0 ? 'IP Option - End of Options List (EOL)' : 'IP Option - No-Operation (NOP)',
        value: '',
        abbrev: type === 0 ? 'ip.options.eol' : 'ip.options.nop',
        rawBytesRange: [at, at],
        children: [optionTypeRow(type, at)],
      });
      at += 1;
      // End of Option List: everything after it is padding.
      if (type === 0) break;
      continue;
    }

    const kind = OPTION_KINDS[type];
    const label = kind?.name ?? `Unknown (0x${type.toString(16).padStart(2, '0')})`;
    if (at + 1 >= bytes.length) break;
    const length = bytes[at + 1];
    // A length that does not advance would spin here forever, and a length
    // past the header is a malformed packet rather than a licence to read
    // beyond it.
    if (length < 2 || at + length > end || at + length > bytes.length) {
      out.push({
        name: `${label} (${type})`,
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
      optionTypeRow(type, at),
      { name: 'Length', value: length, abbrev: 'ip.opt.len', rawBytesRange: [at + 1, at + 1] },
    ];
    const u16 = (p: number) => (bytes[p] << 8) | bytes[p + 1];
    let summary = '';

    if (type === 0x94 && length === 4) {
      // Router Alert: "every router on the path must look inside this packet",
      // which is what makes IGMP and RSVP work at all.
      const value = u16(at + 2);
      summary = `${value === 0 ? 'Router shall examine packet' : 'Reserved'} (${value})`;
      children.push({ name: 'Router Alert', value: summary, abbrev: 'ip.opt.ra', rawBytesRange: [at + 2, at + 3] });
    } else if ((type === 0x07 || type === 0x83 || type === 0x89) && length >= 3) {
      routeRows(bytes, at, length, type, children);
      // Not the reference's: the route itself on the collapsed row, which is
      // what the option is read for.
      summary = children
        .filter((c) => c.abbrev === 'ip.rec_rt' || c.abbrev === 'ip.src_rt' || c.abbrev === 'ip.dst')
        .map((c) => String(c.value).replace(' <- (next)', '')).join(', ');
    } else if (type === 0x44 && length >= 4) {
      timestampRows(bytes, at, length, children);
    } else if (type === 0x88 && length === 4) {
      // RFC 6814 retired it; the reference notes as much on the Length row.
      children[1].children = [{ name: '[Option type is deprecated]', value: '', generated: true, abbrev: 'ip.opt.deprecated' }];
      children.push({ name: 'Stream Identifier', value: u16(at + 2), abbrev: 'ip.opt.sid', rawBytesRange: [at + 2, at + 3] });
    } else if ((type === 0x0b || type === 0x0c) && length === 4) {
      children.push({ name: 'MTU', value: u16(at + 2), abbrev: 'ip.opt.mtu', rawBytesRange: [at + 2, at + 3] });
    } else if (length > 2) {
      // Not read field by field here: the bytes are shown so the option is
      // still evidence rather than a gap.
      const hex = Array.from(bytes.slice(at + 2, at + length))
        .map((b) => b.toString(16).padStart(2, '0')).join('');
      children.push({ name: 'Data', value: hex, abbrev: 'ip.opt.data', rawBytesRange: [at + 2, at + length - 1] });
    }

    out.push({
      name: `${kind ? 'IP Option - ' : ''}${label} (${length} byte${length === 1 ? '' : 's'})`,
      value: summary,
      ...(kind ? { abbrev: kind.abbrev } : {}),
      rawBytesRange: [at, at + length - 1],
      children,
    });
    at += length;
  }

  return out;
}

/**
 * Record Route and the two source routes: a pointer, then four-byte slots.
 * Which slot is which follows `dissect_ipopt_route` and
 * `dissect_ipopt_record_route` exactly - the pointer is 1-based and names the
 * slot the next router fills, a source route's last slot is the destination,
 * and a pointer past the end means the route is complete.
 */
function routeRows(bytes: Uint8Array, at: number, length: number, type: number, children: ProtocolField[]): void {
  const pointer = bytes[at + 2];
  // A pointer before the first slot or into the middle of one is malformed,
  // and the reference says which and stops reading there.
  const bad = pointer < 4 ? { abbrev: 'ip.opt.ptr.before_address', message: 'Pointer points before first address' }
    : pointer & 3 ? { abbrev: 'ip.opt.ptr.middle_address', message: 'Pointer points to middle of address' }
      : undefined;
  children.push({
    name: 'Pointer', value: pointer, abbrev: 'ip.opt.ptr', rawBytesRange: [at + 2, at + 2],
    ...(bad ? {
      children: [{
        name: `[${bad.message}]`, value: '', generated: true, abbrev: bad.abbrev,
        expertInfo: { category: 'Broken', message: bad.message },
      }],
    } : {}),
  });
  if (bad) return;
  const record = type === 0x07;
  for (let slot = 3; slot + 4 <= length; slot += 4) {
    const address = ipv4At(bytes, at + slot);
    const range: [number, number] = [at + slot, at + slot + 3];
    const next = slot + 1 === pointer;
    if (pointer > length || slot + 1 < pointer) {
      children.push({ name: 'Recorded Route', value: address, abbrev: 'ip.rec_rt', rawBytesRange: range });
    } else if (record) {
      children.push({ name: 'Empty Route', value: next ? `${address} <- (next)` : address, abbrev: 'ip.empty_rt', rawBytesRange: range });
    } else if (slot === length - 4) {
      children.push({ name: 'Destination Address', value: address, abbrev: 'ip.dst', rawBytesRange: range });
    } else {
      children.push({ name: 'Source Route', value: next ? `${address} <- (next)` : address, abbrev: 'ip.src_rt', rawBytesRange: range });
    }
  }
}

/** Time Stamp: pointer, overflow and flag, then stamps alone or after addresses. */
function timestampRows(bytes: Uint8Array, at: number, length: number, children: ProtocolField[]): void {
  const pointer = bytes[at + 2];
  const flag = bytes[at + 3] & 0x0f;
  const note = pointer === 1 ? ' (header is full)'
    : pointer < 5 ? ' (points before first address)'
      : ((pointer - 1) & 3) ? ' (points to middle of field)' : '';
  children.push(
    { name: 'Pointer', value: `${pointer}${note}`, abbrev: 'ip.opt.ptr', rawBytesRange: [at + 2, at + 2] },
    { name: 'Overflow', value: bytes[at + 3] >> 4, abbrev: 'ip.opt.overflow', rawBytesRange: [at + 3, at + 3], bitfield: { bitOffset: 0, bitLength: 4, totalBits: 8 } },
    { name: 'Flag', value: `${TIMESTAMP_FLAGS[flag] ?? 'Unknown'} (0x${flag.toString(16)})`, abbrev: 'ip.opt.flag', rawBytesRange: [at + 3, at + 3], bitfield: { bitOffset: 4, bitLength: 4, totalBits: 8 } },
  );
  const withAddress = flag === 1 || flag === 3;
  const stride = withAddress ? 8 : 4;
  const u32 = (p: number) => ((bytes[p] << 24) | (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3]) >>> 0;
  for (let p = at + 4; p + stride <= at + length; p += stride) {
    if (withAddress) {
      children.push({ name: 'Address', value: u32(p) === 0 ? '-' : ipv4At(bytes, p), abbrev: 'ip.opt.time_stamp_addr', rawBytesRange: [p, p + 3] });
      children.push({ name: 'Time stamp', value: u32(p + 4), abbrev: 'ip.opt.time_stamp', rawBytesRange: [p + 4, p + 7] });
    } else {
      children.push({ name: 'Time stamp', value: u32(p), abbrev: 'ip.opt.time_stamp', rawBytesRange: [p, p + 3] });
    }
  }
}
