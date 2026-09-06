/**
 * VRRP (RFC 3768 for v2, RFC 5798 for v3), IP protocol 112.
 *
 *   Announcement (v2)
 *   Announcement (v3)
 *
 * The standard version of what `dissectors/hsrp.ts` does, and it matters for
 * the same reason: a gateway failover leaves no trace in the traffic it
 * interrupts, because the address and the virtual MAC never change. Only the
 * advertisement says which router is holding the address, and a priority of 0
 * is a router **resigning** - the one packet that explains a several-second
 * gap in everything else.
 *
 * Two versions share the protocol number and are told apart by the version
 * nibble, not by the length. They differ in more than a field: v2's `Adver Int`
 * counts **seconds** and v3's `Max Adver Int` counts **centiseconds**, so
 * reading a v3 packet with v2's rule reports an interval a hundred times too
 * long. v3 also drops the authentication fields entirely, having concluded -
 * correctly - that a cleartext password on a multicast group protects nothing.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address } from '../addressFormat';

export interface VrrpResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** RFC 3768 §5.3.4 - the only type either version defines. */
const TYPE_ADVERTISEMENT = 1;

const AUTH_TYPES: Record<number, string> = {
  0: 'No Authentication',
  1: 'Simple Text Authentication',
  2: 'IP Authentication Header',
};

/** Enough for the fixed header; the addresses follow. */
const MIN_BYTES = 8;

export function dissectVrrp(bytes: Uint8Array, start: number, end: number): VrrpResult | null {
  if (start + MIN_BYTES > end) return null;
  const version = bytes[start] >> 4;
  const type = bytes[start] & 0x0f;
  if ((version !== 2 && version !== 3) || type !== TYPE_ADVERTISEMENT) return null;

  const vrid = bytes[start + 1];
  const priority = bytes[start + 2];
  const addressCount = bytes[start + 3];
  if (start + MIN_BYTES + addressCount * 4 > end) return null;

  const fields: Record<string, string | number> = {
    'vrrp.version': version,
    'vrrp.type': type,
    'vrrp.virt_rtr_id': vrid,
    'vrrp.prio': priority,
    'vrrp.addr_count': addressCount,
  };

  const rows: ProtocolField[] = [
    { name: 'Version', value: version, abbrev: 'vrrp.version', rawBytesRange: [start, start] },
    { name: 'Type', value: `Advertisement (${type})`, abbrev: 'vrrp.type',
      rawBytesRange: [start, start] },
    { name: 'Virtual Rtr ID', value: vrid, abbrev: 'vrrp.virt_rtr_id',
      rawBytesRange: [start + 1, start + 1] },
    {
      name: 'Priority',
      // 255 is the address owner and 0 is a router giving the address up. Both
      // are the interesting cases and neither reads as special as a bare number.
      value: priority === 255 ? `${priority} (Current Master has stopped participating, IP Address Owner)`
        : priority === 0 ? `${priority} (Current Master has stopped participating)`
          : `${priority} (Non-default backup priority)`,
      abbrev: 'vrrp.prio', rawBytesRange: [start + 2, start + 2],
    },
    { name: 'Addr Count', value: addressCount, abbrev: 'vrrp.addr_count',
      rawBytesRange: [start + 3, start + 3] },
  ];

  if (version === 2) {
    const authType = bytes[start + 4];
    const adverInt = bytes[start + 5];
    fields['vrrp.auth_type'] = authType;
    fields['vrrp.adver_int'] = adverInt;
    rows.push(
      { name: 'Auth Type', value: `${AUTH_TYPES[authType] ?? 'Unknown'} (${authType})`,
        abbrev: 'vrrp.auth_type', rawBytesRange: [start + 4, start + 4] },
      // Seconds in v2 - see the header comment; v3 counts the same field in
      // centiseconds, which is the trap in reading the two with one rule.
      { name: 'Adver Int', value: `${adverInt}`, abbrev: 'vrrp.adver_int',
        rawBytesRange: [start + 5, start + 5] },
    );
  } else {
    // v3 spends the byte v2 used for Auth Type on four more bits of interval.
    const maxAdverInt = ((bytes[start + 4] & 0x0f) << 8) | bytes[start + 5];
    fields['vrrp.short_adver_int'] = maxAdverInt;
    rows.push({ name: 'Max Adver Int', value: `${maxAdverInt} (in centiseconds)`,
      abbrev: 'vrrp.short_adver_int', rawBytesRange: [start + 4, start + 5] });
  }

  const checksum = (bytes[start + 6] << 8) | bytes[start + 7];
  fields['vrrp.checksum'] = checksum;
  rows.push({ name: 'Checksum', value: `0x${checksum.toString(16).padStart(4, '0')}`,
    abbrev: 'vrrp.checksum', rawBytesRange: [start + 6, start + 7] });

  const addresses: string[] = [];
  for (let i = 0; i < addressCount; i++) {
    const at = start + MIN_BYTES + i * 4;
    const address = formatIpv4Address(bytes, at);
    addresses.push(address);
    rows.push({ name: 'IP Address', value: address, abbrev: 'vrrp.ip_addr',
      rawBytesRange: [at, at + 3] });
  }
  if (addresses.length > 0) fields['vrrp.ip_addr'] = addresses[0];

  return {
    protocolLabel: 'VRRP',
    info: `Announcement (v${version})`,
    fields,
    layer: {
      name: 'Virtual Router Redundancy Protocol',
      summary: 'Virtual Router Redundancy Protocol',
      rawBytesRange: [start, Math.max(start, end - 1)],
      fields: rows,
    },
  };
}
