import { ProtocolField } from '../../types/packet';
import { formatMac } from '../addressFormat';
import { L2DissectorResult } from './l2';

/**
 * LLDP - Link Layer Discovery Protocol, IEEE 802.1AB (ethertype 0x88cc).
 *
 * The LLDPDU is a flat run of TLVs: a 16-bit header carrying a 7-bit type and
 * a 9-bit length, then that many payload bytes, repeating until the End TLV
 * (type 0) or the end of the frame.
 *
 * Everything here - the Info column's `MA/<id> IN/<id> <ttl>` shape, the
 * two-letter subtype prefixes, and which subtypes render as hex rather than
 * text - was read off `tshark -T fields -e _ws.col.info` for frames built to
 * cover all 7x7 chassis/port subtype combinations, so Inwire's Info column
 * matches the reference analyzer's character for character rather than approximating it.
 */

const TLV_END = 0;
const TLV_CHASSIS_ID = 1;
const TLV_PORT_ID = 2;
const TLV_TTL = 3;
const TLV_PORT_DESCRIPTION = 4;
const TLV_SYSTEM_NAME = 5;
const TLV_SYSTEM_DESCRIPTION = 6;
const TLV_SYSTEM_CAPABILITIES = 7;
const TLV_MANAGEMENT_ADDRESS = 8;

/**
 * Chassis and Port ID subtypes are numbered differently for the same names -
 * "Port component" is chassis 3 but port 2 - so the two tables cannot be
 * merged. `hex` marks the subtypes the reference analyzer renders as raw hex digits
 * instead of text.
 */
interface SubtypeSpec {
  name: string;
  /** The reference analyzer's two-letter Info-column prefix. */
  prefix: string;
  render?: 'hex' | 'mac' | 'address';
}

const CHASSIS_SUBTYPES: Record<number, SubtypeSpec> = {
  1: { name: 'Chassis component', prefix: 'CC' },
  2: { name: 'Interface alias', prefix: 'IA' },
  3: { name: 'Port component', prefix: 'PC', render: 'hex' },
  4: { name: 'MAC address', prefix: 'MA', render: 'mac' },
  5: { name: 'Network address', prefix: 'NA', render: 'address' },
  6: { name: 'Interface name', prefix: 'IN' },
  7: { name: 'Locally assigned', prefix: 'LA' },
};

const PORT_SUBTYPES: Record<number, SubtypeSpec> = {
  1: { name: 'Interface alias', prefix: 'IA' },
  2: { name: 'Port component', prefix: 'PC', render: 'hex' },
  3: { name: 'MAC address', prefix: 'MA', render: 'mac' },
  4: { name: 'Network address', prefix: 'NA', render: 'address' },
  5: { name: 'Interface name', prefix: 'IN' },
  6: { name: 'Agent circuit ID', prefix: 'AC' },
  7: { name: 'Locally assigned', prefix: 'LA' },
};

/** IANA address family numbers, of which only these two appear in practice. */
const ADDRESS_FAMILY_IPV4 = 1;
const ADDRESS_FAMILY_IPV6 = 2;

const CAPABILITY_NAMES = [
  'Other',
  'Repeater',
  'Bridge',
  'WLAN access point',
  'Router',
  'Telephone',
  'DOCSIS cable device',
  'Station only',
  'C-VLAN component',
  'S-VLAN component',
  'TPMR component',
];

function toAscii(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
  return out;
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/**
 * A network address as it appears inside a Chassis/Port ID TLV: one address
 * family byte, then the address itself.
 */
function formatNetworkAddress(bytes: Uint8Array): string {
  if (bytes.length < 1) return '';
  const family = bytes[0];
  const rest = bytes.subarray(1);
  if (family === ADDRESS_FAMILY_IPV4 && rest.length >= 4) {
    return `${rest[0]}.${rest[1]}.${rest[2]}.${rest[3]}`;
  }
  if (family === ADDRESS_FAMILY_IPV6 && rest.length >= 16) {
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      groups.push(((rest[i] << 8) | rest[i + 1]).toString(16));
    }
    return groups.join(':');
  }
  return toHex(rest);
}

/** Renders an ID payload (subtype byte already stripped) per its subtype. */
function renderId(spec: SubtypeSpec | undefined, payload: Uint8Array): string {
  if (!spec) return toHex(payload);
  switch (spec.render) {
    case 'mac':
      return payload.length >= 6 ? formatMac(payload.subarray(0, 6)) : toHex(payload);
    case 'address':
      return formatNetworkAddress(payload);
    case 'hex':
      return toHex(payload);
    default:
      return toAscii(payload);
  }
}

function describeCapabilities(bits: number): string {
  const set = CAPABILITY_NAMES.filter((_, i) => (bits >> i) & 1);
  return set.length ? set.join(', ') : 'None';
}

/**
 * Dissects an LLDPDU starting at `offset` (immediately after the ethertype).
 *
 * Returns null only when there is nothing to read at all; a truncated or
 * malformed TLV run still produces a layer for everything decoded up to the
 * bad TLV, which is what makes a snaplen-clipped capture readable.
 */
export function dissectLldp(rawBytes: Uint8Array, offset: number): L2DissectorResult | null {
  if (offset >= rawBytes.length) return null;

  const fields: ProtocolField[] = [];
  const filterFields: Record<string, string | number> = {};

  let chassisSummary = '';
  let portSummary = '';
  let ttl: number | null = null;
  let systemName: string | null = null;
  let systemDescription: string | null = null;
  let sawEnd = false;

  let cursor = offset;
  // Frames are padded to the 60-byte Ethernet minimum, and the padding reads
  // as an unbroken run of type-0 TLVs. Stopping at the End TLV rather than at
  // the buffer's end is what keeps that padding out of the tree.
  while (cursor + 2 <= rawBytes.length) {
    const header = (rawBytes[cursor] << 8) | rawBytes[cursor + 1];
    const type = header >> 9;
    const length = header & 0x1ff;
    const valueStart = cursor + 2;
    const valueEnd = valueStart + length;

    if (type === TLV_END) {
      fields.push({
        name: 'End of LLDPDU',
        value: '',
        rawBytesRange: [cursor, cursor + 1],
      });
      sawEnd = true;
      break;
    }

    // A length that runs off the end of the frame means the capture was cut
    // short or the frame is corrupt. Record it and stop rather than reading
    // past the buffer.
    if (valueEnd > rawBytes.length) {
      fields.push({
        name: '[Malformed TLV]',
        value: `Type ${type} claims ${length} bytes, only ${rawBytes.length - valueStart} remain`,
        generated: true,
      });
      break;
    }

    const value = rawBytes.subarray(valueStart, valueEnd);

    switch (type) {
      case TLV_CHASSIS_ID: {
        const subtype = value[0];
        const spec = CHASSIS_SUBTYPES[subtype];
        const id = renderId(spec, value.subarray(1));
        chassisSummary = `${spec?.prefix ?? '??'}/${id}`;
        filterFields['lldp.chassis.id'] = id;
        filterFields['lldp.chassis.subtype'] = subtype;
        fields.push({
          name: `Chassis Subtype = ${spec?.name ?? `Unknown (${subtype})`}, Id`,
          value: id,
          rawBytesRange: [cursor, valueEnd - 1],
          children: [
            { name: 'Chassis Id Subtype', value: `${spec?.name ?? 'Unknown'} (${subtype})`, rawBytesRange: [valueStart, valueStart] },
            { name: 'Chassis Id', value: id, rawBytesRange: [valueStart + 1, valueEnd - 1] },
          ],
        });
        break;
      }

      case TLV_PORT_ID: {
        const subtype = value[0];
        const spec = PORT_SUBTYPES[subtype];
        const id = renderId(spec, value.subarray(1));
        portSummary = `${spec?.prefix ?? '??'}/${id}`;
        filterFields['lldp.port.id'] = id;
        filterFields['lldp.port.subtype'] = subtype;
        fields.push({
          name: `Port Subtype = ${spec?.name ?? `Unknown (${subtype})`}, Id`,
          value: id,
          rawBytesRange: [cursor, valueEnd - 1],
          children: [
            { name: 'Port Id Subtype', value: `${spec?.name ?? 'Unknown'} (${subtype})`, rawBytesRange: [valueStart, valueStart] },
            { name: 'Port Id', value: id, rawBytesRange: [valueStart + 1, valueEnd - 1] },
          ],
        });
        break;
      }

      case TLV_TTL: {
        ttl = length >= 2 ? (value[0] << 8) | value[1] : 0;
        filterFields['lldp.time_to_live'] = ttl;
        fields.push({
          name: 'Time To Live',
          value: `${ttl} sec`,
          rawBytesRange: [cursor, valueEnd - 1],
          children: [
            // TTL 0 is how a station withdraws itself before going down -
            // worth calling out, because it is the difference between "this
            // neighbour exists" and "this neighbour is leaving".
            { name: ttl === 0 ? '[Shutdown LLDPDU]' : '[Normal LLDPDU]', value: '', generated: true },
            { name: 'Seconds', value: ttl, rawBytesRange: [valueStart, valueEnd - 1] },
          ],
        });
        break;
      }

      case TLV_PORT_DESCRIPTION: {
        const text = toAscii(value);
        filterFields['lldp.port.desc'] = text;
        fields.push({ name: 'Port Description', value: text, rawBytesRange: [cursor, valueEnd - 1] });
        break;
      }

      case TLV_SYSTEM_NAME: {
        systemName = toAscii(value);
        filterFields['lldp.tlv.system.name'] = systemName;
        fields.push({ name: 'System Name', value: systemName, rawBytesRange: [cursor, valueEnd - 1] });
        break;
      }

      case TLV_SYSTEM_DESCRIPTION: {
        systemDescription = toAscii(value);
        filterFields['lldp.tlv.system.desc'] = systemDescription;
        fields.push({ name: 'System Description', value: systemDescription, rawBytesRange: [cursor, valueEnd - 1] });
        break;
      }

      case TLV_SYSTEM_CAPABILITIES: {
        const capabilities = length >= 2 ? (value[0] << 8) | value[1] : 0;
        const enabled = length >= 4 ? (value[2] << 8) | value[3] : 0;
        filterFields['lldp.tlv.system.cap'] = capabilities;
        fields.push({
          name: 'Capabilities',
          value: describeCapabilities(enabled),
          rawBytesRange: [cursor, valueEnd - 1],
          children: [
            { name: 'Capabilities', value: `0x${capabilities.toString(16).padStart(4, '0')} (${describeCapabilities(capabilities)})`, rawBytesRange: [valueStart, valueStart + 1] },
            { name: 'Enabled Capabilities', value: `0x${enabled.toString(16).padStart(4, '0')} (${describeCapabilities(enabled)})`, rawBytesRange: [valueStart + 2, valueStart + 3] },
          ],
        });
        break;
      }

      case TLV_MANAGEMENT_ADDRESS: {
        // Layout: address string length (which counts the subtype byte plus
        // the address), address subtype, address, interface subtype,
        // interface number, OID length, OID.
        const addrStringLen = value[0] ?? 0;
        const address = formatNetworkAddress(value.subarray(1, 1 + addrStringLen));
        filterFields['lldp.mgn.addr'] = address;
        const children: ProtocolField[] = [
          { name: 'Address String Length', value: addrStringLen, rawBytesRange: [valueStart, valueStart] },
          { name: 'Management Address', value: address, rawBytesRange: [valueStart + 1, valueStart + addrStringLen] },
        ];
        const ifaceAt = 1 + addrStringLen;
        if (value.length >= ifaceAt + 5) {
          const ifaceSubtype = value[ifaceAt];
          const ifaceNumber =
            (value[ifaceAt + 1] << 24) | (value[ifaceAt + 2] << 16) | (value[ifaceAt + 3] << 8) | value[ifaceAt + 4];
          children.push(
            { name: 'Interface Subtype', value: ifaceSubtype === 1 ? 'Unknown (1)' : ifaceSubtype === 2 ? 'ifIndex (2)' : ifaceSubtype === 3 ? 'System port number (3)' : `${ifaceSubtype}`, rawBytesRange: [valueStart + ifaceAt, valueStart + ifaceAt] },
            { name: 'Interface Number', value: ifaceNumber >>> 0, rawBytesRange: [valueStart + ifaceAt + 1, valueStart + ifaceAt + 4] },
          );
        }
        fields.push({ name: 'Management Address', value: address, rawBytesRange: [cursor, valueEnd - 1], children });
        break;
      }

      default: {
        // Organisationally specific TLVs (127) and anything else we do not
        // decode: named honestly, with their bytes, rather than dropped.
        fields.push({
          name: type === 127 ? 'Organization Specific TLV' : `Unknown TLV (type ${type})`,
          value: `${length} byte${length === 1 ? '' : 's'}`,
          rawBytesRange: [cursor, valueEnd - 1],
        });
        break;
      }
    }

    cursor = valueEnd;
  }

  if (fields.length === 0) return null;

  // The reference analyzer's Info column, exactly: chassis, port, TTL, then System Name
  // and System Description when those TLVs are present.
  const parts: string[] = [];
  if (chassisSummary) parts.push(chassisSummary);
  if (portSummary) parts.push(portSummary);
  if (ttl !== null) parts.push(String(ttl));
  if (systemName) parts.push(`SysN=${systemName}`);
  if (systemDescription) parts.push(`SysD=${systemDescription}`);

  return {
    protocolLabel: 'LLDP',
    // A frame with no recognisable mandatory TLVs still gets a name rather
    // than falling back to the frame-length placeholder this dissector exists
    // to eliminate.
    info: parts.length ? parts.join(' ') : 'LLDP Data Unit',
    fields: filterFields,
    layer: {
      name: 'Link Layer Discovery Protocol',
      // The summary carries the neighbour's identity, which is the one thing
      // worth reading without expanding the tree.
      summary: systemName
        ? `Link Layer Discovery Protocol, System Name = ${systemName}`
        : 'Link Layer Discovery Protocol',
      // Only the TLVs we actually consumed - trailing Ethernet padding after
      // the End TLV is not part of the LLDPDU.
      rawBytesRange: [offset, (sawEnd ? cursor + 1 : cursor - 1)],
      fields,
    },
  };
}
