import { ProtocolField } from '../../types/packet';
import { toHex, formatMac } from '../addressFormat';
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

const TLV_ORG_SPECIFIC = 127;

/** The two organisations whose TLVs appear on an ordinary office link. */
const OUI_IEEE_802_3 = 0x00120f;
const OUI_TIA_TR41 = 0x0012bb;

const OUI_NAMES: Record<number, string> = {
  [OUI_IEEE_802_3]: 'Ieee 802.3',
  [OUI_TIA_TR41]: 'Telecommunications Industry Association TR-41 Committee',
};

const TLV_TYPE_NAMES: Record<number, string> = {
  [TLV_END]: 'End of LLDPDU',
  [TLV_CHASSIS_ID]: 'Chassis Id',
  [TLV_PORT_ID]: 'Port Id',
  [TLV_TTL]: 'Time to Live',
  [TLV_PORT_DESCRIPTION]: 'Port Description',
  [TLV_SYSTEM_NAME]: 'System Name',
  [TLV_SYSTEM_DESCRIPTION]: 'System Description',
  [TLV_SYSTEM_CAPABILITIES]: 'System Capabilities',
  [TLV_MANAGEMENT_ADDRESS]: 'Management Address',
  [TLV_ORG_SPECIFIC]: 'Organization Specific',
};

/**
 * IEEE 802.3's PMD auto-negotiation advertised capabilities, **least
 * significant bit first**, which is the order the reference numbers them in.
 *
 * The bit order is the whole reason this list is a constant rather than
 * inlined: the same sixteen bits are drawn twice, once in this order and once
 * reversed - see `pmdCapabilityRows`.
 */
const PMD_CAPABILITIES: readonly { readonly suffix: string; readonly label: string }[] = [
  { suffix: '1000base_tfd', label: '1000BASE-T (full duplex mode)' },
  { suffix: '1000base_t', label: '1000BASE-T (half duplex mode)' },
  { suffix: '1000base_xfd', label: '1000BASE-X (-LX, -SX, -CX full duplex mode)' },
  { suffix: '1000base_x', label: '1000BASE-X (-LX, -SX, -CX half duplex mode)' },
  { suffix: 'fdx_bpause', label: 'Asymmetric and Symmetric PAUSE (for full-duplex links)' },
  { suffix: 'fdx_spause', label: 'Symmetric PAUSE (for full-duplex links)' },
  { suffix: 'fdx_apause', label: 'Asymmetric PAUSE (for full-duplex links)' },
  { suffix: 'fdx_pause', label: 'PAUSE (for full-duplex links)' },
  { suffix: '100base_t2fd', label: '100BASE-T2 (full duplex mode)' },
  { suffix: '100base_t2', label: '100BASE-T2 (half duplex mode)' },
  { suffix: '100base_txfd', label: '100BASE-TX (full duplex mode)' },
  { suffix: '100base_tx', label: '100BASE-TX (half duplex mode)' },
  { suffix: '100base_t4', label: '100BASE-T4' },
  { suffix: '10base_tfd', label: '10BASE-T (full duplex mode)' },
  { suffix: '10base_t', label: '10BASE-T (half duplex mode)' },
  { suffix: 'other', label: 'Other or unknown' },
];

/** LLDP-MED capability bits, least significant first (ANSI/TIA-1057 10.2.2). */
const MED_CAPABILITIES: readonly { readonly suffix: string; readonly label: string }[] = [
  { suffix: 'llpd', label: 'LLDP-MED Capabilities' },
  { suffix: 'network_policy', label: 'Network Policy' },
  { suffix: 'location_id', label: 'Location Identification' },
  { suffix: 'mdi_pse', label: 'Extended Power via MDI-PSE' },
  { suffix: 'mid_pd', label: 'Extended Power via MDI-PD' },
  { suffix: 'inventory', label: 'Inventory' },
];

const MED_CLASS_NAMES: Record<number, string> = {
  1: 'Endpoint Class I', 2: 'Endpoint Class II', 3: 'Endpoint Class III', 4: 'Network Connectivity',
};

/**
 * The operational MAU types that turn up on a copper office link. Anything
 * else is shown as its number rather than guessed at - the full IANA table is
 * ~50 entries and naming one wrongly is worse than not naming it.
 */
const MAU_TYPE_NAMES: Record<number, string> = {
  0x0000: 'other or unknown',
  0x000a: '10BASE-T duplex mode unknown',
  0x000b: '10BASE-T half duplex mode',
  0x000c: '10BASE-T full duplex mode',
  0x000f: '100BASE-TX half duplex mode',
  0x0010: '100BASE-TX full duplex mode',
  0x0014: '1000BASE-T half duplex mode',
  0x0015: '1000BASE-T full duplex mode',
  0x001d: '10GBASE-T',
};

function toAscii(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
  return out;
}

/**
 * The type and length every TLV starts with, packed into one 16-bit word: a
 * 7-bit type then a 9-bit length.
 *
 * Drawn on every TLV rather than only on the ones this file decodes, because
 * an undecoded TLV is exactly where a reader needs to know how many bytes the
 * sender claimed and what it called them.
 */
function tlvHeaderRows(cursor: number, type: number, length: number): ProtocolField[] {
  const range: [number, number] = [cursor, cursor + 1];
  return [
    {
      name: 'TLV Type', value: `${TLV_TYPE_NAMES[type] ?? 'Unknown'} (${type})`,
      abbrev: 'lldp.tlv.type', rawBytesRange: range,
      bitfield: { bitOffset: 0, bitLength: 7, totalBits: 16 },
    },
    {
      name: 'TLV Length', value: length, abbrev: 'lldp.tlv.len', rawBytesRange: range,
      bitfield: { bitOffset: 7, bitLength: 9, totalBits: 16 },
    },
  ];
}

/** One row per bit of a little flag word, named from a table. */
function flagRows(
  bits: number,
  table: readonly { readonly suffix: string; readonly label: string }[],
  prefix: string,
  at: [number, number],
  reversed = false,
): ProtocolField[] {
  return table.map((entry, index) => {
    const bit = reversed ? table.length - 1 - index : index;
    return {
      name: entry.label,
      value: (bits >> bit) & 1 ? 'Capable' : 'Not capable',
      abbrev: `${prefix}.${entry.suffix}`,
      rawBytesRange: at,
      bitfield: { bitOffset: at[1] - at[0] === 1 ? 15 - bit : 7 - bit, bitLength: 1, totalBits: at[1] - at[0] === 1 ? 16 : 8 },
    };
  });
}

/**
 * The PMD advertised capabilities, twice.
 *
 * The second subtree is the same sixteen bits read in the opposite bit order,
 * and it is **deliberately wrong** - it is there because enough implementers
 * got the order backwards that reading a neighbour's advertisement the wrong
 * way round is the only way to make sense of it. The reference draws both and
 * labels the second "Same in inverse (wrong) bitorder"; copying that is what
 * lets a reader tell a genuinely odd advertisement from a byte-order bug at
 * the far end, which is otherwise indistinguishable.
 */
function pmdCapabilityRows(caps: number, at: [number, number]): ProtocolField[] {
  // The inverse half's names are the base names with `_inv` appended, and it
  // is spelled that way rather than written out because the reference has no
  // field for the inverse subtree NODE - only for its sixteen children. A
  // bare `..._inv` literal here would be a name `tshark -G fields` does not
  // have, and `scripts/dissect/registry.ts` reads these as literals.
  const base = 'lldp.ieee.802_3.pmd_auto_neg_advertised_caps';
  return [
    {
      name: 'PMD Auto-Negotiation Advertised Capability',
      value: `0x${caps.toString(16).padStart(4, '0')}`,
      abbrev: base,
      rawBytesRange: at,
      children: flagRows(caps, PMD_CAPABILITIES, base, at),
    },
    {
      name: 'Same in inverse (wrong) bitorder',
      value: '',
      rawBytesRange: at,
      children: flagRows(caps, PMD_CAPABILITIES, `${base}_inv`, at, true),
    },
  ];
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

    const headerRows = tlvHeaderRows(cursor, type, length);

    if (type === TLV_END) {
      fields.push({
        name: 'End of LLDPDU',
        value: '',
        rawBytesRange: [cursor, cursor + 1],
        children: headerRows,
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
            ...headerRows,
            { name: 'Chassis Id Subtype', value: `${spec?.name ?? 'Unknown'} (${subtype})`, abbrev: 'lldp.chassis.subtype', rawBytesRange: [valueStart, valueStart] },
            { name: 'Chassis Id', value: id, abbrev: 'lldp.chassis.id', rawBytesRange: [valueStart + 1, valueEnd - 1] },
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
            ...headerRows,
            { name: 'Port Id Subtype', value: `${spec?.name ?? 'Unknown'} (${subtype})`, abbrev: 'lldp.port.subtype', rawBytesRange: [valueStart, valueStart] },
            // The reference names this row after the subtype it carries, so a
            // MAC-address port id answers `lldp.port.id.mac` and not the
            // generic name. The bag keeps `lldp.port.id` either way, because
            // "which port" is one question whatever form the answer took.
            {
              name: 'Port Id', value: id,
              abbrev: spec?.render === 'mac' ? 'lldp.port.id.mac' : 'lldp.port.id',
              rawBytesRange: [valueStart + 1, valueEnd - 1],
            },
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
            { name: ttl === 0 ? 'Shutdown LLDPDU' : 'Normal LLDPDU', value: '', abbrev: 'lldp.pdu_type', generated: true },
            ...headerRows,
            { name: 'Seconds', value: ttl, abbrev: 'lldp.time_to_live', rawBytesRange: [valueStart, valueEnd - 1] },
          ],
        });
        break;
      }

      case TLV_PORT_DESCRIPTION: {
        const text = toAscii(value);
        filterFields['lldp.port.desc'] = text;
        fields.push({ name: 'Port Description', value: text, rawBytesRange: [cursor, valueEnd - 1], children: headerRows });
        break;
      }

      case TLV_SYSTEM_NAME: {
        systemName = toAscii(value);
        filterFields['lldp.tlv.system.name'] = systemName;
        fields.push({ name: 'System Name', value: systemName, rawBytesRange: [cursor, valueEnd - 1], children: headerRows });
        break;
      }

      case TLV_SYSTEM_DESCRIPTION: {
        systemDescription = toAscii(value);
        filterFields['lldp.tlv.system.desc'] = systemDescription;
        fields.push({ name: 'System Description', value: systemDescription, rawBytesRange: [cursor, valueEnd - 1], children: headerRows });
        break;
      }

      case TLV_SYSTEM_CAPABILITIES: {
        const capabilities = length >= 2 ? (value[0] << 8) | value[1] : 0;
        const enabled = length >= 4 ? (value[2] << 8) | value[3] : 0;
        filterFields['lldp.tlv.system_cap'] = capabilities;
        fields.push({
          name: 'Capabilities',
          value: describeCapabilities(enabled),
          rawBytesRange: [cursor, valueEnd - 1],
          children: [
            ...headerRows,
            { name: 'Capabilities', value: `0x${capabilities.toString(16).padStart(4, '0')} (${describeCapabilities(capabilities)})`, abbrev: 'lldp.tlv.system_cap', rawBytesRange: [valueStart, valueStart + 1] },
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
        filterFields['lldp.mgn.addr.ip4'] = address;
        const children: ProtocolField[] = [
          ...headerRows,
          { name: 'Address String Length', value: addrStringLen, rawBytesRange: [valueStart, valueStart] },
          { name: 'Management Address', value: address, abbrev: 'lldp.mgn.addr.ip4', rawBytesRange: [valueStart + 1, valueStart + addrStringLen] },
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

      case TLV_ORG_SPECIFIC: {
        // Three OUI bytes, one organisation-defined subtype byte, then a
        // payload only that organisation can read. Everything below this line
        // is per-OUI, which is why the two are decoded separately rather than
        // through one table: IEEE 802.3's subtype 1 and TIA's subtype 1 are
        // different structures that happen to share a number.
        if (length < 4) {
          fields.push({ name: 'Organization Specific TLV', value: `${length} bytes`, rawBytesRange: [cursor, valueEnd - 1], children: headerRows });
          break;
        }
        const oui = (value[0] << 16) | (value[1] << 8) | value[2];
        const subtype = value[3];
        const ouiText = `${value[0].toString(16).padStart(2, '0')}:${value[1].toString(16).padStart(2, '0')}:${value[2].toString(16).padStart(2, '0')}`;
        const children: ProtocolField[] = [
          ...headerRows,
          {
            name: 'Organization Unique Code',
            value: `${ouiText} (${OUI_NAMES[oui] ?? 'Unknown'})`,
            abbrev: 'lldp.orgtlv.oui', rawBytesRange: [valueStart, valueStart + 2],
          },
        ];
        let title = `Organization Specific TLV (OUI ${ouiText}, subtype ${subtype})`;

        if (oui === OUI_IEEE_802_3 && subtype === 1 && length >= 9) {
          // MAC/PHY Configuration/Status: what this port negotiated, and what
          // it was willing to negotiate. The gap between the two is how a
          // gigabit port ends up running at 100 Mbit and nobody notices.
          title = 'Ieee 802.3 - MAC/PHY Configuration/Status';
          const autoNeg = value[4];
          const caps = (value[5] << 8) | value[6];
          const mauType = (value[7] << 8) | value[8];
          const autoNegAt: [number, number] = [valueStart + 4, valueStart + 4];
          children.push(
            { name: 'IEEE 802.3 Subtype', value: `MAC/PHY Configuration/Status (0x${subtype.toString(16).padStart(2, '0')})`, abbrev: 'lldp.ieee.802_3.subtype', rawBytesRange: [valueStart + 3, valueStart + 3] },
            {
              name: 'Auto-Negotiation Support/Status', value: `0x${autoNeg.toString(16).padStart(2, '0')}`,
              abbrev: 'lldp.ieee.802_3.mac_phy_auto_neg_status', rawBytesRange: autoNegAt,
              children: [
                { name: 'Auto-Negotiation', value: autoNeg & 0x01 ? 'Supported' : 'Not supported', abbrev: 'lldp.ieee.802_3.mac_phy_auto_neg_status.supported', rawBytesRange: autoNegAt, bitfield: { bitOffset: 7, bitLength: 1, totalBits: 8 } },
                { name: 'Auto-Negotiation', value: autoNeg & 0x02 ? 'Enabled' : 'Not enabled', abbrev: 'lldp.ieee.802_3.mac_phy_auto_neg_status.enabled', rawBytesRange: autoNegAt, bitfield: { bitOffset: 6, bitLength: 1, totalBits: 8 } },
              ],
            },
            ...pmdCapabilityRows(caps, [valueStart + 5, valueStart + 6]),
            {
              name: 'Operational MAU Type',
              value: `${MAU_TYPE_NAMES[mauType] ?? 'Unknown'} (0x${mauType.toString(16).padStart(4, '0')})`,
              abbrev: 'lldp.ieee.802_3.pmd_mau_type', rawBytesRange: [valueStart + 7, valueStart + 8],
            },
          );
        } else if (oui === OUI_TIA_TR41 && subtype === 1 && length >= 7) {
          // LLDP-MED Media Capabilities: what an endpoint says it can do, and
          // which class of endpoint it claims to be. A phone that advertises
          // Network Policy is asking the switch for a voice VLAN.
          title = 'Telecommunications Industry Association TR-41 Committee - Media Capabilities';
          const caps = (value[4] << 8) | value[5];
          const classType = value[6];
          const capsAt: [number, number] = [valueStart + 4, valueStart + 5];
          children.push(
            { name: 'Media Subtype', value: `Media Capabilities (0x${subtype.toString(16).padStart(2, '0')})`, abbrev: 'lldp.media.subtype', rawBytesRange: [valueStart + 3, valueStart + 3] },
            {
              name: 'Capabilities', value: `0x${caps.toString(16).padStart(4, '0')}`,
              abbrev: 'lldp.media.subtype.caps', rawBytesRange: capsAt,
              children: flagRows(caps, MED_CAPABILITIES, 'lldp.media.subtype.caps', capsAt),
            },
            { name: 'Class Type', value: `${MED_CLASS_NAMES[classType] ?? 'Unknown'} (${classType})`, abbrev: 'lldp.media.subtype.class', rawBytesRange: [valueStart + 6, valueStart + 6] },
          );
        }

        fields.push({ name: title, value: '', rawBytesRange: [cursor, valueEnd - 1], children });
        break;
      }

      default: {
        // Anything else we do not decode: named honestly, with its type, its
        // length and its bytes, rather than dropped.
        fields.push({
          name: `Unknown TLV (type ${type})`,
          value: `${length} byte${length === 1 ? '' : 's'}`,
          rawBytesRange: [cursor, valueEnd - 1],
          children: headerRows,
        });
        break;
      }
    }

    cursor = valueEnd;
  }

  if (fields.length === 0) return null;

  // The reference analyzer's Info column, exactly: chassis, port, TTL, then
  // System Name and System Description when those TLVs are present.
  //
  // Each element is FOLLOWED by a space rather than joined by one, so the line
  // ends in whitespace - verified against tshark on synthetic frames at every
  // combination of present TLVs, not inferred from the single LLDP frame in
  // the fixtures. `join(' ')` is one character short on every LLDP frame, and
  // this is the third dissector here to trip on trailing space after SIP's
  // `" | "` and CDP's two.
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
    info: parts.length ? `${parts.join(' ')} ` : 'LLDP Data Unit',
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
