/**
 * CDP - the Cisco Discovery Protocol, on 802.3 with an LLC/SNAP header
 * (OUI 00:00:0C, PID 0x2000).
 *
 *   Device ID: switch.example.com  Port ID: GigabitEthernet0/1
 *
 * The proprietary twin of LLDP, and on a Cisco network it is usually the one
 * that is actually switched on. Both answer the question a capture cannot
 * otherwise answer at all: **what is on the other end of this cable** - which
 * switch, which port, which VLAN. `services/networkFacts.ts` already records
 * an LLDP neighbour and reports "no neighbour LLDP seen" otherwise; on the
 * networks where that message is most often wrong, CDP is why.
 *
 * The frame is a two-byte version and TTL, a checksum, then TLVs. Two details
 * matter for reading it safely. A TLV's **length includes its own four-byte
 * header**, so a length under 4 is malformed rather than empty and must end
 * the walk - a zero-length TLV read as "advance by 0" is an infinite loop on
 * hostile input. And the **Device ID is not a hostname**: on a switch with no
 * configured name it is the chassis serial number, which is why it is reported
 * as the device id it is called rather than folded into name resolution.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address, formatMac } from '../addressFormat';

export interface CdpResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** The SNAP protocol id CDP travels under, and the OUI that gives it meaning. */
export const CDP_SNAP_PID = 0x2000;
export const CISCO_OUI = 0x00000c;

const DEVICE_ID = 0x0001, ADDRESSES = 0x0002, PORT_ID = 0x0003, CAPABILITIES = 0x0004,
  SOFTWARE_VERSION = 0x0005, PLATFORM = 0x0006, NATIVE_VLAN = 0x000a,
  DUPLEX = 0x000b, VTP_DOMAIN = 0x0009, MANAGEMENT_ADDRESSES = 0x0016;

const TLV_NAMES: Record<number, string> = {
  [DEVICE_ID]: 'Device ID',
  [ADDRESSES]: 'Addresses',
  [PORT_ID]: 'Port ID',
  [CAPABILITIES]: 'Capabilities',
  [SOFTWARE_VERSION]: 'Software Version',
  [PLATFORM]: 'Platform',
  0x0007: 'IP Prefix/Gateway',
  0x0008: 'Protocol Hello',
  [VTP_DOMAIN]: 'VTP Management Domain',
  [NATIVE_VLAN]: 'Native VLAN',
  [DUPLEX]: 'Duplex',
  0x000e: 'VoIP VLAN Reply',
  0x000f: 'VoIP VLAN Query',
  0x0010: 'Power Consumption',
  0x0012: 'Trust Bitmap',
  0x0013: 'Untrusted Port CoS',
  [MANAGEMENT_ADDRESSES]: 'Management Addresses',
  0x001a: 'Power Available',
};

/** The capability bits, which say what the neighbour *is*. */
const CAPABILITY_BITS: [number, string][] = [
  [0x01, 'Router'],
  [0x02, 'Transparent Bridge'],
  [0x04, 'Source Route Bridge'],
  [0x08, 'Switch'],
  [0x10, 'Host'],
  [0x20, 'IGMP capable'],
  [0x40, 'Repeater'],
];

/** A TLV's length counts its own type and length fields. */
const TLV_HEADER_BYTES = 4;

const utf8 = new TextDecoder('utf-8', { fatal: false });

/** What the neighbour reports itself to be, or `Unknown` when nothing is set. */
function capabilityNames(value: number): string {
  const names = CAPABILITY_BITS.filter(([bit]) => (value & bit) !== 0).map(([, name]) => name);
  return names.length > 0 ? names.join(', ') : 'Unknown';
}

export function dissectCdp(bytes: Uint8Array, start: number, end: number): CdpResult | null {
  if (start + 4 > end) return null;
  const version = bytes[start];
  // Only versions 1 and 2 exist. This is the whole of the fingerprint that is
  // not the SNAP header, which is fine because the SNAP header is specific.
  if (version !== 1 && version !== 2) return null;
  const ttl = bytes[start + 1];
  const checksum = (bytes[start + 2] << 8) | bytes[start + 3];

  const fields: Record<string, string | number> = {
    'cdp.version': version,
    'cdp.ttl': ttl,
    'cdp.checksum': checksum,
  };
  const rows: ProtocolField[] = [
    { name: 'Version', value: version, abbrev: 'cdp.version', rawBytesRange: [start, start] },
    { name: 'TTL', value: `${ttl} seconds`, abbrev: 'cdp.ttl',
      rawBytesRange: [start + 1, start + 1] },
    { name: 'Checksum', value: `0x${checksum.toString(16).padStart(4, '0')}`,
      abbrev: 'cdp.checksum', rawBytesRange: [start + 2, start + 3] },
  ];

  let deviceId = '';
  let portId = '';
  let p = start + 4;
  while (p + TLV_HEADER_BYTES <= end) {
    const type = (bytes[p] << 8) | bytes[p + 1];
    const length = (bytes[p + 2] << 8) | bytes[p + 3];
    // A length shorter than its own header cannot be advanced past, so this
    // both rejects malformed input and is what stops the walk spinning.
    if (length < TLV_HEADER_BYTES || p + length > end) break;
    const valueStart = p + TLV_HEADER_BYTES;
    const valueEnd = p + length;
    const name = TLV_NAMES[type] ?? `Unknown (0x${type.toString(16).padStart(4, '0')})`;
    const text = () => utf8.decode(bytes.subarray(valueStart, valueEnd));

    let rendered: string;
    switch (type) {
      case DEVICE_ID:
        deviceId = text();
        fields['cdp.deviceid'] = deviceId;
        rendered = deviceId;
        break;
      case PORT_ID:
        portId = text();
        fields['cdp.portid'] = portId;
        rendered = portId;
        break;
      case SOFTWARE_VERSION:
        fields['cdp.software_version'] = text();
        rendered = text();
        break;
      case PLATFORM:
        fields['cdp.platform'] = text();
        rendered = text();
        break;
      case VTP_DOMAIN:
        rendered = text();
        break;
      case CAPABILITIES: {
        const value = valueEnd - valueStart >= 4
          ? ((bytes[valueStart] << 24) | (bytes[valueStart + 1] << 16)
            | (bytes[valueStart + 2] << 8) | bytes[valueStart + 3]) >>> 0
          : 0;
        fields['cdp.capabilities'] = value;
        rendered = capabilityNames(value);
        break;
      }
      case NATIVE_VLAN: {
        const vlan = valueEnd - valueStart >= 2
          ? (bytes[valueStart] << 8) | bytes[valueStart + 1] : 0;
        fields['cdp.native_vlan'] = vlan;
        rendered = `${vlan}`;
        break;
      }
      case DUPLEX:
        rendered = valueEnd > valueStart && bytes[valueStart] !== 0 ? 'Full' : 'Half';
        fields['cdp.duplex'] = rendered;
        break;
      case ADDRESSES:
      case MANAGEMENT_ADDRESSES: {
        const found = readAddresses(bytes, valueStart, valueEnd);
        if (found.length > 0 && type === ADDRESSES) fields['cdp.nrgyz.ip_address'] = found[0];
        rendered = found.length > 0 ? found.join(', ') : `${valueEnd - valueStart} bytes`;
        break;
      }
      default:
        rendered = `${valueEnd - valueStart} bytes`;
    }

    rows.push({ name, value: rendered, rawBytesRange: [p, valueEnd - 1] });
    p = valueEnd;
  }

  // Each Info element is FOLLOWED by two spaces rather than joined by them, so
  // the line ends in whitespace. That is the reference analyzer's format and
  // not an artefact of building it - a `join('  ')` here produces something
  // one character different on every CDP frame, and a `trimEnd()` anywhere in
  // the chain would undo this. Both halves are optional: a neighbour that
  // names only its port still says so.
  let info = '';
  if (deviceId) info += `Device ID: ${deviceId}  `;
  if (portId) info += `Port ID: ${portId}  `;

  return {
    protocolLabel: 'CDP',
    info,
    fields,
    layer: {
      name: 'Cisco Discovery Protocol',
      summary: 'Cisco Discovery Protocol',
      rawBytesRange: [start, Math.max(start, end - 1)],
      fields: rows,
    },
  };
}

/**
 * The address list a CDP Addresses TLV carries.
 *
 * A count, then per address a protocol type, a protocol id and a length. Only
 * IPv4 and IPv6 are rendered - the format can carry CLNS, DECnet and five more
 * dead protocols, and a length is the only thing that makes it safe to skip
 * one without knowing what it was.
 */
function readAddresses(bytes: Uint8Array, start: number, end: number): string[] {
  if (start + 4 > end) return [];
  const count = ((bytes[start] << 24) | (bytes[start + 1] << 16)
    | (bytes[start + 2] << 8) | bytes[start + 3]) >>> 0;
  const out: string[] = [];
  let p = start + 4;
  for (let i = 0; i < count && p + 5 <= end; i++) {
    const protocolLength = bytes[p + 1];
    const addressLengthAt = p + 2 + protocolLength;
    if (addressLengthAt + 2 > end) break;
    const addressLength = (bytes[addressLengthAt] << 8) | bytes[addressLengthAt + 1];
    const addressAt = addressLengthAt + 2;
    if (addressAt + addressLength > end) break;
    if (addressLength === 4) out.push(formatIpv4Address(bytes, addressAt));
    else if (addressLength === 6) out.push(formatMac(bytes.subarray(addressAt, addressAt + 6)));
    p = addressAt + addressLength;
  }
  return out;
}
