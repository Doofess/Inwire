/**
 * HomePlug AV management messages (ethertype 0x88e1) - what powerline
 * adapters say to each other and to the host they bridge: who the central
 * coordinator is, the network key, link statistics, firmware queries. Every
 * adapter on a home's wiring sends them, and the host sees the ones addressed
 * to it or broadcast.
 *
 * The header is all this reads: the version, the message type, the
 * fragmentation info, and a vendor message's OUI. The type is named from the
 * table the OUI selects - Qualcomm Atheros's, which nearly every adapter sold
 * runs on, or ST/IoTecha's - generated from the reference's own tables into
 * `homeplugNames.ts`. The body is left as bytes: there are some 240 message
 * types, each a layout of its own.
 *
 * Shapes taken from `tshark -T pdml` on frames built for every branch below
 * (`scripts/homeplug/dissect.ts`), including the reference's quirks:
 *
 * - FMI follows the type whenever the version BYTE is not zero, though only
 *   bit 0 is shown as the version - so a version byte of 2 reads "1.0" and
 *   still has an FMI.
 * - A version 1.0 public message has no FMI, yet the reference reads the same
 *   two bytes as fragment fields under a "Public MME" heading.
 * - Any type from 0x8000 up is a vendor message and carries an OUI, Manufacturer
 *   Specific (MSB 4) as well as Vendor Specific (MSB 5).
 * - The Info column names an unknown type unpadded (`Unknown 0x2`) and an
 *   unknown OUI the same way (`OUI:0x10203`).
 */
import type { ProtocolField } from '../../types/packet';
import type { LeafResult } from './dispatch';
import { QUALCOMM, ST_IOTECHA, STANDARD } from './homeplugNames';

const OUI_QUALCOMM = 0x00b052;
const OUI_ST_IOTECHA = 0x0080e1;
const VENDORS: Readonly<Record<number, string>> = {
  [OUI_QUALCOMM]: 'Qualcomm Atheros',
  [OUI_ST_IOTECHA]: 'ST/IoTecha',
  0x644d70: 'dSPACE GmbH',
};
const LSB_NAMES = ['Request', 'Confirm', 'Indication', 'Response'];
const MSB_NAMES = [
  'STA - Central Coordinator', 'Proxy Coordinator', 'Central Coordinator - Central Coordinator',
  'STA - STA', 'Manufacturer Specific', 'Vendor Specific',
];

const hex = (n: number, digits: number) => `0x${n.toString(16).padStart(digits, '0')}`;
const bits = (bitOffset: number, bitLength: number) => ({ bitOffset, bitLength, totalBits: 8 });

/** The three fragment fields over two bytes, as both FMI and "Public MME" draw them. */
function fragmentRows(b: Uint8Array, at: number): ProtocolField[] {
  return [
    { name: 'Fragment count', value: b[at] >> 4, abbrev: 'homeplug_av.public.frag_count', rawBytesRange: [at, at], bitfield: bits(0, 4) },
    { name: 'Fragment index', value: b[at] & 0x0f, abbrev: 'homeplug_av.public.frag_index', rawBytesRange: [at, at], bitfield: bits(4, 4) },
    { name: 'Fragment Sequence number', value: b[at + 1], abbrev: 'homeplug_av.public.frag_seqnum', rawBytesRange: [at + 1, at + 1] },
  ];
}

export function dissectHomeplugAv(b: Uint8Array, start: number, end: number): LeafResult | null {
  if (start + 3 > end) return null;
  const version = b[start];
  const mmtype = b[start + 1] | (b[start + 2] << 8);
  const lsb = mmtype & 0x3;
  const msb = mmtype >> 13;
  const hasFmi = version !== 0;
  let at = start + 3;
  if (hasFmi && at + 2 > end) return null;
  const fmiAt = at;
  if (hasFmi) at += 2;

  const vendor = mmtype >= 0x8000;
  if (vendor && at + 3 > end) return null;
  const oui = vendor ? (b[at] << 16) | (b[at + 1] << 8) | b[at + 2] : -1;
  const table = oui === OUI_QUALCOMM ? QUALCOMM : oui === OUI_ST_IOTECHA ? ST_IOTECHA : vendor ? null : STANDARD;
  const typeAbbrev = oui === OUI_QUALCOMM ? 'homeplug_av.mmhdr.mmtype.qualcomm'
    : oui === OUI_ST_IOTECHA ? 'homeplug_av.mmhdr.mmtype.st' : 'homeplug_av.mmhdr.mmtype';
  const typeName = table?.[mmtype];

  const fields: Record<string, string | number> = {
    'homeplug_av.mmhdr.mmver': version & 1,
    [typeAbbrev]: mmtype,
    'homeplug_av.mmhdr.mmtype.lsb': lsb,
    'homeplug_av.mmhdr.mmtype.msb': msb,
  };
  const header: ProtocolField[] = [
    { name: 'Version', value: `${version & 1 ? '1.1' : '1.0'} (${version & 1})`, abbrev: 'homeplug_av.mmhdr.mmver', rawBytesRange: [start, start], bitfield: bits(7, 1) },
    {
      name: 'Type', value: `${typeName ?? 'Unknown'} (${hex(mmtype, 4)})`, abbrev: typeAbbrev, rawBytesRange: [start + 1, start + 2],
      children: [
        { name: 'LSB', value: `${LSB_NAMES[lsb]} (${hex(lsb, 1)})`, abbrev: 'homeplug_av.mmhdr.mmtype.lsb', rawBytesRange: [start + 1, start + 1], bitfield: bits(6, 2) },
        { name: 'MSB', value: `${MSB_NAMES[msb] ?? 'Unknown'} (${hex(msb, 1)})`, abbrev: 'homeplug_av.mmhdr.mmtype.msb', rawBytesRange: [start + 2, start + 2], bitfield: bits(0, 3) },
      ],
    },
  ];
  if (hasFmi) {
    const fmi = b[fmiAt] | (b[fmiAt + 1] << 8);
    fields['homeplug_av.mmhdr.fmi'] = fmi;
    header.push({ name: 'Fragmentation Info', value: hex(fmi, 4), abbrev: 'homeplug_av.mmhdr.fmi', rawBytesRange: [fmiAt, fmiAt + 1], children: fragmentRows(b, fmiAt) });
  }
  const rows: ProtocolField[] = [
    { name: 'MAC Management Header', value: '', abbrev: 'homeplug_av.mmhdr', rawBytesRange: [start, at - 1], children: header },
  ];

  let info: string;
  const unknownType = `Unknown 0x${mmtype.toString(16)}`;
  if (vendor) {
    fields['homeplug_av.vendor.oui'] = oui;
    const vendorName = VENDORS[oui];
    const vendorRows: ProtocolField[] = [
      { name: 'OUI', value: `${vendorName ?? 'Unknown'} (${hex(oui, 6)})`, abbrev: 'homeplug_av.vendor.oui', rawBytesRange: [at, at + 2] },
    ];
    let vendorEnd = at + 2;
    if (oui === OUI_ST_IOTECHA && at + 7 <= end) {
      // ST/IoTecha's messages open with a version and three reserved bytes,
      // which the reference draws inside the vendor heading.
      vendorRows.push(
        { name: 'MME version', value: hex(b[at + 3], 2), abbrev: 'homeplug_av.st_iotecha.mmever', rawBytesRange: [at + 3, at + 3] },
        { name: 'Reserved', value: [b[at + 4], b[at + 5], b[at + 6]].map((x) => x.toString(16).padStart(2, '0')).join(''), abbrev: 'homeplug_av.st_iotecha.rsvd', rawBytesRange: [at + 4, at + 6] },
      );
      vendorEnd = at + 6;
    }
    rows.push({ name: 'Vendor MME', value: '', abbrev: 'homeplug_av.vendor', rawBytesRange: [at, vendorEnd], children: vendorRows });
    at = vendorEnd + 1;
    info = table !== null ? `${vendorName}, ${typeName ?? unknownType}` : vendorName ?? `OUI:0x${oui.toString(16)}`;
  } else {
    if (!hasFmi && at + 2 <= end) {
      rows.push({ name: 'Public MME', value: '', abbrev: 'homeplug_av.public', rawBytesRange: [at, at + 1], children: fragmentRows(b, at) });
      at += 2;
    }
    info = typeName ?? unknownType;
  }
  if (at < end) rows.push({ name: 'Payload', value: `${end - at} bytes`, rawBytesRange: [at, end - 1] });

  return {
    protocolLabel: 'HomePlug AV',
    info,
    layer: { name: 'HomePlug AV protocol', summary: info, fields: rows, rawBytesRange: [start, end - 1] },
    fields,
  };
}
