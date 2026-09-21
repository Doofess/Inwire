/**
 * The link layer: what sits in front of the network header, and how much of it.
 *
 * Until Phase 6 this was assumed rather than read. Every frame was decoded as
 * Ethernet II with the network header at offset 14, and the capture file's own
 * declaration of what its frames are - the pcap header's `network` field, the
 * pcapng IDB's `LinkType` - was parsed and then ignored. That is fine for the
 * captures this app takes itself, which are always Ethernet, and wrong for
 * every other kind:
 *
 *   * a **Linux cooked** capture (`tcpdump -i any`) puts a 16- or 20-byte
 *     pseudo-header in front, so the IP header was read 2 or 6 bytes early and
 *     the frame came out as garbage with a plausible-looking version nibble;
 *   * a **raw IP** capture has no link layer at all, so the first 14 bytes of
 *     the IP header were consumed as MAC addresses;
 *   * a **loopback** capture starts with a 4-byte address family;
 *   * and an **802.3 frame with an LLC header** - which is what every STP BPDU
 *     on the wire is - had its length field read as an ethertype.
 *
 * The last of those was visible in this repo's own fixture: STP frames
 * dissected correctly only because the STP dissector reached past an LLC header
 * nothing had described, so the tree jumped from Ethernet straight to Spanning
 * Tree and `frameProtocols` never contained `llc`.
 *
 * This module reads the link layer the file says it has, and returns where the
 * network layer starts along with what it will be. Nothing downstream of it
 * needs to know which of the five it was.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatMac } from '../addressFormat';
import { resolveMacVendor } from '../macVendors';
import { LINKTYPE } from '../dissect/types';
import { labelForEtherType } from './l2';

/** An ethertype value at or below this is really an 802.3 length. */
const MAX_802_3_LENGTH = 1500;

/**
 * The unnumbered-format command, from the five bits `000. 00..` of the
 * control byte.
 *
 * Only the handful an ordinary capture contains are named; anything else is
 * shown as its number rather than guessed at, which is the same rule the SAP
 * table above follows.
 */
function unnumberedCommand(control: number): string {
  const cmd = ((control & 0xe0) >> 3) | ((control & 0x0c) >> 2);
  const named: Record<number, string> = {
    0x00: 'Unnumbered Information',
    0x03: 'Disconnected Mode',
    0x04: 'Unnumbered Poll',
    0x08: 'Disconnect',
    0x0c: 'Unnumbered Acknowledgment',
    0x0f: 'Set Asynchronous Balanced Mode Extended',
    0x11: 'Frame Reject',
    0x17: 'Exchange Identification',
    0x1c: 'Test',
  };
  return `${named[cmd] ?? 'Unknown'} (0x${cmd.toString(16).padStart(2, '0')})`;
}

export interface LinkLayerResult {
  /** The link-layer tree layers, outermost first. Empty for raw IP. */
  layers: ProtocolLayer[];
  fields: Record<string, string | number>;
  /** Where the network-layer dispatch should start reading. */
  l3Offset: number;
  /**
   * What to dispatch on: an ethertype for everything that has one, and the
   * 802.3 length for an LLC frame with no SNAP header (which is how the
   * caller still recognises one).
   */
  etherType: number;
  srcMac?: string;
  dstMac?: string;
  /** The Frame layer's "Encapsulation type" row. */
  encapsulation: string;
  /**
   * Where the LLC header begins, when the frame has one. The STP dissector
   * takes this offset - a BPDU is defined relative to its LLC header, not to
   * the frame.
   */
  llcOffset?: number;
  llcDsap?: number;
  /**
   * The SNAP header's organisation code, when the frame has one.
   *
   * A SNAP protocol id means nothing on its own: it is only unique **within**
   * an OUI. Cisco's 0x2000 under OUI 00:00:0C is CDP, and 0x2000 under
   * OUI 00:00:00 would be an ethertype nobody has assigned. `etherType` alone
   * cannot express that difference, so the OUI travels beside it.
   */
  snapOui?: number;
  /** True when the link layer ran off the end of a truncated capture. */
  truncated: boolean;
}

/** Wireshark's name and number for each link type, for the Frame layer. */
const ENCAPSULATION: Record<number, string> = {
  [LINKTYPE.NULL]: 'NULL/Loopback (0)',
  [LINKTYPE.LOOP]: 'OpenBSD loopback (108)',
  [LINKTYPE.ETHERNET]: 'Ethernet (1)',
  [LINKTYPE.RAW_IP]: 'Raw IP (101)',
  [LINKTYPE.LINUX_SLL]: 'Linux cooked-mode capture v1 (113)',
  [LINKTYPE.LINUX_SLL2]: 'Linux cooked-mode capture v2 (276)',
};

export function describeEtherType(etherType: number): string {
  switch (etherType) {
    case 0x0800: return 'IPv4';
    case 0x86dd: return 'IPv6';
    case 0x0806: return 'ARP';
    case 0x8100: return '802.1Q Virtual LAN';
    case 0x88a8: return '802.1ad Provider Bridge (QinQ)';
    // Everything this switch does not name falls through to the ethertype
    // table the dissectors share, so a frame the app can already label "LLDP"
    // in the Protocol column does not simultaneously call its own ethertype
    // "Unknown" one row into the Ethernet layer.
    default: return labelForEtherType(etherType) ?? 'Unknown';
  }
}

/**
 * The Address / LG bit / IG bit rows under a MAC address.
 *
 * Lives here rather than in pcapParser because this module owns the Ethernet
 * layer now, and the SLL headers show a source MAC with the same three rows.
 */
export function macAddressFields(mac: string, offset: number, isDestination = false): ProtocolField[] {
  const firstByte = parseInt(mac.slice(0, 2), 16);
  const locallyAdministered = (firstByte & 0x02) !== 0;
  const groupAddress = (firstByte & 0x01) !== 0;

  return [
    // Wireshark's own label for `eth.addr` is 'Address', and it emits one
    // under each of Source and Destination - so both carry the abbrev here.
    { name: 'Address', value: resolveMacVendor(mac), abbrev: 'eth.addr', rawBytesRange: [offset, offset + 5] },
    {
      name: 'LG bit',
      value: locallyAdministered
        ? 'Locally administered address (this is NOT the factory default)'
        : 'Globally unique address (factory default)',
      // Only the destination's row is `eth.lg`, for the same reason `eth.ig`
      // below is: an abbrev names one field, and the source's LG bit is a
      // different fact about a different address.
      ...(isDestination ? { abbrev: 'eth.lg' } : {}),
      rawBytesRange: [offset, offset + 2],
      bitfield: { bitOffset: 6, bitLength: 1, totalBits: 24 },
    },
    {
      name: 'IG bit',
      value: groupAddress
        ? 'Group address (multicast/broadcast)'
        : 'Individual address (unicast)',
      // Only the destination's row is `eth.ig`: an abbrev names one field, and
      // the source's group bit is a different fact about a different address.
      ...(isDestination ? { abbrev: 'eth.ig' } : {}),
      rawBytesRange: [offset, offset + 2],
      bitfield: { bitOffset: 7, bitLength: 1, totalBits: 24 },
    },
  ];
}

/**
 * The network layer of a header-less capture, from the IP version nibble.
 *
 * Raw IP and the BSD loopback header both leave the caller to work out which
 * of the two families it is looking at; loopback's own address-family value is
 * host-endian and differs per OS (AF_INET6 is 24 on Darwin, 28 on FreeBSD, 30
 * on NetBSD), so the version nibble is both simpler and more reliable.
 */
function etherTypeFromVersion(bytes: Uint8Array, offset: number): number {
  if (offset >= bytes.length) return 0;
  const version = bytes[offset] >> 4;
  return version === 6 ? 0x86dd : version === 4 ? 0x0800 : 0;
}

export function dissectLinkLayer(rawBytes: Uint8Array, linktype: number): LinkLayerResult {
  const encapsulation = ENCAPSULATION[linktype] ?? `Unknown (${linktype})`;

  switch (linktype) {
    case LINKTYPE.RAW_IP:
      // No link layer at all: the frame IS the IP datagram. Decoding this as
      // Ethernet consumed the first 14 bytes of the IP header as addresses.
      return {
        layers: [], fields: {}, l3Offset: 0,
        etherType: etherTypeFromVersion(rawBytes, 0),
        encapsulation, truncated: false,
      };

    case LINKTYPE.NULL:
    // DLT_LOOP is DLT_NULL with the address family fixed big-endian.
    // `dissectNull` reads both orders and lets the IP version nibble decide,
    // so it is already right for this one - which is why this is a second
    // label on the same case rather than a decoder of its own.
    case LINKTYPE.LOOP:
      return dissectNull(rawBytes, encapsulation);

    case LINKTYPE.LINUX_SLL:
      return dissectSll(rawBytes, encapsulation);

    case LINKTYPE.LINUX_SLL2:
      return dissectSll2(rawBytes, encapsulation);

    case LINKTYPE.ETHERNET:
    default:
      // An unknown link type is decoded as Ethernet, which is what this app
      // did for every capture until now and is right far more often than any
      // other guess. The Frame layer names the type it could not identify, so
      // a nonsense dissection has something to be traced back to.
      return dissectEthernet(rawBytes, encapsulation);
  }
}

// --- Ethernet ----------------------------------------------------------------

function dissectEthernet(rawBytes: Uint8Array, encapsulation: string): LinkLayerResult {
  if (rawBytes.length < 14) {
    return { layers: [], fields: {}, l3Offset: rawBytes.length, etherType: 0, encapsulation, truncated: true };
  }
  const dstMac = formatMac(rawBytes.slice(0, 6));
  const srcMac = formatMac(rawBytes.slice(6, 12));
  const etherType = (rawBytes[12] << 8) | rawBytes[13];

  const layers: ProtocolLayer[] = [{
    name: 'Ethernet II',
    summary: `Ethernet II, Src: ${srcMac}, Dst: ${dstMac}`,
    rawBytesRange: [0, 13],
    fields: [
      { name: 'Destination', value: resolveMacVendor(dstMac), abbrev: 'eth.dst', rawBytesRange: [0, 5], children: macAddressFields(dstMac, 0, true) },
      { name: 'Source', value: resolveMacVendor(srcMac), abbrev: 'eth.src', rawBytesRange: [6, 11], children: macAddressFields(srcMac, 6) },
      etherType <= MAX_802_3_LENGTH
        // An 802.3 frame's bytes 12-13 are a length, not a type, and calling
        // it "Type: 0x0027 (Unknown)" is a straightforwardly wrong reading of
        // the wire.
        ? { name: 'Length', value: etherType, rawBytesRange: [12, 13] }
        : { name: 'Type', value: `0x${etherType.toString(16).padStart(4, '0')} (${describeEtherType(etherType)})`, abbrev: 'eth.type', rawBytesRange: [12, 13] },
      { name: '[Stream index]', value: 0, generated: true },
    ],
  }];

  const fields: Record<string, string | number> = {
    'eth.src': srcMac,
    'eth.dst': dstMac,
    // The destination's group bit, as a field rather than something a rule has
    // to read out of the frame's bytes. See the registry entry.
    'eth.ig': (parseInt(dstMac.slice(0, 2), 16) & 0x01) !== 0 ? 1 : 0,
  };
  if (etherType > MAX_802_3_LENGTH) fields['eth.type'] = etherType;

  const result: LinkLayerResult = {
    layers, fields, l3Offset: 14, etherType, srcMac, dstMac, encapsulation, truncated: false,
  };

  // 802.1Q / 802.1ad (QinQ) VLAN tags: a 4-byte tag (2-byte TCI + 2-byte real
  // ethertype) can appear between the MACs and the "real" ethertype, and can
  // repeat for double-tagged trunk traffic. Strip every tag we find so the
  // network dispatch sees the correct offset and correct ethertype, exactly
  // how Wireshark's packet-vlan.c walks nested tags.
  stripVlanTags(rawBytes, result);
  readLlc(rawBytes, result);
  return result;
}

function stripVlanTags(rawBytes: Uint8Array, out: LinkLayerResult): void {
  let depth = 0;
  while (
    (out.etherType === 0x8100 || out.etherType === 0x88a8)
    && rawBytes.length >= out.l3Offset + 4 && depth < 8
  ) {
    const at = out.l3Offset;
    const tci = (rawBytes[at] << 8) | rawBytes[at + 1];
    const priority = (tci >> 13) & 0x7;
    const dei = (tci >> 12) & 0x1;
    const vlanId = tci & 0x0fff;
    const inner = (rawBytes[at + 2] << 8) | rawBytes[at + 3];

    out.layers.push({
      name: '802.1Q Virtual LAN',
      summary: `802.1Q Virtual LAN, PRI: ${priority}, DEI: ${dei}, ID: ${vlanId}`,
      rawBytesRange: [at, at + 3],
      fields: [
        { name: 'Priority', value: priority, rawBytesRange: [at, at] },
        { name: 'Drop Eligible Indicator (DEI)', value: dei, rawBytesRange: [at, at] },
        { name: 'VLAN ID', value: vlanId, abbrev: 'vlan.id', rawBytesRange: [at, at + 1] },
        { name: 'Type', value: `0x${inner.toString(16).padStart(4, '0')} (${describeEtherType(inner)})`, rawBytesRange: [at + 2, at + 3] },
      ],
    });
    out.fields['vlan.id'] = vlanId;
    out.etherType = inner;
    out.l3Offset = at + 4;
    depth++;
  }
}

/** DSAP values worth naming; everything else is shown as its hex value. */
const SAP_NAMES: Record<number, string> = {
  0x00: 'NULL LSAP',
  0x02: 'Individual LLC Sublayer Management',
  0x06: 'TCP/IP',
  0x42: 'Spanning Tree BPDU',
  0xaa: 'SNAP',
  0xe0: 'NetWare',
  0xf0: 'NetBIOS',
  0xfe: 'ISO Network Layer',
  0xff: 'Global LSAP',
};

function sapName(sap: number): string {
  return SAP_NAMES[sap & 0xfe] ?? SAP_NAMES[sap] ?? 'Unknown';
}

/**
 * The 802.2 LLC header, and the SNAP header that may follow it.
 *
 * An 802.3 frame's type/length field is a length, and the payload begins with
 * DSAP / SSAP / Control rather than with a network header. When the SAPs are
 * both 0xAA and the control byte is 0x03 (Unnumbered Information), five more
 * bytes follow - a 3-byte OUI and a 2-byte ethertype - and *that* ethertype is
 * what the network dispatch should use. This is how IPv4 is carried over
 * 802.11 and over 802.3 on older equipment.
 */
function readLlc(rawBytes: Uint8Array, out: LinkLayerResult): void {
  if (out.etherType > MAX_802_3_LENGTH) return;
  const at = out.l3Offset;
  if (at + 3 > rawBytes.length) { out.truncated = true; return; }

  const dsap = rawBytes[at];
  const ssap = rawBytes[at + 1];
  const control = rawBytes[at + 2];
  out.llcOffset = at;
  out.llcDsap = dsap;

  // A control field whose low two bits are not 11 is a 2-byte (numbered)
  // control field. Only the 1-byte unnumbered form carries SNAP.
  const unnumbered = (control & 0x03) === 0x03;
  const controlLen = unnumbered ? 1 : 2;
  const snap = unnumbered && dsap === 0xaa && ssap === 0xaa && control === 0x03;
  const headerEnd = at + 2 + controlLen + (snap ? 5 : 0);

  const fields = [
    {
      name: 'DSAP',
      value: `${sapName(dsap)} (0x${dsap.toString(16).padStart(2, '0')})`,
      abbrev: 'llc.dsap',
      rawBytesRange: [at, at] as [number, number],
      children: [{
        // The seven bits that are the service access point, which the
        // reference draws above the IG bit because that is the order they sit
        // in: `0100 001. = SAP`, then `.... ...0 = IG Bit`.
        name: 'SAP',
        value: sapName(dsap),
        abbrev: 'llc.dsap.sap',
        rawBytesRange: [at, at] as [number, number],
        bitfield: { bitOffset: 0, bitLength: 7, totalBits: 8 },
      }, {
        name: `.... ...${dsap & 1} = IG Bit`,
        value: (dsap & 1) ? 'Group' : 'Individual',
        rawBytesRange: [at, at] as [number, number],
      }],
    },
    {
      name: 'SSAP',
      value: `${sapName(ssap)} (0x${ssap.toString(16).padStart(2, '0')})`,
      abbrev: 'llc.ssap',
      rawBytesRange: [at + 1, at + 1] as [number, number],
      children: [{
        name: 'SAP',
        value: sapName(ssap),
        abbrev: 'llc.ssap.sap',
        rawBytesRange: [at + 1, at + 1] as [number, number],
        bitfield: { bitOffset: 0, bitLength: 7, totalBits: 8 },
      }, {
        name: `.... ...${ssap & 1} = CR Bit`,
        value: (ssap & 1) ? 'Response' : 'Command',
        abbrev: 'llc.ssap.cr',
        rawBytesRange: [at + 1, at + 1] as [number, number],
      }],
    },
    {
      name: 'Control field',
      value: unnumbered
        ? `U, func=UI (0x${control.toString(16).padStart(2, '0')})`
        : `0x${control.toString(16).padStart(2, '0')}`,
      abbrev: 'llc.control',
      rawBytesRange: [at + 2, at + 1 + controlLen] as [number, number],
      // What the control byte says it is. An unnumbered frame carries the
      // command in five scattered bits - 000. 00.. - which is why it is read
      // here rather than left as two hex digits.
      children: unnumbered
        ? [
          {
            name: 'Frame type', value: `Unnumbered frame (0x0${control & 0x03})`,
            abbrev: 'llc.control.ftype',
            rawBytesRange: [at + 2, at + 2] as [number, number],
            bitfield: { bitOffset: 6, bitLength: 2, totalBits: 8 },
          },
          {
            name: 'Command',
            value: unnumberedCommand(control),
            abbrev: 'llc.control.u_modifier_cmd',
            rawBytesRange: [at + 2, at + 2] as [number, number],
          },
        ]
        : [],
    },
  ];

  if (snap && headerEnd <= rawBytes.length) {
    const oui = (rawBytes[at + 3] << 16) | (rawBytes[at + 4] << 8) | rawBytes[at + 5];
    const snapType = (rawBytes[at + 6] << 8) | rawBytes[at + 7];
    fields.push(
      {
        name: 'Organization Code',
        value: oui === 0 ? 'Encapsulated Ethernet (00:00:00)' : `0x${oui.toString(16).padStart(6, '0')}`,
        abbrev: 'llc.oui',
        rawBytesRange: [at + 3, at + 5] as [number, number],
      } as typeof fields[number],
      {
        name: 'Type',
        value: `0x${snapType.toString(16).padStart(4, '0')} (${describeEtherType(snapType)})`,
        abbrev: 'llc.type',
        rawBytesRange: [at + 6, at + 7] as [number, number],
      } as typeof fields[number],
    );
    // SNAP's ethertype is the real one: dispatch continues on it, past both
    // headers, exactly as if the frame had been Ethernet II all along.
    out.etherType = snapType;
    out.l3Offset = headerEnd;
    out.snapOui = oui;
    out.fields['llc.oui'] = oui;
    out.fields['llc.type'] = snapType;
    out.fields['eth.type'] = snapType;
  } else {
    // Plain LLC. The payload is whatever the DSAP says it is (a BPDU, for
    // 0x42), and the caller dispatches on `llcDsap`. `l3Offset` stays at the
    // LLC header, because a BPDU's own offsets are defined relative to it.
    out.fields['llc.dsap'] = dsap;
    out.fields['llc.ssap'] = ssap;
  }
  out.fields['llc.control'] = control;
  if (snap) {
    out.fields['llc.dsap'] = dsap;
    out.fields['llc.ssap'] = ssap;
  }

  out.layers.push({
    name: 'Logical-Link Control',
    summary: 'Logical-Link Control',
    rawBytesRange: [at, Math.min(rawBytes.length - 1, headerEnd - 1)],
    fields,
  });
}

// --- BSD loopback -------------------------------------------------------------

function dissectNull(rawBytes: Uint8Array, encapsulation: string): LinkLayerResult {
  if (rawBytes.length < 4) {
    return { layers: [], fields: {}, l3Offset: rawBytes.length, etherType: 0, encapsulation, truncated: true };
  }
  // The 4-byte address family is written in the *capturing host's* byte order
  // and is not marked, so it cannot be read reliably. Both orders are checked
  // against the small set of families that ever appear here, and the IP
  // version nibble settles what the header actually precedes.
  const le = rawBytes[0] | (rawBytes[1] << 8) | (rawBytes[2] << 16) | (rawBytes[3] << 24);
  const be = (rawBytes[0] << 24) | (rawBytes[1] << 16) | (rawBytes[2] << 8) | rawBytes[3];
  const family = (le >>> 0) <= 0xff ? le >>> 0 : (be >>> 0) <= 0xff ? be >>> 0 : le >>> 0;
  const etherType = etherTypeFromVersion(rawBytes, 4);
  const familyName = family === 2 ? 'AF_INET'
    : family === 24 || family === 28 || family === 30 ? 'AF_INET6'
      : `AF (${family})`;

  return {
    layers: [{
      name: 'Null/Loopback',
      summary: `Null/Loopback, Family: ${familyName}`,
      rawBytesRange: [0, 3],
      fields: [{ name: 'Family', value: `${familyName} (${family})`, rawBytesRange: [0, 3] }],
    }],
    fields: {},
    l3Offset: 4,
    etherType,
    encapsulation,
    truncated: false,
  };
}

// --- Linux cooked capture -----------------------------------------------------

/** ARPHRD types worth naming in the cooked header. */
const ARPHRD: Record<number, string> = {
  0: 'Generic', 1: 'Ethernet', 512: 'Loopback', 772: 'Loopback',
  776: 'IPv6-in-IPv4', 778: 'IPIP', 801: 'IEEE 802.11', 824: 'NetLink',
};

const SLL_PACKET_TYPE: Record<number, string> = {
  0: 'Unicast to us', 1: 'Broadcast', 2: 'Multicast',
  3: 'Unicast to another host', 4: 'Sent by us',
};

/**
 * `tcpdump -i any` on Linux, v1: a 16-byte pseudo-header in place of a real
 * link layer, because the frames it aggregates come from adapters with
 * different link layers and no single one of them would describe them all.
 *
 *   packet type (2) | ARPHRD type (2) | address length (2) | address (8) | protocol (2)
 */
function dissectSll(rawBytes: Uint8Array, encapsulation: string): LinkLayerResult {
  if (rawBytes.length < 16) {
    return { layers: [], fields: {}, l3Offset: rawBytes.length, etherType: 0, encapsulation, truncated: true };
  }
  const packetType = (rawBytes[0] << 8) | rawBytes[1];
  const hardware = (rawBytes[2] << 8) | rawBytes[3];
  const addrLen = (rawBytes[4] << 8) | rawBytes[5];
  const protocol = (rawBytes[14] << 8) | rawBytes[15];
  const srcMac = addrLen === 6 ? formatMac(rawBytes.slice(6, 12)) : undefined;

  const fields: Record<string, string | number> = {};
  if (srcMac) fields['eth.src'] = srcMac;
  if (protocol > MAX_802_3_LENGTH) fields['eth.type'] = protocol;

  return {
    layers: [{
      name: 'Linux cooked capture v1',
      summary: 'Linux cooked capture v1',
      rawBytesRange: [0, 15],
      fields: [
        { name: 'Packet type', value: `${SLL_PACKET_TYPE[packetType] ?? 'Unknown'} (${packetType})`, rawBytesRange: [0, 1] },
        { name: 'Link-layer address type', value: `${ARPHRD[hardware] ?? 'Unknown'} (${hardware})`, rawBytesRange: [2, 3] },
        { name: 'Link-layer address length', value: addrLen, rawBytesRange: [4, 5] },
        ...(srcMac
          ? [{ name: 'Source', value: resolveMacVendor(srcMac), abbrev: 'eth.src', rawBytesRange: [6, 11] as [number, number], children: macAddressFields(srcMac, 6) }]
          : []),
        { name: 'Protocol', value: `0x${protocol.toString(16).padStart(4, '0')} (${describeEtherType(protocol)})`, abbrev: 'eth.type', rawBytesRange: [14, 15] },
      ],
    }],
    fields,
    l3Offset: 16,
    etherType: protocol,
    srcMac,
    encapsulation,
    truncated: false,
  };
}

/**
 * The v2 cooked header, which reordered the fields and grew to 20 bytes:
 *
 *   protocol (2) | reserved (2) | interface index (4) | ARPHRD type (2)
 *   | packet type (1) | address length (1) | address (8)
 */
function dissectSll2(rawBytes: Uint8Array, encapsulation: string): LinkLayerResult {
  if (rawBytes.length < 20) {
    return { layers: [], fields: {}, l3Offset: rawBytes.length, etherType: 0, encapsulation, truncated: true };
  }
  const protocol = (rawBytes[0] << 8) | rawBytes[1];
  const ifIndex = ((rawBytes[4] << 24) | (rawBytes[5] << 16) | (rawBytes[6] << 8) | rawBytes[7]) >>> 0;
  const hardware = (rawBytes[8] << 8) | rawBytes[9];
  const packetType = rawBytes[10];
  const addrLen = rawBytes[11];
  const srcMac = addrLen === 6 ? formatMac(rawBytes.slice(12, 18)) : undefined;

  const fields: Record<string, string | number> = {};
  if (srcMac) fields['eth.src'] = srcMac;
  if (protocol > MAX_802_3_LENGTH) fields['eth.type'] = protocol;

  return {
    layers: [{
      name: 'Linux cooked capture v2',
      summary: 'Linux cooked capture v2',
      rawBytesRange: [0, 19],
      fields: [
        { name: 'Protocol', value: `0x${protocol.toString(16).padStart(4, '0')} (${describeEtherType(protocol)})`, abbrev: 'eth.type', rawBytesRange: [0, 1] },
        { name: 'Interface index', value: ifIndex, rawBytesRange: [4, 7] },
        { name: 'Link-layer address type', value: `${ARPHRD[hardware] ?? 'Unknown'} (${hardware})`, rawBytesRange: [8, 9] },
        { name: 'Packet type', value: `${SLL_PACKET_TYPE[packetType] ?? 'Unknown'} (${packetType})`, rawBytesRange: [10, 10] },
        { name: 'Link-layer address length', value: addrLen, rawBytesRange: [11, 11] },
        ...(srcMac
          ? [{ name: 'Source', value: resolveMacVendor(srcMac), abbrev: 'eth.src', rawBytesRange: [12, 17] as [number, number], children: macAddressFields(srcMac, 12) }]
          : []),
      ],
    }],
    fields,
    l3Offset: 20,
    etherType: protocol,
    srcMac,
    encapsulation,
    truncated: false,
  };
}
