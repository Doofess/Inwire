import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatMac, formatIpv4Address } from '../addressFormat';

/**
 * Result of a link-layer dissector. `protocolLabel` is what the Protocol
 * column shows; the caller maps it onto the coarse ProtocolType separately.
 */
export interface L2DissectorResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  /** Dissected values under their conventional field names, for display filters. */
  fields?: Record<string, string | number>;
}

/**
 * ARP (ethertype 0x0806).
 *
 * Fixed layout from `l3Offset`: hardware type (2), protocol type (2),
 * hardware size (1), protocol size (1), opcode (2), then sender MAC (6),
 * sender IP (4), target MAC (6), target IP (4) for the IPv4-over-Ethernet
 * case that is essentially all real ARP traffic.
 */
export function dissectArp(rawBytes: Uint8Array, l3Offset: number): L2DissectorResult | null {
  if (rawBytes.length < l3Offset + 28) return null;

  const hardwareType = (rawBytes[l3Offset] << 8) | rawBytes[l3Offset + 1];
  const protocolType = (rawBytes[l3Offset + 2] << 8) | rawBytes[l3Offset + 3];
  const opcode = (rawBytes[l3Offset + 6] << 8) | rawBytes[l3Offset + 7];
  const senderMac = formatMac(rawBytes.slice(l3Offset + 8, l3Offset + 14));
  const senderIp = formatIpv4Address(rawBytes, l3Offset + 14);
  const targetMac = formatMac(rawBytes.slice(l3Offset + 18, l3Offset + 24));
  const targetIp = formatIpv4Address(rawBytes, l3Offset + 24);

  const opcodeName =
    opcode === 1 ? 'request' :
    opcode === 2 ? 'reply' :
    opcode === 3 ? 'reverse request' :
    opcode === 4 ? 'reverse reply' :
    `unknown (${opcode})`;

  // A host announcing its own address - sender and target IP equal - is a
  // gratuitous ARP, and the reference analyzer says so rather than asking "who has" an
  // address the sender already owns. RFC 5227 names two more shapes, which
  // are how a host claims an address at all: a PROBE asks for one from
  // 0.0.0.0 before using it, and an ANNOUNCEMENT is the gratuitous request
  // that follows, its target MAC left zero. `packet-arp.c` decides all three
  // exactly so.
  const isGratuitous = senderIp === targetIp && (opcode === 1 || opcode === 2);
  const isAnnouncement = isGratuitous && opcode === 1 && targetMac === '00:00:00:00:00:00';
  const isProbe = !isGratuitous && opcode === 1 && senderIp === '0.0.0.0';

  let info: string;
  if (isAnnouncement) {
    info = `ARP Announcement for ${targetIp}`;
  } else if (isGratuitous) {
    info = `Gratuitous ARP for ${senderIp} (${opcode === 1 ? 'Request' : 'Reply'})`;
  } else if (isProbe) {
    info = `Who has ${targetIp}? (ARP Probe)`;
  } else if (opcode === 1) {
    info = `Who has ${targetIp}? Tell ${senderIp}`;
  } else if (opcode === 2) {
    info = `${senderIp} is at ${senderMac}`;
  } else {
    info = `ARP ${opcodeName}`;
  }

  return {
    protocolLabel: 'ARP',
    info,
    fields: {
      'arp.opcode': opcode,
      'arp.src.proto_ipv4': senderIp,
      'arp.dst.proto_ipv4': targetIp,
      'arp.src.hw_mac': senderMac,
      'arp.dst.hw_mac': targetMac,
      ...(isGratuitous ? { 'arp.isgratuitous': 1 } : {}),
      ...(isProbe ? { 'arp.isprobe': 1 } : {}),
      ...(isAnnouncement ? { 'arp.isannouncement': 1 } : {}),
    },
    layer: {
      name: 'Address Resolution Protocol',
      summary: `Address Resolution Protocol (${
        isAnnouncement ? 'ARP Announcement'
        : isProbe ? 'ARP Probe'
        : isGratuitous ? `${opcodeName}/gratuitous ARP`
        : opcodeName})`,
      rawBytesRange: [l3Offset, l3Offset + 27],
      fields: [
        // The four fixed header fields, which were drawn from the first
        // version of this dissector and never named - so `arp.hw.type` and
        // the three beside it resolved to nothing, on every ARP frame in
        // both captures. The five below them were named in the bag only,
        // which counts for the measurement and not for the detail pane's
        // Apply as Filter; naming the rows costs nothing and fixes that.
        { name: 'Hardware type', value: hardwareType === 1 ? 'Ethernet (1)' : `${hardwareType}`, abbrev: 'arp.hw.type', rawBytesRange: [l3Offset, l3Offset + 1] },
        { name: 'Protocol type', value: protocolType === 0x0800 ? 'IPv4 (0x0800)' : `0x${protocolType.toString(16).padStart(4, '0')}`, abbrev: 'arp.proto.type', rawBytesRange: [l3Offset + 2, l3Offset + 3] },
        { name: 'Hardware size', value: rawBytes[l3Offset + 4], abbrev: 'arp.hw.size', rawBytesRange: [l3Offset + 4, l3Offset + 4] },
        { name: 'Protocol size', value: rawBytes[l3Offset + 5], abbrev: 'arp.proto.size', rawBytesRange: [l3Offset + 5, l3Offset + 5] },
        { name: 'Opcode', value: `${opcodeName} (${opcode})`, abbrev: 'arp.opcode', rawBytesRange: [l3Offset + 6, l3Offset + 7] },
        ...(isGratuitous ? [{ name: '[Is gratuitous]', value: 'True', generated: true, abbrev: 'arp.isgratuitous' }] : []),
        ...(isProbe ? [{ name: '[Is probe]', value: 'True', generated: true, abbrev: 'arp.isprobe' }] : []),
        ...(isAnnouncement ? [{ name: '[Is announcement]', value: 'True', generated: true, abbrev: 'arp.isannouncement' }] : []),
        { name: 'Sender MAC address', value: senderMac, abbrev: 'arp.src.hw_mac', rawBytesRange: [l3Offset + 8, l3Offset + 13] },
        { name: 'Sender IP address', value: senderIp, abbrev: 'arp.src.proto_ipv4', rawBytesRange: [l3Offset + 14, l3Offset + 17] },
        { name: 'Target MAC address', value: targetMac, abbrev: 'arp.dst.hw_mac', rawBytesRange: [l3Offset + 18, l3Offset + 23] },
        { name: 'Target IP address', value: targetIp, abbrev: 'arp.dst.proto_ipv4', rawBytesRange: [l3Offset + 24, l3Offset + 27] },
      ],
    },
  };
}

/** Formats an STP bridge/root identifier: 4-bit priority, 12-bit system ID extension, 6-byte MAC. */
function formatBridgeId(rawBytes: Uint8Array, offset: number): { text: string; priority: number; sysIdExt: number; mac: string } {
  const priorityField = (rawBytes[offset] << 8) | rawBytes[offset + 1];
  // The low 12 bits were carved out of the original 16-bit priority to carry a
  // VLAN id (802.1t), so priority is only the top 4 bits, scaled by 4096.
  const priority = (priorityField >> 12) * 4096;
  const sysIdExt = priorityField & 0x0fff;
  const mac = formatMac(rawBytes.slice(offset + 2, offset + 8));
  return { text: `${priority}/${sysIdExt}/${mac}`, priority, sysIdExt, mac };
}

/**
 * Spanning Tree BPDUs, reached through an 802.3 + LLC header rather than an
 * ethertype: when bytes 12-13 of the frame hold a value <= 1500 they are a
 * *length*, and the next three bytes are LLC DSAP/SSAP/Control. DSAP 0x42 is
 * the STP service access point.
 *
 * `llcOffset` points at the DSAP byte, so the BPDU itself begins 3 bytes later.
 */
/**
 * Message Age, Max Age, Hello Time and Forward Delay.
 *
 * Each is a `u16` of 256ths of a second - 0x0200 is two seconds - which is
 * why they are divided rather than shown raw, and why the reference prints
 * "2" against a value of 512.
 */
function stpTimerRows(rawBytes: Uint8Array, bpdu: number): ProtocolField[] {
  const timers: [string, string, number][] = [
    ['Message Age', 'stp.msg_age', 27],
    ['Max Age', 'stp.max_age', 29],
    ['Hello Time', 'stp.hello', 31],
    ['Forward Delay', 'stp.forward', 33],
  ];
  return timers.map(([name, abbrev, at]) => ({
    name,
    value: ((rawBytes[bpdu + at] << 8) | rawBytes[bpdu + at + 1]) / 256,
    abbrev,
    rawBytesRange: [bpdu + at, bpdu + at + 1] as [number, number],
  }));
}

export function dissectStp(rawBytes: Uint8Array, llcOffset: number): L2DissectorResult | null {
  const bpdu = llcOffset + 3;
  if (rawBytes.length < bpdu + 4) return null;

  const protocolId = (rawBytes[bpdu] << 8) | rawBytes[bpdu + 1];
  if (protocolId !== 0x0000) return null; // not an IEEE 802.1D BPDU

  const version = rawBytes[bpdu + 2];
  const bpduType = rawBytes[bpdu + 3];

  // A Topology Change Notification is only 4 bytes long - it carries no
  // root/cost/port fields at all, so it must be handled before reading them.
  if (bpduType === 0x80) {
    return {
      protocolLabel: 'STP',
      info: 'Topology Change Notification',
      fields: { 'stp.type': bpduType, 'stp.version': version },
      layer: {
        name: 'Spanning Tree Protocol',
        summary: 'Spanning Tree Protocol, Topology Change Notification',
        rawBytesRange: [llcOffset, bpdu + 3],
        fields: [
          { name: 'Protocol Identifier', value: 'Spanning Tree Protocol (0x0000)', abbrev: 'stp.protocol', rawBytesRange: [bpdu, bpdu + 1] },
          { name: 'Protocol Version Identifier', value: version, abbrev: 'stp.version', rawBytesRange: [bpdu + 2, bpdu + 2] },
          { name: 'BPDU Type', value: 'Topology Change Notification (0x80)', abbrev: 'stp.type', rawBytesRange: [bpdu + 3, bpdu + 3] },
        ],
      },
    };
  }

  if (rawBytes.length < bpdu + 35) return null;

  const flags = rawBytes[bpdu + 4];
  const root = formatBridgeId(rawBytes, bpdu + 5);
  const rootCost =
    ((rawBytes[bpdu + 13] << 24) | (rawBytes[bpdu + 14] << 16) | (rawBytes[bpdu + 15] << 8) | rawBytes[bpdu + 16]) >>> 0;
  const bridge = formatBridgeId(rawBytes, bpdu + 17);
  const portId = (rawBytes[bpdu + 25] << 8) | rawBytes[bpdu + 26];

  // The reference analyzer's own abbreviations for the BPDU type, and note the *double*
  // spaces separating the three sections of the summary.
  const typeName = bpduType === 0x02 ? 'RST' : 'Conf.';
  const info = `${typeName} Root = ${root.text}  Cost = ${rootCost}  Port = 0x${portId.toString(16).padStart(4, '0')}`;

  return {
    protocolLabel: bpduType === 0x02 ? 'RSTP' : 'STP',
    info,
    fields: {
      'stp.type': bpduType,
      'stp.version': version,
      'stp.root.cost': rootCost,
      'stp.port': portId,
      'stp.flags': flags,
      'stp.msg_age': ((rawBytes[bpdu + 27] << 8) | rawBytes[bpdu + 28]) / 256,
      'stp.max_age': ((rawBytes[bpdu + 29] << 8) | rawBytes[bpdu + 30]) / 256,
      'stp.hello': ((rawBytes[bpdu + 31] << 8) | rawBytes[bpdu + 32]) / 256,
      'stp.forward': ((rawBytes[bpdu + 33] << 8) | rawBytes[bpdu + 34]) / 256,
    },
    layer: {
      name: 'Spanning Tree Protocol',
      summary: `Spanning Tree Protocol, ${info}`,
      rawBytesRange: [llcOffset, Math.min(rawBytes.length - 1, bpdu + 34)],
      fields: [
        { name: 'Protocol Identifier', value: 'Spanning Tree Protocol (0x0000)', abbrev: 'stp.protocol', rawBytesRange: [bpdu, bpdu + 1] },
        { name: 'Protocol Version Identifier', value: version, abbrev: 'stp.version', rawBytesRange: [bpdu + 2, bpdu + 2] },
        { name: 'BPDU Type', value: `${bpduType === 0x02 ? 'Rapid/Multiple' : 'Configuration'} (0x${bpduType.toString(16).padStart(2, '0')})`, abbrev: 'stp.type', rawBytesRange: [bpdu + 3, bpdu + 3] },
        {
          name: 'BPDU flags',
          value: `0x${flags.toString(16).padStart(2, '0')}`,
          abbrev: 'stp.flags',
          rawBytesRange: [bpdu + 4, bpdu + 4],
          // The two bits every BPDU carries. A topology change is the single
          // most operationally interesting thing a BPDU says - it is what a
          // flapping link looks like from the switch side - and it was inside
          // a hex byte nobody could filter on.
          children: [
            {
              name: 'Topology Change Acknowledgment', value: (flags & 0x80) !== 0 ? 'Yes' : 'No',
              abbrev: 'stp.flags.tcack', rawBytesRange: [bpdu + 4, bpdu + 4],
              bitfield: { bitOffset: 0, bitLength: 1, totalBits: 8 },
            },
            {
              name: 'Topology Change', value: (flags & 0x01) !== 0 ? 'Yes' : 'No',
              abbrev: 'stp.flags.tc', rawBytesRange: [bpdu + 4, bpdu + 4],
              bitfield: { bitOffset: 7, bitLength: 1, totalBits: 8 },
            },
          ],
        },
        {
          name: 'Root Identifier',
          value: root.text,
          rawBytesRange: [bpdu + 5, bpdu + 12],
          children: [
            { name: 'Root Bridge Priority', value: root.priority, abbrev: 'stp.root.prio' },
            { name: 'Root Bridge System ID Extension', value: root.sysIdExt, abbrev: 'stp.root.ext' },
            { name: 'Root Bridge System ID', value: root.mac, abbrev: 'stp.root.hw' },
          ],
        },
        { name: 'Root Path Cost', value: rootCost, abbrev: 'stp.root.cost', rawBytesRange: [bpdu + 13, bpdu + 16] },
        {
          name: 'Bridge Identifier',
          value: bridge.text,
          rawBytesRange: [bpdu + 17, bpdu + 24],
          children: [
            { name: 'Bridge Priority', value: bridge.priority, abbrev: 'stp.bridge.prio' },
            { name: 'Bridge System ID Extension', value: bridge.sysIdExt, abbrev: 'stp.bridge.ext' },
            { name: 'Bridge System ID', value: bridge.mac, abbrev: 'stp.bridge.hw' },
          ],
        },
        { name: 'Port identifier', value: `0x${portId.toString(16).padStart(4, '0')}`, abbrev: 'stp.port', rawBytesRange: [bpdu + 25, bpdu + 26] },
        // The four timers, eight bytes this build read past. They are the
        // whole of a spanning tree's convergence behaviour: Max Age and Hello
        // Time say how long a switch waits before deciding the root is gone,
        // and Forward Delay is why a port takes thirty seconds to pass
        // traffic. Carried in 1/256 of a second and shown in seconds, as the
        // reference shows them.
        ...stpTimerRows(rawBytes, bpdu),
      ],
    },
  };
}

/**
 * Ethertypes we can name in the Protocol column but do not (yet) dissect.
 * The reference analyzer still shows a real protocol name for these; without the mapping
 * they would inherit the caller's fallback and be labeled something wrong.
 */
const ETHERTYPE_LABELS: Record<number, string> = {
  0x893a: 'ieee1905',
  0x88cc: 'LLDP',
  0x8863: 'PPPoED',
  0x8864: 'PPPoES',
  0x88e1: 'HomePlug AV',
  0x22f0: 'IEEE 1722',
  0x8809: 'Slow Protocols',
  0x88f7: 'PTP',
};

export function labelForEtherType(etherType: number): string | undefined {
  return ETHERTYPE_LABELS[etherType];
}
