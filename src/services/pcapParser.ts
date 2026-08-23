import { Packet, ProtocolLayer } from '../types/packet';

/**
 * Standard Libpcap file header structure (24 bytes)
 * magic_number (4 bytes) = 0xa1b2c3d4
 * version_major (2 bytes) = 2
 * version_minor (2 bytes) = 4
 * thiszone (4 bytes) = 0 (GMT)
 * sigfigs (4 bytes) = 0
 * snaplen (4 bytes) = 65535
 * network (4 bytes) = 1 (LINKTYPE_ETHERNET)
 */

export class PcapService {
  /**
   * Generates a compliant binary Libpcap 2.4 file from packet stream
   */
  public static generatePcapBinary(packets: Packet[]): Blob {
    let totalSize = 24; // Global header
    for (const p of packets) {
      totalSize += 16 + p.rawBytes.length; // 16 bytes pcap_pkthdr + raw bytes
    }

    const buffer = new ArrayBuffer(totalSize);
    const view = new DataView(buffer);
    let offset = 0;

    // 1. Write Global Header (Little Endian standard)
    view.setUint32(offset, 0xa1b2c3d4, true); // Magic
    offset += 4;
    view.setUint16(offset, 2, true); // Major version
    offset += 2;
    view.setUint16(offset, 4, true); // Minor version
    offset += 2;
    view.setInt32(offset, 0, true); // Timezone GMT
    offset += 4;
    view.setUint32(offset, 0, true); // Sigfigs
    offset += 4;
    view.setUint32(offset, 65535, true); // Snaplen
    offset += 4;
    view.setUint32(offset, 1, true); // LinkType: Ethernet (1)
    offset += 4;

    // 2. Write Packet Records
    for (const packet of packets) {
      const tsSec = Math.floor(packet.timestamp / 1000);
      const tsUsec = (packet.timestamp % 1000) * 1000;
      const capLen = packet.rawBytes.length;
      const origLen = packet.length;

      // Packet Header (16 bytes)
      view.setUint32(offset, tsSec, true);
      offset += 4;
      view.setUint32(offset, tsUsec, true);
      offset += 4;
      view.setUint32(offset, capLen, true);
      offset += 4;
      view.setUint32(offset, origLen, true);
      offset += 4;

      // Packet Raw Bytes
      const destUint8 = new Uint8Array(buffer, offset, capLen);
      destUint8.set(packet.rawBytes);
      offset += capLen;
    }

    return new Blob([buffer], { type: 'application/vnd.tcpdump.pcap' });
  }

  /**
   * Parse a binary .pcap file uploaded by user
   */
  public static async parsePcapFile(file: File): Promise<Packet[]> {
    const arrayBuffer = await file.arrayBuffer();
    const view = new DataView(arrayBuffer);
    const parsedPackets: Packet[] = [];

    if (arrayBuffer.byteLength < 24) {
      throw new Error('File is too small to be a valid PCAP file.');
    }

    // Read magic number
    const magic = view.getUint32(0, false);
    let isLittleEndian = true;

    if (magic === 0xa1b2c3d4) {
      isLittleEndian = false; // Big endian
    } else if (magic === 0xd4c3b2a1) {
      isLittleEndian = true; // Little endian
    } else if (magic === 0x4d3cb2a1 || magic === 0xa1b23c4d) {
      // Nanosecond pcap
      isLittleEndian = magic === 0x4d3cb2a1;
    } else {
      // Might be pcapng or json
      try {
        const text = new TextDecoder().decode(arrayBuffer);
        const json = JSON.parse(text);
        if (Array.isArray(json)) {
          return json;
        }
      } catch {
        // Continue to attempt fallback libpcap parse
      }
    }

    let offset = 24;
    let packetIndex = 1;
    let baseTime: number | null = null;
    let prevTime = 0;

    while (offset + 16 <= arrayBuffer.byteLength) {
      const tsSec = view.getUint32(offset, isLittleEndian);
      const tsUsec = view.getUint32(offset + 4, isLittleEndian);
      const capLen = view.getUint32(offset + 8, isLittleEndian);
      const origLen = view.getUint32(offset + 12, isLittleEndian);
      offset += 16;

      if (offset + capLen > arrayBuffer.byteLength) {
        break; // Truncated final packet
      }

      const rawBytes = new Uint8Array(arrayBuffer.slice(offset, offset + capLen));
      offset += capLen;

      const epochMs = tsSec * 1000 + Math.floor(tsUsec / 1000);
      if (baseTime === null) baseTime = epochMs;
      const relativeTime = (epochMs - baseTime) / 1000;
      const timeDelta = prevTime === 0 ? 0 : (epochMs - prevTime) / 1000;
      prevTime = epochMs;

      // Extract basic layers from Ethernet frame
      const packet = decodeRawEthernetPacket(rawBytes, packetIndex++, epochMs, relativeTime, timeDelta, origLen);
      parsedPackets.push(packet);

      if (parsedPackets.length >= 10000) {
        break; // Safety limit for memory in browser
      }
    }

    return parsedPackets;
  }

  /**
   * Export to JSON string
   */
  public static exportToJson(packets: Packet[]): string {
    const sanitized = packets.map(p => ({
      no: p.id,
      time: p.relativeTime.toFixed(6),
      source: p.source,
      destination: p.destination,
      protocol: p.protocol,
      length: p.length,
      info: p.info,
      status: p.status,
      anomaly: p.anomaly?.title,
      layers: p.layers.map(l => ({
        layer: l.name,
        summary: l.summary,
        fields: l.fields.map(f => ({ name: f.name, value: f.value })),
      })),
    }));

    return JSON.stringify(sanitized, null, 2);
  }

  /**
   * Export to CSV
   */
  public static exportToCsv(packets: Packet[]): string {
    const headers = ['No.', 'Time(s)', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'Status', 'Anomaly'];
    const rows = packets.map(p => [
      p.id,
      p.relativeTime.toFixed(6),
      `"${p.source}"`,
      `"${p.destination}"`,
      p.protocol,
      p.length,
      `"${p.info.replace(/"/g, '""')}"`,
      p.status,
      p.anomaly ? `"${p.anomaly.title.replace(/"/g, '""')}"` : '""',
    ]);

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  }
}

export function decodeRawEthernetPacket(
  rawBytes: Uint8Array,
  id: number,
  epochMs: number,
  relativeTime: number,
  timeDelta: number,
  origLen: number
): Packet {
  const hexDump = formatHexDump(rawBytes);
  const asciiDump = formatAsciiDump(rawBytes);

  let srcMac = '00:00:00:00:00:00';
  let dstMac = '00:00:00:00:00:00';
  let etherType = 0x0800;

  if (rawBytes.length >= 14) {
    dstMac = formatMac(rawBytes.slice(0, 6));
    srcMac = formatMac(rawBytes.slice(6, 12));
    etherType = (rawBytes[12] << 8) | rawBytes[13];
  }

  let srcIp = srcMac;
  let dstIp = dstMac;
  let proto: Packet['protocol'] = 'TCP';
  let srcPort: number | undefined;
  let dstPort: number | undefined;
  let info = `Frame (${rawBytes.length} bytes)`;

  const layers: ProtocolLayer[] = [
    {
      name: 'Frame',
      summary: `Frame ${id}: ${rawBytes.length} bytes on wire (${rawBytes.length * 8} bits), ${origLen} bytes captured`,
      rawBytesRange: [0, rawBytes.length - 1],
      fields: [
        { name: 'Interface id', value: '0 (eth0)' },
        { name: 'Frame Number', value: id },
        { name: 'Frame Length', value: `${rawBytes.length} bytes` },
        { name: 'Capture Length', value: `${origLen} bytes` },
        { name: 'Epoch Time', value: new Date(epochMs).toISOString() },
      ],
    },
    {
      name: 'Ethernet II',
      summary: `Ethernet II, Src: ${srcMac}, Dst: ${dstMac}`,
      rawBytesRange: [0, 13],
      fields: [
        { name: 'Destination', value: dstMac, rawBytesRange: [0, 5] },
        { name: 'Source', value: srcMac, rawBytesRange: [6, 11] },
        { name: 'Type', value: `0x${etherType.toString(16).padStart(4, '0')} (${describeEtherType(etherType)})`, rawBytesRange: [12, 13] },
      ],
    },
  ];

  // 802.1Q / 802.1ad (QinQ) VLAN tags: a 4-byte tag (2-byte TCI + 2-byte real
  // ethertype) can appear between the MACs and the "real" ethertype, and can
  // repeat for double-tagged trunk traffic. Strip every tag we find so the
  // IPv4/IPv6 branches below see the correct offset and correct ethertype,
  // exactly how Wireshark's packet-vlan.c walks nested tags.
  let l3Offset = 14;
  let currentEtherType = etherType;
  let vlanDepth = 0;
  while ((currentEtherType === 0x8100 || currentEtherType === 0x88a8) && rawBytes.length >= l3Offset + 4 && vlanDepth < 8) {
    const tci = (rawBytes[l3Offset] << 8) | rawBytes[l3Offset + 1];
    const priority = (tci >> 13) & 0x7;
    const dei = (tci >> 12) & 0x1;
    const vlanId = tci & 0x0fff;
    const innerEtherType = (rawBytes[l3Offset + 2] << 8) | rawBytes[l3Offset + 3];

    layers.push({
      name: '802.1Q Virtual LAN',
      summary: `802.1Q Virtual LAN, PRI: ${priority}, DEI: ${dei}, ID: ${vlanId}`,
      rawBytesRange: [l3Offset, l3Offset + 3],
      fields: [
        { name: 'Priority', value: priority, rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Drop Eligible Indicator (DEI)', value: dei, rawBytesRange: [l3Offset, l3Offset] },
        { name: 'VLAN ID', value: vlanId, rawBytesRange: [l3Offset, l3Offset + 1] },
        { name: 'Type', value: `0x${innerEtherType.toString(16).padStart(4, '0')} (${describeEtherType(innerEtherType)})`, rawBytesRange: [l3Offset + 2, l3Offset + 3] },
      ],
    });

    currentEtherType = innerEtherType;
    l3Offset += 4;
    vlanDepth++;
  }

  // IPv4 Decode
  if (currentEtherType === 0x0800 && rawBytes.length >= l3Offset + 20) {
    const ipHeaderLen = (rawBytes[l3Offset] & 0x0f) * 4;
    const ipTotalLen = (rawBytes[l3Offset + 2] << 8) | rawBytes[l3Offset + 3];
    const ipProtocolNum = rawBytes[l3Offset + 9];
    srcIp = `${rawBytes[l3Offset + 12]}.${rawBytes[l3Offset + 13]}.${rawBytes[l3Offset + 14]}.${rawBytes[l3Offset + 15]}`;
    dstIp = `${rawBytes[l3Offset + 16]}.${rawBytes[l3Offset + 17]}.${rawBytes[l3Offset + 18]}.${rawBytes[l3Offset + 19]}`;

    layers.push({
      name: 'Internet Protocol Version 4',
      summary: `Internet Protocol Version 4, Src: ${srcIp}, Dst: ${dstIp}`,
      rawBytesRange: [l3Offset, l3Offset + ipHeaderLen - 1],
      fields: [
        { name: 'Version', value: '4', rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Header Length', value: `${ipHeaderLen} bytes`, rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Total Length', value: ipTotalLen, rawBytesRange: [l3Offset + 2, l3Offset + 3] },
        { name: 'Time to Live (TTL)', value: rawBytes[l3Offset + 8], rawBytesRange: [l3Offset + 8, l3Offset + 8] },
        { name: 'Protocol', value: ipProtocolNum === 6 ? 'TCP (6)' : ipProtocolNum === 17 ? 'UDP (17)' : `${ipProtocolNum}`, rawBytesRange: [l3Offset + 9, l3Offset + 9] },
        { name: 'Source Address', value: srcIp, rawBytesRange: [l3Offset + 12, l3Offset + 15] },
        { name: 'Destination Address', value: dstIp, rawBytesRange: [l3Offset + 16, l3Offset + 19] },
      ],
    });

    const transportOffset = l3Offset + ipHeaderLen;
    const transport = decodeTransportLayer(rawBytes, transportOffset, ipProtocolNum);
    if (transport) {
      proto = transport.proto;
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      layers.push(transport.layer);
    }
  } else if (currentEtherType === 0x86dd && rawBytes.length >= l3Offset + 40) {
    // IPv6 Decode - fixed 40-byte header only; IPv6 extension headers are not supported.
    const nextHeader = rawBytes[l3Offset + 6];
    const hopLimit = rawBytes[l3Offset + 7];
    srcIp = formatIpv6Address(rawBytes, l3Offset + 8);
    dstIp = formatIpv6Address(rawBytes, l3Offset + 24);

    layers.push({
      name: 'Internet Protocol Version 6',
      summary: `Internet Protocol Version 6, Src: ${srcIp}, Dst: ${dstIp}`,
      rawBytesRange: [l3Offset, l3Offset + 39],
      fields: [
        { name: 'Version', value: '6', rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Next Header', value: nextHeader === 6 ? 'TCP (6)' : nextHeader === 17 ? 'UDP (17)' : nextHeader === 58 ? 'ICMPv6 (58)' : `${nextHeader}`, rawBytesRange: [l3Offset + 6, l3Offset + 6] },
        { name: 'Hop Limit', value: hopLimit, rawBytesRange: [l3Offset + 7, l3Offset + 7] },
        { name: 'Source Address', value: srcIp, rawBytesRange: [l3Offset + 8, l3Offset + 23] },
        { name: 'Destination Address', value: dstIp, rawBytesRange: [l3Offset + 24, l3Offset + 39] },
      ],
    });

    const transportOffset = l3Offset + 40;
    const transport = decodeTransportLayer(rawBytes, transportOffset, nextHeader);
    if (transport) {
      proto = transport.proto;
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      layers.push(transport.layer);
    }
  }

  return {
    id,
    timestamp: epochMs,
    relativeTime,
    timeDelta,
    source: srcIp,
    destination: dstIp,
    sourcePort: srcPort,
    destPort: dstPort,
    protocol: proto,
    length: rawBytes.length,
    info,
    status: 'ok',
    layers,
    rawBytes,
    hexDump,
    asciiDump,
    interfaceName: 'eth0',
  };
}

function formatMac(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(':');
}

function describeEtherType(etherType: number): string {
  switch (etherType) {
    case 0x0800: return 'IPv4';
    case 0x86dd: return 'IPv6';
    case 0x0806: return 'ARP';
    case 0x8100: return '802.1Q Virtual LAN';
    case 0x88a8: return '802.1ad Provider Bridge (QinQ)';
    default: return 'Unknown';
  }
}

/**
 * Formats a 16-byte IPv6 address (starting at `offset` within `bytes`) as
 * 8 colon-separated 4-hex-digit groups. No double-colon zero-compression.
 */
function formatIpv6Address(bytes: Uint8Array, offset: number): string {
  const groups: string[] = [];
  for (let i = 0; i < 8; i++) {
    const word = (bytes[offset + i * 2] << 8) | bytes[offset + i * 2 + 1];
    groups.push(word.toString(16).padStart(4, '0'));
  }
  return groups.join(':');
}

/**
 * Decodes the transport-layer (TCP/UDP/ICMP) portion of a frame, shared by
 * both the IPv4 and IPv6 decode branches. Returns null when the protocol
 * number is unrecognized or there aren't enough bytes to decode it.
 */
function decodeTransportLayer(
  rawBytes: Uint8Array,
  transportOffset: number,
  ipProtocolNum: number
): { proto: Packet['protocol']; srcPort?: number; dstPort?: number; info: string; layer: ProtocolLayer } | null {
  // TCP Decode
  if (ipProtocolNum === 6 && rawBytes.length >= transportOffset + 20) {
    const srcPort = (rawBytes[transportOffset] << 8) | rawBytes[transportOffset + 1];
    const dstPort = (rawBytes[transportOffset + 2] << 8) | rawBytes[transportOffset + 3];
    // ">>> 0" reinterprets the bitwise result as unsigned - without it, any
    // seq/ack number with the top bit set comes out as a negative number,
    // since JS's <</| operators always produce signed 32-bit results.
    const seqNum = ((rawBytes[transportOffset + 4] << 24) | (rawBytes[transportOffset + 5] << 16) | (rawBytes[transportOffset + 6] << 8) | rawBytes[transportOffset + 7]) >>> 0;
    const ackNum = ((rawBytes[transportOffset + 8] << 24) | (rawBytes[transportOffset + 9] << 16) | (rawBytes[transportOffset + 10] << 8) | rawBytes[transportOffset + 11]) >>> 0;
    const flags = rawBytes[transportOffset + 13];
    const syn = (flags & 0x02) !== 0;
    const ack = (flags & 0x10) !== 0;
    const fin = (flags & 0x01) !== 0;
    const rst = (flags & 0x04) !== 0;
    const psh = (flags & 0x08) !== 0;

    const flagList: string[] = [];
    if (syn) flagList.push('SYN');
    if (ack) flagList.push('ACK');
    if (fin) flagList.push('FIN');
    if (rst) flagList.push('RST');
    if (psh) flagList.push('PSH');

    let proto: Packet['protocol'] = 'TCP';
    if (srcPort === 443 || dstPort === 443) proto = 'TLS';
    else if (srcPort === 80 || dstPort === 80) proto = 'HTTP';
    else if (srcPort === 22 || dstPort === 22) proto = 'SSH';

    const info = `${srcPort} → ${dstPort} [${flagList.join(', ')}] Seq=${seqNum} Ack=${ackNum} Len=${rawBytes.length - transportOffset - 20}`;

    return {
      proto,
      srcPort,
      dstPort,
      info,
      layer: {
        name: 'Transmission Control Protocol',
        summary: `Transmission Control Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`,
        rawBytesRange: [transportOffset, transportOffset + 19],
        fields: [
          { name: 'Source Port', value: srcPort, rawBytesRange: [transportOffset, transportOffset + 1] },
          { name: 'Destination Port', value: dstPort, rawBytesRange: [transportOffset + 2, transportOffset + 3] },
          { name: 'Sequence Number', value: seqNum, rawBytesRange: [transportOffset + 4, transportOffset + 7] },
          { name: 'Acknowledgment Number', value: ackNum, rawBytesRange: [transportOffset + 8, transportOffset + 11] },
          { name: 'Flags', value: `0x${flags.toString(16).padStart(3, '0')} (${flagList.join(', ')})`, rawBytesRange: [transportOffset + 12, transportOffset + 13] },
        ],
      },
    };
  } else if (ipProtocolNum === 17 && rawBytes.length >= transportOffset + 8) {
    // UDP Decode
    const srcPort = (rawBytes[transportOffset] << 8) | rawBytes[transportOffset + 1];
    const dstPort = (rawBytes[transportOffset + 2] << 8) | rawBytes[transportOffset + 3];
    const udpLen = (rawBytes[transportOffset + 4] << 8) | rawBytes[transportOffset + 5];

    let proto: Packet['protocol'] = 'UDP';
    if (srcPort === 53 || dstPort === 53) proto = 'DNS';
    else if (srcPort === 1883 || dstPort === 1883) proto = 'MQTT';

    const info = `${srcPort} → ${dstPort} Len=${udpLen}`;

    return {
      proto,
      srcPort,
      dstPort,
      info,
      layer: {
        name: 'User Datagram Protocol',
        summary: `User Datagram Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`,
        rawBytesRange: [transportOffset, transportOffset + 7],
        fields: [
          { name: 'Source Port', value: srcPort, rawBytesRange: [transportOffset, transportOffset + 1] },
          { name: 'Destination Port', value: dstPort, rawBytesRange: [transportOffset + 2, transportOffset + 3] },
          { name: 'Length', value: udpLen, rawBytesRange: [transportOffset + 4, transportOffset + 5] },
        ],
      },
    };
  } else if ((ipProtocolNum === 1 || ipProtocolNum === 58) && rawBytes.length >= transportOffset + 4) {
    // ICMP (v4, protocol 1) / ICMPv6 (protocol 58) Decode - ICMPv6 uses
    // different type numbers than ICMPv4 for the same messages (e.g. echo
    // request/reply is 128/129 in ICMPv6 vs 8/0 in ICMPv4), and adds the IPv6
    // Neighbor Discovery messages (router/neighbor solicitation/advertisement)
    // that make up most real-world ICMPv6 traffic.
    const isIcmpv6 = ipProtocolNum === 58;
    const icmpType = rawBytes[transportOffset];
    const icmpCode = rawBytes[transportOffset + 1];

    let info: string;
    if (isIcmpv6) {
      switch (icmpType) {
        case 128: info = 'Echo (ping) request'; break;
        case 129: info = 'Echo (ping) reply'; break;
        case 133: info = 'Router Solicitation'; break;
        case 134: info = 'Router Advertisement'; break;
        case 135: info = 'Neighbor Solicitation'; break;
        case 136: info = 'Neighbor Advertisement'; break;
        case 137: info = 'Redirect'; break;
        default: info = `ICMPv6 Type ${icmpType} Code ${icmpCode}`;
      }
    } else if (icmpType === 8) {
      info = 'Echo (ping) request';
    } else if (icmpType === 0) {
      info = 'Echo (ping) reply';
    } else {
      info = `ICMP Type ${icmpType} Code ${icmpCode}`;
    }

    return {
      proto: 'ICMP',
      info,
      layer: {
        name: isIcmpv6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol',
        summary: `${isIcmpv6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol'}, ${info}`,
        rawBytesRange: [transportOffset, transportOffset + 3],
        fields: [
          { name: 'Type', value: icmpType, rawBytesRange: [transportOffset, transportOffset] },
          { name: 'Code', value: icmpCode, rawBytesRange: [transportOffset + 1, transportOffset + 1] },
        ],
      },
    };
  }

  return null;
}

export function formatHexDump(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

export function formatAsciiDump(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
    .join('');
}
