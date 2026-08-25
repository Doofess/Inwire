import { Packet, ProtocolLayer, ProtocolField, AnomalyInfo } from '../types/packet';
import { TcpStreamTracker } from './tcpStreamTracker';
import { resolveMacVendor, resolveMacName } from './macVendors';
import { formatMac, formatIpv4Address, formatIpv6Address } from './addressFormat';
import { dissectArp, dissectStp, labelForEtherType, L2DissectorResult } from './dissectors/l2';
import { dissectTls } from './dissectors/tls';
import { dissectDns } from './dissectors/dns';
import { dissectQuicDatagram } from './dissectors/quic';
import { dissectIeee1905 } from './dissectors/ieee1905';
import { QuicFlowTracker } from './quicFlowTracker';
import { IcmpEchoTracker } from './icmpEchoTracker';

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

/**
 * Flattens a ProtocolField for JSON export, recursing into nested children so
 * sub-fields (TCP's raw seq/ack numbers, IP's DSCP/ECN and flag bits, ICMP's
 * identifier) survive the export instead of being silently dropped.
 */
function mapField(f: ProtocolField): { name: string; value: string | number | boolean; children?: ReturnType<typeof mapField>[] } {
  return {
    name: f.name,
    value: f.value,
    ...(f.children && f.children.length > 0 ? { children: f.children.map(mapField) } : {}),
  };
}

interface ExtractedFrame {
  rawBytes: Uint8Array;
  /**
   * Epoch time in nanoseconds. Deliberately a bigint: epoch-nanoseconds is
   * ~1.8e18, well past Number.MAX_SAFE_INTEGER (9e15), so a float64 would
   * silently quantize timestamps to ~256 ns and lose the very precision a
   * nanosecond capture exists to record.
   */
  tsNanos: bigint;
  origLen: number;
  /** Decimal places the capture's timestamps are meaningful to (6 = us, 9 = ns). */
  tsPrecision: number;
}

/**
 * Converts a raw tick count plus a seconds-per-tick resolution into exact
 * epoch nanoseconds. Integer nanosecond-per-tick resolutions - which covers
 * every power-of-10 resolution pcapng uses in practice - stay in bigint math
 * and are exact; the rare power-of-2 resolutions fall back to float, where a
 * sub-nanosecond rounding error is irrelevant anyway.
 */
function ticksToNanos(ticks: bigint, secondsPerTick: number): bigint {
  const nanosPerTick = secondsPerTick * 1e9;
  return Number.isInteger(nanosPerTick)
    ? ticks * BigInt(nanosPerTick)
    : BigInt(Math.round(Number(ticks) * nanosPerTick));
}

/** Decimal places to display for a given seconds-per-tick resolution. */
function precisionFor(secondsPerTick: number): number {
  return Math.min(9, Math.max(0, Math.round(-Math.log10(secondsPerTick))));
}

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
   * Parse a binary .pcap or .pcapng file uploaded by user
   */
  public static async parsePcapFile(file: File): Promise<Packet[]> {
    const arrayBuffer = await file.arrayBuffer();

    if (arrayBuffer.byteLength < 8) {
      throw new Error('File is too small to be a valid PCAP file.');
    }

    const magic = new DataView(arrayBuffer).getUint32(0, false);

    // pcapng's Section Header Block type (0x0A0D0D0A) is a byte-palindrome,
    // so it reads identically regardless of the file's actual byte order -
    // no endianness detection needed before recognizing it.
    if (magic === 0x0a0d0d0a) {
      return PcapService.buildPacketsFromFrames(PcapService.extractPcapNgFrames(arrayBuffer));
    }

    if (arrayBuffer.byteLength < 24) {
      throw new Error('File is too small to be a valid PCAP file.');
    }

    let isLittleEndian = true;
    let subSecondIsNanos = false;
    if (magic === 0xa1b2c3d4) {
      isLittleEndian = false; // Big endian
    } else if (magic === 0xd4c3b2a1) {
      isLittleEndian = true; // Little endian
    } else if (magic === 0x4d3cb2a1 || magic === 0xa1b23c4d) {
      // Nanosecond pcap
      isLittleEndian = magic === 0x4d3cb2a1;
      subSecondIsNanos = true;
    } else {
      // Might be a JSON export
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

    return PcapService.buildPacketsFromFrames(
      PcapService.extractClassicPcapFrames(arrayBuffer, isLittleEndian, subSecondIsNanos)
    );
  }

  /**
   * Extracts raw frames + timestamps from a classic Libpcap 2.4 file.
   *
   * `subSecondIsNanos` distinguishes the two libpcap flavors: the original
   * format's second timestamp field is microseconds, while the nanosecond
   * variant (magic 0x4d3cb2a1 / 0xa1b23c4d) puts nanoseconds in the exact
   * same field. Reading one as the other is off by a factor of 1000.
   */
  private static extractClassicPcapFrames(
    buffer: ArrayBuffer,
    isLittleEndian: boolean,
    subSecondIsNanos: boolean
  ): ExtractedFrame[] {
    const view = new DataView(buffer);
    const frames: ExtractedFrame[] = [];
    const nanosPerSubSecondUnit = subSecondIsNanos ? 1n : 1000n;
    const tsPrecision = subSecondIsNanos ? 9 : 6;
    let offset = 24;

    while (offset + 16 <= buffer.byteLength) {
      const tsSec = view.getUint32(offset, isLittleEndian);
      const tsSubSecond = view.getUint32(offset + 4, isLittleEndian);
      const capLen = view.getUint32(offset + 8, isLittleEndian);
      const origLen = view.getUint32(offset + 12, isLittleEndian);
      offset += 16;

      if (offset + capLen > buffer.byteLength) break; // Truncated final packet

      frames.push({
        rawBytes: new Uint8Array(buffer.slice(offset, offset + capLen)),
        tsNanos: BigInt(tsSec) * 1_000_000_000n + BigInt(tsSubSecond) * nanosPerSubSecondUnit,
        origLen,
        tsPrecision,
      });
      offset += capLen;

      if (frames.length >= 10000) break; // Safety limit for memory in browser
    }

    return frames;
  }

  /**
   * Extracts raw frames + timestamps from a pcapng file by walking its
   * block structure: a Section Header Block establishes byte order for
   * everything that follows it, Interface Description Blocks record each
   * interface's timestamp resolution, and Enhanced Packet Blocks carry the
   * actual frame bytes. Any other block type (interface stats, name
   * resolution, decryption secrets, vendor-specific blocks, ...) is safely
   * skipped using its own declared length - a reader doesn't need to
   * understand every block kind to walk past it, which is the whole point
   * of the block-based format.
   */
  private static extractPcapNgFrames(buffer: ArrayBuffer): ExtractedFrame[] {
    const view = new DataView(buffer);
    const frames: ExtractedFrame[] = [];
    let offset = 0;
    let isLittleEndian = true;
    // Per-interface timestamp resolution (seconds per tick), indexed by
    // declaration order within the current section - this is exactly what
    // an Enhanced Packet Block's Interface ID field refers to.
    let interfaceResolutions: number[] = [];

    while (offset + 8 <= buffer.byteLength) {
      const blockType = view.getUint32(offset, isLittleEndian);
      const blockLen = view.getUint32(offset + 4, isLittleEndian);

      if (blockLen < 12 || offset + blockLen > buffer.byteLength) break; // truncated/corrupt

      if (blockType === 0x0a0d0d0a) {
        // Section Header Block - the byte-order magic right after the
        // length field re-establishes endianness for the rest of this
        // section (multiple sections, each with their own byte order, are
        // technically legal - reset per new SHB encountered).
        const boMagicAsLE = view.getUint32(offset + 8, true);
        isLittleEndian = boMagicAsLE === 0x1a2b3c4d;
        interfaceResolutions = [];
      } else if (blockType === 0x00000001) {
        // Interface Description Block: LinkType(2) Reserved(2) SnapLen(4), then options.
        let tsresol = 1e-6; // default per spec: microseconds
        const optionsEnd = offset + blockLen - 4;
        let optOffset = offset + 16;
        while (optOffset + 4 <= optionsEnd) {
          const optCode = view.getUint16(optOffset, isLittleEndian);
          const optLen = view.getUint16(optOffset + 2, isLittleEndian);
          if (optCode === 0) break; // opt_endofopt
          if (optCode === 9 && optLen >= 1 && optOffset + 4 < optionsEnd) {
            // if_tsresol: high bit set means a power of 2, otherwise a power of 10.
            const raw = view.getUint8(optOffset + 4);
            const exponent = raw & 0x7f;
            tsresol = (raw & 0x80) !== 0 ? 2 ** -exponent : 10 ** -exponent;
          }
          optOffset += 4 + optLen + ((4 - (optLen % 4)) % 4); // options are 4-byte padded too
        }
        interfaceResolutions.push(tsresol);
      } else if (blockType === 0x00000006) {
        // Enhanced Packet Block: InterfaceID(4) TsHigh(4) TsLow(4) CapLen(4) OrigLen(4), then data.
        const interfaceId = view.getUint32(offset + 8, isLittleEndian);
        const tsHigh = view.getUint32(offset + 12, isLittleEndian);
        const tsLow = view.getUint32(offset + 16, isLittleEndian);
        const capLen = view.getUint32(offset + 20, isLittleEndian);
        const origLen = view.getUint32(offset + 24, isLittleEndian);
        const dataStart = offset + 28;

        if (dataStart + capLen <= buffer.byteLength) {
          const resolution = interfaceResolutions[interfaceId] ?? 1e-6;
          // Reassemble the 64-bit tick count in bigint: a nanosecond-resolution
          // capture's tick count exceeds float64's exact-integer range, so
          // doing this as (tsHigh * 2**32 + tsLow) quantizes the timestamp.
          const ticks = (BigInt(tsHigh) << 32n) | BigInt(tsLow);
          frames.push({
            rawBytes: new Uint8Array(buffer.slice(dataStart, dataStart + capLen)),
            tsNanos: ticksToNanos(ticks, resolution),
            origLen,
            tsPrecision: precisionFor(resolution),
          });
        }
      }
      // Every other block type carries no frame data we need.

      offset += blockLen;
      if (frames.length >= 10000) break; // Safety limit for memory in browser
    }

    return frames;
  }

  /**
   * Shared decode pass used by both the classic-pcap and pcapng extractors:
   * runs each extracted frame through the same dissection pipeline used for
   * live-captured packets, so imported files and live capture produce
   * identical Packet shapes.
   */
  private static buildPacketsFromFrames(frames: ExtractedFrame[]): Packet[] {
    const parsedPackets: Packet[] = [];
    let packetIndex = 1;
    let baseNanos: bigint | null = null;
    let prevNanos: bigint | null = null;
    const tcpTracker = new TcpStreamTracker();
    const icmpTracker = new IcmpEchoTracker();
    const quicTracker = new QuicFlowTracker();

    for (const frame of frames) {
      if (baseNanos === null) baseNanos = frame.tsNanos;
      // Subtracting in bigint *before* converting to a float is what keeps
      // nanosecond precision: the difference is a small number of seconds, so
      // it lands well inside float64's exact range even though the absolute
      // epoch-nanosecond value does not.
      const relativeTime = Number(frame.tsNanos - baseNanos) / 1e9;
      const timeDelta = prevNanos === null ? 0 : Number(frame.tsNanos - prevNanos) / 1e9;
      prevNanos = frame.tsNanos;
      const epochMs = Number(frame.tsNanos / 1_000_000n);

      const { packet, icmpMatchedRequestFrameId } = decodeRawEthernetPacket(
        frame.rawBytes, packetIndex++, epochMs, relativeTime, timeDelta, frame.origLen, tcpTracker, icmpTracker, quicTracker
      );
      packet.tsPrecision = frame.tsPrecision;
      parsedPackets.push(packet);

      if (icmpMatchedRequestFrameId !== undefined) {
        const requestPacket = parsedPackets.find(p => p.id === icmpMatchedRequestFrameId);
        if (requestPacket) {
          requestPacket.info += ` (reply in ${packet.id})`;
        }
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
      anomalies: p.anomalies?.map(a => a.title),
      layers: p.layers.map(l => ({
        layer: l.name,
        summary: l.summary,
        fields: l.fields.map(mapField),
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
      p.anomalies && p.anomalies.length > 0
        ? `"${p.anomalies.map(a => a.title).join('; ').replace(/"/g, '""')}"`
        : '""',
    ]);

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  }
}

/**
 * Maps dissected layer names to their Wireshark filter-field abbreviations for
 * the Frame layer's "[Protocols in frame]" field. Module-level so it isn't
 * rebuilt once per decoded packet.
 */
const PROTOCOL_NAME_MAP: Record<string, string> = {
  'Frame': 'frame',
  'Ethernet II': 'eth',
  '802.1Q Virtual LAN': 'vlan',
  'Internet Protocol Version 4': 'ip',
  'Internet Protocol Version 6': 'ipv6',
  'Transmission Control Protocol': 'tcp',
  'User Datagram Protocol': 'udp',
  'Internet Control Message Protocol': 'icmp',
  'Internet Control Message Protocol v6': 'icmpv6',
  'Address Resolution Protocol': 'arp',
  'Spanning Tree Protocol': 'stp',
  'IEEE 1905.1a': 'ieee1905',
};

export function decodeRawEthernetPacket(
  rawBytes: Uint8Array,
  id: number,
  epochMs: number,
  relativeTime: number,
  timeDelta: number,
  origLen: number,
  tcpTracker?: TcpStreamTracker,
  icmpTracker?: IcmpEchoTracker,
  quicTracker?: QuicFlowTracker
): { packet: Packet; icmpMatchedRequestFrameId?: number } {
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

  // Frames with no network layer (ARP, STP, other pure-L2 traffic) show their
  // MAC addresses in the address columns, resolved to names the way Wireshark
  // does - "SagemcomBroa_aa:bb:cc", "Broadcast", "Nearest-Customer-Bridge".
  // The IPv4/IPv6 branches below overwrite these when an L3 address exists.
  let srcIp = resolveMacName(srcMac);
  let dstIp = resolveMacName(dstMac);
  let proto: Packet['protocol'] = 'TCP';
  // The Protocol column's free-form label, when it differs from the coarse
  // ProtocolType - "TLSv1.2", "ICMPv6", "STP". Left undefined when the two
  // would read the same.
  let protocolLabel: string | undefined;
  // Wireshark's tcp.analysis.* field names that fired for this frame, if any.
  let analysisFlags: string[] | undefined;
  // Dissected values under their Wireshark field names, for display filters
  // and color rules to reference generically.
  const filterFields: Record<string, string | number> = {};
  let srcPort: number | undefined;
  let dstPort: number | undefined;
  let info = `Frame (${rawBytes.length} bytes)`;
  let status: Packet['status'] = 'ok';
  let streamId: number | undefined;
  let anomalies: AnomalyInfo[] | undefined;
  let icmpMatchedRequestFrameId: number | undefined;

  const layers: ProtocolLayer[] = [
    {
      name: 'Frame',
      summary: `Frame ${id}: ${origLen || rawBytes.length} bytes on wire (${(origLen || rawBytes.length) * 8} bits), ${rawBytes.length} bytes captured (${rawBytes.length * 8} bits)`,
      rawBytesRange: [0, rawBytes.length - 1],
      fields: [
        { name: 'Interface id', value: '0 (eth0)' },
        { name: 'Frame Number', value: id },
        { name: 'Frame Length', value: `${origLen || rawBytes.length} bytes` },
        { name: 'Capture Length', value: `${rawBytes.length} bytes` },
        { name: 'Epoch Time', value: new Date(epochMs).toISOString() },
        { name: '[Time delta from previous captured frame]', value: `${timeDelta.toFixed(6)} seconds` },
        { name: '[Time since reference or first frame]', value: `${relativeTime.toFixed(6)} seconds` },
      ],
    },
    {
      name: 'Ethernet II',
      summary: `Ethernet II, Src: ${srcMac}, Dst: ${dstMac}`,
      rawBytesRange: [0, 13],
      fields: [
        { name: 'Destination', value: resolveMacVendor(dstMac), rawBytesRange: [0, 5] },
        { name: 'Source', value: resolveMacVendor(srcMac), rawBytesRange: [6, 11] },
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

  // Link-layer protocols that carry no IP header. These have to be dispatched
  // before the IPv4/IPv6 branches, and without them a frame keeps this
  // function's fallback protocol - which is why ARP and STP frames used to be
  // labeled "TCP" and summarized as "Frame (N bytes)".
  //
  // An ethertype field <= 1500 is really an 802.3 *length*, and what follows
  // is an LLC header (DSAP/SSAP/Control) rather than a network-layer header.
  // DSAP 0x42 is the Spanning Tree Protocol's service access point.
  const isLlcFrame = currentEtherType <= 1500;
  let l2Result: L2DissectorResult | null = null;
  if (currentEtherType === 0x0806) {
    l2Result = dissectArp(rawBytes, l3Offset);
  } else if (currentEtherType === 0x893a) {
    l2Result = dissectIeee1905(rawBytes, l3Offset);
  } else if (isLlcFrame && rawBytes.length > l3Offset && rawBytes[l3Offset] === 0x42) {
    l2Result = dissectStp(rawBytes, l3Offset);
  }

  if (l2Result) {
    Object.assign(filterFields, l2Result.fields);
    protocolLabel = l2Result.protocolLabel;
    proto = l2Result.protocolLabel === 'ARP' ? 'ARP' : 'TCP';
    info = l2Result.info;
    layers.push(l2Result.layer);
  } else if (currentEtherType !== 0x0800 && currentEtherType !== 0x86dd) {
    // Not dissected, but still nameable from the ethertype - better an honest
    // "ieee1905" than an inherited default of "TCP".
    protocolLabel = labelForEtherType(currentEtherType)
      ?? (isLlcFrame ? 'LLC' : `0x${currentEtherType.toString(16).padStart(4, '0')}`);
  }

  // IPv4 Decode
  if (currentEtherType === 0x0800 && rawBytes.length >= l3Offset + 20) {
    const ipHeaderLen = (rawBytes[l3Offset] & 0x0f) * 4;
    const tos = rawBytes[l3Offset + 1];
    const dscp = tos >> 2;
    const ecn = tos & 0x3;
    const ipTotalLen = (rawBytes[l3Offset + 2] << 8) | rawBytes[l3Offset + 3];
    const identification = (rawBytes[l3Offset + 4] << 8) | rawBytes[l3Offset + 5];
    const flagsAndFragOffset = (rawBytes[l3Offset + 6] << 8) | rawBytes[l3Offset + 7];
    const ipReservedBit = (flagsAndFragOffset >> 15) & 0x1;
    const dontFragment = (flagsAndFragOffset >> 14) & 0x1;
    const moreFragments = (flagsAndFragOffset >> 13) & 0x1;
    const fragmentOffset = flagsAndFragOffset & 0x1fff;
    const ttl = rawBytes[l3Offset + 8];
    const ipProtocolNum = rawBytes[l3Offset + 9];
    const headerChecksumActual = (rawBytes[l3Offset + 10] << 8) | rawBytes[l3Offset + 11];
    const headerChecksumComputed = computeIpHeaderChecksum(rawBytes, l3Offset, ipHeaderLen);
    const checksumCorrect = headerChecksumActual === headerChecksumComputed;
    srcIp = `${rawBytes[l3Offset + 12]}.${rawBytes[l3Offset + 13]}.${rawBytes[l3Offset + 14]}.${rawBytes[l3Offset + 15]}`;
    dstIp = `${rawBytes[l3Offset + 16]}.${rawBytes[l3Offset + 17]}.${rawBytes[l3Offset + 18]}.${rawBytes[l3Offset + 19]}`;

    const ipLayer: ProtocolLayer = {
      name: 'Internet Protocol Version 4',
      summary: `Internet Protocol Version 4, Src: ${srcIp}, Dst: ${dstIp}`,
      rawBytesRange: [l3Offset, l3Offset + ipHeaderLen - 1],
      fields: [
        { name: 'Version', value: '4', rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Header Length', value: `${ipHeaderLen} bytes`, rawBytesRange: [l3Offset, l3Offset] },
        {
          name: 'Differentiated Services Field',
          value: `0x${tos.toString(16).padStart(2, '0')} (DSCP: ${dscp}, ECN: ${ecn})`,
          rawBytesRange: [l3Offset + 1, l3Offset + 1],
          children: [
            { name: 'Differentiated Services Codepoint', value: dscp, rawBytesRange: [l3Offset + 1, l3Offset + 1] },
            { name: 'Explicit Congestion Notification', value: ecn, rawBytesRange: [l3Offset + 1, l3Offset + 1] },
          ],
        },
        { name: 'Total Length', value: ipTotalLen, rawBytesRange: [l3Offset + 2, l3Offset + 3] },
        { name: 'Identification', value: `0x${identification.toString(16).padStart(4, '0')} (${identification})`, rawBytesRange: [l3Offset + 4, l3Offset + 5] },
        {
          name: 'Flags',
          value: `0x${((flagsAndFragOffset >> 13) & 0x7).toString(16).padStart(2, '0')}`,
          rawBytesRange: [l3Offset + 6, l3Offset + 6],
          children: [
            { name: 'Reserved bit', value: ipReservedBit === 1 ? 'Set' : 'Not set', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
            { name: "Don't fragment", value: dontFragment === 1 ? 'Set' : 'Not set', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
            { name: 'More fragments', value: moreFragments === 1 ? 'Set' : 'Not set', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
          ],
        },
        { name: 'Fragment Offset', value: fragmentOffset, rawBytesRange: [l3Offset + 6, l3Offset + 7] },
        { name: 'Time to Live (TTL)', value: ttl, rawBytesRange: [l3Offset + 8, l3Offset + 8] },
        { name: 'Protocol', value: ipProtocolNum === 6 ? 'TCP (6)' : ipProtocolNum === 17 ? 'UDP (17)' : `${ipProtocolNum}`, rawBytesRange: [l3Offset + 9, l3Offset + 9] },
        {
          name: 'Header Checksum',
          value: `0x${headerChecksumActual.toString(16).padStart(4, '0')} [${checksumCorrect ? 'correct' : 'incorrect'}]`,
          rawBytesRange: [l3Offset + 10, l3Offset + 11],
          children: [
            { name: '[Header checksum status]', value: checksumCorrect ? 'Correct' : `Incorrect, should be 0x${headerChecksumComputed.toString(16).padStart(4, '0')}` },
          ],
        },
        { name: 'Source Address', value: srcIp, rawBytesRange: [l3Offset + 12, l3Offset + 15] },
        { name: 'Destination Address', value: dstIp, rawBytesRange: [l3Offset + 16, l3Offset + 19] },
      ],
    };
    layers.push(ipLayer);

    const transportOffset = l3Offset + ipHeaderLen;
    filterFields['ip.ttl'] = ttl;
    filterFields['ip.src'] = srcIp;
    filterFields['ip.dst'] = dstIp;
    filterFields['ip.proto'] = ipProtocolNum;

    const transport = decodeTransportLayer(rawBytes, transportOffset, ipProtocolNum, srcIp, dstIp, tcpTracker, ttl, icmpTracker, id, ipTotalLen - ipHeaderLen, quicTracker);
    if (transport) {
      proto = transport.proto;
      protocolLabel = transport.protocolLabel;
      analysisFlags = transport.analysisFlags;
      Object.assign(filterFields, transport.fields);
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      layers.push(transport.layer);
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      anomalies = transport.anomalies;
      icmpMatchedRequestFrameId = transport.icmpMatchedRequestFrameId;
      if (transport.streamId !== undefined) {
        ipLayer.fields.push({ name: '[Stream index]', value: transport.streamId });
      }
    }
  } else if (currentEtherType === 0x86dd && rawBytes.length >= l3Offset + 40) {
    // IPv6 Decode - fixed 40-byte header only; IPv6 extension headers are not supported.
    const ipv6PayloadLen = (rawBytes[l3Offset + 4] << 8) | rawBytes[l3Offset + 5];
    const nextHeader = rawBytes[l3Offset + 6];
    const hopLimit = rawBytes[l3Offset + 7];
    srcIp = formatIpv6Address(rawBytes, l3Offset + 8);
    dstIp = formatIpv6Address(rawBytes, l3Offset + 24);

    const ipv6Layer: ProtocolLayer = {
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
    };
    layers.push(ipv6Layer);

    // A zero IPv6 payload length is only legal for a jumbogram (RFC 2675),
    // which must carry a Hop-by-Hop Jumbo Payload option - anything else is
    // malformed, and in practice it means the NIC coalesced receive segments
    // (LRO) without fixing the length field up. The bytes after the header are
    // then not a single coherent segment: dissecting them anyway invents a
    // multi-kilobyte TCP payload that advances the sequence tracker past
    // everything that follows, silently suppressing the lost-segment and
    // ACKed-unseen-segment analysis on every later frame in that stream.
    // Wireshark stops here and labels the frame malformed; so do we.
    filterFields['ipv6.hlim'] = hopLimit;
    filterFields['ipv6.src'] = srcIp;
    filterFields['ipv6.dst'] = dstIp;
    filterFields['ipv6.nxt'] = nextHeader;

    const isMalformedJumbo = ipv6PayloadLen === 0 && rawBytes.length > l3Offset + 40;
    if (isMalformedJumbo) {
      proto = 'TCP';
      protocolLabel = 'IPv6';
      info = '[Malformed Packet]';
      status = 'warning';
    }

    const transportOffset = l3Offset + 40;
    const transport = isMalformedJumbo
      ? null
      : decodeTransportLayer(rawBytes, transportOffset, nextHeader, srcIp, dstIp, tcpTracker, hopLimit, icmpTracker, id, ipv6PayloadLen, quicTracker);
    if (transport) {
      proto = transport.proto;
      protocolLabel = transport.protocolLabel;
      analysisFlags = transport.analysisFlags;
      Object.assign(filterFields, transport.fields);
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      layers.push(transport.layer);
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      anomalies = transport.anomalies;
      icmpMatchedRequestFrameId = transport.icmpMatchedRequestFrameId;
      if (transport.streamId !== undefined) {
        ipv6Layer.fields.push({ name: '[Stream index]', value: transport.streamId });
      }
    }
  }

  const frameProtocols = layers.map(l => PROTOCOL_NAME_MAP[l.name] ?? l.name.toLowerCase().replace(/\s+/g, '_'));
  layers[0].fields.push({ name: '[Protocols in frame]', value: frameProtocols.join(':') });

  return {
    packet: {
      id,
      timestamp: epochMs,
      relativeTime,
      timeDelta,
      source: srcIp,
      destination: dstIp,
      sourcePort: srcPort,
      destPort: dstPort,
      protocol: proto,
      protocolLabel,
      analysisFlags,
      frameProtocols,
      fields: filterFields,
      // The on-wire frame size, which is what Wireshark's Length column shows.
      // It differs from rawBytes.length whenever the capture used a snaplen.
      // Falls back to the captured size if a source didn't report a wire size.
      length: origLen || rawBytes.length,
      info,
      status,
      streamId,
      layers,
      rawBytes,
      hexDump,
      asciiDump,
      anomalies,
      interfaceName: 'eth0',
    },
    icmpMatchedRequestFrameId,
  };
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
 * Formats a 16-byte IPv6 address (starting at `offset` within `bytes`) in the
 * RFC 5952 canonical form Wireshark displays: leading zeros stripped from each
 * group, lowercase hex, and the *longest* run of two or more all-zero groups
 * collapsed to "::" (leftmost run wins a tie, and a single zero group is never
 * collapsed - "2001:db8:0:1:1:1:1:1" stays as-is).
 *
 * Without this an address renders as 39 characters of zero-padded groups,
 * which both diverges from Wireshark and overflows the address column.
 */

/**
 * Reads the first CRLF-terminated ASCII line of a text protocol payload
 * (SSDP's "M-SEARCH * HTTP/1.1", HTTP's request line). Returns null unless the
 * line is entirely printable and plausibly a request line, so binary payloads
 * on the same port don't produce mojibake in the Info column.
 */
function readAsciiRequestLine(rawBytes: Uint8Array, payloadStart: number): string | null {
  const limit = Math.min(rawBytes.length, payloadStart + 256);
  let end = payloadStart;
  while (end < limit && rawBytes[end] !== 0x0d && rawBytes[end] !== 0x0a) {
    const byte = rawBytes[end];
    if (byte < 0x20 || byte > 0x7e) return null;
    end++;
  }
  if (end === payloadStart || end >= limit) return null;
  return new TextDecoder().decode(rawBytes.subarray(payloadStart, end));
}

/**
 * Walks an ICMPv6 Neighbor Discovery option list, looking for one option type.
 * Options start after the message body and are each a type byte, a length in
 * 8-byte units (a zero length would mean an infinite loop, so it terminates),
 * and the option data.
 */
function findNdpOption(rawBytes: Uint8Array, optionsStart: number, wantedType: number): Uint8Array | null {
  let offset = optionsStart;
  while (offset + 2 <= rawBytes.length) {
    const type = rawBytes[offset];
    const lengthUnits = rawBytes[offset + 1];
    if (lengthUnits === 0) return null;
    const optionEnd = offset + lengthUnits * 8;
    if (optionEnd > rawBytes.length) return null;
    if (type === wantedType) return rawBytes.subarray(offset + 2, optionEnd);
    offset = optionEnd;
  }
  return null;
}

/**
 * "Neighbor Solicitation for fe80::17a6:fd9a:5a8c:e5bf from 44:15:24:aa:bb:cc"
 *
 * Layout after the 4-byte ICMPv6 header: 4 reserved bytes, the 16-byte target
 * address, then options. Option type 1 is the sender's link-layer address.
 */
function describeNeighborSolicitation(rawBytes: Uint8Array, transportOffset: number): string {
  const targetOffset = transportOffset + 8;
  if (targetOffset + 16 > rawBytes.length) return 'Neighbor Solicitation';

  const target = formatIpv6Address(rawBytes, targetOffset);
  const sourceLinkAddr = findNdpOption(rawBytes, targetOffset + 16, 1);
  return sourceLinkAddr && sourceLinkAddr.length >= 6
    ? `Neighbor Solicitation for ${target} from ${formatMac(sourceLinkAddr.subarray(0, 6))}`
    : `Neighbor Solicitation for ${target}`;
}

/**
 * "Neighbor Advertisement fe80::17a6:... (sol, ovr) is at 04:7c:16:52:db:17"
 *
 * Same layout as a solicitation, except the first reserved byte carries the
 * Router/Solicited/Override flags, and option type 2 is the target's
 * link-layer address.
 */
function describeNeighborAdvertisement(rawBytes: Uint8Array, transportOffset: number): string {
  const targetOffset = transportOffset + 8;
  if (targetOffset + 16 > rawBytes.length) return 'Neighbor Advertisement';

  const target = formatIpv6Address(rawBytes, targetOffset);
  const flagBits = rawBytes[transportOffset + 4];
  const flags: string[] = [];
  if (flagBits & 0x80) flags.push('rtr');
  if (flagBits & 0x40) flags.push('sol');
  if (flagBits & 0x20) flags.push('ovr');
  const flagText = flags.length > 0 ? ` (${flags.join(', ')})` : '';

  const targetLinkAddr = findNdpOption(rawBytes, targetOffset + 16, 2);
  return targetLinkAddr && targetLinkAddr.length >= 6
    ? `Neighbor Advertisement ${target}${flagText} is at ${formatMac(targetLinkAddr.subarray(0, 6))}`
    : `Neighbor Advertisement ${target}${flagText}`;
}

/**
 * Decodes the transport-layer (TCP/UDP/ICMP) portion of a frame, shared by
 * both the IPv4 and IPv6 decode branches. Returns null when the protocol
 * number is unrecognized or there aren't enough bytes to decode it.
 */
function decodeTransportLayer(
  rawBytes: Uint8Array,
  transportOffset: number,
  ipProtocolNum: number,
  srcIp: string,
  dstIp: string,
  tcpTracker?: TcpStreamTracker,
  ttl?: number,
  icmpTracker?: IcmpEchoTracker,
  frameId?: number,
  /**
   * Number of bytes belonging to the transport header+payload as *declared by
   * the network layer* (IPv4: Total Length - IHL; IPv6: Payload Length, which
   * already excludes the fixed 40-byte header). Real Ethernet frames are
   * padded up to a 60-byte minimum, so deriving TCP payload length from
   * rawBytes.length would count that padding as payload.
   */
  l4SegmentLen?: number,
  quicTracker?: QuicFlowTracker
): {
  proto: Packet['protocol'];
  protocolLabel?: string;
  srcPort?: number;
  dstPort?: number;
  info: string;
  layer: ProtocolLayer;
  streamId?: number;
  status?: Packet['status'];
  analysisFlags?: string[];
  fields?: Record<string, string | number>;
  anomalies?: AnomalyInfo[];
  icmpMatchedRequestFrameId?: number;
} | null {
  // TCP Decode
  if (ipProtocolNum === 6 && rawBytes.length >= transportOffset + 20) {
    const srcPort = (rawBytes[transportOffset] << 8) | rawBytes[transportOffset + 1];
    const dstPort = (rawBytes[transportOffset + 2] << 8) | rawBytes[transportOffset + 3];
    // ">>> 0" reinterprets the bitwise result as unsigned - without it, any
    // seq/ack number with the top bit set comes out as a negative number,
    // since JS's <</| operators always produce signed 32-bit results.
    const seqNum = ((rawBytes[transportOffset + 4] << 24) | (rawBytes[transportOffset + 5] << 16) | (rawBytes[transportOffset + 6] << 8) | rawBytes[transportOffset + 7]) >>> 0;
    const ackNum = ((rawBytes[transportOffset + 8] << 24) | (rawBytes[transportOffset + 9] << 16) | (rawBytes[transportOffset + 10] << 8) | rawBytes[transportOffset + 11]) >>> 0;
    // Data Offset is the top 4 bits of this byte, in 32-bit words - hardcoding
    // 20 bytes here (as this file previously did everywhere) silently
    // misreads Len= and the payload-scan offset whenever real options are
    // present, which is most real-world TCP traffic.
    const dataOffsetWords = (rawBytes[transportOffset + 12] >> 4) & 0x0f;
    const tcpHeaderLen = Math.max(20, dataOffsetWords * 4);
    const flags = rawBytes[transportOffset + 13];
    const syn = (flags & 0x02) !== 0;
    const ack = (flags & 0x10) !== 0;
    const fin = (flags & 0x01) !== 0;
    const rst = (flags & 0x04) !== 0;
    const psh = (flags & 0x08) !== 0;
    const urg = (flags & 0x20) !== 0;
    const ece = (flags & 0x40) !== 0;
    const cwr = (flags & 0x80) !== 0;
    const rawWindow = (rawBytes[transportOffset + 14] << 8) | rawBytes[transportOffset + 15];

    // Wireshark's fixed flag order, which is *not* the bit order: a typical
    // data segment reads "[PSH, ACK]", never "[ACK, PSH]".
    const flagList: string[] = [];
    if (syn) flagList.push('SYN');
    if (fin) flagList.push('FIN');
    if (rst) flagList.push('RST');
    if (psh) flagList.push('PSH');
    if (ack) flagList.push('ACK');
    if (urg) flagList.push('URG');
    if (ece) flagList.push('ECE');
    if (cwr) flagList.push('CWR');

    // Port only *hints* at the protocol. Whether the frame actually gets a TLS
    // label depends on it containing a real TLS record, checked further down
    // once the payload boundaries are known - a bare ACK or keep-alive on a
    // 443 connection is a plain TCP frame to Wireshark, not a TLS one.
    const isTlsPort = srcPort === 443 || dstPort === 443;
    let proto: Packet['protocol'] = 'TCP';
    let protocolLabel: string | undefined;
    if (isTlsPort) proto = 'TLS';
    else if (srcPort === 80 || dstPort === 80) proto = 'HTTP';
    else if (srcPort === 22 || dstPort === 22) proto = 'SSH';

    const tcpOptions = tcpHeaderLen > 20 ? parseTcpOptions(rawBytes, transportOffset + 20, transportOffset + tcpHeaderLen) : null;
    // Handshake-only options. SACK blocks are handled further down, once the
    // stream tracker is available, because their edges display relative to the
    // peer's sequence space just like Ack= does.
    const handshakeOptionParts: string[] = [];
    if (tcpOptions && syn) {
      if (tcpOptions.mss !== undefined) handshakeOptionParts.push(`MSS=${tcpOptions.mss}`);
      if (tcpOptions.windowScale !== undefined) handshakeOptionParts.push(`WS=${2 ** tcpOptions.windowScale}`);
      if (tcpOptions.sackPermitted) handshakeOptionParts.push('SACK_PERM');
    }

    const tcpPayloadStart = transportOffset + tcpHeaderLen;
    // Prefer the network layer's declared segment length over the raw frame
    // length so Ethernet's 60-byte minimum padding isn't counted as payload
    // (a bare 54-byte ACK would otherwise report Len=6). Clamping against
    // what was actually captured keeps snaplen-truncated captures honest:
    // they degrade to "however much was captured", never more. Require
    // l4SegmentLen to at least cover the TCP header itself - TCP
    // segmentation offload leaves IP Total Length at 0 on outbound frames
    // captured on the sending host's own NIC (this app's primary capture
    // setup), and without this guard that reads as "0 bytes of payload" on
    // segments that may carry a full MSS or more, silently disabling
    // retransmission/out-of-order detection for that entire direction.
    const capturedPayloadLength = Math.max(0, rawBytes.length - tcpPayloadStart);
    const payloadLength = l4SegmentLen !== undefined && l4SegmentLen >= tcpHeaderLen
      ? Math.max(0, Math.min(capturedPayloadLength, l4SegmentLen - tcpHeaderLen))
      : capturedPayloadLength;
    // Try the TLS record layer before anything else claims the payload. A hit
    // gives both the versioned Protocol label and the Info summary; a miss
    // means the frame is plain TCP however suggestive its port number is.
    const tlsResult = payloadLength > 0
      ? dissectTls(rawBytes, tcpPayloadStart, Math.min(rawBytes.length, tcpPayloadStart + payloadLength))
      : null;
    if (tlsResult) {
      proto = 'TLS';
      protocolLabel = tlsResult.protocolLabel;
    } else if (proto === 'TLS') {
      proto = 'TCP';
    }

    // TLS payloads are encrypted from essentially the first byte - never
    // scan them, since any "match" there would be a false positive.
    const tcpHost =
      !isTlsPort && tcpPayloadStart < rawBytes.length
        ? extractLiteralUrlOrHost(rawBytes, tcpPayloadStart)
        : null;
    // Register this direction's window scale before anything reads it back, so
    // a SYN's own advertised window still displays unscaled (scaling only takes
    // effect from the first non-SYN segment, per RFC 7323).
    if (tcpTracker && syn && tcpOptions?.windowScale !== undefined) {
      tcpTracker.setWindowScaleShift(srcIp, srcPort, dstIp, dstPort, tcpOptions.windowScale);
    }
    const windowScaleShift = tcpTracker && !syn ? tcpTracker.getWindowScaleShift(srcIp, srcPort, dstIp, dstPort) : 0;
    const windowSize = rawWindow * 2 ** windowScaleShift;

    const relSeq = tcpTracker ? tcpTracker.getRelativeSeq(srcIp, srcPort, dstIp, dstPort, seqNum, syn) : seqNum;
    const relAck = tcpTracker && ack ? tcpTracker.getRelativeSeq(dstIp, dstPort, srcIp, srcPort, ackNum) : ackNum;

    // SACK edges name bytes in the *peer's* sequence space - they acknowledge
    // what the other end sent - so they map through the peer direction's base,
    // exactly like Ack= does. Printing them raw shows 10-digit absolute
    // sequence numbers next to a single-digit Seq=/Ack= pair.
    const sackParts: string[] = [];
    if (tcpOptions && !syn) {
      for (const block of tcpOptions.sackBlocks) {
        const left = tcpTracker ? tcpTracker.getRelativeSeq(dstIp, dstPort, srcIp, srcPort, block.leftEdge) : block.leftEdge;
        const right = tcpTracker ? tcpTracker.getRelativeSeq(dstIp, dstPort, srcIp, srcPort, block.rightEdge) : block.rightEdge;
        sackParts.push(`SLE=${left} SRE=${right}`);
      }
    }
    const optionsSummary = [...handshakeOptionParts, ...sackParts].join(' ');

    // This segment's *own* next sequence number - deliberately independent of
    // the tracker's per-direction high-water mark, which would report the
    // stream's furthest-seen sequence for a retransmit/out-of-order segment
    // and a stale value for a keep-alive (which skips checkSequence). SYN and
    // FIN each consume one sequence number. Wireshark omits the field for
    // zero-length non-SYN/FIN segments, where it would just repeat Seq.
    const nextSeqDelta = payloadLength + (syn || fin ? 1 : 0);
    const expectedNextRel = nextSeqDelta > 0 ? relSeq + nextSeqDelta : undefined;

    let streamId: number | undefined;
    let status: Packet['status'] | undefined;
    let anomalies: AnomalyInfo[] | undefined;
    let streamPacketNumber: number | undefined;
    let conversationCompleteness: string | undefined;
    let isKeepAlive = false;
    let isKeepAliveAck = false;
    let lostSegment = false;
    let ackedUnseenSegment = false;
    if (tcpTracker) {
      streamId = tcpTracker.getStreamId(srcIp, srcPort, dstIp, dstPort);
      streamPacketNumber = tcpTracker.recordStreamPacket(streamId);
      tcpTracker.updateConnectionState(streamId, syn, ack, fin, rst);

      isKeepAlive = tcpTracker.checkKeepAlive(srcIp, srcPort, dstIp, dstPort, seqNum, payloadLength, syn, fin, rst);
      isKeepAliveAck = !isKeepAlive && payloadLength === 0 && ack && !syn && !fin && !rst
        && tcpTracker.consumeKeepAliveAck(srcIp, srcPort, dstIp, dstPort);

      // Both gap checks must run *before* checkSequence() advances this
      // direction's high-water mark, otherwise the segment that reveals the
      // gap is the same one that closes it and neither ever fires. A
      // keep-alive deliberately sits one byte behind, so it is never a gap.
      if (!isKeepAlive) {
        lostSegment = tcpTracker.isPreviousSegmentMissing(srcIp, srcPort, dstIp, dstPort, seqNum);
      }
      if (ack && !isKeepAliveAck) {
        ackedUnseenSegment = tcpTracker.isAckingUnseenSegment(srcIp, srcPort, dstIp, dstPort, ackNum);
      }

      if (!isKeepAlive) {
        const seqResult = tcpTracker.checkSequence(srcIp, srcPort, dstIp, dstPort, seqNum, payloadLength);
        if (seqResult === 'retransmit') {
          status = 'retransmit';
          anomalies = [{
            type: 'tcp-retransmission',
            severity: 'low',
            title: 'TCP Retransmission',
            description: `Segment with sequence number ${seqNum} was already seen on stream #${streamId} - likely a retransmission after packet loss or a duplicate ACK race.`,
            recommendation: 'Check for network congestion, packet loss, or an unusually high round-trip time on this path.',
          }];
        } else if (seqResult === 'out-of-order') {
          status = 'warning';
          anomalies = [{
            type: 'tcp-out-of-order',
            severity: 'low',
            title: 'TCP Out-of-Order Segment',
            description: `Segment with sequence number ${seqNum} arrived out of order relative to previously seen data on stream #${streamId}.`,
            recommendation: 'Usually harmless (multi-path routing or reordering in transit) - investigate further only if paired with retransmissions or application-level errors.',
          }];
        }
      }

      conversationCompleteness = tcpTracker.getConversationCompleteness(streamId);
    }

    // Every expert annotation is a bracketed *prefix* on the Info column, and
    // several can stack on one segment - Wireshark shows e.g.
    // "[TCP Previous segment not captured] [TCP Out-Of-Order] 443 → 51685 ...".
    // They are ordered here the way Wireshark emits them: the gap that
    // explains the segment first, then the segment's own classification.
    const expertTags: string[] = [];
    // Wireshark's own tcp.analysis.* field names, kept alongside the display
    // tags so color rules and display filters can match on them the way
    // Wireshark's do ("tcp.analysis.flags && !tcp.analysis.keep_alive").
    const analysisFlags: string[] = [];
    if (lostSegment) { expertTags.push('[TCP Previous segment not captured]'); analysisFlags.push('lost_segment'); }
    if (ackedUnseenSegment) { expertTags.push('[TCP ACKed unseen segment]'); analysisFlags.push('ack_lost_segment'); }
    if (isKeepAlive) { expertTags.push('[TCP Keep-Alive]'); analysisFlags.push('keep_alive'); }
    if (isKeepAliveAck) { expertTags.push('[TCP Keep-Alive ACK]'); analysisFlags.push('keep_alive_ack'); }
    if (status === 'retransmit') { expertTags.push('[TCP Retransmission]'); analysisFlags.push('retransmission'); }
    else if (status === 'warning') { expertTags.push('[TCP Out-Of-Order]'); analysisFlags.push('out_of_order'); }

    // When a subdissector claimed the payload, its summary *replaces* the TCP
    // one - Wireshark shows "Application Data", not the ports and sequence
    // numbers underneath it. Expert tags still lead, since they describe the
    // segment rather than its contents.
    const infoParts = tlsResult
      ? [tlsResult.info]
      : [
          `${srcPort} → ${dstPort}`,
          `[${flagList.join(', ')}]`,
          `Seq=${relSeq}`,
          ...(ack ? [`Ack=${relAck}`] : []),
          `Win=${windowSize}`,
          `Len=${payloadLength}`,
          ...(optionsSummary ? [optionsSummary] : []),
          ...(tcpHost ? [tcpHost] : []),
        ];
    const info = `${expertTags.map(t => t + ' ').join('')}${infoParts.join(' ')}`;

    return {
      proto,
      protocolLabel,
      srcPort,
      dstPort,
      info,
      streamId,
      fields: {
        'tcp.flags': flags,
        'tcp.flags.syn': syn ? 1 : 0,
        'tcp.flags.fin': fin ? 1 : 0,
        'tcp.flags.reset': rst ? 1 : 0,
        'tcp.flags.push': psh ? 1 : 0,
        'tcp.flags.ack': ack ? 1 : 0,
        'tcp.srcport': srcPort,
        'tcp.dstport': dstPort,
        'tcp.window_size': windowSize,
        'tcp.len': payloadLength,
      },
      status: status ?? (analysisFlags.length > 0 && !isKeepAlive && !isKeepAliveAck ? 'warning' : undefined),
      analysisFlags,
      anomalies,
      layer: {
        name: 'Transmission Control Protocol',
        summary: `Transmission Control Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`,
        rawBytesRange: [transportOffset, transportOffset + tcpHeaderLen - 1],
        fields: [
          { name: 'Source Port', value: srcPort, rawBytesRange: [transportOffset, transportOffset + 1] },
          { name: 'Destination Port', value: dstPort, rawBytesRange: [transportOffset + 2, transportOffset + 3] },
          {
            name: 'Sequence Number',
            value: `${relSeq} (relative sequence number)`,
            rawBytesRange: [transportOffset + 4, transportOffset + 7],
            children: [
              { name: 'Sequence Number (raw)', value: seqNum, rawBytesRange: [transportOffset + 4, transportOffset + 7] },
            ],
          },
          {
            name: 'Acknowledgment Number',
            value: `${relAck} (relative ack number)`,
            rawBytesRange: [transportOffset + 8, transportOffset + 11],
            children: [
              { name: 'Acknowledgment Number (raw)', value: ackNum, rawBytesRange: [transportOffset + 8, transportOffset + 11] },
            ],
          },
          { name: 'Header Length', value: `${tcpHeaderLen} bytes`, rawBytesRange: [transportOffset + 12, transportOffset + 12] },
          { name: 'Flags', value: `0x${flags.toString(16).padStart(3, '0')} (${flagList.join(', ')})`, rawBytesRange: [transportOffset + 12, transportOffset + 13] },
          ...(expectedNextRel !== undefined ? [{ name: '[Next Sequence Number]', value: expectedNextRel }] : []),
          ...(streamPacketNumber !== undefined ? [{ name: '[Stream Packet Number]', value: streamPacketNumber }] : []),
          ...(conversationCompleteness !== undefined ? [{ name: '[Conversation completeness]', value: conversationCompleteness }] : []),
          ...(tcpOptions ? tcpOptions.fields : []),
        ],
      },
    };
  } else if (ipProtocolNum === 17 && rawBytes.length >= transportOffset + 8) {
    // UDP Decode
    const srcPort = (rawBytes[transportOffset] << 8) | rawBytes[transportOffset + 1];
    const dstPort = (rawBytes[transportOffset + 2] << 8) | rawBytes[transportOffset + 3];
    const udpLen = (rawBytes[transportOffset + 4] << 8) | rawBytes[transportOffset + 5];

    let proto: Packet['protocol'] = 'UDP';
    let protocolLabel: string | undefined;
    // The DNS wire format is reused verbatim by mDNS, LLMNR and NBNS; each
    // keeps its own name in the Protocol column while sharing the dissector.
    const dnsPortLabel =
      srcPort === 53 || dstPort === 53 ? 'DNS' :
      srcPort === 5353 || dstPort === 5353 ? 'MDNS' :
      srcPort === 5355 || dstPort === 5355 ? 'LLMNR' :
      srcPort === 137 || dstPort === 137 ? 'NBNS' :
      undefined;
    if (dnsPortLabel) proto = 'DNS';
    else if (srcPort === 1883 || dstPort === 1883) proto = 'MQTT';

    // QUIC (HTTP/3) rides on UDP:443 and, like TLS, is encrypted from
    // essentially the first byte - never scan it, only DNS gets the precise
    // wire-format decode, everything else gets the literal-prefix scan.
    const udpPayloadStart = transportOffset + 8;
    const isQuic = srcPort === 443 || dstPort === 443;
    const isSsdp = srcPort === 1900 || dstPort === 1900;

    // The UDP header's Length field counts the 8-byte header itself, but
    // Wireshark's "Len=" - like TCP's - reports payload only.
    const udpPayloadLen = Math.max(0, udpLen - 8);

    // Each subdissector that claims the payload replaces the generic
    // "src → dst Len=n" summary entirely, the way Wireshark does.
    let info: string | null = null;

    if (dnsPortLabel) {
      const dnsInfo = dissectDns(rawBytes, udpPayloadStart);
      if (dnsInfo) {
        protocolLabel = dnsPortLabel;
        info = dnsInfo;
      }
    } else if (isSsdp) {
      const requestLine = readAsciiRequestLine(rawBytes, udpPayloadStart);
      if (requestLine) {
        protocolLabel = 'SSDP';
        // Wireshark's HTTP-style dissectors emit a trailing space after the
        // request line; kept so the diff against tshark is exact.
        info = `${requestLine} `;
      }
    } else if (isQuic) {
      // A short header is only identifiable as QUIC in the context of a
      // handshake already seen on this flow, so packets that precede one stay
      // plain UDP - which is what Wireshark reports for them too.
      const isShortHeaderCandidate = udpPayloadStart < rawBytes.length && (rawBytes[udpPayloadStart] & 0x80) === 0;
      const flowIsKnown = quicTracker?.isKnownFlow(srcIp, srcPort, dstIp, dstPort) ?? false;

      if (!isShortHeaderCandidate || flowIsKnown) {
        const knownConnectionId = isShortHeaderCandidate
          ? quicTracker?.matchConnectionId(srcIp, srcPort, dstIp, dstPort, rawBytes, udpPayloadStart + 1)
          : undefined;
        const quic = dissectQuicDatagram(
          rawBytes, udpPayloadStart, Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen), knownConnectionId
        );
        if (quic) {
          if (quic.isLongHeader) {
            quicTracker?.noteLongHeader(srcIp, srcPort, dstIp, dstPort, quic.connectionIds);
          }
          proto = 'QUIC';
          protocolLabel = 'QUIC';
          info = quic.info;
        }
      }
    }

    if (info === null) {
      // QUIC and DNS payloads are either encrypted or already structured, so
      // the literal-prefix scan only runs on everything else.
      const udpHost = !isQuic && !dnsPortLabel && udpPayloadStart < rawBytes.length
        ? extractLiteralUrlOrHost(rawBytes, udpPayloadStart)
        : null;
      info = `${srcPort} → ${dstPort} Len=${udpPayloadLen}${udpHost ? ' ' + udpHost : ''}`;
    }

    return {
      proto,
      protocolLabel,
      srcPort,
      dstPort,
      info,
      fields: {
        'udp.srcport': srcPort,
        'udp.dstport': dstPort,
        'udp.length': udpLen,
      },
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
    const icmpProtocolLabel = isIcmpv6 ? 'ICMPv6' : 'ICMP';
    const icmpType = rawBytes[transportOffset];
    const icmpCode = rawBytes[transportOffset + 1];
    const isEchoRequest = isIcmpv6 ? icmpType === 128 : icmpType === 8;
    const isEchoReply = isIcmpv6 ? icmpType === 129 : icmpType === 0;

    let icmpId: number | undefined;
    let icmpSeq: number | undefined;
    if ((isEchoRequest || isEchoReply) && rawBytes.length >= transportOffset + 8) {
      icmpId = (rawBytes[transportOffset + 4] << 8) | rawBytes[transportOffset + 5];
      icmpSeq = (rawBytes[transportOffset + 6] << 8) | rawBytes[transportOffset + 7];
    }

    let info: string;
    if (isIcmpv6) {
      switch (icmpType) {
        case 128: info = 'Echo (ping) request'; break;
        case 129: info = 'Echo (ping) reply'; break;
        case 133: info = 'Router Solicitation'; break;
        case 134: info = 'Router Advertisement'; break;
        case 135: info = describeNeighborSolicitation(rawBytes, transportOffset); break;
        case 136: info = describeNeighborAdvertisement(rawBytes, transportOffset); break;
        case 137: info = 'Redirect'; break;
        case 130: info = 'Multicast Listener Query'; break;
        case 131: info = 'Multicast Listener Report'; break;
        case 132: info = 'Multicast Listener Done'; break;
        case 143: info = 'Multicast Listener Report Message v2'; break;
        default: info = `ICMPv6 Type ${icmpType} Code ${icmpCode}`;
      }
    } else if (icmpType === 8) {
      info = 'Echo (ping) request';
    } else if (icmpType === 0) {
      info = 'Echo (ping) reply';
    } else {
      info = `ICMP Type ${icmpType} Code ${icmpCode}`;
    }

    if (icmpId !== undefined && icmpSeq !== undefined) {
      // Wireshark shows both the big-endian wire value and the same 16 bits
      // reinterpreted little-endian, since many ping implementations
      // increment the sequence counter in host (LE) byte order.
      const seqLe = ((icmpSeq << 8) | (icmpSeq >> 8)) & 0xffff;
      const ttlPart = ttl !== undefined ? `, ttl=${ttl}` : '';
      info += ` id=0x${icmpId.toString(16).padStart(4, '0')}, seq=${icmpSeq}/${seqLe}${ttlPart}`;
    }

    let icmpMatchedRequestFrameId: number | undefined;
    if (icmpTracker && icmpId !== undefined && icmpSeq !== undefined && frameId !== undefined) {
      if (isEchoRequest) {
        icmpTracker.recordRequest(srcIp, dstIp, icmpId, icmpSeq, frameId);
      } else if (isEchoReply) {
        icmpMatchedRequestFrameId = icmpTracker.matchReply(srcIp, dstIp, icmpId, icmpSeq);
        if (icmpMatchedRequestFrameId !== undefined) {
          info += ` (request in ${icmpMatchedRequestFrameId})`;
        }
      }
    }

    const fields: ProtocolField[] = [
      { name: 'Type', value: icmpType, rawBytesRange: [transportOffset, transportOffset] },
      { name: 'Code', value: icmpCode, rawBytesRange: [transportOffset + 1, transportOffset + 1] },
    ];
    if (icmpId !== undefined && icmpSeq !== undefined) {
      fields.push(
        { name: 'Identifier (BE)', value: `0x${icmpId.toString(16).padStart(4, '0')} (${icmpId})`, rawBytesRange: [transportOffset + 4, transportOffset + 5] },
        { name: 'Sequence Number (BE)', value: icmpSeq, rawBytesRange: [transportOffset + 6, transportOffset + 7] },
      );
    }

    return {
      proto: 'ICMP',
      protocolLabel: icmpProtocolLabel,
      fields: isIcmpv6
        ? { 'icmpv6.type': icmpType, 'icmpv6.code': icmpCode }
        : { 'icmp.type': icmpType, 'icmp.code': icmpCode },
      info,
      icmpMatchedRequestFrameId,
      layer: {
        name: isIcmpv6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol',
        summary: `${isIcmpv6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol'}, ${info}`,
        rawBytesRange: [transportOffset, transportOffset + (icmpId !== undefined ? 7 : 3)],
        fields,
      },
    };
  }

  return null;
}

/**
 * Parses the variable-length TCP options region (RFC 9293 3.1) starting at
 * the first byte past the fixed 20-byte header, up to (not including)
 * `optionsEnd` (the start of the real payload, derived from the Data Offset
 * field). Stops early on End-of-Option-List or anything malformed, rather
 * than guessing - a truncated/corrupt options list is common in captured
 * traffic and should degrade gracefully, not throw.
 */
function parseTcpOptions(
  rawBytes: Uint8Array,
  optionsStart: number,
  optionsEnd: number
): {
  fields: ProtocolField[];
  mss?: number;
  windowScale?: number;
  sackPermitted: boolean;
  sackBlocks: { leftEdge: number; rightEdge: number }[];
} {
  const fields: ProtocolField[] = [];
  let mss: number | undefined;
  let windowScale: number | undefined;
  let sackPermitted = false;
  const sackBlocks: { leftEdge: number; rightEdge: number }[] = [];

  let offset = optionsStart;
  while (offset < optionsEnd && offset < rawBytes.length) {
    const kind = rawBytes[offset];
    if (kind === 0) break; // End of Option List
    if (kind === 1) {
      fields.push({ name: 'TCP Option - No-Operation (NOP)', value: 'NOP', rawBytesRange: [offset, offset] });
      offset += 1;
      continue;
    }

    if (offset + 1 >= optionsEnd || offset + 1 >= rawBytes.length) break; // no room for a length byte
    const length = rawBytes[offset + 1];
    if (length < 2 || offset + length > optionsEnd || offset + length > rawBytes.length) break; // malformed - stop rather than misread

    if (kind === 2 && length === 4) {
      mss = (rawBytes[offset + 2] << 8) | rawBytes[offset + 3];
      fields.push({ name: 'TCP Option - Maximum Segment Size', value: `MSS: ${mss}`, rawBytesRange: [offset, offset + length - 1] });
    } else if (kind === 3 && length === 3) {
      windowScale = rawBytes[offset + 2];
      fields.push({ name: 'TCP Option - Window Scale', value: `${windowScale} (multiply by ${2 ** windowScale})`, rawBytesRange: [offset, offset + length - 1] });
    } else if (kind === 4 && length === 2) {
      sackPermitted = true;
      fields.push({ name: 'TCP Option - SACK Permitted', value: 'True', rawBytesRange: [offset, offset + length - 1] });
    } else if (kind === 5) {
      const blockCount = Math.floor((length - 2) / 8);
      for (let i = 0; i < blockCount; i++) {
        const blockOffset = offset + 2 + i * 8;
        const leftEdge = ((rawBytes[blockOffset] << 24) | (rawBytes[blockOffset + 1] << 16) | (rawBytes[blockOffset + 2] << 8) | rawBytes[blockOffset + 3]) >>> 0;
        const rightEdge = ((rawBytes[blockOffset + 4] << 24) | (rawBytes[blockOffset + 5] << 16) | (rawBytes[blockOffset + 6] << 8) | rawBytes[blockOffset + 7]) >>> 0;
        sackBlocks.push({ leftEdge, rightEdge });
        fields.push({ name: `TCP Option - SACK Block ${i + 1}`, value: `${leftEdge}-${rightEdge}`, rawBytesRange: [blockOffset, blockOffset + 7] });
      }
    } else if (kind === 8 && length === 10) {
      const tsval = ((rawBytes[offset + 2] << 24) | (rawBytes[offset + 3] << 16) | (rawBytes[offset + 4] << 8) | rawBytes[offset + 5]) >>> 0;
      const tsecr = ((rawBytes[offset + 6] << 24) | (rawBytes[offset + 7] << 16) | (rawBytes[offset + 8] << 8) | rawBytes[offset + 9]) >>> 0;
      fields.push({ name: 'TCP Option - Timestamps', value: `TSval ${tsval}, TSecr ${tsecr}`, rawBytesRange: [offset, offset + length - 1] });
    } else {
      fields.push({ name: `TCP Option - Unknown (Kind ${kind})`, value: `${length} bytes`, rawBytesRange: [offset, offset + length - 1] });
    }

    offset += length;
  }

  return { fields, mss, windowScale, sackPermitted, sackBlocks };
}

/**
 * Standard Internet checksum (RFC 1071) over the IPv4 header, with the
 * checksum field itself treated as zero - the same algorithm the sender
 * used to produce it, so a correct header always recomputes to the value
 * actually stored there.
 */
function computeIpHeaderChecksum(rawBytes: Uint8Array, l3Offset: number, ipHeaderLen: number): number {
  let sum = 0;
  for (let i = 0; i < ipHeaderLen; i += 2) {
    if (i === 10) continue;
    const word = i + 1 < ipHeaderLen ? (rawBytes[l3Offset + i] << 8) | rawBytes[l3Offset + i + 1] : rawBytes[l3Offset + i] << 8;
    sum += word;
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (~sum) & 0xffff;
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

// Surfacing a readable hostname/URL in the Info column is far more useful at
// a glance than "Len=76" alone - but a generic "does this look like a domain"
// regex scanned over an entire payload is a bad idea: high-entropy encrypted
// traffic (TLS, QUIC on port 443) renders as ASCII noise once non-printable
// bytes become '.', and over a large enough payload that noise very often
// happens to look like a short hostname (e.g. "3b.Hl.sBR"). No amount of
// regex tightening fixes that, because that traffic genuinely contains no
// real hostname - any match there is a false positive by construction.
//
// So instead of one heuristic scan, this uses two precise extractors and
// only runs them where cleartext can plausibly exist:
//  - DNS query names are decoded from the actual wire format (length-prefixed
//    labels), not guessed at - the length byte must numerically match the
//    label that follows, which noise essentially never satisfies.
//  - Everywhere else, only literal, highly-specific prefixes ("http://",
//    "Host: ") are matched - safe because matching an exact multi-byte
//    literal by chance in random bytes is astronomically unlikely.
// Neither runs on known-encrypted traffic (TLS/QUIC on port 443), since that
// can never contain genuine plaintext.
const URL_PATTERN = /https?:\/\/[^\s"'<>\\]+/;
const HTTP_HOST_HEADER_PATTERN = /(?:^|\r\n)Host:\s*([^\r\n]+)/i;

// formatAsciiDump() turns CR/LF into '.' along with every other non-printable
// byte, which destroys the "\r\n" line boundary the Host-header match relies
// on - this variant keeps real CR/LF characters so line-based matching works,
// while still mapping every other non-printable byte to '.' as before.
function toLineAwareText(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => {
      if (b === 13) return '\r';
      if (b === 10) return '\n';
      return b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
    })
    .join('');
}

function extractLiteralUrlOrHost(rawBytes: Uint8Array, payloadStart: number): string | null {
  const text = toLineAwareText(rawBytes.slice(payloadStart));
  const urlMatch = text.match(URL_PATTERN);
  if (urlMatch) return urlMatch[0].replace(/[.,;:)]+$/, '');
  const hostMatch = text.match(HTTP_HOST_HEADER_PATTERN);
  return hostMatch ? hostMatch[1].trim() : null;
}

/**
 * Decodes the QNAME of the first question in a DNS message using the real
 * length-prefixed label wire format (RFC 1035 4.1.2), starting right after
 * the fixed 12-byte DNS header. Returns null on anything that doesn't look
 * like a well-formed, fully-printable name (including compression pointers,
 * which aren't resolved here) rather than guessing.
 */
function decodeDnsQueryName(rawBytes: Uint8Array, dnsMessageStart: number): string | null {
  let offset = dnsMessageStart + 12; // past ID/Flags/QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT
  const labels: string[] = [];

  for (let guard = 0; guard < 32; guard++) {
    if (offset >= rawBytes.length) return null;
    const len = rawBytes[offset];
    if (len === 0) break; // root label - end of name
    if ((len & 0xc0) === 0xc0) return null; // compression pointer - not resolved here
    if (len > 63 || offset + 1 + len > rawBytes.length) return null; // malformed/truncated

    let label = '';
    for (let i = 0; i < len; i++) {
      const byte = rawBytes[offset + 1 + i];
      if (byte < 32 || byte > 126) return null; // not a printable hostname label
      label += String.fromCharCode(byte);
    }
    labels.push(label);
    offset += 1 + len;
  }

  return labels.length > 0 ? labels.join('.') : null;
}
