import { Packet, ProtocolLayer, ProtocolField, ExpertCategory, ExpertInfo } from '../types/packet';
import { CATEGORY_RANK, expertItemsFor } from './expertInfo';
import { CATEGORY_BY_FLAG } from './dissect/tcpAnalysis';
import { TcpStreamTracker } from './tcpStreamTracker';
import { resolveMacName } from './macVendors';
import { formatMac, formatIpv6Address } from './addressFormat';
import { dissectArp, dissectStp, labelForEtherType, L2DissectorResult } from './dissectors/l2';
import { dissectLinkLayer } from './dissectors/linkLayer';
import { dissectIpv4Options, dscpName, ecnName, inferTtl } from './dissectors/ipv4';
import { dissectNtp, dissectStun, dissectUdpByContent } from './dissectors/udpApps';
import { L3Tracker } from './l3Tracker';
import {
  Direction, directionFromAddresses, directionFromMacs, directionFromOffload,
  directionOf, type HostIdentity,
  ETHERNET_MAX_FRAME,
} from './direction';

/**
 * What sits in front of a transport segment on a plain Ethernet/IPv4 frame:
 * the 14-byte Ethernet header and a 20-byte IPv4 header with no options.
 *
 * `ETHERNET_MAX_FRAME` minus this is the largest transport segment that can
 * have travelled as one frame - 1,480 bytes. Past that the adapter segmented
 * it, so the bytes in the buffer were never the bytes on the wire and a
 * checksum over them means nothing. Named because `1514 - 34` stated neither
 * number's job, and 34 is the one that reads as arbitrary.
 */
const ETHERNET_IPV4_HEADER_BYTES = 14 + 20;
import { SCORING_FRAMES, inferHostIdentity } from './hostIdentity';
import { dissectTlsSegment, looksLikeTlsRecord, type TlsSegmentResult } from './dissectors/tls';
import { dissectAppStream, freshAppDirection, type AppStreamResult } from './dissectors/appStream';
import { keyLog } from './tls/keyLog';
import { buildHttp3Layer } from './dissectors/http3';
import { DSB_SECRETS_TYPE_TLS_KEY_LOG } from './pcapngWriter';
import { freshTlsConversation, freshTlsCursor } from './tcpStreamTracker';
import type { TcpAnalysis } from './dissect/tcpAnalysis';
import { LINKTYPE } from './dissect/types';
import { buildDnsLayer, dnsInfoLine, parseDnsMessage } from './dissectors/dns';
import { dissectNbns } from './dissectors/nbns';
import { dissectSyslog } from './dissectors/syslog';
import { dissectRadius } from './dissectors/radius';
import { dissectSnmp } from './dissectors/snmp';
import { DnsTracker } from './dnsTracker';
import { dissectQuicDatagram } from './dissectors/quic';
import { buildQuicTlsLayer } from './dissectors/tls';
import { dissectIeee1905 } from './dissectors/ieee1905';
import { dissectIgmp } from './dissectors/igmp';
import { dissectLldp } from './dissectors/lldp';
import { dissectDhcp, dissectDhcpv6 } from './dissectors/dhcp';
import { walkIpv6Extensions, IPV6_EXT_HEADERS, NO_NEXT_HEADER } from './dissectors/ipv6Ext';
import { QuicFlowTracker } from './quicFlowTracker';
import { displayProtocol, toBase64 } from './exportSchema';
import { buildCsvText } from './tabularWriters';
import { IcmpEchoTracker } from './icmpEchoTracker';
import { poolExpert, poolTokens } from './dissect/tokenPool';
import { FieldBlockWriter } from './dissect/fieldSplit';

/**
 * One decoder, not one per call. Constructing a TextDecoder is not free, and
 * the ASCII-line reader below runs on every frame with a payload - a CPU
 * profile put TextDecoder construction at 8% of a dissection run, the same
 * class of cost as the Intl.DateTimeFormat that was being rebuilt twice a
 * frame. Stateless without `{stream: true}`, which nothing here uses.
 */
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

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
  /**
   * The file's declared link type (`LINKTYPE`), which decides what sits in
   * front of the network header. Read and then ignored until Phase 6, so every
   * capture was decoded as if it were Ethernet.
   */
  linktype: number;
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

    // 2. Write Packet Records, in capture order. The buffer can hold frames
    //    from several adapters that arrived out of order (the ordering window
    //    only covers thread skew); a file is forever, so it is sorted here.
    //    Stable, so equal stamps keep frame-number order.
    const ordered = [...packets].sort((a, b) => a.tsUs - b.tsUs);
    for (const packet of ordered) {
      const tsSec = Math.floor(packet.tsUs / 1_000_000);
      const tsUsec = packet.tsUs - tsSec * 1_000_000;
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
   * Parses a capture file into packets, up to `maxFrames` of them.
   *
   * `totalFrames` is how many the file holds, counted by walking every record
   * header even past the cap - the caller can then say "12,858 frames, first
   * 10,000 loaded" instead of quietly showing fewer packets than the file has.
   * The cap is the caller's buffer size, not a constant here: this used to be
   * a hardcoded 10,000 in both extractors, which meant a capture exported from
   * a full 50,000-frame buffer could never be imported whole again.
   */
  /**
   * `keepTrees` decides whether the returned frames carry their protocol tree.
   *
   * The app imports without it: a tree is 10.6 kB against the frame's own
   * 1.2 kB, so keeping one per frame is what stood between the buffer and a
   * capture of any size (docs/decisions/0007). The detail pane rebuilds the
   * tree it needs by replaying that frame's conversation. Scripts that want
   * the tree - a dissector's own assertions - ask for it.
   */
  public static async parseCaptureFile(
    file: File,
    maxFrames: number = Number.POSITIVE_INFINITY,
    keepTrees = false,
  ): Promise<{ packets: Packet[]; totalFrames: number }> {
    const extracted = await PcapService.extractFrames(file, maxFrames);
    return {
      packets: PcapService.buildPacketsFromFrames(
        extracted.frames, keepTrees, PcapService.inferHostFromFrames(extracted.frames),
      ),
      totalFrames: extracted.totalFrames,
    };
  }

  /**
   * Who took this capture, decided before it is dissected for real.
   *
   * A live capture knows the answer from the agent's adapter list before the
   * first frame arrives, so the Worker passes it straight in. A file knows
   * nothing: the host has to be **inferred from the frames**, and there are no
   * frames until they have been dissected. `App.deriveForBuffer` closed that
   * loop after the fact - infer, then walk the buffer writing `direction` onto
   * each frame - and for the Direction column that is enough, because the
   * column reads the property.
   *
   * It is not enough for anything the dissector decides *using* the direction,
   * and there is one: the checksum verdict. A frame this machine sent was
   * handed to the sniffer before the NIC filled its checksum in, so the value
   * in the buffer is not the value on the wire and the honest verdict is
   * `Unverified` (see `checksumVerdict`). Deciding that after dissection is not
   * an option - the verdict is a tree row, an expert finding and a dense
   * column, and a filled column row cannot be rewritten. So the answer has to
   * be known *first*.
   *
   * **Measured, not assumed**: with no host, the two parity fixtures raised
   * 3,891 and 3,594 "Bad checksum" findings on import and painted 30.3 % and
   * 24.4 % of their lists Broken - every one of them an artefact of the capture
   * having been taken on the sending machine. That is the same noise that kept
   * the old "Expert Warnings" band switched off, arriving by a different door.
   *
   * The cost is a **bounded** extra dissection: `SCORING_FRAMES` frames at
   * most, whatever the file's size, because that is all `inferHostIdentity`
   * reads anyway - its signals are frequency ratios and converge long before
   * then. The prefix pass is thrown away; the trackers it advanced are its own.
   *
   * A second implementation of the scoring - reading MACs and TTLs straight
   * out of the bytes - would avoid the pass and is the wrong trade: two
   * implementations of one decision agree until they do not, and this repo has
   * already paid that price once over the agent's wire format.
   */
  private static inferHostFromFrames(frames: ExtractedFrame[]): HostIdentity | undefined {
    if (frames.length === 0) return undefined;
    const prefix = frames.length > SCORING_FRAMES ? frames.slice(0, SCORING_FRAMES) : frames;
    return inferHostIdentity(PcapService.buildPacketsFromFrames(prefix)) ?? undefined;
  }

  /** Every frame in the file, as a plain array. */
  public static async parsePcapFile(file: File): Promise<Packet[]> {
    return (await PcapService.parseCaptureFile(file)).packets;
  }

  /** Every frame, with its protocol tree - for scripts that assert on trees. */
  public static async parsePcapFileWithTrees(file: File): Promise<Packet[]> {
    return (await PcapService.parseCaptureFile(file, Number.POSITIVE_INFINITY, true)).packets;
  }

  private static async extractFrames(
    file: File,
    maxFrames: number,
  ): Promise<{ frames: ExtractedFrame[]; totalFrames: number }> {
    const arrayBuffer = await file.arrayBuffer();

    if (arrayBuffer.byteLength < 8) {
      throw new Error('File is too small to be a valid PCAP file.');
    }

    const magic = new DataView(arrayBuffer).getUint32(0, false);

    // pcapng's Section Header Block type (0x0A0D0D0A) is a byte-palindrome,
    // so it reads identically regardless of the file's actual byte order -
    // no endianness detection needed before recognizing it.
    if (magic === 0x0a0d0d0a) {
      return PcapService.extractPcapNgFrames(arrayBuffer, maxFrames);
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
      // Not a magic number this parser knows.
      //
      // This branch used to try `JSON.parse` and, if the result was an array,
      // return it verbatim AS `Packet[]` - no validation of any kind. Any JSON
      // array at all therefore became "packets": objects with no `rawBytes`,
      // which throw the moment the hex pane renders one. JSON now goes through
      // `tabularImport.ts` with every other format, where it is checked.
      //
      // Falling through to a classic-pcap parse is kept: a headerless or
      // slightly-off capture is still worth attempting, and it costs a bad
      // frame count rather than a crash.
    }

    // The global header's last field is the link type every frame in the file
    // shares. It has always been parsed by the comment at the top of this file
    // and by nothing else.
    const linktype = new DataView(arrayBuffer).getUint32(20, isLittleEndian);
    return PcapService.extractClassicPcapFrames(arrayBuffer, isLittleEndian, subSecondIsNanos, maxFrames, linktype);
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
    subSecondIsNanos: boolean,
    maxFrames: number,
    linktype: number,
  ): { frames: ExtractedFrame[]; totalFrames: number } {
    const view = new DataView(buffer);
    const frames: ExtractedFrame[] = [];
    let totalFrames = 0;
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

      totalFrames++;
      // Past the cap the walk continues over the record headers alone, so the
      // total is exact without holding the bytes of frames that won't load.
      if (frames.length < maxFrames) {
        frames.push({
          rawBytes: new Uint8Array(buffer.slice(offset, offset + capLen)),
          tsNanos: BigInt(tsSec) * 1_000_000_000n + BigInt(tsSubSecond) * nanosPerSubSecondUnit,
          origLen,
          tsPrecision,
          linktype,
        });
      }
      offset += capLen;
    }

    return { frames, totalFrames };
  }

  /**
   * Extracts raw frames + timestamps from a pcapng file by walking its
   * block structure: a Section Header Block establishes byte order for
   * everything that follows it, Interface Description Blocks record each
   * interface's timestamp resolution, and Enhanced Packet Blocks carry the
   * actual frame bytes, and a Decryption Secrets Block hands over the key log
   * for the connections in the file. Any other block type (interface stats,
   * name resolution, vendor-specific blocks, ...) is safely skipped using its
   * own declared length - a reader doesn't need to understand every block kind
   * to walk past it, which is the whole point of the block-based format.
   */
  private static extractPcapNgFrames(
    buffer: ArrayBuffer,
    maxFrames: number,
  ): { frames: ExtractedFrame[]; totalFrames: number } {
    const view = new DataView(buffer);
    const frames: ExtractedFrame[] = [];
    let totalFrames = 0;
    let offset = 0;
    let isLittleEndian = true;
    // Per-interface timestamp resolution (seconds per tick), indexed by
    // declaration order within the current section - this is exactly what
    // an Enhanced Packet Block's Interface ID field refers to.
    let interfaceResolutions: number[] = [];
    // Per-interface link type, indexed the same way. A pcapng file may hold
    // interfaces with different link layers in one section - which is exactly
    // what `tcpdump -i any` produces - so this cannot be a per-file constant.
    let interfaceLinkTypes: number[] = [];

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
        interfaceLinkTypes = [];
      } else if (blockType === 0x00000001) {
        // Interface Description Block: LinkType(2) Reserved(2) SnapLen(4), then options.
        const ifLinkType = view.getUint16(offset + 8, isLittleEndian);
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
        interfaceLinkTypes.push(ifLinkType);
      } else if (blockType === 0x0000000a) {
        // Decryption Secrets Block: SecretsType(4) SecretsLength(4), then the
        // secrets. Read here rather than in a pass of its own because a DSB is
        // written *before* the packets it opens, so walking the file in order
        // is what makes the secrets available by the time those frames are
        // dissected. A file that carries its own secrets needs nothing from
        // the user at all.
        const secretsType = view.getUint32(offset + 8, isLittleEndian);
        const secretsLength = view.getUint32(offset + 12, isLittleEndian);
        if (secretsType === DSB_SECRETS_TYPE_TLS_KEY_LOG && offset + 16 + secretsLength <= offset + blockLen) {
          const text = utf8Decoder
            .decode(new Uint8Array(buffer, offset + 16, secretsLength));
          keyLog.add(text);
        }
      } else if (blockType === 0x00000006) {
        // Enhanced Packet Block: InterfaceID(4) TsHigh(4) TsLow(4) CapLen(4) OrigLen(4), then data.
        const interfaceId = view.getUint32(offset + 8, isLittleEndian);
        const tsHigh = view.getUint32(offset + 12, isLittleEndian);
        const tsLow = view.getUint32(offset + 16, isLittleEndian);
        const capLen = view.getUint32(offset + 20, isLittleEndian);
        const origLen = view.getUint32(offset + 24, isLittleEndian);
        const dataStart = offset + 28;

        if (dataStart + capLen <= buffer.byteLength) {
          totalFrames++;
          if (frames.length >= maxFrames) {
            offset += blockLen;
            continue;
          }
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
            linktype: interfaceLinkTypes[interfaceId] ?? LINKTYPE.ETHERNET,
          });
        }
      }
      // Every other block type carries no frame data we need.

      offset += blockLen;
    }

    return { frames, totalFrames };
  }

  /**
   * Shared decode pass used by both the classic-pcap and pcapng extractors:
   * runs each extracted frame through the same dissection pipeline used for
   * live-captured packets, so imported files and live capture produce
   * identical Packet shapes.
   */
  private static buildPacketsFromFrames(
    frames: ExtractedFrame[],
    keepTrees = false,
    /** See `inferHostFromFrames`. Absent means every frame reads as Unknown. */
    host?: HostIdentity,
  ): Packet[] {
    const parsedPackets: Packet[] = [];
    let packetIndex = 1;
    let baseNanos: bigint | null = null;
    let prevNanos: bigint | null = null;
    const tcpTracker = new TcpStreamTracker();
    const icmpTracker = new IcmpEchoTracker();
    const quicTracker = new QuicFlowTracker();
    const dnsTracker = new DnsTracker();
    const l3Tracker = new L3Tracker();

    for (const frame of frames) {
      if (baseNanos === null) baseNanos = frame.tsNanos;
      // Subtracting in bigint *before* converting to a float is what keeps
      // nanosecond precision: the difference is a small number of seconds, so
      // it lands well inside float64's exact range even though the absolute
      // epoch-nanosecond value does not.
      const relativeTime = Number(frame.tsNanos - baseNanos) / 1e9;
      const timeDelta = prevNanos === null ? 0 : Number(frame.tsNanos - prevNanos) / 1e9;
      prevNanos = frame.tsNanos;
      const tsUs = Number(frame.tsNanos / 1000n);

      const { packet, icmpMatchedRequestFrameId, infoPatches } = decodeRawEthernetPacket(
        frame.rawBytes, packetIndex++, tsUs, relativeTime, timeDelta, frame.origLen,
        tcpTracker, icmpTracker, quicTracker, dnsTracker, undefined, frame.linktype, l3Tracker,
        host,
      );
      packet.tsPrecision = frame.tsPrecision;
      if (frame.tsPrecision > 6) packet.tsNanos = frame.tsNanos;
      // Dissected, then dropped: the tree has already done its work by here -
      // it is what the fields, the Info line and the expert findings were read
      // out of - and keeping one per frame is 89% of a buffer's memory.
      if (!keepTrees) packet.layers = [];
      parsedPackets.push(packet);

      if (icmpMatchedRequestFrameId !== undefined) {
        // Indexed, not searched - on the same invariant the block below states
        // and has always relied on. As a `.find` this scanned the whole
        // growing array once per ICMP reply, so importing a ping-heavy capture
        // of N frames with k replies cost O(N*k); the guard on `id` is what
        // makes the index safe if that invariant ever stops holding.
        const requestPacket = parsedPackets[icmpMatchedRequestFrameId - 1];
        if (requestPacket && requestPacket.id === icmpMatchedRequestFrameId) {
          requestPacket.info += ` (reply in ${packet.id})`;
        }
      }
      if (infoPatches) {
        // Frame ids are 1-based positions in this array, so no search is needed.
        for (const patch of infoPatches) {
          const target = parsedPackets[patch.frameId - 1];
          if (target && target.id === patch.frameId) applyInfoPatch(target, patch);
        }
      }
    }

    // The dense fields move into columns once the frames are built - at the one
    // moment a finished frame joins a buffer, rather than inside the dissector,
    // which has no single write to intercept (`dissect/fieldSplit.ts`).
    new FieldBlockWriter().absorb(parsedPackets);

    return parsedPackets;
  }

  /**
   * Export to JSON string.
   *
   * The field names are the ones `exportSchema` recognises, and `epoch` is
   * present, so a JSON export re-imports through the same evaluator as a CSV.
   * It did not before: the old shape renamed `id` to `no` and `relativeTime`
   * to `time`, dropped `rawBytes` entirely, and was then handed straight back
   * to the app as if it were a `Packet[]`.
   *
   * `layers` stays in - it is what makes this export readable by other tools -
   * but it is decoration on the way back, because the layers are re-derived
   * from `rawBytes` when those are present and cannot be trusted when they
   * are not.
   */
  public static exportToJson(packets: Packet[], includeRawBytes = false): string {
    const sanitized = packets.map(p => ({
      no: p.id,
      time: p.relativeTime.toFixed(6),
      epoch: p.tsUs / 1000,
      source: p.source,
      destination: p.destination,
      protocol: displayProtocol(p),
      length: p.length,
      info: p.info,
      status: p.status,
      expert: expertItemsFor(p).map((i) => i.summary).join('; '),
      ...(includeRawBytes
        ? { rawBytes: p.rawBytes.length > 0 ? toBase64(p.rawBytes) : '' }
        : {}),
      layers: p.layers.map(l => ({
        layer: l.name,
        summary: l.summary,
        fields: l.fields.map(mapField),
      })),
    }));

    return JSON.stringify(sanitized, null, 2);
  }

  /**
   * Export to CSV.
   *
   * Delegates to `tabularWriters` so CSV, Excel and the importer cannot drift
   * apart on columns, quoting or encoding. The hand-rolled version this
   * replaced quoted three columns of nine, emitted no BOM, and joined with
   * bare LF.
   */
  public static exportToCsv(packets: Packet[], includeRawBytes = false): string {
    return buildCsvText(packets, includeRawBytes);
  }
}

/**
 * Maps dissected layer names to their conventional filter-field abbreviations for
 * the Frame layer's "[Protocols in frame]" field. Module-level so it isn't
 * rebuilt once per decoded packet.
 */
/**
 * Every finding in the tree, flattened, and the one the frame is painted by.
 *
 * Two answers from one walk because they are read by different things and
 * neither can go back for the other. `inwire.expert.category` is published as
 * a field so a colour rule and a display filter can ask what is wrong with a
 * frame - neither can walk a tree, which is why the expert system could not
 * reach the packet list at all before this existed. The flat list lands on
 * `Packet.expert` because the tree is dissected on demand
 * (docs/decisions/0007) and Expert Information aggregates over the whole
 * buffer, where no tree exists to walk.
 *
 * "Strongest" is first in `CATEGORY_ORDER`, not worst on a scale - there is no
 * scale any more. It is the same tie-break the shipped colour chain applies,
 * stated once so the field and the chain cannot disagree about a frame that is
 * both Broken and a Capture gap.
 */
function collectExpert(
  layers: ProtocolLayer[],
): { expert?: ExpertInfo[]; strongest?: ExpertCategory } {
  let strongest: ExpertCategory | undefined;
  const found: ExpertInfo[] = [];
  // First in `CATEGORY_ORDER` wins, which is the same order the shipped colour
  // rules sit in - so the category published as a field is the one the row is
  // actually painted by, rather than a second opinion about the same frame.
  const consider = (c: ExpertCategory) => {
    if (strongest === undefined || CATEGORY_RANK[c] < CATEGORY_RANK[strongest]) strongest = c;
  };
  const visit = (fields: ProtocolField[]) => {
    for (const field of fields) {
      if (field.expertInfo) {
        found.push(field.expertInfo);
        consider(field.expertInfo.category ?? 'Note');
      }
      if (field.children) visit(field.children);
    }
  };
  for (const layer of layers) visit(layer.fields);
  // Pooled: a finding is a fixed sentence a dissector emits, so the same set
  // recurs across a capture - 209 distinct sets over both fixtures, against
  // one array per frame that carries any (`dissect/tokenPool.ts`).
  return { expert: found.length > 0 ? poolExpert(found) : undefined, strongest };
}

const PROTOCOL_NAME_MAP: Record<string, string> = {
  'Frame': 'frame',
  'NetBIOS Name Service': 'nbns',
  'Syslog message': 'syslog',
  'RADIUS Protocol': 'radius',
  'Simple Network Management Protocol': 'snmp',
  'Transport Layer Security': 'tls',
  'Hypertext Transfer Protocol': 'http',
  'HyperText Transfer Protocol 2': 'http2',
  'HyperText Transfer Protocol Version 3': 'http3',
  'Ethernet II': 'eth',
  '802.1Q Virtual LAN': 'vlan',
  // The link layers a capture file may declare instead of Ethernet
  // (services/dissectors/linkLayer.ts). Without these the underscore rule
  // would name them `linux_cooked_capture_v1` and `null/loopback`, neither of
  // which is a filter token anybody could type.
  'Logical-Link Control': 'llc',
  'Linux cooked capture v1': 'sll',
  'Linux cooked capture v2': 'sll',
  'Null/Loopback': 'null',
  'Internet Protocol Version 4': 'ip',
  'Internet Protocol Version 6': 'ipv6',
  'Transmission Control Protocol': 'tcp',
  'User Datagram Protocol': 'udp',
  'Internet Control Message Protocol': 'icmp',
  'Internet Control Message Protocol v6': 'icmpv6',
  'Address Resolution Protocol': 'arp',
  'Spanning Tree Protocol': 'stp',
  'IEEE 1905.1a': 'ieee1905',
  'Domain Name System': 'dns',
  'Dynamic Host Configuration Protocol': 'dhcp',
  'DHCPv6': 'dhcpv6',
  'Link Layer Discovery Protocol': 'lldp',
  'Internet Group Management Protocol': 'igmp',
  // The IPv6 extension headers. Without these the layer names fall through to
  // the underscore rule and the protocol hierarchy reads
  // `ipv6_hop-by-hop_options` where Wireshark reads `ipv6.hopopts` - and the
  // walker's own token would be appended a second time at the end of the
  // chain, out of the position it actually occupies.
  'IPv6 Hop-by-Hop Options': 'ipv6.hopopts',
  'IPv6 Destination Options': 'ipv6.dstopts',
  'IPv6 Routing': 'ipv6.routing',
  'IPv6 Fragment': 'ipv6.fragment',
  'IPv6 Authentication Header': 'ah',
  'IPv6 Encapsulating Security Payload': 'ipv6.ext',
  'IPv6 Mobility': 'ipv6.ext',
  'IPv6 Host Identity Protocol': 'ipv6.ext',
  'IPv6 Shim6': 'ipv6.ext',
};

/**
 * Ports a cleartext HTTP dissector is offered. Wireshark's own default list,
 * minus the ones this build has no reason to claim.
 */
const HTTP_PORTS = new Set([80, 591, 3128, 8000, 8008, 8080, 8888]);

export function decodeRawEthernetPacket(
  rawBytes: Uint8Array,
  id: number,
  tsUs: number,
  relativeTime: number,
  timeDelta: number,
  origLen: number,
  tcpTracker?: TcpStreamTracker,
  icmpTracker?: IcmpEchoTracker,
  quicTracker?: QuicFlowTracker,
  dnsTracker?: DnsTracker,
  /**
   * The adapter this frame was captured from, for the Frame layer's interface
   * rows. Absent for imported captures, which carry no live interface - the
   * rows then say so rather than inventing one.
   */
  captureInterface?: { name: string; label: string },
  /**
   * The capture's link type (`LINKTYPE`). Defaults to Ethernet, which is what
   * the live agent always captures and what every caller assumed before
   * Phase 6 - but an imported file says what it holds, and now that is read.
   */
  linktype: number = LINKTYPE.ETHERNET,
  /**
   * Fragments and ARP bindings - the two facts about the network layer that
   * are invisible in any single frame. Appended last rather than slotted in
   * beside the other trackers so no existing positional call site moves.
   * See services/l3Tracker.ts.
   */
  l3Tracker?: L3Tracker,
  /**
   * Who this machine is, for deciding which way each frame went.
   *
   * Appended last, like `l3Tracker` before it, so no positional call site
   * moves. Absent - or empty - means the question cannot be answered, and the
   * frame carries `Direction.Unknown` rather than a guess. See
   * `services/direction.ts`.
   */
  host?: HostIdentity,
): {
  packet: Packet;
  icmpMatchedRequestFrameId?: number;
  infoPatches?: InfoPatch[];
  /** name -> addresses this frame taught, for the passive resolution map. */
  resolvedNames?: { name: string; addresses: string[] }[];
} {
  const interfaceName = captureInterface?.name ?? 'unknown';
  const interfaceDescription = captureInterface?.label ?? 'Imported capture';
  // hexDump/asciiDump are deliberately NOT built here. They are display
  // artifacts for the ONE packet a user has selected, but building them
  // eagerly stored them for every packet in the buffer: for a 1500-byte
  // frame the two strings cost roughly 13KB of UTF-16 on top of the 1.5KB
  // of rawBytes they were both derived from. Deriving them on demand via
  // packetHexDump()/packetAsciiDump() below is what makes a 50,000-packet
  // buffer fit in memory at all.

  // The link layer the capture file says it has - Ethernet, Linux cooked,
  // raw IP or loopback - with its VLAN tags stripped and its LLC/SNAP header
  // read. Until Phase 6 this was hard-coded to Ethernet II at offset 14 and
  // the file's own declaration was parsed and ignored
  // (services/dissectors/linkLayer.ts).
  const link = dissectLinkLayer(rawBytes, linktype);
  const srcMac = link.srcMac ?? '00:00:00:00:00:00';
  const dstMac = link.dstMac ?? '00:00:00:00:00:00';

  // Frames with no network layer (ARP, STP, other pure-L2 traffic) show their
  // MAC addresses in the address columns, resolved to names the way the reference analyzer
  // does - "SagemcomBroa_5d:cc:62", "Broadcast", "Nearest-Customer-Bridge".
  // The IPv4/IPv6 branches below overwrite these when an L3 address exists.
  let srcIp = link.srcMac ? resolveMacName(srcMac) : '';
  let dstIp = link.dstMac ? resolveMacName(dstMac) : '';

  // Which way this frame went, decided here because this is the last moment
  // the MACs are still the frame's own: the IPv4 and IPv6 branches below
  // overwrite srcIp/dstIp with network addresses. The MAC test is the
  // strongest signal there is and answers for every frame on an Ethernet link,
  // including the broadcasts this machine sends - which is why the source is
  // tested before the destination. Links with no MACs at all (a TUN-style VPN)
  // fall through to the address test after dissection.
  let direction = host ? directionFromMacs(link.srcMac, link.dstMac, host) : 0;
  /**
   * Did this machine send the frame?
   *
   * Read here, from the MAC decision alone, because it is needed by the
   * checksum verdict deep in the network and transport branches - long before
   * the address-based fallback runs. On any Ethernet capture the MACs have
   * already answered; on a link with no MACs the answer is "not known", which
   * is the safe way round: an unknown frame keeps the ordinary verdict rather
   * than being excused.
   */
  const sentByUs = directionOf(direction) === Direction.Out;
  let proto: Packet['protocol'] = 'TCP';
  // The Protocol column's free-form label, when it differs from the coarse
  // ProtocolType - "TLSv1.2", "ICMPv6", "STP". Left undefined when the two
  // would read the same.
  let protocolLabel: string | undefined;
  // The reference analyzer's tcp.analysis.* field names that fired for this frame, if any.
  let analysisFlags: string[] | undefined;
  // Dissected values under their conventional field names, for display filters
  // and color rules to reference generically.
  const filterFields: Record<string, string | number> = { ...link.fields };
  let srcPort: number | undefined;
  let dstPort: number | undefined;
  let info = `Frame (${rawBytes.length} bytes)`;
  let status: Packet['status'] = 'ok';
  let streamId: number | undefined;
  let icmpMatchedRequestFrameId: number | undefined;
  let infoPatches: InfoPatch[] | undefined;
  /** frameProtocols tokens for IPv6 extension headers, which have no layer name mapping. */
  let extensionTokens: string[] = [];
  /**
   * Tokens for a dissector that claims the transport payload without adding a
   * layer of its own (QUIC, SSDP), and where in the chain they go.
   *
   * Appending them was wrong in a way the protocol hierarchy made obvious: a
   * QUIC frame carrying a TLS handshake ends up with `... udp tls`, so an
   * appended `quic` read as a child of TLS - the exact inverse of what
   * contains what.
   */
  let transportTokens: string[] = [];
  let transportLayerIndex = -1;
  let resolvedNames: { name: string; addresses: string[] }[] | undefined;

  const layers: ProtocolLayer[] = [
    {
      name: 'Frame',
      summary: `Frame ${id}: ${origLen || rawBytes.length} bytes on wire (${(origLen || rawBytes.length) * 8} bits), ${rawBytes.length} bytes captured (${rawBytes.length * 8} bits)`,
      rawBytesRange: [0, rawBytes.length - 1],
      // Ordered as the reference analyzer orders it: identity, then encapsulation, then the
      // three clocks, then the generated deltas, then the frame's own numbers.
      fields: [
        { name: 'Section number', value: 1, generated: true },
        {
          name: 'Interface id',
          value: `0 (${interfaceName})`,
          generated: true,
          children: [
            { name: 'Interface name', value: interfaceName, generated: true },
            { name: 'Interface description', value: interfaceDescription, generated: true },
          ],
        },
        { name: 'Encapsulation type', value: link.encapsulation },
        { name: 'Arrival Time', value: formatArrivalTime(tsUs) },
        { name: 'UTC Arrival Time', value: formatArrivalTime(tsUs, true) },
        { name: 'Epoch Arrival Time', value: `${Math.floor(tsUs / 1_000_000)}.${String(tsUs % 1_000_000).padStart(6, '0')}000` },
        { name: '[Time shift for this packet]', value: '0.000000000 seconds', generated: true },
        { name: '[Time delta from previous captured frame]', value: `${timeDelta.toFixed(9)} seconds`, generated: true },
        { name: '[Time delta from previous displayed frame]', value: `${timeDelta.toFixed(9)} seconds`, generated: true },
        { name: '[Time since reference or first frame]', value: `${relativeTime.toFixed(9)} seconds`, generated: true },
        { name: 'Frame Number', value: id },
        { name: 'Frame Length', value: `${origLen || rawBytes.length} bytes (${(origLen || rawBytes.length) * 8} bits)` },
        { name: 'Capture Length', value: `${rawBytes.length} bytes (${rawBytes.length * 8} bits)` },
        { name: '[Frame is marked]', value: 'False', generated: true },
        { name: '[Frame is ignored]', value: 'False', generated: true },
        // A frame longer than the Ethernet MTU was never on the wire in this
        // shape: the adapter's segmentation offload split it, and the capture
        // was taken before that happened. It is why the checksum in it is
        // often zero, and saying so here is what stops that reading as damage.
        ...((origLen || rawBytes.length) > ETHERNET_MAX_FRAME ? [{
          name: '[Frame exceeds MTU]',
          value: 'Segmentation offloaded to the adapter; this frame was never sent in this form',
          generated: true,
          expertInfo: {
            // Unverifiable rather than a protocol note: a frame this large was
            // handed to the sniffer above segmentation offload, so its size is
            // an artefact of where we are standing, not of the wire.
            category: 'Unverifiable' as const,
            message: `Frame is ${origLen || rawBytes.length} bytes, past the ${ETHERNET_MAX_FRAME}-byte Ethernet MTU - segmentation offload`,
          },
        }] : []),
      ],
    },
    ...link.layers,
  ];

  const l3Offset = link.l3Offset;
  const currentEtherType = link.etherType;

  // Link-layer protocols that carry no IP header. These have to be dispatched
  // before the IPv4/IPv6 branches, and without them a frame keeps this
  // function's fallback protocol - which is why ARP and STP frames used to be
  // labeled "TCP" and summarized as "Frame (N bytes)".
  //
  // An ethertype field <= 1500 is really an 802.3 *length*, and what follows
  // is an LLC header (DSAP/SSAP/Control) rather than a network-layer header.
  // DSAP 0x42 is the Spanning Tree Protocol's service access point.
  const isLlcFrame = link.llcOffset !== undefined && currentEtherType <= 1500;
  let l2Result: L2DissectorResult | null = null;
  if (currentEtherType === 0x0806) {
    l2Result = dissectArp(rawBytes, l3Offset);
  } else if (currentEtherType === 0x893a) {
    l2Result = dissectIeee1905(rawBytes, l3Offset);
  } else if (currentEtherType === 0x88cc) {
    l2Result = dissectLldp(rawBytes, l3Offset);
  } else if (link.llcDsap === 0x42 && link.llcOffset !== undefined) {
    // A BPDU's offsets are defined relative to its LLC header, not to the
    // frame, so the STP dissector is given where that header started rather
    // than where the link layer finished.
    l2Result = dissectStp(rawBytes, link.llcOffset);
  }

  if (l2Result) {
    // One address answered by two different MACs is either a misconfiguration
    // or somebody spoofing, and it is invisible in either frame alone. Only a
    // claim counts - a request's target fields are a question, and treating
    // them as a binding would report every ARP scan as a conflict.
    // `fields` is optional on the result and the ARP dissector always sets it,
    // so this guard has never fired. It is here because the type says it can
    // be absent and a dissector added later may well leave it so - which under
    // the old non-strict compiler would have read two properties off
    // `undefined` at runtime rather than failing to build.
    if (l2Result.protocolLabel === 'ARP' && l3Tracker && l2Result.fields) {
      const claimedIp = l2Result.fields['arp.src.proto_ipv4'];
      const claimedMac = l2Result.fields['arp.src.hw_mac'];
      if (typeof claimedIp === 'string' && typeof claimedMac === 'string') {
        const conflict = l3Tracker.arpClaim(claimedIp, claimedMac, id);
        if (conflict) {
          l2Result.layer.fields.push({
            name: '[Duplicate IP address detected]',
            value: `${conflict.address} was claimed by ${conflict.previousMac} in frame ${conflict.previousFrame}`,
            generated: true,
            linkToFrame: conflict.previousFrame,
            expertInfo: {
              category: 'Security',
              message: `Duplicate IP address configured (${conflict.address})`,
            },
          });
          l2Result.info += ` (duplicate use of ${conflict.address} detected!)`;
        }
      }
    }
    Object.assign(filterFields, l2Result.fields);
    protocolLabel = l2Result.protocolLabel;
    proto = l2Result.protocolLabel === 'ARP' ? 'ARP' : 'TCP';
    info = l2Result.info;
    layers.push(l2Result.layer);
  } else if (currentEtherType !== 0x0800 && currentEtherType !== 0x86dd) {
    // Not dissected, but still nameable from the ethertype - better an honest
    // "ieee1905" than an inherited default of "TCP".
    //
    // Info has to be set here too, not just the label. Leaving it alone is
    // what made LLDP frames show "Frame (57 bytes)" in the Info column while
    // the Protocol column read LLDP correctly: this branch named the protocol
    // and then let the frame-length placeholder stand. Any ethertype that
    // lands here from now on says what it is.
    const known = labelForEtherType(currentEtherType);
    protocolLabel = known
      ?? (isLlcFrame ? 'LLC' : `0x${currentEtherType.toString(16).padStart(4, '0')}`);
    const etherTypeHex = `0x${currentEtherType.toString(16).padStart(4, '0')}`;
    const l2PayloadLen = Math.max(0, rawBytes.length - l3Offset);
    info = isLlcFrame
      ? `LLC frame, ${l2PayloadLen} byte${l2PayloadLen === 1 ? '' : 's'}`
      : known
        ? `${known} (${etherTypeHex}), ${l2PayloadLen} byte${l2PayloadLen === 1 ? '' : 's'}`
        : `Ethernet II, unhandled ethertype ${etherTypeHex}`;
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
    // Same offload policy as the transport checksums (see `checksumVerdict`):
    // a header captured on the sending host before the NIC filled the field in
    // is "Unverified", never "Bad". A zero header checksum is not legal on the
    // wire, and a frame past the MTU was segmented by the adapter - both mean
    // the bytes here were never the bytes that were sent.
    // ...and a header on a frame we sent, for the same reason: partial offload
    // leaves a non-zero wrong value that looks exactly like corruption.
    const ipChecksumStatus = headerChecksumActual === 0 || origLen > ETHERNET_MAX_FRAME || sentByUs
      ? 'Unverified'
      : checksumCorrect ? 'Good' : 'Bad';
    const ttlGuess = inferTtl(ttl);
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
          // Named, not numbered. IPv6 has shown "EF PHB" and "ECT(0)" since
          // this phase's first half; IPv4 printed 46 and 2, so the same
          // traffic read differently depending on which version carried it.
          name: 'Differentiated Services Field',
          value: `0x${tos.toString(16).padStart(2, '0')} (DSCP: ${dscpName(dscp)}, ECN: ${ecnName(ecn)})`,
          rawBytesRange: [l3Offset + 1, l3Offset + 1],
          children: [
            { name: 'Differentiated Services Codepoint', value: `${dscpName(dscp)} (${dscp})`, abbrev: 'ip.dsfield.dscp', rawBytesRange: [l3Offset + 1, l3Offset + 1] },
            { name: 'Explicit Congestion Notification', value: `${ecnName(ecn)} (${ecn})`, abbrev: 'ip.dsfield.ecn', rawBytesRange: [l3Offset + 1, l3Offset + 1] },
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
        {
          name: 'Time to Live (TTL)',
          value: ttl,
          abbrev: 'ip.ttl',
          rawBytesRange: [l3Offset + 8, l3Offset + 8],
          // A TTL of 57 means nothing on its own and means "seven hops away"
          // once you know what initial values stacks actually use. Generated,
          // because it is inferred - see inferTtl.
          children: ttlGuess ? [
            { name: '[Inferred initial TTL]', value: ttlGuess.initial, generated: true },
            { name: '[Hops away]', value: ttlGuess.hops, generated: true },
          ] : undefined,
        },
        { name: 'Protocol', value: ipProtocolNum === 6 ? 'TCP (6)' : ipProtocolNum === 17 ? 'UDP (17)' : `${ipProtocolNum}`, abbrev: 'ip.proto', rawBytesRange: [l3Offset + 9, l3Offset + 9] },
        {
          name: 'Header Checksum',
          value: `0x${headerChecksumActual.toString(16).padStart(4, '0')} [${checksumCorrect ? 'correct' : 'incorrect'}]`,
          rawBytesRange: [l3Offset + 10, l3Offset + 11],
          abbrev: 'ip.checksum',
          children: [
            // The row's value is the status the field carries, not prose:
            // a row with an abbrev is one right-click from becoming a filter,
            // and `ip.checksum.status == "Correct"` would match nothing.
            {
              name: '[Header checksum status]',
              value: ipChecksumStatus,
              generated: true,
              abbrev: 'ip.checksum.status',
              ...(ipChecksumStatus === 'Bad'
                ? { expertInfo: { category: 'Broken' as const, message: `Bad checksum, should be 0x${headerChecksumComputed.toString(16).padStart(4, '0')}` } }
                : {}),
            },
          ],
        },
        { name: 'Source Address', value: srcIp, abbrev: 'ip.src', rawBytesRange: [l3Offset + 12, l3Offset + 15] },
        { name: 'Destination Address', value: dstIp, abbrev: 'ip.dst', rawBytesRange: [l3Offset + 16, l3Offset + 19] },
      ],
    };

    // Anything between the fixed 20-byte header and the transport header is
    // options. `ipHeaderLen` was used to find the transport header and the
    // bytes in between were never looked at - which loses the Router Alert
    // that every IGMP report on a normal network carries.
    if (ipHeaderLen > 20) {
      const options = dissectIpv4Options(rawBytes, l3Offset + 20, l3Offset + ipHeaderLen);
      if (options.length > 0) {
        ipLayer.fields.push({
          name: 'Options',
          value: `(${ipHeaderLen - 20} bytes)`,
          rawBytesRange: [l3Offset + 20, l3Offset + ipHeaderLen - 1],
          children: options,
        });
        filterFields['ip.opt.type'] = rawBytes[l3Offset + 20];
      }
    }

    layers.push(ipLayer);

    const transportOffset = l3Offset + ipHeaderLen;
    filterFields['ip.ttl'] = ttl;
    filterFields['ip.src'] = srcIp;
    filterFields['ip.dst'] = dstIp;
    filterFields['ip.checksum'] = headerChecksumActual;
    filterFields['ip.checksum.status'] = ipChecksumStatus;
    filterFields['ip.proto'] = ipProtocolNum;
    filterFields['ip.dsfield.dscp'] = dscp;
    filterFields['ip.dsfield.ecn'] = ecn;
    filterFields['ip.hdr_len'] = ipHeaderLen;
    filterFields['ip.id'] = identification;
    filterFields['ip.flags.df'] = dontFragment;
    filterFields['ip.flags.mf'] = moreFragments;
    filterFields['ip.frag_offset'] = fragmentOffset;

    // A fragmented datagram's transport header is in its FIRST fragment only.
    // Every other fragment carries application data at that offset, and
    // decoding it as a transport header produced two invented port numbers and
    // a length read out of the payload - specific, plausible, and nothing
    // about it looked like a failure.
    const fragmentPayloadLen = Math.max(0, ipTotalLen - ipHeaderLen);
    const isFragment = moreFragments === 1 || fragmentOffset > 0;
    const fragmentBytes = fragmentOffset * 8;
    const fragmentPayload = isFragment
      ? rawBytes.subarray(transportOffset, Math.min(rawBytes.length, transportOffset + fragmentPayloadLen))
      : null;
    const datagram = fragmentPayload && l3Tracker
      ? l3Tracker.fragment(srcIp, dstIp, identification, ipProtocolNum, fragmentBytes, moreFragments === 1, fragmentPayload, id)
      : null;
    // The datagram is whole and this is the frame that finished it, so this is
    // the frame the transport dissector runs in - which is where Wireshark
    // shows it too, and why every earlier fragment reads as "Fragmented IP
    // protocol" rather than each carrying a piece of the answer.
    const reassembled = datagram?.reassembled ?? null;

    if (isFragment) {
      ipLayer.fields.push({
        name: '[Fragment]',
        value: `offset ${fragmentBytes}, ${fragmentPayloadLen} byte${fragmentPayloadLen === 1 ? '' : 's'}`,
        generated: true,
      });
      if (datagram) {
        if (reassembled && datagram.contributions) {
          const parts = datagram.contributions.map((c) => `#${c.frame}(${c.bytes})`).join(', ');
          ipLayer.fields.push({
            name: `[${datagram.contributions.length} Reassembled IPv4 fragments (${reassembled.length} bytes)]`,
            value: parts,
            generated: true,
            abbrev: 'ip.reassembled',
            children: datagram.contributions.map((c) => ({
              name: `[Frame: ${c.frame}, payload: ${c.offset}-${c.offset + c.bytes - 1} (${c.bytes} bytes)]`,
              value: '',
              generated: true,
              linkToFrame: c.frame,
            })),
            ...(datagram.overlapped ? {
              expertInfo: {
                category: 'Broken' as const,
                message: 'Fragments overlap; the first copy of each byte was used',
              },
            } : {}),
          });
        } else {
          ipLayer.fields.push({
            name: '[Fragments so far]',
            value: `${datagram.frames.length} frame${datagram.frames.length === 1 ? '' : 's'}, ${datagram.bytesSoFar} bytes`,
            generated: true,
          });
          if (datagram.complete && datagram.totalLength !== undefined) {
            // The last fragment has arrived and there is still a hole. At this
            // frame there is no way to tell a fragment that is late from one
            // that will never come - fragments routinely arrive out of order
            // on any path with more than one route - so this says what is true
            // rather than declaring a failure. Handing the transport dissector
            // a buffer with the gap quietly zero-filled is the one thing that
            // is not an option.
            ipLayer.fields.push({
              name: '[Datagram incomplete]',
              value: `${datagram.totalLength} bytes expected, ${datagram.bytesSoFar} captured - waiting for a missing fragment`,
              generated: true,
              expertInfo: {
                // The datagram is not malformed - we simply never saw all of
                // it. That is the sniffer's gap, not the sender's fault.
                category: 'CaptureGap',
                message: 'IPv4 datagram not reassembled: a fragment has not been captured',
              },
            });
          }
        }
      }
      if (reassembled && datagram) {
        // Only once the datagram is actually assembled - not merely once the
        // fragment with More Fragments clear has arrived. A trailing fragment
        // often arrives first, and forgetting the datagram at that point threw
        // away the state the fragments still to come needed.
        //
        // The earlier fragments only learn which frame completed the datagram
        // now, the same way a reassembled TLS record's segments do.
        infoPatches = (infoPatches ?? []).concat(
          datagram.frames.filter((frameId) => frameId !== id).map((frameId) => ({
            frameId, suffix: ` [Reassembled in ${id}]`,
          })),
        );
        l3Tracker?.forgetFragments(srcIp, dstIp, identification, ipProtocolNum);
      }
    }

    const transport = reassembled
      // The whole datagram, dissected from offset 0 of its own buffer. The
      // pseudo-header is built from this frame's addresses and the datagram's
      // real length, so the transport checksum is verified against what was
      // actually sent rather than against one fragment of it.
      ? decodeTransportLayer(reassembled, 0, ipProtocolNum, srcIp, dstIp, tcpTracker, ttl, icmpTracker, id, reassembled.length, quicTracker, tsUs, dnsTracker,
        ipv4PseudoHeader(rawBytes, l3Offset, ipProtocolNum, reassembled.length), sentByUs)
      : isFragment
        ? null
        : decodeTransportLayer(rawBytes, transportOffset, ipProtocolNum, srcIp, dstIp, tcpTracker, ttl, icmpTracker, id, ipTotalLen - ipHeaderLen, quicTracker, tsUs, dnsTracker,
          ipv4PseudoHeader(rawBytes, l3Offset, ipProtocolNum, ipTotalLen - ipHeaderLen), sentByUs);

    if (isFragment && !reassembled) {
      // Wireshark's own wording for a fragment it cannot yet reassemble.
      protocolLabel = 'IPv4';
      const protoName = ipProtocolNum === 6 ? 'TCP' : ipProtocolNum === 17 ? 'UDP' : ipProtocolNum === 1 ? 'ICMP' : 'IP';
      info = `Fragmented IP protocol (proto=${protoName} ${ipProtocolNum}, off=${fragmentBytes}, ID=${identification.toString(16).padStart(4, '0')})`;
    }

    if (transport) {
      proto = transport.proto;
      protocolLabel = transport.protocolLabel;
      analysisFlags = transport.analysisFlags;
      Object.assign(filterFields, transport.fields);
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      // A layer dissected out of a reassembled datagram describes bytes that
      // are not in this frame's hex dump, so it carries no byte ranges - the
      // same rule a TLS record reassembled across segments follows. The
      // `[Reassembled IPv4 fragments]` row above is where those bytes are
      // accounted for.
      if (reassembled) {
        stripByteRanges(transport.layer);
        for (const extra of transport.extraLayers ?? []) stripByteRanges(extra);
      }
      transportLayerIndex = layers.length;
      layers.push(transport.layer);
      // Timing lives here, not in the transport decoder, so the [Timestamps]
      // subtree the reference analyzer nests under UDP/TCP is attached from this side.
      transport.layer.fields.push({
        name: '[Timestamps]',
        value: '',
        generated: true,
        children: [
          { name: '[Time since first frame]', value: `${relativeTime.toFixed(9)} seconds`, generated: true },
          { name: '[Time since previous frame]', value: `${timeDelta.toFixed(9)} seconds`, generated: true },
        ],
      });
      if (transport.extraLayers) layers.push(...transport.extraLayers);
      if (transport.protocolTokens) transportTokens = transport.protocolTokens;
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      icmpMatchedRequestFrameId = transport.icmpMatchedRequestFrameId;
      // Concatenated, not replaced: the fragment block above may already have
      // written `[Reassembled in N]` onto this datagram's earlier fragments,
      // and this is the frame that completed it - so both sets of patches
      // belong to it.
      const fromTransport = transportPatches(transport, id);
      if (fromTransport) infoPatches = (infoPatches ?? []).concat(fromTransport);
      resolvedNames = transport.resolvedNames;
      if (transport.streamId !== undefined) {
        ipLayer.fields.push({ name: '[Stream index]', value: transport.streamId, generated: true });
      }
    } else if (!isFragment) {
      // A fragment has no transport header to have failed to dissect - it was
      // never carrying one, or the datagram is not complete yet. Saying "IP
      // protocol 17 payload (not dissected)" of it would describe the wrong
      // absence; the fragment wording above says the right one.
      ({ label: protocolLabel, info } = describeUndissectedIpPayload(ipProtocolNum));
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
        // The first 4 bytes are one word carrying three fields at three
        // different render widths - 8, 32 and 24 bits. That is why totalBits
        // is dissector-supplied: nothing about the fields themselves implies
        // these widths, they are the reference analyzer's presentation convention, matched
        // here against `tshark -V`.
        {
          name: 'Version',
          value: '6',
          rawBytesRange: [l3Offset, l3Offset],
          bitfield: { bitOffset: 0, bitLength: 4, totalBits: 8 },
        },
        ...ipv6TrafficClassFields(rawBytes, l3Offset),
        {
          name: 'Flow Label',
          value: `0x${(((rawBytes[l3Offset + 1] & 0x0f) << 16) | (rawBytes[l3Offset + 2] << 8) | rawBytes[l3Offset + 3]).toString(16).padStart(5, '0')}`,
          rawBytesRange: [l3Offset + 1, l3Offset + 3],
          bitfield: { bitOffset: 4, bitLength: 20, totalBits: 24 },
        },
        { name: 'Payload Length', value: ipv6PayloadLen, rawBytesRange: [l3Offset + 4, l3Offset + 5] },
        { name: 'Next Header', value: describeIpv6NextHeader(nextHeader), abbrev: 'ipv6.nxt', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
        { name: 'Hop Limit', value: hopLimit, abbrev: 'ipv6.hlim', rawBytesRange: [l3Offset + 7, l3Offset + 7] },
        {
          name: 'Source Address', value: srcIp, abbrev: 'ipv6.src', rawBytesRange: [l3Offset + 8, l3Offset + 23],
          children: [{ name: '[Address Space]', value: ipv6AddressSpace(srcIp), generated: true }],
        },
        {
          name: 'Destination Address', value: dstIp, abbrev: 'ipv6.dst', rawBytesRange: [l3Offset + 24, l3Offset + 39],
          children: [{ name: '[Address Space]', value: ipv6AddressSpace(dstIp), generated: true }],
        },
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
    // The reference analyzer stops here and labels the frame malformed; so do we.
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

    // The extension-header chain sits between the fixed header and the
    // transport one. Skipping it reads a Hop-by-Hop option as an ICMPv6
    // header - which is what every MLDv2 report in the fixtures used to show.
    const payloadEnd = Math.min(rawBytes.length, l3Offset + 40 + ipv6PayloadLen);
    const chain = isMalformedJumbo
      ? null
      : walkIpv6Extensions(rawBytes, l3Offset + 40, nextHeader, payloadEnd);
    if (chain) {
      layers.push(...chain.layers);
      extensionTokens = chain.protocolTokens;
    }
    const transportOffset = chain ? chain.transportOffset : l3Offset + 40;
    let effectiveNextHeader = chain ? chain.finalNextHeader : nextHeader;
    const transportPayloadLen = ipv6PayloadLen - (transportOffset - (l3Offset + 40));

    // --- fragments -----------------------------------------------------------
    // The same mechanism as IPv4's, keyed the way RFC 8200 §4.5 keys it: source,
    // destination and the Fragment header's 32-bit identification, with the
    // protocol deliberately left out - the Fragment header sits above whatever
    // the payload turns out to be, which is exactly why IPv6 moved
    // fragmentation out of the fixed header in the first place.
    const isV6Fragment = chain?.fragmentPayloadOffset !== undefined;
    const v6PayloadStart = chain?.fragmentPayloadOffset ?? transportOffset;
    const v6FragmentPayload = isV6Fragment
      ? rawBytes.subarray(v6PayloadStart, Math.min(rawBytes.length, payloadEnd))
      : null;
    const v6Datagram = v6FragmentPayload && l3Tracker && chain?.fragmentId !== undefined
      ? l3Tracker.fragment(
        srcIp, dstIp, chain.fragmentId, IPV6_FRAGMENT_KEY,
        chain.fragmentOffset ?? 0, chain.moreFragments ?? false, v6FragmentPayload, id,
      )
      : null;
    const v6Reassembled = v6Datagram?.reassembled ?? null;

    // The fragmentable part may itself begin with extension headers - the
    // walker stopped at the Fragment header, and everything after it belongs
    // to the reassembled datagram rather than to this frame.
    let v6ReassembledOffset = 0;
    if (v6Reassembled) {
      const inner = walkIpv6Extensions(v6Reassembled, 0, effectiveNextHeader, v6Reassembled.length);
      for (const layer of inner.layers) stripByteRanges(layer);
      layers.push(...inner.layers);
      extensionTokens = [...extensionTokens, ...inner.protocolTokens];
      effectiveNextHeader = inner.finalNextHeader;
      v6ReassembledOffset = inner.transportOffset;
    }

    if (isV6Fragment) {
      const fragmentLayer = layers.find((l) => l.name === 'IPv6 Fragment');
      if (fragmentLayer && v6Datagram) {
        if (v6Reassembled && v6Datagram.contributions) {
          const parts = v6Datagram.contributions.map((c) => `#${c.frame}(${c.bytes})`).join(', ');
          fragmentLayer.fields.push({
            name: `[${v6Datagram.contributions.length} Reassembled IPv6 fragments (${v6Reassembled.length} bytes)]`,
            value: parts,
            generated: true,
            abbrev: 'ipv6.reassembled',
            children: v6Datagram.contributions.map((c) => ({
              name: `[Frame: ${c.frame}, payload: ${c.offset}-${c.offset + c.bytes - 1} (${c.bytes} bytes)]`,
              value: '',
              generated: true,
              linkToFrame: c.frame,
            })),
            ...(v6Datagram.overlapped ? {
              expertInfo: {
                category: 'Broken' as const,
                message: 'Fragments overlap; the first copy of each byte was used',
              },
            } : {}),
          });
          filterFields['ipv6.reassembled'] = v6Reassembled.length;
        } else {
          fragmentLayer.fields.push({
            name: '[Fragments so far]',
            value: `${v6Datagram.frames.length} frame${v6Datagram.frames.length === 1 ? '' : 's'}, ${v6Datagram.bytesSoFar} bytes`,
            generated: true,
          });
          if (v6Datagram.complete && v6Datagram.totalLength !== undefined) {
            fragmentLayer.fields.push({
              name: '[Datagram incomplete]',
              value: `${v6Datagram.totalLength} bytes expected, ${v6Datagram.bytesSoFar} captured - waiting for a missing fragment`,
              generated: true,
              expertInfo: {
                category: 'CaptureGap',
                message: 'IPv6 datagram not reassembled: a fragment has not been captured',
              },
            });
          }
        }
      }
      if (v6Reassembled && v6Datagram) {
        infoPatches = (infoPatches ?? []).concat(
          v6Datagram.frames.filter((frameId) => frameId !== id).map((frameId) => ({
            frameId, suffix: ` [Reassembled in ${id}]`,
          })),
        );
        l3Tracker?.forgetFragments(srcIp, dstIp, chain!.fragmentId!, IPV6_FRAGMENT_KEY);
      }
    }

    const transport = isMalformedJumbo
      ? null
      : v6Reassembled
        ? decodeTransportLayer(v6Reassembled, v6ReassembledOffset, effectiveNextHeader, srcIp, dstIp, tcpTracker, hopLimit, icmpTracker, id, v6Reassembled.length - v6ReassembledOffset, quicTracker, tsUs, dnsTracker, ipv6PseudoHeader(rawBytes, l3Offset, effectiveNextHeader, v6Reassembled.length - v6ReassembledOffset), sentByUs)
        : (chain?.stopsHere ?? false)
          ? null
          : decodeTransportLayer(rawBytes, transportOffset, effectiveNextHeader, srcIp, dstIp, tcpTracker, hopLimit, icmpTracker, id, transportPayloadLen, quicTracker, tsUs, dnsTracker, ipv6PseudoHeader(rawBytes, l3Offset, effectiveNextHeader, transportPayloadLen), sentByUs);
    if (transport) {
      proto = transport.proto;
      protocolLabel = transport.protocolLabel;
      analysisFlags = transport.analysisFlags;
      Object.assign(filterFields, transport.fields);
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      // A layer dissected out of a reassembled datagram describes bytes that
      // are not in this frame's hex dump, so it carries no byte ranges - the
      // same rule a TLS record reassembled across segments follows.
      if (v6Reassembled) {
        stripByteRanges(transport.layer);
        for (const extra of transport.extraLayers ?? []) stripByteRanges(extra);
      }
      transportLayerIndex = layers.length;
      layers.push(transport.layer);
      // Timing lives here, not in the transport decoder, so the [Timestamps]
      // subtree the reference analyzer nests under UDP/TCP is attached from this side.
      transport.layer.fields.push({
        name: '[Timestamps]',
        value: '',
        generated: true,
        children: [
          { name: '[Time since first frame]', value: `${relativeTime.toFixed(9)} seconds`, generated: true },
          { name: '[Time since previous frame]', value: `${timeDelta.toFixed(9)} seconds`, generated: true },
        ],
      });
      if (transport.extraLayers) layers.push(...transport.extraLayers);
      if (transport.protocolTokens) transportTokens = transport.protocolTokens;
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      icmpMatchedRequestFrameId = transport.icmpMatchedRequestFrameId;
      // Concatenated, not replaced, for the same reason as the IPv4 branch:
      // the fragment block above may already have written `[Reassembled in N]`
      // onto this datagram's earlier fragments, and this is the frame that
      // completed it.
      const fromTransport = transportPatches(transport, id);
      if (fromTransport) infoPatches = (infoPatches ?? []).concat(fromTransport);
      resolvedNames = transport.resolvedNames;
      if (transport.streamId !== undefined) {
        ipv6Layer.fields.push({ name: '[Stream index]', value: transport.streamId, generated: true });
      }
    } else if (!isMalformedJumbo) {
      if (chain && chain.fragmentPayloadOffset !== undefined) {
        // A fragment of a datagram that is not (yet) whole. Its payload is a
        // slice of something larger, not a transport header.
        protocolLabel = 'IPv6';
        info = `IPv6 fragment (off=${chain.fragmentOffset ?? 0} more=${chain.moreFragments ? 1 : 0} ident=0x${(chain.fragmentId ?? 0).toString(16).padStart(8, '0')} nxt=${chain.finalNextHeader})`;
      } else if (chain && chain.finalNextHeader === NO_NEXT_HEADER) {
        protocolLabel = 'IPv6';
        info = 'IPv6 No Next Header';
      } else {
        // Same fallback as IPv4. Guarded on the jumbo case, which has already
        // set its own more specific label and [Malformed Packet] info.
        ({ label: protocolLabel, info } = describeUndissectedIpPayload(effectiveNextHeader));
      }
    }
  }

  // The worst finding anywhere in this frame's tree, as one field. A colour
  // rule and a display filter can both ask about it; neither can walk a tree,
  // which is why "Expert Warnings" could not be a rule before this existed.
  // Only for frames the MACs could not answer for. Two cases reach here: a
  // link with no Ethernet header at all, where there were never any MACs to
  // compare, and a host identity that knows an address but not a MAC - which
  // is what the socket table alone gives.
  if (direction === 0 && host) {
    direction = directionFromAddresses(srcIp, dstIp, host);
  }
  if (direction === 0) {
    // Last, and only ever able to say "out". A frame larger than the link can
    // carry was handed to the sniffer above segmentation offload, and a
    // required checksum the NIC has not filled in yet is the same story: both
    // are artefacts only a *transmitting* stack leaves, so their absence
    // proves nothing and they can never conclude "in".
    const unfilled = filterFields['tcp.checksum'] === 0 || filterFields['udp.checksum'] === 0;
    direction = directionFromOffload(
      origLen || rawBytes.length, link.srcMac !== undefined, unfilled,
    );
  }

  const { expert, strongest } = collectExpert(layers);
  if (strongest) filterFields['inwire.expert.category'] = strongest;

  const frameProtocols = layers.map(l => PROTOCOL_NAME_MAP[l.name] ?? l.name.toLowerCase().replace(/\s+/g, '_'));
  if (transportTokens.length > 0 && transportLayerIndex >= 0) {
    frameProtocols.splice(transportLayerIndex + 1, 0, ...transportTokens.filter(t => !frameProtocols.includes(t)));
  }
  // Extension headers are layers with generated names; their filter tokens
  // come from the walker, which knows which header each one was.
  for (const token of extensionTokens) if (!frameProtocols.includes(token)) frameProtocols.push(token);
  layers[0].fields.push(
    { name: '[Protocols in frame]', value: frameProtocols.join(':'), generated: true },
    { name: 'Character encoding', value: 'ASCII (0)' },
  );

  return {
    packet: {
      id,
      tsUs,
      relativeTime,
      timeDelta,
      source: srcIp,
      destination: dstIp,
      sourcePort: srcPort,
      destPort: dstPort,
      protocol: proto,
      protocolLabel,
      // Pooled at the point they stop changing. Both are short lists with very
      // few distinct values across a capture - 21 chains and 13 flag sets over
      // both fixtures - so the buffer held one array per frame where a few
      // dozen do (`services/dissect/tokenPool.ts`). Everything above this line
      // still built and mutated its own array; from here they are shared and
      // frozen.
      analysisFlags: analysisFlags ? poolTokens(analysisFlags) : undefined,
      frameProtocols: poolTokens(frameProtocols),
      fields: filterFields,
      // The on-wire frame size, which is what the reference analyzer's Length column shows.
      // It differs from rawBytes.length whenever the capture used a snaplen.
      // Falls back to the captured size if a source didn't report a wire size.
      length: origLen || rawBytes.length,
      info,
      status,
      streamId,
      // Packed: direction, the signal that decided it, and the duplicate bit.
      // Left off entirely when nothing decided, so a frame with no answer
      // costs no slot at all (`services/direction.ts`).
      ...(direction !== Direction.Unknown ? { direction } : {}),
      layers,
      rawBytes,
      ...(expert ? { expert } : {}),
      ...(resolvedNames && resolvedNames.length > 0 ? { resolved: resolvedNames } : {}),
      interfaceName: captureInterface?.label ?? 'eth0',
    },
    icmpMatchedRequestFrameId,
    infoPatches,
    resolvedNames,
  };
}

/**
 * A change to an EARLIER frame's Info that only this frame can know about.
 *
 * "[TCP PDU reassembled in 12]" on frames 10 and 11 is written by frame 12,
 * the one that completed the record; "(reply in 42)" on a ping request is
 * written by the reply. Single-pass dissection cannot see the future, so the
 * frame that learns the fact hands it back and the caller patches the list -
 * the import path directly, the live path on its next flush.
 */
export interface InfoPatch {
  frameId: number;
  /** Appended to the frame's Info. */
  suffix?: string;
  /** Replaces the frame's Protocol label - a ClientHello re-labelled with the negotiated version. */
  protocolLabel?: string;
  /**
   * The frame that answered this DNS query. Recorded as a field rather than
   * appended to Info, because Wireshark shows it in the tree only - the query
   * row's Info stays as it was.
   */
  responseInFrame?: number;
}

function transportPatches(
  transport: {
    reassembledFrom?: number[];
    labelPatches?: { frameId: number; protocolLabel: string }[];
    dnsMatchedQueryFrameId?: number;
  },
  completedIn: number,
): InfoPatch[] | undefined {
  const out: InfoPatch[] = [];
  for (const frameId of transport.reassembledFrom ?? []) out.push({ frameId, suffix: ` [TCP PDU reassembled in ${completedIn}]` });
  for (const patch of transport.labelPatches ?? []) out.push(patch);
  // The query frame learns which frame answered it only now.
  if (transport.dnsMatchedQueryFrameId !== undefined) {
    out.push({ frameId: transport.dnsMatchedQueryFrameId, responseInFrame: completedIn });
  }
  return out.length > 0 ? out : undefined;
}

/** Applies one patch to a packet, in place. */
export function applyInfoPatch(packet: Packet, patch: InfoPatch): void {
  if (patch.suffix) packet.info += patch.suffix;
  if (patch.protocolLabel) packet.protocolLabel = patch.protocolLabel;
  if (patch.responseInFrame !== undefined) {
    packet.fields = { ...(packet.fields ?? {}), 'dns.response_in': patch.responseInFrame };
    for (const layer of packet.layers ?? []) {
      if (layer.name !== 'Domain Name System') continue;
      layer.fields.push({
        name: '[Response In]', value: patch.responseInFrame, generated: true,
        linkToFrame: patch.responseInFrame, abbrev: 'dns.response_in',
      });
    }
  }
}

/**
 * Where frame `id` sits in a buffer, or -1.
 *
 * Ids are handed out in order and only ever leave from the head, so the
 * position is arithmetic: `id - packets[0].id`. That is a guess and not a
 * guarantee - the Worker takes an id before it dissects, so a frame that fails
 * to dissect burns one and leaves a hole - so the guess is checked, and a miss
 * falls back to a binary search. Ids ascend either way, holes or not, so the
 * fallback is log n rather than the linear scan it replaces.
 *
 * This exists because the two patch passes were each a `.map` over the whole
 * buffer, ten times a second, to touch one or two frames: 14.1 ms per pass at a
 * million frames, against 1.6 ms to copy the array once
 * (`scripts/perf/buffer-cost.ts`).
 */
export function indexOfFrame(packets: Packet[], id: number): number {
  if (packets.length === 0) return -1;
  const guess = id - packets[0].id;
  if (guess >= 0 && guess < packets.length && packets[guess].id === id) return guess;
  let lo = 0;
  let hi = packets.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const at = packets[mid].id;
    if (at === id) return mid;
    if (at < id) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/**
 * Applies patches by writing into `packets` directly. **The caller must own the
 * array** - it is mutated, though the packets in it are replaced rather than
 * changed, so anything else holding one of them still sees what it saw.
 *
 * For a caller that has just built a fresh array (the flush, which has already
 * paid for one copy in its `concat`) this is the whole cost; `applyInfoPatches`
 * is the copying wrapper for callers that have not.
 */
export function applyInfoPatchesInPlace(packets: Packet[], patches: InfoPatch[]): boolean {
  let changed = false;
  for (const patch of patches) {
    const at = indexOfFrame(packets, patch.frameId);
    if (at < 0) continue;
    const copy = { ...packets[at] };
    applyInfoPatch(copy, patch);
    packets[at] = copy;
    changed = true;
  }
  return changed;
}

/** Applies patches to packets already in a list; the packets are replaced, not mutated. */
export function applyInfoPatches(packets: Packet[], patches: InfoPatch[]): Packet[] {
  if (patches.length === 0) return packets;
  const next = packets.slice();
  return applyInfoPatchesInPlace(next, patches) ? next : packets;
}


/**
 * The nine flag bits plus Reserved, as the reference analyzer lists them.
 *
 * Drawn as a 12-bit window starting 4 bits into the data-offset byte: the
 * low nibble of byte 12 plus all of byte 13. Offsets below are relative to
 * that window, which is what the rendered string shows.
 */
// `abbrev` where the registry has the bit as a field of its own, which is
// what makes the row one right-click from `tcp.flags.syn == 1`. The five
// without one are drawn and not published; a row with no abbrev is display
// only, and the tree's menu greys out its filter items rather than offering
// an expression nothing would answer.
const TCP_FLAG_ROWS: { name: string; bitOffset: number; bitLength: number; set: string; unset: string; abbrev?: string }[] = [
  { name: 'Reserved', bitOffset: 0, bitLength: 3, set: 'Set', unset: 'Not set' },
  { name: 'Accurate ECN', bitOffset: 3, bitLength: 1, set: 'Set', unset: 'Not set' },
  { name: 'Congestion Window Reduced', bitOffset: 4, bitLength: 1, set: 'Set', unset: 'Not set' },
  { name: 'ECN-Echo', bitOffset: 5, bitLength: 1, set: 'Set', unset: 'Not set' },
  { name: 'Urgent', bitOffset: 6, bitLength: 1, set: 'Set', unset: 'Not set' },
  { name: 'Acknowledgment', bitOffset: 7, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.ack' },
  { name: 'Push', bitOffset: 8, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.push' },
  { name: 'Reset', bitOffset: 9, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.reset' },
  { name: 'Syn', bitOffset: 10, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.syn' },
  { name: 'Fin', bitOffset: 11, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.fin' },
];

function tcpFlagFields(rawBytes: Uint8Array, transportOffset: number): ProtocolField[] {
  // The 12 drawn bits as one number, so each row can read its own bits out of
  // it without repeating the mid-byte window arithmetic.
  const window12 = ((rawBytes[transportOffset + 12] & 0x0f) << 8) | rawBytes[transportOffset + 13];

  return TCP_FLAG_ROWS.map(row => {
    const shift = 12 - row.bitOffset - row.bitLength;
    const mask = (1 << row.bitLength) - 1;
    const isSet = ((window12 >> shift) & mask) !== 0;
    return {
      name: row.name,
      value: isSet ? row.set : row.unset,
      ...(row.abbrev ? { abbrev: row.abbrev } : {}),
      rawBytesRange: [transportOffset + 12, transportOffset + 13] as [number, number],
      bitfield: {
        bitOffset: row.bitOffset,
        bitLength: row.bitLength,
        totalBits: 12,
        windowStartBit: 4,
      },
    };
  });
}


/**
 * Traffic Class and the DSCP/ECN pair nested beneath it.
 *
 * All three render at 32 bits even though the class is 8 bits and its parts
 * are 6 and 2: the reference analyzer draws a child at its parent's width so the nested
 * rows line up as one ruler down the column. Verified against `tshark -V`.
 *
 * The names come from `dissectors/ipv4.ts`, which is the only copy. There were
 * two: this file held a private 13-entry `DSCP_NAMES` in a different format
 * (`'Default (0)'` against `'CS0'`) while the IPv4 branch imported the full
 * 24-entry table taken from Wireshark's `dscp_vals`. So **nine codepoints -
 * AF12, AF13, AF22, AF23, AF32, AF33, AF42, AF43 and Voice-Admit - rendered as
 * a name over IPv4 and as a bare number over IPv6 in the same capture**, and
 * the ones both tables did carry were spelled differently. `ECN_NAMES` had
 * diverged the same way. The IPv4 spelling wins because it is the one checked
 * against the reference analyzer.
 */
function ipv6TrafficClassFields(rawBytes: Uint8Array, l3Offset: number): ProtocolField[] {
  const trafficClass = ((rawBytes[l3Offset] & 0x0f) << 4) | ((rawBytes[l3Offset + 1] & 0xf0) >> 4);
  const dscp = trafficClass >> 2;
  const ecn = trafficClass & 0x03;

  return [
    {
      name: 'Traffic Class',
      value: `0x${trafficClass.toString(16).padStart(2, '0')} (DSCP: ${dscpName(dscp)}, ECN: ${ecnName(ecn)})`,
      rawBytesRange: [l3Offset, l3Offset + 3],
      bitfield: { bitOffset: 4, bitLength: 8, totalBits: 32 },
      children: [
        {
          name: 'Differentiated Services Codepoint',
          value: `${dscpName(dscp)} (${dscp})`,
          rawBytesRange: [l3Offset, l3Offset + 3],
          bitfield: { bitOffset: 4, bitLength: 6, totalBits: 32 },
        },
        {
          name: 'Explicit Congestion Notification',
          value: `${ecnName(ecn)} (${ecn})`,
          rawBytesRange: [l3Offset, l3Offset + 3],
          bitfield: { bitOffset: 10, bitLength: 2, totalBits: 32 },
        },
      ],
    },
  ];
}


/**
 * The reference analyzer's arrival-time format: `Aug 25, 2026 20:16:40.351587600 Jerusalem
 * Daylight Time`. The spelled-out zone name comes from Intl rather than an
 * offset, because that is what the reference analyzer prints and an offset would not match.
 *
 * Sub-millisecond digits are zero-padded rather than invented: the agent
 * timestamps to microsecond resolution, so the last three digits of the
 * nanosecond field are genuinely unknown, not measured.
 */
/** The reference analyzer's [Address Space] classification for an IPv6 address. */
function describeIpv6NextHeader(n: number): string {
  const ext = IPV6_EXT_HEADERS[n];
  if (ext) return `IPv6 ${ext} (${n})`;
  if (n === NO_NEXT_HEADER) return 'No Next Header (59)';
  const name = IP_PROTOCOL_NAMES[n];
  return name ? `${name} (${n})` : String(n);
}

function ipv6AddressSpace(address: string): string {
  const a = address.toLowerCase();
  if (a === '::1') return 'Loopback';
  if (a === '::') return 'Unspecified';
  if (a.startsWith('ff')) return 'Multicast';
  if (a.startsWith('fe8') || a.startsWith('fe9') || a.startsWith('fea') || a.startsWith('feb')) return 'Link-Local Unicast';
  if (a.startsWith('fc') || a.startsWith('fd')) return 'Unique Local Unicast';
  return 'Global Unicast';
}

/**
 * The two formatters, built once.
 *
 * `new Intl.DateTimeFormat(...)` was being constructed inside
 * `formatArrivalTime`, which is called twice for every frame - so a 12,858
 * frame capture built 25,716 of them. Constructing one is among the most
 * expensive things in the language: it resolves a locale and sets up ICU, and
 * it measured at ~49 us a call. A CPU profile of a full dissection put this one
 * function at **38% of the entire profile, and more than half of all dissection
 * time** - far and away the largest single cost in the pipeline, for two rows
 * of a tree that 92% of frames never show anyone.
 *
 * Lazily, because the locale data load is not work to do at module init in a
 * Worker that may never dissect anything.
 */
let localArrivalFormat: Intl.DateTimeFormat | undefined;
let utcArrivalFormat: Intl.DateTimeFormat | undefined;

function arrivalFormatter(utc: boolean): Intl.DateTimeFormat {
  if (utc) {
    utcArrivalFormat ??= new Intl.DateTimeFormat('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false, timeZone: 'UTC', timeZoneName: 'long',
    });
    return utcArrivalFormat;
  }
  localArrivalFormat ??= new Intl.DateTimeFormat('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false, timeZoneName: 'long',
  });
  return localArrivalFormat;
}

function formatArrivalTime(tsUs: number, utc = false): string {
  const parts = arrivalFormatter(utc).formatToParts(new Date(tsUs / 1000));
  // One pass over the parts rather than a `find` per field: there are six
  // fields and about ten parts, so the old form was sixty scans a frame.
  let month = '', day = '', year = '', hour = '', minute = '', second = '', zone = '';
  for (const p of parts) {
    switch (p.type) {
      case 'month': month = p.value; break;
      case 'day': day = p.value; break;
      case 'year': year = p.value; break;
      case 'hour': hour = p.value; break;
      case 'minute': minute = p.value; break;
      case 'second': second = p.value; break;
      case 'timeZoneName': zone = p.value; break;
    }
  }
  const fractional = String((tsUs % 1_000_000) * 1000).padStart(9, '0');
  return `${month} ${day}, ${year} ${hour}:${minute}:${second}.${fractional} ${zone}`;
}


/**
 * Formats a 16-byte IPv6 address (starting at `offset` within `bytes`) in the
 * RFC 5952 canonical form the reference analyzer displays: leading zeros stripped from each
 * group, lowercase hex, and the *longest* run of two or more all-zero groups
 * collapsed to "::" (leftmost run wins a tie, and a single zero group is never
 * collapsed - "2001:db8:0:1:1:1:1:1" stays as-is).
 *
 * Without this an address renders as 39 characters of zero-padded groups,
 * which both diverges from the reference analyzer and overflows the address column.
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
  return utf8Decoder.decode(rawBytes.subarray(payloadStart, end));
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
 * Every Neighbor Discovery option of one type, in order.
 *
 * `findNdpOption` stops at the first, which is right for a link-layer address
 * but wrong for the two things a Router Advertisement carries several of: a
 * router may advertise more than one prefix, and more than one RDNSS option.
 * Shares the termination rules with it - a zero length would loop forever, and
 * an option claiming to run past the frame is truncated rather than trusted.
 */
function collectNdpOptions(rawBytes: Uint8Array, optionsStart: number, wantedType: number): Uint8Array[] {
  const found: Uint8Array[] = [];
  let offset = optionsStart;
  while (offset + 2 <= rawBytes.length) {
    const lengthUnits = rawBytes[offset + 1];
    if (lengthUnits === 0) break;
    const optionEnd = offset + lengthUnits * 8;
    if (optionEnd > rawBytes.length) break;
    if (rawBytes[offset] === wantedType) found.push(rawBytes.subarray(offset + 2, optionEnd));
    offset = optionEnd;
  }
  return found;
}

/**
 * What a Router Advertisement announces, as filterable fields.
 *
 * The RA is how a passive observer learns an IPv6 network's shape without
 * asking anything: the prefix hosts are autoconfiguring from, the resolvers
 * they were handed, how long the router expects to be the default one, and
 * whether it is telling them to use DHCPv6 as well. Nothing else on the wire
 * carries it, and the machine's own configuration does not say where any of it
 * came from - which is exactly what makes it worth putting beside the OS's
 * answer in the Network panel.
 *
 * RFC 4861 4.2: after the 4-byte ICMPv6 header come the hop limit, a flags
 * byte, the router lifetime, reachable time and retransmit timer, then
 * options. Option 3 is Prefix Information and option 25 (RFC 8106) is RDNSS.
 */
function routerAdvertisementFields(
  rawBytes: Uint8Array, transportOffset: number,
): Record<string, string | number> {
  const body = transportOffset + 4;
  if (body + 12 > rawBytes.length) return {};
  const flags = rawBytes[body + 1];
  const out: Record<string, string | number> = {
    'icmpv6.nd.ra.cur_hop_limit': rawBytes[body],
    // Managed and Other: "get your address from DHCPv6" and "get everything
    // else from DHCPv6". A network where both are clear is pure SLAAC.
    'icmpv6.nd.ra.flag.m': (flags & 0x80) !== 0 ? 1 : 0,
    'icmpv6.nd.ra.flag.o': (flags & 0x40) !== 0 ? 1 : 0,
    // Zero is meaningful and not missing: it says "I am not a default router",
    // which is how a router announces it is going away.
    'icmpv6.nd.ra.router_lifetime': (rawBytes[body + 2] << 8) | rawBytes[body + 3],
  };

  const prefixes: string[] = [];
  for (const option of collectNdpOptions(rawBytes, body + 12, 3)) {
    if (option.length < 30) continue;
    prefixes.push(`${formatIpv6Address(option, 14)}/${option[0]}`);
    if (prefixes.length === 1) {
      out['icmpv6.opt.prefix.valid_lifetime'] =
        ((option[2] << 24) | (option[3] << 16) | (option[4] << 8) | option[5]) >>> 0;
      out['icmpv6.opt.prefix.preferred_lifetime'] =
        ((option[6] << 24) | (option[7] << 16) | (option[8] << 8) | option[9]) >>> 0;
    }
  }
  if (prefixes.length > 0) out['icmpv6.opt.prefix'] = prefixes.join(',');

  const resolvers: string[] = [];
  for (const option of collectNdpOptions(rawBytes, body + 12, 25)) {
    // 2 reserved bytes and a 4-byte lifetime, then whole addresses.
    for (let at = 6; at + 16 <= option.length; at += 16) {
      resolvers.push(formatIpv6Address(option, at));
    }
  }
  if (resolvers.length > 0) out['icmpv6.opt.rdnss'] = resolvers.join(',');
  return out;
}

/**
 * "Neighbor Solicitation for fe80::17a6:fd9a:5a8c:e5bf from 44:15:24:5d:cc:62"
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
  quicTracker?: QuicFlowTracker,
  /** Capture time, epoch microseconds - the analysis flags compare timings. */
  tsUs?: number,
  dnsTracker?: DnsTracker,
  /**
   * The IP pseudo-header for the transport checksum (RFC 793 / RFC 8200), or
   * undefined when the network layer could not supply one.
   */
  pseudoHeader?: Uint8Array,
  /** See `checksumVerdict` - this machine sent the frame, so its checksums
   *  may not have been filled in yet. */
  sentByUs = false,
): {
  proto: Packet['protocol'];
  protocolLabel?: string;
  srcPort?: number;
  dstPort?: number;
  info: string;
  layer: ProtocolLayer;
  /**
   * Layers sitting above the transport header - DNS over UDP, for instance.
   * Separate from `layer` because the transport decoder owns exactly one
   * header of its own, and a subdissector that claims the payload adds to the
   * stack rather than replacing it.
   */
  extraLayers?: ProtocolLayer[];
  /**
   * Extra `frameProtocols` tokens for a dissector that claims the payload
   * without contributing a layer of its own - QUIC, whose only tree output is
   * the TLS handshake it carries, and SSDP, which is one request line. Without
   * these the bareword `quic` in a filter or a colour rule would have no layer
   * to find, which is the same gap the extension-header walker fills.
   */
  protocolTokens?: string[];
  streamId?: number;
  status?: Packet['status'];
  analysisFlags?: string[];
  fields?: Record<string, string | number>;
  icmpMatchedRequestFrameId?: number;
  /** Earlier frames that carried parts of a TLS record this segment completed. */
  reassembledFrom?: number[];
  /** Earlier frames whose Protocol label this segment's ServerHello settled. */
  labelPatches?: { frameId: number; protocolLabel: string }[];
  /** The query frame this DNS response answers, for its "[Response In]" patch. */
  dnsMatchedQueryFrameId?: number;
  /** Names this frame mapped to addresses, for passive name resolution. */
  resolvedNames?: { name: string; addresses: string[] }[];
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

    // The reference analyzer's fixed flag order, which is *not* the bit order: a typical
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
    // 443 connection is a plain TCP frame to the reference analyzer, not a TLS one.
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
    // In wire order, as Wireshark prints them: "MSS=1344 SACK_PERM WS=128"
    // and "MSS=1428 WS=256 SACK_PERM" are different stacks' SYNs.
    const handshakeOptionParts: string[] = tcpOptions && syn ? tcpOptions.infoParts : [];

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
    // TLS is dissected further down, once the tracker has said whether this
    // segment continues its direction in order: the record cursor that
    // decides which frame a record belongs to may only advance on in-order
    // data, and a gap resets it.
    let tlsResult: TlsSegmentResult | null = null;

    const storedChecksum = (rawBytes[transportOffset + 16] << 8) | rawBytes[transportOffset + 17];
    const checksum = checksumVerdict(pseudoHeader, rawBytes, transportOffset,
      l4SegmentLen !== undefined && l4SegmentLen >= tcpHeaderLen ? transportOffset + l4SegmentLen : rawBytes.length,
      storedChecksum, false, sentByUs);

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
    // FIN each consume one sequence number. The reference analyzer omits the field for
    // zero-length non-SYN/FIN segments, where it would just repeat Seq.
    const nextSeqDelta = payloadLength + (syn || fin ? 1 : 0);
    const expectedNextRel = nextSeqDelta > 0 ? relSeq + nextSeqDelta : undefined;

    let streamId: number | undefined;
    let status: Packet['status'] | undefined;
    let streamPacketNumber: number | undefined;
    let conversationCompleteness: string | undefined;
    let isKeepAlive = false;
    let lostSegment = false;
    let tlsInOrder = true;
    let analysis: TcpAnalysis | undefined;
    if (tcpTracker) {
      streamId = tcpTracker.getStreamId(srcIp, srcPort, dstIp, dstPort);
      streamPacketNumber = tcpTracker.recordStreamPacket(streamId);
      tcpTracker.updateConnectionState(streamId, syn, ack, fin, rst);

      // Asked before the analysis advances the direction, so it describes
      // where the stream stood when this segment arrived.
      tlsInOrder = tcpTracker.isAtOrPastExpected(srcIp, srcPort, dstIp, dstPort, seqNum);
      analysis = tcpTracker.analyze(srcIp, srcPort, dstIp, dstPort, {
        frame: frameId ?? 0, timeUs: tsUs ?? 0, seq: seqNum, ack: ackNum, window: rawWindow,
        segLen: payloadLength, syn, ack_: ack, fin, rst, windowScaleOption: tcpOptions?.windowScale,
        sackBlocks: tcpOptions?.sackBlocks.map((b) => ({ left: b.leftEdge, right: b.rightEdge })),
      });
      isKeepAlive = analysis.flags.includes('keep_alive');
      lostSegment = analysis.flags.includes('lost_segment');
      // `status` still moves, because the list and the display filter read it.
      // What is gone is the pair of `AnomalyInfo` objects that used to be built
      // here: they duplicated the analysis flags that already raise a Loss
      // finding of their own, so every retransmission was counted twice in the
      // Expert tab - once as Sequence from the tree and once as Security from
      // the anomaly. One event, one finding.
      if (analysis.flags.includes('retransmission') || analysis.flags.includes('fast_retransmission') || analysis.flags.includes('spurious_retransmission')) {
        status = 'retransmit';
      } else if (analysis.flags.includes('out_of_order')) {
        status = 'warning';
      }

      conversationCompleteness = tcpTracker.getConversationCompleteness(streamId);
    }

    // The TLS record layer, now that the segment's place in the stream is
    // known. Only streams that look like TLS pay for cursor state: port 443, a
    // direction that already has a cursor, or a plausible record header.
    let reassembledFrom: number[] | undefined;
    let labelPatches: { frameId: number; protocolLabel: string }[] | undefined;
    // A segment out of order is still dissected - Wireshark reassembles it and
    // labels it with what it carries - but a retransmission is not: its bytes
    // were already read in order, and Wireshark shows the plain TCP line for
    // the copy. Getting this backwards costs either the Server Hellos that
    // arrive out of order or 8 % of a download-heavy capture's Protocol column.
    const isRetransmitted = analysis !== undefined
      && (analysis.flags.includes('retransmission')
        || analysis.flags.includes('fast_retransmission')
        || analysis.flags.includes('spurious_retransmission'));
    // DNS over TCP, which is what a zone transfer, a response too big for a
    // datagram, and every DNS-over-TLS connection underneath its encryption
    // are. It differs from the datagram form by a two-byte length prefix and
    // nothing else, so the whole of Phase 7's dissector applies to it - it was
    // simply never reached, because the dispatch only looked at UDP.
    let tcpDns: {
      info: string; layer: ProtocolLayer;
      fields: Record<string, string | number>;
      resolved: { name: string; addresses: string[] }[];
    } | null = null;
    if ((srcPort === 53 || dstPort === 53) && payloadLength > 2) {
      const declared = (rawBytes[tcpPayloadStart] << 8) | rawBytes[tcpPayloadStart + 1];
      const messageStart = tcpPayloadStart + 2;
      const messageEnd = Math.min(rawBytes.length, messageStart + declared);
      // Only a message that fits inside this one segment. A DNS response split
      // across segments needs the reassembly the TLS cursor does, and claiming
      // it here would mean parsing half a message and reporting the half.
      if (declared > 0 && messageStart + declared <= tcpPayloadStart + payloadLength) {
        const parsed = parseDnsMessage(rawBytes, messageStart, messageEnd);
        if (parsed) {
          const dissection = buildDnsLayer(rawBytes, messageStart, messageEnd, undefined);
          if (dissection) {
            tcpDns = {
              info: dnsInfoLine(parsed, false),
              layer: dissection.layer,
              fields: dissection.fields,
              resolved: dissection.resolved,
            };
          }
        }
      }
    }

    if (!tcpDns && payloadLength > 0 && !isKeepAlive && !isRetransmitted) {
      const payloadEnd = Math.min(rawBytes.length, tcpPayloadStart + payloadLength);
      const existing = tcpTracker?.peekTlsCursor(srcIp, srcPort, dstIp, dstPort);
      if (isTlsPort || existing !== undefined || looksLikeTlsRecord(rawBytes, tcpPayloadStart, payloadEnd)) {
        const cursor = tcpTracker ? tcpTracker.tlsCursor(srcIp, srcPort, dstIp, dstPort) : freshTlsCursor();
        const conversation = tcpTracker ? tcpTracker.tlsConversation(srcIp, srcPort, dstIp, dstPort) : freshTlsConversation();
        const outcome = dissectTlsSegment(rawBytes, tcpPayloadStart, payloadEnd, {
          // An out-of-order or retransmitted segment is read against a copy
          // of the cursor: its bytes were (or will be) counted in order, so
          // consuming them twice would put the record layer out of step, but
          // a Server Hello sitting in one is still a Server Hello and
          // Wireshark labels it as one.
          frameId: frameId ?? 0, cursor, conversation, inOrder: tlsInOrder, segmentSeq: seqNum, gap: lostSegment,
        });
        if (outcome.kind === 'tls') {
          tlsResult = outcome.result;
          reassembledFrom = outcome.result.reassembledFrom;
          labelPatches = outcome.result.labelPatches;
        }
      }
    }
    // Cleartext HTTP, which until now was a Protocol column filled in from the
    // port number over a payload nothing read. Gated on the port list rather
    // than sniffed from every TCP stream: `looksLikeHttp1` is strict, but a
    // stream is only recognisable at a message boundary and nothing tells us
    // where one is, so a mid-stream guess on an arbitrary port would sometimes
    // find a "request" inside a binary payload. A stream already identified
    // keeps being read whatever its port.
    let httpResult: AppStreamResult | null = null;
    // Never on a connection that has shown TLS. A frame that only *continues* a
    // TLS record produces no `tlsResult`, and without this guard it would fall
    // through to here and be handed to the HTTP decoders as cleartext - which
    // is to say, ciphertext would be fed into the same decoder the decrypted
    // plaintext goes to, from the same connection's state. The symptom was
    // HTTP/2 frame boundaries that stopped lining up a few kilobytes into a
    // download, which looks like a framing bug and is not one.
    const tlsOnThisConnection = tcpTracker !== undefined && (
      isTlsPort
      || tcpTracker.peekTlsCursor(srcIp, srcPort, dstIp, dstPort)?.unknown === false
      || tcpTracker.peekTlsCursor(dstIp, dstPort, srcIp, srcPort)?.unknown === false
    );
    if (!tcpDns && !tlsResult && !tlsOnThisConnection
      && payloadLength > 0 && !isKeepAlive && !isRetransmitted && tlsInOrder && tcpTracker) {
      const conversation = tcpTracker.tlsConversation(srcIp, srcPort, dstIp, dstPort);
      const serverIsDestination = HTTP_PORTS.has(dstPort) || (!HTTP_PORTS.has(srcPort) && dstPort < srcPort);
      const known = serverIsDestination ? conversation.appClient : conversation.appServer;
      if (HTTP_PORTS.has(srcPort) || HTTP_PORTS.has(dstPort) || (known !== undefined && known.protocol !== 'unknown')) {
        if (serverIsDestination) conversation.appClient ??= freshAppDirection();
        else conversation.appServer ??= freshAppDirection();
        const own = (serverIsDestination ? conversation.appClient : conversation.appServer)!;
        const peer = serverIsDestination ? conversation.appServer : conversation.appClient;
        const payloadEnd = Math.min(rawBytes.length, tcpPayloadStart + payloadLength);
        const app = dissectAppStream(
          rawBytes.subarray(tcpPayloadStart, payloadEnd), own, serverIsDestination, conversation.alpn, peer,
        );
        if (app.protocolLabel !== null) httpResult = app;
      }
    }

    if (tcpDns) {
      proto = 'DNS';
      protocolLabel = 'DNS';
    } else if (tlsResult) {
      proto = 'TLS';
      protocolLabel = tlsResult.appProtocolLabel ?? tlsResult.protocolLabel;
    } else if (httpResult) {
      proto = 'HTTP';
      protocolLabel = httpResult.protocolLabel ?? 'HTTP';
    } else if (proto === 'TLS' || proto === 'HTTP') {
      // The port was only ever a hint. A bare ACK or a handshake segment on
      // port 80 carries no HTTP, and calling it HTTP is what made the shipped
      // `http` colour rule paint a connection's whole three-way handshake.
      proto = 'TCP';
    }

    // Every expert annotation is a bracketed *prefix* on the Info column, and
    // several can stack on one segment - the reference analyzer shows e.g.
    // "[TCP Previous segment not captured] [TCP Out-Of-Order] 443 → 51685 ...".
    // They are ordered here the way the reference analyzer emits them: the gap that
    // explains the segment first, then the segment's own classification.
    // The tags, in the order Wireshark prints them, and the tcp.analysis.*
    // names display filters and colour rules match on.
    const expertTags: string[] = analysis ? analysis.tags : [];
    const analysisFlags: string[] = analysis ? [...analysis.flags] : [];
    const isKeepAliveAck = analysisFlags.includes('keep_alive_ack');

    // When a subdissector claimed the payload, its summary *replaces* the TCP
    // one - the reference analyzer shows "Application Data", not the ports and sequence
    // numbers underneath it. Expert tags still lead, since they describe the
    // segment rather than its contents.
    const infoParts = tcpDns
      ? [tcpDns.info]
      : tlsResult
      ? [tlsResult.info]
      : httpResult
      ? [httpResult.info.join(', ')]
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
    // "[TCP Previous segment not captured] , Application Data": when a
    // subdissector provided the Info, Wireshark's column joins the TCP expert
    // tags to it with " , " - the artefact of two dissectors each appending
    // to one column. Matched exactly, since the column text is the contract.
    const info = (tlsResult || tcpDns || httpResult) && expertTags.length > 0
      ? `${expertTags.join(' ')} , ${infoParts.join(' ')}`
      : `${expertTags.map(t => t + ' ').join('')}${infoParts.join(' ')}`;

    return {
      proto,
      protocolLabel,
      srcPort,
      dstPort,
      info,
      streamId,
      extraLayers: tcpDns
        ? [tcpDns.layer]
        : tlsResult
        ? [tlsResult.layer, ...(tlsResult.appLayers ?? [])]
        : httpResult
        ? httpResult.layers
        : undefined,
      // A name learned over TCP is a name learned; the passive resolution map
      // does not care which transport carried the answer.
      resolvedNames: tcpDns && tcpDns.resolved.length > 0 ? tcpDns.resolved : undefined,
      reassembledFrom,
      labelPatches,
      fields: {
        ...(tlsResult ? tlsResult.fields : {}),
        ...(httpResult ? httpResult.fields : {}),
        ...(tcpDns ? tcpDns.fields : {}),
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
        'tcp.seq': relSeq,
        'tcp.seq_raw': seqNum,
        'tcp.ack': relAck,
        'tcp.ack_raw': ackNum,
        'tcp.checksum': storedChecksum,
        'tcp.checksum.status': checksum.status,
        ...(tcpOptions?.mss !== undefined ? { 'tcp.options.mss': tcpOptions.mss } : {}),
        ...(tcpOptions?.windowScale !== undefined ? { 'tcp.options.wscale.shift': tcpOptions.windowScale } : {}),
        ...(tcpOptions?.sackPermitted ? { 'tcp.options.sack_perm': 1 } : {}),
        ...(tcpOptions?.tsval !== undefined ? { 'tcp.options.timestamp.tsval': tcpOptions.tsval } : {}),
        ...(analysis?.ackRttUs !== undefined ? { 'tcp.analysis.ack_rtt': analysis.ackRttUs / 1e6 } : {}),
        ...(analysis?.initialRttUs !== undefined ? { 'tcp.analysis.initial_rtt': analysis.initialRttUs / 1e6 } : {}),
        ...(analysis?.bytesInFlight !== undefined ? { 'tcp.analysis.bytes_in_flight': analysis.bytesInFlight } : {}),
        ...(analysis?.dupAckNum !== undefined ? { 'tcp.analysis.duplicate_ack_num': analysis.dupAckNum, 'tcp.analysis.duplicate_ack_frame': analysis.dupAckFrame ?? 0 } : {}),
      },
      status: status ?? (analysisFlags.length > 0 && !isKeepAlive && !isKeepAliveAck ? 'warning' : undefined),
      analysisFlags,
      layer: {
        name: 'Transmission Control Protocol',
        summary: `Transmission Control Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`,
        rawBytesRange: [transportOffset, transportOffset + tcpHeaderLen - 1],
        fields: [
          { name: 'Source Port', value: srcPort, abbrev: 'tcp.srcport', rawBytesRange: [transportOffset, transportOffset + 1] },
          { name: 'Destination Port', value: dstPort, abbrev: 'tcp.dstport', rawBytesRange: [transportOffset + 2, transportOffset + 3] },
          {
            name: 'Sequence Number',
            value: `${relSeq} (relative sequence number)`,
            abbrev: 'tcp.seq',
            rawBytesRange: [transportOffset + 4, transportOffset + 7],
            children: [
              { name: 'Sequence Number (raw)', value: seqNum, abbrev: 'tcp.seq_raw', rawBytesRange: [transportOffset + 4, transportOffset + 7] },
            ],
          },
          {
            name: 'Acknowledgment Number',
            value: `${relAck} (relative ack number)`,
            abbrev: 'tcp.ack',
            rawBytesRange: [transportOffset + 8, transportOffset + 11],
            children: [
              { name: 'Acknowledgment Number (raw)', value: ackNum, abbrev: 'tcp.ack_raw', rawBytesRange: [transportOffset + 8, transportOffset + 11] },
            ],
          },
          {
            // The data-offset nibble. The reference analyzer names it Header Length and
            // shows both the byte count and the raw nibble it decoded from.
            name: 'Header Length',
            value: `${tcpHeaderLen} bytes (${tcpHeaderLen / 4})`,
            rawBytesRange: [transportOffset + 12, transportOffset + 12],
            bitfield: { bitOffset: 0, bitLength: 4, totalBits: 8 },
          },
          {
            name: 'Flags',
            value: `0x${flags.toString(16).padStart(3, '0')} (${flagList.join(', ')})`,
            abbrev: 'tcp.flags',
            rawBytesRange: [transportOffset + 12, transportOffset + 13],
            children: tcpFlagFields(rawBytes, transportOffset),
            // A reset is an expert finding in its own right, which it never
            // was: it had a colour rule but nothing in the Expert tab, so a
            // capture where four connections were killed said so in the row
            // colours and nowhere you could count it. The category is Reset
            // rather than Broken because nothing is damaged - a conversation
            // ended, abruptly and on purpose.
            ...(rst ? { expertInfo: { category: 'Reset' as const, message: 'Connection reset (RST)' } } : {}),
          },
          ...(expectedNextRel !== undefined ? [{ name: '[Next Sequence Number]', value: expectedNextRel, generated: true }] : []),
          // The window as sent, then the window after the scale factor from
          // this connection's SYN. Wireshark draws both, and `tcp.window_size`
          // is the scaled one - the number that actually bounds the sender.
          { name: 'Window', value: rawWindow, rawBytesRange: [transportOffset + 14, transportOffset + 15] },
          { name: '[Calculated window size]', value: windowSize, generated: true, abbrev: 'tcp.window_size' },
          { name: '[TCP Segment Len]', value: payloadLength, generated: true, abbrev: 'tcp.len' },
          {
            name: 'Checksum',
            value: `0x${storedChecksum.toString(16).padStart(4, '0')} [${checksum.status === 'Good' ? 'correct' : checksum.status === 'Bad' ? 'incorrect' : 'unverified'}]`,
            rawBytesRange: [transportOffset + 16, transportOffset + 17],
            abbrev: 'tcp.checksum',
            children: [{ name: '[Checksum Status]', value: checksum.status, generated: true, abbrev: 'tcp.checksum.status',
              ...(checksum.status === 'Bad' ? { expertInfo: { category: 'Broken' as const, message: 'Bad checksum' } } : {}) }],
          },
          ...(streamPacketNumber !== undefined ? [{ name: '[Stream Packet Number]', value: streamPacketNumber, generated: true }] : []),
          ...(conversationCompleteness !== undefined ? [{ name: '[Conversation completeness]', value: conversationCompleteness, generated: true }] : []),
          ...(tcpOptions ? tcpOptions.fields : []),
          ...(analysis ? tcpAnalysisFields(analysis) : []),
        ],
      },
    };
  } else if (ipProtocolNum === 17 && rawBytes.length >= transportOffset + 8) {
    // UDP Decode
    const srcPort = (rawBytes[transportOffset] << 8) | rawBytes[transportOffset + 1];
    const dstPort = (rawBytes[transportOffset + 2] << 8) | rawBytes[transportOffset + 3];
    const udpLen = (rawBytes[transportOffset + 4] << 8) | rawBytes[transportOffset + 5];
    const udpChecksum = (rawBytes[transportOffset + 6] << 8) | rawBytes[transportOffset + 7];
    const udpVerdict = checksumVerdict(pseudoHeader, rawBytes, transportOffset, transportOffset + udpLen, udpChecksum, true, sentByUs);

    let proto: Packet['protocol'] = 'UDP';
    let protocolLabel: string | undefined;
    // The DNS wire format is reused verbatim by mDNS and LLMNR; each keeps its
    // own name in the Protocol column while sharing the dissector.
    //
    // NBNS used to be in this list and is not any more. It shares the message
    // STRUCTURE and nothing else - its names are RFC 1001 encoded, its opcodes
    // and record types are its own - so reading it as DNS produced
    // `Standard query 0x8f8e TYPE32 FHEPFCELEHFCEPFFFACACACACACACAAA`, which is
    // the name `WORKGROUP<00>` with the encoding left on. See dissectors/nbns.ts.
    const nbnsPort = srcPort === 137 || dstPort === 137;
    const dnsPortLabel =
      srcPort === 53 || dstPort === 53 ? 'DNS' :
      srcPort === 5353 || dstPort === 5353 ? 'MDNS' :
      srcPort === 5355 || dstPort === 5355 ? 'LLMNR' :
      undefined;
    if (dnsPortLabel || nbnsPort) proto = 'DNS';
    else if (srcPort === 1883 || dstPort === 1883) proto = 'MQTT';

    // QUIC (HTTP/3) rides on UDP:443 and, like TLS, is encrypted from
    // essentially the first byte - never scan it, only DNS gets the precise
    // wire-format decode, everything else gets the literal-prefix scan.
    const udpPayloadStart = transportOffset + 8;
    const isQuic = srcPort === 443 || dstPort === 443;
    const isSsdp = srcPort === 1900 || dstPort === 1900;
    const isDhcp = (srcPort === 67 || srcPort === 68) && (dstPort === 67 || dstPort === 68);
    const isDhcpv6 = (srcPort === 546 || srcPort === 547) && (dstPort === 546 || dstPort === 547);

    // The UDP header's Length field counts the 8-byte header itself, but
    // The reference analyzer's "Len=" - like TCP's - reports payload only.
    const udpPayloadLen = Math.max(0, udpLen - 8);

    // Each subdissector that claims the payload replaces the generic
    // "src → dst Len=n" summary entirely, the way the reference analyzer does.
    let info: string | null = null;
    const extraLayers: ProtocolLayer[] = [];
    const dhcpFields: Record<string, string | number> = {};
    const dnsFields: Record<string, string | number> = {};
    const quicFields: Record<string, string | number> = {};
    const appFields: Record<string, string | number> = {};
    let dnsMatchedQueryFrameId: number | undefined;
    let resolvedNames: { name: string; addresses: string[] }[] | undefined;
    const protocolTokens: string[] = [];

    if (isDhcp || isDhcpv6) {
      const payloadEnd = Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen);
      const dhcp = isDhcp
        ? dissectDhcp(rawBytes, udpPayloadStart, payloadEnd)
        : dissectDhcpv6(rawBytes, udpPayloadStart, payloadEnd);
      if (dhcp) {
        protocolLabel = dhcp.protocolLabel;
        info = dhcp.info;
        extraLayers.push(dhcp.layer);
        Object.assign(dhcpFields, dhcp.fields);
      }
    } else if (srcPort === 161 || dstPort === 161 || srcPort === 162 || dstPort === 162) {
      const payloadEnd = Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen);
      const snmp = dissectSnmp(rawBytes, udpPayloadStart, payloadEnd);
      if (snmp) {
        protocolLabel = snmp.protocolLabel;
        info = snmp.info;
        extraLayers.push(snmp.layer);
        protocolTokens.push('snmp');
        Object.assign(appFields, snmp.fields);
      }
    } else if (srcPort === 514 || dstPort === 514) {
      const payloadEnd = Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen);
      const syslog = dissectSyslog(rawBytes, udpPayloadStart, payloadEnd);
      if (syslog) {
        protocolLabel = syslog.protocolLabel;
        info = syslog.info;
        extraLayers.push(syslog.layer);
        protocolTokens.push('syslog');
        Object.assign(appFields, syslog.fields);
      }
    } else if (srcPort === 1812 || dstPort === 1812 || srcPort === 1813 || dstPort === 1813
      || srcPort === 1645 || dstPort === 1645 || srcPort === 1646 || dstPort === 1646) {
      // 1645/1646 are the pre-standard ports a lot of kit still ships with.
      const payloadEnd = Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen);
      const radius = dissectRadius(rawBytes, udpPayloadStart, payloadEnd);
      if (radius) {
        protocolLabel = radius.protocolLabel;
        info = radius.info;
        extraLayers.push(radius.layer);
        protocolTokens.push('radius');
        Object.assign(appFields, radius.fields);
      }
    } else if (nbnsPort) {
      const payloadEnd = Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen);
      const nbns = dissectNbns(rawBytes, udpPayloadStart, payloadEnd);
      if (nbns) {
        protocolLabel = nbns.protocolLabel;
        info = nbns.info;
        extraLayers.push(nbns.layer);
        protocolTokens.push('nbns');
        Object.assign(dnsFields, nbns.fields);
        if (nbns.resolved.length > 0) resolvedNames = nbns.resolved;
      }
    } else if (dnsPortLabel) {
      const multicast = dnsPortLabel === 'MDNS';
      const payloadEnd = Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen);
      const parsed = parseDnsMessage(rawBytes, udpPayloadStart, payloadEnd);
      if (parsed) {
        protocolLabel = dnsPortLabel;
        info = dnsInfoLine(parsed, multicast);

        // Pair the query with its response. The response knows which frame
        // asked; the query only learns its answer afterwards, which is what
        // the returned frame id is patched back onto.
        let pairing: { requestFrame?: number; elapsedUs?: number } | undefined;
        if (dnsTracker && frameId !== undefined && tsUs !== undefined) {
          const question = parsed.questions[0]?.name ?? '';
          if (parsed.isResponse) {
            const hit = dnsTracker.matchResponse(parsed.transactionId, dstIp, dstPort, question, multicast, tsUs);
            if (hit) {
              pairing = { requestFrame: hit.frameId, elapsedUs: hit.elapsedUs };
              dnsMatchedQueryFrameId = hit.frameId;
            }
          } else {
            dnsTracker.recordQuery(parsed.transactionId, srcIp, srcPort, question, multicast, frameId, tsUs);
          }
        }

        const dns = buildDnsLayer(rawBytes, udpPayloadStart, payloadEnd, pairing);
        if (dns) {
          extraLayers.push(dns.layer);
          Object.assign(dnsFields, dns.fields);
          if (dns.resolved.length > 0) resolvedNames = dns.resolved;
        }
      }
    } else if (isSsdp) {
      const requestLine = readAsciiRequestLine(rawBytes, udpPayloadStart);
      if (requestLine) {
        protocolLabel = 'SSDP';
        protocolTokens.push('ssdp');
        // The reference analyzer's HTTP-style dissectors emit a trailing space after the
        // request line; kept so the diff against tshark is exact.
        info = `${requestLine} `;
      }
    } else if (isQuic) {
      // A short header is only identifiable as QUIC in the context of a
      // handshake already seen on this flow, so packets that precede one stay
      // plain UDP - which is what the reference analyzer reports for them too.
      const isShortHeaderCandidate = udpPayloadStart < rawBytes.length && (rawBytes[udpPayloadStart] & 0x80) === 0;
      const flowIsKnown = quicTracker?.isKnownFlow(srcIp, srcPort, dstIp, dstPort) ?? false;

      if (!isShortHeaderCandidate || flowIsKnown) {
        const knownConnectionId = isShortHeaderCandidate
          ? quicTracker?.matchConnectionId(srcIp, srcPort, dstIp, dstPort, rawBytes, udpPayloadStart + 1)
          : undefined;
        const quic = dissectQuicDatagram(
          rawBytes,
          udpPayloadStart,
          Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen),
          knownConnectionId,
          quicTracker?.createInitialDecryptor(srcIp, srcPort, dstIp, dstPort, rawBytes)
        );
        if (quic) {
          if (quic.isLongHeader) {
            quicTracker?.noteLongHeader(srcIp, srcPort, dstIp, dstPort, quic.connectionIds);
          }
          proto = 'QUIC';
          protocolLabel = 'QUIC';
          protocolTokens.push('quic');
          info = quic.info;

          // The TLS handshake rides in CRYPTO frames, reassembled across
          // Initial packets by the flow tracker. This is the only way a
          // passive observer learns a QUIC connection's server name: the
          // ClientHello is inside an encrypted packet whose keys derive from
          // the connection ID, and it does not fit in one packet once a
          // post-quantum key share is in it.
          // STREAM frames only exist here when a key log opened the packets
          // that carried them, so this is where HTTP/3 becomes readable at
          // all. It is read before the handshake facts below because a
          // datagram can carry both.
          const streams = quicTracker?.readStreams(srcIp, srcPort, dstIp, dstPort, quic.streamFragments) ?? [];
          const http3 = buildHttp3Layer(streams);
          if (http3) {
            protocolLabel = 'HTTP3';
            info = `${quic.info}, ${http3.info.join(', ')}`;
            Object.assign(appFields, http3.fields);
          }

          const facts = quicTracker?.addCryptoFragments(srcIp, srcPort, dstIp, dstPort, quic.cryptoFragments);
          if (facts?.hello) {
            const h = facts.hello;
            if (h.sni !== null) quicFields['tls.handshake.extensions_server_name'] = h.sni;
            if (h.alpn.length > 0) quicFields['tls.handshake.extensions_alpn_str'] = h.alpn.join(',');
            quicFields['tls.handshake.ja3'] = h.ja3;
            quicFields['tls.handshake.ja3_full'] = h.ja3Full;
            quicFields['tls.handshake.ja4'] = h.ja4;
            quicFields['tls.handshake.ja4_r'] = h.ja4Raw;
            quicFields['tls.handshake.extensions_ech'] = h.echPresent ? 1 : 0;
            extraLayers.push(buildQuicTlsLayer(h, undefined));
          }
          if (facts?.serverHello) {
            const sh = facts.serverHello;
            quicFields['tls.handshake.ciphersuite'] = sh.cipher;
            quicFields['tls.handshake.ja3s'] = sh.ja3s;
            quicFields['tls.handshake.ja3s_full'] = sh.ja3sFull;
            if (sh.selectedVersion !== null) quicFields['tls.handshake.extensions.supported_version'] = sh.selectedVersion;
            extraLayers.push(buildQuicTlsLayer(undefined, sh));
          }

          // Last, so `frameProtocols` - which is read off the layer names in
          // order - puts `http3` after the `tls` of a datagram that carries
          // both a handshake message and application data. HTTP/3 is carried
          // *by* the connection the handshake sets up, not beside it.
          if (http3) extraLayers.push(http3.layer);
        }
      }
    }

    if (info === null) {
      // NTP and STUN, by their port first and then by what the payload
      // actually is. The content check is what matters for STUN: it is how a
      // WebRTC call finds itself, it runs on whichever port the ICE candidate
      // got, and RFC 5389 put a fixed magic cookie in the header precisely so
      // that it could be recognised anywhere. Without this every one of those
      // frames reads as anonymous UDP with a length.
      const payloadEnd = Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen);
      const app = (srcPort === 123 || dstPort === 123)
        ? dissectNtp(rawBytes, udpPayloadStart, payloadEnd)
        : (srcPort === 3478 || dstPort === 3478 || srcPort === 3479 || dstPort === 3479)
          ? dissectStun(rawBytes, udpPayloadStart, payloadEnd)
          : dissectUdpByContent(rawBytes, udpPayloadStart, payloadEnd);
      if (app) {
        protocolLabel = app.protocolLabel;
        info = app.info;
        extraLayers.push(app.layer);
        protocolTokens.push(app.token);
        Object.assign(appFields, app.fields);
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
      extraLayers,
      protocolTokens,
      dnsMatchedQueryFrameId,
      resolvedNames,
      fields: {
        'udp.srcport': srcPort,
        'udp.dstport': dstPort,
        'udp.length': udpLen,
        'udp.checksum': udpChecksum,
        'udp.checksum.status': udpVerdict.status,
        ...dhcpFields,
        ...dnsFields,
        ...quicFields,
        ...appFields,
      },
      layer: {
        name: 'User Datagram Protocol',
        summary: `User Datagram Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`,
        rawBytesRange: [transportOffset, transportOffset + 7],
        fields: [
          { name: 'Source Port', value: srcPort, abbrev: 'udp.srcport', rawBytesRange: [transportOffset, transportOffset + 1] },
          { name: 'Destination Port', value: dstPort, abbrev: 'udp.dstport', rawBytesRange: [transportOffset + 2, transportOffset + 3] },
          { name: 'Length', value: udpLen, abbrev: 'udp.length', rawBytesRange: [transportOffset + 4, transportOffset + 5] },
          {
            name: 'Checksum',
            value: `0x${udpChecksum.toString(16).padStart(4, '0')} [${udpVerdict.status === 'Good' ? 'correct' : udpVerdict.status === 'Bad' ? 'incorrect' : 'unverified'}]`,
            rawBytesRange: [transportOffset + 6, transportOffset + 7], abbrev: 'udp.checksum',
            // The finding IPv4 and TCP both raised and UDP did not, so a
            // damaged datagram was reported in the tree and nowhere else -
            // not in the Expert tab, not by a colour band, not by a filter on
            // the category. Same verdict function and so the same offload
            // policy: a frame this machine sent is `Unverified`, never `Bad`.
            children: [{ name: '[Checksum Status]', value: udpVerdict.status, generated: true, abbrev: 'udp.checksum.status',
              ...(udpVerdict.status === 'Bad' ? { expertInfo: { category: 'Broken' as const, message: 'Bad checksum' } } : {}) }],
          },
          { name: 'UDP payload', value: `${Math.max(0, udpLen - 8)} bytes`, rawBytesRange: [transportOffset + 8, transportOffset + Math.max(8, udpLen - 1)] },
        ],
      },
    };
  } else if (ipProtocolNum === 2) {
    // IGMP sits directly on IP with no ports, so it is dispatched here beside
    // ICMP rather than in the port-based subdissector path.
    const igmp = dissectIgmp(rawBytes, transportOffset, l4SegmentLen ?? rawBytes.length - transportOffset);
    if (igmp) {
      return {
        // No IGMP member in the coarse ProtocolType union; ICMP is the closest
        // existing key, and protocolLabel carries the real name to the column.
        proto: 'ICMP',
        protocolLabel: igmp.protocolLabel,
        info: igmp.info,
        fields: igmp.fields,
        layer: igmp.layer,
      };
    }
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
        case 128: info = 'Echo (ping) request '; break;
        case 129: info = 'Echo (ping) reply   '; break;
        case 133: info = 'Router Solicitation'; break;
        case 134: info = 'Router Advertisement'; break;
        case 135: info = describeNeighborSolicitation(rawBytes, transportOffset); break;
        case 136: info = describeNeighborAdvertisement(rawBytes, transportOffset); break;
        case 137: info = 'Redirect'; break;
        case 130: info = 'Multicast Listener Query'; break;
        case 131: info = 'Multicast Listener Report'; break;
        case 132: info = 'Multicast Listener Done'; break;
        case 143: info = 'Multicast Listener Report Message v2'; break;
        case 1: info = `Destination Unreachable (${ICMPV6_UNREACHABLE_CODES[icmpCode] ?? `Code ${icmpCode}`})`; break;
        case 2: info = 'Packet Too Big'; break;
        case 3: info = `Time Exceeded (${icmpCode === 0 ? 'hop limit exceeded in transit' : 'fragment reassembly time exceeded'})`; break;
        case 4: info = `Parameter Problem (${icmpCode === 0 ? 'erroneous header field encountered' : icmpCode === 1 ? 'unrecognized Next Header type encountered' : 'unrecognized IPv6 option encountered'})`; break;
        default: info = `ICMPv6 Type ${icmpType} Code ${icmpCode}`;
      }
    } else if (icmpType === 8) {
      // Two trailing spaces, and five after "reply": Wireshark pads the word so
      // the id= columns line up down the Info column. Matched exactly, since
      // the column text is the contract the parity harness compares.
      info = 'Echo (ping) request ';
    } else if (icmpType === 0) {
      info = 'Echo (ping) reply   ';
    } else {
      const named = ICMP_TYPE_NAMES[icmpType];
      const code = icmpType === 3 ? ICMP_UNREACHABLE_CODES[icmpCode]
        : icmpType === 11 ? (icmpCode === 0 ? 'Time to live exceeded in transit' : 'Fragment reassembly time exceeded')
        : icmpType === 5 ? ICMP_REDIRECT_CODES[icmpCode] : undefined;
      info = named ? (code ? `${named} (${code})` : named) : `ICMP Type ${icmpType} Code ${icmpCode}`;
    }

    if (icmpId !== undefined && icmpSeq !== undefined) {
      // The reference analyzer shows both the big-endian wire value and the same 16 bits
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
        ? {
            'icmpv6.type': icmpType, 'icmpv6.code': icmpCode,
            // Only for an RA. Every other ICMPv6 type would carry a bag of
            // empty keys, and a field a frame does not have is a field that
            // correctly matches nothing.
            ...(icmpType === 134 ? routerAdvertisementFields(rawBytes, transportOffset) : {}),
          }
        : { 'icmp.type': icmpType, 'icmp.code': icmpCode },
      info,
      icmpMatchedRequestFrameId,
      layer: {
        name: isIcmpv6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol',
        summary: `${isIcmpv6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol'}, ${info}`,
        rawBytesRange: [transportOffset, transportOffset + (icmpId !== undefined ? 7 : 3)],
        fields: icmpMatchedRequestFrameId !== undefined
          ? [
              ...fields,
              // The echo request this reply answers. Generated - it describes
              // another frame, not bytes in this one - and clickable, so the
              // pairing the tracker already computes is navigable instead of
              // only appearing as text in the Info column.
              {
                name: '[Request In]',
                value: icmpMatchedRequestFrameId,
                generated: true,
                linkToFrame: icmpMatchedRequestFrameId,
              },
            ]
          : fields,
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
  /** The SYN's option summary, in wire order. */
  infoParts: string[];
  tsval?: number;
  tsecr?: number;
} {
  const fields: ProtocolField[] = [];
  let mss: number | undefined;
  let windowScale: number | undefined;
  let sackPermitted = false;
  const sackBlocks: { leftEdge: number; rightEdge: number }[] = [];
  const infoParts: string[] = [];
  let tsval: number | undefined;
  let tsecr: number | undefined;

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
      infoParts.push(`MSS=${mss}`);
      fields.push({ name: 'TCP Option - Maximum Segment Size', value: `MSS: ${mss}`, rawBytesRange: [offset, offset + length - 1], abbrev: 'tcp.options.mss' });
    } else if (kind === 3 && length === 3) {
      windowScale = rawBytes[offset + 2];
      infoParts.push(`WS=${2 ** windowScale}`);
      fields.push({ name: 'TCP Option - Window Scale', value: `${windowScale} (multiply by ${2 ** windowScale})`, rawBytesRange: [offset, offset + length - 1], abbrev: 'tcp.options.wscale.shift' });
    } else if (kind === 4 && length === 2) {
      sackPermitted = true;
      infoParts.push('SACK_PERM');
      fields.push({ name: 'TCP Option - SACK Permitted', value: 'True', rawBytesRange: [offset, offset + length - 1], abbrev: 'tcp.options.sack_perm' });
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
      tsval = ((rawBytes[offset + 2] << 24) | (rawBytes[offset + 3] << 16) | (rawBytes[offset + 4] << 8) | rawBytes[offset + 5]) >>> 0;
      tsecr = ((rawBytes[offset + 6] << 24) | (rawBytes[offset + 7] << 16) | (rawBytes[offset + 8] << 8) | rawBytes[offset + 9]) >>> 0;
      fields.push({ name: 'TCP Option - Timestamps', value: `TSval ${tsval}, TSecr ${tsecr}`, rawBytesRange: [offset, offset + length - 1], abbrev: 'tcp.options.timestamp.tsval' });
    } else {
      fields.push({ name: `TCP Option - Unknown (Kind ${kind})`, value: `${length} bytes`, rawBytesRange: [offset, offset + length - 1] });
    }

    offset += length;
  }

  return { fields, mss, windowScale, sackPermitted, sackBlocks, infoParts, tsval, tsecr };
}

/** The [SEQ/ACK analysis] subtree, as Wireshark lays it out. */
function tcpAnalysisFields(a: TcpAnalysis): ProtocolField[] {
  const children: ProtocolField[] = [];
  if (a.ackOfFrame !== undefined) {
    children.push({ name: '[This is an ACK to the segment in frame]', value: a.ackOfFrame, generated: true, linkToFrame: a.ackOfFrame });
    children.push({ name: '[The RTT to ACK the segment was]', value: `${((a.ackRttUs ?? 0) / 1e6).toFixed(9)} seconds`, generated: true, abbrev: 'tcp.analysis.ack_rtt' });
  }
  if (a.initialRttUs !== undefined) {
    children.push({ name: '[iRTT]', value: `${(a.initialRttUs / 1e6).toFixed(9)} seconds`, generated: true, abbrev: 'tcp.analysis.initial_rtt' });
  }
  if (a.bytesInFlight !== undefined) {
    children.push({ name: '[Bytes in flight]', value: a.bytesInFlight, generated: true, abbrev: 'tcp.analysis.bytes_in_flight' });
  }
  if (a.flags.length > 0) {
    // The flag decides the category (`dissect/tcpAnalysis.ts`), which is where
    // "the sniffer missed frames" finally stops being filed as network loss.
    const categoryOf = (flag: string): ExpertCategory =>
      CATEGORY_BY_FLAG[flag as keyof typeof CATEGORY_BY_FLAG] ?? 'Note';
    children.push({
      name: '[TCP Analysis Flags]', value: '', generated: true,
      children: a.tags.map((tag, i) => {
        const category = categoryOf(a.flags[i] ?? '');
        return {
          name: `[Expert Info (${category})]`,
          value: tag.replace(/^\[TCP |\]$/g, ''), generated: true,
          expertInfo: { category, message: tag },
        };
      }),
    });
  }
  if (children.length === 0) return [];
  return [{ name: '[SEQ/ACK analysis]', value: '', generated: true, children }];
}

// --- transport checksums --------------------------------------------------------

/** The IPv4 pseudo-header: src, dst, zero, protocol, transport length. */
function ipv4PseudoHeader(rawBytes: Uint8Array, l3Offset: number, protocol: number, transportLen: number): Uint8Array | undefined {
  if (transportLen <= 0 || transportLen > 0xffff) return undefined;
  const ph = new Uint8Array(12);
  ph.set(rawBytes.subarray(l3Offset + 12, l3Offset + 20), 0);
  ph[9] = protocol;
  ph[10] = transportLen >> 8; ph[11] = transportLen & 0xff;
  return ph;
}

/**
 * The protocol number IPv6 fragments are keyed under.
 *
 * RFC 8200 §4.5 keys a datagram on source, destination and identification and
 * deliberately leaves the payload protocol out - the Fragment header sits
 * above whatever the payload turns out to be. Passing one constant for every
 * IPv6 fragment is how that exclusion is expressed to a tracker whose key was
 * written for IPv4's, and 44 is the Fragment header's own number.
 */
const IPV6_FRAGMENT_KEY = 44;

/**
 * Removes every byte range from a layer and its rows.
 *
 * A layer dissected from a reassembled datagram, or from any buffer that is
 * not the frame the user is looking at, would otherwise point the hex view at
 * offsets in this frame that hold something else entirely. Wireshark solves
 * this with a second data source tab; the honest answer with one hex view is
 * to say nothing rather than to point somewhere wrong.
 */
function stripByteRanges(layer: ProtocolLayer): void {
  delete layer.rawBytesRange;
  const visit = (fields: ProtocolField[]) => {
    for (const field of fields) {
      delete field.rawBytesRange;
      if (field.children) visit(field.children);
    }
  };
  visit(layer.fields);
}

/** The IPv6 pseudo-header (RFC 8200 §8.1): src, dst, 32-bit length, zeros, next header. */
function ipv6PseudoHeader(rawBytes: Uint8Array, l3Offset: number, nextHeader: number, payloadLen: number): Uint8Array | undefined {
  if (payloadLen <= 0) return undefined;
  const ph = new Uint8Array(40);
  ph.set(rawBytes.subarray(l3Offset + 8, l3Offset + 40), 0);
  ph[32] = (payloadLen >>> 24) & 0xff; ph[33] = (payloadLen >>> 16) & 0xff; ph[34] = (payloadLen >>> 8) & 0xff; ph[35] = payloadLen & 0xff;
  ph[39] = nextHeader;
  return ph;
}

/** One's-complement sum over the pseudo-header and a byte range, RFC 1071. */
function transportChecksum(pseudoHeader: Uint8Array, rawBytes: Uint8Array, start: number, end: number): number {
  let sum = 0;
  for (let i = 0; i + 1 < pseudoHeader.length; i += 2) sum += (pseudoHeader[i] << 8) | pseudoHeader[i + 1];
  for (let i = start; i + 1 < end; i += 2) sum += (rawBytes[i] << 8) | rawBytes[i + 1];
  if ((end - start) % 2 === 1) sum += rawBytes[end - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

/**
 * Verdict on a transport checksum, with the offload policy Wireshark ships
 * (its TCP/UDP validation is off by default for exactly this reason): a
 * segment captured on the sending host before the NIC filled the checksum
 * in - one larger than the wire MTU (segmentation offload) or with a zero
 * checksum - is "Unverified", never "Bad". A frame the capture truncated is
 * Unverified too, since the bytes to check are not all there.
 */
function checksumVerdict(
  pseudoHeader: Uint8Array | undefined, rawBytes: Uint8Array, start: number, declaredEnd: number, stored: number, udp: boolean,
  /**
   * True when this machine SENT the frame, which settles the question.
   *
   * The existing guards catch offload only where it leaves an obvious trace -
   * a zero checksum, a frame past the MTU. Windows' partial checksum offload
   * leaves neither: the NIC writes the pseudo-header sum and finishes the job
   * afterwards, so the field is non-zero, wrong, and indistinguishable from
   * corruption by looking at the bytes.
   *
   * Measured over both fixtures, that is **1,998 and 3,459 frames, and 100% of
   * them outbound** - every "Bad" checksum in either capture. Wireshark cannot
   * make this call because it does not know which frames the host sent; it
   * settles for shipping TCP/UDP validation off by default. Knowing the
   * direction, the honest verdict is Unverified.
   */
  sentByUs: boolean,
): { status: 'Good' | 'Bad' | 'Unverified'; computed?: number } {
  if (pseudoHeader === undefined || stored === 0 || declaredEnd > rawBytes.length || declaredEnd - start > ETHERNET_MAX_FRAME - ETHERNET_IPV4_HEADER_BYTES) {
    return { status: 'Unverified' };
  }
  if (sentByUs) return { status: 'Unverified' };
  const computed = transportChecksum(pseudoHeader, rawBytes, start, declaredEnd);
  // A UDP checksum computing to 0 is sent as 0xffff.
  const good = computed === 0 || (udp && computed === 0 && stored === 0xffff);
  return { status: good ? 'Good' : 'Bad', computed };
}

/**
 * Standard Internet checksum (RFC 1071) over the IPv4 header, with the
 * checksum field itself treated as zero - the same algorithm the sender
 * used to produce it, so a correct header always recomputes to the value
 * actually stored there.
 */
/**
 * IANA protocol numbers, for the Protocol column when nothing dissects the
 * payload. Only the ones that actually turn up on a LAN or a VPN link - the
 * point is to name what a capture will really contain, not to mirror the whole
 * registry, and anything missing still gets an honest "IP Protocol N".
 */
/** ICMPv4 type names, and the codes worth spelling out (RFC 792). */
const ICMP_TYPE_NAMES: Record<number, string> = {
  3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect', 9: 'Router advertisement',
  10: 'Router solicitation', 11: 'Time-to-live exceeded', 12: 'Parameter problem',
  13: 'Timestamp request', 14: 'Timestamp reply', 15: 'Information request', 16: 'Information reply',
  17: 'Address mask request', 18: 'Address mask reply',
};
const ICMP_UNREACHABLE_CODES: Record<number, string> = {
  0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable', 3: 'Port unreachable',
  4: 'Fragmentation needed', 5: 'Source route failed', 6: 'Destination network unknown',
  7: 'Destination host unknown', 9: 'Network administratively prohibited',
  10: 'Host administratively prohibited', 13: 'Communication administratively filtered',
};
const ICMP_REDIRECT_CODES: Record<number, string> = {
  0: 'Redirect for network', 1: 'Redirect for host', 2: 'Redirect for TOS and network', 3: 'Redirect for TOS and host',
};
const ICMPV6_UNREACHABLE_CODES: Record<number, string> = {
  0: 'no route to destination', 1: 'communication with destination administratively prohibited',
  2: 'beyond scope of source address', 3: 'address unreachable', 4: 'port unreachable',
  5: 'source address failed ingress/egress policy', 6: 'reject route to destination',
};

const IP_PROTOCOL_NAMES: Record<number, string> = {
  0: 'IPv6 Hop-by-Hop',
  2: 'IGMP',
  4: 'IPv4',
  41: 'IPv6',
  43: 'IPv6-Route',
  44: 'IPv6-Frag',
  46: 'RSVP',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  59: 'IPv6-NoNxt',
  60: 'IPv6-Opts',
  89: 'OSPF',
  103: 'PIM',
  112: 'VRRP',
  115: 'L2TP',
  132: 'SCTP',
  137: 'MPLS-in-IP',
};

/**
 * Names an IP payload that no dissector claimed.
 *
 * Without this, an undissected protocol kept `decodeRawEthernetPacket`'s
 * initial values and was displayed as a TCP frame whose Info column read
 * "Frame (N bytes)" - actively wrong on both counts. This is the IP-layer
 * counterpart of the ethertype fallback used for undissected L2 frames.
 */
function describeUndissectedIpPayload(ipProtocolNum: number): { label: string; info: string } {
  const name = IP_PROTOCOL_NAMES[ipProtocolNum];
  return name
    ? { label: name, info: `${name} payload (protocol ${ipProtocolNum}, not dissected)` }
    : {
        label: `IP Protocol ${ipProtocolNum}`,
        info: `IP protocol ${ipProtocolNum} payload (not dissected)`,
      };
}

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

/**
 * The hex dump for a packet, built on demand.
 *
 * Prefers a stored dump if one exists - imported captures and older code
 * paths may still carry them - and otherwise renders from rawBytes. Cheap
 * enough to call per render for a single selected packet; do not map it
 * across the whole buffer.
 */
export function packetHexDump(packet: { hexDump?: string; rawBytes: Uint8Array }): string {
  return packet.hexDump ?? formatHexDump(packet.rawBytes);
}

/** The ASCII dump for a packet, built on demand. See packetHexDump. */
export function packetAsciiDump(packet: { asciiDump?: string; rawBytes: Uint8Array }): string {
  return packet.asciiDump ?? formatAsciiDump(packet.rawBytes);
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
