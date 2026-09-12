import { Packet, ProtocolLayer, ProtocolField, ExpertCategory, ExpertInfo } from '../types/packet';
import { applyInfoPatch } from './dissect/infoPatch';
import { CATEGORY_RANK, expertItemsFor } from './expertInfo';
import { TcpStreamTracker } from './tcpStreamTracker';
import { resolveMacName } from './macVendors';
import { dissectArp, dissectStp, labelForEtherType, L2DissectorResult } from './dissectors/l2';
import { dissectLinkLayer } from './dissectors/linkLayer';
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
import { SCORING_FRAMES, inferHostIdentity } from './hostIdentity';
import { decodeNetworkLayer } from './dissectors/networkLayer';
import { keyLog } from './tls/keyLog';
import { DSB_SECRETS_TYPE_TLS_KEY_LOG } from './pcapngWriter';
import { LINKTYPE, type InfoPatch } from './dissect/types';
// Re-exported because it was declared here for a long time and four modules
// import it from this path; it now lives with the rest of the contract.
export type { InfoPatch } from './dissect/types';
import { dissectCdp, CDP_SNAP_PID, CISCO_OUI } from './dissectors/cdp';
import { DnsTracker } from './dnsTracker';
import { dissectIeee1905 } from './dissectors/ieee1905';
import { dissectLldp } from './dissectors/lldp';
import { QuicFlowTracker } from './quicFlowTracker';
import { displayProtocol, toBase64 } from './exportSchema';
import { buildCsvText } from './tabularWriters';
import { IcmpEchoTracker } from './icmpEchoTracker';
import { poolExpert, poolTokens } from './dissect/tokenPool';
import { FieldBlockWriter } from './dissect/fieldSplit';

/**
 * Frames handed over at a time while an import streams.
 *
 * Matched to what a live flush carries rather than to a chunk on disk: the
 * store batches into 4,096-frame chunks itself, and the caller wants batches
 * small enough that it can yield to the UI between them.
 */
export const IMPORT_BATCH_FRAMES = 2048;

/**
 * Frames kept in reach of a patch before they are handed over.
 *
 * The same bound `captureWriter.ts` puts on its staging ring, and for the same
 * reason: a patch chases a protocol event, so an ICMP reply seconds later or a
 * TCP PDU reassembled across a stalled stream can reach a long way back. Here
 * it is a frame count alone, not a time - an import replays a whole capture's
 * timestamps as fast as it can dissect, so a clock horizon would be met
 * instantly and hold nothing.
 *
 * 100,000 frames of held summaries is roughly 66 MB, which is the price of an
 * import not losing cross-references the same file would keep if it were
 * captured live.
 */
export const IMPORT_PATCH_WINDOW = 100_000;

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

  /**
   * A capture file, handed over in batches rather than all at once.
   *
   * What `parseCaptureFile` is for a file that fits in the buffer, this is for
   * one that does not: the caller writes each batch to the capture store and
   * keeps only the tail, so the import is bounded by the store rather than by
   * memory.
   *
   * `onBatch` is **synchronous**, and that is deliberate rather than
   * unfinished. The dissection pass owns five trackers whose state is the
   * whole reason a frame's row is not a function of its own bytes; an `await`
   * in the middle of it would let a second import interleave with them. So the
   * batches arrive during the pass, and the caller drops each one as it goes -
   * which is what bounds the memory.
   *
   * What that does **not** do is yield to the UI. An import of a million
   * frames blocks the main thread for the whole dissection, exactly as it did
   * before this existed; streaming changed where the frames end up, not who is
   * doing the work. Moving the pass off the main thread is its own step.
   *
   * Frames are numbered 1..N over the file, exactly as `parseCaptureFile`
   * numbers them, so nothing downstream can tell which route a frame took.
   */
  public static async streamCaptureFile(
    file: File,
    onBatch: (packets: Packet[]) => void,
    /**
     * `patchWindow` is settable for the same reason `CaptureHost` takes
     * `scanSliceMs`: what has to be asserted is the behaviour at the window's
     * edge, and reaching it honestly would mean a test that dissects several
     * hundred thousand frames.
     */
    options: { keepTrees?: boolean; patchWindow?: number; batchFrames?: number } = {},
  ): Promise<{ totalFrames: number; built: number; missedPatches: number }> {
    // No cap: the point is the frames the cap used to throw away. What bounds
    // this is the patch window above, and whatever the caller does with each
    // batch.
    const extracted = await PcapService.extractFrames(file, Number.POSITIVE_INFINITY);
    const host = PcapService.inferHostFromFrames(extracted.frames);

    let built = 0;
    const { missedPatches } = PcapService.buildPacketsInBatches(
      extracted.frames,
      (batch) => { built += batch.length; onBatch(batch); },
      options.keepTrees ?? false,
      host,
      options.batchFrames ?? IMPORT_BATCH_FRAMES,
      options.patchWindow ?? IMPORT_PATCH_WINDOW,
    );
    return { totalFrames: extracted.totalFrames, built, missedPatches };
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
    const all: Packet[] = [];
    PcapService.buildPacketsInBatches(
      frames, (batch) => { all.push(...batch); }, keepTrees, host,
    );
    return all;
  }

  /**
   * The same pass, handing frames over as it goes instead of at the end.
   *
   * ## Why the array cannot simply be returned
   *
   * A capture file bigger than the RAM buffer used to be **truncated**: the
   * importer built `maxFrames` frames and said so in a note. The store can hold
   * the rest, but only if the frames reach it, and they cannot all be in one
   * array on the way - that array is the thing the cap existed to bound.
   *
   * ## The patch window is why this is not just a loop with a callback
   *
   * Dissection amends frames it has already emitted: `[TCP PDU reassembled in
   * N]` on every segment of a multi-segment PDU, `[Reassembled in N]` for IP
   * fragments, `dns.response_in` written onto the query by its answer, and
   * ICMP `(reply in N)` where the round trip can be seconds. This pass applies
   * all of those by **indexing straight into the array it is building** -
   * `parsedPackets[patch.frameId - 1]` - which stops working the moment a
   * frame has been handed over and dropped.
   *
   * So frames are held until no open patch can still reach them, exactly the
   * way `captureWriter.ts` holds rows behind its horizon, and only then handed
   * over. A patch that reaches back further than the window is counted rather
   * than applied to the wrong frame - which is what an unchecked index would
   * do, silently, to whichever frame happened to be there.
   *
   * The dense-field split runs on the way out rather than at the end, for the
   * same reason: a frame is only finished once it is out of patch range.
   */
  private static buildPacketsInBatches(
    frames: ExtractedFrame[],
    onBatch: (packets: Packet[]) => void,
    keepTrees = false,
    host?: HostIdentity,
    batchFrames = IMPORT_BATCH_FRAMES,
    patchWindow = IMPORT_PATCH_WINDOW,
  ): { missedPatches: number } {
    /** The window: frames built and not yet handed over, oldest first. */
    const parsedPackets: Packet[] = [];
    /** How many have left it, so an id still maps to a position. */
    let shipped = 0;
    let missedPatches = 0;
    const fieldWriter = new FieldBlockWriter();

    /**
     * The frame with this id, or undefined if it is out of the window.
     *
     * `- shipped` is the load-bearing part: without it every patch after the
     * first hand-over lands on the wrong offset, and `scripts/capture/
     * import-stream.ts` fails three ways. The `id` check after it is
     * belt-and-braces - nothing reachable makes the array and the counter
     * disagree, and removing it fails nothing - kept because the cost of being
     * wrong here is a cross-reference written onto an unrelated frame.
     */
    const held = (frameId: number): Packet | undefined => {
      const at = frameId - 1 - shipped;
      if (at < 0 || at >= parsedPackets.length) return undefined;
      const packet = parsedPackets[at];
      return packet !== undefined && packet.id === frameId ? packet : undefined;
    };

    /** Hands over everything past `keep`, splitting its dense fields first. */
    const drain = (keep: number): void => {
      while (parsedPackets.length > keep) {
        const batch = parsedPackets.splice(0, Math.min(batchFrames, parsedPackets.length - keep));
        // After the patches, never before: a frame leaves the window only once
        // nothing can still amend it, and this is that moment.
        fieldWriter.absorb(batch);
        shipped += batch.length;
        onBatch(batch);
      }
    };

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
        const requestPacket = held(icmpMatchedRequestFrameId);
        if (requestPacket) requestPacket.info += ` (reply in ${packet.id})`;
        else missedPatches += 1;
      }
      if (infoPatches) {
        // Frame ids are 1-based positions in the window, so no search is needed.
        for (const patch of infoPatches) {
          const target = held(patch.frameId);
          if (target) applyInfoPatch(target, patch);
          else missedPatches += 1;
        }
      }

      // Everything past the window is finished, and goes.
      if (parsedPackets.length > patchWindow + batchFrames) drain(patchWindow);
    }

    // Whatever is left has nothing else coming for it.
    drain(0);
    return { missedPatches };
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
  'Lightweight Directory Access Protocol': 'ldap',
  'SMB2': 'smb2',
  'Border Gateway Protocol': 'bgp',
  'Generic Routing Encapsulation': 'gre',
  'Session Initiation Protocol': 'sip',
  'Real-time Transport Control Protocol': 'rtcp',
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
  'Trivial File Transfer Protocol': 'tftp',
  'NetBIOS Datagram Service': 'nbdgm',
  'BFD Control Message': 'bfd',
  'BFD Echo Message': 'bfd',
  'Constrained Application Protocol': 'coap',
  'Precision Time Protocol (IEEE1588)': 'ptp',
  'Cisco Hot Standby Router Protocol': 'hsrp',
  'Virtual Router Redundancy Protocol': 'vrrp',
  'Open Shortest Path First': 'ospf',
  'Routing Information Protocol': 'rip',
  'RIPng': 'ripng',
  'Cisco Discovery Protocol': 'cdp',
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
  // does - "SagemcomBroa_aa:bb:cc", "Broadcast", "Nearest-Customer-Bridge".
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
  } else if (currentEtherType === CDP_SNAP_PID && link.snapOui === CISCO_OUI) {
    // CDP is not an ethertype: 0x2000 is a protocol id under Cisco's OUI, and
    // is only CDP in that company. Dispatching on the pair is what keeps this
    // from claiming a SNAP frame that happens to carry the same number under
    // somebody else's organisation code.
    l2Result = dissectCdp(rawBytes, l3Offset, rawBytes.length);
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
  // The network layer, and the transport layer under it - see
  // dissectors/networkLayer.ts. It returns rather than assigns, because sixteen
  // of this function's locals are decided in there; `layers` and `filterFields`
  // are containers and are still written through.
  ({
    srcIp, dstIp, proto, protocolLabel, info, status, analysisFlags, srcPort, dstPort,
    streamId, icmpMatchedRequestFrameId, infoPatches, resolvedNames, transportLayerIndex,
    extensionTokens, transportTokens,
  } = decodeNetworkLayer(rawBytes, l3Offset, currentEtherType, layers, filterFields, {
    srcIp, dstIp, proto, protocolLabel, info, status, analysisFlags, srcPort, dstPort,
    streamId, icmpMatchedRequestFrameId, infoPatches, resolvedNames, transportLayerIndex,
    extensionTokens, transportTokens,
  }, { id, tsUs, relativeTime, timeDelta, origLen, tcpTracker, icmpTracker, quicTracker,
       dnsTracker, l3Tracker, sentByUs }));

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
 * Applies one patch to a packet, in place.
 *
 * Moved to `dissect/infoPatch.ts` and re-exported here so every caller is
 * unchanged. It left because `captureWriter.ts` needs it, and importing it
 * from this file pulled the entire parser into the capture store process.
 */
export { applyInfoPatch };

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

/**
 * The formatted text for one whole second, kept so the next frame in it is free.
 *
 * Caching the `Intl.DateTimeFormat` OBJECT (above) removed the cost of building
 * one per frame. It did not remove the cost of USING one: `formatToParts` is an
 * ICU call that allocates a part array, and a later profile still put this
 * function at **15.2% of the entire pipeline** - the largest single item in it,
 * ahead of the whole TCP transport decoder.
 *
 * Everything it produces except the fractional digits is a function of the
 * whole second: the date, the wall clock to the second, and the zone name. A
 * capture delivers thousands of frames inside one of those - the fixture
 * averages ~3,300 a second and bursts past 9,000 - so a single-entry cache per
 * formatter hits essentially always, and misses only on the second boundary.
 *
 * Keyed on the second rather than the day, which costs nothing extra and is
 * what makes a DST transition come out right: the zone name is re-resolved
 * whenever the second changes, so the frame either side of the change is
 * formatted by ICU rather than by an assumption about how often zones move.
 */
interface ArrivalSecond {
  second: number;
  /** "Sep 11, 2026 00:13:50" - everything before the fractional part. */
  head: string;
  /** The zone name, which follows the fractional part. */
  zone: string;
}

let localArrivalSecond: ArrivalSecond | undefined;
let utcArrivalSecond: ArrivalSecond | undefined;

function arrivalSecond(tsUs: number, utc: boolean): ArrivalSecond {
  const second = Math.floor(tsUs / 1_000_000);
  const cached = utc ? utcArrivalSecond : localArrivalSecond;
  if (cached !== undefined && cached.second === second) return cached;

  const parts = arrivalFormatter(utc).formatToParts(new Date(second * 1000));
  // One pass over the parts rather than a `find` per field: there are six
  // fields and about ten parts, so the old form was sixty scans a frame.
  let month = '', day = '', year = '', hour = '', minute = '', sec = '', zone = '';
  for (const p of parts) {
    switch (p.type) {
      case 'month': month = p.value; break;
      case 'day': day = p.value; break;
      case 'year': year = p.value; break;
      case 'hour': hour = p.value; break;
      case 'minute': minute = p.value; break;
      case 'second': sec = p.value; break;
      case 'timeZoneName': zone = p.value; break;
    }
  }
  const fresh: ArrivalSecond = {
    second,
    head: `${month} ${day}, ${year} ${hour}:${minute}:${sec}`,
    zone,
  };
  if (utc) utcArrivalSecond = fresh; else localArrivalSecond = fresh;
  return fresh;
}

function formatArrivalTime(tsUs: number, utc = false): string {
  const { head, zone } = arrivalSecond(tsUs, utc);
  const fractional = String((tsUs % 1_000_000) * 1000).padStart(9, '0');
  return `${head}.${fractional} ${zone}`;
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











// --- transport checksums --------------------------------------------------------











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



