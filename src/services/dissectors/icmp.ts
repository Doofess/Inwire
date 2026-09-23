/**
 * ICMP and ICMPv6, which had no module and 120 inline lines.
 *
 * It was the last transport-shaped decoder still living inside
 * `networkLayer.ts` - TCP, UDP, IGMP, VRRP and OSPF all moved out under ADR
 * 0023, and this one stayed because it was short. It stopped being short the
 * moment anything measured it: `scripts/parity/tree-coverage.ts` read **icmp
 * 2/11** on both fixtures, and 2 of those 11 were `icmp.type` and `icmp.code`.
 *
 * **Most of the gap was rows that already existed and carried no name.**
 * `Identifier (BE)` and `Sequence Number (BE)` were drawn on 528 inwire frames
 * with no `abbrev`, so `icmp.ident` and `icmp.seq` - two of the most typed
 * filters there are - resolved to nothing, and the detail pane could not turn
 * either row into one. The reference draws four rows there, not two: it shows
 * the same sixteen bits read big-endian AND little-endian, because most ping
 * implementations increment the sequence counter in host order and the wire
 * value is therefore the one nobody recognises.
 *
 * The rest is depth this build simply did not have: the checksum and its
 * verdict, the echo payload, the elapsed time between a request and its reply,
 * and - on the v6 side - every Neighbor Discovery option as a subtree instead
 * of a string.
 *
 * **The NDP options were the sharpest case.** `collectNdpOptions` has been
 * walking them for as long as the Network panel has existed, and everything it
 * found went into the flat field bag or into an Info string. Not one option
 * ever became a `ProtocolField`, so the tree for a Neighbor Solicitation was
 * Type and Code and nothing else - for a message whose entire content is the
 * target address and the sender's MAC.
 */
import type { ProtocolField } from '../../types/packet';
import type { TransportResult } from '../dissect/types';
import type { IcmpEchoTracker } from '../icmpEchoTracker';
import { formatIpv6Address, formatMac } from '../addressFormat';
import { checksumVerdict } from '../dissect/transportShared';
import { dataLayer } from './mediaType';
// The reference's FT_BYTES rendering. It was a copy of the loop three other
// dissectors also carried, and it clamped only the top end - `bytes[-1]` is
// `undefined` and a thrown `TypeError`, not a short read. The shared one
// clamps both ends, and is 4.7x faster for the same string (`hexBytes.ts`).
import { hexColons } from '../dissect/hexBytes';

/** Everything the decode needs that is neither the bytes nor the offset. */
export interface IcmpContext {
  /** Protocol 58 rather than 1 - a different type space and a pseudo-header. */
  isIcmpv6: boolean;
  srcIp: string;
  dstIp: string;
  /** The outer TTL/hop limit, which the reference puts in the echo's Info. */
  ttl?: number;
  frameId?: number;
  /** Capture time, epoch microseconds - the response time is measured from it. */
  tsUs?: number;
  icmpTracker?: IcmpEchoTracker;
  /** Bytes the network layer says belong to this message, padding excluded. */
  l4SegmentLen?: number;
  /** The IPv6 pseudo-header. Undefined on ICMPv4, which checksums no such thing. */
  pseudoHeader?: Uint8Array;
  /** See `checksumVerdict` - `undefined` is a third answer, not a false. */
  sentByUs?: boolean;
}

/**
 * ICMPv4 checksums the message **and nothing else** - no pseudo-header, which
 * is the one thing that separates it from every other transport here.
 *
 * `checksumVerdict` treats an undefined pseudo-header as "the network layer
 * could not supply one", which is an honest Unverified for TCP and UDP and
 * flatly wrong for this: there is nothing to supply. A zero-length array is
 * the accurate statement, and it contributes nothing to the one's-complement
 * sum, so the verdict comes out of the same function as everyone else's rather
 * than out of a second implementation kept in step by hand.
 */
const NO_PSEUDO_HEADER = new Uint8Array(0);

/**
 * The two protocols' names for the four fields they both have.
 *
 * Spelled out rather than built from a `${prefix}` template, and that is the
 * lesson `scripts/dissect/registry.ts` taught on the TCP analysis flags one
 * commit ago: the registry's scanner reads quoted literals out of the
 * dissection sources, so a name assembled at run time is a name it reports as
 * registered-with-no-writer - and a name `grep` cannot find either.
 */
const SHARED_ABBREV = {
  icmp: {
    type: 'icmp.type', code: 'icmp.code',
    checksum: 'icmp.checksum', checksumStatus: 'icmp.checksum.status',
  },
  icmpv6: {
    type: 'icmpv6.type', code: 'icmpv6.code',
    checksum: 'icmpv6.checksum', checksumStatus: 'icmpv6.checksum.status',
  },
} as const;

/** `2 (0x0002)` - the reference's own showname for a 16-bit identifier. */
function decimalAndHex(value: number): string {
  return `${value} (0x${value.toString(16).padStart(4, '0')})`;
}

function u16(b: Uint8Array, at: number): number {
  return (b[at] << 8) | b[at + 1];
}

function u32(b: Uint8Array, at: number): number {
  return ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
}

/** The same sixteen bits the other way round, which is what `*_le` means. */
function swap16(value: number): number {
  return ((value << 8) | (value >> 8)) & 0xffff;
}

/**
 * A checksum row and its verdict child, in the shape TCP and UDP already use.
 *
 * Returns nothing at all when the message is too short to hold one, rather
 * than a row reading `0x0000 [unverified]` over bytes that are not there.
 */
function checksumRows(
  rawBytes: Uint8Array, transportOffset: number, at: number,
  names: typeof SHARED_ABBREV['icmp'] | typeof SHARED_ABBREV['icmpv6'], ctx: IcmpContext,
): { rows: ProtocolField[]; stored: number; status: string } | null {
  if (at + 2 > rawBytes.length) return null;
  const stored = u16(rawBytes, at);
  const declaredEnd = transportOffset + (ctx.l4SegmentLen ?? rawBytes.length - transportOffset);
  const verdict = checksumVerdict(
    ctx.isIcmpv6 ? ctx.pseudoHeader : NO_PSEUDO_HEADER,
    rawBytes, transportOffset, declaredEnd, stored, ctx.sentByUs);
  return {
    stored,
    status: verdict.status,
    rows: [{
      name: 'Checksum',
      value: `0x${stored.toString(16).padStart(4, '0')} [${verdict.status === 'Good' ? 'correct' : verdict.status === 'Bad' ? 'incorrect' : 'unverified'}]`,
      rawBytesRange: [at, at + 1],
      abbrev: names.checksum,
      children: [{
        name: '[Checksum Status]',
        value: verdict.status,
        generated: true,
        abbrev: names.checksumStatus,
        ...(verdict.status === 'Bad' ? { expertInfo: { category: 'Broken' as const, message: 'Bad checksum' } } : {}),
      }],
    }],
  };
}

/**
 * One bit of a flags byte or word, drawn the way the reference draws it.
 *
 * `totalBits` is the width of the whole field the bit lives in - 8 for a
 * Router Advertisement's flags byte, 32 for a Neighbor Advertisement's flags
 * word - and it is stated by the caller rather than derived, for the reason
 * `ProtocolField.bitfield` gives: nothing in the renderer can know it.
 */
function flagBit(
  name: string, set: boolean, abbrev: string, at: number, bitOffset: number, totalBits: number,
): ProtocolField {
  return {
    name,
    value: set,
    abbrev,
    rawBytesRange: [at, at + totalBits / 8 - 1],
    bitfield: { bitOffset, bitLength: 1, totalBits },
  };
}

/**
 * Walks the Neighbor Discovery option list, building a subtree per option.
 *
 * RFC 4861 4.6: every option is a type byte, a length in **8-byte units**, and
 * the option body. A zero length would never advance, so it terminates - the
 * same rule `findNdpOption` and `collectNdpOptions` keep, and the same reason.
 *
 * The parent row's value is the reference's own parenthetical summary, so a
 * collapsed option still says what it is: an eight-byte option carrying a MAC
 * reads `ICMPv6 Option: (Source link-layer address : 44:15:24:aa:bb:cc)`
 * without being opened.
 */
function ndpOptionRows(rawBytes: Uint8Array, optionsStart: number, end: number): ProtocolField[] {
  const rows: ProtocolField[] = [];
  let at = optionsStart;
  while (at + 2 <= end && at + 2 <= rawBytes.length) {
    const type = rawBytes[at];
    const lengthUnits = rawBytes[at + 1];
    if (lengthUnits === 0) break;
    const optionEnd = at + lengthUnits * 8;
    if (optionEnd > end || optionEnd > rawBytes.length) break;

    const children: ProtocolField[] = [
      { name: 'Type', value: `${NDP_OPTION_NAMES[type] ?? 'Unknown'} (${type})`, abbrev: 'icmpv6.opt.type', rawBytesRange: [at, at] },
      { name: 'Length', value: `${lengthUnits} (${lengthUnits * 8} bytes)`, abbrev: 'icmpv6.opt.length', rawBytesRange: [at + 1, at + 1] },
    ];
    let summary = NDP_OPTION_NAMES[type] ?? `Unknown (${type})`;

    if ((type === 1 || type === 2) && at + 8 <= optionEnd) {
      const mac = formatMac(rawBytes.subarray(at + 2, at + 8));
      children.push({ name: 'Link-layer address', value: mac, abbrev: 'icmpv6.opt.linkaddr', rawBytesRange: [at + 2, at + 7] });
      // The reference publishes the same six bytes a second time under a name
      // that says WHICH address it is, and hides that row in the GUI. Both are
      // real filter names, so both are emitted; the directional one carries no
      // row of its own here for the same reason it carries none there.
      children.push({
        name: type === 1 ? 'Source Link-layer address' : 'Target Link-layer address',
        value: mac,
        abbrev: type === 1 ? 'icmpv6.opt.src_linkaddr' : 'icmpv6.opt.target_linkaddr',
        rawBytesRange: [at + 2, at + 7],
      });
      summary += ` : ${mac}`;
    } else if (type === 3 && at + 32 <= optionEnd) {
      const prefixLength = rawBytes[at + 2];
      const flags = rawBytes[at + 3];
      const prefix = formatIpv6Address(rawBytes, at + 16);
      children.push(
        { name: 'Prefix Length', value: prefixLength, abbrev: 'icmpv6.opt.prefix.length', rawBytesRange: [at + 2, at + 2] },
        {
          name: 'Flag',
          value: `0x${flags.toString(16).padStart(2, '0')}`,
          abbrev: 'icmpv6.opt.prefix.flag',
          rawBytesRange: [at + 3, at + 3],
          children: [
            flagBit('On-link Flag (L)', (flags & 0x80) !== 0, 'icmpv6.opt.prefix.flag.l', at + 3, 0, 8),
            flagBit('Autonomous Address Configuration Flag (A)', (flags & 0x40) !== 0, 'icmpv6.opt.prefix.flag.a', at + 3, 1, 8),
            flagBit('Router Address Flag (R)', (flags & 0x20) !== 0, 'icmpv6.opt.prefix.flag.r', at + 3, 2, 8),
            flagBit('DHCPv6-PD Preferred Flag (P)', (flags & 0x10) !== 0, 'icmpv6.opt.prefix.flag.p', at + 3, 3, 8),
            { name: 'Reserved', value: flags & 0x0f, abbrev: 'icmpv6.opt.prefix.flag.reserved', rawBytesRange: [at + 3, at + 3], bitfield: { bitOffset: 4, bitLength: 4, totalBits: 8 } },
          ],
        },
        { name: 'Valid Lifetime', value: u32(rawBytes, at + 4), abbrev: 'icmpv6.opt.prefix.valid_lifetime', rawBytesRange: [at + 4, at + 7] },
        { name: 'Preferred Lifetime', value: u32(rawBytes, at + 8), abbrev: 'icmpv6.opt.prefix.preferred_lifetime', rawBytesRange: [at + 8, at + 11] },
        { name: 'Reserved', value: '', abbrev: 'icmpv6.opt.reserved', rawBytesRange: [at + 12, at + 15] },
        // **This row's abbrev disagrees with the same key in the field bag,
        // and the disagreement is older than this module.** The reference
        // emits `icmpv6.opt.prefix` once per Prefix Information option, and a
        // filter matches if ANY occurrence does. The bag holds one value per
        // key, so `routerAdvertisementFields` puts the whole comma-joined list
        // of `prefix/length` there for the Network panel to read back. The
        // tree can hold repeated rows and therefore says what the reference
        // says; the bag cannot, and what needs changing to close that is the
        // filter engine's one-value-per-key model rather than either writer.
        { name: 'Prefix', value: prefix, abbrev: 'icmpv6.opt.prefix', rawBytesRange: [at + 16, at + 31] },
      );
      summary += ` : ${prefix}/${prefixLength}`;
    } else if (type === 5 && at + 8 <= optionEnd) {
      const mtu = u32(rawBytes, at + 4);
      children.push(
        { name: 'Reserved', value: '', abbrev: 'icmpv6.opt.reserved', rawBytesRange: [at + 2, at + 3] },
        { name: 'MTU', value: mtu, abbrev: 'icmpv6.opt.mtu', rawBytesRange: [at + 4, at + 7] },
      );
      summary += ` : ${mtu}`;
    } else if (type === 25 && at + 8 <= optionEnd) {
      children.push(
        { name: 'Reserved', value: '', abbrev: 'icmpv6.opt.reserved', rawBytesRange: [at + 2, at + 3] },
        { name: 'Lifetime', value: u32(rawBytes, at + 4), abbrev: 'icmpv6.opt.rdnss.lifetime', rawBytesRange: [at + 4, at + 7] },
      );
      const servers: string[] = [];
      for (let server = at + 8; server + 16 <= optionEnd; server += 16) {
        const address = formatIpv6Address(rawBytes, server);
        servers.push(address);
        // Same repeated-field shape as the prefix above: one row per server.
        children.push({ name: 'Recursive DNS Servers', value: address, abbrev: 'icmpv6.opt.rdnss', rawBytesRange: [server, server + 15] });
      }
      if (servers.length > 0) summary = `Recursive DNS Server ${servers.join(' ')}`;
    }

    rows.push({ name: 'ICMPv6 Option', value: `(${summary})`, abbrev: 'icmpv6.opt', rawBytesRange: [at, optionEnd - 1], children });
    at = optionEnd;
  }
  return rows;
}

/**
 * The Multicast Address Records of an MLDv2 report (RFC 3810 5.2).
 *
 * A fixed 4-byte record header - type, auxiliary data length, source count -
 * then the multicast address, then that many source addresses, then the
 * auxiliary data. The two lengths are what make the walk data-driven rather
 * than fixed-stride, and both are read before either is trusted to advance.
 */
function mldReportRows(rawBytes: Uint8Array, start: number, end: number): ProtocolField[] {
  const rows: ProtocolField[] = [];
  let at = start;
  while (at + 20 <= end && at + 20 <= rawBytes.length) {
    const recordType = rawBytes[at];
    const auxWords = rawBytes[at + 1];
    const sources = u16(rawBytes, at + 2);
    const recordEnd = at + 20 + sources * 16 + auxWords * 4;
    if (recordEnd > end || recordEnd > rawBytes.length) break;
    const group = formatIpv6Address(rawBytes, at + 4);

    const children: ProtocolField[] = [
      { name: 'Record Type', value: `${MLD_RECORD_TYPES[recordType] ?? 'Unknown'} (${recordType})`, abbrev: 'icmpv6.mldr.mar.record_type', rawBytesRange: [at, at] },
      { name: 'Aux Data Len', value: auxWords, abbrev: 'icmpv6.mldr.mar.aux_data_len', rawBytesRange: [at + 1, at + 1] },
      { name: 'Number of Sources', value: sources, abbrev: 'icmpv6.mldr.mar.nb_sources', rawBytesRange: [at + 2, at + 3] },
      { name: 'Multicast Address', value: group, abbrev: 'icmpv6.mldr.mar.multicast_address', rawBytesRange: [at + 4, at + 19] },
    ];
    for (let i = 0; i < sources; i++) {
      const source = at + 20 + i * 16;
      children.push({ name: 'Source Address', value: formatIpv6Address(rawBytes, source), abbrev: 'icmpv6.mldr.mar.source_address', rawBytesRange: [source, source + 15] });
    }

    rows.push({
      name: 'Multicast Address Record',
      value: `${MLD_RECORD_TYPES[recordType] ?? `Type ${recordType}`}: ${group}`,
      abbrev: 'icmpv6.mldr.mar',
      rawBytesRange: [at, recordEnd - 1],
      children,
    });
    at = recordEnd;
  }
  return rows;
}

/**
 * Reads an ICMP or ICMPv6 message.
 *
 * Returns null when there are not even four bytes of header, which is the one
 * case with nothing honest to say.
 */
export function dissectIcmp(
  rawBytes: Uint8Array, transportOffset: number, ctx: IcmpContext,
): TransportResult | null {
  if (rawBytes.length < transportOffset + 4) return null;

  const { isIcmpv6 } = ctx;
  const names = isIcmpv6 ? SHARED_ABBREV.icmpv6 : SHARED_ABBREV.icmp;
  const protocolLabel = isIcmpv6 ? 'ICMPv6' : 'ICMP';
  const icmpType = rawBytes[transportOffset];
  const icmpCode = rawBytes[transportOffset + 1];
  const isEchoRequest = isIcmpv6 ? icmpType === 128 : icmpType === 8;
  const isEchoReply = isIcmpv6 ? icmpType === 129 : icmpType === 0;
  const messageEnd = transportOffset + (ctx.l4SegmentLen ?? rawBytes.length - transportOffset);

  let icmpId: number | undefined;
  let icmpSeq: number | undefined;
  if ((isEchoRequest || isEchoReply) && rawBytes.length >= transportOffset + 8) {
    icmpId = u16(rawBytes, transportOffset + 4);
    icmpSeq = u16(rawBytes, transportOffset + 6);
  }

  let info: string;
  if (isIcmpv6) {
    switch (icmpType) {
      case 128: info = 'Echo (ping) request '; break;
      case 129: info = 'Echo (ping) reply   '; break;
      case 133: info = 'Router Solicitation'; break;
      case 134: info = describeRouterAdvertisement(rawBytes, transportOffset); break;
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
    const ttlPart = ctx.ttl !== undefined ? `, ttl=${ctx.ttl}` : '';
    info += ` id=0x${icmpId.toString(16).padStart(4, '0')}, seq=${icmpSeq}/${swap16(icmpSeq)}${ttlPart}`;
  }

  let icmpMatchedRequestFrameId: number | undefined;
  let responseTimeMs: number | undefined;
  if (ctx.icmpTracker && icmpId !== undefined && icmpSeq !== undefined && ctx.frameId !== undefined) {
    if (isEchoRequest) {
      ctx.icmpTracker.recordRequest(ctx.srcIp, ctx.dstIp, icmpId, icmpSeq, ctx.frameId, ctx.tsUs);
    } else if (isEchoReply) {
      const matched = ctx.icmpTracker.matchReply(ctx.srcIp, ctx.dstIp, icmpId, icmpSeq);
      if (matched) {
        icmpMatchedRequestFrameId = matched.frameId;
        info += ` (request in ${matched.frameId})`;
        if (matched.tsUs !== undefined && ctx.tsUs !== undefined) {
          responseTimeMs = (ctx.tsUs - matched.tsUs) / 1000;
        }
      }
    }
  }

  const fields: ProtocolField[] = [
    { name: 'Type', value: icmpType, abbrev: names.type, rawBytesRange: [transportOffset, transportOffset] },
    { name: 'Code', value: icmpCode, abbrev: names.code, rawBytesRange: [transportOffset + 1, transportOffset + 1] },
  ];
  const checksum = checksumRows(rawBytes, transportOffset, transportOffset + 2, names, ctx);
  if (checksum) fields.push(...checksum.rows);

  const bag: Record<string, string | number> = isIcmpv6
    ? { 'icmpv6.type': icmpType, 'icmpv6.code': icmpCode }
    : { 'icmp.type': icmpType, 'icmp.code': icmpCode };
  if (checksum) {
    // The verdict goes in as the WORD rather than the number the reference's
    // PDML carries, matching what `tcp.checksum.status` and
    // `udp.checksum.status` already hold - the colour rules and the expert
    // list read it, and neither of those speaks Wireshark's enum.
    if (isIcmpv6) {
      bag['icmpv6.checksum'] = checksum.stored;
      bag['icmpv6.checksum.status'] = checksum.status;
    } else {
      bag['icmp.checksum'] = checksum.stored;
      bag['icmp.checksum.status'] = checksum.status;
    }
  }

  if (icmpId !== undefined && icmpSeq !== undefined) {
    fields.push(
      { name: 'Identifier (BE)', value: decimalAndHex(icmpId), abbrev: isIcmpv6 ? 'icmpv6.echo.identifier' : 'icmp.ident', rawBytesRange: [transportOffset + 4, transportOffset + 5] },
      ...(isIcmpv6 ? [] : [{ name: 'Identifier (LE)', value: decimalAndHex(swap16(icmpId)), abbrev: 'icmp.ident_le', rawBytesRange: [transportOffset + 4, transportOffset + 5] as [number, number] }]),
      { name: 'Sequence Number (BE)', value: decimalAndHex(icmpSeq), abbrev: isIcmpv6 ? 'icmpv6.echo.sequence_number' : 'icmp.seq', rawBytesRange: [transportOffset + 6, transportOffset + 7] },
      ...(isIcmpv6 ? [] : [{ name: 'Sequence Number (LE)', value: decimalAndHex(swap16(icmpSeq)), abbrev: 'icmp.seq_le', rawBytesRange: [transportOffset + 6, transportOffset + 7] as [number, number] }]),
    );
    if (isIcmpv6) {
      bag['icmpv6.echo.identifier'] = icmpId;
      bag['icmpv6.echo.sequence_number'] = icmpSeq;
    } else {
      bag['icmp.ident'] = icmpId;
      bag['icmp.ident_le'] = swap16(icmpId);
      bag['icmp.seq'] = icmpSeq;
      bag['icmp.seq_le'] = swap16(icmpSeq);
    }
    if (icmpMatchedRequestFrameId !== undefined) {
      if (!isIcmpv6) bag['icmp.resp_to'] = icmpMatchedRequestFrameId;
      if (responseTimeMs !== undefined && !isIcmpv6) bag['icmp.resptime'] = responseTimeMs;
      // The echo request this reply answers. Generated - it describes another
      // frame, not bytes in this one - and clickable, so the pairing the
      // tracker already computes is navigable instead of only appearing as
      // text in the Info column.
      fields.push({
        name: '[Request frame]',
        value: icmpMatchedRequestFrameId,
        generated: true,
        abbrev: isIcmpv6 ? undefined : 'icmp.resp_to',
        linkToFrame: icmpMatchedRequestFrameId,
      });
      if (responseTimeMs !== undefined) {
        fields.push({
          name: '[Response time]',
          value: `${responseTimeMs.toFixed(3)} ms`,
          generated: true,
          abbrev: isIcmpv6 ? undefined : 'icmp.resptime',
        });
      }
    }
    // The payload after the 8-byte echo header. The reference names it and
    // then HIDES the row, showing the same bytes through its `data` dissector
    // instead - which is the one thing `tree-coverage.ts` exempts wholesale,
    // since "no dissection happened here" is a statement this build makes by
    // drawing nothing. The name is a real filter, so the row is drawn; it
    // costs nothing per frame because a tree is built on demand (ADR 0007).
    if (messageEnd > transportOffset + 8) {
      fields.push({
        name: 'ICMP Data',
        value: hexColons(rawBytes, transportOffset + 8, messageEnd),
        abbrev: isIcmpv6 ? 'icmpv6.data' : 'icmp.data',
        rawBytesRange: [transportOffset + 8, Math.min(messageEnd, rawBytes.length) - 1],
      });
    }
  }

  // **The datagram the error is about.** An ICMP error carries the original IP
  // header and the first eight bytes of what followed it, and until now this
  // build showed neither a subtree nor the bytes: the layer's own byte range
  // stopped at byte 7, so the quote sat outside the layer entirely. The
  // offsets are handed back rather than dissected here, because the array the
  // inner packet's layers belong in lives in `decodeNetworkLayer` - see
  // `decodeQuotedDatagram`, which is also where the three refusals that make
  // recursing safe are written down.
  const embeddedNetwork = QUOTES_A_DATAGRAM[isIcmpv6 ? 'icmpv6' : 'icmp'].has(icmpType)
    && transportOffset + 8 < Math.min(messageEnd, rawBytes.length)
    ? { offset: transportOffset + 8, etherType: isIcmpv6 ? 0x86dd : 0x0800, end: Math.min(messageEnd, rawBytes.length) }
    : undefined;
  if (embeddedNetwork) errorBodyRows(rawBytes, transportOffset, icmpType, icmpCode, isIcmpv6, fields, bag);

  if (isIcmpv6) {
    Object.assign(bag, icmpv6BodyRows(rawBytes, transportOffset, messageEnd, icmpType, fields));
    // Only for an RA. Every other ICMPv6 type would carry a bag of empty keys,
    // and a field a frame does not have is a field that correctly matches
    // nothing.
    if (icmpType === 134) Object.assign(bag, routerAdvertisementFields(rawBytes, transportOffset));
  }

  return {
    proto: 'ICMP',
    protocolLabel,
    fields: bag,
    info,
    icmpMatchedRequestFrameId,
    embeddedNetwork,
    // **The same bytes as the `ICMP Data` row above, as the layer the
    // reference actually shows.** That row's comment says the reference names
    // `icmp.data` and then hides it, drawing these bytes through its `data`
    // dissector instead - so the honest reading is that both exist, and this
    // build had the named row and not the layer. Only an echo: an error
    // message's trailing bytes are a quoted datagram, which `embeddedNetwork`
    // recurses into rather than calling undissected.
    ...((isEchoRequest || isEchoReply) && messageEnd > transportOffset + 8
      ? {
        extraLayers: [dataLayer(rawBytes.subarray(
          transportOffset + 8, Math.min(messageEnd, rawBytes.length),
        ))],
      }
      : {}),
    layer: {
      name: isIcmpv6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol',
      summary: `${isIcmpv6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol'}, ${info}`,
      // The whole message, which is what the reference highlights. It used to
      // stop at byte 7 - the echo header - so on an error message the quoted
      // datagram sat outside the layer entirely and on a Neighbor Discovery
      // message so did every option.
      rawBytesRange: [transportOffset, Math.min(messageEnd, rawBytes.length) - 1],
      fields,
    },
  };
}

/**
 * The four bytes between an error's code and the datagram it quotes.
 *
 * They are `Unused` on most error types and carry one useful number on three
 * of them, which is the whole reason this is a switch rather than one row: the
 * MTU that WOULD have fitted, the byte offset of the header field that was
 * wrong, or the gateway the sender should have used instead. Every one of them
 * is the actionable half of the message - an error saying "fragmentation
 * needed" without the MTU is a report with the answer left out.
 *
 * Neither fixture contains a single ICMP error frame, so none of this is
 * measurable by `tree-coverage.ts`; `scripts/icmp/dissect.ts` builds the
 * frames byte by byte and checks them against tshark, which is the same move
 * `scripts/parity/synthetic.ts` makes for protocols the captures do not hold.
 */
function errorBodyRows(
  rawBytes: Uint8Array, transportOffset: number, icmpType: number, icmpCode: number,
  isIcmpv6: boolean, fields: ProtocolField[], bag: Record<string, string | number>,
): void {
  const body = transportOffset + 4;
  if (body + 4 > rawBytes.length) return;

  if (isIcmpv6) {
    // Packet Too Big's MTU is read by `icmpv6BodyRows`, which owns type 2.
    if (icmpType === 4) {
      const pointer = u32(rawBytes, body);
      fields.push({ name: 'Pointer', value: pointer, abbrev: 'icmpv6.pointer', rawBytesRange: [body, body + 3] });
      bag['icmpv6.pointer'] = pointer;
    } else if (icmpType !== 2) {
      fields.push({ name: 'Reserved', value: hexColons(rawBytes, body, body + 4), abbrev: 'icmpv6.reserved', rawBytesRange: [body, body + 3] });
    }
    return;
  }

  if (icmpType === 3 && icmpCode === 4) {
    // Fragmentation needed. The first two bytes are unused and the next two
    // are the MTU of the hop that could not forward it - the one number that
    // makes a black-hole MTU problem diagnosable rather than merely visible.
    const mtu = u16(rawBytes, body + 2);
    fields.push({ name: 'MTU of next hop', value: mtu, abbrev: 'icmp.mtu', rawBytesRange: [body + 2, body + 3] });
    bag['icmp.mtu'] = mtu;
  } else if (icmpType === 12) {
    const pointer = rawBytes[body];
    fields.push({ name: 'Pointer', value: pointer, abbrev: 'icmp.pointer', rawBytesRange: [body, body] });
    bag['icmp.pointer'] = pointer;
  } else if (icmpType === 5) {
    const gateway = `${rawBytes[body]}.${rawBytes[body + 1]}.${rawBytes[body + 2]}.${rawBytes[body + 3]}`;
    fields.push({ name: 'Gateway Address', value: gateway, abbrev: 'icmp.redir_gw', rawBytesRange: [body, body + 3] });
    bag['icmp.redir_gw'] = gateway;
  } else {
    fields.push({ name: 'Unused', value: hexColons(rawBytes, body, body + 4), abbrev: 'icmp.unused', rawBytesRange: [body, body + 3] });
  }
}

/**
 * The per-type body of an ICMPv6 message, appended to `fields`.
 *
 * Returns whatever belongs in the flat field bag; the tree rows go straight
 * into the array it was handed, because every branch adds a different number
 * of them and returning a list to be concatenated would say less.
 */
function icmpv6BodyRows(
  rawBytes: Uint8Array, transportOffset: number, messageEnd: number, icmpType: number, fields: ProtocolField[],
): Record<string, string | number> {
  const bag: Record<string, string | number> = {};
  const body = transportOffset + 4;

  const reserved = (at: number, length: number): void => {
    if (at + length > rawBytes.length) return;
    fields.push({ name: 'Reserved', value: hexColons(rawBytes, at, at + length), abbrev: 'icmpv6.reserved', rawBytesRange: [at, at + length - 1] });
  };
  const targetAddress = (at: number, abbrev: string, name = 'Target Address'): string | null => {
    if (at + 16 > rawBytes.length) return null;
    const address = formatIpv6Address(rawBytes, at);
    fields.push({ name, value: address, abbrev, rawBytesRange: [at, at + 15] });
    bag[abbrev] = address;
    return address;
  };

  switch (icmpType) {
    case 133: // Router Solicitation: four reserved bytes, then options.
      reserved(body, 4);
      fields.push(...ndpOptionRows(rawBytes, body + 4, messageEnd));
      break;

    case 134: { // Router Advertisement.
      if (body + 12 > rawBytes.length) break;
      const flags = rawBytes[body + 1];
      fields.push(
        { name: 'Cur hop limit', value: rawBytes[body], abbrev: 'icmpv6.nd.ra.cur_hop_limit', rawBytesRange: [body, body] },
        {
          name: 'Flags',
          value: `0x${flags.toString(16).padStart(2, '0')}`,
          abbrev: 'icmpv6.nd.ra.flag',
          rawBytesRange: [body + 1, body + 1],
          children: [
            flagBit('Managed address configuration', (flags & 0x80) !== 0, 'icmpv6.nd.ra.flag.m', body + 1, 0, 8),
            flagBit('Other configuration', (flags & 0x40) !== 0, 'icmpv6.nd.ra.flag.o', body + 1, 1, 8),
            flagBit('Home Agent', (flags & 0x20) !== 0, 'icmpv6.nd.ra.flag.h', body + 1, 2, 8),
            { name: 'Prf (Default Router Preference)', value: `${ROUTER_PREFERENCE[(flags >> 3) & 0x03] ?? 'Reserved'} (${(flags >> 3) & 0x03})`, abbrev: 'icmpv6.nd.ra.flag.prf', rawBytesRange: [body + 1, body + 1], bitfield: { bitOffset: 3, bitLength: 2, totalBits: 8 } },
            flagBit('ND Proxy', (flags & 0x04) !== 0, 'icmpv6.nd.ra.flag.p', body + 1, 5, 8),
            flagBit('SNAC Router', (flags & 0x02) !== 0, 'icmpv6.nd.ra.flag.s', body + 1, 6, 8),
            { name: 'Reserved', value: flags & 0x01, abbrev: 'icmpv6.nd.ra.flag.rsv', rawBytesRange: [body + 1, body + 1], bitfield: { bitOffset: 7, bitLength: 1, totalBits: 8 } },
          ],
        },
        { name: 'Router lifetime (s)', value: u16(rawBytes, body + 2), abbrev: 'icmpv6.nd.ra.router_lifetime', rawBytesRange: [body + 2, body + 3] },
        { name: 'Reachable time (ms)', value: u32(rawBytes, body + 4), abbrev: 'icmpv6.nd.ra.reachable_time', rawBytesRange: [body + 4, body + 7] },
        { name: 'Retrans timer (ms)', value: u32(rawBytes, body + 8), abbrev: 'icmpv6.nd.ra.retrans_timer', rawBytesRange: [body + 8, body + 11] },
      );
      bag['icmpv6.nd.ra.reachable_time'] = u32(rawBytes, body + 4);
      bag['icmpv6.nd.ra.retrans_timer'] = u32(rawBytes, body + 8);
      fields.push(...ndpOptionRows(rawBytes, body + 12, messageEnd));
      break;
    }

    case 135: // Neighbor Solicitation: reserved, target, options.
      reserved(body, 4);
      targetAddress(body + 4, 'icmpv6.nd.ns.target_address');
      fields.push(...ndpOptionRows(rawBytes, body + 20, messageEnd));
      break;

    case 136: { // Neighbor Advertisement: a 32-bit flags word, target, options.
      if (body + 4 > rawBytes.length) break;
      const word = u32(rawBytes, body);
      fields.push({
        name: 'Flags',
        value: `0x${word.toString(16).padStart(8, '0')}`,
        abbrev: 'icmpv6.nd.na.flag',
        rawBytesRange: [body, body + 3],
        children: [
          flagBit('Router', (word & 0x80000000) !== 0, 'icmpv6.nd.na.flag.r', body, 0, 32),
          flagBit('Solicited', (word & 0x40000000) !== 0, 'icmpv6.nd.na.flag.s', body, 1, 32),
          flagBit('Override', (word & 0x20000000) !== 0, 'icmpv6.nd.na.flag.o', body, 2, 32),
          { name: 'Reserved', value: word & 0x1fffffff, abbrev: 'icmpv6.nd.na.flag.rsv', rawBytesRange: [body, body + 3], bitfield: { bitOffset: 3, bitLength: 29, totalBits: 32 } },
        ],
      });
      targetAddress(body + 4, 'icmpv6.nd.na.target_address');
      fields.push(...ndpOptionRows(rawBytes, body + 20, messageEnd));
      break;
    }

    case 137: // Redirect: reserved, the target, the destination, options.
      reserved(body, 4);
      targetAddress(body + 4, 'icmpv6.nd.rd.target_address');
      // The destination the redirect is FOR, drawn with no abbrev because the
      // reference registers no name for it - `-G fields` has
      // `icmpv6.nd.rd.target_address` and nothing beside it. A row with no
      // abbrev is display only, which is the honest state: inventing a name
      // here would be a filter that works in this build and nowhere else,
      // which is the exact failure `wireshark-abbrevs.ts` exists to catch.
      if (body + 36 <= rawBytes.length) {
        fields.push({ name: 'Destination Address', value: formatIpv6Address(rawBytes, body + 20), rawBytesRange: [body + 20, body + 35] });
      }
      fields.push(...ndpOptionRows(rawBytes, body + 36, messageEnd));
      break;

    case 2: // Packet Too Big carries the MTU that would have fitted.
      if (body + 4 <= rawBytes.length) {
        const mtu = u32(rawBytes, body);
        fields.push({ name: 'MTU', value: mtu, abbrev: 'icmpv6.mtu', rawBytesRange: [body, body + 3] });
        bag['icmpv6.mtu'] = mtu;
      }
      break;

    case 143: // Multicast Listener Report v2.
      if (body + 4 > rawBytes.length) break;
      reserved(body, 2);
      fields.push({ name: 'Number of Multicast Address Records', value: u16(rawBytes, body + 2), abbrev: 'icmpv6.mldr.nb_mcast_records', rawBytesRange: [body + 2, body + 3] });
      fields.push(...mldReportRows(rawBytes, body + 4, messageEnd));
      break;
  }

  return bag;
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
    'icmpv6.nd.ra.router_lifetime': u16(rawBytes, body + 2),
  };

  const prefixes: string[] = [];
  for (const option of collectNdpOptions(rawBytes, body + 12, 3)) {
    if (option.length < 30) continue;
    prefixes.push(`${formatIpv6Address(option, 14)}/${option[0]}`);
    if (prefixes.length === 1) {
      out['icmpv6.opt.prefix.valid_lifetime'] = u32(option, 2);
      out['icmpv6.opt.prefix.preferred_lifetime'] = u32(option, 6);
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
 * "Router Advertisement from 44:15:24:aa:bb:cc"
 *
 * The router names itself with the same option a Neighbor Solicitation uses -
 * type 1, the sender's link-layer address - which is the one fact that
 * distinguishes two routers advertising on the same link. Without it every
 * advertisement in a capture reads identically, which is exactly the case
 * somebody opens a capture to tell apart.
 *
 * Layout after the 4-byte ICMPv6 header: hop limit, flags, router lifetime,
 * reachable time and retrans timer - 12 bytes - and then the options. The
 * option is optional, and an advertisement without one is named without it.
 */
function describeRouterAdvertisement(rawBytes: Uint8Array, transportOffset: number): string {
  const optionsOffset = transportOffset + 16;
  if (optionsOffset > rawBytes.length) return 'Router Advertisement';
  const sourceLinkAddr = findNdpOption(rawBytes, optionsOffset, 1);
  return sourceLinkAddr && sourceLinkAddr.length >= 6
    ? `Router Advertisement from ${formatMac(sourceLinkAddr.subarray(0, 6))}`
    : 'Router Advertisement';
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
 * The message types that quote the datagram that provoked them.
 *
 * RFC 792 and RFC 4443 both say the same thing in their own numbers: an error
 * report carries back the header of the packet it is about, so the host that
 * sent it can tell WHICH of its conversations the router is complaining about.
 * Nothing else in either protocol does - an echo carries a payload, a Neighbor
 * Solicitation carries options, and neither is a packet.
 */
const QUOTES_A_DATAGRAM: Record<'icmp' | 'icmpv6', Set<number>> = {
  // Destination unreachable, source quench, redirect, time exceeded,
  // parameter problem.
  icmp: new Set([3, 4, 5, 11, 12]),
  // Destination unreachable, packet too big, time exceeded, parameter problem.
  icmpv6: new Set([1, 2, 3, 4]),
};

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

/** The Neighbor Discovery options worth naming, by their IANA type. */
const NDP_OPTION_NAMES: Record<number, string> = {
  1: 'Source link-layer address', 2: 'Target link-layer address', 3: 'Prefix information',
  4: 'Redirected header', 5: 'MTU', 24: 'Route Information', 25: 'Recursive DNS Server',
  31: 'DNS Search List', 37: 'Captive-Portal', 38: 'PREF64',
};

/** RFC 4191's two-bit Default Router Preference. */
const ROUTER_PREFERENCE: Record<number, string> = {
  0: 'Medium', 1: 'High', 2: 'Reserved', 3: 'Low',
};

/** RFC 3810 5.2.12's record types. */
const MLD_RECORD_TYPES: Record<number, string> = {
  1: 'Mode is include', 2: 'Mode is exclude', 3: 'Changed to include',
  4: 'Changed to exclude', 5: 'Allow new sources', 6: 'Block old sources',
};
