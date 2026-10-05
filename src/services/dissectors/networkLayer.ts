/**
 * The network layer, and the transport dispatch under it.
 *
 * This is the half of `decodeRawEthernetPacket` a **tunnel** has to be able to
 * re-enter. GRE, VXLAN, L2TP and GTP all dissect *through* themselves into an
 * inner packet, and the reference analyzer reports that inner packet's
 * addresses rather than the outer ones - which means the IPv4/IPv6 walk has to
 * be a function somebody can call again with a different offset. It was 533
 * lines in the middle of an 878-line function, and it was not.
 *
 * **Nothing about the decode changed in the move.** The branch below is the
 * same 533 lines it was, character for character; what changed is only how the
 * state around it is carried. Sixteen of the caller's locals are decided in
 * here, so they are destructured in at the top and returned at the bottom -
 * which is what let the body move without a single edit inside it. `layers` and
 * `filterFields` are containers the branch appends to, so they are passed by
 * reference and need no such treatment.
 *
 * The ten helpers at the end came with it because nothing else uses them, and
 * `decodeTransportLayer` came because this is its only caller - leaving it
 * behind would have made the two modules import each other.
 */
import type { Packet, ProtocolField, ProtocolLayer } from '../../types/packet';
import type { TransportResult } from '../dissect/types';
import type {
  TcpTrackerApi, IcmpTrackerApi, QuicTrackerApi, DnsTrackerApi, L3TrackerApi,
} from '../dissect/trackerApi';
import type { InfoPatch } from '../dissect/types';
import { formatIpv6Address } from '../addressFormat';
import { ETHERNET_MAX_FRAME } from '../direction';
import { dissectIpv4Options, dscpName, ecnName, inferTtl } from './ipv4';
import { NO_NEXT_HEADER, walkIpv6Extensions } from './ipv6Ext';
import { describeIpProtocol } from '../dissect/ipProtocolNames';
import { dissectPortless, isPortlessProtocol } from './portless';
import { GRE_PROTOCOL, encapsulatedInfo, innerNetworkStart, readGreHeader } from './gre';
import {
  VXLAN_HEADER_LENGTH, isVxlanPort, readInnerEthernet, readVxlanHeader,
} from './vxlan';
import { dissectArp } from './l2';
import { resolveMacName } from '../macVendors';
import { dissectTcpTransport } from './tcpTransport';
import { dissectUdpTransport } from './udpTransport';
import { dissectIcmp } from './icmp';
import { ipv6AddressDetail, ipv6EmbeddedRows } from './ipv6Address';

/**
 * The caller state the network layer decides.
 *
 * Passed in with the values the frame had before this ran and handed back with
 * whatever the decode settled, rather than mutated through a reference: a
 * sixteen-field object written through `state.srcIp = ...` would have meant
 * editing all 533 lines, and an edit is where a mistake hides.
 */
export interface NetworkDecode {
  srcIp: string;
  dstIp: string;
  proto: Packet['protocol'];
  protocolLabel?: string;
  info: string;
  status: Packet['status'];
  analysisFlags?: string[];
  srcPort?: number;
  dstPort?: number;
  streamId?: number;
  icmpMatchedRequestFrameId?: number;
  infoPatches?: InfoPatch[];
  resolvedNames?: { name: string; addresses: string[] }[];
  /** Where in `layers` the transport layer went, so tokens can be spliced in. */
  transportLayerIndex: number;
  /** frameProtocols tokens for IPv6 extension headers, which have no layer name. */
  extensionTokens: string[];
  /** Tokens for a dissector that claims the payload without adding a layer. */
  transportTokens: string[];
}

/** Everything the decode needs that is neither the bytes nor the state above. */
/**
 * Every name the reference hangs under an address row: `addr`, `*_host` and
 * `host`.
 *
 * All four families spelled out as literals rather than composed from
 * `${family}.${side}_host`, which is the rule this branch learnt twice: the
 * registry's scanner reads quoted dotted literals out of the dissection
 * sources, so a name assembled at run time is invisible to it - and to grep.
 * A composed field name is a field name nothing is holding to anything.
 *
 * The reference marks all of these `hide="yes"`: they exist to be typed into
 * a filter bar, not to be read in a detail pane. That is why they were the
 * largest gap left on either fixture and nobody had noticed - 4,226 frames of
 * `ip.*_host` and 8,400 of `ipv6.*_host`, none of them visible in the
 * reference's own tree either.
 */
const HOST_ALIASES = {
  ip: {
    Source: { addr: 'ip.addr', own: 'ip.src_host', shared: 'ip.host' },
    Destination: { addr: 'ip.addr', own: 'ip.dst_host', shared: 'ip.host' },
  },
  ipv6: {
    Source: { addr: 'ipv6.addr', own: 'ipv6.src_host', shared: 'ipv6.host' },
    Destination: { addr: 'ipv6.addr', own: 'ipv6.dst_host', shared: 'ipv6.host' },
  },
} as const;

function hostAliasRows(
  family: 'ip' | 'ipv6', address: string, at: [number, number],
  side: 'Source' | 'Destination',
): ProtocolField[] {
  const names = HOST_ALIASES[family][side];
  return [
    { name: 'Source or Destination Address', value: address, abbrev: names.addr, rawBytesRange: at },
    { name: `${side} Host`, value: address, abbrev: names.own, rawBytesRange: at },
    { name: 'Source or Destination Host', value: address, abbrev: names.shared, rawBytesRange: at },
  ];
}

/**
 * Under an IPv6 address: what kind of address it is (`ipv6Address.ts`), then
 * the either-end names, with the same detail again beneath `ipv6.addr` - which
 * is where the reference hangs its `ipv6.addr_*` twins.
 */
function ipv6AddressChildren(
  rawBytes: Uint8Array, at: number, address: string, side: 'Source' | 'Destination',
): ProtocolField[] {
  return [
    ...ipv6AddressDetail(rawBytes, at, side),
    ...hostAliasRows('ipv6', address, [at, at + 15], side).map((row) => (row.abbrev === 'ipv6.addr'
      ? { ...row, children: ipv6AddressDetail(rawBytes, at, 'Either') }
      : row)),
  ];
}

/**
 * The `[Stream index]` row under an IP layer.
 *
 * Nothing happens on a quoted datagram: `context.quoted` means these bytes are
 * a router's description of a packet somebody else sent, and giving it a
 * conversation index would both invent a conversation and shift every real
 * one's number by one.
 */
function ipStreamRow(
  context: NetworkContext, family: 'ip' | 'ipv6', src: string, dst: string,
  filterFields: Record<string, string | number>,
): ProtocolField[] {
  if (context.quoted || context.l3Tracker === undefined) return [];
  const facts = family === 'ip'
    ? context.l3Tracker.ipStream(src, dst, context.tsUs)
    : context.l3Tracker.ipv6Stream(src, dst, context.tsUs);
  filterFields[`${family}.stream`] = facts.index;
  return [{ name: '[Stream index]', value: facts.index, generated: true, abbrev: `${family}.stream` }];
}

/**
 * UDP's conversation index and its two clocks, and nothing for any other
 * transport.
 *
 * The two timestamp rows were frame-relative for every protocol, under labels
 * the reference uses for **stream**-relative numbers. TCP has had the real
 * thing since it gained `tcp.time_relative` and `tcp.time_delta`, computed
 * from per-connection clocks in `tcpStreamTracker.ts`; UDP had the labels and
 * not the numbers. It has both now, from the same conversation record that
 * answers `udp.stream`.
 *
 * **Every other transport used to keep the frame-relative pair**, and that was
 * a second clock where the reference draws none: ICMP has no `[Timestamps]`
 * at all, and on TCP it sat beside the stream-relative pair with the same
 * labels and different numbers. The frame's own times are the Frame layer's.
 */
function udpConversationRows(
  context: NetworkContext, ipProtocolNum: number, src: string, dst: string,
  transport: { layer: ProtocolLayer; srcPort?: number; dstPort?: number },
  filterFields: Record<string, string | number>,
): ProtocolField[] {
  const facts = !context.quoted
    && ipProtocolNum === 17
    && context.l3Tracker !== undefined
    && transport.srcPort !== undefined
    && transport.dstPort !== undefined
    ? context.l3Tracker.udpStream(src, transport.srcPort, dst, transport.dstPort, context.tsUs)
    : undefined;
  if (facts === undefined) return [];

  filterFields['udp.stream'] = facts.index;
  return [
    { name: '[Stream index]', value: facts.index, generated: true, abbrev: 'udp.stream' },
    { name: '[Stream Packet Number]', value: facts.pnum, generated: true, abbrev: 'udp.stream.pnum' },
    {
      name: '[Timestamps]',
      value: '',
      generated: true,
      children: [
        {
          name: '[Time since first frame]', value: `${facts.sinceFirst.toFixed(9)} seconds`,
          generated: true, abbrev: 'udp.time_relative',
        },
        {
          name: '[Time since previous frame]', value: `${facts.sincePrev.toFixed(9)} seconds`,
          generated: true, abbrev: 'udp.time_delta',
        },
      ],
    },
  ];
}

export interface NetworkContext {
  id: number;
  tsUs: number;
  relativeTime: number;
  timeDelta: number;
  origLen: number;
  tcpTracker?: TcpTrackerApi;
  icmpTracker?: IcmpTrackerApi;
  quicTracker?: QuicTrackerApi;
  dnsTracker?: DnsTrackerApi;
  l3Tracker?: L3TrackerApi;
  /** This machine sent the frame, so its checksums may not be filled in yet. */
  sentByUs: boolean | undefined;
  /**
   * This decode IS the datagram an ICMP error quoted, rather than the frame.
   *
   * Two things follow, and both are refusals. Nothing may reach a tracker: a
   * quoted TCP header is eight bytes of a segment that was sent once and is
   * being described by somebody else, so feeding it to `TcpStreamTracker`
   * would invent a retransmission, a stream and an RTT sample out of a
   * router's complaint. And nothing may recurse again - an error quoting an
   * error is legal and terminates on its own, but a bound that cannot be
   * reasoned about is not one worth having.
   */
  quoted?: boolean;
}

/**
 * Reads the IPv4 or IPv6 header at `l3Offset` and everything under it.
 *
 * `layers` is appended to and `filterFields` written through; everything else
 * travels in and out through `state`.
 */
export function decodeNetworkLayer(
  rawBytes: Uint8Array,
  l3Offset: number,
  currentEtherType: number,
  layers: ProtocolLayer[],
  filterFields: Record<string, string | number>,
  state: NetworkDecode,
  context: NetworkContext,
): NetworkDecode {
  let {
    srcIp, dstIp, proto, protocolLabel, info, status, analysisFlags, srcPort, dstPort,
    streamId, icmpMatchedRequestFrameId, infoPatches, resolvedNames, transportLayerIndex,
    extensionTokens, transportTokens,
  } = state;
  const {
    id, tsUs, relativeTime, timeDelta, origLen, tcpTracker, icmpTracker, quicTracker,
    dnsTracker, l3Tracker, sentByUs,
  } = context;
  // What the capture did not keep of this frame: a snaplen. The transport
  // then reads its lengths from its headers rather than from what was kept
  // (`dissectTcpTransport`'s `payloadLength`).
  const captureShort = Math.max(0, origLen - rawBytes.length);


  /**
   * A tunnel, looked *through* rather than named.
   *
   * The reference reports the inner packet in every column - Protocol, Info,
   * Source and Destination - so this recurses and hands back whatever the
   * inner packet decided. `layers` and `filterFields` are shared, so the outer
   * IP header and the GRE header stay in the tree above the inner one, which
   * is where they belong.
   *
   * When there is nothing readable inside, the frame reads as `GRE` with the
   * reference's own `Encapsulated ...` wording - the one case the word appears.
   */
  const decodeGreTunnel = (payloadStart: number, payloadEnd: number): NetworkDecode | null => {
    const header = readGreHeader(rawBytes, payloadStart, payloadEnd);
    if (header === null) return null;
    layers.push(header.layer);
    Object.assign(filterFields, header.fields);
    const carried: NetworkDecode = {
      srcIp, dstIp, proto, protocolLabel, info, status, analysisFlags, srcPort, dstPort,
      streamId, icmpMatchedRequestFrameId, infoPatches, resolvedNames, transportLayerIndex,
      extensionTokens, transportTokens: [...transportTokens, 'gre'],
    };
    const inner = innerNetworkStart(
      rawBytes, payloadStart + header.headerLength, header.protocolType, payloadEnd);
    if (inner === null) {
      return { ...carried, proto: 'GRE', protocolLabel: 'GRE', info: encapsulatedInfo(header.protocolType) };
    }
    return decodeNetworkLayer(
      rawBytes, inner.offset, inner.etherType, layers, filterFields, carried, context);
  };

  /**
   * The datagram an ICMP error quotes back, dissected in place.
   *
   * **It looks like the two tunnels below and is the opposite of them.** GRE
   * and VXLAN look THROUGH themselves: the reference reports the inner
   * packet in every column, so those two hand back whatever the inner decode
   * decided. An ICMP error is about a packet rather than carrying one - the
   * Source, Destination, Protocol and Info all belong to the router that sent
   * the complaint - so this returns nothing at all and the outer frame's
   * state is untouched. What it shares with them is the one thing worth
   * sharing: `layers` is the same array, so the quoted IP header and whatever
   * sits under it appear in the tree beneath the ICMP layer, which is where
   * the reference puts them.
   *
   * Three refusals make that safe, and each is a bug that would otherwise be
   * silent:
   *
   * - **The bytes are truncated to what was actually quoted.** An error
   *   carries the original IP header plus eight bytes, and that header's own
   *   Total Length describes the WHOLE original datagram - so every
   *   `rawBytes.length` guard downstream would be answering about a buffer
   *   that keeps going. A `subarray` preserves indices, so every byte range
   *   the inner decode produces still points at the right place in this
   *   frame's hex dump, and every length check bounds at the quote.
   * - **No tracker travels with it.** A quoted TCP header would otherwise
   *   open a stream, claim a sequence base and be counted as a segment.
   * - **The field bag is thrown away.** The inner `ip.src` is not this
   *   frame's source, and one key holds one value.
   */
  const decodeQuotedDatagram = (embedded: { offset: number; etherType: number; end: number }): void => {
    if (context.quoted) return;
    const quotedBytes = rawBytes.subarray(0, Math.min(embedded.end, rawBytes.length));
    if (embedded.offset >= quotedBytes.length) return;
    decodeNetworkLayer(
      quotedBytes, embedded.offset, embedded.etherType, layers, {},
      {
        // Placeholders. Every one of these is thrown away with the object -
        // what the call is FOR is the rows it appends to `layers`.
        srcIp: '', dstIp: '', proto: 'TCP', info: '', status: 'ok',
        transportLayerIndex: -1, extensionTokens: [], transportTokens: [],
      },
      {
        id, tsUs, relativeTime, timeDelta, origLen,
        sentByUs: undefined, quoted: true,
      });
  };

  /**
   * VXLAN, which differs from GRE in where the recursion lands.
   *
   * GRE's payload is a network packet, so `innerNetworkStart` hands an offset
   * and an ethertype straight to `decodeNetworkLayer`. VXLAN's payload is a
   * whole Ethernet FRAME, so its own header has to be read first and then the
   * ethertype dispatched - and that dispatch lives in `decodeRawEthernetPacket`
   * rather than here, because until now no tunnel needed it. Rather than lift
   * the whole chain out for one caller, the two cases that occur inside an
   * overlay are handled: IP recurses exactly as GRE does, and ARP goes to the
   * same `dissectArp` the outer frame would use.
   *
   * ARP is the case that makes this a layer-2 tunnel rather than a layer-3 one.
   * It carries no addresses this column can show, so the reference reports the
   * inner MACs - and `pcapParser` has already filled those columns with the
   * OUTER pair, which is why they are overwritten here and nowhere else.
   */
  const decodeVxlanTunnel = (payloadStart: number, payloadEnd: number): NetworkDecode | null => {
    const header = readVxlanHeader(rawBytes, payloadStart, payloadEnd);
    if (header === null) return null;
    const inner = readInnerEthernet(rawBytes, payloadStart + VXLAN_HEADER_LENGTH, payloadEnd);
    if (inner === null) return null;
    layers.push(header.layer);
    layers.push(inner.layer);
    Object.assign(filterFields, header.fields);
    const carried: NetworkDecode = {
      srcIp, dstIp, proto, protocolLabel, info, status, analysisFlags, srcPort, dstPort,
      streamId, icmpMatchedRequestFrameId, infoPatches, resolvedNames, transportLayerIndex,
      extensionTokens, transportTokens: [...transportTokens, 'vxlan', 'eth'],
    };

    if (inner.etherType === 0x0800 || inner.etherType === 0x86dd) {
      return decodeNetworkLayer(
        rawBytes, inner.l3Offset, inner.etherType, layers, filterFields, carried, context);
    }

    if (inner.etherType === 0x0806) {
      const arp = dissectArp(rawBytes, inner.l3Offset);
      if (arp === null) return null;
      layers.push(arp.layer);
      Object.assign(filterFields, arp.fields);
      return {
        ...carried,
        // The inner pair, resolved the way the outer pair is - which is what
        // turns ff:ff:ff:ff:ff:ff into `Broadcast`.
        srcIp: resolveMacName(inner.srcMac),
        dstIp: resolveMacName(inner.dstMac),
        proto: 'ARP',
        protocolLabel: arp.protocolLabel,
        info: arp.info,
        transportTokens: [...carried.transportTokens, 'arp'],
      };
    }

    // Anything else inside an overlay is not something this build reads, and
    // the tunnel is what it can honestly report.
    return {
      ...carried,
      protocolLabel: 'VxLAN',
      info: `Virtual eXtensible Local Area Network, VNI: ${header.vni}`,
    };
  };

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
    // The same shape as `checksumVerdict`: a header that verifies is Good
    // whoever sent it, and only a FAILING one needs the direction - an unknown
    // direction costs the accusation rather than the whole verdict.
    const ipChecksumStatus =
      headerChecksumActual === 0 || origLen > ETHERNET_MAX_FRAME || sentByUs === true ? 'Unverified'
        : checksumCorrect ? 'Good'
          : sentByUs === undefined ? 'Unverified'
            : 'Bad';
    const ttlGuess = inferTtl(ttl);
    srcIp = `${rawBytes[l3Offset + 12]}.${rawBytes[l3Offset + 13]}.${rawBytes[l3Offset + 14]}.${rawBytes[l3Offset + 15]}`;
    dstIp = `${rawBytes[l3Offset + 16]}.${rawBytes[l3Offset + 17]}.${rawBytes[l3Offset + 18]}.${rawBytes[l3Offset + 19]}`;

    const ipLayer: ProtocolLayer = {
      name: 'Internet Protocol Version 4',
      summary: `Internet Protocol Version 4, Src: ${srcIp}, Dst: ${dstIp}`,
      rawBytesRange: [l3Offset, l3Offset + ipHeaderLen - 1],
      fields: [
        { name: 'Version', value: '4', abbrev: 'ip.version', rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Header Length', value: `${ipHeaderLen} bytes`, abbrev: 'ip.hdr_len', rawBytesRange: [l3Offset, l3Offset] },
        {
          // Named, not numbered. IPv6 has shown "EF PHB" and "ECT(0)" since
          // this phase's first half; IPv4 printed 46 and 2, so the same
          // traffic read differently depending on which version carried it.
          name: 'Differentiated Services Field',
          value: `0x${tos.toString(16).padStart(2, '0')} (DSCP: ${dscpName(dscp)}, ECN: ${ecnName(ecn)})`,
          abbrev: 'ip.dsfield',
          rawBytesRange: [l3Offset + 1, l3Offset + 1],
          children: [
            { name: 'Differentiated Services Codepoint', value: `${dscpName(dscp)} (${dscp})`, abbrev: 'ip.dsfield.dscp', rawBytesRange: [l3Offset + 1, l3Offset + 1] },
            { name: 'Explicit Congestion Notification', value: `${ecnName(ecn)} (${ecn})`, abbrev: 'ip.dsfield.ecn', rawBytesRange: [l3Offset + 1, l3Offset + 1] },
          ],
        },
        { name: 'Total Length', value: ipTotalLen, abbrev: 'ip.len', rawBytesRange: [l3Offset + 2, l3Offset + 3] },
        { name: 'Identification', value: `0x${identification.toString(16).padStart(4, '0')} (${identification})`, abbrev: 'ip.id', rawBytesRange: [l3Offset + 4, l3Offset + 5] },
        {
          name: 'Flags',
          value: `0x${((flagsAndFragOffset >> 13) & 0x7).toString(16).padStart(2, '0')}`,
          abbrev: 'ip.flags',
          rawBytesRange: [l3Offset + 6, l3Offset + 6],
          children: [
            { name: 'Reserved bit', value: ipReservedBit === 1 ? 'Set' : 'Not set', abbrev: 'ip.flags.rb', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
            { name: "Don't fragment", value: dontFragment === 1 ? 'Set' : 'Not set', abbrev: 'ip.flags.df', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
            { name: 'More fragments', value: moreFragments === 1 ? 'Set' : 'Not set', abbrev: 'ip.flags.mf', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
          ],
        },
        { name: 'Fragment Offset', value: fragmentOffset, abbrev: 'ip.frag_offset', rawBytesRange: [l3Offset + 6, l3Offset + 7] },
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
        { name: 'Protocol', value: describeIpProtocol(ipProtocolNum), abbrev: 'ip.proto', rawBytesRange: [l3Offset + 9, l3Offset + 9] },
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
        // **`_host` beside `addr`, and it is not the same row twice.** Both
        // hold this address, but they answer different questions once name
        // resolution is on: `ip.addr` stays the address and `ip.host` becomes
        // the name. With resolution off they read alike, which is exactly why
        // the reference marks all three `hide="yes"` - they are filter names
        // rather than rows anybody reads. `filter/fields.ts` is what makes
        // them worth emitting.
        { name: 'Source Address', value: srcIp, abbrev: 'ip.src', rawBytesRange: [l3Offset + 12, l3Offset + 15], children: hostAliasRows('ip', srcIp, [l3Offset + 12, l3Offset + 15], 'Source') },
        { name: 'Destination Address', value: dstIp, abbrev: 'ip.dst', rawBytesRange: [l3Offset + 16, l3Offset + 19], children: hostAliasRows('ip', dstIp, [l3Offset + 16, l3Offset + 19], 'Destination') },
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

    ipLayer.fields.push(...ipStreamRow(context, 'ip', srcIp, dstIp, filterFields));

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
            frameId, suffix: ` [Reassembled in ${id}]`, links: { 'ip.reassembled_in': id },
          })),
        );
        l3Tracker?.forgetFragments(srcIp, dstIp, identification, ipProtocolNum);
      }
    }

    if (ipProtocolNum === GRE_PROTOCOL && !isFragment) {
      const tunnelled = decodeGreTunnel(transportOffset, Math.min(rawBytes.length, l3Offset + ipTotalLen));
      if (tunnelled) return tunnelled;
    }

    // Port-gated, and read here rather than in `udpDispatch.ts` for the same
    // reason GRE is read here: a tunnel decides the ADDRESS columns, and this
    // is the function that owns them. A subdissector returning up through the
    // transport result could only ever change the label.
    if (ipProtocolNum === 17 && !isFragment && rawBytes.length >= transportOffset + 8
      && isVxlanPort((rawBytes[transportOffset] << 8) | rawBytes[transportOffset + 1],
        (rawBytes[transportOffset + 2] << 8) | rawBytes[transportOffset + 3])) {
      const tunnelled = decodeVxlanTunnel(
        transportOffset + 8, Math.min(rawBytes.length, l3Offset + ipTotalLen));
      if (tunnelled) return tunnelled;
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
          ipv4PseudoHeader(rawBytes, l3Offset, ipProtocolNum, ipTotalLen - ipHeaderLen), sentByUs, captureShort);

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
      // UDP's conversation rows live here, not in its decoder, because the
      // conversation record is keyed on the addresses this layer holds.
      transport.layer.fields.push(...udpConversationRows(
        context, ipProtocolNum, srcIp, dstIp, transport, filterFields,
      ));
      if (transport.extraLayers) layers.push(...transport.extraLayers);
      if (transport.embeddedNetwork) decodeQuotedDatagram(transport.embeddedNetwork);
      if (transport.protocolTokens) transportTokens = transport.protocolTokens;
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      icmpMatchedRequestFrameId = transport.icmpMatchedRequestFrameId;
      // Concatenated, not replaced: the fragment block above may already have
      // written `[Reassembled in N]` onto this datagram's earlier fragments,
      // and this is the frame that completed it - so both sets of patches
      // belong to it.
      const fromTransport = transportPatches(transport, id, 'icmp.resp_in');
      if (fromTransport) infoPatches = (infoPatches ?? []).concat(fromTransport);
      resolvedNames = transport.resolvedNames;
      // **`[Stream index]` is the TCP layer's row and is drawn there now.**
      // It sat here carrying no abbrev, so `tcp.stream` was answerable only by
      // a synthetic reader in `filter/fields.ts` and the detail pane showed
      // the number under the wrong protocol. Two rows for one fact would be
      // worse than the one in the wrong place.
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
          abbrev: 'ipv6.version',
          rawBytesRange: [l3Offset, l3Offset],
          bitfield: { bitOffset: 0, bitLength: 4, totalBits: 8 },
        },
        ...ipv6TrafficClassFields(rawBytes, l3Offset),
        {
          name: 'Flow Label',
          value: `0x${(((rawBytes[l3Offset + 1] & 0x0f) << 16) | (rawBytes[l3Offset + 2] << 8) | rawBytes[l3Offset + 3]).toString(16).padStart(6, '0')}`,
          abbrev: 'ipv6.flow',
          rawBytesRange: [l3Offset + 1, l3Offset + 3],
          bitfield: { bitOffset: 4, bitLength: 20, totalBits: 24 },
        },
        { name: 'Payload Length', value: ipv6PayloadLen, abbrev: 'ipv6.plen', rawBytesRange: [l3Offset + 4, l3Offset + 5] },
        { name: 'Next Header', value: describeIpProtocol(nextHeader), abbrev: 'ipv6.nxt', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
        { name: 'Hop Limit', value: hopLimit, abbrev: 'ipv6.hlim', rawBytesRange: [l3Offset + 7, l3Offset + 7] },
        {
          name: 'Source Address', value: srcIp, abbrev: 'ipv6.src', rawBytesRange: [l3Offset + 8, l3Offset + 23],
          children: ipv6AddressChildren(rawBytes, l3Offset + 8, srcIp, 'Source'),
        },
        {
          name: 'Destination Address', value: dstIp, abbrev: 'ipv6.dst', rawBytesRange: [l3Offset + 24, l3Offset + 39],
          children: ipv6AddressChildren(rawBytes, l3Offset + 24, dstIp, 'Destination'),
        },
        ...ipv6EmbeddedRows(rawBytes, l3Offset + 8, l3Offset + 24),
      ],
    };
    ipv6Layer.fields.push(...ipStreamRow(context, 'ipv6', srcIp, dstIp, filterFields));

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
            frameId, suffix: ` [Reassembled in ${id}]`, links: { 'ipv6.reassembled.in': id },
          })),
        );
        l3Tracker?.forgetFragments(srcIp, dstIp, chain!.fragmentId!, IPV6_FRAGMENT_KEY);
      }
    }

    if (effectiveNextHeader === GRE_PROTOCOL && !isV6Fragment && !isMalformedJumbo
      && !(chain?.stopsHere ?? false)) {
      const tunnelled = decodeGreTunnel(
        transportOffset, Math.min(rawBytes.length, transportOffset + transportPayloadLen));
      if (tunnelled) return tunnelled;
    }

    if (effectiveNextHeader === 17 && !isV6Fragment && !isMalformedJumbo
      && !(chain?.stopsHere ?? false) && rawBytes.length >= transportOffset + 8
      && isVxlanPort((rawBytes[transportOffset] << 8) | rawBytes[transportOffset + 1],
        (rawBytes[transportOffset + 2] << 8) | rawBytes[transportOffset + 3])) {
      const tunnelled = decodeVxlanTunnel(transportOffset + 8,
        Math.min(rawBytes.length, transportOffset + transportPayloadLen));
      if (tunnelled) return tunnelled;
    }

    const transport = isMalformedJumbo
      ? null
      : v6Reassembled
        ? decodeTransportLayer(v6Reassembled, v6ReassembledOffset, effectiveNextHeader, srcIp, dstIp, tcpTracker, hopLimit, icmpTracker, id, v6Reassembled.length - v6ReassembledOffset, quicTracker, tsUs, dnsTracker, ipv6PseudoHeader(rawBytes, l3Offset, effectiveNextHeader, v6Reassembled.length - v6ReassembledOffset), sentByUs)
        : (chain?.stopsHere ?? false)
          ? null
          : decodeTransportLayer(rawBytes, transportOffset, effectiveNextHeader, srcIp, dstIp, tcpTracker, hopLimit, icmpTracker, id, transportPayloadLen, quicTracker, tsUs, dnsTracker, ipv6PseudoHeader(rawBytes, l3Offset, effectiveNextHeader, transportPayloadLen), sentByUs, captureShort);
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
      // UDP's conversation rows live here, not in its decoder, because the
      // conversation record is keyed on the addresses this layer holds.
      transport.layer.fields.push(...udpConversationRows(
        context, effectiveNextHeader, srcIp, dstIp, transport, filterFields,
      ));
      if (transport.extraLayers) layers.push(...transport.extraLayers);
      if (transport.embeddedNetwork) decodeQuotedDatagram(transport.embeddedNetwork);
      if (transport.protocolTokens) transportTokens = transport.protocolTokens;
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      icmpMatchedRequestFrameId = transport.icmpMatchedRequestFrameId;
      // Concatenated, not replaced, for the same reason as the IPv4 branch:
      // the fragment block above may already have written `[Reassembled in N]`
      // onto this datagram's earlier fragments, and this is the frame that
      // completed it.
      const fromTransport = transportPatches(transport, id, 'icmpv6.resp_in');
      if (fromTransport) infoPatches = (infoPatches ?? []).concat(fromTransport);
      resolvedNames = transport.resolvedNames;
      // **`[Stream index]` is the TCP layer's row and is drawn there now.**
      // It sat here carrying no abbrev, so `tcp.stream` was answerable only by
      // a synthetic reader in `filter/fields.ts` and the detail pane showed
      // the number under the wrong protocol. Two rows for one fact would be
      // worse than the one in the wrong place.
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

  return {
    srcIp, dstIp, proto, protocolLabel, info, status, analysisFlags, srcPort, dstPort,
    streamId, icmpMatchedRequestFrameId, infoPatches, resolvedNames, transportLayerIndex,
    extensionTokens, transportTokens,
  };
}

// --- the transport dispatch, and the helpers only this file uses ---------------

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
  tcpTracker?: TcpTrackerApi,
  ttl?: number,
  icmpTracker?: IcmpTrackerApi,
  frameId?: number,
  /**
   * Number of bytes belonging to the transport header+payload as *declared by
   * the network layer* (IPv4: Total Length - IHL; IPv6: Payload Length, which
   * already excludes the fixed 40-byte header). Real Ethernet frames are
   * padded up to a 60-byte minimum, so deriving TCP payload length from
   * rawBytes.length would count that padding as payload.
   */
  l4SegmentLen?: number,
  quicTracker?: QuicTrackerApi,
  /** Capture time, epoch microseconds - the analysis flags compare timings. */
  tsUs?: number,
  dnsTracker?: DnsTrackerApi,
  /**
   * The IP pseudo-header for the transport checksum (RFC 793 / RFC 8200), or
   * undefined when the network layer could not supply one.
   */
  pseudoHeader?: Uint8Array,
  /** See `checksumVerdict` - this machine sent the frame, so its checksums
   *  may not have been filled in yet. Undefined is "not known", which is a
   *  third answer and not a synonym for `false`. */
  sentByUs?: boolean,
  /** How many bytes of the frame the capture did not keep - a snaplen. */
  notCaptured = 0,
): TransportResult | null {
  // TCP Decode
  if (ipProtocolNum === 6 && rawBytes.length >= transportOffset + 20) {
    // TCP - see dissectors/tcpTransport.ts.
    const read = dissectTcpTransport(rawBytes, transportOffset, {
      srcIp, dstIp, frameId, tsUs, tcpTracker, l4SegmentLen, pseudoHeader, sentByUs, notCaptured,
    });
    if (read) return read;
  } else if (ipProtocolNum === 6 && notCaptured > 0 && rawBytes.length >= transportOffset + 4) {
    // A snaplen that ended the frame inside the TCP header. The ports are
    // there, so the segment is named by them - as Wireshark does - rather
    // than written off as an IP payload nobody dissected.
    return partialTcpHeader(rawBytes, transportOffset);
  } else if (ipProtocolNum === 17 && rawBytes.length >= transportOffset + 8) {
    // UDP - see dissectors/udpTransport.ts.
    const read = dissectUdpTransport(rawBytes, transportOffset, {
      srcIp, dstIp, frameId, tsUs, quicTracker, dnsTracker, pseudoHeader, sentByUs,
    });
    if (read) return read;
  } else if (isPortlessProtocol(ipProtocolNum)) {
    // IGMP, VRRP and OSPF - see dissectors/portless.ts.
    const read = dissectPortless(rawBytes, transportOffset, ipProtocolNum, l4SegmentLen);
    if (read) return read;
  } else if (ipProtocolNum === 1 || ipProtocolNum === 58) {
    // ICMP (v4, protocol 1) / ICMPv6 (protocol 58) - see dissectors/icmp.ts.
    // ICMPv6 uses different type numbers than ICMPv4 for the same messages
    // (echo request/reply is 128/129 rather than 8/0) and adds the IPv6
    // Neighbor Discovery messages that make up most real ICMPv6 traffic, so
    // one module reads both and branches on the protocol number.
    const read = dissectIcmp(rawBytes, transportOffset, {
      isIcmpv6: ipProtocolNum === 58,
      srcIp, dstIp, ttl, frameId, tsUs, icmpTracker, l4SegmentLen, pseudoHeader, sentByUs,
    });
    if (read) return read;
  }

  return null;
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

/**
 * A TCP header the capture kept only the start of: its ports, and nothing a
 * reader would have to guess at. No stream, no analysis - a sequence number
 * that was not captured cannot place the segment in one.
 */
function partialTcpHeader(rawBytes: Uint8Array, transportOffset: number): TransportResult {
  const srcPort = (rawBytes[transportOffset] << 8) | rawBytes[transportOffset + 1];
  const dstPort = (rawBytes[transportOffset + 2] << 8) | rawBytes[transportOffset + 3];
  return {
    proto: 'TCP',
    srcPort,
    dstPort,
    info: `${srcPort} → ${dstPort}`,
    layer: {
      name: 'Transmission Control Protocol',
      summary: `Transmission Control Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`,
      fields: [
        { name: 'Source Port', value: srcPort, abbrev: 'tcp.srcport' },
        { name: 'Destination Port', value: dstPort, abbrev: 'tcp.dstport' },
      ],
    },
    fields: { 'tcp.srcport': srcPort, 'tcp.dstport': dstPort },
  };
}

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

/** The IPv4 pseudo-header: src, dst, zero, protocol, transport length. */
function ipv4PseudoHeader(rawBytes: Uint8Array, l3Offset: number, protocol: number, transportLen: number): Uint8Array | undefined {
  if (transportLen <= 0 || transportLen > 0xffff) return undefined;
  const ph = new Uint8Array(12);
  ph.set(rawBytes.subarray(l3Offset + 12, l3Offset + 20), 0);
  ph[9] = protocol;
  ph[10] = transportLen >> 8; ph[11] = transportLen & 0xff;
  return ph;
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
      abbrev: 'ipv6.tclass',
      rawBytesRange: [l3Offset, l3Offset + 3],
      bitfield: { bitOffset: 4, bitLength: 8, totalBits: 32 },
      children: [
        {
          name: 'Differentiated Services Codepoint',
          value: `${dscpName(dscp)} (${dscp})`,
          abbrev: 'ipv6.tclass.dscp',
          rawBytesRange: [l3Offset, l3Offset + 3],
          bitfield: { bitOffset: 4, bitLength: 6, totalBits: 32 },
        },
        {
          name: 'Explicit Congestion Notification',
          value: `${ecnName(ecn)} (${ecn})`,
          abbrev: 'ipv6.tclass.ecn',
          rawBytesRange: [l3Offset, l3Offset + 3],
          bitfield: { bitOffset: 10, bitLength: 2, totalBits: 32 },
        },
      ],
    },
  ];
}

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

function transportPatches(
  transport: {
    reassembledFrom?: number[];
    labelPatches?: { frameId: number; protocolLabel: string }[];
    dnsMatchedQueryFrameId?: number;
    icmpMatchedRequestFrameId?: number;
  },
  completedIn: number,
  /** Which ICMP's `resp_in` a matched request gains - the family this frame is. */
  icmpResponseIn: 'icmp.resp_in' | 'icmpv6.resp_in',
): InfoPatch[] | undefined {
  const out: InfoPatch[] = [];
  // The request learns its answer only now. Its `(reply in N)` Info suffix
  // travels as the batch's `icmpReplies`; the tree link travels here, so it
  // reaches the stored row and a tree rebuilt from it.
  if (transport.icmpMatchedRequestFrameId !== undefined) {
    out.push({ frameId: transport.icmpMatchedRequestFrameId, links: { [icmpResponseIn]: completedIn } });
  }
  for (const frameId of transport.reassembledFrom ?? []) {
    out.push({ frameId, suffix: ` [TCP PDU reassembled in ${completedIn}]`, links: { 'tcp.reassembled_in': completedIn } });
  }
  for (const patch of transport.labelPatches ?? []) out.push(patch);
  // The query frame learns which frame answered it only now.
  if (transport.dnsMatchedQueryFrameId !== undefined) {
    out.push({ frameId: transport.dnsMatchedQueryFrameId, responseInFrame: completedIn });
  }
  return out.length > 0 ? out : undefined;
}

/**
 * IANA protocol numbers, for the Protocol column when nothing dissects the
 * payload. Only the ones that actually turn up on a LAN or a VPN link - the
 * point is to name what a capture will really contain, not to mirror the whole
 * registry, and anything missing still gets an honest "IP Protocol N".
 */
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
 * Walks an ICMPv6 Neighbor Discovery option list, looking for one option type.
 * Options start after the message body and are each a type byte, a length in
 * 8-byte units (a zero length would mean an infinite loop, so it terminates),
 * and the option data.
 */

/**
 * Every Neighbor Discovery option of one type, in order.
 *
 * `findNdpOption` stops at the first, which is right for a link-layer address
 * but wrong for the two things a Router Advertisement carries several of: a
 * router may advertise more than one prefix, and more than one RDNSS option.
 * Shares the termination rules with it - a zero length would loop forever, and
 * an option claiming to run past the frame is truncated rather than trusted.
 */
