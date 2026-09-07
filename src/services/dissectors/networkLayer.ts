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
import type { TcpStreamTracker } from '../tcpStreamTracker';
import type { IcmpEchoTracker } from '../icmpEchoTracker';
import type { QuicFlowTracker } from '../quicFlowTracker';
import type { DnsTracker } from '../dnsTracker';
import type { L3Tracker } from '../l3Tracker';
import type { InfoPatch } from '../dissect/types';
import { formatIpv6Address, formatMac } from '../addressFormat';
import { ETHERNET_MAX_FRAME } from '../direction';
import { dissectIpv4Options, dscpName, ecnName, inferTtl } from './ipv4';
import { IPV6_EXT_HEADERS, NO_NEXT_HEADER, walkIpv6Extensions } from './ipv6Ext';
import { dissectPortless, isPortlessProtocol } from './portless';
import { dissectTcpTransport } from './tcpTransport';
import { dissectUdpTransport } from './udpTransport';

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
export interface NetworkContext {
  id: number;
  tsUs: number;
  relativeTime: number;
  timeDelta: number;
  origLen: number;
  tcpTracker?: TcpStreamTracker;
  icmpTracker?: IcmpEchoTracker;
  quicTracker?: QuicFlowTracker;
  dnsTracker?: DnsTracker;
  l3Tracker?: L3Tracker;
  /** This machine sent the frame, so its checksums may not be filled in yet. */
  sentByUs: boolean;
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
): TransportResult | null {
  // TCP Decode
  if (ipProtocolNum === 6 && rawBytes.length >= transportOffset + 20) {
    // TCP - see dissectors/tcpTransport.ts.
    const read = dissectTcpTransport(rawBytes, transportOffset, {
      srcIp, dstIp, frameId, tsUs, tcpTracker, l4SegmentLen, pseudoHeader, sentByUs,
    });
    if (read) return read;
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
 * The protocol number IPv6 fragments are keyed under.
 *
 * RFC 8200 §4.5 keys a datagram on source, destination and identification and
 * deliberately leaves the payload protocol out - the Fragment header sits
 * above whatever the payload turns out to be. Passing one constant for every
 * IPv6 fragment is how that exclusion is expressed to a tracker whose key was
 * written for IPv4's, and 44 is the Fragment header's own number.
 */
const IPV6_FRAGMENT_KEY = 44;

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

function ipv6AddressSpace(address: string): string {
  const a = address.toLowerCase();
  if (a === '::1') return 'Loopback';
  if (a === '::') return 'Unspecified';
  if (a.startsWith('ff')) return 'Multicast';
  if (a.startsWith('fe8') || a.startsWith('fe9') || a.startsWith('fea') || a.startsWith('feb')) return 'Link-Local Unicast';
  if (a.startsWith('fc') || a.startsWith('fd')) return 'Unique Local Unicast';
  return 'Global Unicast';
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
