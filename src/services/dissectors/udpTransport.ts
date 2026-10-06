/**
 * The UDP branch of the transport decode.
 *
 * Lifted verbatim out of `decodeTransportLayer`, which held TCP, UDP, the three
 * portless protocols and ICMP in one 977-line function. Nothing about the
 * decode changed in the move - the parity harness holds both fixtures to the
 * byte, and it did not shift.
 *
 * What the split buys is that the *shape* of the decode is now legible: this
 * reads a UDP header, verifies its checksum under the offload policy, and hands
 * the payload to whichever subdissector claims it - by port through
 * `udpDispatch.ts`, by content through `heuristics.ts` when no port did, or to
 * one of the four that return more than a label (DHCP, DNS, NBNS, QUIC).
 */
import type { Packet, ProtocolLayer } from '../../types/packet';
import type { TransportResult } from '../dissect/types';
import type { QuicHandshakeFacts } from '../quicFlowTracker';
import type { QuicTrackerApi, DnsTrackerApi, L3TrackerApi } from '../dissect/trackerApi';
import { wireGuardFacts } from './wireguard';
import { checksumVerdict, extractLiteralUrlOrHost } from '../dissect/transportShared';
import { dissectDhcp, dissectDhcpv6 } from './dhcp';
import { buildDnsLayer, dnsInfoLine, parseDnsMessage } from './dns';
import { detectUdpPayload } from './heuristics';
import { buildHttp3Layer } from './http3';
import { dissectNbns } from './nbns';
import { dissectSsdp } from './ssdp';
import { buildQuicLayer, dissectQuicDatagram } from './quic';
import { buildQuicTlsLayer } from './tls';
import { dissectNtp, dissectStun } from './udpApps';
import { dataLayer } from './mediaType';
import { findUdpPort } from './dispatch';

/** A cut SSDP datagram's start line, which is all of it there may be to name. */
const START_LINE_DECODER = new TextDecoder();

/** Everything the UDP decode needs that is not the bytes themselves. */
export interface UdpContext {
  srcIp: string;
  dstIp: string;
  frameId?: number;
  /** Capture time, epoch microseconds. */
  tsUs?: number;
  quicTracker?: QuicTrackerApi;
  dnsTracker?: DnsTrackerApi;
  /** Datagram sessions: WireGuard's. */
  l3Tracker?: L3TrackerApi;
  /** The IP pseudo-header for the checksum, or undefined when there is none. */
  pseudoHeader?: Uint8Array;
  /** This machine sent the frame, so its checksum may not be filled in yet. */
  sentByUs?: boolean;
}

/** Reads a UDP datagram and whatever claims its payload. */
export function dissectUdpTransport(
  rawBytes: Uint8Array,
  transportOffset: number,
  context: UdpContext,
): TransportResult | null {
  const { srcIp, dstIp, frameId, tsUs, quicTracker, dnsTracker, l3Tracker, pseudoHeader } = context;
  // No `?? false`: see the same line in `tcpTransport.ts`.
  const { sentByUs } = context;
  // UDP Decode
  const srcPort = (rawBytes[transportOffset] << 8) | rawBytes[transportOffset + 1];
  const dstPort = (rawBytes[transportOffset + 2] << 8) | rawBytes[transportOffset + 3];
  const udpLen = (rawBytes[transportOffset + 4] << 8) | rawBytes[transportOffset + 5];
  const udpChecksum = (rawBytes[transportOffset + 6] << 8) | rawBytes[transportOffset + 7];
  const udpVerdict = checksumVerdict(pseudoHeader, rawBytes, transportOffset, transportOffset + udpLen, udpChecksum, sentByUs);

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
  // Which leaf protocol claims these ports, if any. Resolved once here rather
  // than as a branch per protocol - the table is in `dissectors/udpDispatch.ts`.
  const subdissector = findUdpPort(srcPort, dstPort, dstIp);

  // The UDP header's Length field counts the 8-byte header itself, but
  // The reference analyzer's "Len=" - like TCP's - reports payload only.
  const udpPayloadLen = Math.max(0, udpLen - 8);
  // The datagram the capture did not keep all of - a snaplen. A dissector is
  // given what was kept; this is how the row says why it may be short.
  const payloadCut = udpPayloadStart + udpPayloadLen > rawBytes.length && udpLen >= 8;

  // Each subdissector that claims the payload replaces the generic
  // "src → dst Len=n" summary entirely, the way the reference analyzer does.
  let info: string | null = null;
  const extraLayers: ProtocolLayer[] = [];
  const dhcpFields: Record<string, string | number> = {};
  const dnsFields: Record<string, string | number> = {};
  const quicFields: Record<string, string | number> = {};
  const appFields: Record<string, string | number> = {};
  const ssdpFields: Record<string, string | number> = {};
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
  } else if (subdissector !== null) {
    // Every leaf UDP protocol - one label, one Info line, one tree layer and
    // a bag of fields - goes through `dissectors/udpDispatch.ts` rather than
    // through a branch of its own here. See that module for why.
    const payloadEnd = Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen);
    const read = subdissector.dissect(rawBytes, udpPayloadStart, payloadEnd);
    if (read) {
      protocolLabel = read.protocolLabel;
      info = read.info;
      extraLayers.push(read.layer, ...(read.innerLayers ?? []));
      protocolTokens.push(subdissector.token);
      Object.assign(appFields, read.fields);
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
    if (!parsed && payloadCut) {
      // Too little of the message kept to read even its header. The port has
      // named it, and a column saying so with nothing after it is what
      // Wireshark shows for one that ran out before it could say more.
      protocolLabel = dnsPortLabel;
      info = '';
    } else if (parsed) {
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
    const payloadEnd = Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen);
    const ssdp = dissectSsdp(rawBytes, udpPayloadStart, payloadEnd);
    if (ssdp) {
      protocolLabel = 'SSDP';
      protocolTokens.push('ssdp');
      info = ssdp.info;
      extraLayers.push(ssdp.layer);
      Object.assign(ssdpFields, ssdp.fields);
    } else if (payloadCut) {
      // The headers ran past what was kept, so there is no message to read -
      // but a start line that was kept whole is still the row's name.
      const lineEnd = rawBytes.subarray(udpPayloadStart, payloadEnd).indexOf(0x0a);
      protocolLabel = 'SSDP';
      protocolTokens.push('ssdp');
      info = lineEnd > 0
        ? `${START_LINE_DECODER.decode(rawBytes.subarray(udpPayloadStart, udpPayloadStart + lineEnd)).replace(/\r$/, '')} `
        : '';
    }
  } else if (isQuic) {
    // A short header is only identifiable as QUIC in the context of a
    // handshake already seen on this flow, so packets that precede one stay
    // plain UDP - which is what the reference analyzer reports for them too.
    const isShortHeaderCandidate = udpPayloadStart < rawBytes.length && (rawBytes[udpPayloadStart] & 0x80) === 0;
    const flowIsKnown = quicTracker?.isKnownFlow(srcIp, srcPort, dstIp, dstPort) ?? false;

    if (!isShortHeaderCandidate || flowIsKnown) {
      // A resolver rather than an id: a datagram coalesces several packets
      // and only the short-header ones carry an id to match, so the lookup
      // belongs at each packet rather than once at the datagram's first byte.
      const resolveConnectionId = quicTracker
        ? (bytes: Uint8Array, at: number) =>
          quicTracker.matchConnectionId(srcIp, srcPort, dstIp, dstPort, bytes, at)
        : undefined;
      // The handshake facts are gathered packet by packet, as the datagram is
      // walked, rather than from the whole datagram afterwards: the ServerHello
      // that names the cipher suite is usually in the Initial AHEAD of the
      // Handshake and 1-RTT packets that need it, in the same datagram.
      // `dissectQuicDatagram` has the measurement.
      const facts: QuicHandshakeFacts = {};
      const quic = dissectQuicDatagram(
        rawBytes,
        udpPayloadStart,
        Math.min(rawBytes.length, udpPayloadStart + udpPayloadLen),
        resolveConnectionId,
        quicTracker?.createInitialDecryptor(srcIp, srcPort, dstIp, dstPort, rawBytes),
        quicTracker
          ? (fragments) => {
            const learned = quicTracker.addCryptoFragments(srcIp, srcPort, dstIp, dstPort, fragments);
            if (learned) Object.assign(facts, learned);
          }
          : undefined,
      );
      if (quic) {
        // A long header names its connection outright; a short one is
        // recognised by the id the resolver matched while dissecting.
        const connectionNumber = quic.isLongHeader
          ? quicTracker?.noteLongHeader(
            srcIp, srcPort, dstIp, dstPort, quic.connectionIds,
            quic.packets.some((p) => p.headerForm === 'long' && (p.dcidLength ?? 0) === 0))
          : quicTracker?.connectionNumberForFlow(
            srcIp, srcPort, dstIp, dstPort, quic.packets[0]?.dcid);
        if (connectionNumber !== undefined) quicFields['quic.connection.number'] = connectionNumber;
        proto = 'QUIC';
        protocolLabel = 'QUIC';
        protocolTokens.push('quic');
        info = quic.info;

        // First into `extraLayers`, because everything else this datagram
        // carries is carried *by* the connection these headers describe - the
        // TLS handshake below and the HTTP/3 pushed last. `frameProtocols` is
        // read off the layer names in order, so the stack has to read
        // `udp:quic:tls:http3` rather than putting QUIC after its own payload.
        const quicLayer = buildQuicLayer(quic.packets, quic.info, connectionNumber);
        if (quicLayer) {
          extraLayers.push(quicLayer.layer);
          Object.assign(quicFields, quicLayer.fields);
        }

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

        if (facts.hello) {
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
        if (facts.serverHello) {
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
    const byPort = (srcPort === 123 || dstPort === 123)
      ? dissectNtp(rawBytes, udpPayloadStart, payloadEnd)
      : (srcPort === 3478 || dstPort === 3478 || srcPort === 3479 || dstPort === 3479)
        ? dissectStun(rawBytes, udpPayloadStart, payloadEnd)
        : null;
    // Content-based detection, and only where no port claimed the payload -
    // see the rules at the top of dissectors/heuristics.ts.
    const found = byPort !== null
      ? { result: byPort, detector: null as string | null }
      : detectUdpPayload(rawBytes, udpPayloadStart, payloadEnd);
    if (found) {
      const app = found.result;
      protocolLabel = app.protocolLabel;
      info = app.info;
      extraLayers.push(app.layer);
      protocolTokens.push(app.token);
      Object.assign(appFields, app.fields);
      // Which detector claimed it, so a wrong label can be traced to the
      // rule that made it rather than guessed at.
      if (found.detector !== null) appFields['inwire.heuristic'] = found.detector;
      // A WireGuard datagram's session: which handshake it belongs to, and
      // on a response the initiation it answers.
      if (app.token === 'wg' && l3Tracker !== undefined && frameId !== undefined) {
        const facts = wireGuardFacts(rawBytes, udpPayloadStart);
        const session = l3Tracker.wireguard(facts.type, `${srcIp}:${srcPort}`, `${dstIp}:${dstPort}`, frameId,
          facts.sender, facts.receiver);
        if (session !== null) {
          appFields['wg.stream'] = session.stream;
          app.layer.fields.push({ name: 'Stream index', value: session.stream, abbrev: 'wg.stream', generated: true });
          if (session.responseTo !== undefined) {
            appFields['wg.response_to'] = session.responseTo;
            app.layer.fields.push({
              name: 'Response to Frame', value: session.responseTo, abbrev: 'wg.response_to',
              generated: true, linkToFrame: session.responseTo,
            });
          }
        }
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
    // Nothing claimed the datagram, so its payload is the reference's `data`
    // protocol. UDP needs no equivalent of TCP's `tlsOnThisConnection` guard:
    // a datagram is claimed or it is not, with no reassembly state that could
    // make "produced no layer" mean something other than "unclaimed".
    //
    // **The bytes have to actually be there**, which is not the same as the
    // header saying how many there are. An ICMP error quotes its datagram's
    // IP header and the first eight bytes after it - exactly a UDP header and
    // nothing else - while that header still declares the whole original
    // length. Reading the declared length raised a `Data` layer on every
    // quoted datagram, over bytes past the end of the frame, and
    // `scripts/icmp/dissect.ts` caught it on the commit that introduced it.
    extraLayers: extraLayers.length === 0 && udpPayloadLen > 0
      && udpPayloadStart + udpPayloadLen <= rawBytes.length
      ? [dataLayer(rawBytes.subarray(udpPayloadStart, udpPayloadStart + udpPayloadLen))]
      : extraLayers,
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
      ...ssdpFields,
    },
    layer: {
      name: 'User Datagram Protocol',
      summary: `User Datagram Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`,
      rawBytesRange: [transportOffset, transportOffset + 7],
      fields: [
        { name: 'Source Port', value: srcPort, abbrev: 'udp.srcport', rawBytesRange: [transportOffset, transportOffset + 1], children: [{ name: 'Source or Destination Port', value: srcPort, abbrev: 'udp.port', rawBytesRange: [transportOffset, transportOffset + 1] }] },
        { name: 'Destination Port', value: dstPort, abbrev: 'udp.dstport', rawBytesRange: [transportOffset + 2, transportOffset + 3], children: [{ name: 'Source or Destination Port', value: dstPort, abbrev: 'udp.port', rawBytesRange: [transportOffset + 2, transportOffset + 3] }] },
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
        { name: 'UDP payload', value: `${Math.max(0, udpLen - 8)} bytes`, abbrev: 'udp.payload', rawBytesRange: [transportOffset + 8, transportOffset + Math.max(8, udpLen - 1)] },
      ],
    },
  };
}
