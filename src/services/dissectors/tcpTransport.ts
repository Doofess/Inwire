/**
 * The TCP branch of the transport decode.
 *
 * Lifted verbatim out of `decodeTransportLayer`, which held TCP, UDP, the three
 * portless protocols and ICMP in one 977-line function. Nothing about the
 * decode changed in the move; the parity harness holds both fixtures to the
 * byte and did not shift.
 *
 * This is the branch that grew: it reads a TCP header and its options, runs
 * Wireshark's sequence analysis through `dissect/tcpAnalysis.ts`, verifies the
 * checksum under the offload policy, and then decides which of five things
 * claims the payload - DNS behind a length prefix, LDAP, a TLS record, the
 * cleartext HTTP family, or nothing at all. Each of those is already its own
 * module; what was left here was the dispatch between them, and that is what
 * this file now is.
 */
import type { ExpertCategory, Packet, ProtocolField, ProtocolLayer } from '../../types/packet';
import type { TransportResult } from '../dissect/types';
import type { TcpStreamTracker } from '../tcpStreamTracker';
import { ABBREV_BY_FLAG, CATEGORY_BY_FLAG, type TcpAnalysis, type TcpAnalysisFlag } from '../dissect/tcpAnalysis';
import { checksumVerdict, extractLiteralUrlOrHost } from '../dissect/transportShared';
import { freshTlsConversation, freshTlsCursor } from '../tcpStreamTracker';
import { dissectAppStream, freshAppDirection, type AppStreamResult } from './appStream';
import { buildDnsLayer, dnsInfoLine, parseDnsMessage } from './dns';
import { dissectLdap, looksLikeLdap, freshLdapConversation, type LdapResult } from './ldap';
import { dissectKerberos, looksLikeKerberos, KERBEROS_PORT, type KerberosResult } from './kerberos';
import { dissectSmb2, looksLikeSmb2, freshSmb2Conversation, SMB2_PORT, type Smb2Result } from './smb2';
import { dissectBgp, looksLikeBgp, freshBgpDirection, BGP_PORT, type BgpResult } from './bgp';
import type { TcpReassembly } from './tls';
import { dissectTlsSegment, looksLikeTlsRecord, type TlsSegmentResult } from './tls';

/**
 * The ports the cleartext HTTP family is dispatched on. 443 is not here: that
 * is TLS, and the HTTP inside it is reached through the decrypted stream.
 */
const HTTP_PORTS = new Set([80, 591, 3128, 8000, 8008, 8080, 8888]);

/**
 * The ports LDAP is dispatched on: 389, and Microsoft's Global Catalog on 3268
 * which speaks the same protocol. 636 and 3269 are the TLS-wrapped forms and
 * arrive here as TLS, never as LDAP.
 */
const LDAP_PORTS = new Set([389, 3268]);

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
const TCP_FLAG_ROWS: { name: string; bitOffset: number; bitLength: number; set: string; unset: string; abbrev?: string; char: string }[] = [
  { name: 'Reserved', bitOffset: 0, bitLength: 3, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.res', char: 'R' },
  { name: 'Accurate ECN', bitOffset: 3, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.ae', char: 'E' },
  { name: 'Congestion Window Reduced', bitOffset: 4, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.cwr', char: 'C' },
  { name: 'ECN-Echo', bitOffset: 5, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.ece', char: 'E' },
  { name: 'Urgent', bitOffset: 6, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.urg', char: 'U' },
  { name: 'Acknowledgment', bitOffset: 7, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.ack', char: 'A' },
  { name: 'Push', bitOffset: 8, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.push', char: 'P' },
  { name: 'Reset', bitOffset: 9, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.reset', char: 'R' },
  { name: 'Syn', bitOffset: 10, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.syn', char: 'S' },
  { name: 'Fin', bitOffset: 11, bitLength: 1, set: 'Set', unset: 'Not set', abbrev: 'tcp.flags.fin', char: 'F' },
];

/**
 * The twelve flag bits as one string - `·······AP···` - which is how the
 * reference analyzer renders them and the fastest way to read a segment's
 * intent without expanding the subtree.
 *
 * One character per bit, most significant first, so the index into the string
 * IS `bitOffset`. Reserved spans three bits and therefore three characters,
 * each answering for its own bit rather than for the field: a string that
 * said `RRR` because any one of them was set would be the only row here that
 * lied about which bit it meant.
 */
function tcpFlagsString(window12: number): string {
  let out = '';
  for (const row of TCP_FLAG_ROWS) {
    for (let i = 0; i < row.bitLength; i++) {
      const shift = 12 - row.bitOffset - i - 1;
      out += ((window12 >> shift) & 1) === 1 ? row.char : '·';
    }
  }
  return out;
}

/**
 * The six things a TCP conversation may contain, in the reference's bit order
 * and with its own letters. A capture missing SYN and SYN-ACK is one whose
 * relative sequence numbers are relative to wherever the capture started,
 * which is the single most useful thing this subtree says.
 */
const COMPLETENESS_BITS: { name: string; bit: number; char: string }[] = [
  { name: 'RST', bit: 32, char: 'R' },
  { name: 'FIN', bit: 16, char: 'F' },
  { name: 'Data', bit: 8, char: 'D' },
  { name: 'ACK', bit: 4, char: 'A' },
  { name: 'SYN-ACK', bit: 2, char: 'S' },
  { name: 'SYN', bit: 1, char: 'S' },
];

function completenessFields(mask: number): ProtocolField[] {
  const str = mask === 0
    // The reference's own spelling for "none of them", rather than six dots,
    // because six dots and a missing row look the same at a glance.
    ? '[ Null ]'
    : COMPLETENESS_BITS.map((b) => ((mask & b.bit) !== 0 ? b.char : '·')).join('');
  return [
    { name: 'Completeness Flags', value: str, abbrev: 'tcp.completeness.str', generated: true },
    ...COMPLETENESS_BITS.map((b) => ({
      name: b.name,
      value: (mask & b.bit) !== 0 ? 'Present' : 'Absent',
      abbrev: `tcp.completeness.${b.name.toLowerCase()}`,
      generated: true,
    })),
  ];
}

/** Everything the TCP decode needs that is not the bytes themselves. */
export interface TcpContext {
  srcIp: string;
  dstIp: string;
  frameId?: number;
  /** Capture time, epoch microseconds - the analysis flags compare timings. */
  tsUs?: number;
  tcpTracker?: TcpStreamTracker;
  /** Transport header + payload as the network layer declared it, not as the
   *  frame was padded. */
  l4SegmentLen?: number;
  /** The IP pseudo-header for the checksum, or undefined when there is none. */
  pseudoHeader?: Uint8Array;
  /** This machine sent the frame, so its checksum may not be filled in yet. */
  sentByUs?: boolean;
}

/** Reads a TCP segment and whatever claims its payload. */
export function dissectTcpTransport(
  rawBytes: Uint8Array,
  transportOffset: number,
  context: TcpContext,
): TransportResult | null {
  const { srcIp, dstIp, frameId, tsUs, tcpTracker, l4SegmentLen, pseudoHeader } = context;
  // No `?? false`: undefined means the direction is not known, and
  // `checksumVerdict` needs to tell that from a decided "not us".
  const { sentByUs } = context;
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

  const tcpOptions = tcpHeaderLen > 20 ? parseTcpOptions(rawBytes, transportOffset + 20, transportOffset + tcpHeaderLen, ackNum) : null;
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
    storedChecksum, sentByUs);

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
  // Read whether or not URG is set, which is the reference's behaviour: the
  // two bytes are in every header, and a pointer with no URG flag is worth
  // seeing rather than hiding.
  const urgentPointer = (rawBytes[transportOffset + 18] << 8) | rawBytes[transportOffset + 19];
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
  /** Seconds since this stream's first frame, and since its previous one. */
  let sinceStreamStart: number | undefined;
  let sincePreviousInStream: number | undefined;
  let conversationCompleteness: string | undefined;
  let completenessMask = 0;
  let isKeepAlive = false;
  let lostSegment = false;
  let tlsInOrder = true;
  let analysis: TcpAnalysis | undefined;
  /** Whether this frame's FIN opened the close or answered it. */
  let finRole: 'active' | 'passive' | undefined;
  if (tcpTracker) {
    streamId = tcpTracker.getStreamId(srcIp, srcPort, dstIp, dstPort);
    const position = tcpTracker.recordStreamPacket(streamId, tsUs);
    streamPacketNumber = position.packetNumber;
    sinceStreamStart = position.sinceFirst;
    sincePreviousInStream = position.sincePrevious;
    tcpTracker.updateConnectionState(streamId, syn, ack, fin, rst, payloadLength > 0);
    if (fin) finRole = tcpTracker.noteFin(srcIp, srcPort, dstIp, dstPort);

    // Asked before the analysis advances the direction, so it describes
    // where the stream stood when this segment arrived.
    tlsInOrder = tcpTracker.isAtOrPastExpected(srcIp, srcPort, dstIp, dstPort, seqNum);
    analysis = tcpTracker.analyze(srcIp, srcPort, dstIp, dstPort, {
      frame: frameId ?? 0, timeUs: tsUs ?? 0, seq: seqNum, ack: ackNum, window: rawWindow,
      segLen: payloadLength, syn, ack_: ack, fin, rst, psh, windowScaleOption: tcpOptions?.windowScale,
      sackBlocks: tcpOptions?.sackBlocks.map((b) => ({ left: b.leftEdge, right: b.rightEdge })),
    });
    isKeepAlive = analysis.flags.includes('keep_alive');
    lostSegment = analysis.flags.includes('lost_segment');
    // A gap has to reach the TLS record cursor even when the segment that
    // reports it carries no payload, and very often it does not: the frame
    // that first lands past a hole is frequently a bare ACK. TLS dissection
    // is gated on `payloadLength > 0`, so on those frames the cursor was
    // never told, kept waiting for a record whose remaining bytes were never
    // captured, and swallowed everything that followed into it.
    //
    // Measured on the bulk fixture: 671,438 bytes go missing between
    // frames 2884 and 4035, and the gap is reported on frame 3195 - a
    // zero-length ACK. The reference analyzer abandons the record there and
    // resynchronises; this build carried it across and attributed some
    // eleven hundred frames to one impossible record.
    if (lostSegment && payloadLength === 0 && tcpTracker) {
      tcpTracker.noteGap(srcIp, srcPort, dstIp, dstPort, seqNum);
    }
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
    completenessMask = tcpTracker.getCompletenessMask(streamId);
  }

  // The TLS record layer, now that the segment's place in the stream is
  // known. Only streams that look like TLS pay for cursor state: port 443, a
  // direction that already has a cursor, or a plausible record header.
  let reassembledFrom: number[] | undefined;
  let reassemblies: TcpReassembly[] | undefined;
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

  // LDAP, beside DNS-over-TCP and for the same reason: it is a length-delimited
  // message on a well-known port, so it needs the stream only for its own
  // framing. Unlike DNS it keeps per-connection state - the entry counter a
  // `searchResDone` reports - which is why it is handed the tracker.
  //
  // Port-gated, and deliberately: `looksLikeLdap` is a SEQUENCE holding an
  // INTEGER and a tag in a known range, which is a shape plenty of binary
  // protocols share. Claiming an arbitrary TCP stream on that would be the
  // confident wrong label `dissectors/heuristics.ts` exists to avoid.
  let ldapResult: LdapResult | null = null;
  if (!tcpDns && payloadLength > 0 && !isKeepAlive && !isRetransmitted && tlsInOrder
    && (LDAP_PORTS.has(srcPort) || LDAP_PORTS.has(dstPort))) {
    const payloadEnd = Math.min(rawBytes.length, tcpPayloadStart + payloadLength);
    if (looksLikeLdap(rawBytes, tcpPayloadStart, payloadEnd)) {
      const state = tcpTracker
        ? tcpTracker.ldapConversation(srcIp, srcPort, dstIp, dstPort)
        : freshLdapConversation();
      ldapResult = dissectLdap(rawBytes, tcpPayloadStart, payloadEnd, state);
    }
  }

  // Kerberos, the same shape again - a length-prefixed message on a well-known
  // port - and the one of the three that needs NO per-connection state: every
  // Info line the reference prints is a function of the message alone, since it
  // prints only the message's name. `framed` is true here and false on UDP,
  // which is the whole difference between the two transports.
  let kerberosResult: KerberosResult | null = null;
  if (!tcpDns && !ldapResult && payloadLength > 0 && !isKeepAlive && !isRetransmitted && tlsInOrder
    && (srcPort === KERBEROS_PORT || dstPort === KERBEROS_PORT)) {
    const payloadEnd = Math.min(rawBytes.length, tcpPayloadStart + payloadLength);
    // Past the four-byte length prefix before asking what the message looks
    // like - the prefix is framing, not part of the DER.
    if (looksLikeKerberos(rawBytes, tcpPayloadStart + 4, payloadEnd)) {
      kerberosResult = dissectKerberos(rawBytes, tcpPayloadStart, payloadEnd, true);
    }
  }

  // SMB2, the same shape as LDAP: a length-prefixed message on a well-known
  // port, with per-connection state - a Create response names the file the
  // REQUEST asked for, which no single frame carries.
  let smb2Result: Smb2Result | null = null;
  if (!tcpDns && !ldapResult && !kerberosResult && payloadLength > 0 && !isKeepAlive
    && !isRetransmitted && tlsInOrder && (srcPort === SMB2_PORT || dstPort === SMB2_PORT)) {
    const payloadEnd = Math.min(rawBytes.length, tcpPayloadStart + payloadLength);
    if (looksLikeSmb2(rawBytes, tcpPayloadStart, payloadEnd)) {
      const state = tcpTracker
        ? tcpTracker.smb2Conversation(srcIp, srcPort, dstIp, dstPort)
        : freshSmb2Conversation();
      smb2Result = dissectSmb2(rawBytes, tcpPayloadStart, payloadEnd, state);
    }
  }

  // BGP, and the one of the five that keeps its state per DIRECTION. The other
  // four decline a message split across segments; a BGP session's dominant
  // traffic is the full-table UPDATE, which does not fit one - so this reads
  // the stream, and a segment already inside a message is recognised by the
  // state in flight rather than by a marker it does not carry.
  let bgpResult: BgpResult | null = null;
  if (!tcpDns && !ldapResult && !kerberosResult && !smb2Result && payloadLength > 0
    && !isKeepAlive && !isRetransmitted && tlsInOrder
    && (srcPort === BGP_PORT || dstPort === BGP_PORT)) {
    const payloadEnd = Math.min(rawBytes.length, tcpPayloadStart + payloadLength);
    const pending = tcpTracker?.peekBgpDirection(srcIp, srcPort, dstIp, dstPort);
    if (pending !== undefined || looksLikeBgp(rawBytes, tcpPayloadStart, payloadEnd)) {
      const state = tcpTracker
        ? tcpTracker.bgpDirection(srcIp, srcPort, dstIp, dstPort)
        : freshBgpDirection();
      bgpResult = dissectBgp(rawBytes, tcpPayloadStart, payloadEnd, state);
    }
  }

  if (!tcpDns && !ldapResult && !kerberosResult && !smb2Result && !bgpResult && payloadLength > 0
    && !isKeepAlive && !isRetransmitted) {
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
        frameId: frameId ?? 0, tsUs, cursor, conversation, inOrder: tlsInOrder, segmentSeq: seqNum, gap: lostSegment,
        // Whichever end is the TLS port; the other is an ephemeral client one.
        serverPort: dstPort === 443 ? dstPort : srcPort === 443 ? srcPort : dstPort,
      });
      if (outcome.kind === 'tls') {
        tlsResult = outcome.result;
        reassembledFrom = outcome.result.reassembledFrom;
        reassemblies = outcome.result.reassemblies;
        labelPatches = outcome.result.labelPatches;
        // `tls.stream` is assigned here rather than inside the TLS decoder
        // because this is where the connection is identified. It is a sequence
        // of its own, not `tcp.stream`: a connection only takes a number once
        // it has actually produced a record.
        if (tcpTracker !== undefined) {
          const tlsStream = tcpTracker.getTlsStreamId(srcIp, srcPort, dstIp, dstPort);
          tlsResult.layer.fields.push({
            name: '[Stream index]', value: tlsStream, generated: true, abbrev: 'tls.stream',
          });
          // Into the bag as well as onto the row, for the same reason the four
          // `*.stream` indices are: `seedsFor` reads it back off the frame so a
          // replay can be told what this conversation was called.
          tlsResult.fields['tls.stream'] = tlsStream;
        }
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
  if (!tcpDns && !ldapResult && !tlsResult && !tlsOnThisConnection
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
        frameId !== undefined && tsUs !== undefined ? { id: frameId, tsUs } : undefined,
      );
      if (app.protocolLabel !== null) httpResult = app;
    }
  }

  if (tcpDns) {
    proto = 'DNS';
    protocolLabel = 'DNS';
  } else if (ldapResult) {
    proto = 'LDAP';
    protocolLabel = 'LDAP';
  } else if (kerberosResult) {
    proto = 'KRB5';
    // The Protocol column says KRB5 and the filter token says `kerberos`. Both
    // are the reference's own choice and they genuinely differ.
    protocolLabel = 'KRB5';
  } else if (smb2Result) {
    proto = 'SMB2';
    protocolLabel = 'SMB2';
  } else if (bgpResult) {
    proto = 'BGP';
    protocolLabel = 'BGP';
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
  const infoParts = kerberosResult
    ? [kerberosResult.info]
    : bgpResult
    ? [bgpResult.info]
    : smb2Result
    ? [smb2Result.info]
    : ldapResult
    ? [ldapResult.info]
    : tcpDns
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
  const info = (tlsResult || tcpDns || httpResult || ldapResult || smb2Result || kerberosResult || bgpResult)
    && expertTags.length > 0
    ? `${expertTags.join(' ')} , ${infoParts.join(' ')}`
    : `${expertTags.map(t => t + ' ').join('')}${infoParts.join(' ')}`;

  return {
    proto,
    protocolLabel,
    srcPort,
    dstPort,
    info,
    streamId,
    extraLayers: kerberosResult
      ? [kerberosResult.layer]
      : bgpResult
      ? [bgpResult.layer]
      : smb2Result
      ? [smb2Result.layer]
      : ldapResult
      ? [ldapResult.layer]
      : tcpDns
      ? [tcpDns.layer]
      : tlsResult
      ? [tlsResult.layer, ...(tlsResult.appLayers ?? [])]
      : httpResult
      ? httpResult.layers
      : undefined,
    // The certificate's rows sit inside the TLS layer's tree, so there is no
    // layer name for `frameProtocols` to read `x509ce` off - the same position
    // QUIC and SSDP are in, and the same answer.
    protocolTokens: tlsResult?.protocolTokens,
    // A name learned over TCP is a name learned; the passive resolution map
    // does not care which transport carried the answer.
    resolvedNames: tcpDns && tcpDns.resolved.length > 0 ? tcpDns.resolved : undefined,
    reassembledFrom,
    labelPatches,
    fields: {
      ...(kerberosResult ? kerberosResult.fields : {}),
      ...(bgpResult ? bgpResult.fields : {}),
      ...(smb2Result ? smb2Result.fields : {}),
      ...(ldapResult ? ldapResult.fields : {}),
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
      ...(tcpOptions?.mss !== undefined ? { 'tcp.options.mss_val': tcpOptions.mss } : {}),
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
        { name: 'Source Port', value: srcPort, abbrev: 'tcp.srcport', rawBytesRange: [transportOffset, transportOffset + 1], children: [{ name: 'Source or Destination Port', value: srcPort, abbrev: 'tcp.port', rawBytesRange: [transportOffset, transportOffset + 1] }] },
        { name: 'Destination Port', value: dstPort, abbrev: 'tcp.dstport', rawBytesRange: [transportOffset + 2, transportOffset + 3], children: [{ name: 'Source or Destination Port', value: dstPort, abbrev: 'tcp.port', rawBytesRange: [transportOffset + 2, transportOffset + 3] }] },
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
          abbrev: 'tcp.hdr_len',
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
        ...(expectedNextRel !== undefined
          ? [{ name: '[Next Sequence Number]', value: expectedNextRel, generated: true, abbrev: 'tcp.nxtseq' }]
          : []),
        // The window as sent, then the window after the scale factor from
        // this connection's SYN. Wireshark draws both, and `tcp.window_size`
        // is the scaled one - the number that actually bounds the sender.
        { name: 'Window', value: rawWindow, abbrev: 'tcp.window_size_value', rawBytesRange: [transportOffset + 14, transportOffset + 15] },
        { name: '[Calculated window size]', value: windowSize, generated: true, abbrev: 'tcp.window_size' },
        // **-1 when the scale is not in play**, which is the reference's own
        // encoding and not a missing value: it means no scaling, either
        // because this is the SYN that advertises it or because one end never
        // did. A 1 would claim the option was negotiated and multiplied by one.
        {
          name: '[Window size scaling factor]',
          value: windowScaleShift > 0 ? 2 ** windowScaleShift : -1,
          generated: true,
          abbrev: 'tcp.window_size_scalefactor',
        },
        { name: '[TCP Segment Len]', value: payloadLength, generated: true, abbrev: 'tcp.len' },
        {
          name: 'Checksum',
          value: `0x${storedChecksum.toString(16).padStart(4, '0')} [${checksum.status === 'Good' ? 'correct' : checksum.status === 'Bad' ? 'incorrect' : 'unverified'}]`,
          rawBytesRange: [transportOffset + 16, transportOffset + 17],
          abbrev: 'tcp.checksum',
          children: [{ name: '[Checksum Status]', value: checksum.status, generated: true, abbrev: 'tcp.checksum.status',
            ...(checksum.status === 'Bad' ? { expertInfo: { category: 'Broken' as const, message: 'Bad checksum' } } : {}) }],
        },
        {
          name: 'Urgent Pointer',
          value: urgentPointer,
          abbrev: 'tcp.urgent_pointer',
          rawBytesRange: [transportOffset + 18, transportOffset + 19],
        },
        // **The stream index, on the TCP layer where it belongs.** It was
        // emitted on IP and answered as a filter only by a synthetic reader,
        // so it sat in the one tree-coverage section where every entry is a
        // defect: a filter the app accepts for a row the pane will not draw.
        ...(streamId !== undefined
          ? [{ name: '[Stream index]', value: streamId, generated: true, abbrev: 'tcp.stream' }]
          : []),
        ...(streamPacketNumber !== undefined
          ? [{ name: '[Stream Packet Number]', value: streamPacketNumber, generated: true, abbrev: 'tcp.stream.pnum' }]
          : []),
        ...(sinceStreamStart !== undefined
          ? [{
            name: '[Time since first frame in this TCP stream]',
            value: sinceStreamStart.toFixed(9),
            generated: true,
            abbrev: 'tcp.time_relative',
          }]
          : []),
        ...(sincePreviousInStream !== undefined
          ? [{
            name: '[Time since previous frame in this TCP stream]',
            value: sincePreviousInStream.toFixed(9),
            generated: true,
            abbrev: 'tcp.time_delta',
          }]
          : []),
        ...(conversationCompleteness !== undefined
          ? [{
            name: '[Conversation completeness]',
            value: conversationCompleteness,
            generated: true,
            abbrev: 'tcp.completeness',
            // The summary above stays plain English - the reference prints
            // "Incomplete, ESTABLISHED (7)" and the number is an internal
            // bitmask nobody reading a UI should have to decode. The bits
            // underneath are a different thing: six separate statements about
            // what this capture contains, each one a filter worth typing.
            children: completenessFields(completenessMask),
          }]
          : []),
        // **What this frame DOES to the connection**, which the flag bits
        // above state and do not interpret. The reference draws these as
        // generated rows and they are the filters anyone reaches for on a
        // capture full of short-lived connections: `tcp.connection.rst` finds
        // every refused or dropped one without a flag expression, and
        // `tcp.connection.fin_active` answers "which end hung up first" -
        // which a flag cannot, because both ends send the same flag.
        ...connectionRows(syn, ack, fin, rst, finRole),
        // **A PDU that spanned segments, drawn where TCP reassembled it.**
        // This build tracked every contributing frame and every byte count
        // from the day TLS records were first followed across segments, and
        // spent all of it on one composed string inside the TLS record. The
        // reference draws a subtree with a row per frame, each a link - which
        // is the difference between reading "#289(1428), #290(1164)" and
        // clicking through to frame 289.
        ...reassemblyRows(reassemblies),
        // **A parent, where they were flat siblings of Window and Checksum.**
        // The reference nests them under one Options row and names that row
        // `tcp.options`; without it there was no way to tell, in the tree,
        // where the fixed header ended and the variable part began.
        ...(tcpOptions && tcpOptions.fields.length > 0
          ? [{
            name: `Options: (${tcpHeaderLen - 20} bytes)`,
            value: '',
            abbrev: 'tcp.options',
            rawBytesRange: [transportOffset + 20, transportOffset + tcpHeaderLen - 1] as [number, number],
            children: tcpOptions.fields,
          }]
          : []),
        ...(analysis ? tcpAnalysisFields(analysis) : []),
        // The payload itself, which had no row at all - so a segment whose
        // payload no sub-dissector claimed showed a header and then nothing,
        // with no way to tell an empty ACK from 1,440 unread bytes.
        ...(payloadLength > 0
          ? [{
            name: 'TCP payload',
            value: `${payloadLength} byte${payloadLength === 1 ? '' : 's'}`,
            abbrev: 'tcp.payload',
            rawBytesRange: [
              transportOffset + tcpHeaderLen,
              Math.min(rawBytes.length, transportOffset + tcpHeaderLen + payloadLength) - 1,
            ] as [number, number],
          }]
          : []),
      ],
    },
  };
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
  optionsEnd: number,
  /**
   * This segment's own cumulative ACK, raw.
   *
   * Needed only for D-SACK, which is defined against it (RFC 2883): a first
   * SACK block at or below the ACK is reporting data the receiver already
   * has. Passed in rather than re-read here so there is one place that
   * decodes the header.
   */
  ackNumber: number,
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
  /**
   * The two rows every option carries, whatever its kind.
   *
   * The reference draws Kind and Length under each option; this build drew
   * neither, so `tcp.option_kind` and `tcp.option_len` were absent on every
   * frame that had options at all. A helper rather than four copies, because
   * the single-byte options have no length byte and must not claim one.
   */
  const optionHeader = (at: number, kind: number, length?: number): ProtocolField[] => [
    { name: 'Kind', value: kind, abbrev: 'tcp.option_kind', rawBytesRange: [at, at] },
    ...(length === undefined
      ? []
      : [{ name: 'Length', value: length, abbrev: 'tcp.option_len', rawBytesRange: [at + 1, at + 1] as [number, number] }]),
  ];
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
    if (kind === 0) {
      // **Drawn, then stop.** The list really does end here, but the byte is
      // an option like any other and the reference shows it - breaking without
      // a row lost the one option that says where the options stopped.
      fields.push({
        name: 'TCP Option - End of Option List (EOL)',
        value: 'EOL',
        abbrev: 'tcp.options.eol',
        rawBytesRange: [offset, offset],
        children: optionHeader(offset, kind),
      });
      break;
    }
    if (kind === 1) {
      fields.push({
        name: 'TCP Option - No-Operation (NOP)',
        value: 'NOP',
        abbrev: 'tcp.options.nop',
        rawBytesRange: [offset, offset],
        children: optionHeader(offset, kind),
      });
      offset += 1;
      continue;
    }

    if (offset + 1 >= optionsEnd || offset + 1 >= rawBytes.length) break; // no room for a length byte
    const length = rawBytes[offset + 1];
    if (length < 2 || offset + length > optionsEnd || offset + length > rawBytes.length) break; // malformed - stop rather than misread

    if (kind === 2 && length === 4) {
      mss = (rawBytes[offset + 2] << 8) | rawBytes[offset + 3];
      infoParts.push(`MSS=${mss}`);
      // **The option row is named after the OPTION; the value is a child.**
      // That is the reference's arrangement - `tcp.options.mss` is the option
      // and `tcp.options.mss_val` the number inside it - and it matters for
      // more than tidiness: the two have different byte ranges, so a reader
      // clicking the value highlights the two bytes rather than the whole
      // option. Same for the two below.
      fields.push({
        name: 'TCP Option - Maximum Segment Size',
        value: `MSS: ${mss}`,
        rawBytesRange: [offset, offset + length - 1],
        abbrev: 'tcp.options.mss',
        children: [
          ...optionHeader(offset, kind, length),
          { name: 'MSS Value', value: mss, abbrev: 'tcp.options.mss_val', rawBytesRange: [offset + 2, offset + 3] },
        ],
      });
    } else if (kind === 3 && length === 3) {
      windowScale = rawBytes[offset + 2];
      infoParts.push(`WS=${2 ** windowScale}`);
      fields.push({
        name: 'TCP Option - Window Scale',
        value: `${windowScale} (multiply by ${2 ** windowScale})`,
        rawBytesRange: [offset, offset + length - 1],
        abbrev: 'tcp.options.wscale',
        children: [
          ...optionHeader(offset, kind, length),
          { name: 'Shift count', value: windowScale, abbrev: 'tcp.options.wscale.shift', rawBytesRange: [offset + 2, offset + 2] },
          // Drawn since the option was first read, and never named. It is the
          // number that actually applies to every window field on the
          // connection, which makes it the one worth filtering on.
          { name: '[Multiplier]', value: 2 ** windowScale, generated: true, abbrev: 'tcp.options.wscale.multiplier' },
        ],
      });
    } else if (kind === 4 && length === 2) {
      sackPermitted = true;
      infoParts.push('SACK_PERM');
      fields.push({
        name: 'TCP Option - SACK Permitted',
        value: 'True',
        rawBytesRange: [offset, offset + length - 1],
        abbrev: 'tcp.options.sack_perm',
        children: optionHeader(offset, kind, length),
      });
    } else if (kind === 5) {
      const blockCount = Math.floor((length - 2) / 8);
      const blockRows: ProtocolField[] = [];
      for (let i = 0; i < blockCount; i++) {
        const blockOffset = offset + 2 + i * 8;
        const leftEdge = ((rawBytes[blockOffset] << 24) | (rawBytes[blockOffset + 1] << 16) | (rawBytes[blockOffset + 2] << 8) | rawBytes[blockOffset + 3]) >>> 0;
        const rightEdge = ((rawBytes[blockOffset + 4] << 24) | (rawBytes[blockOffset + 5] << 16) | (rawBytes[blockOffset + 6] << 8) | rawBytes[blockOffset + 7]) >>> 0;
        sackBlocks.push({ leftEdge, rightEdge });
        // **RFC 2883 D-SACK: the FIRST block only, and only when it reports
        // data the receiver has already acknowledged.** Either it sits at or
        // below the cumulative ACK - "I got that again" - or it is contained
        // within the second block, which is how a D-SACK is reported when
        // there is also a genuine hole. Both tests are on the raw sequence
        // space, which is what the option carries.
        //
        // It says something no other field does: the sender retransmitted
        // something that had already arrived, so the loss it reacted to was
        // not loss. That is a spurious retransmission, and it is the
        // difference between a lossy path and an impatient timer.
        const isDsack = i === 0 && (
          seqLessOrEqual(rightEdge, ackNumber)
          || (blockCount > 1 && isContainedInSecondBlock(rawBytes, offset, leftEdge, rightEdge))
        );
        blockRows.push({
          name: isDsack ? 'D-SACK Sequence' : `TCP SACK Block ${i + 1}`,
          value: `${leftEdge}-${rightEdge}`,
          abbrev: isDsack ? 'tcp.options.sack.dsack' : undefined,
          rawBytesRange: [blockOffset, blockOffset + 7],
          children: [
            // **Named, and absolute.** The Info column maps these to relative
            // numbers against the peer's base sequence; the tree cannot,
            // because the option is parsed before the base is in scope here.
            // Absolute-and-named beats relative-and-unnameable: a filter can
            // reach them now, and the Info line still reads as Wireshark's.
            {
              name: isDsack ? 'D-SACK left edge' : 'left edge', value: leftEdge,
              abbrev: isDsack ? 'tcp.options.sack.dsack_le' : 'tcp.options.sack_le',
              rawBytesRange: [blockOffset, blockOffset + 3],
            },
            {
              name: isDsack ? 'D-SACK right edge' : 'right edge', value: rightEdge,
              abbrev: isDsack ? 'tcp.options.sack.dsack_re' : 'tcp.options.sack_re',
              rawBytesRange: [blockOffset + 4, blockOffset + 7],
            },
          ],
        });
      }
      fields.push({
        name: 'TCP Option - SACK',
        value: blockRows.map((row) => row.value).join(' '),
        abbrev: 'tcp.options.sack',
        rawBytesRange: [offset, offset + length - 1],
        children: [
          ...optionHeader(offset, kind, length),
          { name: 'TCP SACK Count', value: blockCount, generated: true, abbrev: 'tcp.options.sack.count' },
          ...blockRows,
        ],
      });
    } else if (kind === 8 && length === 10) {
      tsval = ((rawBytes[offset + 2] << 24) | (rawBytes[offset + 3] << 16) | (rawBytes[offset + 4] << 8) | rawBytes[offset + 5]) >>> 0;
      tsecr = ((rawBytes[offset + 6] << 24) | (rawBytes[offset + 7] << 16) | (rawBytes[offset + 8] << 8) | rawBytes[offset + 9]) >>> 0;
      fields.push({
        name: 'TCP Option - Timestamps',
        value: `TSval ${tsval}, TSecr ${tsecr}`,
        rawBytesRange: [offset, offset + length - 1],
        abbrev: 'tcp.options.timestamp.tsval',
        children: [
          ...optionHeader(offset, kind, length),
          // **TSecr had no field of its own.** It was decoded, rendered into
          // the string above, returned from here, and consumed by nothing -
          // which is also why the RTT it gives away for free was never taken.
          { name: 'Timestamp echo reply', value: tsecr, abbrev: 'tcp.options.timestamp.tsecr', rawBytesRange: [offset + 6, offset + 9] },
        ],
      });
    } else {
      fields.push({
        name: `TCP Option - Unknown (Kind ${kind})`,
        value: `${length} bytes`,
        rawBytesRange: [offset, offset + length - 1],
        children: optionHeader(offset, kind, length),
      });
    }

    offset += length;
  }

  return { fields, mss, windowScale, sackPermitted, sackBlocks, infoParts, tsval, tsecr };
}

/** The [SEQ/ACK analysis] subtree, as Wireshark lays it out. */
function tcpAnalysisFields(a: TcpAnalysis): ProtocolField[] {
  const children: ProtocolField[] = [];
  if (a.ackOfFrame !== undefined) {
    children.push({ name: '[This is an ACK to the segment in frame]', value: a.ackOfFrame, generated: true, linkToFrame: a.ackOfFrame, abbrev: 'tcp.analysis.acks_frame' });
    children.push({ name: '[The RTT to ACK the segment was]', value: `${((a.ackRttUs ?? 0) / 1e6).toFixed(9)} seconds`, generated: true, abbrev: 'tcp.analysis.ack_rtt' });
  }
  if (a.initialRttUs !== undefined) {
    children.push({ name: '[iRTT]', value: `${(a.initialRttUs / 1e6).toFixed(9)} seconds`, generated: true, abbrev: 'tcp.analysis.initial_rtt' });
  }
  if (a.bytesInFlight !== undefined) {
    children.push({ name: '[Bytes in flight]', value: a.bytesInFlight, generated: true, abbrev: 'tcp.analysis.bytes_in_flight' });
  }
  if (a.pushBytesSent !== undefined) {
    children.push({ name: '[Bytes sent since last PSH flag]', value: a.pushBytesSent, generated: true, abbrev: 'tcp.analysis.push_bytes_sent' });
  }
  // **Computed since this analysis was written and never drawn.** `rtoUs` and
  // `rtoFrame` come out of `checkSequence` on a retransmission and went
  // straight into the bin; the reference shows both, and the frame number is
  // what makes the interval mean anything.
  if (a.rtoUs !== undefined) {
    children.push({ name: '[The RTO for this segment was]', value: `${(a.rtoUs / 1e6).toFixed(9)} seconds`, generated: true, abbrev: 'tcp.analysis.rto' });
  }
  if (a.rtoFrame !== undefined) {
    children.push({ name: '[RTO based on delta from frame]', value: a.rtoFrame, generated: true, linkToFrame: a.rtoFrame, abbrev: 'tcp.analysis.rto_frame' });
  }
  if (a.flags.length > 0) {
    // The flag decides the category (`dissect/tcpAnalysis.ts`), which is where
    // "the sniffer missed frames" finally stops being filed as network loss.
    const categoryOf = (flag: string): ExpertCategory =>
      CATEGORY_BY_FLAG[flag as keyof typeof CATEGORY_BY_FLAG] ?? 'Note';
    children.push({
      name: '[TCP Analysis Flags]', value: '', generated: true, abbrev: 'tcp.analysis.flags',
      children: a.tags.map((tag, i) => {
        const flag = a.flags[i] ?? '';
        const category = categoryOf(flag);
        return {
          name: `[Expert Info (${category})]`,
          value: tag.replace(/^\[TCP |\]$/g, ''), generated: true,
          // **The verdict's own name.** These fifteen were computed check for
          // check against Wireshark's algorithm and published only into a
          // string array, so the row that states one could not say which
          // field it was - and `tcp.analysis.retransmission` was a filter
          // that worked for a name that did not exist.
          ...(flag in ABBREV_BY_FLAG
            ? { abbrev: ABBREV_BY_FLAG[flag as TcpAnalysisFlag] }
            : {}),
          expertInfo: { category, message: tag },
        };
      }),
    });
  }
  if (children.length === 0) return [];
  return [{ name: '[SEQ/ACK analysis]', value: '', generated: true, abbrev: 'tcp.analysis', children }];
}

function tcpFlagFields(rawBytes: Uint8Array, transportOffset: number): ProtocolField[] {
  // The 12 drawn bits as one number, so each row can read its own bits out of
  // it without repeating the mid-byte window arithmetic.
  const window12 = ((rawBytes[transportOffset + 12] & 0x0f) << 8) | rawBytes[transportOffset + 13];

  return [...TCP_FLAG_ROWS.map(row => {
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
  }),
  // Last, as the reference draws it: the summary is read after the bits it
  // summarises, and putting it first would push the twelve rows down a line
  // for a string that only repeats them.
  {
    name: 'TCP Flags',
    value: tcpFlagsString(window12),
    abbrev: 'tcp.flags.str',
    rawBytesRange: [transportOffset + 12, transportOffset + 13] as [number, number],
  }];
}

/**
 * `a <= b` in TCP's 32-bit sequence space, which wraps.
 *
 * A plain `<=` is wrong across the wrap: a sequence just past 2^32 is a small
 * number, and comparing it to a large one reads as far behind rather than
 * just ahead. The signed difference is the standard answer (RFC 1982) and is
 * what `tcpAnalysis.ts` uses for the same reason.
 */
function seqLessOrEqual(a: number, b: number): boolean {
  return ((a - b) | 0) <= 0;
}

/**
 * Whether the first SACK block sits inside the second.
 *
 * RFC 2883's other D-SACK form: when there is also a genuine hole, the
 * duplicate is reported as a first block contained within the second, which
 * is otherwise a nonsense ordering - SACK blocks are not required to be
 * sorted, but a block inside another says something no ordinary SACK does.
 */
function isContainedInSecondBlock(
  rawBytes: Uint8Array, optionOffset: number, leftEdge: number, rightEdge: number,
): boolean {
  const at = optionOffset + 10;
  if (at + 7 >= rawBytes.length) return false;
  const secondLeft = ((rawBytes[at] << 24) | (rawBytes[at + 1] << 16) | (rawBytes[at + 2] << 8) | rawBytes[at + 3]) >>> 0;
  const secondRight = ((rawBytes[at + 4] << 24) | (rawBytes[at + 5] << 16) | (rawBytes[at + 6] << 8) | rawBytes[at + 7]) >>> 0;
  return seqLessOrEqual(secondLeft, leftEdge) && seqLessOrEqual(rightEdge, secondRight);
}

/**
 * The reference's `tcp.connection.*` rows: what this frame does to the
 * connection, rather than which bits it has set.
 *
 * All `FT_NONE` in the reference's dictionary - presence IS the value - so
 * each is drawn only on the frame it is true of, and a filter naming one
 * matches exactly those frames.
 *
 * A SYN with ACK is the acknowledge and not a second request, which is why
 * the first two are exclusive rather than both firing on a SYN-ACK.
 */
function connectionRows(
  syn: boolean, ack: boolean, fin: boolean, rst: boolean,
  finRole: 'active' | 'passive' | undefined,
): ProtocolField[] {
  const rows: ProtocolField[] = [];
  if (syn && !ack) rows.push({ name: '[Connection establish request (SYN)]', value: true, generated: true, abbrev: 'tcp.connection.syn' });
  if (syn && ack) rows.push({ name: '[Connection establish acknowledge (SYN+ACK)]', value: true, generated: true, abbrev: 'tcp.connection.synack' });
  if (fin) {
    rows.push({ name: '[Connection finish (FIN)]', value: true, generated: true, abbrev: 'tcp.connection.fin' });
    if (finRole === 'active') {
      rows.push({ name: '[This frame initiates the connection closing]', value: true, generated: true, abbrev: 'tcp.connection.fin_active' });
    } else if (finRole === 'passive') {
      rows.push({ name: '[This frame undergoes the connection closing]', value: true, generated: true, abbrev: 'tcp.connection.fin_passive' });
    }
  }
  if (rst) rows.push({ name: '[Connection reset (RST)]', value: true, generated: true, abbrev: 'tcp.connection.rst' });
  return rows;
}

/**
 * The reference's `[N Reassembled TCP Segments]` subtree, one per PDU this
 * frame completed.
 *
 * Every number here was already tracked - `TlsRecordCursor.contributions`
 * has carried `{frame, bytes}` since records were first followed across
 * segments. What was missing is that each contributor becomes its own row
 * with `linkToFrame`, so the frames that carried a PDU are reachable rather
 * than merely listed.
 *
 * Byte OFFSETS are computed by running sum rather than stored, which is safe
 * for the one reason worth stating: contributions are appended in arrival
 * order and a record is only completed once, so the sum is the same walk the
 * reassembly itself did.
 */
function reassemblyRows(reassemblies: TcpReassembly[] | undefined): ProtocolField[] {
  if (reassemblies === undefined || reassemblies.length === 0) return [];
  return reassemblies.map((pdu) => {
    let at = 0;
    const segments: ProtocolField[] = pdu.contributions.map((c) => {
      const row: ProtocolField = {
        name: `Frame: ${c.frame}, payload: ${at}-${at + c.bytes - 1} (${c.bytes} bytes)`,
        value: c.frame,
        abbrev: 'tcp.segment',
        generated: true,
        linkToFrame: c.frame,
      };
      at += c.bytes;
      return row;
    });
    const summary = pdu.contributions.map((c) => `#${c.frame}(${c.bytes})`).join(', ');
    return {
      name: `[${pdu.contributions.length} Reassembled TCP Segments (${pdu.length} bytes)]`,
      value: summary,
      abbrev: 'tcp.segments',
      generated: true,
      children: [
        ...segments,
        { name: 'Segment count', value: pdu.contributions.length, generated: true, abbrev: 'tcp.segment.count' },
        { name: 'Reassembled TCP length', value: pdu.length, generated: true, abbrev: 'tcp.reassembled.length' },
      ],
    };
  });
}
