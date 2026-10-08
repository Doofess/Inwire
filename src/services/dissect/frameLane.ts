/**
 * Which lane a frame is dissected on, decided from its headers alone - the
 * Sequencer's half of ADR 0053 phase 3, built and held to the dissector in
 * phase 2 before anything is sharded on it.
 *
 * Dissection on several cores keeps one SEQUENTIAL lane, which is today's
 * code exactly, and adds TCP shards. A frame may go to a shard only if
 * everything it would number across conversations is known before it is
 * dissected, so the Sequencer can hand the numbers out in frame order and the
 * shard can be told them. For a plain TCP segment that is three things - its
 * MAC pair's `eth.stream`, its address pair's `ip.stream`/`ipv6.stream`, and
 * its connection's place in the TCP order - and this reads them out of the
 * headers with the dissector's own formatters, so the strings are the ones the
 * trackers are asked with.
 *
 * **Wrong in only one direction, on purpose.** A frame sent to a shard that
 * the dissector then numbered differently would be a wrong tree, silently; a
 * TCP segment left on the sequential lane only costs speed. So everything
 * that is not a plain segment stays: anything under a tunnel, an IP fragment,
 * IPv6 with extension headers, QinQ, a link type that is not Ethernet, and any
 * frame whose headers the capture cut. `scripts/pipeline/sequencer.ts` holds
 * every frame of the fixtures and the burst to that: for each frame this sends
 * to the TCP lane, the calls the dissection made to the cross-conversation
 * numbering must be exactly the ones read here.
 *
 * **A fragment of a TCP datagram is a barrier.** Its ports are in the first
 * fragment only, and which connection it belongs to is known when the last one
 * reassembles it - so it cannot be numbered ahead. `fragmentOf` says so, and
 * the lane carries what the headers do say - the addresses, the datagram, and
 * on the first fragment the connection - which is what the coordinator routes
 * it by and holds later frames back on until it is done (ADR 0053 phase 3).
 */
import { formatIpv4Address, formatIpv6Address, formatMacAt } from '../addressFormat';
import { LINKTYPE } from './types';
import { tcpConnectionKey } from './sequencer';

/** A frame the Sequencer can number ahead of dissection: one plain TCP segment. */
export interface TcpLane {
  lane: 'tcp';
  srcMac: string;
  dstMac: string;
  family: 'ip' | 'ipv6';
  src: string;
  dst: string;
  srcPort: number;
  dstPort: number;
  /** The connection, as `TcpStreamTracker` keys it (`tcpConnectionKey`). */
  key: string;
  /** The unordered address pair: what a shard is chosen by. */
  pair: string;
}

/** Everything else, dissected in frame order on the sequential lane. */
export interface SequentialLane {
  lane: 'sequential';
  /** An IP fragment of a TCP datagram: a barrier for its address pair in phase 3. */
  fragmentOf?: 'tcp';
}

/**
 * An IP fragment of a TCP datagram, with what its headers DO say: its MAC and
 * address pairs, which datagram it is part of, and - on the first fragment,
 * which carries the TCP header - the connection. Phase 3 dissects it on the
 * shard that holds the connection, as a barrier (`pipeline/coordinator.ts`).
 */
export interface TcpFragmentLane extends SequentialLane {
  fragmentOf: 'tcp';
  srcMac: string;
  dstMac: string;
  family: 'ip' | 'ipv6';
  src: string;
  dst: string;
  pair: string;
  /** The datagram: family, both addresses and the identification field. */
  datagram: string;
  /** The connection, read from the first fragment's TCP header; absent on any other. */
  key?: string;
}

export type FrameLane = TcpLane | SequentialLane | TcpFragmentLane;

const SEQUENTIAL: SequentialLane = { lane: 'sequential' };

function tcpFragment(
  bytes: Uint8Array, family: 'ip' | 'ipv6', src: string, dst: string, identification: number, tcpAt: number | null,
): TcpFragmentLane {
  const key = tcpAt !== null && bytes.length >= tcpAt + 4
    ? tcpConnectionKey(src, (bytes[tcpAt] << 8) | bytes[tcpAt + 1], dst, (bytes[tcpAt + 2] << 8) | bytes[tcpAt + 3]).key
    : undefined;
  return {
    lane: 'sequential',
    fragmentOf: 'tcp',
    srcMac: formatMacAt(bytes, 6),
    dstMac: formatMacAt(bytes, 0),
    family,
    src,
    dst,
    pair: src < dst ? `${src}|${dst}` : `${dst}|${src}`,
    datagram: `${family}|${src}|${dst}|${identification}`,
    ...(key !== undefined ? { key } : {}),
  };
}

/** Whether a lane is a TCP fragment, and so carries its addresses. */
export function isTcpFragment(lane: FrameLane): lane is TcpFragmentLane {
  return lane.lane === 'sequential' && lane.fragmentOf === 'tcp';
}

/**
 * The lane for one captured frame. `bytes` is what the capture kept; a frame
 * cut inside its headers is sequential, which is what its dissection would
 * have to be too.
 */
export function frameLane(bytes: Uint8Array, linktype: number): FrameLane {
  if (linktype !== LINKTYPE.ETHERNET || bytes.length < 14) return SEQUENTIAL;
  let etherType = (bytes[12] << 8) | bytes[13];
  let l3 = 14;
  // One 802.1Q tag, as the link layer reads it (`stripVlanTags`). Stacked and
  // 802.1ad tags are left to the sequential lane rather than read twice.
  if (etherType === 0x8100) {
    if (bytes.length < 18) return SEQUENTIAL;
    etherType = (bytes[16] << 8) | bytes[17];
    l3 = 18;
    if (etherType === 0x8100 || etherType === 0x88a8) return SEQUENTIAL;
  }

  let family: 'ip' | 'ipv6';
  let src: string;
  let dst: string;
  let tcp: number;
  if (etherType === 0x0800) {
    if (bytes.length < l3 + 20 || (bytes[l3] >> 4) !== 4) return SEQUENTIAL;
    const headerLength = (bytes[l3] & 0x0f) * 4;
    if (headerLength < 20) return SEQUENTIAL;
    const protocol = bytes[l3 + 9];
    const flagsAndOffset = (bytes[l3 + 6] << 8) | bytes[l3 + 7];
    const fragment = (flagsAndOffset & 0x2000) !== 0 || (flagsAndOffset & 0x1fff) !== 0;
    if (fragment) {
      if (protocol !== 6) return SEQUENTIAL;
      return tcpFragment(
        bytes, 'ip', formatIpv4Address(bytes, l3 + 12), formatIpv4Address(bytes, l3 + 16),
        (bytes[l3 + 4] << 8) | bytes[l3 + 5], (flagsAndOffset & 0x1fff) === 0 ? l3 + headerLength : null,
      );
    }
    if (protocol !== 6) return SEQUENTIAL;
    family = 'ip';
    src = formatIpv4Address(bytes, l3 + 12);
    dst = formatIpv4Address(bytes, l3 + 16);
    tcp = l3 + headerLength;
  } else if (etherType === 0x86dd) {
    if (bytes.length < l3 + 40 || (bytes[l3] >> 4) !== 6) return SEQUENTIAL;
    const nextHeader = bytes[l3 + 6];
    // An IPv6 fragment header, first in the chain: the same barrier.
    if (nextHeader === 44) {
      if (bytes.length < l3 + 48 || bytes[l3 + 40] !== 6) return SEQUENTIAL;
      const offset = ((bytes[l3 + 42] << 8) | bytes[l3 + 43]) >> 3;
      const identification = ((bytes[l3 + 44] << 24) | (bytes[l3 + 45] << 16) | (bytes[l3 + 46] << 8) | bytes[l3 + 47]) >>> 0;
      return tcpFragment(
        bytes, 'ipv6', formatIpv6Address(bytes, l3 + 8), formatIpv6Address(bytes, l3 + 24),
        identification, offset === 0 ? l3 + 48 : null,
      );
    }
    if (nextHeader !== 6) return SEQUENTIAL;
    // A zero payload length with bytes after the header is a jumbogram, or a
    // malformed one; the network layer reads it apart (`isMalformedJumbo`).
    if (((bytes[l3 + 4] << 8) | bytes[l3 + 5]) === 0) return SEQUENTIAL;
    family = 'ipv6';
    src = formatIpv6Address(bytes, l3 + 8);
    dst = formatIpv6Address(bytes, l3 + 24);
    tcp = l3 + 40;
  } else {
    return SEQUENTIAL;
  }

  // The whole fixed TCP header, as `decodeTransportLayer` requires before it
  // hands the segment to TCP at all.
  if (bytes.length < tcp + 20) return SEQUENTIAL;
  const srcPort = (bytes[tcp] << 8) | bytes[tcp + 1];
  const dstPort = (bytes[tcp + 2] << 8) | bytes[tcp + 3];
  return {
    lane: 'tcp',
    srcMac: formatMacAt(bytes, 6),
    dstMac: formatMacAt(bytes, 0),
    family,
    src,
    dst,
    srcPort,
    dstPort,
    key: tcpConnectionKey(src, srcPort, dst, dstPort).key,
    pair: src < dst ? `${src}|${dst}` : `${dst}|${src}`,
  };
}
