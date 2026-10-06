/**
 * Finding a protocol by what its bytes say, not by which port they arrived on.
 *
 * Port dispatch is a convention, and the traffic that matters least respects
 * it: WebRTC media lands on whatever port ICE negotiated, peer-to-peer clients
 * pick a port at install time, and anything trying not to be noticed picks 443.
 * Wireshark solves this with heuristic dissectors tried in order, and this is
 * the same idea - it replaces a two-line `if` chain over STUN and NTP that was
 * the whole of Inwire's content-based dispatch.
 *
 * **The failure mode here is a confident wrong label**, which is worse than
 * `50000 → 50001 Len=76`: a reader who sees "SNMP" believes it. So three rules,
 * and they are the whole design:
 *
 *   1. **A detector keys on a magic number, a fixed-value field, or a
 *      self-describing length.** Never on length alone, never on "these bytes
 *      are printable". STUN's RFC 5389 cookie is the model; RADIUS declaring
 *      its own size that happens to match the datagram is the next best thing.
 *   2. **Port dispatch wins.** These run only where nothing claimed the payload
 *      already, so a protocol on its own port is never second-guessed.
 *   3. **Every detector must reject every other's payloads.** That is not a
 *      hope, it is `scripts/dissect/heuristics.ts`, which runs the whole cross
 *      product plus a corpus of real frames lifted from the parity fixtures.
 *
 * Order matters only where two detectors could both accept, which rule 3 makes
 * impossible - so the order below is by cost, cheapest first, and is not
 * load-bearing.
 */
import type { UdpAppResult } from './udpApps';
import { dissectNtp, dissectStun, looksLikeNtp, looksLikeStun } from './udpApps';
import { dissectNbns, looksLikeNbns } from './nbns';
import { dissectSnmp, looksLikeSnmp } from './snmp';
import { dissectSip, looksLikeSip } from './sip';
import { dissectRadius, looksLikeRadius } from './radius';
import { dissectSyslog, looksLikeSyslog } from './syslog';
import { dissectRtcp, looksLikeRtcp } from './rtcp';
import { dissectWireGuard, looksLikeWireGuard } from './wireguard';

export interface HeuristicDissector {
  /** The detector's name, so a match can be explained rather than just made. */
  name: string;
  /** Strictly: does this payload carry this protocol's own fingerprint? */
  looksLike: (bytes: Uint8Array, start: number, end: number) => boolean;
  /** Reads it. May still return null - a detector is a filter, not a promise. */
  dissect: (bytes: Uint8Array, start: number, end: number) => UdpAppResult | null;
}

/**
 * Adapts a dissector that returns its own result shape.
 *
 * The six protocols added since `UdpAppResult` was written return a `layer`
 * plus fields without a `token`, because their token comes from
 * `PROTOCOL_NAME_MAP`. Here the token has to be explicit, since a heuristic
 * match has no port to have been dispatched from.
 */
function adapt<T extends { protocolLabel: string; info: string; layer: UdpAppResult['layer']; fields: Record<string, string | number> }>(
  token: string,
  dissect: (bytes: Uint8Array, start: number, end: number) => T | null,
): (bytes: Uint8Array, start: number, end: number) => UdpAppResult | null {
  return (bytes, start, end) => {
    const result = dissect(bytes, start, end);
    return result === null ? null : { ...result, token };
  };
}

/**
 * The detectors, cheapest first.
 *
 * Syslog is last on purpose. Its fingerprint - `<` a number under 192 `>` - is
 * the weakest here by some distance, and while rule 3 proves it rejects the
 * others' payloads today, a detector added later is more likely to collide
 * with this one than with any of the rest.
 */
export const HEURISTIC_DISSECTORS: readonly HeuristicDissector[] = [
  { name: 'STUN', looksLike: looksLikeStun, dissect: dissectStun },
  { name: 'NTP', looksLike: looksLikeNtp, dissect: dissectNtp },
  { name: 'RADIUS', looksLike: looksLikeRadius, dissect: adapt('radius', dissectRadius) },
  { name: 'SNMP', looksLike: looksLikeSnmp, dissect: adapt('snmp', dissectSnmp) },
  { name: 'NBNS', looksLike: looksLikeNbns, dissect: adapt('nbns', dissectNbns) },
  { name: 'SIP', looksLike: looksLikeSip, dissect: adapt('sip', dissectSip) },
  { name: 'RTCP', looksLike: looksLikeRtcp, dissect: adapt('rtcp', dissectRtcp) },
  { name: 'Syslog', looksLike: looksLikeSyslog, dissect: adapt('syslog', dissectSyslog) },
  { name: 'WireGuard', looksLike: looksLikeWireGuard, dissect: dissectWireGuard },
];

export interface HeuristicMatch {
  result: UdpAppResult;
  /** Which detector claimed it. Published so a mislabel is diagnosable. */
  detector: string;
}

/**
 * Whichever of the detectors claims this payload, or null.
 *
 * Consulted only when no port dispatched it, which is how a STUN exchange on an
 * arbitrary ICE port or a syslog relay on a non-standard one stops being
 * reported as anonymous UDP.
 */
export function detectUdpPayload(bytes: Uint8Array, start: number, end: number): HeuristicMatch | null {
  // A payload too short to carry any of these fingerprints cannot be claimed,
  // and checking once here keeps every detector from re-deriving it.
  if (end - start < 4) return null;
  for (const candidate of HEURISTIC_DISSECTORS) {
    if (!candidate.looksLike(bytes, start, end)) continue;
    const result = candidate.dissect(bytes, start, end);
    if (result !== null) return { result, detector: candidate.name };
  }
  return null;
}
