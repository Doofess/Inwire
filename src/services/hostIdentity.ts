/**
 * Which machine a capture was taken on, worked out from the capture itself.
 *
 * A live capture never needs this: the agent is running on the machine and
 * says which MAC and which addresses the adapter has. An imported file has no
 * agent, and the frames are all there is - so either direction is unavailable
 * for every imported capture, or it is inferred.
 *
 * Inferring it is very tractable, because a capturing host and everything else
 * on its segment leave different traces, and they differ by a lot rather than
 * a little. Measured over `test/fixtures/inwire_capture_1788478187989.pcap`,
 * comparing the two MACs that account for 99.6% of its frames:
 *
 * |                          | the host  | the gateway |
 * |--------------------------|-----------|-------------|
 * | distinct source IPs      | 1         | 77          |
 * | TTLs                     | 128/255/1 | 55, 54, 101 |
 * | frames over 1514 bytes   | 315       | 0           |
 * | LLDP naming its own MAC  | yes       | no          |
 *
 * Every one of those separates cleanly, which is what makes a weighted score
 * honest rather than a coin toss dressed up. They are also independent - a
 * router's TTLs are decremented *because* it routed, and it sees many source
 * addresses *because* it routed, but a NAT box, a bridge and a mirror port
 * fail them differently - so agreement between several is worth much more than
 * any one of them.
 *
 * ## The strongest signal is one Windows gives away for free
 *
 * Windows runs an LLDP agent, and its LLDPDU carries a chassis id (the machine
 * name) and a port id which is *the sending adapter's own MAC*. A frame whose
 * LLDP port id equals its own source MAC is a machine introducing itself, and
 * that is as close to being told as an imported capture gets. The fixture has
 * exactly one such frame, and it names `ROTEM` and `04:7c:16:52:db:17`.
 *
 * This also corrects an assumption worth writing down: an LLDP frame in a
 * capture is *not* necessarily a switch. Treating that one as a neighbour
 * would have labelled the capturing host as its own upstream device.
 *
 * ## What it refuses to do
 *
 * It never returns a host it is not reasonably sure of, and it never hides how
 * sure it is. `confidence` and `basis` travel with the answer so the packet
 * list can mark inferred arrows and say what the inference went on - the same
 * discipline Follow Stream applies to its first-speaker guess. A user can
 * override, and then this is not consulted at all.
 */
import type { Packet } from '../types/packet';
import { fieldValue } from './dissect/fieldAccess';
import type { HostIdentity } from './direction';
import type { AgentAdapter } from './agentProtocol';

/**
 * How many frames the scoring pass reads.
 *
 * The signals are all frequency ratios, so they converge quickly - the fixture
 * separates its two candidates within the first couple of thousand frames -
 * and reading more only costs time. A capture shorter than this is read whole.
 */
export const SCORING_FRAMES = 20_000;

/** Below this the answer is offered but marked, above it it is presented plainly. */
export const CONFIDENT_AT = 0.6;

/** TTL and hop-limit values a stack starts at. A frame at one has not been routed. */
const INITIAL_TTLS = new Set([32, 64, 128, 255]);

const ETHERNET_MAX_FRAME = 1514;
const BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff';
const ZERO_MAC = '00:00:00:00:00:00';

interface Candidate {
  mac: string;
  /** Frames sent from this MAC. The denominator for every ratio below. */
  sent: number;
  /** Source addresses seen behind it. One means an endpoint; many mean a router. */
  sources: Set<string>;
  /** Frames whose TTL was still at a stack's initial value. */
  initialTtl: number;
  /** Frames with a TTL that has been decremented at least once. */
  routedTtl: number;
  /** Frames too large for the link, which only a sending NIC produces. */
  offloaded: number;
  /** This MAC advertised itself over LLDP. Near-conclusive. */
  selfLldp: boolean;
  /** This MAC appeared as a DHCP client. Only an endpoint asks for a lease. */
  dhcpClient: boolean;
  /** ARP requests sent. An endpoint asks; a router mostly answers. */
  arpRequests: number;
}

function candidate(mac: string): Candidate {
  return {
    mac, sent: 0, sources: new Set(), initialTtl: 0, routedTtl: 0,
    offloaded: 0, selfLldp: false, dhcpClient: false, arpRequests: 0,
  };
}

/**
 * The weights, and why they are ordered this way.
 *
 * Not tuned to make the fixture come out right - the fixture separates on
 * every signal, so any positive weighting produces the same winner there.
 * They are ordered by how hard each one is to be wrong about:
 *
 * - **self-LLDP** is a machine stating its own identity. Nothing else comes
 *   close, so it is worth more than everything else put together.
 * - **DHCP client** is nearly as good; a router does not ask its own segment
 *   for a lease, though it may relay one, which is why it is not conclusive.
 * - **initial TTLs** is the workhorse. It is a ratio, so a busy router cannot
 *   out-vote a quiet host by volume.
 * - **one source address** distinguishes an endpoint from anything forwarding.
 * - **offload** is a strong positive but a weak negative: a host that never
 *   sent a large frame is not thereby a router.
 * - **ARP requests** is the weakest and is worth little on its own.
 */
const WEIGHTS = {
  selfLldp: 1.0, dhcpClient: 0.55, initialTtl: 0.35,
  singleSource: 0.25, offload: 0.2, arp: 0.05,
};

function scoreOf(c: Candidate): number {
  let score = 0;
  if (c.selfLldp) score += WEIGHTS.selfLldp;
  if (c.dhcpClient) score += WEIGHTS.dhcpClient;

  const ttlSeen = c.initialTtl + c.routedTtl;
  if (ttlSeen > 0) {
    // Centred on zero rather than running 0..1, so a MAC whose traffic is
    // overwhelmingly routed is pushed *down* rather than merely not helped.
    // Without that, a busy gateway scores well on volume alone.
    score += WEIGHTS.initialTtl * ((c.initialTtl - c.routedTtl) / ttlSeen);
  }
  if (c.sources.size === 1) score += WEIGHTS.singleSource;
  else if (c.sources.size > 4) score -= WEIGHTS.singleSource;

  if (c.offloaded > 0) score += WEIGHTS.offload;
  if (c.arpRequests > 0) score += WEIGHTS.arp;
  return score;
}

function describe(c: Candidate): string {
  const parts: string[] = [];
  if (c.selfLldp) parts.push('it advertises itself over LLDP');
  if (c.dhcpClient) parts.push('it asked for a DHCP lease');
  const ttlSeen = c.initialTtl + c.routedTtl;
  if (ttlSeen > 0 && c.initialTtl > c.routedTtl) {
    parts.push(`${Math.round((c.initialTtl / ttlSeen) * 100)}% of its frames carry an initial TTL`);
  }
  if (c.sources.size === 1) parts.push('it sends from one address');
  if (c.offloaded > 0) parts.push(`${c.offloaded} frames exceed the MTU (send-side offload)`);
  return parts.length > 0 ? parts.join(', ') : 'it sends most of the traffic';
}

function readMac(packet: Packet, key: 'eth.src' | 'eth.dst'): string | undefined {
  const value = fieldValue(packet, key);
  return typeof value === 'string' && value !== ZERO_MAC ? value : undefined;
}

function isGroupMac(mac: string): boolean {
  if (mac === BROADCAST_MAC) return true;
  const first = parseInt(mac.slice(0, 2), 16);
  return Number.isFinite(first) && (first & 0x01) === 1;
}

/**
 * Reads a capture and decides which MAC belongs to the machine that took it.
 *
 * Returns `null` when nothing scored well enough to be worth offering, which
 * is the right answer for a capture taken on a span port or a file that is all
 * one direction. A null here means the Direction column reads `·` and says so,
 * rather than picking whichever MAC happened to send the most frames.
 */
export function inferHostIdentity(packets: readonly Packet[]): HostIdentity | null {
  const candidates = new Map<string, Candidate>();
  const addressesByMac = new Map<string, Set<string>>();
  const limit = Math.min(packets.length, SCORING_FRAMES);

  for (let i = 0; i < limit; i++) {
    const packet = packets[i];
    const srcMac = readMac(packet, 'eth.src');
    if (srcMac === undefined || isGroupMac(srcMac)) continue;

    let c = candidates.get(srcMac);
    if (c === undefined) { c = candidate(srcMac); candidates.set(srcMac, c); }
    c.sent++;

    const protocols = packet.frameProtocols ?? [];
    // The registered address fields, not `Packet.source`. `source` is a
    // rendering: for a pure-L2 frame it holds a resolved MAC name, and for a
    // frame with name resolution on it can hold a hostname - neither of which
    // is an address, and counting either would make an ARP-heavy endpoint look
    // like it sends from several.
    const source = fieldValue(packet, 'ip.src') ?? fieldValue(packet, 'ipv6.src');
    if (typeof source === 'string' && source.length > 0) {
      c.sources.add(source);
      let addresses = addressesByMac.get(srcMac);
      if (addresses === undefined) { addresses = new Set(); addressesByMac.set(srcMac, addresses); }
      addresses.add(source);
    }

    const ttl = fieldValue(packet, 'ip.ttl') ?? fieldValue(packet, 'ipv6.hlim');
    if (typeof ttl === 'number') {
      if (INITIAL_TTLS.has(ttl)) c.initialTtl++;
      // A TTL of 1 is a link-local multicast that was never meant to be
      // routed, not a packet that has crossed 127 hops. Counting it as routed
      // would penalise exactly the mDNS and SSDP an endpoint emits.
      else if (ttl > 1) c.routedTtl++;
    }

    if (packet.length > ETHERNET_MAX_FRAME) c.offloaded++;
    if (protocols.includes('arp') && fieldValue(packet, 'arp.opcode') === 1) c.arpRequests++;
    if (protocols.includes('dhcp') || protocols.includes('bootp')) {
      // Only the client half. A server's ACK carries the client's MAC too, so
      // matching on the field alone would nominate the DHCP server.
      const clientMac = fieldValue(packet, 'dhcp.hw.mac_addr');
      if (typeof clientMac === 'string' && clientMac === srcMac) c.dhcpClient = true;
    }
    if (protocols.includes('lldp')) {
      // A machine introducing itself: the port it is advertising is the port
      // it is speaking from. A switch's LLDPDU names the switch's own port,
      // which is not the MAC the frame was sent from on this segment.
      const portId = fieldValue(packet, 'lldp.port.id');
      if (typeof portId === 'string' && portId.toLowerCase() === srcMac) c.selfLldp = true;
    }
  }

  if (candidates.size === 0) return null;

  const ranked = [...candidates.values()]
    // A MAC that sent a handful of frames has not shown enough of itself to be
    // scored; its ratios are noise. Below this it cannot win, but it is still
    // counted so the winner's margin is measured against real competition.
    //
    // Self-LLDP and a DHCP request are exempt, and the exemption is the point
    // of the floor rather than a hole in it: the floor exists because *ratios*
    // need a sample, and those two are not ratios. They are a machine stating
    // its own identity, and one such frame says as much as a thousand would.
    // A laptop that joins a network and is captured for ten seconds sends
    // exactly one DHCP Request.
    .filter((c) => c.sent >= 8 || c.selfLldp || c.dhcpClient)
    .sort((a, b) => scoreOf(b) - scoreOf(a));
  if (ranked.length === 0) return null;

  const best = ranked[0];
  const bestScore = scoreOf(best);
  if (bestScore <= 0) return null;

  // The margin matters as much as the score. Two MACs that both look like
  // endpoints - a capture from a bridge, or two adapters on one machine -
  // should not produce a confident answer for whichever edged ahead.
  const runnerUp = ranked.length > 1 ? Math.max(0, scoreOf(ranked[1])) : 0;
  const margin = bestScore / (bestScore + runnerUp);
  const confidence = Math.min(1, Math.max(0, bestScore / 1.6)) * margin;

  return {
    macs: new Set([best.mac]),
    addresses: addressesByMac.get(best.mac) ?? new Set(),
    inferred: true,
    confidence,
    basis: describe(best),
  };
}

/**
 * The identity the agent reported, which is knowledge rather than inference.
 *
 * Every adapter is folded in, not only the ones being captured on, and that is
 * the more correct reading rather than a shortcut: a frame captured on the
 * Ethernet port whose source MAC belongs to the Wi-Fi card really did leave
 * this machine, and calling it transit because it came from the "wrong"
 * adapter would be wrong about the only thing this column claims.
 *
 * Returns null when there is nothing usable, so the caller can tell "the agent
 * has not answered yet" from "the agent answered and this machine has no
 * addresses" - the first leaves the previous identity standing, and the second
 * would be a machine that cannot have sent anything.
 */
export function hostFromAdapters(adapters: readonly AgentAdapter[]): HostIdentity | null {
  const macs = new Set<string>();
  const addresses = new Set<string>();
  for (const adapter of adapters) {
    if (adapter.mac) macs.add(adapter.mac.toLowerCase());
    for (const entry of adapter.ipv4) addresses.add(entry.address);
    for (const entry of adapter.ipv6) addresses.add(entry.address);
  }
  if (macs.size === 0 && addresses.size === 0) return null;
  return { macs, addresses, inferred: false, confidence: 1 };
}

/**
 * The identity a user chose by hand, which is never second-guessed.
 *
 * An override is not a hint to the scorer - it is the answer. Someone who has
 * told the app which machine took the capture knows something it does not, and
 * blending that with a score would produce a third answer neither of them
 * asked for.
 */
export function overrideHostIdentity(mac: string, addresses: Iterable<string> = []): HostIdentity {
  return {
    macs: new Set([mac.toLowerCase()]),
    addresses: new Set(addresses),
    inferred: true,
    confidence: 1,
    basis: 'you chose this host',
  };
}
