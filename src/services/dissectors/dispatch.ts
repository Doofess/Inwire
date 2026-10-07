/**
 * One registry for the protocols that are dispatched by a number and nothing
 * else.
 *
 * ## What this replaces, and what it deliberately does not
 *
 * Dispatch in this build grew four shapes: an `if/else if` chain on the
 * ethertype in `pcapParser.ts`, another on the IP protocol number in
 * `networkLayer.ts`, a three-way ternary in `portless.ts`, and
 * `udpDispatch.ts`'s predicate list - which was already most of the way here
 * and is the shape this generalises. Adding a protocol therefore meant
 * editing whichever of the four its number happened to live in, plus
 * `PROTOCOL_NAME_MAP`, plus `LAYERS`, plus `FIELDS`.
 *
 * A registration is one entry now, in one list, and
 * `scripts/dissect/dispatch.ts` holds the whole list to the properties the old
 * chains only had by accident.
 *
 * **Three tables, not four.** There is no leaf TCP protocol in this build - the
 * seven things that can claim a TCP payload all carry per-connection state -
 * so there is no `tcp.port` table. An empty table is a promise with no
 * customer, and the next person to want one would fill it by force.
 *
 * ## The one invariant, and why it is the whole design
 *
 * **An entry returns a `LeafResult` and nothing else, and `LeafResult` may not
 * be widened.** `TransportResult` in `dissect/types.ts` carries thirteen
 * optional members - a stream id, an embedded network to recurse into, a
 * matched frame id, resolved names, label patches - and every one of them
 * exists because some protocol needed the caller to do something afterwards.
 * `udpDispatch.ts`'s header already refused DHCP, DNS, NBNS and QUIC on
 * exactly this ground; the rule is restated here because a general table is a
 * more tempting place to break it.
 *
 * So: an entry whose dissector needs a tracker, a matched frame, a resolved
 * name or a recursion does not belong in this file. It stays where it is, in
 * a chain that can express what it needs, and this table stays a table.
 *
 * ## What is NOT on it, each for a stated reason
 *
 *   * **CDP and STP.** CDP dispatches on a SNAP protocol id *within* an OUI
 *     and STP on the LLC DSAP. Neither is an ethertype, and an `ethertype`
 *     table whose two most interesting entries ignore the ethertype is a
 *     table lying about its key.
 *   * **TCP, UDP, ICMP, ICMPv6 and GRE** in the IP-protocol chain. Every one
 *     returns ports, a stream id, an `embeddedNetwork` or a tracker's state.
 *   * **DNS, NBNS, DHCP, DHCPv6, QUIC and SSDP** on UDP, for the same reason -
 *     resolved names, a matched query frame, a flow tracker.
 *   * **The seven-stage TCP cascade.** Each stage is guarded on no earlier
 *     stage having claimed the payload, on the segment not being a keep-alive
 *     or a retransmission, and on the record cursor being in order, and TLS
 *     additionally on ciphertext never reaching the HTTP decoder. Encoding
 *     that as predicates moves the cascade into data without removing any of
 *     it.
 *   * **`HEURISTIC_DISSECTORS`.** Keyed by content rather than by a value,
 *     consulted only after port dispatch fails, and already held to a
 *     cross-product assertion of its own.
 */
import type { ProtocolLayer } from '../../types/packet';
import { dissectArp } from './l2';
import { dissectIeee1905 } from './ieee1905';
import { dissectLldp } from './lldp';
import { dissectIgmp } from './igmp';
import { dissectOspf } from './ospf';
import { dissectVrrp } from './vrrp';
import { dissectSip } from './sip';
import { dissectSnmp } from './snmp';
import { dissectSyslog } from './syslog';
import { dissectRadius } from './radius';
import { dissectTftp } from './tftp';
import { dissectNbds } from './nbds';
import { dissectBfd, dissectBfdEcho } from './bfd';
import { dissectCoap } from './coap';
import { dissectPtp } from './ptp';
import { dissectHsrp, HSRP_V1_GROUP, HSRP_V2_GROUP } from './hsrp';
import { dissectRip, dissectRipng } from './rip';
import { dissectKerberosDatagram, KERBEROS_PORT } from './kerberos';
import { dissectEapol } from './eapol';
import { dissectDropboxDiscovery, dissectPortControl } from './portControl';
import { dissectMediaType } from './mediaType';

/** The three things this build dispatches on by value. */
export type DispatchTableName = 'ethertype' | 'ip.proto' | 'udp.port';

/**
 * What every entry returns: a label, a line of info, a layer and its fields.
 *
 * `fields` is optional here and required in `SimpleUdpResult`, which is the
 * only difference between them - so every existing leaf dissector's result is
 * already a `LeafResult` without being touched.
 */
export interface LeafResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields?: Record<string, string | number>;
  /**
   * Protocols carried inside this one, each its own layer after `layer` - EAP
   * inside EAPOL, which the reference draws as a protocol of its own.
   */
  innerLayers?: ProtocolLayer[];
  /**
   * The token this frame is known by, when it is not the entry's own: one
   * port that carries two protocols - NAT-PMP and PCP on 5351 - names
   * whichever it found.
   */
  token?: string;
}

/** What an entry may look at beyond the bytes, for the one case that needs it. */
export interface DispatchContext {
  /** Both ports, for a `udp.port` entry that claims on something else too. */
  srcPort?: number;
  dstPort?: number;
  /** The datagram's destination, which is how HSRP is told from a unicast. */
  dstAddress?: string;
}

export interface DispatchEntry {
  table: DispatchTableName;
  /**
   * The values this entry claims. Empty only when `claims` decides instead,
   * which `scripts/dissect/dispatch.ts` enforces - an entry claiming nothing
   * and deciding nothing is unreachable, and would look like a registration.
   */
  values: readonly number[];
  /**
   * An extra condition, for an entry a number alone cannot identify. The one
   * caller is HSRP: a datagram on port 1985 addressed to a host is not HSRP,
   * it is somebody else using the port.
   */
  claims?(ctx: DispatchContext): boolean;
  /** The `LAYERS` token this protocol is known by. */
  token: string;
  dissect(bytes: Uint8Array, start: number, end: number): LeafResult | null;
}

/**
 * The two single-valued tables, indexed once at load.
 *
 * Safe as maps precisely because `scripts/dissect/dispatch.ts` asserts no two
 * entries in a table claim the same value, and that neither of these two uses
 * `claims` - so there is nothing for declaration order to decide.
 */
const BY_ETHERTYPE = new Map<number, DispatchEntry>();
const BY_IP_PROTO = new Map<number, DispatchEntry>();
const UDP_ENTRIES: DispatchEntry[] = [];

/** `0x0806` -> ARP. One lookup, no allocation: this runs on every frame. */
export function findEthertype(etherType: number): DispatchEntry | null {
  return BY_ETHERTYPE.get(etherType) ?? null;
}

/** `89` -> OSPF. As above, on every IP datagram. */
export function findIpProto(ipProtocolNum: number): DispatchEntry | null {
  return BY_IP_PROTO.get(ipProtocolNum) ?? null;
}

/**
 * The UDP table, scanned in declaration order.
 *
 * **Ordered rather than a map, and that is not laziness.** A datagram offers
 * two numbers and the rule this replaces was "the first entry claiming either
 * port wins"; a map would have to look one end up first, which changes the
 * answer for a datagram whose two ports are claimed by different entries.
 * Fourteen entries, reached only after the port dispatch above has declined.
 *
 * **Scalars rather than an array and a context object**, because this is a
 * per-datagram call. The first version allocated both and cost 12% of
 * dissection throughput - the table was fine, the calling convention was not.
 */
export function findUdpPort(
  srcPort: number, dstPort: number, dstAddress: string,
): DispatchEntry | null {
  for (const entry of UDP_ENTRIES) {
    if (!entry.values.includes(srcPort) && !entry.values.includes(dstPort)) continue;
    if (entry.claims !== undefined && !entry.claims({ srcPort, dstPort, dstAddress })) continue;
    return entry;
  }
  return null;
}

/** The general form, for the assertion script. Not on any hot path. */
export function findEntry(
  table: DispatchTableName, values: readonly number[], ctx: DispatchContext = {},
): DispatchEntry | null {
  if (table === 'ethertype') return findEthertype(values[0]);
  if (table === 'ip.proto') return findIpProto(values[0]);
  return findUdpPort(values[0], values[1] ?? values[0], ctx.dstAddress ?? '');
}

/** Claims a datagram or a frame carrying any of these values. */
const on = (...values: readonly number[]) => values;

/**
 * The registry.
 *
 * One list rather than three, so `findEntry` needs no table argument beyond
 * the name and the assertion script has a single thing to walk. Plain data
 * rather than a `register()` call from each dissector: a side-effect
 * registration is only as complete as the imports that happened to run, which
 * is a class of bug this file exists to end rather than to introduce.
 */
const DISPATCH_TABLE: readonly DispatchEntry[] = [
  // --- ethertype ------------------------------------------------------------
  { table: 'ethertype', values: on(0x0806), token: 'arp', dissect: (b, s) => dissectArp(b, s) },
  { table: 'ethertype', values: on(0x893a), token: 'ieee1905', dissect: (b, s) => dissectIeee1905(b, s) },
  { table: 'ethertype', values: on(0x88cc), token: 'lldp', dissect: (b, s) => dissectLldp(b, s) },
  { table: 'ethertype', values: on(0x888e), token: 'eapol', dissect: dissectEapol },

  // --- ip.proto: the three that sit on IP with no ports at all --------------
  { table: 'ip.proto', values: on(2), token: 'igmp', dissect: (b, s, e) => dissectIgmp(b, s, e - s) },
  { table: 'ip.proto', values: on(89), token: 'ospf', dissect: dissectOspf },
  { table: 'ip.proto', values: on(112), token: 'vrrp', dissect: dissectVrrp },

  // --- udp.port: the leaf protocols, in no significant order ----------------
  // A datagram matches at most one because no two claim a port in common,
  // which `scripts/dissect/dispatch.ts` asserts rather than assumes.
  { table: 'udp.port', values: on(5060, 5061), token: 'sip', dissect: dissectSip },
  { table: 'udp.port', values: on(161, 162), token: 'snmp', dissect: dissectSnmp },
  { table: 'udp.port', values: on(514), token: 'syslog', dissect: dissectSyslog },
  // 1645/1646 are the pre-standard ports a lot of kit still ships with.
  { table: 'udp.port', values: on(1812, 1813, 1645, 1646), token: 'radius', dissect: dissectRadius },
  { table: 'udp.port', values: on(69), token: 'tftp', dissect: dissectTftp },
  // The KDC answers on 88 over both transports. A datagram carries exactly one
  // message and no length prefix, which is the whole difference from the TCP
  // side in `tcpTransport.ts`.
  { table: 'udp.port', values: on(KERBEROS_PORT), token: 'kerberos', dissect: dissectKerberosDatagram },
  { table: 'udp.port', values: on(138), token: 'nbdgm', dissect: dissectNbds },
  // 4784 is multihop and carries the same control header. 3785 does NOT - it
  // is the echo port, and an echo packet has no format at all.
  { table: 'udp.port', values: on(3784, 4784), token: 'bfd', dissect: dissectBfd },
  { table: 'udp.port', values: on(3785), token: 'bfd', dissect: dissectBfdEcho },
  { table: 'udp.port', values: on(5683, 5684), token: 'coap', dissect: dissectCoap },
  { table: 'udp.port', values: on(319, 320), token: 'ptp', dissect: dissectPtp },
  {
    table: 'udp.port',
    values: on(1985, 2029),
    // The one entry that reads anything but a port. A datagram on 1985
    // addressed to a host is not HSRP - see `dissectors/hsrp.ts`.
    claims: (ctx) => ctx.dstAddress === HSRP_V1_GROUP || ctx.dstAddress === HSRP_V2_GROUP,
    token: 'hsrp',
    dissect: dissectHsrp,
  },
  { table: 'udp.port', values: on(520), token: 'rip', dissect: dissectRip },
  { table: 'udp.port', values: on(521), token: 'ripng', dissect: dissectRipng },
  { table: 'udp.port', values: on(5350, 5351), token: 'portcontrol', dissect: dissectPortControl },
  {
    table: 'udp.port', values: on(17500), token: 'db-lsp-disc',
    dissect: (b, s, e) => dissectDropboxDiscovery(b, s, e, (bytes) => dissectMediaType(bytes, 'application/json')),
  },
];

for (const entry of DISPATCH_TABLE) {
  if (entry.table === 'udp.port') { UDP_ENTRIES.push(entry); continue; }
  const index = entry.table === 'ethertype' ? BY_ETHERTYPE : BY_IP_PROTO;
  for (const value of entry.values) index.set(value, entry);
}

/** Everything registered, for the assertion script. */
export function registeredEntries(): readonly DispatchEntry[] {
  return DISPATCH_TABLE;
}
