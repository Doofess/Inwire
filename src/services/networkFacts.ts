/**
 * What the capture itself says about the network it was taken on.
 *
 * The counterpart to `adapter_config`. That message says how the machine was
 * *told* to behave; this says what actually happened - which resolver was
 * really asked, which MAC really answered for the gateway, which router really
 * advertised the prefix. Putting the two side by side is the whole point of
 * the Network panel, because the interesting cases are the ones where they
 * disagree:
 *
 *   - a resolver being queried that the OS does not list (a browser with its
 *     own DNS settings, or something that has been redirected);
 *   - no plain DNS at all, but a DoH endpoint being contacted - which looks
 *     like a broken resolver until you see the second half;
 *   - a gateway MAC that is not the one the neighbour table holds, which is
 *     what ARP spoofing looks like from here.
 *
 * None of it is a lookup. Every fact is read off a frame that was going to be
 * dissected anyway, so this costs a handful of comparisons per frame and never
 * touches the network - the same rule the rest of the off-wire work follows
 * (`docs/decisions/0009-off-wire-enrichment.md`), from the other direction.
 *
 * **It lives in the Worker.** The main thread reads a posted snapshot and
 * never derives one, so a fact cannot be invented on the way to the screen.
 * It is deliberately tiny and bounded: every collection here is capped, and a
 * capture of a million frames produces the same few dozen facts a capture of
 * ten thousand does.
 */
import type { Packet } from '../types/packet';
import { fieldValue } from './dissect/fieldAccess';
import type { HostIdentity } from './direction';

/**
 * Caps. Not memory management - these are tiny - but a statement that these
 * are *facts about the network*, and a network with 200 resolvers in it is one
 * where the reading has gone wrong and a list is not the way to show it.
 */
const MAX_PER_LIST = 32;

export interface ObservedRouter {
  /** The router's link-local address: whoever actually sent the RA. */
  address: string;
  prefixes: string[];
  rdnss: string[];
  routerLifetime: number | null;
  prefixValidLifetime: number | null;
  /** "Get an address from DHCPv6" / "get everything else from DHCPv6". */
  managed: boolean;
  other: boolean;
}

export interface ObservedNeighbour {
  /** The MAC the LLDPDU actually arrived from. */
  mac: string;
  systemName: string | null;
  portId: string | null;
  portDescription: string | null;
  managementAddress: string | null;
}

export interface NetworkFacts {
  /** The MAC this machine sends off-link traffic to. */
  gatewayMac: string | null;
  /** Addresses that answered ARP for the gateway, or that RAs came from. */
  gatewayAddresses: string[];
  /** Resolvers that were actually asked something. */
  dnsServers: string[];
  /** The server in a DHCP offer or acknowledgement. */
  dhcpServer: string | null;
  router: ObservedRouter | null;
  /**
   * An LLDP neighbour, if there is one - and only if.
   *
   * Windows runs an LLDP agent, so a great many captures contain an LLDPDU
   * that is the capturing host introducing *itself*: chassis id the machine
   * name, port id its own MAC. The fixture this was built against has exactly
   * one LLDP frame and that is what it is. Reporting it as a neighbour would
   * name the machine as its own upstream switch, so a frame whose port id is
   * its own source MAC is recorded as `self` instead and never here.
   */
  neighbour: ObservedNeighbour | null;
  /** The host's own LLDP advertisement, when it made one. */
  selfAdvertisedName: string | null;
  /** Encrypted-DNS endpoints contacted: DoT by port, DoH by server name. */
  encryptedDns: string[];
}

export function emptyNetworkFacts(): NetworkFacts {
  return {
    gatewayMac: null, gatewayAddresses: [], dnsServers: [], dhcpServer: null,
    router: null, neighbour: null, selfAdvertisedName: null, encryptedDns: [],
  };
}

/** Server names that mean a browser is resolving over HTTPS rather than DNS. */
const DOH_HOSTS = [
  'dns.google', 'cloudflare-dns.com', 'mozilla.cloudflare-dns.com', 'one.one.one.one',
  'dns.quad9.net', 'doh.opendns.com', 'dns.nextdns.io', 'dns.adguard.com',
  'chrome.cloudflare-dns.com', 'doh.cleanbrowsing.org', 'dns10.quad9.net',
];

function isPrivateOrLocal(address: string): boolean {
  if (address.includes(':')) {
    const lower = address.toLowerCase();
    return lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')
      || lower === '::1';
  }
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some((n) => !Number.isFinite(n))) return false;
  const [a, b] = octets;
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168) || (a === 169 && b === 254);
}

function stringField(packet: Packet, key: string): string | null {
  const value = fieldValue(packet, key);
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function numberField(packet: Packet, key: string): number | null {
  const value = fieldValue(packet, key);
  return typeof value === 'number' ? value : null;
}

/**
 * The MAC a frame this machine sent off-link was addressed to, or null.
 *
 * The part of the forwarding fact that reads the frame, so a shard can read it
 * and the merge can count it later (`observeForwardedTo`).
 */
export function forwardingOf(packet: Packet, host: HostIdentity): string | null {
  if (host.macs.size === 0) return null;
  const srcMac = stringField(packet, 'eth.src');
  if (srcMac === null || !host.macs.has(srcMac)) return null;
  const destination = stringField(packet, 'ip.dst') ?? stringField(packet, 'ipv6.dst');
  if (destination === null || isPrivateOrLocal(destination)) return null;
  const dstMac = stringField(packet, 'eth.dst');
  if (dstMac === null || host.macs.has(dstMac)) return null;
  return dstMac;
}

/** What a TLS frame says about encrypted DNS: the destination port, address and server name. */
export interface TlsFacts { port: number | null; server: string | null; sni: string | null }

export function tlsFactsOf(packet: Packet): TlsFacts {
  return {
    port: numberField(packet, 'tcp.dstport'),
    server: stringField(packet, 'ip.dst') ?? stringField(packet, 'ipv6.dst'),
    sni: stringField(packet, 'tls.handshake.extensions_server_name'),
  };
}

/**
 * Collects the facts a capture reveals, as frames arrive.
 *
 * Stateful and incremental rather than a pass over the buffer, because it runs
 * in the Worker where there is no buffer - and because the answers are
 * monotonic. `changed` is what the Worker watches, so the main thread is told
 * when something new was learned and not once per flush.
 */
export class NetworkFactsCollector {
  private facts = emptyNetworkFacts();
  private dns = new Set<string>();
  private gateways = new Set<string>();
  private encrypted = new Set<string>();
  private dirty = false;
  /**
   * MACs this machine has sent off-link traffic to, and how often.
   *
   * A count rather than the first one seen: on a segment with more than one
   * router, or during a failover, the gateway is the one most of the traffic
   * actually goes through, and the first frame is a poor sample of that.
   */
  private forwardedTo = new Map<string, number>();
  /**
   * Addresses seen answering ARP, by the MAC that answered.
   *
   * Held for every replying host rather than only the gateway, because the
   * gateway is not known yet when most of these arrive. Only the gateway's
   * entry is ever published - this is not a neighbour table.
   */
  private arpByMac = new Map<string, string>();

  reset(): void {
    this.facts = emptyNetworkFacts();
    this.dns.clear();
    this.gateways.clear();
    this.encrypted.clear();
    this.forwardedTo.clear();
    this.arpByMac.clear();
    this.dirty = false;
  }

  /** True once, after something new was learned. Clears when read. */
  takeChanged(): boolean {
    const changed = this.dirty;
    this.dirty = false;
    return changed;
  }

  snapshot(): NetworkFacts {
    return {
      ...this.facts,
      gatewayAddresses: [...this.gateways].slice(0, MAX_PER_LIST),
      dnsServers: [...this.dns].slice(0, MAX_PER_LIST),
      encryptedDns: [...this.encrypted].slice(0, MAX_PER_LIST),
    };
  }

  observe(packet: Packet, host: HostIdentity): void {
    const protocols = packet.frameProtocols;
    if (protocols === undefined) return;

    // One pass over the chain rather than six `includes` calls. Measured, this
    // whole method costs **nothing detectable**: 18,938 frames/s with it and
    // 18,946 without, over three runs each, against a run-to-run spread of
    // ±4% (`scripts/perf/throughput.ts`). The single pass is kept because it
    // is the shape that says "dispatch on the protocol", not because it was
    // faster - it was not measurably either way, and an earlier version of
    // this comment claimed a 2.5% saving that a proper measurement disproved.
    for (let i = 0; i < protocols.length; i++) {
      switch (protocols[i]) {
        case 'dns': this.observeDns(packet, host); break;
        case 'dhcp': case 'bootp': this.observeDhcp(packet); break;
        case 'icmpv6': this.observeIcmpv6(packet); break;
        case 'arp': this.observeArp(packet); break;
        case 'lldp': this.observeLldp(packet, host); break;
        case 'tls': this.observeTls(packet); break;
        default: break;
      }
    }
    this.observeForwarding(packet, host);
  }

  /**
   * The MAC this machine hands off-link traffic to.
   *
   * Purely by elimination and without needing a routing table: a frame this
   * machine sent to an address outside every private range left the segment,
   * and whatever MAC it was addressed to is what forwarded it. Restricted to
   * frames we know we sent, or the answer would be whichever router the rest
   * of the segment uses.
   */
  private observeForwarding(packet: Packet, host: HostIdentity): void {
    const dstMac = forwardingOf(packet, host);
    if (dstMac !== null) this.observeForwardedTo(dstMac, host);
  }

  /**
   * Counts a frame `forwardingOf` found. Checks the host again: a caller that
   * read the frame elsewhere may hold an older identity than this one.
   */
  observeForwardedTo(dstMac: string, host: HostIdentity): void {
    if (host.macs.size === 0 || host.macs.has(dstMac)) return;
    const seen = (this.forwardedTo.get(dstMac) ?? 0) + 1;
    this.forwardedTo.set(dstMac, seen);
    // Only promote a MAC that is actually carrying the traffic. One frame to a
    // stray MAC - a probe, a misdirected packet - should not rename the
    // gateway, and re-deciding on every frame would churn the posted snapshot.
    if (seen < 8) return;
    let best: string | null = null;
    let bestCount = 0;
    for (const [mac, count] of this.forwardedTo) {
      if (count > bestCount) { best = mac; bestCount = count; }
    }
    if (best !== null && best !== this.facts.gatewayMac) {
      this.facts.gatewayMac = best;
      this.dirty = true;
      // The ARP reply that named it has almost certainly already gone past.
      this.adoptGatewayAddress();
    }
  }

  private observeDns(packet: Packet, host: HostIdentity): void {
    // The query, not the answer: the server is the destination of a question,
    // and recording the source of a response would add this machine's own
    // address to the list every time it answered an mDNS query.
    const port = numberField(packet, 'udp.dstport') ?? numberField(packet, 'tcp.dstport');
    if (port !== 53) return;
    const server = stringField(packet, 'ip.dst') ?? stringField(packet, 'ipv6.dst');
    if (server === null) return;
    // Multicast DNS and LLMNR are not resolvers; they are the segment
    // shouting. Listing 224.0.0.251 as a configured-looking DNS server would
    // be actively misleading beside the OS's list.
    if (server.startsWith('224.') || server.startsWith('239.')
      || server.toLowerCase().startsWith('ff0')) return;
    // Only what this machine asked. In promiscuous mode a neighbour's queries
    // are visible too, and their resolver is not ours.
    if (host.macs.size > 0) {
      const srcMac = stringField(packet, 'eth.src');
      if (srcMac !== null && !host.macs.has(srcMac)) return;
    }
    if (!this.dns.has(server) && this.dns.size < MAX_PER_LIST) {
      this.dns.add(server);
      this.dirty = true;
    }
  }

  private observeDhcp(packet: Packet): void {
    const server = stringField(packet, 'dhcp.option.dhcp_server_id');
    if (server !== null && server !== this.facts.dhcpServer) {
      this.facts.dhcpServer = server;
      this.dirty = true;
    }
  }

  private observeIcmpv6(packet: Packet): void {
    if (numberField(packet, 'icmpv6.type') !== 134) return;
    const address = packet.source;
    if (!address) return;
    const prefixes = stringField(packet, 'icmpv6.opt.prefix');
    const rdnss = stringField(packet, 'icmpv6.opt.rdnss');
    const router: ObservedRouter = {
      address,
      prefixes: prefixes ? prefixes.split(',') : [],
      rdnss: rdnss ? rdnss.split(',') : [],
      routerLifetime: numberField(packet, 'icmpv6.nd.ra.router_lifetime'),
      prefixValidLifetime: numberField(packet, 'icmpv6.opt.prefix.valid_lifetime'),
      managed: numberField(packet, 'icmpv6.nd.ra.flag.m') === 1,
      other: numberField(packet, 'icmpv6.nd.ra.flag.o') === 1,
    };
    // Replaced rather than merged: an RA is a complete statement of the
    // router's current position, and a router that has stopped advertising a
    // prefix means for it to stop being advertised.
    if (JSON.stringify(router) !== JSON.stringify(this.facts.router)) {
      this.facts.router = router;
      this.dirty = true;
    }
    if (!this.gateways.has(address) && this.gateways.size < MAX_PER_LIST) {
      this.gateways.add(address);
      this.dirty = true;
    }
  }

  private observeArp(packet: Packet): void {
    // Replies only. A request advertises the sender, which is anybody.
    if (numberField(packet, 'arp.opcode') !== 2) return;
    const address = stringField(packet, 'arp.src.proto_ipv4');
    const mac = stringField(packet, 'arp.src.hw_mac');
    if (address === null || mac === null) return;
    // Remembered against the MAC rather than matched against the gateway now,
    // because the ordering is the other way round in practice: a machine ARPs
    // for its gateway when it joins the network, long before it has sent the
    // eight off-link frames that identify which MAC is forwarding. Matching
    // only in the moment lost the gateway's IPv4 address on every capture
    // that opened with an ARP exchange, which is most of them.
    if (this.arpByMac.size < MAX_PER_LIST * 4) this.arpByMac.set(mac, address);
    this.adoptGatewayAddress();
  }

  /** Promotes the gateway MAC's known address, whenever both halves exist. */
  private adoptGatewayAddress(): void {
    const mac = this.facts.gatewayMac;
    if (mac === null) return;
    const address = this.arpByMac.get(mac);
    if (address === undefined || this.gateways.has(address)) return;
    if (this.gateways.size >= MAX_PER_LIST) return;
    this.gateways.add(address);
    this.dirty = true;
  }

  private observeLldp(packet: Packet, host: HostIdentity): void {
    const mac = stringField(packet, 'eth.src');
    if (mac === null) return;
    const portId = stringField(packet, 'lldp.port.id');
    const systemName = stringField(packet, 'lldp.tlv.system.name')
      ?? stringField(packet, 'lldp.chassis.id');

    // A machine introducing itself, not a switch. Windows runs an LLDP agent,
    // so this is common rather than exotic - the capture this was built
    // against contains exactly one LLDP frame and it is the host's own.
    const isSelf = (portId !== null && portId.toLowerCase() === mac) || host.macs.has(mac);
    if (isSelf) {
      if (systemName !== null && systemName !== this.facts.selfAdvertisedName) {
        this.facts.selfAdvertisedName = systemName;
        this.dirty = true;
      }
      return;
    }

    const neighbour: ObservedNeighbour = {
      mac,
      systemName,
      portId,
      portDescription: stringField(packet, 'lldp.port.desc'),
      managementAddress: stringField(packet, 'lldp.mgn.addr.ip4'),
    };
    if (JSON.stringify(neighbour) !== JSON.stringify(this.facts.neighbour)) {
      this.facts.neighbour = neighbour;
      this.dirty = true;
    }
  }

  private observeTls(packet: Packet): void {
    this.observeTlsFacts(tlsFactsOf(packet));
  }

  observeTlsFacts({ port, server, sni: name }: TlsFacts): void {
    // DoT has a port of its own, so it needs no name to be recognised - which
    // matters, because a DoT connection that resumes a session sends no SNI.
    if (port === 853) {
      if (server !== null) this.addEncrypted(`${server} (DoT)`);
      return;
    }
    if (name === null) return;
    const lower = name.toLowerCase();
    // A name list rather than a heuristic. "Contains dns" would catch every
    // host on dnsimple.com and every CDN edge with dns in its name, and a
    // wrong entry here reads as "your machine is resolving somewhere odd",
    // which is exactly the alarm this should not raise falsely.
    if (DOH_HOSTS.includes(lower)) this.addEncrypted(`${name} (DoH)`);
  }

  private addEncrypted(entry: string): void {
    if (!this.encrypted.has(entry) && this.encrypted.size < MAX_PER_LIST) {
      this.encrypted.add(entry);
      this.dirty = true;
    }
  }
}
