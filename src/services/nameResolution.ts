/**
 * The passive name map: what the capture itself says the addresses are called.
 *
 * Every name here was carried by a frame that was already on the wire. Nothing
 * is looked up, so this works on an imported file from a network that no
 * longer exists, it cannot leak which addresses were captured to a resolver,
 * and it is instant. That is the whole reason a passive map is worth having
 * over reverse DNS: an analyzer that phones home to name the traffic it was
 * given has told somebody what you are looking at.
 *
 * ## Where the names come from
 *
 * | Source | What it proves |
 * |---|---|
 * | `dhcp` | a host naming *itself* to its own network - the strongest claim |
 * | `lldp` | a switch or AP naming itself on the local segment |
 * | `nbns` | a Windows host announcing its NetBIOS name |
 * | `dns` / `mdns` | an answer that maps this name to this address |
 * | `sni` / `quic-sni` | a name a client *asked for* while opening a connection |
 *
 * The ranking matters because they disagree. One CDN address serves thousands
 * of names, so an SNI says far less about the address than a DNS answer does,
 * and a DHCP hostname is the host's own word about itself. A higher-ranked
 * source replaces a lower one; within a rank the first name seen wins, so the
 * packet list does not relabel a host halfway down the capture.
 *
 * ## What is deliberately not learned
 *
 * A real ECH ClientHello's outer SNI names the ECH provider
 * (`cloudflare-ech.com`), not the site. It is a name the traffic genuinely
 * carried, which is exactly what makes it dangerous to learn - it would look
 * like a real answer while being the same wrong answer for every address
 * behind that provider.
 */

import { Packet } from '../types/packet';
import { isEchPublicName } from './dissectors/tls';
import { fieldValue } from './dissect/fieldAccess';

export type NameSource = 'dhcp' | 'lldp' | 'nbns' | 'dns' | 'mdns' | 'sni' | 'quic-sni' | 'arp';

/** Higher wins. See the table above for why these sit where they do. */
const SOURCE_RANK: Record<NameSource, number> = {
  dhcp: 40,
  lldp: 40,
  nbns: 30,
  dns: 20,
  mdns: 20,
  arp: 15,
  sni: 10,
  'quic-sni': 10,
};

export const SOURCE_LABELS: Record<NameSource, string> = {
  dhcp: 'DHCP',
  lldp: 'LLDP',
  nbns: 'NBNS',
  dns: 'DNS',
  mdns: 'mDNS',
  arp: 'ARP',
  sni: 'TLS SNI',
  'quic-sni': 'QUIC SNI',
};

export interface ResolvedHost {
  address: string;
  name: string;
  source: NameSource;
  /** The frame that taught it, so the list can jump to the evidence. */
  frame: number;
  /** How many frames carried this address, filled in by `withCounts`. */
  frames?: number;
}

/** Bounds memory on a capture full of one-off names (a scan, a busy resolver). */
const MAX_ENTRIES = 20000;

export class NameResolutionMap {
  private byAddress = new Map<string, ResolvedHost>();
  /** MAC to the vendor-independent name a host gave for itself. */
  private byMac = new Map<string, ResolvedHost>();

  /**
   * Records one claim. A stronger source replaces a weaker one; an equal one
   * does not, so a host keeps the first name it was seen under.
   */
  learn(address: string, name: string, source: NameSource, frame: number, target: 'address' | 'mac' = 'address'): void {
    const clean = name.trim().replace(/\.$/, '');
    if (!clean || !address) return;
    // A name that is just the address back again teaches nothing and would
    // make the "resolved" list look far fuller than it is.
    if (clean.toLowerCase() === address.toLowerCase()) return;
    if (source === 'sni' || source === 'quic-sni') {
      if (isEchPublicName(clean)) return;
    }

    const map = target === 'mac' ? this.byMac : this.byAddress;
    const existing = map.get(address);
    if (existing && SOURCE_RANK[existing.source] >= SOURCE_RANK[source]) return;
    if (!existing && map.size >= MAX_ENTRIES) return;
    map.set(address, { address, name: clean, source, frame });
  }

  /**
   * Everything one frame has to say about what things are called.
   *
   * Reads the registered fields rather than taking a channel of its own, so a
   * dissector that starts publishing a name is picked up here without another
   * plumbing change - the exception is a DNS answer set, which maps one name
   * to several addresses and so cannot fit in the flat field bag.
   */
  learnFromPacket(packet: Packet): void {
    const f = packet.fields;
    const frame = packet.id;

    // DNS and mDNS answers: name -> addresses, from the parsed record set.
    if (packet.resolved) {
      const source: NameSource = packet.protocolLabel === 'MDNS' ? 'mdns' : 'dns';
      for (const entry of packet.resolved) {
        for (const address of entry.addresses) this.learn(address, entry.name, source, frame);
      }
    }

    if (!f) return;

    // A server name names the address the frame was SENT TO - the client is
    // the one asking for it, so the destination is the host being named.
    const sni = fieldValue(packet, 'tls.handshake.extensions_server_name');
    if (typeof sni === 'string' && packet.destination) {
      // A ServerHello travels the other way and carries no SNI, so a frame
      // with one is always client-to-server.
      this.learn(packet.destination, sni, packet.protocol === 'QUIC' ? 'quic-sni' : 'sni', frame);
    }

    // DHCP: the client names itself. `dhcp.ip.your` is the address the server
    // is handing out, which is the address that name belongs to; on a request
    // there is no address yet, so the MAC carries it instead.
    const dhcpName = fieldValue(packet, 'dhcp.option.hostname') ?? fieldValue(packet, 'dhcp.fqdn.name');
    if (typeof dhcpName === 'string') {
      const offered = fieldValue(packet, 'dhcp.ip.your');
      const requested = fieldValue(packet, 'dhcp.option.requested_ip_address');
      if (typeof offered === 'string' && offered !== '0.0.0.0') this.learn(offered, dhcpName, 'dhcp', frame);
      else if (typeof requested === 'string') this.learn(requested, dhcpName, 'dhcp', frame);
      const mac = fieldValue(packet, 'dhcp.hw.mac_addr');
      if (typeof mac === 'string') this.learn(mac, dhcpName, 'dhcp', frame, 'mac');
    }

    const dhcpv6Name = fieldValue(packet, 'dhcpv6.client_domain');
    if (typeof dhcpv6Name === 'string') this.learn(packet.source, dhcpv6Name, 'dhcp', frame);

    // LLDP: the device names itself, and the management address it advertises
    // is the one that name belongs to.
    const lldpName = fieldValue(packet, 'lldp.tlv.system.name');
    if (typeof lldpName === 'string') {
      const mgmt = fieldValue(packet, 'lldp.mgn.addr');
      if (typeof mgmt === 'string') this.learn(mgmt, lldpName, 'lldp', frame);
      const chassis = fieldValue(packet, 'lldp.chassis.id');
      if (typeof chassis === 'string') this.learn(chassis, lldpName, 'lldp', frame, 'mac');
    }

    // ARP: a MAC and an address seen as the same host. No name, but it is what
    // lets the device inventory join the two halves of one machine.
    const arpMac = fieldValue(packet, 'arp.src.hw_mac');
    const arpIp = fieldValue(packet, 'arp.src.proto_ipv4');
    if (typeof arpMac === 'string' && typeof arpIp === 'string' && arpIp !== '0.0.0.0') {
      const known = this.byMac.get(arpMac);
      if (known) this.learn(arpIp, known.name, 'arp', frame);
    }
  }

  /** The name for an address, or undefined when the capture never named it. */
  hostName(address: string): string | undefined {
    return this.byAddress.get(address)?.name;
  }

  /** The name a host gave for itself under a MAC. */
  macName(mac: string): string | undefined {
    return this.byMac.get(mac)?.name;
  }

  /** Everything learned, addresses first, for the Resolved Addresses view. */
  entries(): ResolvedHost[] {
    return [...this.byAddress.values(), ...this.byMac.values()];
  }

  get size(): number {
    return this.byAddress.size + this.byMac.size;
  }

  reset(): void {
    this.byAddress.clear();
    this.byMac.clear();
  }
}

/**
 * The read-only face of the map, for anything that only asks questions.
 *
 * A component takes this rather than the map itself so it cannot teach the map
 * anything: the map is built once from the buffer, and a view that could add
 * to it would be inventing names from whatever it happened to be rendering.
 */
export interface NameLookup {
  hostName(address: string): string | undefined;
  macName(mac: string): string | undefined;
  entries(): ResolvedHost[];
  readonly size: number;
}

/**
 * A fresh handle onto the same map.
 *
 * The incremental fold that builds the map keeps ONE accumulator across ticks,
 * so returning it directly would hand every consumer a value whose identity
 * never changes - and a memo keyed on it would never notice the capture
 * learning a new name. This is O(1) and changes identity per tick, which is
 * what a `useMemo` dependency needs to mean anything.
 */
export function snapshot(map: NameResolutionMap): NameLookup {
  return {
    hostName: (address) => map.hostName(address),
    macName: (mac) => map.macName(mac),
    entries: () => map.entries(),
    get size() { return map.size; },
  };
}

/**
 * Builds a map from a whole buffer.
 *
 * Deriving the map from the packets rather than collecting it during
 * dissection is what makes it work identically for a live capture, an
 * imported file and a restored session: all three end with the same packets,
 * and none of them has to carry a side channel for this.
 */
export function buildNameMap(packets: readonly Packet[]): NameResolutionMap {
  const map = new NameResolutionMap();
  for (const packet of packets) map.learnFromPacket(packet);
  return map;
}
