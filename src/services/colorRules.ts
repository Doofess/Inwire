import { ColorRule, Packet } from '../types/packet';
import { FilterEngine } from './filterEngine';

/**
 * Wireshark's default coloring rules, in its order and under its exact names.
 *
 * Order is the whole design: the chain is first-match-wins, so a retransmitted
 * RST is "Bad TCP" rather than "TCP RST", a plain RST on port 80 is "TCP RST"
 * rather than "HTTP", and an ARP broadcast is "ARP" rather than "Broadcast" -
 * results a protocol-to-color map cannot express at all. The rule *names* are
 * kept identical to Wireshark's because that is what makes a frame-by-frame
 * diff against `tshark -e frame.coloring_rule.name` a meaningful test.
 *
 * Each rule carries two palettes, because NetView's packet list follows the
 * app theme and a single pair cannot serve both grounds:
 *
 *   - `lightBgColor`/`lightTextColor` are Wireshark's own defaults, taken
 *     verbatim from its shipped `colorfilters` file and converted from its
 *     16-bit channels to hex. In light mode the list is pixel-comparable to
 *     Wireshark, including the details that look like bugs but aren't: the
 *     Broadcast rule really does paint a white row, and the five "something is
 *     wrong" rules really do use a dark slate fill even in the light profile.
 *   - `bgColor`/`textColor` are dark-adapted. Wireshark's pastel fills (TCP
 *     #e7e5ff, UDP #daeeff, Broadcast pure white) read as glare on a dark UI,
 *     so each rule keeps Wireshark's *hue* and relative emphasis, re-derived
 *     for a dark ground.
 */
export const DEFAULT_COLOR_RULES: ColorRule[] = [
  {
    id: 'color-bad-tcp',
    name: 'Bad TCP',
    // Keep-alives and window updates are normal traffic that happens to carry
    // an analysis flag, so they are excluded rather than painted as damage.
    filter: 'tcp.analysis.flags && !tcp.analysis.window_update && !tcp.analysis.keep_alive && !tcp.analysis.keep_alive_ack',
    bgColor: '#2a1416',
    textColor: '#f78787',
    lightBgColor: '#12272e',
    lightTextColor: '#f78787',
    enabled: true,
  },
  {
    id: 'color-hsrp-state-change',
    name: 'HSRP State Change',
    filter: 'hsrp.state != 8 && hsrp.state != 16',
    bgColor: '#2b2716',
    textColor: '#fffc9c',
    lightBgColor: '#12272e',
    lightTextColor: '#fffc9c',
    enabled: true,
  },
  {
    id: 'color-stp-topology-change',
    name: 'Spanning Tree Topology Change',
    // Only a *topology change* BPDU is colored; ordinary STP hellos fall
    // through to the Broadcast rule at the end of the chain.
    filter: 'stp.type == 0x80',
    bgColor: '#2b2716',
    textColor: '#fffc9c',
    lightBgColor: '#12272e',
    lightTextColor: '#fffc9c',
    enabled: true,
  },
  {
    id: 'color-ospf-state-change',
    name: 'OSPF State Change',
    filter: 'ospf.msg != 1',
    bgColor: '#2b2716',
    textColor: '#fffc9c',
    lightBgColor: '#12272e',
    lightTextColor: '#fffc9c',
    enabled: true,
  },
  {
    id: 'color-icmp-errors',
    name: 'ICMP errors',
    filter: 'icmp.type in { 3..5, 11 } || icmpv6.type in { 1..4 }',
    bgColor: '#1c2a18',
    textColor: '#b7f774',
    lightBgColor: '#12272e',
    lightTextColor: '#b7f774',
    enabled: true,
  },
  {
    id: 'color-arp',
    name: 'ARP',
    filter: 'arp',
    bgColor: '#2e2a1c',
    textColor: '#e8dca8',
    lightBgColor: '#faf0d7',
    lightTextColor: '#12272e',
    enabled: true,
  },
  {
    id: 'color-icmp',
    name: 'ICMP',
    filter: 'icmp || icmpv6',
    bgColor: '#2b1e2e',
    textColor: '#f0c4f7',
    lightBgColor: '#fce0ff',
    lightTextColor: '#12272e',
    enabled: true,
  },
  {
    id: 'color-tcp-rst',
    name: 'TCP RST',
    filter: 'tcp.flags.reset eq 1',
    bgColor: '#4a0000',
    textColor: '#fffc9c',
    lightBgColor: '#a40000',
    lightTextColor: '#fffc9c',
    enabled: true,
  },
  {
    id: 'color-sctp-abort',
    name: 'SCTP ABORT',
    filter: 'sctp.chunk_type eq ABORT',
    bgColor: '#4a0000',
    textColor: '#fffc9c',
    lightBgColor: '#a40000',
    lightTextColor: '#fffc9c',
    enabled: true,
  },
  {
    id: 'color-ipv4-ttl-low',
    name: 'IPv4 TTL low or unexpected',
    filter: '(ip.dst != 224.0.0.0/4 && ip.ttl < 5 && !(pim || ospf || eigrp || bgp || tcp.port == 179)) || (ip.dst == 224.0.0.0/24 && ip.dst != 224.0.0.251 && ip.ttl != 1 && !(vrrp || carp || eigrp || rip || glbp))',
    bgColor: '#4a0000',
    textColor: '#ecf0eb',
    lightBgColor: '#a40000',
    lightTextColor: '#ecf0eb',
    enabled: true,
  },
  {
    id: 'color-ipv6-hop-limit-low',
    name: 'IPv6 hop limit low or unexpected',
    filter: '(ipv6.dst != ff00::/8 && ipv6.hlim < 5 && !(ospf || bgp || tcp.port == 179)) || (ipv6.dst == ff00::/8 && ipv6.hlim not in { 1, 64, 255 })',
    bgColor: '#4a0000',
    textColor: '#ecf0eb',
    lightBgColor: '#a40000',
    lightTextColor: '#ecf0eb',
    enabled: true,
  },
  {
    id: 'color-checksum-errors',
    name: 'Checksum Errors',
    filter: 'eth.fcs.status == "Bad" || ip.checksum.status == "Bad" || tcp.checksum.status == "Bad" || udp.checksum.status == "Bad"',
    bgColor: '#2a1416',
    textColor: '#f78787',
    lightBgColor: '#12272e',
    lightTextColor: '#f78787',
    // Off by default, matching Wireshark: NIC checksum offload means a frame
    // captured on the host that sent it has not had its checksum filled in
    // yet, so validating locally-captured traffic paints half the list red.
    enabled: false,
  },
  {
    id: 'color-smb',
    name: 'SMB',
    filter: 'smb || nbss || nbns || netbios',
    bgColor: '#2c2c18',
    textColor: '#f2f0c0',
    lightBgColor: '#feffd0',
    lightTextColor: '#12272e',
    enabled: true,
  },
  {
    id: 'color-http',
    name: 'HTTP',
    filter: 'http || tcp.port == 80 || http2',
    bgColor: '#1c2a18',
    textColor: '#c8f0a0',
    lightBgColor: '#e4ffc7',
    lightTextColor: '#12272e',
    enabled: true,
  },
  {
    id: 'color-dcerpc',
    name: 'DCERPC',
    filter: 'dcerpc',
    bgColor: '#241a30',
    textColor: '#c797ff',
    lightBgColor: '#c797ff',
    lightTextColor: '#12272e',
    enabled: true,
  },
  {
    id: 'color-routing',
    name: 'Routing',
    filter: 'hsrp || eigrp || ospf || bgp || cdp || vrrp || carp || gvrp || igmp || ismp',
    bgColor: '#2b2418',
    textColor: '#ecd9a8',
    lightBgColor: '#fff3d5',
    lightTextColor: '#12272e',
    enabled: true,
  },
  {
    id: 'color-tcp-syn-fin',
    name: 'TCP SYN/FIN',
    filter: 'tcp.flags & 0x02 || tcp.flags.fin == 1',
    bgColor: '#262626',
    textColor: '#c8c8c8',
    lightBgColor: '#a0a0a0',
    lightTextColor: '#12272e',
    enabled: true,
  },
  {
    id: 'color-tcp',
    name: 'TCP',
    filter: 'tcp',
    bgColor: '#1e1e2a',
    textColor: '#c5c4e8',
    lightBgColor: '#e7e5ff',
    lightTextColor: '#12272e',
    enabled: true,
  },
  {
    id: 'color-udp',
    name: 'UDP',
    filter: 'udp',
    bgColor: '#182430',
    textColor: '#afd4f0',
    lightBgColor: '#daeeff',
    lightTextColor: '#12272e',
    enabled: true,
  },
  {
    id: 'color-broadcast',
    name: 'Broadcast',
    // The multicast bit of the destination MAC, not equality with
    // ff:ff:ff:ff:ff:ff - this catches STP and other group addresses too.
    filter: 'eth[0] & 1',
    bgColor: '#202020',
    textColor: '#7a7d76',
    // White, exactly as Wireshark has it: a broadcast row is deliberately the
    // plainest thing in the list, distinguished only by its grey text.
    lightBgColor: '#ffffff',
    lightTextColor: '#babdb6',
    enabled: true,
  },
];

interface CompiledRule {
  rule: ColorRule;
  matcher: (p: Packet) => boolean;
}

/**
 * The background/foreground one rule contributes on the current theme.
 *
 * A rule with no light palette - which every user-defined rule is, since the
 * editor collects a single pair - falls back to its dark one rather than
 * rendering nothing, so a custom rule still colors its rows in both themes.
 */
export function resolveRuleColors(rule: ColorRule, isDark: boolean): { background: string; color: string } {
  if (isDark) return { background: rule.bgColor, color: rule.textColor };
  return {
    background: rule.lightBgColor ?? rule.bgColor,
    color: rule.lightTextColor ?? rule.textColor,
  };
}

// Coloring rules are fixed to Wireshark's own chain (above) - there is no UI
// path left to view or edit them, matching Wireshark parity rather than being
// a user-customizable feature.
export class ColorRulesEngine {
  private compiled: CompiledRule[];

  constructor() {
    this.compiled = ColorRulesEngine.compile(DEFAULT_COLOR_RULES);
  }

  // Compiling each rule's filter once here - instead of re-parsing the
  // filter string from scratch on every getPacketStyle call, as before -
  // is what makes this viable at real capture volume: getPacketStyle runs
  // per row per redraw (including the packet-list minimap's full redraw of
  // every buffered packet), and a Chrome performance trace showed
  // re-parsing every rule's filter on every single call as the dominant
  // cost behind a full tab freeze once the buffer reached a few thousand
  // packets.
  private static compile(rules: ColorRule[]): CompiledRule[] {
    return rules
      .filter(rule => rule.enabled)
      .map(rule => {
        try {
          return { rule, matcher: FilterEngine.compileFilter(rule.filter) };
        } catch {
          return { rule, matcher: () => false };
        }
      });
  }

  /**
   * The name of the first rule in the chain that matches, or undefined when
   * none does. Wireshark exposes the same thing as `frame.coloring_rule.name`,
   * which makes it the cleanest way to assert that this chain agrees with
   * Wireshark's frame for frame.
   */
  public getMatchedRuleName(packet: Packet): string | undefined {
    for (const { rule, matcher } of this.compiled) {
      try {
        if (matcher(packet)) return rule.name;
      } catch {
        // A rule that can't be evaluated simply doesn't match.
      }
    }
    return undefined;
  }

  public getPacketStyle(packet: Packet, isDark: boolean = true): { background?: string; color?: string; borderColor?: string } {
    for (const { rule, matcher } of this.compiled) {
      try {
        if (matcher(packet)) {
          return {
            ...resolveRuleColors(rule, isDark),
            borderColor: isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)',
          };
        }
      } catch {
        // Ignore evaluation errors for custom rules
      }
    }

    return {};
  }
}
