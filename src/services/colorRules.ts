import { ColorRule, Packet } from '../types/packet';
import { FilterEngine } from './filterEngine';
// Type-only: packetThemes.ts imports DEFAULT_COLOR_RULES from here, so a value
// import would close a runtime cycle. `import type` is erased at compile.
import type { PacketTheme } from './packetThemes';

/**
 * The reference analyzer's default coloring rules, in its order and under its exact names.
 *
 * Order is the whole design: the chain is first-match-wins, so a retransmitted
 * RST is "Bad TCP" rather than "TCP RST", a plain RST on port 80 is "TCP RST"
 * rather than "HTTP", and an ARP broadcast is "ARP" rather than "Broadcast" -
 * results a protocol-to-color map cannot express at all. The rule *names* are
 * kept identical to the reference analyzer's because that is what makes a frame-by-frame
 * diff against `tshark -e frame.coloring_rule.name` a meaningful test.
 *
 * Each rule carries two palettes, because NetView's packet list follows the
 * app theme and a single pair cannot serve both grounds:
 *
 *   - `lightBgColor`/`lightTextColor` are the reference analyzer's own defaults, taken
 *     verbatim from its shipped `colorfilters` file and converted from its
 *     16-bit channels to hex. In light mode the list is pixel-comparable to
 *     The reference analyzer, including the details that look like bugs but aren't: the
 *     Broadcast rule really does paint a white row, and the five "something is
 *     wrong" rules really do use a dark slate fill even in the light profile.
 *   - `bgColor`/`textColor` are dark-adapted. The reference analyzer's pastel fills (TCP
 *     #e7e5ff, UDP #daeeff, Broadcast pure white) read as glare on a dark UI,
 *     so each rule keeps the reference analyzer's *hue* and relative emphasis, re-derived
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
    // Off by default, matching the reference analyzer: NIC checksum offload means a frame
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
    // White, exactly as the reference analyzer has it: a broadcast row is deliberately the
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
 * The background/foreground one rule contributes under a packet theme.
 *
 * Appearance lives in the theme, not the rule: this used to take an `isDark`
 * boolean and pick between two palettes carried on the rule itself, which tied
 * the packet list to the app theme and allowed exactly two looks. A theme keyed
 * by rule id gives any number of palettes and leaves the rule to do only what
 * it is good at, which is matching.
 *
 * A rule the theme has no entry for falls back to the colors on the rule (what
 * a user-defined rule supplies), and then to the theme's own ground - so an
 * unknown rule renders as a plain row rather than as nothing at all.
 */
export function resolveRuleColors(
  rule: ColorRule,
  theme: PacketTheme,
): { background: string; color: string } {
  const themed = theme.rules[rule.id];
  if (themed) return themed;
  return {
    background: rule.bgColor ?? theme.surface.background,
    color: rule.textColor ?? theme.surface.foreground,
  };
}

// Coloring rules are fixed to the reference analyzer's own chain (above) - there is no UI
// path left to view or edit them, matching the reference analyzer parity rather than being
// a user-customizable feature.
export class ColorRulesEngine {
  private compiled: CompiledRule[];

  /**
   * The rule each packet matched, memoized.
   *
   * The whole reason this class is fast enough to run at capture volume. A
   * packet is immutable once dissected and the chain is deterministic, so its
   * matched rule can never change - yet the packet-list minimap asks for every
   * buffered packet's color on every repaint. Profiling the running app during
   * a live capture measured 142,338 getPacketStyle calls costing 3,799ms in a
   * single 5-second window (76% of all wall-clock time, 82% of all main-thread
   * blocking) at a 15,762-packet buffer, with one full minimap redraw taking
   * 698ms. With this cache the same redraw takes 2.1ms.
   *
   * What is cached is the *rule*, not a pair of colors, because rule matching
   * is theme-independent: resolveRuleColors() applies the theme afterwards, so
   * switching themes costs nothing and needs no invalidation.
   *
   * A WeakMap rather than a Map: packets dropped off the back of the live
   * buffer are collected with no bookkeeping and no unbounded growth.
   */
  private matchCache = new WeakMap<Packet, ColorRule | null>();

  constructor() {
    this.compiled = ColorRulesEngine.compile(DEFAULT_COLOR_RULES);
  }

  // Each rule's filter is turned into a matcher once here rather than being
  // re-derived per call. Note that FilterEngine.compileFilter does NOT
  // currently compile to a closure tree - it preprocesses the filter string
  // and returns a closure that re-parses that string for every packet it is
  // handed. So one uncached chain walk re-parses up to 19 expressions, which
  // is why a single getPacketStyle call was measured at 26.7us and why the
  // memo above matters as much as it does.
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
   * The first rule in the chain that matches, or null when none does, walking
   * the chain only the first time it is asked about a given packet.
   *
   * A null result is cached too, deliberately: "no rule matched" is the
   * *expensive* answer - it is the only one that has run every matcher in the
   * chain - so it is the one least worth paying for twice.
   */
  private matchRule(packet: Packet): ColorRule | null {
    const cached = this.matchCache.get(packet);
    if (cached !== undefined) return cached;

    let matched: ColorRule | null = null;
    for (const { rule, matcher } of this.compiled) {
      try {
        if (matcher(packet)) {
          matched = rule;
          break;
        }
      } catch {
        // A rule that can't be evaluated simply doesn't match.
      }
    }
    this.matchCache.set(packet, matched);
    return matched;
  }

  /**
   * The name of the first rule in the chain that matches, or undefined when
   * none does. The reference analyzer exposes the same thing as `frame.coloring_rule.name`,
   * which makes it the cleanest way to assert that this chain agrees with
   * The reference analyzer's frame for frame.
   */
  public getMatchedRuleName(packet: Packet): string | undefined {
    return this.matchRule(packet)?.name;
  }

  /**
   * How one packet should be painted under a packet theme.
   *
   * Returns `{}` for a packet matching no rule - the chain ends at Broadcast
   * and has no catch-all, exactly as the reference analyzer's does. The caller paints those
   * rows with the theme's own surface, which is what keeps a list internally
   * consistent when the packet theme and the app theme disagree about ground.
   */
  /**
   * The colour that NAMES this packet outside the list.
   *
   * The inspection pane, the hex pane and the detail window all label a frame
   * they did not draw, and a label in the app accent said the same thing for
   * every frame. This says which frame - the same hue the row was painted in,
   * taken at text strength rather than as a wash.
   *
   * Never undefined: a packet matching no rule still has to be labelled, so it
   * takes the theme's neutral accent rather than leaving the caller to invent
   * a fallback.
   */
  public getPacketAccent(packet: Packet, theme: PacketTheme): string {
    const rule = this.matchRule(packet);
    if (!rule) return theme.accentFallback;
    return theme.accents[rule.id] ?? theme.accentFallback;
  }

  public getPacketStyle(
    packet: Packet,
    theme: PacketTheme,
  ): { background?: string; color?: string; borderColor?: string } {
    const rule = this.matchRule(packet);
    if (!rule) return {};
    return {
      ...resolveRuleColors(rule, theme),
      borderColor: theme.surface.border,
    };
  }
}
