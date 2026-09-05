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
 * Each rule carries two palettes, because Inwire's packet list follows the
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
export const WIRESHARK_DEFAULT_RULES: ColorRule[] = [
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

/**
 * The three bands Inwire adds to Wireshark's chain.
 *
 * Wireshark's shipped `colorfilters` predates QUIC being most of a browser's
 * traffic, and it has no band at all for "a dissector said something is wrong"
 * beyond the TCP and checksum cases - so on a modern capture the two most
 * interesting things on screen are painted as plain UDP and plain TCP.
 *
 * These are kept SEPARATE from `WIRESHARK_DEFAULT_RULES` rather than merged
 * into it, because that array is the chain the tshark parity harness compares
 * against frame for frame: measuring "does our engine reach Wireshark's
 * colouring decisions" needs Wireshark's rules, not ours. The app ships both
 * (`DEFAULT_COLOR_RULES`); the harness constructs the engine from Wireshark's
 * alone.
 */
export const INWIRE_EXTRA_RULES: ColorRule[] = [
  {
    id: 'color-expert',
    name: 'Expert Warnings',
    // `inwire.expert.severity` is the worst finding anywhere in the frame's
    // tree, published at dissection: a colour rule cannot walk a tree, so
    // without that field this band could not exist.
    filter: 'inwire.expert.severity == "error" || inwire.expert.severity == "warn"',
    bgColor: '#2e1f0d',
    textColor: '#f0b866',
    lightBgColor: '#fff3d9',
    lightTextColor: '#7a4d00',
    // Off by default, for the same reason Wireshark ships Checksum Errors off:
    // on a capture taken ON the sending host, NIC checksum offload means the
    // checksum has not been filled in yet, and those frames dominate. Measured
    // on the two parity fixtures, this band would paint 14 % and 22 % of the
    // list - almost all of it "Bad checksum" on locally-originated traffic.
    // On a capture from a mirror port, where the checksums are real, it is the
    // most useful band in the chain, which is why it ships ready to switch on
    // in Settings -> Colouring Rules rather than not existing.
    enabled: false,
  },
  {
    id: 'color-tls-handshake',
    name: 'TLS Handshake',
    // Client Hello and Server Hello. The frames that say who is talking to
    // whom, in a capture where everything else is opaque.
    filter: 'tls.handshake.type == 1 || tls.handshake.type == 2',
    bgColor: '#122b23',
    textColor: '#6fd6a8',
    lightBgColor: '#dcf5e9',
    lightTextColor: '#0d4630',
    enabled: true,
  },
  {
    id: 'color-quic',
    name: 'QUIC',
    filter: 'quic',
    bgColor: '#1b2334',
    textColor: '#8fb2f0',
    lightBgColor: '#e2ecff',
    lightTextColor: '#1b3a72',
    enabled: true,
  },
];

/**
 * The chain the app ships with.
 *
 * The three extra bands are inserted where first-match-wins puts them to work:
 * Expert Warnings just after the other "something is broken" rules, so a bad
 * frame is flagged before its protocol is; TLS Handshake and QUIC before the
 * generic TCP and UDP bands, which would otherwise swallow them.
 */
export const DEFAULT_COLOR_RULES: ColorRule[] = insertExtraRules(
  WIRESHARK_DEFAULT_RULES,
  INWIRE_EXTRA_RULES,
);

function insertExtraRules(base: ColorRule[], extra: ColorRule[]): ColorRule[] {
  const byId = new Map(extra.map((r) => [r.id, r]));
  const out: ColorRule[] = [];
  for (const rule of base) {
    // Just after Checksum Errors, which ends Wireshark's run of "broken" bands.
    if (rule.id === 'color-checksum-errors') { out.push(rule); out.push(byId.get('color-expert')!); continue; }
    // Before TCP SYN/FIN, which is the first band that would swallow them.
    if (rule.id === 'color-tcp-syn-fin') {
      out.push(byId.get('color-tls-handshake')!, byId.get('color-quic')!, rule);
      continue;
    }
    out.push(rule);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The user's chain
// ---------------------------------------------------------------------------

export const COLOR_RULES_STORAGE_KEY = 'inwire.colorRules';

/**
 * Validates a stored chain.
 *
 * Field by field and rule by rule, the way every other preference in this app
 * is validated: a rule that has lost its filter is dropped rather than
 * discarding the whole chain, and a chain that ends up empty falls back to the
 * shipped one - a packet list with no colouring at all is not a state anybody
 * chose, and there would be no rule left in the editor to start from.
 */
export function normalizeColorRules(raw: unknown): ColorRule[] | null {
  if (!Array.isArray(raw)) return null;
  const out: ColorRule[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    if (typeof entry !== 'object' || entry === null) continue;
    const v = entry as Record<string, unknown>;
    if (typeof v.id !== 'string' || typeof v.name !== 'string' || typeof v.filter !== 'string') continue;
    if (seen.has(v.id)) continue;
    seen.add(v.id);
    out.push({
      id: v.id,
      name: v.name,
      filter: v.filter,
      enabled: typeof v.enabled === 'boolean' ? v.enabled : true,
      ...(typeof v.bgColor === 'string' ? { bgColor: v.bgColor } : {}),
      ...(typeof v.textColor === 'string' ? { textColor: v.textColor } : {}),
      ...(typeof v.lightBgColor === 'string' ? { lightBgColor: v.lightBgColor } : {}),
      ...(typeof v.lightTextColor === 'string' ? { lightTextColor: v.lightTextColor } : {}),
    });
  }
  return out.length > 0 ? out : null;
}

/** A fresh copy of the shipped chain, for the editor's reset. */
export function defaultColorRules(): ColorRule[] {
  return DEFAULT_COLOR_RULES.map((r) => ({ ...r }));
}

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

  /**
   * @param rules the chain to match against, first-match-wins. Defaults to the
   * shipped chain; the app passes the user's edited one, and the parity
   * harness passes `WIRESHARK_DEFAULT_RULES` so it measures the engine against
   * Wireshark's own decisions rather than against Inwire's extra bands.
   */
  constructor(rules: ColorRule[] = DEFAULT_COLOR_RULES) {
    this.compiled = ColorRulesEngine.compile(rules);
  }

  // Each rule's filter is turned into a matcher once here rather than being
  // re-derived per call.
  //
  // That used to be far less true than it read: `compileFilter` returned a
  // closure that RE-PARSED its filter string for every packet handed to it, so
  // one uncached chain walk re-parsed up to nineteen expressions and a single
  // getPacketStyle call measured 26.7us. It is a real compile now - tokenize,
  // parse, resolve every field against the registry, return a closure over the
  // result - so the per-packet cost is the comparisons and nothing else. The
  // memo below still earns its place: nineteen matchers is nineteen matchers.
  //
  // A rule whose filter does not parse gets a matcher that never fires, rather
  // than taking the whole chain down. A rule that parses but names a protocol
  // Inwire does not dissect compiles fine and simply matches nothing, which is
  // the case for several of Wireshark's defaults that ship here.
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
