import { ColorRule, Packet } from '../types/packet';
import { FilterEngine } from './filterEngine';
// Type-only: packetThemes.ts imports DEFAULT_COLOR_RULES from here, so a value
// import would close a runtime cycle. `import type` is erased at compile.
import type { PacketTheme } from './packetThemes';

/**
 * The reference analyzer's default coloring rules, in its order and under its exact names.
 *
 * **The chain is shipped and not chosen.** There was an editor for one
 * revision - a Settings tab that reordered, recoloured and disabled rules, and
 * stored the result under `inwire.colorRules` - and it is deleted. Colouring
 * is the one part of this UI whose whole job is to be opinionated about which
 * frames matter, and an opinion the user can rewrite is one the app can no
 * longer stand behind: the parity harness compares `frame.coloring_rule.name`
 * against tshark frame for frame, `packetThemes.ts` keys an appearance off
 * every rule id it expects to exist, and the expert bands below assume their
 * own order. All three are statements about THIS chain. The key is retired in
 * `preferences.ts`, so a chain edited under the old build stops painting
 * rather than painting something nobody can see or correct.
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
    //
    // Wireshark writes this rule as `eth[0] & 1`, a read straight out of the
    // frame's bytes. Inwire releases a frame's bytes once the store can supply
    // them again (docs/decisions/0013), and a byte read cannot answer for a
    // frame whose bytes are not resident - it would silently return no match
    // and the row would quietly lose its colour. `eth.ig` is the same bit,
    // dissected once and kept, so the answer survives eviction. The rule's
    // NAME is unchanged, which is what the parity harness compares.
    filter: 'eth.ig == 1',
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
  // --- the expert categories -------------------------------------------------
  //
  // One band per `ExpertCategory`, in `CATEGORY_ORDER`, at the head of the
  // chain. This is where the whole expert system reaches the packet list, and
  // it goes through the ordinary colour-rules machinery rather than a second
  // painter: one system owns a row's colour, `Packet.colorSlot` memoises it
  // for free, the minimap picks it up for free, and every band is reorderable
  // and disable-able in Settings like any other.
  //
  // It replaces a single "Expert Warnings" band keyed on
  // `inwire.expert.severity`, which shipped **disabled** because it painted
  // 14% and 22% of the two fixtures - almost all of it "Bad checksum" on
  // frames this machine had sent, where the NIC had not filled the checksum
  // in yet. Those frames are `Unverifiable` now and the checksum is not
  // reported as bad at all, which is what makes painting by category viable.
  //
  // The colours are not here. Every built-in rule is painted by the theme
  // (`resolveRuleColors`), and these four carry *stated* pairs rather than
  // derived ones - see `FIXED_ROLE_COLORS` in packetThemes.ts.
  {
    id: 'color-expert-broken',
    name: 'Expert: Broken',
    filter: 'inwire.expert.category == "Broken"',
    enabled: true,
  },
  {
    id: 'color-expert-reset',
    name: 'Expert: Reset',
    filter: 'inwire.expert.category == "Reset"',
    enabled: true,
  },
  {
    id: 'color-expert-security',
    name: 'Expert: Security',
    filter: 'inwire.expert.category == "Security"',
    enabled: true,
  },
  {
    id: 'color-expert-loss',
    name: 'Expert: Loss',
    filter: 'inwire.expert.category == "Loss"',
    enabled: true,
  },
  {
    id: 'color-expert-capture-gap',
    name: 'Expert: Capture gap',
    filter: 'inwire.expert.category == "CaptureGap"',
    enabled: true,
  },
  {
    id: 'color-expert-flow-control',
    name: 'Expert: Flow control',
    filter: 'inwire.expert.category == "FlowControl"',
    enabled: true,
  },
  {
    id: 'color-expert-unverifiable',
    name: 'Expert: Unverifiable',
    filter: 'inwire.expert.category == "Unverifiable"',
    enabled: true,
  },
  {
    id: 'color-expert-note',
    name: 'Expert: Note',
    filter: 'inwire.expert.category == "Note"',
    enabled: true,
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
 * The extra bands are inserted where first-match-wins puts them to work: the
 * eight expert categories at the head, so a frame a dissector had something to
 * say about is painted for what is wrong with it rather than for its protocol;
 * TLS Handshake and QUIC before the generic TCP and UDP bands, which would
 * otherwise swallow them.
 */
export const DEFAULT_COLOR_RULES: ColorRule[] = insertExtraRules(
  WIRESHARK_DEFAULT_RULES,
  INWIRE_EXTRA_RULES,
);

function insertExtraRules(base: ColorRule[], extra: ColorRule[]): ColorRule[] {
  const byId = new Map(extra.map((r) => [r.id, r]));
  // The expert bands lead the chain, where Wireshark puts Bad TCP and for the
  // same reason: a frame with a finding is more interesting than the fact that
  // it is TCP, and first-match-wins means whatever leads decides.
  const expertBands = extra.filter((r) => r.id.startsWith('color-expert-'));
  const out: ColorRule[] = [...expertBands];
  for (const rule of base) {
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

/**
 * Distinguishes one engine's cached answers from another's. Module-level so it
 * counts across every engine ever built in this context, which is what makes a
 * generation unique rather than merely different from its predecessor.
 */
let nextEngineGeneration = 1;

/**
 * The slot value meaning "walked the whole chain and nothing matched".
 *
 * Cached like any other answer, deliberately: it is the *expensive* one, being
 * the only result that has run every matcher in the chain.
 */
const NO_RULE_SLOT = 255;

/** Slots per generation, so generation and slot pack into one small integer. */
const SLOT_RADIX = 256;

export class ColorRulesEngine {
  private compiled: CompiledRule[];

  /**
   * Which engine this is, so a stale cached answer is recognised as stale.
   *
   * Every engine gets a number no other engine has had. A packet caches the
   * rule it matched together with the generation that decided it, so an engine
   * built from an edited chain simply does not recognise the previous engine's
   * answers - no invalidation pass, and no way for one to be mistaken for its
   * own.
   */
  private readonly generation = nextEngineGeneration++;

  /**
   * Whether a matched rule can be cached on the packet at all.
   *
   * The cache packs the generation and the rule's position into one number, so
   * it needs the position to fit in a byte. A chain longer than this is
   * degenerate - the shipped one is 21 enabled rules - and the answer is to
   * stop caching rather than to wrap, which would paint frames with a rule
   * that is not the one they matched.
   */
  private readonly cacheable: boolean;

  /**
   * @param rules the chain to match against, first-match-wins. Defaults to the
   * shipped chain; the app passes the user's edited one, and the parity
   * harness passes `WIRESHARK_DEFAULT_RULES` so it measures the engine against
   * Wireshark's own decisions rather than against Inwire's extra bands.
   */
  constructor(rules: ColorRule[] = DEFAULT_COLOR_RULES) {
    this.compiled = ColorRulesEngine.compile(rules);
    this.cacheable = this.compiled.length < NO_RULE_SLOT;
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
    const slot = this.cachedSlot(packet);
    if (slot !== null) return slot === NO_RULE_SLOT ? null : this.compiled[slot].rule;

    let matched: ColorRule | null = null;
    let matchedSlot = NO_RULE_SLOT;
    for (let i = 0; i < this.compiled.length; i++) {
      try {
        if (this.compiled[i].matcher(packet)) {
          matched = this.compiled[i].rule;
          matchedSlot = i;
          break;
        }
      } catch {
        // A rule that can't be evaluated simply doesn't match.
      }
    }
    if (this.cacheable) {
      packet.colorSlot = this.generation * SLOT_RADIX + matchedSlot;
    }
    return matched;
  }

  /**
   * This engine's own cached answer for a packet, or null if it has none.
   *
   * The generation check is what makes a packet safe to carry a cache at all:
   * an answer written by a previous chain unpacks to a different generation and
   * is ignored, so an edited chain needs no invalidation pass over the buffer
   * and cannot read the old chain's decisions as its own.
   */
  private cachedSlot(packet: Packet): number | null {
    const packed = packet.colorSlot;
    if (packed === undefined || !this.cacheable) return null;
    if (Math.floor(packed / SLOT_RADIX) !== this.generation) return null;
    return packed % SLOT_RADIX;
  }

  /**
   * The rule this packet is already known to match, without walking the chain.
   *
   * `undefined` means "not decided yet" and is a real answer, distinct from
   * `null`'s "decided, and nothing matched". It is what lets a caller paint
   * what is known and come back for the rest - the minimap uses it to avoid
   * a synchronous pass over the whole buffer after a rule edit, which measured
   * 202 ms at 100,000 frames and 1,985 ms at a million.
   */
  public matchedRuleIfKnown(packet: Packet): ColorRule | null | undefined {
    const slot = this.cachedSlot(packet);
    if (slot === null) return undefined;
    return slot === NO_RULE_SLOT ? null : this.compiled[slot].rule;
  }

  /** Decides this packet's rule if it is not already decided. */
  public resolve(packet: Packet): void {
    this.matchRule(packet);
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
  // **There was a `getPacketAccent` here and it is deliberately gone.** It
  // returned the matched rule's hue at text strength, and the inspection pane,
  // the hex pane and the detail window pushed it down as a `--primary`
  // override so every accent in them took the colour of the row the frame was
  // selected from. Its argument was that a label in the app accent "said the
  // same thing for every frame"; the answer is that a pane showing one frame
  // does not need to be told which frame, and an accent that changes hue as you
  // arrow through the list is motion carrying no information.
  //
  // The rule is still named in those panes - `getMatchedRuleName` - in words,
  // which is the form that survives a colourblind set and a screenshot. And the
  // list still paints by rule, which is where colour answers a question nothing
  // else does: which of four hundred rows on screen is the broken one.

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
