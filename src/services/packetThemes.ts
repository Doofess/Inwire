import { DEFAULT_COLOR_RULES } from './colorRules';
import { themePalette, type Hue, type ThemePalette } from './themePalettes';
import { contrastRatio, isDarkColor, labToHex, legibleOn, toLabColor } from '../lib/colorMix';

/**
 * The colours the packet list paints itself with, derived from the app theme.
 *
 * This used to be a second, independent theme axis: six hand-authored palettes
 * picked from Settings, stored under their own preference key, and unrelated to
 * the app theme - so a first-run user on a light app theme got a dark packet
 * list, and the `solarized` packet palette had nothing to do with the
 * `solarized-dark` app theme beyond the name. The separation bought the ability
 * to pair a light list with a dark UI; it cost coherence everywhere else, and
 * coherence is what was wanted.
 *
 * What survives from that design, because the reasoning still holds:
 *
 *   - **A theme owns the list's ground, not just its fills.** The rule chain
 *     has no catch-all - it ends at Broadcast, exactly as the reference analyzer's does - so
 *     a packet matching nothing has no rule colour at all. `surface` is what
 *     those rows use, which keeps the list internally consistent instead of
 *     letting unmatched rows fall through to whatever the app is painting.
 *   - **Colours are keyed by `ColorRule.id`**, which keeps matching and
 *     appearance apart: colorRules.ts decides *which* rule a packet matched and
 *     memoizes it per packet; this decides what that rule looks like. Switching
 *     themes therefore costs nothing at capture volume - no re-matching, no
 *     cache to invalidate.
 *
 * What changed is only where the colours come from. Rather than eight themes ×
 * twenty rules of hand-authored pairs - 160 values that would drift apart - each
 * rule is assigned a **role**, each role maps to a **hue**, and each theme
 * supplies its own nine hues (see themePalettes.ts). Adding a colour rule later
 * costs one role assignment instead of eight table edits.
 */
export interface PacketThemeColors {
  background: string;
  color: string;
}

export interface PacketTheme {
  id: string;
  label: string;
  surface: {
    background: string;
    foreground: string;
    border: string;
  };
  /** Keyed by ColorRule.id. Every built-in rule has an entry. */
  rules: Record<string, PacketThemeColors>;
  /**
   * The same colours, as text on a panel rather than as a row fill.
   *
   * Keyed by ColorRule.id like `rules`, and derived from the same hue, so the
   * frame number in the inspection pane's header is recognisably the colour of
   * the row it was selected from. It cannot BE that colour: a row fill is a
   * pale wash chosen to sit under small text, and the same value used as text
   * on a card would be invisible. So the hue is taken at full strength and only
   * its lightness is moved, far enough to be readable on `surface.card`.
   */
  accents: Record<string, string>;
  /**
   * For a packet that matched no rule at all - the chain ends at Broadcast and
   * has no catch-all, so this is a common case rather than an edge one.
   */
  accentFallback: string;
}

/**
 * What a colouring rule *means*, independent of any theme.
 *
 * Ten roles for twenty rules, taken from what the reference analyzer's chain is actually
 * saying rather than from protocol names - which is why `color-tcp-rst` and
 * `color-checksum-errors` share one role: both mean "this is broken".
 */
export type RuleRole =
  | 'error'    // something is wrong: bad TCP, RST, abort, checksum, ICMP errors
  | 'warn'     // suspicious but not broken: low TTL, SYN+FIN
  | 'notice'   // topology and routing state changed
  | 'web'      // HTTP
  | 'session'  // SMB, DCERPC - session and RPC services
  | 'tcp'
  | 'udp'
  | 'arp'
  | 'icmp'
  | 'neutral'; // broadcast, and the ground for anything unmatched

/**
 * Ten roles onto nine hues.
 *
 * **Assigned by how often you actually see a role, not by tradition.** The
 * first attempt followed the reference analyzer's own hues - TCP blue, UDP cyan - and that
 * put the two most common protocols in any capture on adjacent hues. Tinted
 * into a near-white ground they collapsed into the same pale wash, so the
 * majority of rows in a light theme were indistinguishable from each other,
 * which is the one comparison the list has to support.
 *
 * So the frequent roles are spread as far apart as nine hues allow - `tcp`
 * blue, `udp` green, `icmp` magenta, `arp` yellow, `error` red - and the rare
 * ones take what is left. `warn` and `notice` share ORANGE, which is the single
 * remaining collision: both mean "worth a look, nothing is broken", and both
 * cover states (low TTL, an STP topology change) you may go a whole capture
 * without seeing.
 *
 * `scripts/themes/packet-themes.ts` measures the result in Lab and enforces
 * three floors, so this ordering cannot quietly regress: 4 deltaE between any
 * two fills, 7 between any two FREQUENT ones, and 15 between TCP and UDP
 * specifically - the one comparison a reader makes on every screen.
 */
const HUE_BY_ROLE: Record<RuleRole, Hue> = {
  error: 'red',
  warn: 'orange',
  notice: 'orange',
  arp: 'yellow',
  udp: 'green',
  web: 'cyan',
  tcp: 'blue',
  session: 'violet',
  icmp: 'magenta',
  neutral: 'neutral',
};

/** Every built-in rule, and what it means. Theme-independent by design. */
const ROLE_BY_RULE_ID: Record<string, RuleRole> = {
  'color-bad-tcp': 'error',
  'color-tcp-rst': 'error',
  'color-sctp-abort': 'error',
  'color-checksum-errors': 'error',
  'color-icmp-errors': 'error',

  'color-ipv4-ttl-low': 'warn',
  'color-ipv6-hop-limit-low': 'warn',
  'color-tcp-syn-fin': 'warn',

  'color-hsrp-state-change': 'notice',
  'color-stp-topology-change': 'notice',
  'color-ospf-state-change': 'notice',
  'color-routing': 'notice',

  'color-http': 'web',
  'color-smb': 'session',
  'color-dcerpc': 'session',

  'color-tcp': 'tcp',
  'color-udp': 'udp',
  'color-arp': 'arp',
  'color-icmp': 'icmp',
  'color-broadcast': 'neutral',
};

/**
 * How much of each hue's own colourfulness a fill keeps.
 *
 * Fills are built in Lab, not by mixing toward the ground, and that is the
 * whole fix for "UDP and TCP are almost the same colour". Mixing has one knob,
 * and it moves lightness and chroma together: to keep a row readable the mix
 * had to stay low, and a low mix drags every hue toward the ground, so nine
 * well-separated hues arrived as nine near-identical washes. Reducing the mix
 * to satisfy contrast made the collapse worse, not better.
 *
 * In Lab the two are separate knobs. A fill takes its hue's **a/b direction**
 * scaled by this, and its **lightness** from the ground - so hue separation and
 * text contrast stop fighting each other.
 *
 * This was 0.42, and at that strength a screen of ordinary traffic was nine
 * competing washes: everything was tinted, so nothing stood out. It is now a
 * little over half that, which is only possible because LIGHTNESS_BY_HUE below
 * carries the separation chroma gave up. Cutting this alone would scale every
 * inter-fill deltaE by the same factor and the list would stop being readable
 * at exactly the point it stopped being loud.
 */
const CHROMA_SCALE = 0.24;

/**
 * Below this, a palette hue carries no usable colour and must separate by
 * lightness instead.
 *
 * Two hues with no chroma produce the same fill however far apart they look on
 * their own: Colorblind Safe's `magenta` is Okabe-Ito's black and its `neutral`
 * is a mid grey, and both arrive at the ground's lightness with no a/b to tell
 * them apart. Falling back to the hue's OWN lightness is what keeps a
 * near-neutral palette entry meaningful.
 */
const NEUTRAL_CHROMA = 8;

/**
 * How far a fill's lightness sits from the theme's own ground.
 *
 * Away from the ground rather than toward it, so a coloured row is also
 * distinguishable from an unmatched one - the chain has no catch-all, so plenty
 * of rows are painted the bare ground.
 */
const LIGHTNESS_SHIFT_ON_LIGHT = -7;
const LIGHTNESS_SHIFT_ON_DARK = 11;

/**
 * Each hue's own lightness, on top of the shared shift above.
 *
 * This is the property that makes Okabe-Ito - the reference set for
 * colour-vision-safe categorical palettes - survive both CVD and greyscale
 * printing. It is not the hue spacing: it is that the colours ALSO form a
 * luminance ramp, roughly L* 88 at the yellow end down to L* 40 at the blue
 * end. Hue collapses under a colour-vision deficiency; lightness does not.
 *
 * Before this table every fill sat at exactly `ground L + shift`, so the whole
 * of a row's identity was carried by chroma - which is precisely why the list
 * could not be made quieter without becoming unreadable. Spreading the nine
 * over ~14 points of L buys that separation back on an axis that costs nothing
 * in loudness.
 *
 * Signed with `shift`, so the offset always moves AWAY from the ground: on a
 * light theme these darken, on a dark theme they lighten. Ordered so the
 * frequent pairs sit at opposite ends - `blue` (TCP) and `green` (UDP) are 9
 * points apart before their hues are even considered.
 */
const LIGHTNESS_BY_HUE: Record<Hue, number> = {
  blue: -7,
  violet: -5,
  cyan: -4,
  red: -2,
  magenta: -1,
  orange: 1,
  green: 2,
  yellow: 5,
  neutral: 7,
};

/** WCAG AA for normal text. The list is small monospace, so this is a floor. */
const AA = 4.5;

function bestForeground(palette: ThemePalette, background: string): string {
  const onForeground = contrastRatio(palette.surface.foreground, background);
  const onBackground = contrastRatio(palette.surface.background, background);
  return onForeground >= onBackground ? palette.surface.foreground : palette.surface.background;
}

/**
 * One rule's colours on one palette.
 *
 * Built in Lab so the two requirements stop competing:
 *
 * **Hue separation** comes from the a/b axes - each fill points in its own
 * hue's direction, scaled to a common colourfulness. Nine hues therefore stay
 * nine visibly different fills regardless of how light the ground is, which is
 * what the mixing approach could not do.
 *
 * **Legibility** comes from the L axis alone. Lightness starts a fixed step off
 * the ground and moves further from the text until the row clears WCAG AA -
 * and because that knob is independent of a/b, buying contrast no longer costs
 * colour. On a theme whose own body text only just clears AA (Solarized Light
 * is 4.79:1) this is the difference between vivid rows and nine shades of
 * cream.
 *
 * The foreground is still chosen rather than assumed: whichever of the theme's
 * two surface colours contrasts better wins, because a row nobody can read is
 * a worse failure than one slightly off-palette.
 */
function readablePair(background: string, palette: ThemePalette): PacketThemeColors {
  const color = bestForeground(palette, background);
  if (contrastRatio(color, background) >= AA) return { background, color };

  // Deepen the TEXT rather than moving the fill. Two reasons: the fill is
  // carrying the information, so changing it costs the separation this whole
  // scheme exists to produce; and the text keeps its own hue, so a deepened
  // Solarized foreground is still Solarized.
  //
  // The earlier version moved the fill instead, and moved it the wrong way -
  // stepping lightness further from the ground on a light theme makes the fill
  // darker, which reduces contrast against dark text rather than increasing it.
  // Solarized Light sat at 4.16:1 with every row failing for that reason.
  const [textL, textA, textB] = toLabColor(color);
  const [fillL] = toLabColor(background);
  const away = textL < fillL ? -1 : 1;
  for (let step = 4; step <= 70; step += 3) {
    const candidate = labToHex([
      Math.max(0, Math.min(100, textL + away * step)),
      textA,
      textB,
    ]);
    if (contrastRatio(candidate, background) >= AA) return { background, color: candidate };
  }
  // Text alone is not always enough. A fill that lands mid-tone has poor
  // contrast with BOTH ends of the scale - Solarized Dark's broadcast row sat
  // at L45, where even pure black only reaches 4.0:1 - so the last resort is to
  // move the fill itself, away from the text. Done only here, after colour has
  // been given every chance, because moving the fill is what costs separation.
  const [, fa, fb] = toLabColor(background);
  for (let step = 4; step <= 50; step += 4) {
    const nudged = labToHex([
      Math.max(2, Math.min(97, fillL - away * step)),
      fa,
      fb,
    ]);
    const candidate = bestForeground(palette, nudged);
    if (contrastRatio(candidate, nudged) >= AA) return { background: nudged, color: candidate };
  }
  return { background, color: away < 0 ? '#000000' : '#ffffff' };
}

/**
 * One rule's colours on one palette.
 *
 * Built in Lab so hue separation and legibility stop competing for one knob:
 *
 * **Separation** comes from the a/b axes - each fill points in its own hue's
 * direction, scaled to a common, deliberately restrained colourfulness. Nine
 * hues stay nine visibly different fills however light the ground is, which
 * mixing toward the ground could not achieve: a mix low enough to keep rows
 * readable dragged every hue into the same pale wash, and TCP, UDP and QUIC
 * became indistinguishable.
 *
 * **Legibility** is then handled entirely on the text, by `readablePair`, so
 * buying contrast never costs colour.
 */
function derive(
  name: Hue,
  hue: string,
  palette: ThemePalette,
  shift: number,
): PacketThemeColors {
  const [hueL, ha, hb] = toLabColor(hue);
  const [groundL] = toLabColor(palette.surface.background);
  const a = ha * CHROMA_SCALE;
  const b = hb * CHROMA_SCALE;

  // A hue with essentially no colour cannot be told apart by a/b, so it leans
  // on its own lightness instead - otherwise every near-neutral entry in a
  // palette collapses onto the same grey fill.
  const toward = Math.hypot(ha, hb) < NEUTRAL_CHROMA ? (hueL - groundL) * 0.6 : 0;
  // Both offsets point away from the ground, which is what `Math.sign` is for:
  // on a light theme `shift` is negative and the ramp has to darken with it.
  const ramp = Math.sign(shift) * LIGHTNESS_BY_HUE[name];
  const L = Math.max(2, Math.min(97, groundL + shift + ramp + toward));
  return readablePair(labToHex([L, a, b]), palette);
}

/**
 * The packet palette for an app theme.
 *
 * Falls back through `themePalette`, so an unknown or not-yet-resolved theme
 * name yields the dark palette rather than an uncoloured list.
 */
export function getPacketThemeForApp(resolvedTheme: string | undefined): PacketTheme {
  const palette = themePalette(resolvedTheme);
  const shift = isDarkColor(palette.surface.background)
    ? LIGHTNESS_SHIFT_ON_DARK
    : LIGHTNESS_SHIFT_ON_LIGHT;

  const rules: Record<string, PacketThemeColors> = {};
  const accents: Record<string, string> = {};
  for (const rule of DEFAULT_COLOR_RULES) {
    const role = ROLE_BY_RULE_ID[rule.id] ?? 'neutral';
    const name = HUE_BY_ROLE[role];
    const hue = palette.hues[name];
    rules[rule.id] = derive(name, hue, palette, shift);
    accents[rule.id] = legibleOn(hue, palette.surface.card, AA);
  }

  return {
    id: resolvedTheme ?? 'dark',
    label: resolvedTheme ?? 'dark',
    surface: palette.surface,
    rules,
    accents,
    accentFallback: legibleOn(palette.hues.neutral, palette.surface.card, AA),
  };
}

/** Re-exported so callers of the packet palette need only one import. */
export { contrastRatio };

/** Every rule id a theme is expected to cover. Used by the tests. */
export const REQUIRED_RULE_IDS: string[] = DEFAULT_COLOR_RULES.map((r) => r.id);

/** The role assignments, exported so the tests can assert full coverage. */
export { ROLE_BY_RULE_ID, HUE_BY_ROLE };
