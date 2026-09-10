import { DEFAULT_COLOR_RULES } from './colorRules';
import { themePalette, type Hue, type ThemePalette } from './themePalettes';
import { AA_CONTRAST, contrastRatio, isDarkColor, labToHex, legibleOn, toLabColor } from '../lib/colorMix';

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
  | 'error'    // something is wrong: bad TCP, abort, checksum, ICMP errors
  /**
   * A connection was killed. Louder than `error`, and separate from it.
   *
   * The reference analyzer draws this distinction and it is worth keeping: its
   * whole default set works by polarity, with ordinary rows a pale fill under
   * one dark text colour and the broken ones inverting that - dark ground,
   * bright text. `TCP RST` is the single rule that breaks even from *those*,
   * taking a saturated red fill rather than the near-black the other error
   * rules share. Bad TCP and a checksum failure mean "something is off with
   * this segment"; a reset means the conversation is over.
   *
   * Folded into `error` here until now, which lost that step - the two
   * rendered identically.
   */
  | 'reset'
  /**
   * The seven other expert categories.
   *
   * Every one carries a stated colour rather than a derived one, and it is not
   * a preference: `derive()` has nine hues, all nine are spoken for, and the
   * deltaE >= 4 floor between fills already sits at 4.6 with no room. A stated
   * pair also carries its own text, so it depends on no theme underneath it -
   * which is what lets eight new bands exist at all.
   */
  | 'broken'
  | 'loss'
  | 'captureGap'
  | 'flowControl'
  | 'unverifiable'
  | 'expertNote'
  | 'expertSecurity'
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
  // Red as well, and only ever used when a colour set substitutes the hues -
  // see FIXED_ROLE_COLORS, which normally answers for this role instead. It is
  // still declared because a role without a hue is a role the palette cannot
  // fall back for, and `colorblind` needs exactly that fallback.
  reset: 'red',
  // Fallbacks for `colorblind`, which declines stated colours. They collapse
  // onto existing hues there, which is the right trade: that set exists so a
  // reader who cannot use the red/green axis gets a list they can read, and
  // eight more saturated fills is the opposite of that.
  broken: 'red',
  loss: 'orange',
  captureGap: 'violet',
  flowControl: 'cyan',
  unverifiable: 'neutral',
  expertNote: 'green',
  expertSecurity: 'magenta',
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
  'color-tcp-rst': 'reset',

  // The expert bands. `color-expert-reset` shares `reset` with `color-tcp-rst`
  // deliberately: they fire on the same frames from two directions - one on
  // the flag, one on the finding - and painting them differently would be two
  // colours for one event.
  'color-expert-broken': 'broken',
  'color-expert-reset': 'reset',
  'color-expert-security': 'expertSecurity',
  'color-expert-loss': 'loss',
  'color-expert-capture-gap': 'captureGap',
  'color-expert-flow-control': 'flowControl',
  'color-expert-unverifiable': 'unverifiable',
  'color-expert-note': 'expertNote',
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

  // Inwire's three additions (services/colorRules INWIRE_EXTRA_RULES).
  'color-tls-handshake': 'web',
  'color-quic': 'tcp',
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

/**
 * The three colour sets the packet list can be painted in.
 *
 * A second axis over the app theme, and deliberately a *narrow* one. It does
 * not introduce new palettes: `default` and `vibrant` are the same nine theme
 * hues put through the same Lab derivation with two knobs moved, so a Midnight
 * list stays recognisably Midnight either way. Only `colorblind` substitutes
 * hues, and it has to - see OKABE_ITO.
 *
 * Scoped to the packet list and the accents derived from it. The map arcs, the
 * protocol donut and the timeline all read `themePalettes` directly and keep
 * the theme's plain hues, because those surfaces show a handful of large areas
 * where nine hues are already easy to tell apart. The list is the surface where
 * a screenful of small rows has to be distinguished at a glance, and the only
 * one where the trade between loudness and separation is worth a choice.
 */
export type PacketColorSet = 'default' | 'vibrant' | 'colorblind';

export const PACKET_COLOR_SETS: PacketColorSet[] = ['default', 'vibrant', 'colorblind'];

/**
 * Okabe-Ito, the reference set for colour-vision-safe categorical palettes.
 *
 * A retired "Colorblind Safe" *app theme* used to carry these as its nine hues.
 * It is gone, and the set is authored here instead, which is the better place
 * for it: colour-vision safety is a property of the data colours, so as a theme
 * it dragged along a ground and a chrome nobody asked for, and it could not be
 * combined with the dark theme somebody actually wanted to work in. As a colour
 * set it composes with all four themes.
 *
 * Only the a/b direction of each entry is used - `derive` takes lightness from
 * the theme's own ground - so one table serves the light themes and the dark
 * ones. The two near-neutral entries are the exception, and the reason
 * NEUTRAL_CHROMA exists: `magenta` is Okabe-Ito's black and `neutral` a grey,
 * neither of which has an a/b to be told apart by, so both fall back to their
 * own lightness relative to the ground.
 *
 * Mapped onto hue NAMES rather than onto roles, so it flows through the same
 * HUE_BY_ROLE table as every theme and nothing downstream has to know this set
 * exists. Sky blue takes `cyan`, reddish purple takes `violet`, vermillion
 * takes `red`.
 *
 * What makes it safe is not the hue spacing on its own - a deuteranope loses
 * most of the red/green axis whatever the hexes are. It is that the eight
 * chromatic entries also form a luminance ramp, which is the axis
 * LIGHTNESS_BY_HUE already spreads the fills along and `rampScale` stretches.
 */
const OKABE_ITO: Record<Hue, string> = {
  red: '#d55e00',     // vermillion
  orange: '#e69f00',  // orange
  yellow: '#f0e442',  // yellow
  green: '#009e73',   // bluish green
  cyan: '#56b4e9',    // sky blue
  blue: '#0072b2',    // blue
  violet: '#cc79a7',  // reddish purple
  magenta: '#000000', // black
  neutral: '#999999', // grey - not Okabe-Ito's, which has only eight entries
};

export interface PacketColorSetSpec {
  label: string;
  /** How much of each hue's colourfulness a fill keeps. See CHROMA_SCALE. */
  chromaScale: number;
  /** Multiplier on LIGHTNESS_BY_HUE, so a set can buy separation on L. */
  rampScale: number;
  /**
   * Multiplier on LIGHTNESS_SHIFT_ON_LIGHT / _ON_DARK - how far the whole band
   * of fills sits from the theme's ground.
   *
   * Exists because of sRGB, not because of design. A fill is built in Lab and
   * then converted, and Lab describes colours sRGB cannot show: a pale blue at
   * L 80 with any real b runs the blue channel past 255 and gets clamped, which
   * silently discards exactly the a/b separation the fill was carrying. That is
   * how `colorblind` first arrived with sky blue and blue 1.7 deltaE apart on
   * Day - two distinct hues, both clamped to the same near-white. Moving the
   * band away from the ground moves it back inside the gamut, where the hues
   * survive the conversion.
   */
  shiftScale: number;
  /** Substitutes the theme's own nine hues. `colorblind` only. */
  hues?: Record<Hue, string>;
  /**
   * The loudest fill this set may produce, asserted by
   * `scripts/themes/packet-themes.ts`.
   *
   * Per set rather than global, and that is the point of the whole feature. The
   * single global ceiling existed to stop somebody raising CHROMA_SCALE to buy
   * separation the deltaE floors should buy instead. That reasoning still holds
   * for `default`, the list almost everybody reads; it is exactly what
   * `vibrant` exists to opt out of. The FLOORS - WCAG AA on every fill, and all
   * three deltaE bars - stay identical for every set.
   */
  maxChroma: number;
}

export const PACKET_COLOR_SET_SPECS: Record<PacketColorSet, PacketColorSetSpec> = {
  /** Today's list, unchanged. Quiet, and separated mostly on lightness. */
  default: {
    label: 'Default',
    chromaScale: CHROMA_SCALE,
    rampScale: 1,
    shiftScale: 1,
    maxChroma: 22,
  },
  /**
   * Loud on purpose.
   *
   * Roughly double the chroma, which is above where the list sat before it was
   * quietened (0.42) - and the ramp widens with it rather than being left
   * alone, because a fill pushed past the sRGB gamut boundary gets clamped, and
   * clamping is what drags two saturated fills back toward each other. Spending
   * some of the extra separation on L is what keeps the deltaE floors clear at
   * this chroma rather than only just met.
   */
  vibrant: { label: 'Vibrant', chromaScale: 0.5, rampScale: 1.3, shiftScale: 1, maxChroma: 40 },
  /**
   * Okabe-Ito, with the lightness ramp stretched.
   *
   * Chroma sits between the other two: enough that the eight chromatic entries
   * read as colours, not so much that anyone is invited to read meaning off a
   * hue a deuteranope cannot recover. The ramp does that work instead.
   */
  colorblind: {
    label: 'Colourblind',
    chromaScale: 0.3,
    rampScale: 1.6,
    shiftScale: 1.9,
    hues: OKABE_ITO,
    maxChroma: 26,
  },
};

/** The set for a stored value, falling back to `default` for anything else. */
export function packetColorSet(raw: unknown): PacketColorSet {
  return PACKET_COLOR_SETS.includes(raw as PacketColorSet) ? (raw as PacketColorSet) : 'default';
}

/**
 * How much of the row's own ink the Source column's program name keeps.
 *
 * `<address>\<program>` is dimmed deliberately - the address is the identity
 * and the program is an annotation, and at full strength the two read as one
 * long token and the column stops scanning as a list of addresses. The dim was
 * `text-muted-foreground`, which is the APP theme's grey painted on a row the
 * colouring chain filled, and measured across every rule in every theme and
 * colour set its worst case was **1.06:1** - invisible. Eleven of the twelve
 * theme/set combinations were below 1.5:1.
 *
 * Dimming is now a reduction of the row's OWN ink, which the colouring rule
 * chose to be legible on that row's fill, so the annotation inherits the
 * contrast the rule already guaranteed and only gives back a fixed fraction of
 * it. Worst case 3.77:1 at this value, against 4.51:1 undimmed - the rule inks
 * clear AA on their own fills with almost nothing spare, so any dim at all
 * costs some of it, and this buys back the hierarchy for the least.
 * `scripts/themes/packet-themes.ts` holds it to a floor so a palette change
 * cannot quietly undo this.
 */
export const SENDER_INK_ALPHA = 0.85;

/** The floor that value is held to. Below this the annotation stops reading. */
export const SENDER_INK_MIN_CONTRAST = 3;

// WCAG AA for normal text. The list is small monospace, so this is a floor.
const AA = AA_CONTRAST;

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
  spec: PacketColorSetSpec,
): PacketThemeColors {
  const [hueL, ha, hb] = toLabColor(hue);
  const [groundL] = toLabColor(palette.surface.background);
  const a = ha * spec.chromaScale;
  const b = hb * spec.chromaScale;

  // A hue with essentially no colour cannot be told apart by a/b, so it leans
  // on its own lightness instead - otherwise every near-neutral entry in a
  // palette collapses onto the same grey fill.
  const toward = Math.hypot(ha, hb) < NEUTRAL_CHROMA ? (hueL - groundL) * 0.6 : 0;
  // Both offsets point away from the ground, which is what `Math.sign` is for:
  // on a light theme `shift` is negative and the ramp has to darken with it.
  const ramp = Math.sign(shift) * LIGHTNESS_BY_HUE[name] * spec.rampScale;
  const L = Math.max(2, Math.min(97, groundL + shift + ramp + toward));
  return readablePair(labToHex([L, a, b]), palette);
}

/**
 * The packet palette for an app theme.
 *
 * Falls back through `themePalette`, so an unknown or not-yet-resolved theme
 * name yields the dark palette rather than an uncoloured list.
 */
export function getPacketThemeForApp(
  resolvedTheme: string | undefined,
  set: PacketColorSet = 'default',
): PacketTheme {
  const palette = themePalette(resolvedTheme);
  const spec = PACKET_COLOR_SET_SPECS[set] ?? PACKET_COLOR_SET_SPECS.default;
  // A set may substitute the nine hues outright - `colorblind` does - but never
  // the SURFACE, which stays the theme's own. That split is what lets a colour
  // set compose with all four themes instead of being a fifth theme: the
  // ground, the text and the borders belong to the app, and only the data
  // colours belong to the set.
  const hues = spec.hues ?? palette.hues;
  const shift = (isDarkColor(palette.surface.background)
    ? LIGHTNESS_SHIFT_ON_DARK
    : LIGHTNESS_SHIFT_ON_LIGHT) * spec.shiftScale;

  const rules: Record<string, PacketThemeColors> = {};
  const accents: Record<string, string> = {};
  for (const rule of DEFAULT_COLOR_RULES) {
    const role = ROLE_BY_RULE_ID[rule.id] ?? 'neutral';
    const name = HUE_BY_ROLE[role];
    const hue = hues[name];
    // A stated colour wins over a derived one - unless the set has substituted
    // the hues, which is the colourblind set saying the derived ramp is the
    // whole point of it.
    const fixed = spec.hues === undefined ? FIXED_ROLE_COLORS[role] : undefined;
    rules[rule.id] = fixed ?? derive(name, hue, palette, shift, spec);
    // From the theme's HUE, even for a stated fill.
    //
    // An accent is panel text, not a row fill: its job is to sit legibly on a
    // card and stay on the same hue axis as every other accent, which is what
    // `scripts/themes/packet-themes.ts` asserts. Taking it from the stated
    // `#a40000` instead put the reset accent 13.6 degrees off the theme's red
    // - still red, but off the axis the rest of the panel is built on, for no
    // gain. The row is the thing that has to shout; the accent only has to be
    // recognisably the same colour family.
    accents[rule.id] = legibleOn(hue, palette.surface.card, AA);
  }

  return {
    id: `${resolvedTheme ?? 'dark'}:${set}`,
    label: `${resolvedTheme ?? 'dark'} ${spec.label}`,
    surface: palette.surface,
    rules,
    accents,
    accentFallback: legibleOn(hues.neutral, palette.surface.card, AA),
  };
}

/** Re-exported so callers of the packet palette need only one import. */
export { contrastRatio };

/**
 * Roles whose colours are stated rather than derived from the theme's hues.
 *
 * The reference analyzer's own `TCP RST` pair, transcribed from its shipped
 * `colorfilters` (`[42148,0,0][65535,64764,40092]` in its 16-bit form). Kept
 * literal because the point of this role is to be the loudest thing in the
 * list, and a fill tinted into the theme's ground is by construction not that
 * - on Day the derived red came out `#ffdfd7`, a pale salmon that reads as
 * "red" only if you already knew.
 *
 * It is safe to state both halves because the row supplies its own ground AND
 * its own text: nothing about it depends on the theme underneath, and the pair
 * clears WCAG AAA at 7.6:1. That is what makes this different from hard-coding
 * a background and hoping the theme's foreground still reads on it.
 *
 * **A colour set that substitutes the hues overrides this** - see
 * `getPacketThemeForApp`. `colorblind` exists so that somebody who cannot rely
 * on the red/green axis still gets a list they can read, and answering them
 * with a saturated red because another analyzer uses one would defeat the only
 * thing that set is for.
 */
const FIXED_ROLE_COLORS: Partial<Record<RuleRole, PacketThemeColors>> = {
  // The reference analyzer's own RST pair, and the model for the rest.
  reset: { background: '#a40000', color: '#fffc9c' },

  // The expert categories, following the same polarity convention the
  // reference analyzer uses across its whole default set: ordinary rows are a
  // pale fill under dark text, and the ones that mean something is wrong
  // invert that - a dark ground with bright text. The eye catches the
  // inversion far faster than it catches one pale tint among several.
  //
  // So the four that mean trouble are dark grounds...
  broken: { background: '#4a0d0d', color: '#ffb3b3' },
  expertSecurity: { background: '#4a0a52', color: '#f0a6ff' },
  loss: { background: '#5c3200', color: '#ffcf80' },

  // ...and the four that are context rather than fault are muted mid-tones,
  // dark enough to read light text on every theme without shouting. A capture
  // gap, a keep-alive and an unverifiable checksum are not faults, and giving
  // them the same weight as a broken frame is what made the old expert band
  // unusable.
  captureGap: { background: '#2c2246', color: '#c3b6f0' },
  flowControl: { background: '#0e2f3d', color: '#9adcf0' },
  unverifiable: { background: '#2a2a2a', color: '#b0b0b0' },
  expertNote: { background: '#0a4033', color: '#8fdcbb' },
};

/** Every rule id a theme is expected to cover. Used by the tests. */
export const REQUIRED_RULE_IDS: string[] = DEFAULT_COLOR_RULES.map((r) => r.id);

/** The role assignments, exported so the tests can assert full coverage. */
export { ROLE_BY_RULE_ID, HUE_BY_ROLE, FIXED_ROLE_COLORS };
