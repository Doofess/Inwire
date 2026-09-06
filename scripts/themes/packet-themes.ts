/**
 * Assertion tests for the packet palettes.
 *
 *   npx tsx scripts/themes/packet-themes.ts
 *
 * The packet list no longer has themes of its own: it derives its colours from
 * whichever app theme is active, by assigning each colouring rule a semantic
 * role and each role a hue from that theme's own published palette. Three
 * properties matter, and the order has changed with the architecture:
 *
 *   - **Coverage.** A palette is a lookup keyed by rule id. Adding a rule to
 *     the chain without giving it a role would paint that traffic with the
 *     theme's plain ground - a silent gap, since nothing throws.
 *   - **Legibility.** This is now the load-bearing test. Colours are computed
 *     rather than hand-picked, so nobody eyeballs each pair before it ships;
 *     the only thing standing between a derivation bug and an unreadable
 *     packet list is this check. It runs over every theme crossed with every
 *     colour set - twelve derivations - with **no exemptions**.
 *   - **No drift between the palette and the CSS.** Each palette hardcodes its
 *     theme's surface so canvas, MapLibre and these scripts can read it without
 *     a document. Two copies of the same three colours is a drift risk, so the
 *     copies are compared here against index.css itself.
 *
 * The test this replaces asserted that `classic` and `classic-dark` still
 * reproduced the reference analyzer's historical pastels byte-for-byte. That guarantee is
 * deliberately gone: the packet list now matches the app theme, which is a
 * restyle by intent rather than by accident.
 */
import fs from 'node:fs';
import path from 'node:path';
import {
  getPacketThemeForApp,
  packetColorSet,
  PACKET_COLOR_SETS,
  PACKET_COLOR_SET_SPECS,
  REQUIRED_RULE_IDS,
  ROLE_BY_RULE_ID,
  HUE_BY_ROLE,
  FIXED_ROLE_COLORS,
  contrastRatio,
  type PacketColorSet,
  type RuleRole,
} from '../../src/services/packetThemes';
import { PALETTE_BY_THEME, HUES, themePalette } from '../../src/services/themePalettes';
import { deltaE76, chroma, toLabColor } from '../../src/lib/colorMix';
import { THEME_OPTIONS } from '../../src/lib/themeOptions';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean) {
  check(name, condition, true);
}

const isHex = (s: string) => /^#[0-9a-f]{6}$/i.test(s.trim());
const THEMES = THEME_OPTIONS.map((t) => t.value);

/**
 * Every theme crossed with every colour set.
 *
 * The packet list gained a second axis - Default, Vibrant and Colourblind -
 * and the whole point of running the floors over the product rather than over
 * the themes alone is that a set is not a skin on top of a checked palette. It
 * moves chroma, the lightness ramp and how far the band of fills sits from the
 * ground, and Colourblind substitutes the nine hues outright. Twelve
 * derivations, twelve chances for two rows to collapse into each other.
 *
 * Which is not hypothetical: Colourblind's sky blue and blue first arrived 1.7
 * deltaE apart on Day - two unmistakably different hues clamped to the same
 * near-white by the sRGB gamut, at a lightness the Default set never reaches.
 * Only the crossed run could have caught it.
 */
const COMBOS: { theme: string; set: PacketColorSet; label: string }[] = THEMES.flatMap(
  (theme) => PACKET_COLOR_SETS.map((set) => ({ theme, set, label: `${theme}/${set}` })),
);

// --- Roles cover the chain, hues cover the roles -----------------------------

// Wireshark's twenty, plus Inwire's three (Expert Warnings, TLS Handshake,
// QUIC - see INWIRE_EXTRA_RULES for why they exist and why they are kept out
// of the array the parity harness compares against).
check('the rule chain has 30 rules to cover', REQUIRED_RULE_IDS.length, 30);

const rulesWithoutRole = REQUIRED_RULE_IDS.filter((id) => !ROLE_BY_RULE_ID[id]);
check('every rule in the chain has a role', rulesWithoutRole, []);

// The other half of the same drift: a rule renamed or removed leaves a role
// assignment behind that silently never applies.
const orphanRoles = Object.keys(ROLE_BY_RULE_ID).filter((id) => !REQUIRED_RULE_IDS.includes(id));
check('no role is assigned to a rule that does not exist', orphanRoles, []);

const rolesUsed = [...new Set(Object.values(ROLE_BY_RULE_ID))] as RuleRole[];
const rolesWithoutHue = rolesUsed.filter((r) => !HUE_BY_ROLE[r]);
check('every role in use maps to a hue', rolesWithoutHue, []);

const badHueNames = Object.values(HUE_BY_ROLE).filter((h) => !HUES.includes(h));
check('every role maps to a hue the palettes actually declare', badHueNames, []);

// --- Every app theme has a complete palette ----------------------------------

check('a palette exists for every app theme',
  THEMES.filter((t) => !PALETTE_BY_THEME[t]), []);

for (const theme of THEMES) {
  const palette = PALETTE_BY_THEME[theme];
  if (!palette) continue;

  const missingHues = HUES.filter((h) => !palette.hues[h]);
  check(`${theme}: declares all nine hues`, missingHues, []);

  const badHex = [
    ...Object.entries(palette.hues).map(([h, v]) => (isHex(v) ? null : `hue ${h}=${v}`)),
    ...Object.entries(palette.surface).map(([k, v]) => (isHex(v) ? null : `surface ${k}=${v}`)),
  ].filter(Boolean);
  check(`${theme}: every palette colour is a hex triple`, badHex, []);
}

// --- The derived palettes cover the chain ------------------------------------

for (const { theme, set, label } of COMBOS) {
  const packet = getPacketThemeForApp(theme, set);
  check(`${label}: covers every rule in the chain`,
    REQUIRED_RULE_IDS.filter((id) => !packet.rules[id]), []);
  check(`${label}: has no entries for rules that do not exist`,
    Object.keys(packet.rules).filter((id) => !REQUIRED_RULE_IDS.includes(id)), []);
  check(`${label}: every derived colour is a hex triple`,
    Object.entries(packet.rules)
      .flatMap(([id, c]) => [
        isHex(c.background) ? null : `${id}.background=${c.background}`,
        isHex(c.color) ? null : `${id}.color=${c.color}`,
      ])
      .filter(Boolean),
    []);
}

// --- The colour sets themselves ----------------------------------------------

// Same shape of drift as an orphaned role: a set listed but not specified would
// fall back to Default at runtime and look like the picker was broken.
check('every colour set has a spec',
  PACKET_COLOR_SETS.filter((s) => !PACKET_COLOR_SET_SPECS[s]), []);
check('no spec exists for a set that is not offered',
  Object.keys(PACKET_COLOR_SET_SPECS).filter((s) => !PACKET_COLOR_SETS.includes(s as PacketColorSet)),
  []);

// The stored preference is a string off localStorage, so anything can arrive.
check('an unknown stored set falls back to Default', packetColorSet('nope'), 'default');
check('a missing stored set falls back to Default', packetColorSet(undefined), 'default');
check('a real set is kept', packetColorSet('colorblind'), 'colorblind');

// Two sets that produce the same list are a picker entry that does nothing.
// Compared on Graphite, the default theme, and on the fills rather than the
// accents - the accents are derived from the hue directly and so are identical
// between Default and Vibrant by design.
{
  const fillsOf = (set: PacketColorSet) =>
    REQUIRED_RULE_IDS.map((id) => getPacketThemeForApp('dark', set).rules[id].background).join(',');
  const seen = new Map<string, PacketColorSet>();
  const duplicates: string[] = [];
  for (const set of PACKET_COLOR_SETS) {
    const key = fillsOf(set);
    const twin = seen.get(key);
    if (twin) duplicates.push(`${set} is identical to ${twin}`);
    seen.set(key, set);
  }
  check('the three colour sets are actually three different lists', duplicates, []);
}

// --- Legibility: the check that replaces human judgement ----------------------

// 4.5:1 is WCAG AA for normal text. The packet list is small monospace, so this
// is a floor rather than a target - and unlike the hand-authored palettes this
// replaces, there are no exemptions, because there is no longer a fidelity
// requirement pulling the other way.
const AA = 4.5;

for (const { theme, set, label } of COMBOS) {
  const packet = getPacketThemeForApp(theme, set);

  const weak = Object.entries(packet.rules)
    .map(([id, c]) => ({ id, ratio: contrastRatio(c.color, c.background) }))
    .filter((r) => r.ratio < AA)
    .map((r) => `${r.id} (${r.ratio.toFixed(2)}:1)`);
  check(`${label}: every row clears WCAG AA against its own fill`, weak, []);

  // An unmatched row is text on the theme's own ground, and there are plenty
  // of those - the chain deliberately has no catch-all. The ground belongs to
  // the theme, not to the set, which is exactly what makes a colour set safe to
  // combine with all four themes.
  const surfaceRatio = contrastRatio(packet.surface.foreground, packet.surface.background);
  checkTrue(
    `${label}: unmatched rows are legible on the ground (${surfaceRatio.toFixed(2)}:1)`,
    surfaceRatio >= AA,
  );
}

// --- Roles stay distinguishable from EACH OTHER ------------------------------

// The check that was missing, and the reason a bad palette shipped.
//
// Every other assertion here compares a fill against its own text or its own
// ground - "is this row readable" - and all of them passed while TCP, UDP and
// QUIC rows were, in the user's words, almost the same colour in light mode.
// Readability is not distinguishability: nine fills can each be perfectly
// legible and still be nine shades of the same wash.
//
// Measured in Lab rather than by contrast ratio, because the question is
// perceptual difference, not text legibility. ~2.3 deltaE is the just-noticeable
// difference; 10 is the floor for "obvious at a glance across a dense table
// where the two rows are not adjacent".
// Two thresholds, because the pairs are not equally important and one flat
// number would either be too lax for the pairs that matter or force garish
// colours onto the ones that do not.
//
// **Frequent roles** - TCP, UDP, HTTP, ICMP, ARP, errors, unmatched - are what
// fills a real capture, and telling those apart at a glance is the entire job
// of colouring the list. They get the strict bar.
//
// **Every pair** still has to clear the just-noticeable difference by a
// comfortable margin, but rare states (an STP topology change next to a low
// TTL) do not need to be obvious from across the room.
// Calibrated against what deliberately restrained chroma can actually deliver,
// not aspirationally: the design brief is "distinguishable but not vibrant", so
// a bar that could only be met by saturating everything would be the wrong bar.
// Measured worst cases at the shipped chroma are 16.6 (TCP/UDP, on Mono) and
// 4.6 (Gruvbox red vs orange), so each tier keeps real headroom.
const MIN_FREQUENT_DELTA_E = 7;
const MIN_ANY_DELTA_E = 4;

/**
 * The pair the user actually reported, held far higher than the rest.
 *
 * TCP and UDP are the bulk of every capture - and QUIC and DNS ride UDP, so
 * this one comparison covers the whole "UDP, TCP and QUIC are almost the same
 * colour" report. It is the pair most worth over-serving.
 */
const MIN_TCP_UDP_DELTA_E = 15;

// HTTP is deliberately absent: almost all web traffic is TLS now and matches
// `color-tcp`, so plain HTTP is a rare row rather than a frequent one.
const FREQUENT_RULES = [
  'color-tcp', 'color-udp', 'color-icmp', 'color-arp',
  'color-bad-tcp', 'color-broadcast',
];

// Every floor below runs over all twelve combinations, not over the four
// themes. A colour set is allowed to be louder or quieter than Default; it is
// not allowed to be less legible or less separable, and this is where that line
// is drawn.
for (const { theme, set, label } of COMBOS) {
  const packet = getPacketThemeForApp(theme, set);
  const fills = [...new Set(Object.values(packet.rules).map((c) => c.background))];

  const tooAlike: string[] = [];
  for (let i = 0; i < fills.length; i++) {
    for (let j = i + 1; j < fills.length; j++) {
      const d = deltaE76(fills[i], fills[j]);
      if (d < MIN_ANY_DELTA_E) tooAlike.push(`${fills[i]} vs ${fills[j]} (${d.toFixed(1)})`);
    }
  }
  check(`${label}: no two role fills are within ${MIN_ANY_DELTA_E} deltaE`, tooAlike, []);

  const frequentTooAlike: string[] = [];
  for (let i = 0; i < FREQUENT_RULES.length; i++) {
    for (let j = i + 1; j < FREQUENT_RULES.length; j++) {
      const [x, y] = [FREQUENT_RULES[i], FREQUENT_RULES[j]];
      const d = deltaE76(packet.rules[x].background, packet.rules[y].background);
      if (d < MIN_FREQUENT_DELTA_E) frequentTooAlike.push(`${x} vs ${y} (${d.toFixed(1)})`);
    }
  }
  check(`${label}: common traffic is obviously distinguishable`, frequentTooAlike, []);
}

// The exact pair the user reported. TCP and UDP dominate every capture, so if
// any two rows must be told apart it is these - and QUIC and DNS ride UDP, so
// this covers the whole "UDP, TCP and QUIC look the same" complaint.
for (const { theme, set, label } of COMBOS) {
  const packet = getPacketThemeForApp(theme, set);
  const d = deltaE76(packet.rules['color-tcp'].background, packet.rules['color-udp'].background);
  checkTrue(`${label}: TCP and UDP rows are clearly different (${d.toFixed(1)} deltaE)`,
    d >= MIN_TCP_UDP_DELTA_E);
}

// Nine hues, eleven roles - warn and notice share orange - so nine distinct
// DERIVED fills, plus one for every role that states its colour instead of
// deriving it. `reset` is the only such role, and it is stated precisely so
// that it does not collapse into the red the other error rules tint into.
//
// A colour set that substitutes the hues declines the stated colours (see
// getPacketThemeForApp), so it is back to nine.
for (const { theme, set, label } of COMBOS) {
  const packet = getPacketThemeForApp(theme, set);
  const distinct = new Set(Object.values(packet.rules).map((c) => c.background));
  const stated = PACKET_COLOR_SET_SPECS[set].hues === undefined
    ? new Set(Object.keys(FIXED_ROLE_COLORS)).size : 0;
  checkTrue(`${label}: roles produce ${9 + stated} distinct fills (${distinct.size})`,
    distinct.size === 9 + stated);
}

/**
 * The ceiling on how loud a row may be, in any theme.
 *
 * This replaced a check that Mono - a deliberately monochrome theme - stayed
 * quieter than the others. With four themes there is no designated quiet one,
 * because the whole list is quiet now: CHROMA_SCALE came down from 0.42 to
 * 0.24 and the separation it gave up moved onto the lightness axis
 * (LIGHTNESS_BY_HUE in packetThemes.ts).
 *
 * So the restraint is asserted per SET rather than globally. Default keeps the
 * 22 this was written as - just above where the loudest theme lands, well below
 * the 27.6 the old scale produced - and stays the tripwire for someone raising
 * CHROMA_SCALE to buy separation the deltaE floors should buy instead.
 *
 * Vibrant and Colourblind carry their own ceilings, because "quiet" is a
 * property of one set rather than of the list: Vibrant exists precisely to be
 * loud, and holding it to Default's number would be asserting that the feature
 * should not work. Each ceiling still sits just above where its set actually
 * lands, so all three remain tripwires rather than decoration - and every
 * FLOOR above (AA, and the three deltaE bars) is identical for all three.
 */
// Over the DERIVED fills only.
//
// The ceiling is a tripwire for one specific thing: somebody raising
// CHROMA_SCALE to buy separation the deltaE floors are supposed to buy. A
// stated colour is not produced by CHROMA_SCALE and cannot be raised by it, so
// including it here would not catch that mistake - it would only force the
// ceiling up to accommodate a value that was never in danger of drifting,
// which is how a tripwire stops being one. The stated colours are asserted
// exactly instead, below.
const STATED_RULES = new Set(
  Object.entries(ROLE_BY_RULE_ID)
    .filter(([, role]) => role in FIXED_ROLE_COLORS)
    .map(([id]) => id),
);
for (const { theme, set, label } of COMBOS) {
  const packet = getPacketThemeForApp(theme, set);
  const ceiling = PACKET_COLOR_SET_SPECS[set].maxChroma;
  const derived = Object.entries(packet.rules)
    // A set that substitutes the hues derives everything, so nothing is exempt.
    .filter(([id]) => PACKET_COLOR_SET_SPECS[set].hues !== undefined || !STATED_RULES.has(id));
  const loudest = Math.max(...derived.map(([, c]) => chroma(c.background)));
  checkTrue(
    `${label}: no derived row fill is louder than ${ceiling} chroma (${loudest.toFixed(1)})`,
    loudest <= ceiling,
  );
}

// The stated colours, held to the exact values they were transcribed from.
//
// This is the check the chroma ceiling gave up. A stated colour cannot drift
// by someone tuning the ramp, but it can drift by someone editing it - and the
// whole reason it is stated is that it matches the reference analyzer, so the
// value IS the requirement.
check('the reset role states the reference analyzer’s own RST pair',
  FIXED_ROLE_COLORS.reset, { background: '#a40000', color: '#fffc9c' });

for (const { theme, set, label } of COMBOS) {
  const packet = getPacketThemeForApp(theme, set);
  const row = packet.rules['color-tcp-rst'];
  if (PACKET_COLOR_SET_SPECS[set].hues !== undefined) {
    // Colourblind declines the stated pair: somebody who cannot rely on the
    // red/green axis is not helped by a saturated red because another
    // analyzer uses one, and that set exists for exactly that reader.
    checkTrue(`${label}: colourblind derives its own reset fill (${row.background})`,
      row.background !== '#a40000');
    continue;
  }
  check(`${label}: a reset row is the stated pair`, row, FIXED_ROLE_COLORS.reset);
  // A stated pair carries its own ground and its own text, so it has to clear
  // legibility on its own - it cannot lean on the theme underneath it.
  const ratio = contrastRatio(row.background, row.color);
  checkTrue(`${label}: ...and clears AAA on its own (${ratio.toFixed(2)}:1)`, ratio >= 7);
  // And it must be unmistakably louder than the error rules it was split from,
  // or the split bought nothing.
  const errorFill = packet.rules['color-bad-tcp'].background;
  const d = deltaE76(row.background, errorFill);
  checkTrue(`${label}: ...and clearly apart from Bad TCP (${d.toFixed(1)} deltaE)`,
    d >= MIN_FREQUENT_DELTA_E);
}

// The ceilings have to stay ordered, or the picker is offering a distinction it
// does not deliver: Vibrant must be allowed to be louder than Default, and
// Colourblind must sit between them rather than above the loud one.
checkTrue('Vibrant is allowed to be louder than Default',
  PACKET_COLOR_SET_SPECS.vibrant.maxChroma > PACKET_COLOR_SET_SPECS.default.maxChroma);
checkTrue('Colourblind sits between the two',
  PACKET_COLOR_SET_SPECS.colorblind.maxChroma > PACKET_COLOR_SET_SPECS.default.maxChroma
  && PACKET_COLOR_SET_SPECS.colorblind.maxChroma < PACKET_COLOR_SET_SPECS.vibrant.maxChroma);

// And Vibrant has to actually BE louder somewhere, not merely permitted to be.
for (const theme of THEMES) {
  // Derived fills only, for the same reason the ceiling above excludes the
  // stated ones: a colour every set states identically says nothing about
  // whether one set's RAMP is louder than another's, and letting it in made
  // both sets report the same number and the comparison vacuous.
  const loudest = (set: PacketColorSet) =>
    Math.max(...Object.entries(getPacketThemeForApp(theme, set).rules)
      .filter(([id]) => !STATED_RULES.has(id))
      .map(([, c]) => chroma(c.background)));
  checkTrue(
    `${theme}: Vibrant is visibly louder than Default (${loudest('vibrant').toFixed(1)} vs ${loudest('default').toFixed(1)})`,
    loudest('vibrant') > loudest('default') * 1.25,
  );
}

// --- Accents: the same colours, as text on a panel ----------------------------

/**
 * The frame number in the inspection pane, the byte count in the hex pane and
 * the title of the detail window are all painted in the selected frame's own
 * accent, so that a header names a frame in the colour its row was drawn in.
 *
 * That only works if two things hold at once, and they pull against each other:
 * the accent has to be READABLE on a card (which a pale row fill is not), and
 * it has to still LOOK LIKE the row's colour (which a contrast-first
 * derivation would not). Both are checked here.
 */
for (const { theme, set, label } of COMBOS) {
  const packet = getPacketThemeForApp(theme, set);
  const palette = PALETTE_BY_THEME[theme];
  if (!palette) continue;
  const card = palette.surface.card;
  // The set's own hues where it supplies them, the theme's otherwise - the same
  // resolution `getPacketThemeForApp` does, and the accents have to be measured
  // against whichever nine they were actually derived from.
  const hues = PACKET_COLOR_SET_SPECS[set].hues ?? palette.hues;

  check(`${label}: every rule has an accent`,
    REQUIRED_RULE_IDS.filter((id) => !packet.accents[id]), []);
  check(`${label}: every accent is a hex triple`,
    Object.entries(packet.accents)
      .map(([id, c]) => (isHex(c) ? null : `${id}=${c}`))
      .filter(Boolean),
    []);
  checkTrue(`${label}: the unmatched-frame accent is a hex triple`, isHex(packet.accentFallback));

  const unreadable = [...Object.entries(packet.accents), ['fallback', packet.accentFallback] as const]
    .map(([id, c]) => ({ id, ratio: contrastRatio(c, card) }))
    .filter((r) => r.ratio < AA)
    .map((r) => `${r.id} (${r.ratio.toFixed(2)}:1)`);
  check(`${label}: every accent clears WCAG AA on the card it sits on`, unreadable, []);

  // The half that keeps the feature honest. Only the L axis may move, so an
  // accent must stay on its hue's own axis in Lab - otherwise "the colour of
  // the selected packet" quietly becomes "some readable colour".
  //
  // Measured against the HUE rather than against the row fill, because the two
  // are deliberately far apart in lightness; what has to match is the
  // direction, not the value. Near-neutral palette entries are exempt because
  // an angle means nothing at zero chroma - Okabe-Ito's black is one.
  const HUE_ANGLE_TOLERANCE_DEG = 12;
  const angleOf = (hex: string) => {
    const [, a, b] = toLabColor(hex);
    return (Math.atan2(b, a) * 180) / Math.PI;
  };
  const drifted: string[] = [];
  for (const id of REQUIRED_RULE_IDS) {
    const hue = hues[HUE_BY_ROLE[ROLE_BY_RULE_ID[id]]];
    const accent = packet.accents[id];
    if (chroma(hue) < 8 || chroma(accent) < 8) continue;
    let delta = Math.abs(angleOf(accent) - angleOf(hue));
    if (delta > 180) delta = 360 - delta;
    if (delta > HUE_ANGLE_TOLERANCE_DEG) {
      drifted.push(`${id}: ${delta.toFixed(1)} deg from ${hue}`);
    }
  }
  check(`${label}: every accent stays on its own hue's axis`, drifted, []);
}

/**
 * And the accents must be as separable from each other as the fills are - a
 * header that names every frame in the same near-black is exactly the failure
 * the app accent already had.
 *
 * Threshold is well under what the fills are held to, because these are single
 * short labels seen one at a time rather than adjacent rows compared at a
 * glance, and two roles (`warn` and `notice`) deliberately share a hue.
 */
const MIN_ACCENT_DELTA_E = 6;
for (const { theme, set, label } of COMBOS) {
  const packet = getPacketThemeForApp(theme, set);
  const distinct = [...new Set(Object.values(packet.accents))];
  let worst = { pair: '', delta: Infinity };
  for (let i = 0; i < distinct.length; i++) {
    for (let j = i + 1; j < distinct.length; j++) {
      const delta = deltaE76(distinct[i], distinct[j]);
      if (delta < worst.delta) worst = { pair: `${distinct[i]} vs ${distinct[j]}`, delta };
    }
  }
  checkTrue(
    `${label}: accents stay distinguishable (worst ${worst.delta.toFixed(1)} deltaE, ${worst.pair})`,
    worst.delta >= MIN_ACCENT_DELTA_E,
  );
}

// --- No drift between the palettes and index.css -----------------------------

const css = fs.readFileSync(path.join(process.cwd(), 'src/index.css'), 'utf8');
function cssToken(theme: string, token: string): string | undefined {
  const selector = theme === 'light' ? ':root' : `.${theme}`;
  const start = css.indexOf(`${selector} {`);
  if (start === -1) return undefined;
  const body = css.slice(start, css.indexOf('\n}', start));
  return new RegExp(`${token}:\\s*(#[0-9a-fA-F]{6})`).exec(body)?.[1];
}

const surfaceDrift: string[] = [];
for (const theme of THEMES) {
  const palette = PALETTE_BY_THEME[theme];
  if (!palette) continue;
  const pairs: [keyof typeof palette.surface, string][] = [
    ['background', '--background'],
    ['card', '--card'],
    ['foreground', '--foreground'],
    ['border', '--border'],
  ];
  for (const [key, token] of pairs) {
    const fromCss = cssToken(theme, token);
    if (fromCss?.toLowerCase() !== palette.surface[key].toLowerCase()) {
      surfaceDrift.push(`${theme}.${key}: palette ${palette.surface[key]} vs css ${fromCss}`);
    }
  }
}
check('every palette surface matches its theme block in index.css', surfaceDrift, []);

// --- Fallback ----------------------------------------------------------------

// Same reasoning as isDarkTheme's dark default: next-themes leaves
// resolvedTheme undefined for one tick on mount, and resolving that to a light
// palette flashed the wrong ground on every load.
check('an unknown theme name falls back to dark', themePalette('nope'), PALETTE_BY_THEME.dark);
check('undefined falls back to dark', themePalette(undefined), PALETTE_BY_THEME.dark);
checkTrue('the fallback still yields a fully covered palette',
  REQUIRED_RULE_IDS.every((id) => Boolean(getPacketThemeForApp('nope').rules[id])));

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All packet palette checks passed.');
