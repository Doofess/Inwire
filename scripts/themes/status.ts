/**
 * Assertion tests for the status colours.
 *
 *   npx tsx scripts/themes/status.ts
 *
 * Three controls - the Interfaces button, Start/Stop capture, and the fault
 * panel - used to carry raw Tailwind shades, so they rendered identically under
 * every theme - emerald and rose sitting in the header of a warm-accented UI,
 * from a palette none of the four themes contains.
 *
 * They now read per-theme tokens derived from each theme's own palette. The
 * values live in index.css because they must be right before first paint, which
 * makes them a second copy of something a function already computes - exactly
 * the drift risk the surface tokens already have a test for. This is that test.
 *
 * It also holds the pairs to a contrast floor. That matters more here than for
 * decoration: these colours are the only thing distinguishing "capture is
 * running" from "no adapter found" at a glance, and a label nobody can read on
 * its own button defeats the point of colouring it.
 */
import fs from 'node:fs';
import path from 'node:path';
import {
  statusColors,
  statusBaseHues,
  STATUS_TOKENS,
  type StatusColors,
} from '../../src/services/statusColors';
import { THEME_OPTIONS, isDarkTheme } from '../../src/lib/themeOptions';
import { PALETTE_BY_THEME } from '../../src/services/themePalettes';
import { contrastRatio, deltaE76, relativeLuminance } from '../../src/lib/colorMix';

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

const THEMES = THEME_OPTIONS.map((t) => t.value);
const css = fs.readFileSync(path.join(process.cwd(), 'src/index.css'), 'utf8');

function cssToken(theme: string, token: string): string | undefined {
  const selector = theme === 'light' ? ':root' : `.${theme}`;
  const start = css.indexOf(`${selector} {`);
  if (start === -1) return undefined;
  const body = css.slice(start, css.indexOf('\n}', start));
  return new RegExp(`${token}:\\s*(#[0-9a-fA-F]{6})`).exec(body)?.[1];
}

// --- index.css agrees with the derivation ------------------------------------

const drift: string[] = [];
for (const theme of THEMES) {
  const derived = statusColors(theme);
  for (const [field, token] of Object.entries(STATUS_TOKENS)) {
    const fromCss = cssToken(theme, token);
    const expected = derived[field as keyof StatusColors];
    if (fromCss?.toLowerCase() !== expected.toLowerCase()) {
      drift.push(`${theme}${token}: css ${fromCss} vs derived ${expected}`);
    }
  }
}
check('every status token in index.css matches statusColors()', drift, []);

// --- Tailwind can actually see them ------------------------------------------

const themeBlockStart = css.indexOf('@theme {');
const themeBlock = css.slice(themeBlockStart, css.indexOf('\n}', themeBlockStart));
const unmapped = Object.values(STATUS_TOKENS).filter(
  // `--danger` maps to `--color-danger`, so the leading dash of the token is
  // dropped rather than doubled.
  (token) => !themeBlock.includes(`--color${token.slice(1)}: var(${token});`),
);
check('every status token is mapped into @theme so the utilities resolve', unmapped, []);

// The chrome pair used to be guarded here for the same reason - a token in
// every theme block and left out of `@theme` gives a `bg-chrome` utility that
// does not exist, so the bar rendered transparent rather than erroring. There
// is no bar and there are no chrome tokens: the accent header was deleted with
// the migration, and the Colourful switch that painted it went when the only
// thing it still changed was making the brand mark invisible.

// --- Legibility ---------------------------------------------------------------

/**
 * WCAG AA for normal text. No exemptions, including for `light`: its fills are
 * pinned to the shades the app already shipped, but the FOREGROUND on each is
 * derived, which is what lets that bar hold. Pinning white on rose-500 the way
 * the old markup did would sit at 3.58:1 and fail here.
 */
const AA = 4.5;

for (const theme of THEMES) {
  const c = statusColors(theme);
  const card = PALETTE_BY_THEME[theme]?.surface.card;
  if (!card) {
    check(`${theme}: has a palette`, false, true);
    continue;
  }

  const weakFills = (
    [
      ['success', c.success, c.successForeground],
      ['warning', c.warning, c.warningForeground],
      ['danger', c.danger, c.dangerForeground],
      ['danger-strong', c.dangerStrong, c.dangerStrongForeground],
    ] as const
  )
    .map(([name, fill, fg]) => ({ name, ratio: contrastRatio(fill, fg) }))
    .filter((r) => r.ratio < AA)
    .map((r) => `${r.name} (${r.ratio.toFixed(2)}:1)`);
  check(`${theme}: every solid status button is readable`, weakFills, []);

  const weakMuted = (
    [
      ['success-muted', c.successMuted],
      ['warning-muted', c.warningMuted],
      ['danger-muted', c.dangerMuted],
    ] as const
  )
    .map(([name, colour]) => ({ name, ratio: contrastRatio(colour, card) }))
    .filter((r) => r.ratio < AA)
    .map((r) => `${r.name} (${r.ratio.toFixed(2)}:1)`);
  check(`${theme}: every status text colour is readable on the card`, weakMuted, []);
}

// --- One foreground per ground ------------------------------------------------

/**
 * Every LIGHT theme carries white on all four status buttons, with no
 * exceptions.
 *
 * The point is the row, not the individual button. Choosing the foreground per
 * fill was defensible in isolation and wrong in place: the green and the amber
 * came out light enough that near-black won on contrast while the red kept
 * white, so the header showed dark text on two buttons and white on the third -
 * three controls that do one job, looking like three unrelated ones. The fills
 * are now deepened until white clears AA on each, which is what makes one
 * foreground possible at all.
 *
 * Dark themes are deliberately NOT held to this. Their fills come from palettes
 * that span the scale - Solarized publishes one set of accents intended to work
 * on both of its grounds, so its olive green and its red sit at genuinely
 * different depths - and forcing a single foreground would mean either dragging
 * the light hues down until they no longer read as that palette's colours, or
 * brightening the deep ones back up, which is the opposite of the toning-down
 * this file exists to do. Each dark fill takes the text that is legible on it.
 */
for (const theme of THEMES.filter((t) => !isDarkTheme(t))) {
  const c = statusColors(theme);
  check(`${theme}: every status button is white-on-colour`,
    [c.successForeground, c.warningForeground, c.dangerForeground, c.dangerStrongForeground],
    ['#ffffff', '#ffffff', '#ffffff', '#ffffff']);
}

// The dark themes get the weaker guarantee that still matters: whatever each
// fill takes, it is one of the two neutrals and it is readable. The AA check
// above covers readability; this covers "no fill invented a third colour".
for (const theme of THEMES.filter(isDarkTheme)) {
  const c = statusColors(theme);
  check(`${theme}: status foregrounds are black or white, nothing else`,
    [c.successForeground, c.warningForeground, c.dangerForeground, c.dangerStrongForeground]
      .filter((fg) => fg !== '#ffffff' && fg !== '#0b0f14'),
    []);
}

// --- The three statuses stay tellable apart -----------------------------------

/**
 * The whole job of these colours is answering "is this fine or not" without
 * reading the label, so a theme whose green and red converge has lost the
 * feature rather than merely looked odd.
 *
 * Threshold is calibrated against what the published palettes actually achieve
 * rather than set aspirationally. The tightest real pair is Gruvbox's warning
 * and danger at 15.3 - its own burnt orange beside its own bright red, which
 * are genuinely close hues to begin with - then Solarized at 16.2 and Mono at
 * 21.0; everything else clears 29.
 *
 * These numbers came down when the fills were softened, because scaling chroma
 * scales the distance between hues by the same factor. That is the trade the
 * chroma trim is deliberately gentle about, and this floor is what bounds it:
 * trimming further would start failing here rather than quietly making two
 * statuses look alike.
 */
const MIN_STATUS_DELTA_E = 14;
for (const theme of THEMES) {
  const c = statusColors(theme);
  const pairs: [string, string, string][] = [
    ['success/warning', c.success, c.warning],
    ['success/danger', c.success, c.danger],
    ['warning/danger', c.warning, c.danger],
  ];
  let worst = { pair: '', delta: Infinity };
  for (const [name, a, b] of pairs) {
    const delta = deltaE76(a, b);
    if (delta < worst.delta) worst = { pair: name, delta };
  }
  checkTrue(
    `${theme}: the three statuses stay distinct (worst ${worst.delta.toFixed(1)} deltaE, ${worst.pair})`,
    worst.delta >= MIN_STATUS_DELTA_E,
  );
}

/**
 * And Stop Capture stays visibly calmer than an alert.
 *
 * Lower bar than the one above on purpose: these two are the same hue by
 * design, and the difference wanted is "one of these is louder", not "these are
 * different colours".
 */
const MIN_STRONG_DELTA_E = 8;
for (const theme of THEMES) {
  const c = statusColors(theme);
  const delta = deltaE76(c.danger, c.dangerStrong);
  checkTrue(
    `${theme}: Stop Capture reads calmer than an alert (${delta.toFixed(1)} deltaE)`,
    delta >= MIN_STRONG_DELTA_E,
  );
}

// --- The light theme keeps the look it shipped with ---------------------------

// The reference the others are matched against, so its hues are pinned
// rather than read off the palette. Asserted on the BASE hues, before `soften`:
// what is pinned is which colour each status is, not how loud it is, and every
// theme including this one is toned down from there.
{
  const base = statusBaseHues('light');
  check('light starts from emerald-500 for success', base.success, '#10b981');
  check('light starts from amber-500 for warning', base.warning, '#f59e0b');
  check('light starts from rose-500 for danger', base.danger, '#f43f5e');
  check('light starts from rose-700 for Stop Capture', base.dangerStrong, '#be123c');
}

// And every status fill is genuinely quieter than the hue it came from. This is
// the check that stops a future palette edit from walking the brightness back
// up one theme at a time.
for (const theme of THEMES) {
  const base = statusBaseHues(theme);
  const c = statusColors(theme);
  const louder = (
    [
      ['success', base.success, c.success],
      ['warning', base.warning, c.warning],
      ['danger', base.danger, c.danger],
    ] as const
  )
    .filter(([, from, to]) => relativeLuminance(to) >= relativeLuminance(from))
    .map(([name]) => name);
  check(`${theme}: every status fill is dimmer than its palette hue`, louder, []);
}

// --- No raw status shades left in the three controls --------------------------

// The failure mode this whole change exists to prevent, pinned so it cannot
// come back one className at a time.
//
// `AnomalyAlertsPanel.tsx` used to be the second entry and is gone with the
// anomaly model. The others are the surviving surfaces that paint a fault state
// - the two analytics ones ask `isFaultCategory(categoryOfPacket(p))` rather
// than reading an anomaly list - so they are where a raw shade would next creep
// in.
//
// `Header.tsx` was the first entry and is gone with the 64px header bar. Its
// fault states split in two and both are listed in its place: the rail draws the
// adapter's warning badge and the capture button's stop glyph, and the filter
// row draws the banner that says why capture cannot start. Replacing the entry
// rather than dropping it matters - the check is only worth having on whichever
// file currently owns the decision.
const GUARDED_FILES = [
  'src/components/common/ActivityRail.tsx',
  'src/components/common/FilterRow.tsx',
  'src/components/analytics/NetworkMatrix.tsx',
  'src/components/analytics/TrafficTimelineChart.tsx',
];
const RAW_SHADE = /\b(?:bg|text|border|shadow|ring)-(?:rose|emerald|amber|red|green)-\d{2,3}\b/g;
for (const file of GUARDED_FILES) {
  const source = fs.readFileSync(path.join(process.cwd(), file), 'utf8');
  check(`${file}: uses status tokens, not raw Tailwind shades`,
    [...source.matchAll(RAW_SHADE)].map((m) => m[0]), []);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All status colour checks passed.');
