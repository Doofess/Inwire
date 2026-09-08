/**
 * Assertion tests for the app theme registry and its CSS.
 *
 *   npx tsx scripts/themes/registry.ts
 *
 * A theme is declared in three places that have to agree: the registry
 * (themeOptions.ts), a class block of custom properties (index.css), and - for
 * dark ones - the `dark` custom variant that every `dark:` utility resolves
 * against. Nothing at runtime complains when they disagree; the failures are
 * silent and visual, which is what makes them worth a test:
 *
 *   - a theme missing its CSS block renders with the light `:root` palette;
 *   - a block missing ONE property inherits just that property from `:root`,
 *     so a dark theme quietly gets a white card or black text;
 *   - a dark theme missing from the variant list renders every `dark:`
 *     utility in the app as its light treatment on a dark ground.
 *
 * The `isDarkTheme` checks pin down a bug this replaced: lightness used to be
 * `resolvedTheme !== 'light'`, which was correct only while `light` was the
 * only light theme.
 */
import fs from 'node:fs';
import path from 'node:path';
import { contrastRatio, deltaE76 } from '../../src/lib/colorMix';
import {
  RETIRED_THEMES,
  SYSTEM_THEME_PAIR,
  THEME_NAMES,
  THEME_OPTIONS,
  isDarkTheme,
  normalizeThemeName,
} from '../../src/lib/themeOptions';

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

const css = fs.readFileSync(path.join(process.cwd(), 'src/index.css'), 'utf8');

/** The custom properties declared inside one `.selector { ... }` block. */
function tokensIn(selector: string): string[] {
  const start = css.indexOf(`${selector} {`);
  if (start === -1) return [];
  const end = css.indexOf('\n}', start);
  const body = css.slice(start, end);
  return [...body.matchAll(/^\s*(--[a-z-]+):/gm)].map((m) => m[1]);
}

// --- The registry itself -----------------------------------------------------

const light = THEME_OPTIONS.filter((t) => t.mode === 'light');
const dark = THEME_OPTIONS.filter((t) => t.mode === 'dark');

check('two light themes', light.length, 2);
check('two dark themes', dark.length, 2);
check('four themes, all of them real', THEME_NAMES.length, 4);
// `system` is gone, so there is no longer a picker entry that resolves to
// something else at runtime. Every option now names a palette directly, which
// is what let `mode` become required rather than optional.
checkTrue('no theme is offered without a mode', THEME_OPTIONS.every((t) => t.mode !== undefined));
// `system` IS offered in the picker again, but as a MODE over the four rather
// than a fifth palette: it has no class block, no palette and no `mode`, so it
// must never reach next-themes or any of the lookups keyed on a theme name.
// See SYSTEM_THEME_OPTION and useSystemThemePreference.
checkTrue('system is not one of the palettes',
  THEME_OPTIONS.every((t) => t.value !== 'system') && !THEME_NAMES.includes('system'));
checkTrue('the system option resolves to two themes that exist',
  THEME_NAMES.includes(SYSTEM_THEME_PAIR.light) && THEME_NAMES.includes(SYSTEM_THEME_PAIR.dark));
checkTrue('...one light and one dark',
  !isDarkTheme(SYSTEM_THEME_PAIR.light) && isDarkTheme(SYSTEM_THEME_PAIR.dark));
check('theme values are unique', new Set(THEME_OPTIONS.map((t) => t.value)).size, THEME_OPTIONS.length);
// The two defaults keep the ids `light` and `dark` however they are labelled:
// next-themes only writes `color-scheme` onto the document for those two exact
// strings, and that is what keeps native scrollbars and form controls on the
// right side of the light/dark divide.
checkTrue('the default light theme is still called `light`',
  THEME_OPTIONS.some((t) => t.value === 'light' && t.mode === 'light'));
checkTrue('the default dark theme is still called `dark`',
  THEME_OPTIONS.some((t) => t.value === 'dark' && t.mode === 'dark'));

// --- Retired themes land somewhere real --------------------------------------

// The failure this prevents is silent, not loud. next-themes does not validate
// the stored value against `themes`, so a name that maps nowhere leaves the app
// with a class no stylesheet defines: light chrome, a dark packet palette, and
// no `dark:` utilities. See migrateStoredTheme in main.tsx.
for (const [retired, target] of Object.entries(RETIRED_THEMES)) {
  checkTrue(`${retired} migrates to a theme that exists (${target})`,
    THEME_NAMES.includes(target));
}
check('no retired id is also a live one',
  Object.keys(RETIRED_THEMES).filter((k) => THEME_NAMES.includes(k)), []);
check('a live theme is returned unchanged', normalizeThemeName('midnight'), 'midnight');
check('an unknown name falls back to the default dark',
  normalizeThemeName('theme-that-never-existed'), 'dark');
check('a missing value falls back to the default dark', normalizeThemeName(null), 'dark');

// --- isDarkTheme -------------------------------------------------------------

for (const t of light) {
  // The regression: `resolvedTheme !== 'light'` called each of these dark, and
  // MapLibre, D3 and the export cards drew for the wrong ground.
  checkTrue(`${t.value} is NOT dark`, !isDarkTheme(t.value));
}
for (const t of dark) {
  checkTrue(`${t.value} is dark`, isDarkTheme(t.value));
}

// next-themes leaves resolvedTheme undefined for a tick on mount; guessing
// light there flashes a white app before settling.
checkTrue('undefined defaults to dark rather than flashing light', isDarkTheme(undefined));
checkTrue('an unknown stored theme defaults to dark', isDarkTheme('theme-that-was-removed'));

// --- Every theme has a complete CSS block ------------------------------------

// `:root` is the light baseline and therefore the full set every other block
// has to match. A block that omits one silently inherits it from here.
const REQUIRED_TOKENS = tokensIn(':root');
// 23 chrome tokens - 19, plus the `--chrome` pair the header bar and the
// drawer read, `--chrome-brand` for the lockup and `--chrome-sunken` for the
// capture buttons - and the 11 status tokens (see scripts/themes/status.ts). Deliberately a hard number
// rather than a floor: it is the tripwire for someone adding a token to `:root`
// and to nowhere else, which is silent - the other themes just inherit the
// light value and nothing throws.
// 35 since `--packet-gridline-lighten` joined them: how much white the packet
// list's column separators mix into the background they are drawn on. This
// check is what caught it being added, which is exactly the tripwire it is
// there to be - a token declared in `:root` alone is inherited silently by
// every other theme and nothing else would have said so.
check('the :root baseline declares 35 tokens', REQUIRED_TOKENS.length, 35);

for (const t of THEME_OPTIONS) {
  if (!t.mode) continue;
  // `light` IS :root - it is the default and has no class block of its own.
  const selector = t.value === 'light' ? ':root' : `.${t.value}`;
  const tokens = tokensIn(selector);
  checkTrue(`${t.value} has a CSS block (${selector})`, tokens.length > 0);
  const missing = REQUIRED_TOKENS.filter((tok) => !tokens.includes(tok));
  check(`${t.value} declares every token (none inherited from :root)`, missing, []);
}

// --- No two themes may look alike --------------------------------------------

/**
 * The check that was missing, and the reason a duplicate shipped.
 *
 * There used to be only an "are any two token sets identical" test. It passed
 * for a GitHub Light whose card was the same #ffffff as Light's and whose
 * background differed by 0.3 deltaE - below the threshold of human vision -
 * because the two sets were not byte-identical. Exact equality is the wrong
 * bar: what matters is whether a person can tell the themes apart.
 *
 * Distance is measured on `--background` and `--card` alone. Those two cover
 * most of the screen, so they are what "looks like a different theme" actually
 * means; an accent can differ wildly and still leave two themes twins.
 */

/**
 * 5.0 sits well above the ~2.3 "just noticeable difference" while staying under
 * the closest legitimate pair - Graphite vs Midnight, ~7.8 - so it rejects
 * twins without dictating taste.
 *
 * With four themes rather than eight this is doing more work than it used to,
 * not less: the surviving pairs are one warm/cool pair per mode, which is
 * exactly the kind of distinction that is easy to author too subtly.
 */
const MIN_SURFACE_DELTA_E = 5;

function surfaceColors(theme: string): { background: string; card: string } | null {
  const selector = theme === 'light' ? ':root' : `.${theme}`;
  const start = css.indexOf(`${selector} {`);
  if (start === -1) return null;
  const body = css.slice(start, css.indexOf('\n}', start));
  const grab = (tok: string) => new RegExp(`${tok}:\\s*(#[0-9a-fA-F]{6})`).exec(body)?.[1];
  const background = grab('--background');
  const card = grab('--card');
  return background && card ? { background, card } : null;
}

const realThemes = THEME_OPTIONS.filter((t) => t.mode).map((t) => t.value);
const tooAlike: string[] = [];
for (let i = 0; i < realThemes.length; i++) {
  for (let j = i + 1; j < realThemes.length; j++) {
    const a = surfaceColors(realThemes[i]);
    const b = surfaceColors(realThemes[j]);
    if (!a || !b) continue;
    const d = (deltaE76(a.background, b.background) + deltaE76(a.card, b.card)) / 2;
    if (d < MIN_SURFACE_DELTA_E) {
      tooAlike.push(`${realThemes[i]} vs ${realThemes[j]} (${d.toFixed(1)} deltaE)`);
    }
  }
}
check(`no two themes share a surface within ${MIN_SURFACE_DELTA_E} deltaE`, tooAlike, []);

// --- Dark themes reach the `dark:` variant -----------------------------------

const variant = css.slice(css.indexOf('@custom-variant dark'), css.indexOf('@custom-variant dark') + 400);
for (const t of dark) {
  checkTrue(`${t.value} is listed in the dark custom variant`, variant.includes(`.${t.value}`));
}
for (const t of light) {
  if (t.value === 'light') continue;
  checkTrue(`${t.value} is NOT in the dark variant`, !variant.includes(`.${t.value}`));
}

// --- The Colourful setting ---------------------------------------------------

/**
 * The accent bar can be turned off, and the whole switch is one CSS block.
 *
 * What makes that safe is that `bg-chrome` and `text-chrome-foreground` are the
 * only way anything reaches those colours - so the block below is checked to
 * redefine exactly the three tokens and nothing else. A fourth token appearing
 * there would be a colour that changes with the setting and is not documented
 * as doing so.
 */
{
  const plain = tokensIn(':root[data-chrome="plain"]');
  check('the plain-chrome block redefines exactly the chrome tokens',
    [...plain].sort(), ['--chrome', '--chrome-brand', '--chrome-foreground', '--chrome-sunken']);

  // The bug this is written against, and the reason --chrome-brand exists at
  // all: the lockup's dark-theme colour is the surface tone under the accent
  // bar, and against a PLAIN bar - which is that same surface - it would sit at
  // 1:1 and vanish. A logo is allowed to be low contrast; it is not allowed to
  // be invisible, and the difference is not visible in a diff.
  //
  // The floor is 1.6 rather than a WCAG number on purpose. The colourful dark
  // themes run the lockup at about 2:1 deliberately, so a text threshold would
  // fail a treatment that is correct.
  // Parsed line by line rather than with a regex: the values that matter here
  // are half literals and half `var(--other)` references, and following a
  // reference is a recursive lookup, not a pattern.
  const hex = (theme: string, token: string): string => {
    const selector = theme === 'light' ? ':root' : `.${theme}`;
    const start = css.indexOf(`${selector} {`);
    const body = css.slice(start, css.indexOf('\n}', start));
    for (const line of body.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith(`${token}:`)) continue;
      const value = trimmed.slice(token.length + 1).replace(';', '').trim();
      if (value.startsWith('#')) return value;
      if (value.startsWith('var(')) return hex(theme, value.slice(4, value.indexOf(')')));
    }
    return '#000000';
  };

  // The capture buttons' label on their own fill. Which pair that is depends on
  // the theme - the light ones put `--chrome-foreground` on `--chrome-sunken`,
  // the dark ones put `--primary` on it - so the check follows the class rather
  // than assuming one pair. This is button text at 11px uppercase, so it holds
  // to the real AA threshold and not to the logo exemption below.
  for (const t of THEME_OPTIONS) {
    const fill = hex(t.value, '--chrome-sunken');
    const label = hex(t.value, t.mode === 'dark' ? '--primary' : '--chrome-foreground');
    checkTrue(
      `${t.value}: the capture buttons' label clears AA on their fill `
      + `(${contrastRatio(label, fill).toFixed(2)}:1)`,
      contrastRatio(label, fill) >= 4.5);
    // ...and the fill has to be visible AS a button against the bar it sits on.
    checkTrue(
      `${t.value}: ...and the fill reads against the bar `
      + `(${contrastRatio(fill, hex(t.value, '--chrome')).toFixed(2)}:1)`,
      contrastRatio(fill, hex(t.value, '--chrome')) >= 1.25);
  }

  for (const t of THEME_OPTIONS) {
    const brand = hex(t.value, '--chrome-brand');
    checkTrue(
      `${t.value}: the lockup is visible on the colourful bar `
      + `(${contrastRatio(brand, hex(t.value, '--chrome')).toFixed(2)}:1)`,
      contrastRatio(brand, hex(t.value, '--chrome')) >= 1.6);
    // With the bar plain, both sides come from the card pair, so this is the
    // ordinary text contrast and holds to the real threshold.
    checkTrue(
      `${t.value}: ...and on the plain one `
      + `(${contrastRatio(hex(t.value, '--card-foreground'), hex(t.value, '--card')).toFixed(2)}:1)`,
      contrastRatio(hex(t.value, '--card-foreground'), hex(t.value, '--card')) >= 4.5);
  }
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All theme registry checks passed.');
