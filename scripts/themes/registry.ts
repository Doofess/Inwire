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
import { contrastRatio, deltaE76, mixHex } from '../../src/lib/colorMix';
import { ACCENTS } from '../../src/lib/accents';
import { PALETTE_BY_THEME } from '../../src/services/themePalettes';
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

// One light and three dark, and that is the whole set (ADR 0056). Paper and
// Graphite were cut because each was only the other survivor's warm-or-cool
// counterweight; Dim and High Contrast are not spares of Dark - Dim is a grey
// ground beside a near-black one, and High Contrast is an accessibility theme
// held to 7:1 below.
//
// Pinned as exact counts rather than as `>= 1`, because the cost of a theme is
// not in this file: it is a complete token block in index.css, a palette, and
// every pairwise contrast and deltaE check below. A theme added without that
// deliberation should fail here first.
check('one light theme', light.length, 1);
check('three dark themes', dark.length, 3);
check('four themes, all of them real', THEME_NAMES.length, 4);
// `system` is gone, so there is no longer a picker entry that resolves to
// something else at runtime. Every option now names a palette directly, which
// is what let `mode` become required rather than optional.
checkTrue('no theme is offered without a mode', THEME_OPTIONS.every((t) => t.mode !== undefined));
// `system` IS offered in the picker, but as a MODE over the two rather than a
// third palette: it has no class block, no palette and no `mode`, so it must
// never reach next-themes or any of the lookups keyed on a theme name.
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
check('a live theme is returned unchanged', normalizeThemeName('dark'), 'dark');
// The migration most stored profiles actually take. `midnight` was the neutral
// dark theme's id until Graphite was deleted and freed the `dark` one; landing
// it anywhere else would move somebody off the theme they are already using.
check('midnight, the id the dark theme used to have, lands on it',
  normalizeThemeName('midnight'), 'dark');
check('paper falls back to the surviving light theme', normalizeThemeName('paper'), 'light');
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
// 19 surface tokens and the 11 status tokens (see scripts/themes/status.ts).
// Deliberately a hard number rather than a floor: it is the tripwire for
// someone adding a token to `:root` and to nowhere else, which is silent - the
// other themes just inherit the light value and nothing throws.
//
// 33 since the speed test's two directions (ADR 0054), `--speed-download` and
// `--speed-upload`.
//
// It was 35 until the four `--chrome*` tokens went. They painted a 64px accent
// header and a menu drawer, both of which are deleted, and the Colourful switch
// that chose between them had nothing left to change.
// `--packet-gridline-step` is one of the 31: how far, in oklab lightness, the
// packet list's column separators move from the background they are drawn on.
// This check is what caught it being added, which is exactly the tripwire it
// is there to be - a token declared in `:root` alone is inherited silently by
// every other theme and nothing else would have said so.
//
// It is also the token that most needs the tripwire, because it is **signed**:
// Day steps up and Night steps down, so a Night block that inherited Day's
// value would not merely be a shade out, it would draw the line on the wrong
// side of the ground - which is the state that shipped while this was a
// fraction of white and every theme shared it.
//
// `--selection` and `--handle-hover` made it 35 (ADR 0056): both are a share
// that differs per theme, so both are declared in every block.
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
 * 5.0 sits well above the ~2.3 "just noticeable difference" without dictating
 * taste.
 *
 * The number was chosen when there were eight themes and had to clear the
 * closest legitimate pair of the day - Graphite against Midnight, ~7.8. Both of
 * those are deleted, and with **two** themes there is exactly one pair left:
 * Day against Night, which is a light theme against a dark one and clears this
 * by an enormous margin. So this is no longer a bar anything is pressed
 * against; it is the floor a third theme would have to clear, and it is kept at
 * 5 rather than raised to the current distance precisely so it stays a floor
 * rather than a pin on today's palettes.
 */
const MIN_SURFACE_DELTA_E = 5;

/**
 * The same bar, for two STATES of one control rather than two themes.
 *
 * Kept at 5 for the same reason: well above the ~2.3 just-noticeable difference,
 * and low enough not to dictate taste. The rail's active fill clears it against
 * both its ground and its hover by a wide margin today (the tightest is 12.4),
 * so this is a floor rather than a constraint anything is pressed against.
 */
const MIN_STATE_DELTA_E = 5;

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

// --- The `dark:` variant lists exactly the dark themes ------------------------

/**
 * One set comparison, where this was two loops - and the second of them had
 * stopped asserting anything at all.
 *
 * It read `for (const t of light) { if (t.value === 'light') continue; ... }`,
 * which was written when Paper was the second light theme. Paper is deleted, so
 * `light` holds exactly one entry, the `continue` fired on it, and the body
 * never ran: no PASS line, nothing guarded. What it had been guarding is the
 * worse half of the pair - a LIGHT theme listed in the dark variant renders
 * every `dark:` utility in the app as its dark treatment on a white ground,
 * across the whole UI at once - and `light` itself was the one value the loop
 * could never reach, because skipping it was how the loop avoided asserting
 * about `:root`.
 *
 * Read as a set both ways instead. That covers the missing dark theme, the
 * light theme that must not be there, and the third case neither loop could
 * see: a class left in the variant for a theme that no longer exists, which
 * costs nothing today and quietly comes back to life if the id is ever reused.
 * `RETIRED_THEMES` reuses `midnight` and `paper` as stored ids for exactly that
 * reason, so the case is not hypothetical.
 *
 * Read to the statement's own semicolon rather than by a fixed 400-character
 * window. The window worked only because the token declarations under it happen
 * to contain no class selectors; a set comparison cannot afford to scoop up
 * whatever follows.
 */
const variantAt = css.indexOf('@custom-variant dark');
checkTrue('index.css declares a dark custom variant', variantAt !== -1);
const variant = css.slice(variantAt, css.indexOf(';', variantAt) + 1);
const listed = [...new Set(
  [...variant.matchAll(/\.([a-z][a-z0-9-]*)/g)].map((m) => m[1]),
)].sort();
check('the dark variant lists exactly the dark themes, and nothing else',
  listed, dark.map((t) => t.value).sort());

// --- The chrome, against the grounds it actually sits on ---------------------

/**
 * What is left of the Colourful setting's checks, retargeted twice.
 *
 * That setting painted the chrome with a saturated accent, and this section held
 * five checks about it - the capture buttons' label on their fill, the fill
 * against the bar, and the brand lockup against the bar in both states. All of
 * them tested against `--chrome`, the bar it sat on.
 *
 * **It sat on `--chrome` and then it did not, and the checks did not notice.**
 * The 64px accent header was deleted; the mark moved to the rail and then to the
 * title row. `--chrome-brand` resolved to white on the light themes, so turning
 * Colourful ON made the mark white-on-white in Day - while this file went on
 * asserting it was legible against a bar nothing drew any more.
 *
 * **Then it happened a second time, which is why this is a list and not a line.**
 * What survived that cleanup was one check: `--card-foreground` against
 * `--card`, described as "the brand mark in the title row". Two things were
 * wrong with it by the time anybody looked. It was covering the WORDMARK, not
 * the mark - the mark is a shaded form carrying its own colours from
 * `lib/brandMark.ts` and takes nothing from the cascade - and the wordmark has
 * since been deleted outright. And the title row moved off `--card` to
 * `--secondary`, so the ground was wrong as well as the subject.
 *
 * A guard aimed at the wrong ground passes for exactly as long as it is wrong,
 * and this one did it twice. So the rule now is to name the PAIR and the surface
 * it is drawn on, one entry per thing actually rendered, and to let the list
 * grow rather than letting one survivor stand in for a chrome that keeps moving.
 *
 * All four are held to 4.5:1 - the text threshold - rather than the 3:1 WCAG
 * allows for non-text. Two of them are icons and could take the weaker bar; they
 * clear the stronger one in both themes today (the tightest is 4.66), so holding
 * them there costs nothing and says something a 3:1 floor would not.
 */
const hexOf = (theme: string, token: string): string => {
  const selector = theme === 'light' ? ':root' : `.${theme}`;
  const start = css.indexOf(`${selector} {`);
  const body = css.slice(start, css.indexOf('\n}', start));
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith(`${token}:`)) continue;
    const value = trimmed.slice(token.length + 1).replace(';', '').trim();
    if (value.startsWith('#')) return value;
    if (value.startsWith('var(')) return hexOf(theme, value.slice(4, value.indexOf(')')));
  }
  return '#000000';
};

/**
 * The rail's active fill is TRANSLUCENT, so its real ground is a composite.
 *
 * Read out of the component rather than written down twice: the alpha is a
 * Tailwind opacity suffix (`bg-primary/20`), which no token file knows about, so
 * a check that hardcoded it would go on asserting 20% for exactly as long as
 * somebody left it at 20%.
 *
 * **Comments stripped first, and here that is not tidiness.** This is the only
 * read in this file whose result is a NUMBER rather than a yes/no: the alpha
 * drives four contrast and deltaE assertions below. `exec` takes the FIRST
 * match, and `ActivityRail.tsx` explains its own active state at length - so a
 * paragraph mentioning `bg-primary/30` written above the class string would
 * silently move every one of those four assertions onto a ground the rail does
 * not draw, and all four would go on passing. That is the exact failure the
 * section below records having survived twice, arriving by a new route.
 * `session/view.ts` and `electron/shell.ts` strip for the same reason.
 */
const code = (source: string): string => source
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/(^|[^:])\/\/.*$/gm, '$1');

const railSource = code(
  fs.readFileSync(path.join(process.cwd(), 'src/components/common/ActivityRail.tsx'), 'utf8'),
);
const activeAlpha = (() => {
  const m = /bg-primary\/(\d+)/.exec(railSource);
  return m ? Number(m[1]) / 100 : Number.NaN;
})();
checkTrue('the rail draws its active view as a translucent accent fill',
  Number.isFinite(activeAlpha) && activeAlpha > 0 && activeAlpha < 1);
checkTrue('...and the 2px accent edge that used to sit over it is gone',
  !/w-0\.5 rounded-full bg-primary/.test(railSource));

/**
 * Each entry is `[what is drawn, the ground it is drawn on, what renders it]`.
 * The third field is the point: it is what a future session checks before
 * trusting the first two, and it is what was missing when this section spent two
 * revisions testing a ground nothing used.
 */
const CHROME_PAIRS: readonly [string, string, string][] = [
  // The title row's packet counter and the rail's own text. Both surfaces are
  // `bg-secondary`; see `TitleRow` for why the chrome is a step brighter than
  // the panes rather than the same grey.
  ['--secondary-foreground', '--secondary', 'TitleRow / ActivityRail text'],
  // The rail's idle icons, which are `text-muted-foreground` on that ground.
  ['--muted-foreground', '--secondary', 'ActivityRail idle icons'],
  // The status bar shares that ground - it is the third face of the same
  // continuous chrome - so its quiet items ride the two pairs above. Its
  // elapsed clock is its own, and it clears the text floor on both themes.
  ['--primary', '--secondary', 'StatusBar capture elapsed'],
  // The speed test's upload colour is on its figures' arrows, its trace and
  // its latency box, on the card and on the ground (ADR 0054).
  ['--speed-upload', '--card', 'speed test upload, on a card'],
  ['--speed-upload', '--background', 'speed test upload, on the ground'],
  ['--speed-download', '--card', 'speed test download, on a card'],
];

/**
 * The same thing for GLYPHS, at 3:1.
 *
 * **This is a different floor rather than a lower one, and the distinction is
 * the point.** WCAG holds text to 4.5:1 and non-text graphics to 3:1, because a
 * letterform has to be told apart from twenty-five others at 11px while an icon
 * has only to be seen. Measured here rather than assumed, because the pair that
 * put this list in the file failed the text floor: `--warning` on
 * `--secondary` is 4.06:1 in Day.
 *
 * What that failure bought is the rule the rail already follows and the status
 * bar now does too - the hue goes on the glyph and the label stays at
 * `--secondary-foreground`, so the state is carried by SHAPE plus colour and
 * never by colour alone. An entry here is therefore a promise that something
 * else says the same thing: the triangle differs in outline from the plug it
 * replaces, and the dropped count says the word "dropped".
 */
const GLYPH_PAIRS: readonly [string, string, string][] = [
  ['--warning', '--secondary', 'StatusBar warning glyph'],
];

for (const t of THEME_OPTIONS) {
  if (!t.mode) continue;
  // Download IS the accent, written out as a hex so it can be measured.
  check(`${t.value}: --speed-download is --primary`, hexOf(t.value, '--speed-download'), hexOf(t.value, '--primary'));
  for (const [ink, ground, what] of GLYPH_PAIRS) {
    const ratio = contrastRatio(hexOf(t.value, ink), hexOf(t.value, ground));
    checkTrue(`${t.value}: ${what} (${ratio.toFixed(2)}:1, graphic)`, ratio >= 3);
  }
  for (const [ink, ground, what] of CHROME_PAIRS) {
    const ratio = contrastRatio(hexOf(t.value, ink), hexOf(t.value, ground));
    checkTrue(`${t.value}: ${what} (${ratio.toFixed(2)}:1)`, ratio >= 4.5);
  }

  // The active view's glyph, on the composite the translucent fill makes.
  //
  // `--foreground` rather than `--primary`, and Day is why: `--primary` on a
  // tint of itself peaks at 3.97:1 there and falls as the alpha rises, because
  // `#0b6bcb` is a mid-blue and the tint lightens toward it. The
  // accent-on-accent-tint pattern simply cannot clear the floor in this palette,
  // which is a fact about the palette rather than about the floor - so the glyph
  // changed and the floor did not.
  const chrome = hexOf(t.value, '--secondary');
  const fill = mixHex(hexOf(t.value, '--primary'), chrome, activeAlpha);
  const glyph = contrastRatio(hexOf(t.value, '--foreground'), fill);
  checkTrue(`${t.value}: ActivityRail active glyph (${glyph.toFixed(2)}:1)`, glyph >= 4.5);

  // And the fill against the two things it must not be mistaken for. The second
  // is the one that matters and the one a contrast ratio would not catch: an
  // active marker a HOVER can be mistaken for is not a marker, and hover is
  // `--accent`, which is deliberately one step off the same ground.
  const fromChrome = deltaE76(fill, chrome);
  const fromHover = deltaE76(fill, hexOf(t.value, '--accent'));
  checkTrue(`${t.value}: the active fill reads against the rail (${fromChrome.toFixed(1)} deltaE)`,
    fromChrome >= MIN_STATE_DELTA_E);
  checkTrue(`${t.value}: ...and is not its hover (${fromHover.toFixed(1)} deltaE)`,
    fromHover >= MIN_STATE_DELTA_E);
}

console.log();
// --- selection, and High Contrast's 7:1 (ADR 0056) ----------------------------
// The selected row is the accent mixed into the ground, and its text is the
// accent itself, so the pair that has to hold is primary on that mix. The share
// is per theme because it is the largest each ground allows: Light's accents
// sit near 4.5:1 on the ground already, so 6% is all it has room for; the ring
// and the weight carry the selection there, the tint only confirms it.
const SELECTION_SHARE: Record<string, number> = { light: 6, dark: 22, dim: 13, contrast: 19 };

function themeBlock(theme: string): string {
  const selector = theme === 'light' ? ':root' : `.${theme}`;
  const start = css.indexOf(`${selector} {`);
  return start === -1 ? '' : css.slice(start, css.indexOf('\n}', start));
}
function hexIn(theme: string, token: string): string {
  return new RegExp(`${token}:\\s*(#[0-9a-fA-F]{6})`).exec(themeBlock(theme))?.[1] ?? '#000000';
}
function selectionHex(theme: string, primary: string): string {
  return mixHex(primary, hexIn(theme, '--background'), SELECTION_SHARE[theme] / 100);
}

// The Appearance tiles wrap each miniature in a div of that theme's class, so
// Light has to be reachable by `.light` as well as by `:root` - or the Light
// tile inside any dark document would draw in the document's colours.
checkTrue('the light block is selected by .light as well as :root',
  /(^|\n)\.light, :root \{/.test(css));

// And a theme class is not enough on its own: Tailwind declares every
// `--color-*` on :root, where it resolves to the DOCUMENT's theme and is
// inherited already resolved, so `bg-background` under `.light` inside `.dark`
// paints dark. `.theme-scope` re-points each one at the scope's own token -
// and every colour utility a miniature uses must be among them, or that part
// of the tile quietly draws in the wrong theme.
{
  const panel = fs.readFileSync(
    path.join(process.cwd(), 'src/components/common/AppearanceSettingsPanel.tsx'), 'utf8');
  const mini = panel.slice(panel.indexOf('const ThemeMiniature'), panel.indexOf('const SYSTEM_SPLIT'));
  const scope = /(^|\n)\.theme-scope \{([^}]*)\}/.exec(css)?.[2] ?? '';
  const used = [...new Set([...mini.matchAll(/\b(?:bg|ring|border)-([a-z]+(?:-[a-z]+)*)/g)]
    .map((m) => m[1]).filter((n) => !['inset', 'r', 'b', 'l', 't'].includes(n)))];
  checkTrue('the theme miniature carries .theme-scope', /theme-scope/.test(mini));
  for (const name of used) {
    checkTrue(`.theme-scope re-points --color-${name}`,
      scope.includes(`--color-${name}: var(--${name});`));
  }
}

for (const theme of realThemes) {
  const share = SELECTION_SHARE[theme];
  checkTrue(`${theme}: --selection mixes ${share}% of the accent into the ground`,
    new RegExp(`--selection:\\s*color-mix\\(in srgb, var\\(--primary\\) ${share}%, var\\(--background\\)\\)`).test(themeBlock(theme)));
  const primary = hexIn(theme, '--primary');
  const floor = theme === 'contrast' ? 7 : 4.5;
  const ratio = contrastRatio(primary, selectionHex(theme, primary));
  checkTrue(`${theme}: the selected row's text (primary on the mix) is ${floor}:1 (${ratio.toFixed(2)})`, ratio >= floor);
}

for (const fg of ['--foreground', '--muted-foreground', '--primary']) {
  for (const bg of ['--background', '--card', '--secondary']) {
    const ratio = contrastRatio(hexIn('contrast', fg), hexIn('contrast', bg));
    checkTrue(`contrast: ${fg} on ${bg} is 7:1 (${ratio.toFixed(2)})`, ratio >= 7);
  }
}
{
  const warn = contrastRatio(hexIn('contrast', '--warning'), hexIn('contrast', '--secondary'));
  checkTrue(`contrast: --warning on --secondary is 4.5:1 (${warn.toFixed(2)})`, warn >= 4.5);
  const edge = contrastRatio(hexIn('contrast', '--border'), hexIn('contrast', '--background'));
  checkTrue(`contrast: --border on --background is 3:1, the structure on its own (${edge.toFixed(2)})`, edge >= 3);
}

console.log();
// --- every accent swatch, in every theme (ADR 0056) ----------------------------
// An accent replaces --primary, --primary-foreground, --ring and
// --speed-download, so every pair above that reads --primary is asked again
// with each swatch in its place. Blue is the theme blocks' own values, so it
// repeats checks already made; it stays in the loop so the table cannot hold a
// Blue that differs from them and pass.
for (const theme of realThemes) {
  const floor = theme === 'contrast' ? 7 : 4.5;
  const chrome = hexIn(theme, '--secondary');
  const hover = hexIn(theme, '--accent');
  for (const a of ACCENTS) {
    const primary = a.primary[theme];
    const at = `${theme} / ${a.id}`;
    const fill = contrastRatio(a.primaryForeground[theme], primary);
    checkTrue(`${at}: text on the accent fill is 4.5:1 (${fill.toFixed(2)})`, fill >= 4.5);
    for (const bg of ['--background', '--card', '--secondary']) {
      const r = contrastRatio(primary, hexIn(theme, bg));
      checkTrue(`${at}: the accent on ${bg} is ${floor}:1 (${r.toFixed(2)})`, r >= floor);
    }
    const sel = contrastRatio(primary, selectionHex(theme, primary));
    checkTrue(`${at}: the selected row's text is ${floor}:1 (${sel.toFixed(2)})`, sel >= floor);

    const railFill = mixHex(primary, chrome, activeAlpha);
    const glyph = contrastRatio(hexIn(theme, '--foreground'), railFill);
    checkTrue(`${at}: the rail's active glyph is 4.5:1 (${glyph.toFixed(2)})`, glyph >= 4.5);
    const fromChrome = deltaE76(railFill, chrome);
    const fromHover = deltaE76(railFill, hover);
    checkTrue(`${at}: the rail's active fill reads against the rail (${fromChrome.toFixed(1)} deltaE)`,
      fromChrome >= MIN_STATE_DELTA_E);
    checkTrue(`${at}: ...and is not its hover (${fromHover.toFixed(1)} deltaE)`,
      fromHover >= MIN_STATE_DELTA_E);

    // An accent that reads as an error or a warning makes every selected row
    // and focused control say something the app did not mean.
    for (const status of ['--destructive', '--warning']) {
      const d = deltaE76(primary, hexIn(theme, status));
      checkTrue(`${at}: the accent is not ${status} (${d.toFixed(1)} deltaE)`, d >= 10);
    }

    // Download is the accent, upload is purple - unless the accent IS purple,
    // when upload takes the theme's orange.
    const upload = a.uploadHue ? PALETTE_BY_THEME[theme].hues[a.uploadHue] : hexIn(theme, '--speed-upload');
    const apart = deltaE76(primary, upload);
    checkTrue(`${at}: download and upload stay apart (${apart.toFixed(1)} deltaE)`, apart >= 15);
    const onCard = contrastRatio(upload, hexIn(theme, '--card'));
    checkTrue(`${at}: the upload colour on --card is 4.5:1 (${onCard.toFixed(2)})`, onCard >= 4.5);
  }
}

if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All theme registry checks passed.');
