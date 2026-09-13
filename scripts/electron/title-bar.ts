/**
 * The colours the native window buttons are painted, against index.css.
 *
 *   npx tsx scripts/electron/title-bar.ts
 *
 * `electron/titleBarColors.ts` duplicates four of index.css's surfaces as
 * concrete hex, because `titleBarOverlay` is handed its colours by the main
 * process before a renderer exists and there is no cascade to read. Every
 * duplicate in this repository gets a check that it still agrees with its
 * source; this is that check.
 *
 * It matters more than most. The failure mode of a drifted value here is not a
 * wrong colour somewhere in a panel - it is Windows drawing its own glyphs, at
 * a weight we do not control, on a ground that no longer matches the strip they
 * sit in. That reads as a broken window rather than a theming bug.
 *
 * Runs under plain `tsx` with no Electron: `titleBarColors.ts` imports nothing
 * from `electron`, which is the whole reason it is a separate module from
 * `window.ts`.
 */
import { readFileSync } from 'node:fs';
import {
  DEFAULT_TITLE_BAR_THEME, isTitleBarColors, mixHex, resolveTitleBarColors,
  UNFOCUSED_SYMBOL_MIX,
} from '../../electron/titleBarColors';
import { THEME_OPTIONS } from '../../src/lib/themeOptions';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
const checkTrue = (name: string, condition: boolean): void => check(name, condition, true);

const css = readFileSync('src/index.css', 'utf8');

/**
 * One custom property's value inside one `selector { ... }` block.
 *
 * The same `indexOf`/`\n}` walk `scripts/themes/registry.ts` uses, for the same
 * reason: a real CSS parser would be a dependency to read four colours, and the
 * blocks in this file are flat.
 */
/**
 * Throws rather than returning null, and that is deliberate.
 *
 * The first version returned `string | null`, and the check comparing
 * `--foreground` against `--card-foreground` passed while both were null - a
 * broken selector reading as agreement. An assertion that can pass because
 * neither side was found is worse than no assertion, so a token this cannot
 * read stops the script instead of satisfying it.
 */
function tokenIn(selector: string, token: string): string {
  const start = css.indexOf(`${selector} {`);
  if (start === -1) throw new Error(`index.css has no ${selector} block`);
  const body = css.slice(start, css.indexOf('\n}', start));
  const match = new RegExp(`^\\s*${token}:\\s*([^;]+);`, 'm').exec(body);
  if (match === null) throw new Error(`${selector} declares no ${token}`);
  return match[1].trim();
}

/** `light` IS `:root` - it is the default and has no class block of its own. */
const selectorFor = (theme: string): string => (theme === 'light' ? ':root' : `.${theme}`);

console.log('--- the overlay pair is the plain chrome pair, per theme ---\n');

for (const { value: theme, label } of THEME_OPTIONS) {
  const selector = selectorFor(theme);
  const card = tokenIn(selector, '--card');
  const cardForeground = tokenIn(selector, '--card-foreground');
  const focused = resolveTitleBarColors(theme, true);

  // Decision 13: the title row takes `--card`/`--card-foreground` in all four
  // themes, never the saturated `--chrome`. Asserted against index.css so a
  // theme's surface cannot move without this failing.
  check(`${label} paints the overlay on its card surface`, focused.color, card);
  check(`...and its glyphs in the card's foreground`, focused.symbolColor, cardForeground);

  // The dependency worth naming. `PALETTE_BY_THEME.surface.foreground` mirrors
  // `--foreground`, and the overlay uses it as `--card-foreground`. Those are
  // the same value in all four themes today; the day one separates them, this
  // fails instead of quietly painting the wrong glyph colour.
  check(`...and ${label} has not separated --foreground from --card-foreground`,
    tokenIn(selector, '--foreground'), cardForeground);

  // And the one it must NOT be. A saturated band with native Windows buttons in
  // it is the choice that reads as a web page wearing a frame.
  checkTrue(`...and is not ${label}'s accent`, focused.color !== tokenIn(selector, '--chrome'));
}

console.log('\n--- losing focus dims the glyphs, opaquely ---\n');

for (const { value: theme, label } of THEME_OPTIONS) {
  const focused = resolveTitleBarColors(theme, true);
  const blurred = resolveTitleBarColors(theme, false);

  // The ground does not move; only the glyphs fade. A title bar that changed
  // colour on focus would flicker every time the user alt-tabbed.
  check(`${label} keeps its ground when the window blurs`, blurred.color, focused.color);
  checkTrue('...and fades the glyphs', blurred.symbolColor !== focused.symbolColor);
  // Pre-composited rather than expressed as an alpha, because `titleBarOverlay`
  // takes an opaque colour. This is the whole reason `focused` is a parameter.
  check('...to the mix of glyph over ground',
    blurred.symbolColor, mixHex(focused.symbolColor, focused.color, UNFOCUSED_SYMBOL_MIX));
  checkTrue('...and the result is a plain hex Electron will accept',
    isTitleBarColors(blurred));
}

console.log('\n--- a name it cannot resolve opens a window anyway ---\n');

{
  const fallback = resolveTitleBarColors(DEFAULT_TITLE_BAR_THEME, true);
  // This runs while a window is being created. A stored theme from a build that
  // had a theme this one retired must not stop the app opening, so every
  // unknown name resolves rather than throwing.
  check('an unknown theme falls back to the default', resolveTitleBarColors('dracula', true),
    fallback);
  check('...and so does an absent one', resolveTitleBarColors(undefined, true), fallback);
  // `system` is the picker's fifth entry and is a rule, not a palette. The
  // renderer is supposed to send `resolvedTheme`; this is what happens if it
  // ever sends `theme` instead.
  check('...and so does the literal "system"', resolveTitleBarColors('system', true), fallback);
  check('the default is a dark theme', DEFAULT_TITLE_BAR_THEME, 'dark');
}

console.log('\n--- what comes off disk is checked before Electron sees it ---\n');

{
  // `titleBarOverlay` with a malformed colour throws at construction, which
  // would be a profile that stops the app opening - the one outcome
  // `windowState.ts` exists to avoid.
  checkTrue('a good pair is accepted',
    isTitleBarColors({ color: '#112233', symbolColor: '#ffffff' }));
  checkTrue('a short hex is refused', !isTitleBarColors({ color: '#123', symbolColor: '#fff' }));
  checkTrue('a colour name is refused',
    !isTitleBarColors({ color: 'white', symbolColor: 'black' }));
  checkTrue('a missing field is refused', !isTitleBarColors({ color: '#112233' }));
  checkTrue('a number is refused', !isTitleBarColors({ color: 1, symbolColor: 2 }));
  checkTrue('null is refused', !isTitleBarColors(null));
  // Whitespace is tolerated, because a hand-edited profile is a thing that
  // happens and trimming is cheaper than a launch failure.
  checkTrue('a padded hex is accepted',
    isTitleBarColors({ color: ' #112233 ', symbolColor: '#ffffff' }));
}

console.log('\n--- the mix itself ---\n');

{
  check('all of a over none of b', mixHex('#ffffff', '#000000', 1), '#ffffff');
  check('none of a over all of b', mixHex('#ffffff', '#000000', 0), '#000000');
  check('half and half', mixHex('#ffffff', '#000000', 0.5), '#808080');
  // Per channel, not on a packed integer: getting this wrong shows up only on
  // a colour where the channels differ.
  check('per channel', mixHex('#ff0000', '#0000ff', 0.5), '#800080');
  check('a malformed input is null rather than a guess', mixHex('nope', '#000000', 0.5), null);
}

console.log(failures === 0
  ? '\nAll title bar checks passed.'
  : `\n${failures} title bar check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
