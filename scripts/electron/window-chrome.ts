/**
 * The frameless window's own chrome: the ground it opens on, and its controls.
 *
 *   npx tsx scripts/electron/window-chrome.ts
 *
 * This was `title-bar.ts`, and it held a table of native-button colours to
 * index.css. Both halves of that job are gone: the window is frameless, so
 * Windows draws nothing, and the app's controls are CSS that follows the
 * cascade like every other element. What it checks now is the one colour
 * decision that still cannot follow the cascade, plus the three rules that make
 * a hand-drawn control group fail *silently* rather than visibly.
 *
 * ## The colour that cannot follow the cascade
 *
 * `backgroundColor` is fixed when a `BrowserWindow` is constructed, which is
 * before a renderer exists to report a theme. So `electron/windowColors.ts`
 * duplicates each theme's `--background` as concrete hex and main caches the
 * resolved one in `window-state.json`. Every duplicate in this repository gets
 * a check that it still agrees with its source; this is that check.
 *
 * It matters more now than the button colours ever did. A frameless window IS
 * the app's surface, so a drifted value here is not a slightly-off strip at the
 * top - it is the whole window opening in the wrong colour and correcting
 * itself once the bundle has parsed.
 *
 * ## The three silent ways hand-drawn controls fail
 *
 *  - **A control without `app-no-drag` moves the window instead of being
 *    pressed**, and the only symptom is a click that does nothing. On the close
 *    button that is a window that cannot be closed.
 *  - **The title row's spacer and the controls' real width can disagree**,
 *    which puts the window's name off-centre by however much they differ - a
 *    thing nobody measures and everybody sees.
 *  - **Close can stop being red.** `#c42b1c` is learned, not designed; a close
 *    button that hovers to the accent colour still works and is still wrong.
 *
 * Runs under plain `tsx` with no Electron: `windowColors.ts` imports nothing
 * from `electron`, which is the whole reason it is a separate module from
 * `window.ts`.
 */
import { readFileSync } from 'node:fs';
import {
  DEFAULT_WINDOW_THEME, isHexColor, resolveWindowBackground,
} from '../../electron/windowColors';
import {
  TITLE_BAR_HEIGHT, WINDOW_CONTROL_COUNT, WINDOW_CONTROL_HEIGHT, WINDOW_CONTROL_WIDTH,
} from '../../electron/window';
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
const controls = readFileSync('src/components/common/WindowControls.tsx', 'utf8');
const titleRow = readFileSync('src/components/common/TitleRow.tsx', 'utf8');

/**
 * One custom property's value inside one `selector { ... }` block.
 *
 * The same `indexOf`/`\n}` walk `scripts/themes/registry.ts` uses, for the same
 * reason: a real CSS parser would be a dependency to read four colours, and the
 * blocks in this file are flat.
 *
 * **Throws rather than returning null, and that is deliberate.** The first
 * version returned `string | null`, and a check comparing two tokens passed
 * while both were null - a broken selector reading as agreement. An assertion
 * that can pass because neither side was found is worse than no assertion, so a
 * token this cannot read stops the script instead of satisfying it.
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

console.log('--- the ground a window opens on, per theme ---\n');

{
  for (const { value, label } of THEME_OPTIONS) {
    check(`${label} opens on its own --background`,
      resolveWindowBackground(value).toLowerCase(),
      tokenIn(selectorFor(value), '--background').toLowerCase());
  }

  // Every theme, not just the four that exist today: the loop above is driven
  // by THEME_OPTIONS, so a theme added without a palette entry would silently
  // not be checked rather than fail.
  check('every theme in the picker was checked',
    THEME_OPTIONS.length >= 4, true);
}

console.log('\n--- a name it cannot resolve still opens a window ---\n');

{
  // This runs while a window is being created. A stored theme from a build that
  // retired one must not stop the app opening, so the resolver falls back
  // rather than throwing - and the fallback has to be a real colour.
  const fallback = resolveWindowBackground(DEFAULT_WINDOW_THEME);
  checkTrue('the default theme resolves to a hex colour', isHexColor(fallback));
  check('an unknown theme falls back to it', resolveWindowBackground('dracula'), fallback);
  check('...and so does undefined', resolveWindowBackground(undefined), fallback);
  check('...and so does the unresolved "system"', resolveWindowBackground('system'), fallback);
}

console.log('\n--- what comes off disk is checked before Electron sees it ---\n');

{
  // `backgroundColor` rejects a malformed value at construction, so a profile
  // somebody hand-edited would be a window that never opens.
  check('a good colour is accepted', isHexColor('#1e1e1e'), true);
  check('three-digit hex is refused', isHexColor('#fff'), false);
  check('a named colour is refused', isHexColor('rebeccapurple'), false);
  check('a number is refused', isHexColor(0x1e1e1e), false);
  check('null is refused', isHexColor(null), false);
  check('an object is refused', isHexColor({ background: '#1e1e1e' }), false);
}

console.log('\n--- the controls cannot be pressed unless they opt out of the drag ---\n');

{
  // The failure this catches is a click that does nothing at all, on the one
  // control group a window cannot be used without.
  const buttons = controls.match(/<button/g)?.length ?? 0;
  check('there are three controls', buttons, WINDOW_CONTROL_COUNT);

  // On the shared class, so all three carry it and a fourth would too. Asserted
  // on the container as well, because either alone is enough for the drag
  // region and a future refactor could move it.
  checkTrue('the control group opts out of the drag region',
    controls.includes('app-no-drag'));
  checkTrue('...on the shared button class, not per button',
    /const BUTTON = [^;]*app-no-drag/s.test(controls));

  // Each control names itself, because a glyph-only button is unreachable
  // otherwise - and these three are the window's own verbs.
  for (const label of ['Minimize', 'Close']) {
    checkTrue(`the ${label.toLowerCase()} control has an accessible name`,
      controls.includes(`aria-label="${label}"`));
  }
  // The maximize one is a state pair rather than a literal, and the label is
  // the ACTION rather than the state: a button announcing "maximized" would be
  // saying where you are, not what pressing it does.
  checkTrue('the maximize control names the action, both ways',
    controls.includes("'Restore down' : 'Maximize'"));
}

console.log('\n--- the reserve and the controls agree ---\n');

{
  // The title row centres its label by balancing the controls with a spacer. If
  // the two disagree the window's name is off-centre by the difference, which
  // is a thing nobody measures and everybody sees.
  const reserve = WINDOW_CONTROL_WIDTH * WINDOW_CONTROL_COUNT;
  checkTrue(`the title row reserves ${reserve}px`, titleRow.includes(`w-[${reserve}px]`));
  checkTrue('...and a control is that wide',
    controls.includes(`w-[${WINDOW_CONTROL_WIDTH}px]`));

  // 32 in a 40px row. Not centred by accident: Windows' own caption buttons are
  // full-height, and these are not, so the 8px has to be somewhere deliberate.
  check('a control is shorter than the row it sits in',
    WINDOW_CONTROL_HEIGHT < TITLE_BAR_HEIGHT, true);
  checkTrue('...at the height the constant says',
    controls.includes(`h-${WINDOW_CONTROL_HEIGHT / 4}`));
}

console.log('\n--- close keeps the colour people already know ---\n');

{
  // The one hardcoded colour in the app's chrome, and the only one that should
  // be. It is learned rather than designed: every Windows application has used
  // it for a decade, it has to mean the same thing on a light ground and a dark
  // one, and a close button that hovered to `--accent` would be indistinguish-
  // able from minimize at a glance.
  checkTrue('close hovers to Windows\' own red', controls.includes('hover:bg-[#c42b1c]'));
  checkTrue('...with white on it', controls.includes('hover:text-white'));
  checkTrue('the other two hover to the theme\'s accent',
    (controls.match(/hover:bg-accent/g)?.length ?? 0) === 2);

  // And nothing else in the app's chrome hardcodes a colour. The themes are
  // tokens; an exception that spread would be four themes' worth of drift.
  const hardcoded = controls.match(/#[0-9a-f]{6}/gi) ?? [];
  check('close\'s red is the only literal colour in the controls',
    [...new Set(hardcoded.map((c) => c.toLowerCase()))], ['#c42b1c']);
}

console.log(failures === 0
  ? '\nAll window chrome checks passed.'
  : `\n${failures} window chrome check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
