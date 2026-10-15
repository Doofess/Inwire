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
  DEFAULT_WINDOW_THEME, isHexColor, resolveWindowBackground, resolveWindowIsDark,
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

  // Every theme, not just the two that exist today: the loop above is driven by
  // THEME_OPTIONS, so a theme added without a palette entry would silently not
  // be checked rather than fail. The floor is the picker's real contents - Day
  // and Night - and `scripts/themes/registry.ts` is what holds that to exactly
  // one of each.
  check('every theme in the picker was checked',
    THEME_OPTIONS.length >= 2, true);
}

console.log('\n--- the theme the quit confirm is drawn in ---\n');

{
  // `showMessageBox` is drawn by the OS and follows `nativeTheme`, so the app in
  // Night on a machine set to light threw a white box over a dark window on the
  // way out. `guardClose` sets `themeSource` from this, and the decision has to
  // agree with the theme's own declared mode - a palette dark enough to need a
  // dark dialog is exactly a palette whose `mode` is `dark`. That agreement is
  // the whole reason the decision could be derived from luminance rather than
  // from a second list of theme names kept in main.
  for (const { value, label, mode } of THEME_OPTIONS) {
    check(`${label} wants a ${mode} dialog`, resolveWindowIsDark(value), mode === 'dark');
  }
  // Same fallback as the ground it is derived from: a stored name from a build
  // that retired a theme must not decide this by accident.
  check('an unresolvable name falls back to dark', resolveWindowIsDark('nope'), true);
  check('...and so does a missing one', resolveWindowIsDark(undefined), true);

  // The override is held only while the dialog is up. A standing one would pin
  // `prefers-color-scheme` in the renderer, and `useSystemThemePreference` reads
  // exactly that media query - so the app would be following itself, and an OS
  // theme change would never be seen at all. Asserted on the source because the
  // failure is a MISSING restore, which has no runtime signature until somebody
  // changes their OS theme and nothing happens.
  const main = readFileSync('electron/main.ts', 'utf8');
  checkTrue('guardClose sets themeSource for the dialog',
    main.includes('nativeTheme.themeSource = windowIsDark'));
  checkTrue('...and puts it back afterwards',
    main.includes('nativeTheme.themeSource = restore'));
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

  // **The title row has a control of its own now**, and it is the case the rule
  // above was written for: `WindowControls` carries `app-no-drag` on its shared
  // class, which protects the three buttons inside it and nothing else. A
  // fourth button placed BESIDE that group inherits none of it, and the symptom
  // is the one this whole section exists for - a press that drags the window
  // and never fires.
  const own = titleRow.match(/<button[\s\S]*?<\/button>/g) ?? [];
  // Three: the side bar's toggle beside the mark, the back step and the
  // detail-panes toggle. All are glyphs and all sit outside `WindowControls`.
  check('the title row carries three controls of its own', own.length, 3);
  checkTrue('...and every one opts out of the drag region',
    own.every((b) => b.includes('app-no-drag')));
  // Either a literal or an expression - the back control's name says where it
  // goes, so it cannot be a constant string.
  checkTrue('...and every one names itself, being a glyph',
    own.every((b) => /aria-label=(?:"[^"]+"|\{[^}]+\})/.test(b)));
  // A toggle, so it has to say which way it is - a title attribute that always
  // read "Toggle panes" would leave the state to be guessed from the workspace.
  checkTrue('...and announces its state, being a toggle',
    titleRow.includes('aria-pressed='));

  // The control it replaced. The preference stays and persists; what must not
  // come back is the SWITCH, because two ways in is how the two disagree.
  const settings = readFileSync('src/components/common/InterfaceSettingsPanel.tsx', 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ');
  checkTrue('Settings no longer switches the panes',
    !settings.includes('setting-panes') && !/onCheckedChange=\{\(panes\)/.test(settings));
  // ...but still READS the preference, to grey out an arrangement with nothing
  // to arrange. That is the row which really is a setting.
  checkTrue('...and still greys out the arrangement when they are off',
    settings.includes('disabled={!layout.panes}'));
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

  // **This check was `WINDOW_CONTROL_HEIGHT < TITLE_BAR_HEIGHT` and it is
  // equality now**, which is a reversal rather than a loosening and is worth the
  // paragraph.
  //
  // It was 32 in a 40px row, and the comment here read: "Windows' own caption
  // buttons are full-height, and these are not, so the 8px has to be somewhere
  // deliberate." The premise was right and the conclusion was backwards. A
  // caption button that reaches the window's own top edge is the easiest target
  // on the screen when maximised - you throw the pointer at the corner and it
  // cannot overshoot - and that is exactly why Windows draws its own that way.
  // The air above and below was spending the one property the position buys.
  //
  // So the row came down to the buttons rather than the buttons staying short of
  // the row, and 32 is now the floor for both: anything shorter means redrawing
  // controls whose size is Windows' metric rather than this app's choice.
  check('a control fills the row it sits in',
    WINDOW_CONTROL_HEIGHT === TITLE_BAR_HEIGHT, true);
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
  // tokens; an exception that spread would be one hand-kept copy per theme, and
  // the count is not what makes that bad - a literal simply does not follow the
  // cascade, so it is wrong on every theme but the one it was picked against.
  const hardcoded = controls.match(/#[0-9a-f]{6}/gi) ?? [];
  check('close\'s red is the only literal colour in the controls',
    [...new Set(hardcoded.map((c) => c.toLowerCase()))], ['#c42b1c']);
}

console.log(failures === 0
  ? '\nAll window chrome checks passed.'
  : `\n${failures} window chrome check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
