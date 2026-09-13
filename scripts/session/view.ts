/**
 * The four views, and the rail that switches between them.
 *
 *   npx tsx scripts/session/view.ts
 *
 * Everything here guards a **silent** failure. The rail is a strip of a dozen
 * icons and a view is a whole surface, so the ways these can disagree all look
 * like working software:
 *
 *  - `useKeyboardNavigation` resolves `Ctrl+<n>` as `APP_VIEWS[n - 1]` while the
 *    rail's tooltip prints the `shortcut` string that entry declares. Reorder
 *    the array and every tooltip is confidently wrong about which key opens
 *    what, with nothing failing anywhere.
 *  - `VIEW_ICONS` is a `Record<AppView, ...>`, so TypeScript forces an icon for
 *    a new member of the union - but nothing forces an entry in `APP_VIEWS`, and
 *    a view that is in the type and not in that list has no rail button and no
 *    shortcut. It is reachable only by whatever code calls `setView` directly.
 *  - A view with a rail button and no surface in `App.tsx` is a button that
 *    visibly lights up and changes nothing on screen.
 *  - And the pair that currently agree only because one session noticed:
 *    `restoredView` refuses `stream`, and `stream` is exactly the view whose
 *    JSX guard carries a second condition. Those two facts have to move
 *    together, or a restart lands on a view that renders nothing at all.
 *
 * The last section is arithmetic rather than drift: the rail's height against
 * the smallest window the app allows. Its three variable-length groups are
 * `APP_VIEWS`, `WIDGET_TYPE_IDS` and the bottom pair, so adding to any of them
 * is what would overflow it - and an overflowing rail does not report anything,
 * it just puts Settings below the bottom of the window.
 */
import { readFileSync } from 'node:fs';
import {
  APP_VIEWS, isAppView, normalizeViewPrefs, restoredView, viewStore, VIEW_DEFAULTS,
  type AppView,
} from '../../src/services/viewPrefs';
import { WIDGET_TYPE_IDS } from '../../src/services/dashboardPrefs';
import { MIN_WINDOW_HEIGHT } from '../../electron/window';

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

/**
 * Comments stripped, the same way `shell.ts` does it before looking for
 * `frame:`. Every file read below explains at length what it is doing, and a
 * check that cannot tell prose from code fails on its own rationale - which has
 * already happened once in this repository.
 */
function code(file: string): string {
  return readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

const ids = APP_VIEWS.map((v) => v.id);

console.log('--- the order IS the numbering ---\n');

{
  // The tie with teeth. `APP_VIEWS[at - 1]` is what the handler evaluates; this
  // is what the tooltip says.
  const declared = APP_VIEWS.map((v) => v.shortcut);
  const byPosition = APP_VIEWS.map((_, i) => `Ctrl+${i + 1}`);
  check('every view\'s tooltip names the key that actually opens it', declared, byPosition);

  // `e.key` is one character, so a tenth view's `Ctrl+10` could be written in a
  // tooltip and could never fire. Asserted rather than commented because the
  // failure is a shortcut that silently does not exist.
  checkTrue('there are at most nine views, because the shortcut is one digit',
    APP_VIEWS.length <= 9);

  check('no view appears twice', new Set(ids).size, ids.length);
  checkTrue('every entry has a label', APP_VIEWS.every((v) => v.label.length > 0));

  // The handler is the other half of the pair above: if it ever stops indexing
  // `APP_VIEWS`, the numbering becomes a second hand-written list.
  checkTrue('the handler still resolves the digit through APP_VIEWS',
    code('src/hooks/useKeyboardNavigation.ts').includes('APP_VIEWS[at - 1]'));
}

console.log('\n--- the union and the list cannot disagree ---\n');

{
  // Parsed from source because the union does not exist at run time, and because
  // `Record<AppView, ...>` makes TypeScript complain about a missing *icon* and
  // say nothing about a missing rail button.
  const source = code('src/services/viewPrefs.ts');
  const union = /export type AppView =([^;]+);/.exec(source);
  checkTrue('the AppView union is where this expects it', union !== null);
  const members = (union?.[1] ?? '').match(/'([a-z]+)'/g)?.map((m) => m.slice(1, -1)) ?? [];

  check('every member of the union has a rail entry', members.filter((m) => !ids.includes(m as AppView)), []);
  check('...and every rail entry is a member of the union', ids.filter((id) => !members.includes(id)), []);

  // `isAppView` is what the normaliser trusts, so it has to admit all of them
  // and nothing else.
  checkTrue('isAppView admits every view', ids.every((id) => isAppView(id)));
  check('...and rejects what is not one',
    [isAppView('dashboard'), isAppView(''), isAppView(null), isAppView(3)],
    [false, false, false, false]);
}

console.log('\n--- every view has a surface, and a conditional one is not restorable ---\n');

{
  /**
   * The JSX guard for each view, as written in `App.tsx`.
   *
   * Matched only where it opens a JSX expression - `{view === 'x'` - because
   * `view === 'packets'` also appears in an `if` and in an effect, and those say
   * nothing about what is on screen. Everything between the comparison and the
   * `(` or `?` that follows is the *extra* condition: empty means the surface
   * renders whenever the view is active, and anything else means it does not.
   */
  const app = code('src/App.tsx');
  const extras = new Map<string, string>();
  for (const m of app.matchAll(/\{\s*view === '([a-z]+)'([^(?]*)/g)) {
    const rest = m[2].replace(/&&/g, '').replace(/\s+/g, '');
    // The loosest guard wins: a view rendered unconditionally somewhere is
    // reachable, whatever else also tests it.
    if (!extras.has(m[1]) || rest.length < (extras.get(m[1]) ?? '').length) extras.set(m[1], rest);
  }

  check('every view renders something', ids.filter((id) => !extras.has(id)), []);
  check('...and nothing renders for a view that does not exist',
    [...extras.keys()].filter((k) => !ids.includes(k as AppView)), []);

  // The pair. Statistics and Network mount on their view alone; Follow Stream
  // also needs a target, because a pane rendering `target={null}` would be the
  // empty Follow Stream the rail's disabled icon exists to prevent.
  const conditional = ids.filter((id) => (extras.get(id) ?? '').length > 0);
  check('exactly one view needs more than its own name to render', conditional, ['stream']);
  check('...and it is the one `restoredView` refuses',
    conditional.filter((id) => restoredView(id) === id), []);
  check('...while every unconditional view is restored as itself',
    ids.filter((id) => !conditional.includes(id) && restoredView(id) !== id), []);

  // Where a refused view lands. Packets is the only surface that is always
  // mounted, so it is the only safe answer.
  check('a refused view falls to packets', restoredView('stream'), 'packets');

  // Packets is the exception to "unmounted when inactive", and the reason is the
  // virtualised scroll offset. Asserted as the shape that keeps it mounted,
  // because `hidden` and `flex` are the same specificity and swapping the inline
  // style for that utility would make the winner depend on stylesheet order.
  checkTrue('the packet list is hidden rather than unmounted',
    app.includes("view === 'packets' ? undefined : { display: 'none' }"));

  // This check used to read "only Network hides the filter row", and the day it
  // could be inverted is the day Network stopped being a view.
  //
  // A display filter acts on the capture, so a view that hides the filter row is
  // announcing that it is not a way of looking at the capture - which is what
  // Network was: the machine's adapters, DNS and public identity, none of which
  // change when a packet arrives. It is a Settings tab now, beside Driver Info.
  //
  // So the rule is the strong form: **no view hides the filter row.** Every
  // remaining view IS the capture - the list is the frames, Statistics counts
  // them, Follow Stream reads one conversation out of them. A future view that
  // needs the row hidden has to fail here first and answer the question Network
  // never did.
  const hidesFilterRow = [...app.matchAll(/view !== '([a-z]+)'/g)].map((m) => m[1]);
  check('no view hides the filter row', [...new Set(hidesFilterRow)], []);
}

console.log('\n--- the stored view ---\n');

{
  check('the key is the one the plan named', viewStore.key, 'inwire.view');
  check('a fresh install opens on packets', VIEW_DEFAULTS.view, 'packets');

  check('a non-object is refused whole', normalizeViewPrefs('packets'), null);
  check('...and so is null', normalizeViewPrefs(null), null);

  // Clamped rather than rejected, the house rule: a view this build removed
  // lands on packets instead of discarding the key and whatever else ends up in
  // it later.
  check('an unknown view is clamped to packets',
    normalizeViewPrefs({ view: 'dashboard' }), { view: 'packets' });
  check('...and so is a missing one', normalizeViewPrefs({}), { view: 'packets' });
  check('...and so is a non-string', normalizeViewPrefs({ view: 2 }), { view: 'packets' });

  // `stream` is a legal stored value and an illegal restored one, deliberately:
  // what was on screen is what gets written, and the decision about what is
  // resumable is made in one place, on the way in.
  check('stream is a legal stored value', normalizeViewPrefs({ view: 'stream' }), { view: 'stream' });

  for (const id of ids) {
    check(`${id} survives a round trip through the normaliser`,
      normalizeViewPrefs({ view: id })?.view, id);
  }
}

console.log('\n--- the rail fits the smallest window ---\n');

{
  /**
   * The rail's height, from the Tailwind classes that produce it.
   *
   * These numbers are a second place the layout is written down, which is only
   * worth having if they are held to the first - so each is checked against the
   * class it stands for before any of them is added up. Without that this
   * section would assert that one table agrees with itself.
   */
  const rail = code('src/components/common/ActivityRail.tsx');
  const classIs = (name: string, needle: string): void =>
    checkTrue(`${name} is still \`${needle}\``, rail.includes(needle));

  classIs('the button target', "const TARGET = 'w-9 h-9'");
  classIs('the gap inside a group', 'gap-0.5');
  classIs('the divider', 'my-1.5 h-px w-7');
  classIs('the capture group\'s top padding', '${GROUP} pt-1');
  classIs('the bottom group\'s padding', '${GROUP} mt-auto pb-2');
  classIs('the rail\'s own width', 'w-14 shrink-0');
  // The rail starts at the top now: the 40px cell that held the brand mark went
  // with the mark, which is in the title row. An `h-10` cell coming back here
  // would be 40px of rail height spent on nothing, and there is not 40px spare.
  checkTrue('there is no top cell', !rail.includes('h-10 w-full shrink-0'));
  // And with it went the rail's only drag region. The title row is where a
  // window is grabbed; a rail that claimed part of the drag would be a strip of
  // buttons that move the window instead of being pressed.
  checkTrue('the rail is entirely no-drag', !rail.includes('app-drag'));

  const TARGET = 36;        // w-9
  const GAP = 2;            // gap-0.5
  const DIVIDER = 6 + 1 + 6; // my-1.5 + h-px
  const group = (items: number): number => items * TARGET + Math.max(0, items - 1) * GAP;

  const blocks = [
    ['capture: Start/Stop, adapter, schedule', 4 + group(3)],
    ['divider', DIVIDER],
    [`views: ${ids.length}`, group(ids.length)],
    ['divider', DIVIDER],
    [`widgets: ${WIDGET_TYPE_IDS.length}`, group(WIDGET_TYPE_IDS.length)],
    // The bottom group carries its own divider, so the gap between that line and
    // the first button is the group's gap rather than the divider's margin.
    ['bottom: Find, Export/Import, Settings', DIVIDER + GAP + group(3) + 8],
  ] as const;

  let total = 0;
  for (const [name, height] of blocks) {
    total += height;
    console.log(`        ${String(height).padStart(4)}  ${name}`);
  }
  console.log(`        ${String(total).padStart(4)}  total, against ${MIN_WINDOW_HEIGHT} of window\n`);

  // The number the rail's header comment quotes. It said 549 until this script
  // was written, which was the figure for `my-1` dividers and did not count the
  // two groups' padding - so the comment was describing a rail that had already
  // changed. Held here rather than trusted there, and it has earned that once
  // already: deleting the hamburger menu moved Custom Dissectors into the bottom
  // group, and this is the line that says what that cost.
  check('the rail is as tall as it says it is', total, 577);
  // The raw file, not `code()`: the figure lives in the header comment, which is
  // the first thing `code()` throws away. The point of this one is that the
  // prose and the arithmetic cannot part company again.
  checkTrue('...and the comment in the rail says so',
    readFileSync('src/components/common/ActivityRail.tsx', 'utf8').includes(`**${total}px**`));

  // The thing that actually matters. The bottom group is pinned with `mt-auto`,
  // so an overflow does not scroll - it pushes Settings off the bottom edge.
  checkTrue('it fits the smallest window the app allows', total <= MIN_WINDOW_HEIGHT);

  // Reported rather than asserted, and that is deliberate. "There is room for one
  // more" was a check here until the hamburger menu was deleted and Custom
  // Dissectors took the last slot - at which point it failed, and it was the
  // CHECK that was wrong: a full rail is a fact to know, not a defect. The
  // invariant is the line above, that it fits. This is the number that tells the
  // next session what an icon costs before they add one.
  const slack = MIN_WINDOW_HEIGHT - total;
  const roomFor = Math.floor(slack / (TARGET + GAP));
  console.log(`        ${slack}px of slack - room for ${roomFor} more `
    + `${roomFor === 1 ? 'icon' : 'icons'} before a group must scroll`);
  if (roomFor === 0) {
    console.log('        the rail is FULL: anything more needs Settings, or the '
      + 'widgets group has to start scrolling');
  }
  console.log();
}

console.log(failures === 0
  ? '\nAll view checks passed.'
  : `\n${failures} view check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
