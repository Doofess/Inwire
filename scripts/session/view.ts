/**
 * The five views, and the rail that switches between them.
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
 * the smallest window the app allows. `APP_VIEWS` is the one group that grows
 * on its own, so adding a view is what would overflow it - and an overflowing
 * rail does not report anything, it just puts Settings below the bottom of the
 * window.
 */
import { readFileSync } from 'node:fs';
import {
  APP_VIEWS, isAppView, normalizeViewPrefs, restoredView, viewStore, VIEW_DEFAULTS,
  type AppView,
} from '../../src/services/viewPrefs';
import { MIN_WINDOW_HEIGHT, STATUS_BAR_HEIGHT, TITLE_BAR_HEIGHT } from '../../electron/window';

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

  // The pair. Statistics, the map and Frame Detail mount on their view alone;
  // Follow Stream also needs a target, because a pane rendering `target={null}`
  // would be the empty Follow Stream the rail's disabled icon exists to prevent.
  //
  // Frame Detail is the one that had to EARN its place on the unconditional
  // side. It shows a frame and can be opened with none selected, which is the
  // same shape as Follow Stream - the difference is that its empty state is a
  // frame-number box rather than nothing, so the view is its own way in and
  // there is something to restore to.
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

  // **The filter row belongs to Packets, and this is the third form of that
  // rule.** It is worth reading as a sequence, because each form was right about
  // the views it could see and wrong about the ones it could not:
  //
  //  1. "only Network hides the filter row" - Network described the machine, so
  //     a display filter there was a control with nothing in view to act on.
  //  2. "no view hides the filter row" - written the day Network stopped being a
  //     view, on the argument that every remaining view IS the capture.
  //  3. this one. (2) was an EXCLUSION rule, so every view added afterwards
  //     inherited the row without anybody deciding it should. Four did, and all
  //     four fail (1)'s own test: Statistics is handed `packets` rather than
  //     `filteredPackets` on purpose, the Routing Map draws the throttled feed,
  //     Follow Stream reads one conversation, and Frame Detail shows one frame.
  //     The filter narrowed nothing on screen in any of them.
  //
  // So the row is included by NAMING its view. Asserted two ways, because the
  // failure is silent either way: a row that stops being guarded appears over
  // four views that cannot act on it, and a row guarded by exclusion hands
  // itself to the fifth view somebody adds.
  const filterRowAt = app.indexOf('<FilterRow');
  checkTrue('the filter row is rendered in App.tsx', filterRowAt !== -1);
  checkTrue("...only under `view === 'packets'`",
    /view === 'packets'\s*&&\s*\(\s*$/.test(app.slice(Math.max(0, filterRowAt - 200), filterRowAt)));

  // The fragile form, forbidden outright. `view !== 'x'` is how (2) was written
  // and is what let four views inherit a control none of them uses.
  const excludes = [...app.matchAll(/view !== '([a-z]+)'/g)].map((m) => m[1]);
  check('no view is given the filter row by exclusion', [...new Set(excludes)], []);
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

  classIs('the button target', "const TARGET = 'w-11 h-11'");
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

  // **The card.** Four borders and a radius on the window side, which is VS
  // Code's `.part.activitybar.left` (`floatingPanels.css`) rather than an
  // invention here. The three facts below are one arrangement, and each of
  // them breaks the other two if it moves on its own.
  classIs('the rail is a bordered card', 'border border-border rounded-l-lg');

  // The facing edge belongs to the RAIL. VS Code's reason is arithmetic and it
  // carries over exactly: `w-14` under `border-box` leaves 54px of interior
  // between two 1px borders, which centres a 44px target on whole pixels. Hand
  // that border to the neighbour instead and the interior is 55.
  const app = code('src/App.tsx');
  checkTrue('...and `<main>` gives up its facing border to it',
    !/\bborder-l\b/.test(app));
  checkTrue('...while drawing the three outside edges of the cluster',
    app.includes('border-t border-r border-b border-border'));

  // The radius is legal only while the gutter holds these cards off the
  // window: the shell's rule is that nothing meeting the window's own edge
  // draws a corner of its own. Lose the gutter and the radius goes in the same
  // commit, which is what this pairing exists to force.
  checkTrue('the cluster band insets the cards from the window',
    app.includes('bg-secondary pl-1 pr-1 pb-1'));
  checkTrue('...and the outer card carries the matching radius',
    app.includes('rounded-r-lg'));

  const TARGET = 44;        // w-11
  const GAP = 2;            // gap-0.5
  const DIVIDER = 6 + 1 + 6; // my-1.5 + h-px
  const group = (items: number): number => items * TARGET + Math.max(0, items - 1) * GAP;

  // **Three groups, not four.** The widgets group and the 20px collapse header
  // above it went with the dock; the map became a VIEW, so it is inside
  // `views` below rather than a fourth block.
  //
  // The capture group is three icons because **Find packet is deleted**. Its
  // replacement - going to a frame by number - is a control inside the Frame
  // Detail view rather than a rail button, so the views group grew by one in
  // the same change. Both deltas are 46px and they cancel, which is why the
  // total below did not move.
  const blocks = [
    ['capture: Start/Stop, adapter, schedule', 4 + group(3)],
    ['divider', DIVIDER],
    [`views: ${ids.length}`, group(ids.length)],
    // The bottom group carries its own divider, so the gap between that line and
    // the first button is the group's gap rather than the divider's margin.
    ['bottom: Export/Import, Settings', DIVIDER + GAP + group(2) + 8],
  ] as const;

  // What the rail actually gets. The title row spans the full window width and
  // the status bar spans it below, so the rail starts BELOW one and stops ABOVE
  // the other - the window minimum is not the rail's budget, and reading it as
  // one is how Settings ends up under the bottom edge.
  //
  // 680 - 32 - 24 - 4 - 2 = **618**. The last two terms are the card: the
  // cluster band holds the rail 4px clear of the status bar (`pb-1`, VS Code's
  // `spacing-size40`), and the rail's own top and bottom borders come out of
  // its height because `border-box` says so. The borders are drawn by the card
  // rather than by the two strips for a reason of the same kind - a `border-b`
  // on the `h-8` title row would leave 31px for caption buttons that are 46x32
  // because Windows' are.
  //
  // The 680 was chosen to return the rail the 640 it
  // had when the title row was `h-10`; the row has since come down to `h-8` -
  // the window buttons are 46x32, Windows' own caption metric, so at 32 they
  // fill it exactly - and the window minimum did not follow it down. That is
  // 8px the rail gained for nothing. The status bar then took 24 of the slack,
  // which is the first time anything has been funded that way rather than by
  // raising the minimum, and the reasoning is on `MIN_WINDOW_HEIGHT` itself.
  //
  // All of which is why the budget is DERIVED here rather than written down:
  // two subtractions that stay right through a change to any of the three.
  const GUTTER = 4;  // the cluster band's `pb-1`, VS Code's `spacing-size40`
  const SEAMS = 2;   // the card's own border-t + border-b, under `border-box`
  const RAIL_BUDGET = MIN_WINDOW_HEIGHT - TITLE_BAR_HEIGHT - STATUS_BAR_HEIGHT
    - GUTTER - SEAMS;

  let total = 0;
  for (const [name, height] of blocks) {
    total += height;
    console.log(`        ${String(height).padStart(4)}  ${name}`);
  }
  console.log(`        ${String(total).padStart(4)}  total, against ${RAIL_BUDGET} of rail\n`);

  // The number the rail's header comment quotes. It said 549 until this script
  // was written, which was the figure for `my-1` dividers and did not count the
  // two groups' padding - so the comment was describing a rail that had already
  // changed. Held here rather than trusted there, and it has earned that twice:
  // deleting the hamburger menu moved Custom Dissectors into the bottom group,
  // and deleting the `counts` widget took the widgets group from six icons to
  // five. This is the line that says what each of those cost.
  //
  // 630 -> 592 -> 516 -> 494, and two different things are happening in that
  // sequence. (494 has since held through a fourth change that moved nothing:
  // Find packet out of the capture group, Frame Detail into the views group.)
  //
  // **The first three steps are deleted widgets**, all at a 36px target. Find
  // packet moving from the bottom group up under the schedule contributed
  // NOTHING: both groups gap the same, so `group(4) - group(3)` and `group(3) -
  // group(2)` are both 38 and they cancel. Moving an icon between two groups is
  // free; only adding or deleting one is not.
  //
  // **The last step is two changes that nearly cancel**, which is why 516 -> 494
  // is only 22px for a great deal of churn. The dock went, taking the last three
  // widget icons and the 20px collapse header (-160); the map came back as a
  // fourth VIEW (+46); and every target grew from 36 to 44 (+8 each over 12
  // icons, +96, less the icons that no longer exist). The rail is shorter AND
  // its icons are a fifth larger, because deleting six icons buys a lot more
  // than enlarging ten costs.
  check('the rail is as tall as it says it is', total, 494);
  // The raw file, not `code()`: the figure lives in the header comment, which is
  // the first thing `code()` throws away. The point of this one is that the
  // prose and the arithmetic cannot part company again.
  checkTrue('...and the comment in the rail says so',
    readFileSync('src/components/common/ActivityRail.tsx', 'utf8').includes(`**${total}px**`));

  // The thing that actually matters. The bottom group is pinned with `mt-auto`,
  // so an overflow does not scroll - it pushes Settings off the bottom edge.
  checkTrue('it fits the smallest window the app allows', total <= RAIL_BUDGET);

  // Reported rather than asserted, and that is deliberate. "There is room for one
  // more" was a check here until the hamburger menu was deleted and Custom
  // Dissectors took the last slot - at which point it failed, and it was the
  // CHECK that was wrong: a full rail is a fact to know, not a defect. The
  // invariant is the line above, that it fits. This is the number that tells the
  // next session what an icon costs before they add one.
  const slack = RAIL_BUDGET - total;
  const roomFor = Math.floor(slack / (TARGET + GAP));
  console.log(`        ${slack}px of slack - room for ${roomFor} more `
    + `${roomFor === 1 ? 'icon' : 'icons'} before a group must scroll`);
  if (roomFor === 0) {
    // **The views group is the one that scrolls**, and naming it is the point
    // of this line. It used to say "the widgets group", which went with the
    // dock. Capture has to stay reachable - it is how a capture starts - and the
    // bottom group is pinned with `mt-auto`, so an overflow there does not
    // scroll anything, it pushes Settings off the bottom edge.
    console.log('        the rail is FULL: anything more needs Settings, or the '
      + 'views group has to start scrolling');
  }
  console.log();
}

console.log(failures === 0
  ? '\nAll view checks passed.'
  : `\n${failures} view check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
