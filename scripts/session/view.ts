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
import { existsSync, readFileSync } from 'node:fs';
import {
  APP_VIEWS, backTargetFor, isAppView, normalizeViewPrefs, restoredView, viewLabel,
  viewStore, VIEW_DEFAULTS, type AppView,
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

  // **There is no filter row, and this is the fourth form of a rule that had
  // three.** It is worth reading as a sequence, because each form was right
  // about the views it could see and wrong about the ones it could not:
  //
  //  1. "only Network hides the filter row" - Network described the machine, so
  //     a display filter there was a control with nothing in view to act on.
  //  2. "no view hides the filter row" - written the day Network stopped being a
  //     view, on the argument that every remaining view IS the capture.
  //  3. "the row is rendered by NAMING Packets" - because (2) was an EXCLUSION
  //     rule, so every view added afterwards inherited the row without anybody
  //     deciding it should. Four did, and all four fail (1)'s own test.
  //  4. this one. All three argued about where to PUT a row, and none asked why
  //     a filter had to live somewhere a view could hide it. It does not act on
  //     what is in view - `captureScan` answers it over the whole capture on
  //     disk - so it belongs to the app. It is in the title row, and the
  //     objection that drove (1) through (3) is answered the other way round:
  //     **applying a filter goes to Packets.** A control that takes you to its
  //     subject is not a control with nothing to act on.
  //
  // Both halves are asserted because both are silent when broken: a filter that
  // stops navigating leaves somebody in Statistics wondering why nothing
  // happened, and a filter row growing back in the workspace is the 44px strip
  // returning with the same argument that deleted it.
  checkTrue('the filter field is in the title row, not in a row of its own',
    !app.includes('<FilterRow') && app.includes('<FilterBar'));
  checkTrue('...passed to the chrome as its centre slot', /center=\{\s*<FilterBar/.test(app));
  checkTrue('...and applying one goes to look at what it selected',
    /applyFilter[\s\S]{0,400}setView\('packets'\)/.test(app));

  // Clearing must NOT navigate: the empty filter selects the whole capture,
  // which is what every view already shows, so a jump would land nowhere.
  // `[^}]*` is what does the work: it cannot cross out of the guarded
  // statement, so this matches only a `setView('packets')` that is INSIDE the
  // non-empty test. Written that way rather than as the exact one-liner it used
  // to be, because the guard grew a second statement - closing Settings - and a
  // check pinned to the punctuation would have failed on a change that kept
  // every word of what it is here to prove.
  checkTrue('...but clearing it does not',
    /expression\.trim\(\) !== ''\)[^}]*setView\('packets'\)/.test(app));

  // **The presets chevron is a toggle, and the distinction is the whole reason
  // it exists.** A chevron stood at the field's right edge once and was deleted
  // for being a second way to OPEN a list the field's whole width already
  // opened. What the field cannot do is close one - the only ways out were
  // Escape and a click elsewhere, both of which you have to know about - so a
  // control that puts the list away is a new job rather than that one returning.
  // Asserted as the shape of the handler, because an `onMouseDown` that only
  // ever set it open would pass any check that merely looked for a chevron.
  {
    const bar = code('src/components/common/FilterBar.tsx');
    checkTrue('the presets chevron closes as well as opens',
      /presetsVisible \? null : 'chevron'/.test(bar));
    // It tracks what is ON SCREEN rather than the flag: with completions up the
    // flag is true while the presets are not showing, and a chevron reading
    // "close" there would close something nobody can see.
    checkTrue('...and it reads the visible list, not the flag',
      bar.includes("const presetsVisible = showPresetsDropdown && !showSuggestions"));
  }

  // The banner went with the row: it named the agent fault above the packet
  // list while the status bar names it below, and one fault wants one place.
  // Checked as the FILE being gone rather than as the markup being absent,
  // because a banner is a div and a div is easy to rebuild somewhere else.
  checkTrue('the agent fault is reported once, in the status bar',
    !existsSync('src/components/common/FilterRow.tsx'));

  // The fragile form, forbidden outright. `view !== 'x'` is how (2) was written
  // and is what let four views inherit a control none of them uses.
  const excludes = [...app.matchAll(/view !== '([a-z]+)'/g)].map((m) => m[1]);
  check('no view is guarded by exclusion', [...new Set(excludes)], []);
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

console.log('\n--- Settings is a pane and not a view ---\n');

{
  const app = code('src/App.tsx');

  // **The view list answers one question**: is this a way of looking at the
  // capture? Nothing in Settings changes when a packet arrives - which is the
  // exact test that moved Network OUT of that list and into a tab of this pane.
  // Putting Settings in would reverse that with no new argument, and would hand
  // it a `Ctrl+N` it does not want.
  check('Settings is not in the view list', ids.filter((id) => id.includes('setting')), []);

  // It takes the workspace card all the same, which is what stops it being a
  // modal: no scrim, no fixed positioning, nothing floating over the chrome.
  const pane = code('src/components/common/SettingsPane.tsx');
  checkTrue('the pane is not positioned over the window',
    !pane.includes('fixed inset-0') && !/\bz-\d/.test(pane));
  checkTrue('...and paints no scrim', !/bg-black\//.test(pane));
  // `<main>` is the card and draws the border, the radius and the ground; a
  // second set here would be a card inside a card. Asserted as the root's exact
  // class rather than by grepping for a radius, because the pane's CONTENTS are
  // full of rounded things and always were - it is the shell that must be bare.
  checkTrue('...and draws no card of its own',
    pane.includes('className="h-full min-h-0 flex flex-col bg-background text-foreground"'));
  checkTrue('it is rendered inside the workspace', app.includes("sheet === 'settings' ? ("));

  // **One slot, and it is down to one member.** Network joined Settings here
  // for a while and has since become a side bar PANEL - it sits beside the
  // workspace rather than in it, which is what makes its observed column live
  // while frames arrive, an argument a sheet could not make.
  //
  // `sheet` stays a union all the same. It answers "what is IN the workspace
  // card", and a second full-pane surface would join this list rather than sit
  // beside it; a boolean would invite a second boolean, and the argument for
  // one slot would have to be won again.
  checkTrue('a sheet is one state, not a flag each',
    /const \[sheet, setSheet\] = useState<'settings' \| null>/.test(app));
  checkTrue('...and Network is not one any more', !app.includes("sheet === 'network'"));
  // `ids` is typed `AppView[]`, and `'network'` is not in that union - which is
  // itself half the answer, and is why this is written against `string[]`
  // rather than as a comparison `tsc` would reject as impossible. The type says
  // it cannot be a view; this says nobody put it back in the list either.
  checkTrue('Network is not back in the view list',
    !(ids as string[]).includes('network'));
  checkTrue('...and it is not a Settings tab either',
    !code('src/components/common/SettingsPane.tsx').includes("id: 'network'"));

  // **Three ways out and no fourth.** Every other pane is left by the back step,
  // Escape, or the rail. The X and the Close button were the modal's, and a
  // surface with four doors is one nobody knows how to leave.
  checkTrue('the pane has no close control of its own',
    !pane.includes('onClose') && !pane.includes('>Close<'));
  checkTrue('...the back step closes it rather than leaving the view',
    app.includes('if (sheetOpen) { setSheet(null); return; }'));
  checkTrue('...and the rail toggles it',
    app.includes("(open) => (open === which ? null : which)"));

  // **Choosing a view closes it**, and this shipped broken. The pane renders
  // INSTEAD of the view stack, so `setView` underneath it moved the rail's
  // active marker and nothing else: every rail icon looked dead from inside
  // Settings and the back step was the only way out. A sheet has to be closed
  // by the transition that lands somewhere, because the view underneath is
  // deliberately untouched while it is open - nothing else in the app knows a
  // view is being chosen.
  //
  // Both navigations are checked, because both are reachable with the sheet up:
  // the rail and `Ctrl+1..5` go through `handleViewChange`, and the filter field
  // is in the title row, which the sheet does not cover.
  checkTrue('...and choosing a view closes it',
    /handleViewChange = useCallback[\s\S]{0,1600}setSheet\(null\)/.test(app));
  checkTrue('...as does applying a filter, which navigates',
    /expression\.trim\(\) !== ''\)[^}]*setSheet\(null\)/.test(app));

  // The rail says what is on screen and Settings is on screen, so it carries
  // the same marker a view does rather than the outline a toggle gets.
  const railSrc = code('src/components/common/ActivityRail.tsx');
  checkTrue('the rail marks Settings the way it marks a view',
    railSrc.includes("railButton(settingsOpen, 'view')"));
  // Every button in this strip that puts a surface on screen takes the fill,
  // and the three that open a side bar panel compare against the PANEL rather
  // than each holding a boolean of its own - one column shows one of them, so
  // four booleans would make "two lit at once" representable.
  check('...and every side bar button is marked the same way',
    ['interfaces', 'schedule', 'transfer', 'network']
      .filter((p) => !railSrc.includes(`railButton(sideBarPanel === '${p}', 'view')`)),
    []);
  // The strip has shipped two identical glyphs once already - the brand mark
  // opened as an `EthernetPort`, the adapter button's own icon, 42px under it.
  // Network is the adapter's neighbour in meaning and must not be in picture.
  checkTrue('...with a glyph the adapter button does not already use',
    railSrc.includes('<Network className={GLYPH} />')
    && !/<EthernetPort className=\{GLYPH\}/.test(railSrc));
}

console.log('\n--- the back step, and what is a root ---\n');

{
  // **The views are a drill-down, not a flat set**, and the back control is the
  // only thing that says so. `Packets` is the capture, `Frame Detail` is one
  // frame of it, `Follow Stream` is one conversation that frame belongs to -
  // each step down is taken from the surface above it, so each has a place to
  // come back to and it is not always `Packets`.
  check('the chain is stream -> detail -> packets',
    [backTargetFor('stream'), backTargetFor('detail'), backTargetFor('packets')],
    ['detail', 'packets', null]);

  // Statistics and the map are roots deliberately: nothing drills into them and
  // they are reached from the rail rather than from another view, so a back
  // step would have to invent a destination.
  check('the two whole-capture views are roots',
    [backTargetFor('statistics'), backTargetFor('geo')], [null, null]);

  // The property rather than the table: following the chain from any view has
  // to terminate, and terminate somewhere that is itself a root.
  for (const id of ids) {
    let at: AppView | null = id;
    const seen: AppView[] = [];
    while (at !== null && seen.length <= ids.length) { seen.push(at); at = backTargetFor(at); }
    checkTrue(`${id} reaches a root without cycling`,
      seen.length <= ids.length && backTargetFor(seen[seen.length - 1]) === null);
  }

  // The label comes from the same list the rail and the shortcuts read, so the
  // button cannot call a view something its tooltip does not.
  check('the back control names the view the rail does',
    viewLabel('detail'), APP_VIEWS.find((v) => v.id === 'detail')?.label);

  const app = code('src/App.tsx');

  // **Escape is a different key and must stay one hop.** It is the exit - any
  // view to Packets - where the back control is one step. Conflating them would
  // make the stream's two answers look like a bug.
  checkTrue('Escape still goes straight to packets',
    app.includes("setView('packets')"));

  // The pane's own way out is gone, and this is what stops it coming back: a
  // "Back to frame N" in one view's footer is a way out that exists there and
  // nowhere else.
  const stream = code('src/components/stream-follower/StreamFollowerPane.tsx');
  checkTrue('Follow Stream has no back control of its own',
    !/Back to/i.test(stream) && !stream.includes('onReturnToPackets'));

  // Leaving a stream lands on the frame it was followed from, by BOTH ways out.
  // That behaviour belonged to the deleted button; it belongs to leaving.
  const restores = app.split('goToFrame(streamOrigin)').length - 1;
  check('both ways out of a stream restore its origin frame', restores, 2);
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
  classIs('the glyph inside it', "const GLYPH = 'w-5 h-5'");
  classIs('the gap inside a group', 'gap-0.5');
  classIs('the divider', 'my-1.5 h-px w-7');
  classIs('the capture group\'s top padding', '${GROUP} pt-1');
  classIs('the bottom group\'s padding', '${GROUP} mt-auto pb-2');
  classIs('the rail\'s own width', 'w-11 shrink-0');
  // The rail starts at the top now: the 40px cell that held the brand mark went
  // with the mark, which is in the title row. An `h-10` cell coming back here
  // would be 40px of rail height spent on nothing, and there is not 40px spare.
  checkTrue('there is no top cell', !rail.includes('h-10 w-full shrink-0'));
  // And with it went the rail's only drag region. The title row is where a
  // window is grabbed; a rail that claimed part of the drag would be a strip of
  // buttons that move the window instead of being pressed.
  checkTrue('the rail is entirely no-drag', !rail.includes('app-drag'));

  // **Two cards, each with its own complete outline, and a gap between them.**
  // VS Code's `.nosidebar` case (`floatingPanels.css`): a rail with nothing to
  // connect to closes up as a standalone panel with every corner rounded. The
  // three facts below are one arrangement and each breaks the other two if it
  // moves alone.
  // **The rail draws all four borders, always, and the radius is the only thing
  // that varies.** Both of VS Code's arrangements are live: `.nosidebar` is
  // every corner rounded, and a side bar against this edge squares the corners
  // it covers so the two read as one surface. The border is never conditional,
  // because `w-11` under `border-box` is 42px of interior between two 1px
  // borders - an even interior for a 36px target - and handing the facing
  // border to the neighbour makes it 43 and puts the icon column on a half
  // pixel. `scripts/session/side-bar.ts` holds the other half of that seam.
  classIs('the rail draws all four of its own borders', 'border border-border');
  checkTrue('...and gives none of them away', !/border-[lrtb]-0/.test(rail));
  classIs('...keeping the corners that face the gutter', 'rounded-l-lg');
  checkTrue('...and squaring only the corner an open side bar covers',
    /sideBarOpen \? '' : 'rounded-r-lg'/.test(rail));

  // The border belongs to the rail whichever arrangement is in force, and the
  // reason is arithmetic: `w-11` under `border-box` leaves 42px of interior
  // between two 1px borders, which centres a 36px target on whole pixels. Hand
  // that border to a neighbour and the interior is 43.
  const app = code('src/App.tsx');
  checkTrue('...and so is <main>, with all four of its own edges',
    app.includes('border border-border rounded-lg'));

  // **The 4px between the workspace and whatever is to its left is ONE number**,
  // and which element supplies it depends on whether the side bar is open:
  // `<main>`'s own `ml-1` when nothing is beside it, the sash when something is.
  // VS Code's convention either way - the gap belongs to the element on the
  // right, or to the sash standing in that element's place, never to two
  // margins that have to agree.
  checkTrue('the workspace supplies the gap when nothing is beside it',
    /\$\{sideBarOpen \? '' : 'ml-1'\} flex-1/.test(app));
  checkTrue('...and the sash is that same 4px when something is',
    /className="w-1 shrink-0[\s\S]{0,200}cursor-col-resize/.test(app));

  // The radius is legal only while the gutter holds these cards off the
  // window: the shell's rule is that nothing meeting the window's own edge
  // draws a corner of its own. Lose the gutter and the radius goes in the same
  // commit, which is what this pairing exists to force.
  checkTrue('the cluster band insets the cards from the window',
    app.includes('bg-secondary pl-1 pr-1 pb-1'));

  // **The brand mark rides the rail's axis, and the axis is not half the rail's
  // width.** The card is inset by the band's gutter, so the icon column is
  // centred at `gutter + width / 2` - and the mark's block in the title row has
  // to span the same range or it sits a gutter's worth to the left of the icons
  // it crowns. That went wrong for exactly one commit, when the gutter was
  // added and the title row was not looked at, which is why both halves are
  // read out of the source here rather than trusted to agree.
  // `className={\`` as well as `className="`: the rail's class string became a
  // template literal when the radius grew a condition, and this regex is the
  // reason the literal PREFIX had to survive that change character for
  // character. A check that reads a width out of a class string is one edit
  // away from silently finding nothing.
  const railWidth = /className=[{`"]*`?w-(\d+) shrink-0 flex flex-col/.exec(rail)?.[1];
  const markBlock = /className="ml-(\d+) w-(\d+) shrink-0 flex items-center justify-center"/
    .exec(code('src/components/common/TitleRow.tsx'));
  check('the mark block is the rail\'s width', markBlock?.[2], railWidth);
  // `pl-1` on the band and `ml-1` on the block: the same step on Tailwind's
  // scale, which is what makes the two spans identical rather than merely close.
  check('...offset by the same gutter the band applies',
    [markBlock?.[1], /bg-secondary pl-(\d+)/.exec(app)?.[1]],
    ['1', '1']);

  const TARGET = 36;        // w-9
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
    ['capture: Start/Stop, adapter, schedule, Export/Import, Network', 4 + group(5)],
    ['divider', DIVIDER],
    [`views: ${ids.length}`, group(ids.length)],
    // The bottom group carries its own divider, so the gap between that line and
    // the first button is the group's gap rather than the divider's margin.
    ['bottom: Settings', DIVIDER + GAP + group(1) + 8],
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
  // 630 -> 592 -> 516 -> 494 -> 414 -> 452, and four different things are
  // happening in that sequence. (494 held through a change that moved nothing:
  // Find packet out of the capture group, Frame Detail into the views group.)
  //
  // **The first three steps are deleted widgets**, all at a 36px target. Find
  // packet moving from the bottom group up under the schedule contributed
  // NOTHING: both groups gap the same, so `group(4) - group(3)` and `group(3) -
  // group(2)` are both 38 and they cancel. Moving an icon between two groups is
  // free; only adding or deleting one is not.
  //
  // **516 -> 494 is two changes that nearly cancel**, which is why a great deal
  // of churn moved 22px. The dock went, taking the last three widget icons and
  // the 20px collapse header (-160); the map came back as a fourth VIEW (+46);
  // and every target grew from 36 to 44 (+8 each over 12 icons, +96, less the
  // icons that no longer exist).
  //
  // **494 -> 414 is the target going back to 36**, which is the same 8px an
  // icon read the other way - the rail was narrowed to 44px and a 44px target
  // does not fit inside it. Nothing was deleted and nothing moved; this step is
  // purely the size of the button, which is why it is the cleanest number in
  // the sequence: exactly 8 times the ten icons.
  //
  // **414 -> 452 is one ADDED icon and nothing else.** Export/Import moved from
  // the bottom group up under the schedule and Network took the slot it left -
  // the move is free, because both groups gap the same and `group(4) - group(3)`
  // equals `group(3) - group(2)`. What is not free is the eleventh icon: 36 plus
  // its gap, which is the 38 in this step. That is the rule to carry forward -
  // moving an icon between groups costs nothing, adding one costs 38.
  //
  // **452 -> 452 is that rule stated a second time**, which is why the sequence
  // ends on a repeat rather than a new number. Network went back up into the
  // capture group under Export/Import, leaving Settings alone at the bottom:
  // `group(5) - group(4)` is 38 and `group(2) - group(1)` is 38, so the two
  // deltas cancel exactly as they did when Export/Import made the same trip in
  // the other direction. A rule derived once is a coincidence; the same
  // arithmetic twice, in opposite directions, is the rule.
  check('the rail is as tall as it says it is', total, 452);
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
