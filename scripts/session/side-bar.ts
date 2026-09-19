/**
 * The side bar: one slot, one seam, and a place rather than a detour.
 *
 *   npx tsx scripts/session/side-bar.ts
 *
 * The side bar is the column between the activity rail and the workspace card,
 * ported from VS Code's primary side bar the same way the card arrangement
 * itself was. Everything here guards a failure that looks like working
 * software:
 *
 *  - **The seam.** The rail and an open panel read as ONE surface, which means
 *    exactly one of them draws the edge between them. Both drawing it is a 2px
 *    double line; neither drawing it is no line at all. Both render.
 *  - **The rail's borders are arithmetic, not decoration.** `w-11` under
 *    `border-box` is 42px of interior between two 1px borders, which centres a
 *    36px target on whole pixels. Hand the facing border to the side bar - the
 *    obvious way to make one seam - and the interior is 43, and every icon in
 *    the strip lands on a half pixel. VS Code's `floatingPanels.css` records the
 *    identical finding, which is why the rail draws the seam in both codebases.
 *  - **Escape must not close it, and navigating must not either.** Both are one
 *    line away from being added by analogy with the Settings sheet, and both
 *    would be wrong for the opposite reason: a sheet renders INSTEAD of the view
 *    stack, so a navigation under it is invisible and it has to close; this
 *    renders BESIDE the view stack, so a navigation under it is fully visible
 *    and closing it would make it the one pane that cannot be kept while
 *    working.
 *  - **Adapter sampling.** The agent samples interface counters only while
 *    something is subscribed. Tie that to anything other than the mount of the
 *    component that draws them and it outlives the panel, measuring the user's
 *    machine with nothing on screen to show for it.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, sep } from 'node:path';
import {
  isSideBarPanel, MAX_SIDE_BAR_PX, MIN_SIDE_BAR_PX, normalizeSideBar, restoredPanel,
  SIDE_BAR_DEFAULTS, SIDE_BAR_PANELS, sideBarStore, usableSideBarWidth,
  type SideBarPanel,
} from '../../src/services/sideBarPrefs';
import { INTERFACE_STORES } from '../../src/services/interfacePrefs';

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

/** Every source file under `src/`, for the checks that are about absence. */
function walkSrc(dir = 'src'): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) return walkSrc(full);
    return /\.tsx?$/.test(entry) ? [full] : [];
  });
}

/** Comments stripped, so a check cannot pass or fail on its own rationale. */
function code(file: string): string {
  return readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/**
 * The normaliser's answer, for a record it is known to accept.
 *
 * It returns `null` for a value that is not a record at all, which is a
 * different answer and is asserted on its own; this is for the clamping cases,
 * where a `null` would be the failure rather than the shape being read.
 */
function accepted(raw: unknown): { panel: SideBarPanel | null; width: number } {
  const value = normalizeSideBar(raw);
  if (value === null) throw new Error(`the normaliser refused ${JSON.stringify(raw)}`);
  return value;
}

console.log('--- the preference is a place, clamped and not reset ---\n');

{
  check('the four panels are the whole list',
    [...SIDE_BAR_PANELS], ['interfaces', 'schedule', 'transfer', 'network']);
  check('no panel appears twice', new Set(SIDE_BAR_PANELS).size, SIDE_BAR_PANELS.length);

  checkTrue('the guard admits every panel', SIDE_BAR_PANELS.every((p) => isSideBarPanel(p)));
  check('...and rejects what is not one',
    [isSideBarPanel('settings'), isSideBarPanel(''), isSideBarPanel(null), isSideBarPanel(3)],
    [false, false, false, false]);

  // Closed, because opening pushes the workspace: a fresh profile must not meet
  // the packet list's horizontal scroll before it has asked for anything.
  check('a fresh profile opens closed', SIDE_BAR_DEFAULTS.panel, null);
  // 288 is `w-72`, the width the adapter dropdown was drawn for, so the first
  // list to move into this column is unchanged rather than re-tuned.
  check('...at the width the adapter menu had', SIDE_BAR_DEFAULTS.width, 288);

  check('a garbage record is refused whole',
    [normalizeSideBar(null), normalizeSideBar('x'), normalizeSideBar(7)], [null, null, null]);

  // **Clamped, never rejected.** A panel id from a build that had a panel this
  // one removed lands on "closed" rather than discarding the key and taking the
  // width with it - the same rule `normalizeViewPrefs` applies to a retired
  // view, and the reason `'network'` did not cost anybody their stored layout.
  check('an unknown panel clamps to closed',
    accepted({ panel: 'dashboard', width: 300 }), { panel: null, width: 300 });
  check('...and a missing one does too',
    accepted({ width: 300 }), { panel: null, width: 300 });

  check('a width below the floor is raised',
    accepted({ panel: 'network', width: 40 }).width, MIN_SIDE_BAR_PX);
  check('...and one past the ceiling is lowered',
    accepted({ panel: 'network', width: 9000 }).width, MAX_SIDE_BAR_PX);
  check('...and a non-number takes the default',
    [accepted({ width: 'wide' }).width, accepted({ width: NaN }).width],
    [SIDE_BAR_DEFAULTS.width, SIDE_BAR_DEFAULTS.width]);
  check('a legal record survives a round trip',
    accepted({ panel: 'schedule', width: 320 }), { panel: 'schedule', width: 320 });

  // The floor is VS Code's `sidebarPart.ts` number, taken rather than invented -
  // and deliberately NOT `MIN_PANE_PX`, which is 220 and defends a hex dump's
  // 16-byte row.
  check('the floor is the one VS Code measured', MIN_SIDE_BAR_PX, 170);

  // **The split clamp**, which is the dock's surviving rule: stored unclamped
  // against the window, clamped at the point of use. Clamped on the way OUT, a
  // width could never grow back when the window did.
  check('a narrow window shrinks an open panel', usableSideBarWidth(500, 700), 220);
  check('...and a wide one gives back the width that was chosen',
    usableSideBarWidth(500, 1400), 500);
  // The floor wins even against a window with no room, because a column that
  // renders at 20px is a column nobody can see to close.
  check('...and the floor survives a window with no room',
    usableSideBarWidth(500, 300), MIN_SIDE_BAR_PX);

  // The identity today. It exists so that a panel which one day cannot be
  // resumed has one place to say so, rather than the rule being discovered late
  // and scattered through `App` the way `stream`'s was.
  check('every panel is restorable, for now',
    SIDE_BAR_PANELS.map((p) => restoredPanel(p)), [...SIDE_BAR_PANELS]);
  check('...and closed stays closed', restoredPanel(null), null);

  // `resetInterfacePreferences` already refuses to undo a dragged pane size, on
  // the rule that a button restoring a LIST of settings must not quietly undo
  // something that is not on the list. A dragged side bar width has exactly
  // that claim, and "which panel was open" is not on the Interface tab at all.
  checkTrue('the Settings reset cannot undo a dragged width',
    !INTERFACE_STORES.some((s) => s.key === sideBarStore.key));
  check('the key is its own', sideBarStore.key, 'inwire.sideBar');
}

console.log('\n--- the seam is drawn once ---\n');

{
  const rail = code('src/components/common/ActivityRail.tsx');
  const bar = code('src/components/sidebar/SideBar.tsx');

  // **Exactly one of the two draws the edge between them.** Both drawing it is
  // a 2px double line; neither drawing it is no line at all and two grounds
  // running together. Both render, so neither is caught by anything but this.
  checkTrue('the rail draws all four of its own borders',
    rail.includes('border border-border'));
  checkTrue('...and gives none of them away', !/border-[lrtb]-0/.test(rail));
  checkTrue('the side bar gives up exactly the one it shares',
    bar.includes('border border-l-0 border-border'));

  // Which of VS Code's two arrangements is in force is one boolean. The left
  // corners are unconditional on both cards - the rail's face the band's
  // gutter, the side bar's face the rail - so the only corners that vary are
  // the ones an open panel covers.
  checkTrue('the rail keeps the corners that face the gutter',
    rail.includes('rounded-l-lg'));
  checkTrue('...and squares only the corner an open panel covers',
    /sideBarOpen \? '' : 'rounded-r-lg'/.test(rail));
  checkTrue('the side bar rounds only the corners it owns',
    bar.includes('rounded-r-lg') && !/rounded-l/.test(bar));

  // The gap is one number and it belongs to the element on the right - or to
  // the sash standing in that element's place. A margin here would be a second
  // number that has to agree with the first.
  checkTrue('...and draws no margin of its own', !/m[lrxy]?-\d/.test(bar));

  // The ground is what makes the seam legible: the rail is chrome and this is a
  // titled content surface, so the two differ by a real step. On `--secondary`
  // the panel would merge into the rail and there would be nothing for the
  // hairline to separate.
  checkTrue('the panel stands on the card ground, not the chrome',
    bar.includes('bg-card') && !bar.includes('bg-secondary'));

  // One panel exists at a time - mounted or absent, never hidden. The one
  // hidden-rather-than-unmounted surface in this app is the packet list, and it
  // earns that with a virtualised scroll offset; nothing here has that, and one
  // of these panels holds a live agent subscription whose correctness rests on
  // being torn down when it stops being looked at.
  checkTrue('the side bar hides nothing, it mounts one panel',
    !/display:\s*'?none/.test(bar));

  // Total, so a fifth panel cannot be added without deciding what the header
  // says. `agentStatusLabel` is why that matters: a `Partial` record with a
  // `??` behind it turned a missing entry into a confident wrong answer that
  // shipped and was read as a fault for weeks.
  checkTrue('every panel has a title, by the type rather than by habit',
    bar.includes('Record<SideBarPanel, string>'));
}

console.log('\n--- a place, not a detour ---\n');

{
  const app = code('src/App.tsx');

  /**
   * The body of one function, by its two ends rather than by a character
   * budget.
   *
   * The first try here was `/Escape[\s\S]{0,600}setSideBar/`, and it failed on
   * correct code: `useKeyboardNavigation`'s options object sits a few lines
   * below the Escape effect and legitimately contains `setSideBar`, for
   * `Ctrl+B`. A window wide enough to cover a handler is wide enough to catch
   * its neighbour, and the neighbour of every one of these is the place the
   * side bar IS allowed to be opened from.
   */
  const bodyOf = (from: string, to: string): string => {
    const start = app.indexOf(from);
    if (start === -1) throw new Error(`no "${from}" in App.tsx`);
    const end = app.indexOf(to, start + from.length);
    if (end === -1) throw new Error(`no "${to}" after "${from}"`);
    return app.slice(start, end);
  };

  // **Escape must not close it**, and the tempting wrong change is one line at
  // the head of the chain by analogy with the Settings sheet. It would also
  // stop Escape returning a view to Packets in one press, which is the second
  // failure and the one nobody would connect to this file.
  checkTrue('Escape does not reach the side bar',
    !bodyOf("if (e.key !== 'Escape') return;", 'window.addEventListener').includes('setSideBar'));
  checkTrue('...and the sheet is still the first thing it closes',
    app.includes('if (sheetOpen) { setSheet(null); return; }'));

  // **Navigating must not close it either**, which is the exact INVERSE of the
  // rule one line above it in `handleViewChange`. A sheet renders INSTEAD of
  // the view stack, so a navigation under it is invisible and it has to close;
  // this renders BESIDE the view stack, so a navigation under it is fully
  // visible, and closing it would make it the one pane that cannot be kept
  // while working - which is the entire point of a side bar.
  checkTrue('choosing a view leaves the side bar alone',
    !bodyOf('const handleViewChange = useCallback(', '}, [').includes('setSideBar'));
  checkTrue('...and so does applying a filter',
    !bodyOf('const applyFilter = useCallback(', '}, [').includes('setSideBar'));

  // The property has to exist in the React style object as well as in the
  // imperative drag path. `--geo-pane-size` is the recorded case of the other
  // way round: written only by a drag, so the pane had no width until somebody
  // dragged something.
  checkTrue('the width is declared on first paint, not only on drag',
    /"--side-bar-width":/.test(app));
  checkTrue('...as well as during one', app.includes("setProperty(\"--side-bar-width\""));
}

console.log('\n--- what may not come back ---\n');

{
  // Checked as the FILE being gone rather than as the markup being absent,
  // which is the `FilterRow.tsx` technique and for its stated reason: a
  // dropdown is a component, and a component is easy to rebuild somewhere else.
  //
  // The rest of this list fills in as each surface moves - the schedule picker,
  // then the export modal.
  checkTrue('CaptureInterfacePicker.tsx is gone, not kept beside its panel',
    !existsSync('src/components/common/CaptureInterfacePicker.tsx'));
  checkTrue('CaptureSchedulePicker.tsx is gone too',
    !existsSync('src/components/common/CaptureSchedulePicker.tsx'));
  checkTrue('...and so is the export modal',
    !existsSync('src/components/export/ExportImportModal.tsx'));

  // **There is one filter field in this app.** The modal embedded a second
  // `FilterBar` because its scrim covered the real one; a panel sits 32px under
  // that field, so the copy is gone and with it the `variant` union whose only
  // other member it was. A union whose second member nothing can reach is dead
  // vocabulary - `agentSilentLabel`'s unreachable branch shipped as a confident
  // wrong answer, and the dock's post-mortem is about a marker shape kept after
  // its subject went.
  const bar = code('src/components/common/FilterBar.tsx');
  checkTrue('the filter bar has no variants left', !bar.includes('FilterBarVariant'));
  // `<FilterBar` rather than the import, because an import can be unused - and
  // the component's own declaration matches it, so its file is excluded. One
  // surface renders this, and that is the whole claim.
  check('...and exactly one surface renders it',
    walkSrc()
      .filter((f) => !f.endsWith(`common${sep}FilterBar.tsx`))
      .filter((f) => code(f).includes('<FilterBar'))
      .map((f) => f.split(sep).join('/')),
    ['src/App.tsx']);

  // The heavy work moved off the render path, which is the same class of defect
  // as the lease countdown: `useHydratedBytes` over the whole buffer was a
  // one-off in a modal and is ten times a second in a panel.
  const transfer = code('src/components/sidebar/TransferPanel.tsx');
  checkTrue('the transfer panel hydrates at press time, not on render',
    !transfer.includes('useHydratedBytes') && transfer.includes('await packetsBytes('));
  checkTrue('...and anonymises there too, not in a memo',
    /const prepare = async[\s\S]{0,900}anonymiseCapture\(/.test(transfer));

  // **The schedule's height cap, which was a state variable.** One `editing`
  // slot decided which of two fields the single shared calendar was showing,
  // and its comment gave the reason outright - "two month grids stacked would
  // make the panel taller than the header it hangs from". That is a sentence
  // about a menu on a 36px button. Two independent disclosures is the shape
  // that says the cap is gone.
  const sched = code('src/components/sidebar/CaptureSchedulePanel.tsx');
  checkTrue('both calendars can be open at once',
    sched.includes('const [startOpen, setStartOpen]')
    && sched.includes('const [stopOpen, setStopOpen]'));

  // The summary was computed only to fill a tooltip. Two readers now, and the
  // check is that one expression feeds both rather than being written twice.
  const app = code('src/App.tsx');
  check('the countdown is computed once, for the tooltip and the header',
    (app.match(/describeSchedule\(/g) ?? []).length, 1);
  // It was also formatted by a `toLocaleString` written out twice - once in
  // the picker, once INLINE at this call site, same four options in the same
  // order. One format defined twice is one format that drifts, and the two
  // copies existed only because the halves of one feature lived in two files.
  //
  // Asserted as "the call site names the function" rather than as "these
  // options appear once in the tree": `pcapParser.ts` formats a timestamp with
  // the same options for a different reason, and a check that cannot tell
  // those apart is a check that fails on unrelated work.
  checkTrue('...and formatted by a named function, not an inline copy',
    /describeSchedule\([^)]*formatStamp[^)]*\)/.test(app)
    && !/describeSchedule\([\s\S]{0,200}toLocaleString/.test(app));

  const panels = readdirSync('src/components/sidebar')
    .filter((f) => f.endsWith('.tsx'))
    .map((f) => `src/components/sidebar/${f}`);
  checkTrue('there are panels to check', panels.length > 0);

  // **The check that stops a future session "fixing" the keyboard by pinning a
  // Radix menu open inside a layout pane.** `DropdownMenuItem` only works
  // inside a live `DropdownMenuContent` - that is where the roving focus, the
  // typeahead and the `data-state` come from - so the answer for a panel of
  // bare buttons is `useRovingFocus`, never a menu told not to close.
  check('no panel reaches for the menu primitive',
    panels.filter((f) => /from '.*dropdown-menu'/.test(code(f))), []);

  // **Sampling is tied to a MOUNT, not to a flag.** The agent samples interface
  // counters only while somebody is subscribed, and the panel that draws them
  // is the only thing that displays them - so an empty dep array and a cleanup
  // make "nothing is measured while nothing is showing it" a fact about the
  // component tree rather than a condition somebody keeps true.
  const adapters = code('src/components/sidebar/CaptureInterfacePanel.tsx');
  checkTrue('the adapter panel subscribes on mount and unsubscribes on unmount',
    /notify\.current\(true\);[\s\S]{0,140}return \(\) => \{ notify\.current\(false\); \};[\s\S]{0,30}\}, \[\]\)/
      .test(adapters));
  // The ref indirection, which is what stops a future dependency on that
  // callback tearing the subscription down thirty times a second during a
  // capture - a write down the pipe each time, with no symptom on screen.
  checkTrue('...through a ref, so a new callback identity cannot resubscribe',
    adapters.includes('const notify = useRef(onSamplingChange)'));

  // **Network's two-column vocabulary is gone.** `CompareHeader` wrote
  // "Configured (OS)" and "Observed (capture)" ONCE per section, and every pair
  // below it inherited meaning from which SIDE of the row it sat on. A column
  // has no sides, so the words moved onto the values - every value, every time,
  // which is also what keeps a pair readable when its heading is scrolled off.
  const rows = code('src/components/network/rows.tsx');
  checkTrue('the compare header is gone with the columns it labelled',
    !rows.includes('CompareHeader')
    && !code('src/components/network/NetworkPane.tsx').includes('CompareHeader'));
  // The tags are short because a 48px gutter is what one can have beside a
  // value that may be an IPv6 address; the full phrases live in the `title`, so
  // the abbreviation is never the only place the meaning exists.
  checkTrue('...and each value names its own side',
    rows.includes('title="Configured on this machine"')
    && rows.includes('title="Observed in this capture"'));
  // Stacked, "which of these is the surprising one" is no longer answerable by
  // position - the right-hand column was the capture - so the observed tag
  // takes the warning hue on a finding.
  checkTrue('...with the observed side marked when the two disagree',
    /warn \? 'text-warning font-semibold'/.test(rows));
  // The `w-40` label column left ~90px for a value in a 288px panel, and this
  // panel's values are IPv6 addresses and multi-entry DNS lists. A truncated
  // address is a wrong address.
  checkTrue('no fixed label column survives the restack', !/w-40/.test(rows));

  // **The one section that reaches the internet is behind a press**, and this
  // is a consent property rather than a layout one. `PublicIdentity` used to be
  // mounted only when its nav item was chosen; deleting the nav and stacking
  // everything would have mounted it on every open - an outbound lookup nobody
  // asked for, in the app whose standing direction is "no outbound connection
  // the user did not ask for". Mounting is what starts the request, so the
  // guard has to be on the MOUNT and not on a CSS class.
  const net = code('src/components/network/NetworkPane.tsx');
  checkTrue('public identity is not mounted until it is asked for',
    /\{showPublic \? \(\s*<PublicIdentity/.test(net));
  // Per mount rather than persisted: consent to make a request is given for a
  // sitting, and a panel that remembered it would reach out on the next launch
  // with nobody watching.
  checkTrue('...and the asking is not remembered across launches',
    net.includes('useState(false)') && !net.includes("'inwire.publicIdentity'"));

  // **A defect the conversion CREATED.** `countdown` read `Date.now()` at
  // render, which was survivable while this was a sheet - a sheet is a detour,
  // you open it and you leave. A panel sits open for hours, and
  // `adapter_config` is only sent when something CHANGES, so nothing forces a
  // re-render and "expires in 42 minutes" quietly becomes false with no tell.
  checkTrue('the lease countdown takes the clock as an argument',
    /function countdown\(seconds: number \| null, now: number\)/.test(net));
  // And the tick exists only while there is a lease to draw, which is the same
  // discipline the adapter panel's sampling follows.
  checkTrue('...ticked only while a lease is on screen',
    /if \(!hasLease\) return;[\s\S]{0,160}setInterval/.test(net));

  // The sqrt-eased width was a SECOND encoding of volume laid over `max`, and
  // the dishonest one - the easing existed so a tenth of the peak would not
  // look like a tenth. It cannot come back, because there is no longer an
  // authoring-time width to derive it from.
  const spark = code('src/components/common/Sparkline.tsx');
  checkTrue('the sparkline takes its width from CSS, not from traffic',
    !/width\?:/.test(spark) && !spark.includes('style={{ width'));
  check('nothing computes a sparkline width any more',
    walkSrc().filter((f) => code(f).includes('SPARKLINE_WIDTH')), []);
}

console.log(
  failures === 0
    ? '\nAll side bar checks passed.'
    : `\n${failures} side bar check(s) FAILED`,
);
process.exit(failures === 0 ? 0 : 1);
