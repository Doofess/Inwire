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

/*
 * The seam, the deleted popovers and the sampling lifecycle are asserted here
 * too, and land with the code they describe - the column itself, then the two
 * pickers, then the modal. Written up front in the plan and added step by step,
 * so that no check in this file ever passes by describing something that has
 * not been built.
 */

console.log(
  failures === 0
    ? '\nAll side bar checks passed.'
    : `\n${failures} side bar check(s) FAILED`,
);
process.exit(failures === 0 ? 0 : 1);
