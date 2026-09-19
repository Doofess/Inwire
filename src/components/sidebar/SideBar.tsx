import React from 'react';
import { PaneHeader } from '../common/PaneHeader';
import type { SideBarPanel } from '../../services/sideBarPrefs';

/**
 * The column between the activity rail and the workspace card.
 *
 * VS Code's primary side bar, ported the same way the card arrangement itself
 * was - read `src/vs/workbench/browser/media/floatingPanels.css` in
 * `microsoft/vscode`, `.part.sidebar.left` beside `.part.activitybar.left`,
 * before changing any of the geometry below.
 *
 * ## The seam, which is the whole of the geometry
 *
 * **The rail and an open panel read as ONE surface.** That means exactly one of
 * them draws the edge between them, and it is the rail - so this card carries
 * `border-l-0`, drops its left corners, and takes no margin at all. The two
 * failure modes are both visible and neither throws: both drawing it is a 2px
 * double line, neither drawing it is no line and two grounds running together.
 *
 * **Why the rail is the one that draws it** is arithmetic rather than
 * preference, and this repo had already reached VS Code's answer independently.
 * `w-11` under `border-box` is 42px of interior between two 1px borders, which
 * centres a 36px target on whole pixels; hand that facing border over here -
 * the obvious way to make one seam out of two edges - and the rail's interior
 * is 43 and every icon in the strip lands on a half pixel. `floatingPanels.css`
 * says the same thing in its own words: the rail has to draw it "otherwise its
 * visible interior would run past its transparent edge to the side bar's
 * border, leaving an odd number of pixels around the icon column and pushing
 * the items 1px off-center."
 *
 * `border border-l-0` rather than three explicit sides, because the shorthand
 * sets all four and the give-up has to be visible in the class string. It is
 * also what `<main>` used during the revision when it met the rail flush.
 *
 * ## The ground is `--card`, and that is what keeps the seam visible
 *
 * The rail is chrome (`--secondary`); this is a titled content surface, which
 * is what `PaneHeader` is already `bg-card` for. The two grounds differing is
 * what makes the single hairline read in Night at all - the same 13/255
 * argument that moved the chrome off `--card` in the first place. A
 * `bg-secondary` panel would merge into the rail and there would be nothing for
 * the seam to separate.
 *
 * ## One panel is mounted and the rest do not exist
 *
 * Not hidden - mounted or absent. The one hidden-rather-than-unmounted surface
 * in this app is the packet list, and it earns that with a virtualised scroll
 * offset that would have to be measured and restored by hand. Nothing here has
 * that property, and one of these panels holds a live agent subscription whose
 * whole correctness rests on being torn down when it stops being looked at.
 *
 * ## It is not in the Escape chain
 *
 * Deliberately, and the argument is `viewPrefs.ts`'s: a modal is a detour, a
 * pane is a place. The Escape chain is a chain of detours. This is persisted,
 * which is this repo's operational definition of a place, so a key that closed
 * it would be a key that silently rewrites a stored preference. It is toggled
 * by the rail button that opened it, and by `Ctrl+B` - which is that same door's
 * shortcut, not a second door.
 */
export interface SideBarProps {
  panel: SideBarPanel;
  /**
   * The panel itself, built by `App`.
   *
   * A slot rather than the panels' own props, for the reason the title row
   * takes the filter as a slot: this component decides what the COLUMN is -
   * the seam, the header, the one scroller - and has no business knowing what
   * an adapter or an export is. It also keeps the props of four unrelated
   * surfaces from collecting here, which is how a shell becomes a second copy
   * of `App`.
   */
  children: React.ReactNode;
  /** The far-right slot of the header, for whatever actions the panel has. */
  actions?: React.ReactNode;
  /** A live figure the panel wants in the header, in `--primary`. */
  detail?: React.ReactNode;
}

/**
 * What each panel calls itself, as a TOTAL record.
 *
 * Total so that a fifth panel cannot be added without deciding what the header
 * says - the `agentStatusLabel` lesson, where a `Partial` plus a `??` fallback
 * turned a missing entry into a confident wrong answer that shipped.
 */
export const PANEL_TITLES: Record<SideBarPanel, string> = {
  interfaces: 'Interfaces',
  schedule: 'Schedule',
  transfer: 'Export / Import',
  network: 'Network',
};

export const SideBar: React.FC<SideBarProps> = ({ panel, children, actions, detail }) => (
  <div
    className="w-[var(--side-bar-width)] shrink-0 flex flex-col min-w-0 overflow-hidden
      border border-l-0 border-border rounded-r-lg bg-card text-card-foreground"
    aria-label={PANEL_TITLES[panel]}
  >
    <PaneHeader title={PANEL_TITLES[panel]} detail={detail}>{actions}</PaneHeader>
    {/* One scroll container for every panel, so no panel manages its own
        overflow and they cannot disagree about where the scrollbar is. */}
    <div className="flex-1 min-h-0 overflow-y-auto custom-scrollbar">{children}</div>
  </div>
);
