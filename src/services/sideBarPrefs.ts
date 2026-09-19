import { createPreferenceStore } from './preferenceStore';

/**
 * The side bar: which panel is open, and how wide it is.
 *
 * The side bar is the column between the activity rail and the workspace card -
 * VS Code's primary side bar, ported the same way the card arrangement itself
 * was (`src/vs/workbench/browser/media/floatingPanels.css`, and read
 * `.part.sidebar.left` beside `.part.activitybar.left` before changing the
 * geometry).
 *
 * ## Why this is persisted at all
 *
 * `viewPrefs.ts` already overturned the rule that "'which panel did I have
 * open' is not a setting", and gave the test that replaced it: **a modal is a
 * detour, a pane is a place.** A panel here is a place - it sits beside the
 * capture rather than over it, nothing dismisses it, and work continues while
 * it is up. So it is remembered, and that is also why **Escape does not close
 * it**: the Escape chain is a chain of detours, and a key that closed this
 * would be a key that silently rewrites a stored preference.
 *
 * ## One key, two fields
 *
 * `normalizeLayout` makes this argument at length and it applies unchanged: a
 * width that arrives in another window without the panel it belongs to is a
 * paint with the wrong column sized. One key is one `storage` event and one
 * atomic apply.
 *
 * ## Not in `INTERFACE_STORES`
 *
 * `resetInterfacePreferences` deliberately preserves `bottomPaneHeight` and
 * `detailsPaneRatio`, on the rule that a button restoring a LIST of settings
 * must not quietly undo something that is not on the list. A width somebody
 * dragged has exactly that claim, and "which panel was open" is not on the
 * Interface tab at all.
 */
export type SideBarPanel = 'interfaces' | 'schedule' | 'transfer' | 'network';

export const SIDE_BAR_PANELS: readonly SideBarPanel[] = [
  'interfaces',
  'schedule',
  'transfer',
  'network',
] as const;

export function isSideBarPanel(value: unknown): value is SideBarPanel {
  return typeof value === 'string' && SIDE_BAR_PANELS.includes(value as SideBarPanel);
}

/**
 * The floor, and it is VS Code's own number.
 *
 * `sidebarPart.ts`: `readonly minimumWidth: number = 170`. Taken rather than
 * invented, because it is the width at which their Explorer - a tree of
 * truncating filenames with a twisty and an icon, which is the same shape as
 * the adapter list here - stops being usable.
 *
 * **Deliberately not `MIN_PANE_PX`.** That constant is 220 and it defends a hex
 * dump's 16-byte row, which is a fact about hexadecimal and has nothing to say
 * about this column.
 */
export const MIN_SIDE_BAR_PX = 170;

/**
 * The ceiling the STORED value is held to, which is not the one a drag obeys.
 *
 * This one only has to stop a hand-edited `localStorage` from opening a column
 * wider than any window this app runs in. The useful limit - leave the packet
 * list enough width to be a packet list - depends on the window and is applied
 * at the point of use, which is the dock's surviving rule: a width is stored
 * unclamped against the window and clamped when it is used, so narrowing the
 * window shrinks an open panel and widening it gives back the width that was
 * chosen. Clamped on the way out, it could never grow back.
 */
export const MAX_SIDE_BAR_PX = 600;

export interface SideBarPrefs {
  /**
   * The panel the column is showing, or LAST showed.
   *
   * **It is not `null` when the column is closed**, and that separation is a
   * bug fix rather than a nicety. It was one field: closing wrote `null`, so
   * the record of which panel you had been using was destroyed by the act of
   * closing it - and `Ctrl+B`, whose whole job is "reopen the last panel",
   * could only ever fall back to its default. The key remembered a panel
   * across a restart and forgot it across a keystroke.
   */
  panel: SideBarPanel;
  /** Whether the column is showing at all. */
  open: boolean;
  /** The column's width in pixels. Dragged, so it changes continuously. */
  width: number;
}

/**
 * Closed, at the width the adapter menu used to be.
 *
 * **288 is `w-72`**, the width `CaptureInterfacePicker`'s dropdown was drawn
 * for, so the list that moved into this column first is unchanged on a fresh
 * profile rather than being re-tuned against a number nobody measured.
 *
 * **Closed rather than open**, because opening pushes the workspace: a fresh
 * install would otherwise meet the packet list's horizontal scroll before it
 * had asked for anything.
 */
export const SIDE_BAR_DEFAULTS: SideBarPrefs = {
  panel: 'interfaces',
  open: false,
  width: 288,
};

export function normalizeSideBar(raw: unknown): SideBarPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    // Clamped rather than rejected, the house rule: a panel id from a build
    // that had a panel this one removed lands on the default rather than
    // discarding the key and taking the width with it.
    panel: isSideBarPanel(v.panel) ? v.panel : SIDE_BAR_DEFAULTS.panel,
    open: typeof v.open === 'boolean' ? v.open : SIDE_BAR_DEFAULTS.open,
    width:
      typeof v.width === 'number' && Number.isFinite(v.width)
        ? Math.max(MIN_SIDE_BAR_PX, Math.min(v.width, MAX_SIDE_BAR_PX))
        : SIDE_BAR_DEFAULTS.width,
  };
}

export const sideBarStore = createPreferenceStore(
  'inwire.sideBar',
  normalizeSideBar,
  SIDE_BAR_DEFAULTS,
);

/**
 * The panel a fresh window should open on, given what was stored.
 *
 * The identity today, and that is the point of having it. `restoredView` exists
 * because `stream` is a view the normaliser accepts and a window cannot resume
 * - the conversation it named lived in a buffer that is being rebuilt - and the
 * cost of discovering that late was the rule being scattered through `App`.
 * All four panels here need nothing handed to them, so nothing is refused; the
 * seam is cut so that a panel which one day does need something has one place
 * to say so.
 */
export function restoredPanel(stored: SideBarPanel): SideBarPanel {
  return stored;
}

/**
 * The width to actually render, given the window.
 *
 * The other half of the split clamp described on `MAX_SIDE_BAR_PX`. `available`
 * is what the band has after the rail, the gutters and the sash; `reserve` is
 * what the workspace keeps.
 *
 * **`MAIN_RESERVE` is the successor to the dock's `LIST_RESERVE`**, and it
 * inherits that constant's post-mortem AND, in the end, its arithmetic. The
 * rule it left behind is "guarantee the identity - the frame number, the time
 * and both addresses - and let Protocol, Length and Info scroll", and the
 * measurement behind it is that the packet list's fixed columns come to ~785px.
 *
 * **It was 480 for four commits, and 480 cannot keep that promise.** At the
 * 1024 minimum the band is 1016, less the rail's 44 leaves 972, so a 480
 * reserve lets the column take 492 and hands the list 480 - which is 300px
 * short of its own identity columns. `docs/verification.md` said the identity
 * survived; it would not have. 780 is the number that makes the rule true, and
 * it still leaves 192px of column at the smallest window this app allows -
 * above VS Code's own 170 floor, so the panel narrows rather than vanishing.
 *
 * That is the split clamp doing exactly what it is for: the stored width is
 * untouched, so widening the window gives back the 288 or the 600 that was
 * chosen.
 */
export const MAIN_RESERVE_PX = 780;

export function usableSideBarWidth(stored: number, available: number): number {
  const ceiling = Math.max(MIN_SIDE_BAR_PX, available - MAIN_RESERVE_PX);
  return Math.max(MIN_SIDE_BAR_PX, Math.min(stored, ceiling));
}
