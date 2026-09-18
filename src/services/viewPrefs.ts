import { createPreferenceStore } from './preferenceStore';

/**
 * Which of the five surfaces fills the window.
 *
 * ## Why this one IS a preference, when "which panel was open" is not
 *
 * The opposite rule used to be stated a few surfaces ago, by a right-hand
 * dashboard aside that is long since deleted - "'which panel did I have open'
 * is not a setting" - and it was right for what it described: a popover over a
 * column, opened to glance at something and closed again.
 *
 * This is not that. Statistics and Follow Stream used to be modals, and a modal
 * is a detour: you open it, read it, dismiss it, and you are back where you
 * were. As panes they are places, and the question "where was I" now has an
 * answer worth keeping - an analyst who closes the app while reading the
 * protocol hierarchy is not asking to be returned to the packet list. That is
 * the same argument the pane sizes in `inwire.layout` already win on.
 *
 * ## Network was here and is not
 *
 * It was the third view, on Ctrl+3, and it failed the test this list applies:
 * **a view is a way of looking at the capture.** Network describes the machine -
 * its adapters, its DNS, its public identity - and nothing in it changes when a
 * packet arrives. The tell was the filter row, which at the time had to be
 * hidden above Network and nowhere else, because a display filter there was a
 * control with nothing in view to act on. It is a Settings tab now, beside
 * Driver Info, which is the other read-only report about this machine.
 *
 * That tell has since been taken further and no longer singles anything out:
 * the filter row belongs to Packets outright (`view === 'packets'` in
 * `App.tsx`), so it is hidden above Statistics, Frame Detail, the map and
 * Follow Stream too. `scripts/session/view.ts` carries the rule and the two
 * forms it superseded.
 *
 * `Ctrl+3` moved to Follow Stream with it. A stored `'network'` is not a view
 * any more, and `normalizeViewPrefs` clamps it to Packets rather than rejecting
 * the key - which is the whole reason that normaliser clamps.
 *
 * ## Frame Detail was a modal and is a view
 *
 * It passes the test this list applies - it is a way of looking at the capture,
 * and what it looks at is one of the frames in the buffer - and it failed the
 * test for a modal for the same reason Statistics and Follow Stream did before
 * it: a modal is a detour, and reading a frame's tree against the list, the map
 * and the conversation it belongs to is not a detour, it is the work.
 *
 * Second in the list, so `Ctrl+2` opens it. The group reads in the order it is
 * used and the detail view is what the packet list is FOR, so it belongs beside
 * it; Statistics, the map and Follow Stream each moved a key to make room,
 * which is the one standing cost of having the order BE the numbering.
 *
 * **It is restorable, and the go-to-packet box is what bought that.** With
 * nothing selected the view shows the frame-number box and the capture's range,
 * so it is its own way in and has nothing to be handed. That is exactly the
 * property Follow Stream lacks, and the reason the two are treated differently
 * a few lines below.
 *
 * ## Why `stream` can be stored and cannot be restored
 *
 * Follow Stream needs a stream, and nothing about one survives a restart - the
 * target is a conversation in a buffer that is being rebuilt. So `stream` is a
 * legal stored value and `restoredView` refuses to hand it back, falling to
 * `packets`. Storing it anyway rather than rewriting it on the way out keeps the
 * write path honest: what was on screen is what gets recorded, and the decision
 * about what is resumable is made in one place, on the way in.
 */
export type AppView = 'packets' | 'detail' | 'statistics' | 'geo' | 'stream';

export interface AppViewSpec {
  readonly id: AppView;
  readonly label: string;
  /** Shown in the rail's tooltip, so the shortcut is discoverable from it. */
  readonly shortcut: string;
}

/**
 * The rail's view group, in order.
 *
 * The order is the shortcut: `Ctrl+1` is the first entry and so on, so this list
 * and `useKeyboardNavigation` cannot disagree about which key opens what.
 * Digits were entirely unbound before this, which is why they were available.
 */
/**
 * Where a step BACK from each view lands, or null at the root.
 *
 * The views are not a flat set: `Packets` is the capture, `Frame Detail` is one
 * frame of it, and `Follow Stream` is one conversation that frame belongs to.
 * That is a drill-down, and each step down is taken from the surface above it -
 * a frame is chosen in the list, a stream is followed from a frame - so there
 * is a place to come back to and it is not always `Packets`.
 *
 * `Statistics` and the `Routing Map` are deliberately roots. Nothing drills
 * into them and they are not reached from another view; they are other ways of
 * looking at the whole capture, chosen from the rail. A back step there would
 * have to invent a destination.
 *
 * **Escape is a different key and keeps its own rule.** It returns ANY
 * non-Packets view to Packets, in one hop - it is the exit. This is the step.
 * A reader who conflates them will wonder why `stream` has two answers.
 *
 * Total rather than `Partial`, so a new view cannot be added without deciding
 * whether it is a root. That is not style: the same file's agent labels shipped
 * a `Partial` record whose missing key rendered as a confident wrong answer.
 */
const VIEW_BACK: Record<AppView, AppView | null> = {
  packets: null,
  detail: 'packets',
  statistics: null,
  geo: null,
  stream: 'detail',
};

/** The view a back step lands on, or null when there is nowhere to go. */
export function backTargetFor(view: AppView): AppView | null {
  return VIEW_BACK[view];
}

/**
 * A view's name, from the same list the rail and the shortcuts read.
 *
 * So a control that names a view - the back button's "Back to Frame Detail" -
 * cannot call it something the rail's tooltip does not.
 */
export function viewLabel(view: AppView): string {
  return APP_VIEWS.find((v) => v.id === view)?.label ?? view;
}

export const APP_VIEWS: readonly AppViewSpec[] = [
  { id: 'packets', label: 'Packets', shortcut: 'Ctrl+1' },
  // Directly after the list, because it is the list's own second half: a row
  // tells you a frame exists and this is where the frame is read. It was a
  // modal opened from a double-click, which meant the one surface that shows a
  // frame in full could only be reached from the one surface that shows frames
  // in summary - and was dismissed rather than left.
  { id: 'detail', label: 'Frame Detail', shortcut: 'Ctrl+2' },
  { id: 'statistics', label: 'Statistics', shortcut: 'Ctrl+3' },
  // The map was a dock widget with a modal for its full size. It is a view
  // because it passes the test the view list applies and Network failed: it is a
  // way of looking at THE CAPTURE - every arc on it is a conversation in the
  // buffer, and it changes when a packet arrives. Network described the machine
  // and became a Settings tab for exactly that reason.
  //
  // Ahead of Follow Stream rather than after it, so `Ctrl+4` lands on the view
  // that is always available: Follow Stream needs a target and is disabled
  // without one, and a shortcut whose key does nothing most of the time is a
  // shortcut nobody keeps.
  // **The label is `Routing Map`, the id is still `geo`.** The id is not
  // user-visible and it is what `inwire.view` stores, so renaming it would land
  // every profile currently on this view back on Packets - `normalizeViewPrefs`
  // clamps an unknown id rather than keeping it. The name changed because
  // "geo map" describes the projection and "routing map" describes what is
  // drawn on it: arcs between the endpoints of conversations in the buffer.
  { id: 'geo', label: 'Routing Map', shortcut: 'Ctrl+4' },
  { id: 'stream', label: 'Follow Stream', shortcut: 'Ctrl+5' },
];

const VIEW_IDS: readonly string[] = APP_VIEWS.map((v) => v.id);

export function isAppView(value: unknown): value is AppView {
  return typeof value === 'string' && VIEW_IDS.includes(value);
}

export interface ViewPrefs {
  view: AppView;
}

export const VIEW_DEFAULTS: ViewPrefs = { view: 'packets' };

export function normalizeViewPrefs(raw: unknown): ViewPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const value = (raw as Record<string, unknown>).view;
  // Clamped rather than rejected, the house rule: a stored view from a build
  // that had a surface this one removed lands on Packets rather than discarding
  // the key and whatever else ends up in it later. `'network'` is that case
  // today, and every profile that had it open is taking this path right now.
  return { view: isAppView(value) ? value : VIEW_DEFAULTS.view };
}

export const viewStore = createPreferenceStore('inwire.view', normalizeViewPrefs, VIEW_DEFAULTS);

/**
 * The view a fresh window should open on, given what was stored.
 *
 * Separate from the store's normaliser because the two answer different
 * questions. The normaliser says "is this a view" - `stream` is. This says "can
 * this view be resumed", and `stream` cannot: the conversation it pointed at
 * lived in a buffer that no longer exists, so restoring it would show the one
 * state the rail deliberately never shows, an empty Follow Stream.
 */
export function restoredView(stored: AppView): AppView {
  return stored === 'stream' ? 'packets' : stored;
}
