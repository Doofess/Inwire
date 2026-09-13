import { createPreferenceStore } from './preferenceStore';

/**
 * Which of the three surfaces fills the window.
 *
 * ## Why this one IS a preference, when "which panel was open" is not
 *
 * `DashboardAside` states the opposite rule for itself - "'Which panel did I
 * have open' is not a setting" - and that was right for what it described: a
 * popover over a column, opened to glance at something and closed again.
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
 * packet arrives. The tell was the filter row, which had to be hidden above it
 * and nowhere else, because a display filter there was a control with nothing in
 * view to act on. It is a Settings tab now, beside Driver Info, which is the
 * other read-only report about this machine.
 *
 * `Ctrl+3` moved to Follow Stream with it. A stored `'network'` is not a view
 * any more, and `normalizeViewPrefs` clamps it to Packets rather than rejecting
 * the key - which is the whole reason that normaliser clamps.
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
export type AppView = 'packets' | 'statistics' | 'stream';

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
export const APP_VIEWS: readonly AppViewSpec[] = [
  { id: 'packets', label: 'Packets', shortcut: 'Ctrl+1' },
  { id: 'statistics', label: 'Statistics', shortcut: 'Ctrl+2' },
  { id: 'stream', label: 'Follow Stream', shortcut: 'Ctrl+3' },
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
