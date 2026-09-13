import { createPreferenceStore } from './preferenceStore';
import { WIDGET_TYPE_IDS, type WidgetTypeId } from './dashboardPrefs';

/**
 * The dock: which widgets are open, in what order, how wide, and what is pinned.
 *
 * ## Why this is a new key rather than more of `inwire.dashboard`
 *
 * The old key described a **column on the right that could collapse to a rail**:
 * a `mode` of full/icons/hidden, a width that morphed into a 48px strip below
 * 200px, and a per-widget `enabled`. Three of those four facts are about a thing
 * that no longer exists. Keeping them and adding `pinned` beside them would have
 * left every reader having to know which fields still meant something.
 *
 * What `inwire.dashboard` keeps is what is genuinely still true of a widget
 * wherever it is drawn: its custom `title` and its `config`. Those are the
 * widget; this is the furniture.
 *
 * ## Why the active view is NOT in here
 *
 * The plan put `view` in this key. It is in `inwire.view` instead, and the
 * repository's own rule is the reason: `interfacePrefs.ts` says one key per
 * *writer*, and that fields sharing a key should be ones that change each
 * other's meaning. The dock is deliberately view-independent - every widget open
 * in one view is open in all of them - so `view` changes nothing about `width`,
 * `order` or `pinned`, and vice versa. Two independent facts in one key would be
 * two writers racing the same debounce.
 *
 * ## Every type is always present
 *
 * `items` is a permutation of `WIDGET_TYPE_IDS`, exactly once each, with `open`
 * as a flag - not a list of only the open ones. That is what lets a widget you
 * close and reopen come back **where it was** rather than at the bottom of the
 * stack, and it is the shape `normalizeWidgets` already established for the same
 * reason. There is still no third state: the rail's icon is lit when `open` is
 * true and unlit when it is false.
 */
export interface DockItem {
  type: WidgetTypeId;
  /** In the dock. The rail's icon is lit for exactly this. */
  open: boolean;
  /**
   * Held at the top of the stack, above everything unpinned.
   *
   * It deliberately does NOT mean "survives a view change" - nothing is hidden
   * on a view change, because the dock is view-independent.
   *
   * The plan also gave it a second meaning, "kept by close all", and **there is
   * no close-all control**: the rail's widget icons are the only way to close
   * anything, one at a time. So pinning currently buys the top of the stack and
   * immunity from a drag-reorder, and nothing else. Written down because the flag
   * is persisted and a later session adding close-all must honour it rather than
   * discover it.
   */
  pinned: boolean;
}

export interface DockPrefs {
  /** Pixels. Clamped against the window by `clampDockWidth`, not stored clamped. */
  width: number;
  items: DockItem[];
  /**
   * Hidden, leaving only the rail's icons.
   *
   * **What this is not.** `DashboardMode` was three modes - full, icons, hidden
   * - on a right-hand column that morphed into a 48px strip as you dragged it
   * narrower, and Step 6 of the rail work deleted all of it. This is one
   * boolean on a left-hand dock, and the rail it collapses to already exists
   * and is always there. A future session should not read this as the morph
   * coming back.
   *
   * It changes what a widget icon **does**, which is the whole reason it is
   * persisted rather than local: expanded, an icon toggles that widget in the
   * dock; minimized, it opens that widget's overlay. One control, two meanings,
   * and which one is in force has to survive a restart or the first click after
   * every launch is a surprise.
   */
  minimized: boolean;
}

/** The rail's own width, which the dock's arithmetic has to account for. */
export const RAIL_WIDTH = 56;

/**
 * What the packet list is never squeezed below.
 *
 * **640 does not fit every column, and the first version of this comment said it
 * did.** Measured on the running app: No, Dir, Time, Source and Destination take
 * about 785px on their own - Source and Destination are ~280 each, because they
 * are sized for an IPv6 address or a resolved name - so Protocol, Length and Info
 * are off-screen at 640 and the list scrolls horizontally to reach them.
 *
 * It is still the right number, for a reason that is about the window rather than
 * the columns. `MIN_WINDOW_WIDTH` is 1024 and the rail takes 56, so a reserve
 * large enough to keep every column would leave no room for a dock at the
 * smallest supported window at all - the dock simply could not open. Given the
 * choice between "the dock is unavailable at 1024" and "the list scrolls
 * horizontally while the dock is open at 1024", this picks the second: the list
 * already scrolls horizontally by design, and opening the dock is a thing the
 * user did on purpose and can undo with one click.
 *
 * What it does guarantee is that the list keeps its identity - the frame number,
 * the time and both addresses stay visible at every reachable dock width.
 */
export const LIST_RESERVE = 640;

/**
 * The dock's floor, and it is the width at which every widget still renders its
 * real self rather than a lesser one.
 *
 * At 240 with 8px of padding a card is 224px, and all five survive that: two are
 * percentage-width CSS bars, the timeline has its own ResizeObserver and a 320px
 * fallback, the talkers table already truncates host labels at 85px, and the geo
 * map's `aspect-[11/8]` gives a 163px-tall map - small, but legible, and it scales
 * with the dock because that ratio was chosen for a draggable column.
 *
 * So there is no width at which a widget needs a second, compact rendering. That
 * is a feature deliberately **not** built; see the plan.
 */
export const DOCK_MIN_WIDTH = 240;
export const DOCK_MAX_WIDTH = 640;
export const DOCK_DEFAULT_WIDTH = 260;

/** 8, not the old column's 16: that was sized for a 384px column. */
export const DOCK_PADDING = 8;

/**
 * The widest the dock may be, given the window.
 *
 * At the 1024px minimum this is 328, so the dock still has 88px of real travel -
 * there is no degenerate case where min equals max and the resize handle accepts
 * a drag it cannot honour.
 */
export function maxDockWidth(windowWidth: number): number {
  return Math.max(DOCK_MIN_WIDTH, Math.min(DOCK_MAX_WIDTH, windowWidth - RAIL_WIDTH - LIST_RESERVE));
}

/** Clamped rather than rejected, and against the window rather than a constant. */
export function clampDockWidth(value: number, windowWidth: number): number {
  if (!Number.isFinite(value)) return DOCK_DEFAULT_WIDTH;
  return Math.max(DOCK_MIN_WIDTH, Math.min(maxDockWidth(windowWidth), Math.round(value)));
}

/** Nothing open, every type present, registry order. */
export function defaultItems(): DockItem[] {
  return WIDGET_TYPE_IDS.map((type) => ({
    type,
    // Traffic Timeline alone, on a fresh install. An empty dock is
    // undiscoverable for a group whose semantics are novel; all five steals
    // 260px from the packet list before anybody asked. The timeline is the one
    // widget useful continuously while capturing, and its `aspect-[2/1]` makes
    // it the shortest of the five at any width.
    open: type === 'timeseries',
    pinned: false,
  }));
}

export const DOCK_DEFAULTS: DockPrefs = {
  width: DOCK_DEFAULT_WIDTH,
  minimized: false,
  // Built once and never handed out to be edited, the same reason
  // `DASHBOARD_DEFAULTS` does it: this object IS the store's value when nothing
  // is stored, so a getter would hand every reader a new array identity.
  items: defaultItems(),
};

/**
 * Repairs a stored list into a permutation of every type, exactly once.
 *
 * Never rejects. Unknown types are dropped (a build that had a sixth widget),
 * repeats are ignored, and anything missing is appended in registry order - so a
 * widget added to `WIDGET_TYPE_IDS` in a later build appears at the bottom,
 * closed, rather than making the whole key unreadable.
 */
export function normalizeItems(raw: unknown): DockItem[] {
  if (!Array.isArray(raw)) return defaultItems();
  const seen = new Set<WidgetTypeId>();
  const items: DockItem[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'object' || entry === null) continue;
    const { type, open, pinned } = entry as Record<string, unknown>;
    if (typeof type !== 'string') continue;
    if (!(WIDGET_TYPE_IDS as readonly string[]).includes(type)) continue;
    const id = type as WidgetTypeId;
    if (seen.has(id)) continue;
    seen.add(id);
    // Field by field: one unreadable flag must not discard the entry, let alone
    // its siblings. `open` defaults CLOSED for a repaired entry - opening a
    // widget somebody never asked for is the more intrusive way to be wrong.
    items.push({ type: id, open: open === true, pinned: pinned === true });
  }
  for (const type of WIDGET_TYPE_IDS) {
    if (!seen.has(type)) items.push({ type, open: false, pinned: false });
  }
  return items;
}

/**
 * The one-time migration out of `inwire.dashboard`.
 *
 * **A collapsed user's selection is discarded, and that is the decision rather
 * than an oversight.** The old key had three modes. `full` meant "the column is
 * on screen", so `enabled` there is a genuine statement about what the user
 * wanted to see, and it carries across exactly. `icons` and `hidden` meant the
 * column was collapsed or gone - so whatever `enabled` said underneath it, the
 * user had not been looking at any of them, and honouring that list would open up
 * to five widgets into a dock they never asked for on first launch of the new
 * build. They get an empty dock and the tour, which explains the rail.
 *
 * Order carries across in every case: it costs nothing and it is the one part of
 * the old state that is unambiguous.
 */
export function migrateFromDashboard(raw: unknown): DockItem[] | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const { mode, widgets } = raw as Record<string, unknown>;
  if (!Array.isArray(widgets)) return null;
  const columnWasShowing = mode === 'full' || mode === undefined;
  const seen = new Set<WidgetTypeId>();
  const items: DockItem[] = [];
  for (const entry of widgets) {
    if (typeof entry !== 'object' || entry === null) continue;
    const { type, enabled } = entry as Record<string, unknown>;
    if (typeof type !== 'string') continue;
    if (!(WIDGET_TYPE_IDS as readonly string[]).includes(type)) continue;
    const id = type as WidgetTypeId;
    if (seen.has(id)) continue;
    seen.add(id);
    // `enabled !== false` matches the old normaliser: absent meant on.
    items.push({ type: id, open: columnWasShowing && enabled !== false, pinned: false });
  }
  if (items.length === 0) return null;
  for (const type of WIDGET_TYPE_IDS) {
    if (!seen.has(type)) items.push({ type, open: false, pinned: false });
  }
  return items;
}

export function normalizeDockPrefs(raw: unknown): DockPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const value = raw as Record<string, unknown>;
  return {
    // Stored unclamped by the window, deliberately: the window can be any size
    // on the next launch, and a width clamped to yesterday's narrow window would
    // never grow back. `clampDockWidth` is applied at the point of use.
    width: typeof value.width === 'number' && Number.isFinite(value.width)
      ? Math.round(value.width)
      : DOCK_DEFAULT_WIDTH,
    items: normalizeItems(value.items),
    // Defaults to SHOWN for an unreadable value, which is the less surprising
    // way to be wrong: a dock that is there when it should not be is one click
    // from correct, and one that is missing reads as a widget that stopped
    // working.
    minimized: value.minimized === true,
  };
}

const DOCK_KEY = 'inwire.dock';

/**
 * Seeds `inwire.dock` from `inwire.dashboard`, once, before the store reads.
 *
 * The existing migration in `dashboardPrefs` keys on a missing FIELD inside its
 * own key, which a normaliser can see. This one is cross-key - the new key is
 * absent entirely and the old data is under a different name - so a normaliser
 * never gets the chance. It has to happen before `createPreferenceStore` does
 * its module-scope read, which is the line below.
 *
 * Reads and writes storage directly rather than through either store, the same
 * way `applyStoredChrome` does: going through `dashboardStore` would force that
 * module to evaluate for a value this one only needs once, and going through
 * `dockStore` is impossible because it does not exist yet.
 *
 * Silent on failure, in both directions. Blocked or corrupt storage means a
 * fresh dock, which is a worse first launch and not a broken one - and the
 * alternative, throwing at module scope, takes the whole renderer down.
 */
function seedFromDashboard(): void {
  try {
    if (localStorage.getItem(DOCK_KEY) !== null) return;
    const legacy = localStorage.getItem('inwire.dashboard');
    if (legacy === null) return;
    const items = migrateFromDashboard(JSON.parse(legacy));
    if (items === null) return;
    // `minimized` is not migrated from the old `mode`, deliberately. `icons`
    // and `hidden` meant a collapsed column, which sounds like this - but
    // `migrateFromDashboard` already answers them by opening nothing, and
    // carrying the collapse across as well would hide a dock that is already
    // empty. The user would land on a rail whose widget icons all opened
    // overlays, with no sign the dock existed.
    localStorage.setItem(DOCK_KEY, JSON.stringify({
      width: DOCK_DEFAULT_WIDTH, items, minimized: false,
    }));
  } catch {
    // Blocked, absent or corrupt storage. The defaults are a usable dock.
  }
}

seedFromDashboard();

export const dockStore = createPreferenceStore(DOCK_KEY, normalizeDockPrefs, DOCK_DEFAULTS);

/** Pinned first, then stored order. Stable within each group. */
export function dockOrder(items: DockItem[]): DockItem[] {
  const open = items.filter((i) => i.open);
  return [...open.filter((i) => i.pinned), ...open.filter((i) => !i.pinned)];
}

/**
 * Applies a drag-reorder of the **visible** items back onto the stored list.
 *
 * The dock shows `dockOrder(items)` - the open ones, pinned first - and hands
 * back a new sequence of those. Closed items are not in that sequence and must
 * not move: they keep their slots, so a widget closed and reopened still comes
 * back where it was. So the rule is that the new sequence fills the **open
 * slots** of the stored list, in order, and everything else is left alone.
 *
 * Writing the pinned-first sequence into slots that are in stored order is
 * deliberate and is what makes a pinned item immovable: `dockOrder` re-sorts
 * pinned to the front afterwards, so a drag that tried to push one down is
 * undone on the next render. That is the intended behaviour of a pin, not a
 * rounding error.
 *
 * ## Why this is a function here rather than four lines in `App.tsx`
 *
 * It was four lines in `App.tsx`, and they crashed the renderer:
 *
 * ```ts
 * items: dock.items.map((item) => (
 *   item.open ? dock.items.find((i) => i.type === queue.shift())! : item
 * ))
 * ```
 *
 * `queue.shift()` is evaluated **inside `find`'s predicate**, so it ran once per
 * element `find` compared rather than once per open slot. The queue drained in
 * the first couple of comparisons, `shift()` began returning `undefined`,
 * nothing matched, and the non-null assertion let `undefined` into the array -
 * so the next render read `undefined.open` and took the renderer down. The
 * store does not normalise on write, only on read, so it was also persisted, as
 * `null` after `JSON.stringify`. (`normalizeItems` skips those and appends the
 * missing types closed, which is the only reason the key self-heals.)
 *
 * Two lessons, both of which this signature answers. A non-null assertion is a
 * claim about an invariant, and this one had no invariant behind it - so every
 * refusal below returns the list **unchanged** rather than asserting. And a
 * reorder is arithmetic over a persisted permutation, which is the repository's
 * own definition of a decision that belongs in a module an assertion script can
 * import, beside `dockOrder` rather than inside a `useCallback`.
 */
export function reorderItems(items: DockItem[], order: readonly string[]): DockItem[] {
  // A reorder is a permutation of exactly the open items. Anything else is a
  // caller bug, and the conservative answer to one is to change nothing: a drop
  // that does nothing is recoverable by dragging again, and a list with a hole
  // in it is not.
  const openCount = items.filter((i) => i.open).length;
  if (order.length !== openCount) return items;
  if (new Set(order).size !== order.length) return items;

  const byType = new Map<string, DockItem>(items.map((i) => [i.type, i]));
  const moved = order.map((type) => byType.get(type));
  if (moved.some((i) => i === undefined || !i.open)) return items;

  let next = 0;
  return items.map((item) => {
    if (!item.open) return item;
    const slot = moved[next];
    next++;
    // Belt and braces, and deliberately not a `!`: the guards above already
    // prove this is defined, and the whole bug was a `!` standing in for a proof
    // that did not exist.
    return slot ?? item;
  });
}
