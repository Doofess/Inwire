import { createPreferenceStore } from './preferenceStore';
import type { TimeFormat } from '../lib/formatTimeColumn';
import {
  COLUMN_ALIGNS,
  defaultColumnVisibility,
  normalizeColumnVisibility,
  type ColumnAlign,
  type ColumnVisibility,
} from '../lib/packetColumns';

const TIME_FORMATS: readonly TimeFormat[] = ['relative', 'clock', 'date', 'utc', 'delta'];

/**
 * The settings behind Settings -> Interface.
 *
 * Six keys rather than one envelope, cut by WHO WRITES THEM rather than by
 * which panel lists them. The panel is a view; the writer is the thing that has
 * to stay consistent. `preferences.ts` states the rule this follows: separate
 * keys mean a corrupt value in one cannot take the others down with it, and a
 * cross-tab `storage` event names exactly one preference, so a listener can
 * react to that one instead of re-reading everything.
 *
 * Every validator defaults FIELD BY FIELD and clamps rather than rejecting, in
 * the shape `normalizeLayout` established. A value out of storage is untrusted
 * input - hand-edited, or left behind by an older build - and one bad field
 * must never discard its siblings.
 */

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

export type PaneArrangement = 'side-by-side' | 'stacked';

export interface LayoutPrefs {
  /** Pixel height of the detail panes. Dragged, so it changes continuously. */
  bottomPaneHeight: number;
  /** Split between the two panes, as a fraction of the axis they share. */
  detailsPaneRatio: number;
  /** Whether the detail panes are shown at all. */
  panes: boolean;
  arrangement: PaneArrangement;
}

export const LAYOUT_DEFAULTS: LayoutPrefs = {
  bottomPaneHeight: 280,
  detailsPaneRatio: 0.5,
  panes: true,
  arrangement: 'side-by-side',
};

/**
 * The drag sizes and the arrangement share a key deliberately.
 *
 * `arrangement` changes what `detailsPaneRatio` MEANS - a fraction of width
 * when the panes are side by side, a fraction of height when they are stacked.
 * Split across two keys, another tab's change could deliver one without the
 * other, and there would be a paint where the ratio is applied to the wrong
 * axis. One key is one `storage` event and one atomic apply.
 */
export function normalizeLayout(raw: unknown): LayoutPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    // Clamped, not rejected: a height stored on a taller window must not leave
    // the pane occupying a screen it no longer fits.
    bottomPaneHeight:
      typeof v.bottomPaneHeight === 'number' && Number.isFinite(v.bottomPaneHeight)
        ? Math.max(100, Math.min(v.bottomPaneHeight, 900))
        : LAYOUT_DEFAULTS.bottomPaneHeight,
    detailsPaneRatio:
      typeof v.detailsPaneRatio === 'number' && Number.isFinite(v.detailsPaneRatio)
        ? Math.max(0.1, Math.min(v.detailsPaneRatio, 0.9))
        : LAYOUT_DEFAULTS.detailsPaneRatio,
    panes: typeof v.panes === 'boolean' ? v.panes : LAYOUT_DEFAULTS.panes,
    arrangement:
      v.arrangement === 'stacked' || v.arrangement === 'side-by-side'
        ? v.arrangement
        : LAYOUT_DEFAULTS.arrangement,
  };
}

export const layoutStore = createPreferenceStore(
  'netview.layout',
  normalizeLayout,
  LAYOUT_DEFAULTS,
);

// ---------------------------------------------------------------------------
// Packet list
// ---------------------------------------------------------------------------

export type ListDensity = 'compact' | 'default' | 'comfortable';

/**
 * Whether the list follows the live capture.
 *
 * Three states rather than a switch, because the middle one is the current
 * behaviour and is the right default: follow the tail, but stop the moment the
 * user does something that means "I am reading this". Until this setting
 * existed that heuristic could only be armed by a POINTER gesture, so there was
 * no way at all to stop the list moving without a mouse.
 */
export type FollowMode = 'always' | 'reading' | 'never';

export interface PacketListPrefs {
  follow: FollowMode;
  density: ListDensity;
  timeFormat: TimeFormat;
  columns: ColumnVisibility;
  /** Where the text sits in the text columns. See ColumnAlign. */
  align: ColumnAlign;
}

export const PACKET_LIST_DEFAULTS: PacketListPrefs = {
  follow: 'reading',
  density: 'default',
  // The format the list has always shown, so nothing moves for anyone who does
  // not go looking for the setting.
  timeFormat: 'relative',
  columns: defaultColumnVisibility(),
  align: 'left',
};

export function normalizePacketList(raw: unknown): PacketListPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    follow:
      v.follow === 'always' || v.follow === 'reading' || v.follow === 'never'
        ? v.follow
        : PACKET_LIST_DEFAULTS.follow,
    density:
      v.density === 'compact' || v.density === 'default' || v.density === 'comfortable'
        ? v.density
        : PACKET_LIST_DEFAULTS.density,
    timeFormat: TIME_FORMATS.includes(v.timeFormat as TimeFormat)
      ? (v.timeFormat as TimeFormat)
      : PACKET_LIST_DEFAULTS.timeFormat,
    columns: normalizeColumnVisibility(v.columns) ?? defaultColumnVisibility(),
    align: COLUMN_ALIGNS.includes(v.align as ColumnAlign)
      ? (v.align as ColumnAlign)
      : PACKET_LIST_DEFAULTS.align,
  };
}

export const packetListStore = createPreferenceStore(
  'netview.packetListView',
  normalizePacketList,
  PACKET_LIST_DEFAULTS,
);

/**
 * The minimap's own key, separate from the width it already stores.
 *
 * One writer per key. The minimap owns `netview.packetListMinimapWidth`, so it
 * owns this too - putting the on/off flag in a key belonging to the packet list
 * while the width lives elsewhere is the split that confuses whoever reads it
 * next.
 */
export const MINIMAP_DEFAULT = true;

export function normalizeMinimap(raw: unknown): boolean | null {
  return typeof raw === 'boolean' ? raw : null;
}

export const minimapStore = createPreferenceStore(
  'netview.packetListMinimap',
  normalizeMinimap,
  MINIMAP_DEFAULT,
);

// ---------------------------------------------------------------------------
// Performance
// ---------------------------------------------------------------------------

/** How often the analytics panels are handed a new buffer, in milliseconds. */
export type DashboardRefresh = 500 | 2000 | 0;

export interface PerformancePrefs {
  /** 0 means the panels update only when the user asks. */
  dashboardRefreshMs: DashboardRefresh;
  packetBufferCap: number;
}

export const PERFORMANCE_DEFAULTS: PerformancePrefs = {
  dashboardRefreshMs: 500,
  packetBufferCap: 50000,
};

export const BUFFER_CAPS = [10000, 25000, 50000] as const;

export function normalizePerformance(raw: unknown): PerformancePrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    dashboardRefreshMs:
      v.dashboardRefreshMs === 500 || v.dashboardRefreshMs === 2000 || v.dashboardRefreshMs === 0
        ? v.dashboardRefreshMs
        : PERFORMANCE_DEFAULTS.dashboardRefreshMs,
    // Snapped to an offered value rather than clamped to a range: the cap is a
    // choice between three, and an arbitrary number out of storage would render
    // a settings control with nothing selected.
    packetBufferCap:
      typeof v.packetBufferCap === 'number' &&
      (BUFFER_CAPS as readonly number[]).includes(v.packetBufferCap)
        ? v.packetBufferCap
        : PERFORMANCE_DEFAULTS.packetBufferCap,
  };
}

export const performanceStore = createPreferenceStore(
  'netview.performance',
  normalizePerformance,
  PERFORMANCE_DEFAULTS,
);

// ---------------------------------------------------------------------------
// Motion
// ---------------------------------------------------------------------------

export type MotionSetting = 'system' | 'always' | 'never';

export const MOTION_DEFAULT: MotionSetting = 'system';

/**
 * A bare string, on its own key.
 *
 * Two reasons it is not folded in with the layout values. It is read before
 * first paint, so it should not require parsing and validating four fields it
 * does not need. And a corrupt sibling must never be able to reset an explicit
 * "never" back to following the system - for someone who set it because motion
 * makes them ill, that is not a cosmetic regression.
 */
export function normalizeMotion(raw: unknown): MotionSetting | null {
  return raw === 'system' || raw === 'always' || raw === 'never' ? raw : null;
}

export const motionStore = createPreferenceStore(
  'netview.motion',
  normalizeMotion,
  MOTION_DEFAULT,
);

// ---------------------------------------------------------------------------
// Name resolution
// ---------------------------------------------------------------------------

export interface NameResolutionPrefs {
  /** Sends captured addresses to get.geojs.io to place them on the map. */
  geoIp: boolean;
  /** Sends captured addresses to cloudflare-dns.com as PTR queries. */
  reverseDns: boolean;
}

/**
 * Both off. See geoIpService's gate for why this is opt-in rather than opt-out.
 *
 * MAC vendor names are deliberately absent from this shape. They come from a
 * table compiled into the app - services/macVendors is three literals and two
 * pure functions - so nothing is sent and there is nothing to consent to.
 * Listing it beside two lookups that genuinely do phone out would misrepresent
 * all three.
 */
export const NAME_RESOLUTION_DEFAULTS: NameResolutionPrefs = {
  geoIp: false,
  reverseDns: false,
};

export function normalizeNameResolution(raw: unknown): NameResolutionPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    geoIp: typeof v.geoIp === 'boolean' ? v.geoIp : NAME_RESOLUTION_DEFAULTS.geoIp,
    reverseDns:
      typeof v.reverseDns === 'boolean' ? v.reverseDns : NAME_RESOLUTION_DEFAULTS.reverseDns,
  };
}

export const nameResolutionStore = createPreferenceStore(
  'netview.nameResolution',
  normalizeNameResolution,
  NAME_RESOLUTION_DEFAULTS,
);

/**
 * Every store the Interface tab owns, for the operations that act on all of
 * them - the reset button, and config export/import.
 *
 * Name resolution is deliberately NOT here. Reset must never re-enable an
 * outbound lookup somebody turned off; a control that tidies the layout is not
 * consent to start sending addresses to a third party again.
 */
export const INTERFACE_STORES = [
  layoutStore,
  packetListStore,
  minimapStore,
  performanceStore,
  motionStore,
] as const;

/**
 * Restores the settings the Interface tab actually shows.
 *
 * The pane SIZES are pointedly excluded, even though they live in the same key
 * as the pane settings. They are not listed on the tab - they are set by
 * dragging a divider - and a button that restores a list of settings should not
 * quietly undo something that is not on the list. The divider has Home and End
 * for anyone who does want its size back.
 */
export function resetInterfacePreferences(): void {
  for (const store of INTERFACE_STORES) {
    if (store === layoutStore) continue;
    (store as { set(v: unknown): void }).set(store.defaults);
  }
  const { bottomPaneHeight, detailsPaneRatio } = layoutStore.get();
  layoutStore.set({ ...LAYOUT_DEFAULTS, bottomPaneHeight, detailsPaneRatio });
}
