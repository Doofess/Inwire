import { createPreferenceStore } from './preferenceStore';
import type { TimeFormat } from '../lib/formatTimeColumn';
import {
  DEFAULT_COLUMN_ALIGN,
  defaultColumnVisibility,
  normalizeColumnAlign,
  normalizeColumnVisibility,
  normalizeCustomColumns,
  type ColumnAlignMap,
  type ColumnVisibility,
} from '../lib/packetColumns';
import { FIELD_BY_ABBREV } from './dissect/fieldRegistry';
import { BUDGET_CHOICES, type BufferBudgetSetting } from './bufferBudget';
import type { DissectionThreads } from './pipeline/threads';

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
  /**
   * The details pane's share of the axis the two panes share. Hex takes what is
   * left.
   *
   * One share and a remainder rather than a boundary, because the remainder is
   * the pane with no minimum content width worth defending: the tree truncates
   * field names, but a hex dump narrower than its own 16-byte row wraps into
   * nonsense. Making hex `flex-1` means it absorbs every window resize while
   * the tree keeps the width the user actually chose.
   *
   * There was a `geoPaneRatio` beside this - the map's share, back when the map
   * was a third pane in that row - and with it the rule that two shares are
   * stored unclamped against each other and the interaction ("hex keeps at
   * least a tenth") is applied at the point of use. One share has no
   * interaction to defer, so the ceiling below is the whole clamp again.
   */
  detailsPaneRatio: number;
  /** Whether the detail panes are shown at all. */
  panes: boolean;
  arrangement: PaneArrangement;
}

export const LAYOUT_DEFAULTS: LayoutPrefs = {
  bottomPaneHeight: 280,
  // Half each, which is what it was before the map took a third of the row and
  // 0.36 / 0.36 / 0.28 out of it.
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
    // 0.9 again. It was 0.5 while the map was a third pane in the row, because
    // a details pane at 0.9 would then have left a tenth of the row for the hex
    // dump AND the map together. There are two panes, so the dump's tenth is
    // the only thing this ceiling has to defend.
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
  'inwire.layout',
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
  /**
   * Registry field names added from the detail tree's "Apply as Column",
   * drawn between Length and Info in the order they were added.
   */
  customColumns: string[];
  /** Where the text sits, per column. See ColumnAlignMap. */
  align: ColumnAlignMap;
}

export const PACKET_LIST_DEFAULTS: PacketListPrefs = {
  follow: 'reading',
  density: 'default',
  // The format the list has always shown, so nothing moves for anyone who does
  // not go looking for the setting.
  timeFormat: 'relative',
  columns: defaultColumnVisibility(),
  customColumns: [],
  align: { ...DEFAULT_COLUMN_ALIGN },
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
    // A column naming a field this build no longer registers is dropped, not
    // drawn empty under a header for something that does not exist.
    customColumns: normalizeCustomColumns(v.customColumns, (abbrev) => FIELD_BY_ABBREV.has(abbrev)),
    // Accepts the old single string as well as the map, and spreads it over
    // the columns it used to govern - see normalizeColumnAlign.
    align: normalizeColumnAlign(v.align),
  };
}

export const packetListStore = createPreferenceStore(
  'inwire.packetListView',
  normalizePacketList,
  PACKET_LIST_DEFAULTS,
);

/**
 * The minimap's own key, separate from the width it already stores.
 *
 * One writer per key. The minimap owns `inwire.packetListMinimapWidth`, so it
 * owns this too - putting the on/off flag in a key belonging to the packet list
 * while the width lives elsewhere is the split that confuses whoever reads it
 * next.
 */
export const MINIMAP_DEFAULT = true;

export function normalizeMinimap(raw: unknown): boolean | null {
  return typeof raw === 'boolean' ? raw : null;
}

export const minimapStore = createPreferenceStore(
  'inwire.packetListMinimap',
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
  /**
   * Memory the packet buffer's summaries may use, in bytes.
   *
   * Was `packetBufferCap`, a number of frames. A frame cost 2,342 B when that
   * list of counts was written and costs 740 B now, so the largest option had
   * quietly become about 74 MB - the setting was capping a resource nobody was
   * short of, in a unit that says nothing about the one they are.
   *
   * See `services/bufferBudget.ts` for what the budget governs and what it
   * deliberately does not.
   */
  packetBufferBytes: BufferBudgetSetting;
  /**
   * How many cores dissect a live capture (ADR 0053 phase 3): `auto` shards
   * TCP across them, 1 is the single pipeline Worker exactly as it was. Takes
   * effect when the next capture starts.
   */
  dissectionThreads: DissectionThreads;
}

export const PERFORMANCE_DEFAULTS: PerformancePrefs = {
  dashboardRefreshMs: 500,
  // **'auto', not a number.** A fixed 512 MB was a figure chosen for no machine
  // in particular; `autoBufferBudget` reads the machine's RAM and V8's heap
  // limit and answers for the one the app is on. Stored as a word rather than
  // as whatever that resolves to today, because "size it for me" and "I chose
  // this number" are different intentions and only the first follows the
  // machine when the app moves to another one.
  packetBufferBytes: 'auto',
  // **'auto', a word, for the reason the buffer's is**: it follows the machine.
  // On a machine with too few cores to spare it resolves to the single Worker.
  dissectionThreads: 'auto',
};

export function normalizePerformance(raw: unknown): PerformancePrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    dashboardRefreshMs:
      v.dashboardRefreshMs === 500 || v.dashboardRefreshMs === 2000 || v.dashboardRefreshMs === 0
        ? v.dashboardRefreshMs
        : PERFORMANCE_DEFAULTS.dashboardRefreshMs,
    // Snapped to an offered value rather than clamped to a range: the budget is
    // a choice between four, and an arbitrary number out of storage would
    // render a settings control with nothing selected.
    //
    // A stored `packetBufferCap` from before this was a budget lands here as an
    // unrecognised value and falls back to the default, which is the right
    // answer: the old numbers are frame counts, and reading 50000 as 50 kB
    // would give someone a buffer of about seventy frames.
    packetBufferBytes:
      v.packetBufferBytes === 'auto'
        ? 'auto'
        : typeof v.packetBufferBytes === 'number' &&
          (BUDGET_CHOICES as readonly number[]).includes(v.packetBufferBytes)
          ? v.packetBufferBytes
          : PERFORMANCE_DEFAULTS.packetBufferBytes,
    dissectionThreads: v.dissectionThreads === 1 ? 1 : PERFORMANCE_DEFAULTS.dissectionThreads,
  };
}

export const performanceStore = createPreferenceStore(
  'inwire.performance',
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
  'inwire.motion',
  normalizeMotion,
  MOTION_DEFAULT,
);

// ---------------------------------------------------------------------------
// Name resolution
// ---------------------------------------------------------------------------

/**
 * Wireshark's View -> Name Resolution, with the outbound half kept apart from
 * the passive half.
 *
 * `network` and `transport` cost nothing and leak nothing: every name they can
 * show came out of the capture itself (`services/nameResolution.ts`,
 * `services/portServices.ts`). That is why they default ON here where
 * Wireshark defaults network resolution off - Wireshark's default is a guard
 * against reverse-DNS traffic that this pair cannot generate.
 *
 * `geoIp` and `reverseDns` send captured addresses to a third party, so they
 * are opt-in and stay out of the Interface tab's reset.
 */
export interface NameResolutionPrefs {
  /** Host names from the capture, in the address columns and the tables. */
  network: boolean;
  /** Service names beside port numbers, in the statistics tables. */
  transport: boolean;
  /**
   * Permits the app's outbound location lookups: captured addresses to
   * get.geojs.io for the map, and this machine's own public address to
   * ipapi.co for the Network panel's Public identity section. One switch rather than two because both are
   * the same disclosure - a third party learns an address and says where it
   * is - and a switch per vendor invites agreeing to each without noticing
   * they add up to the same thing.
   */
  geoIp: boolean;
  /** Sends captured addresses to cloudflare-dns.com as PTR queries. */
  reverseDns: boolean;
}

/**
 * The two passive switches on, the two outbound ones off. See geoIpService's
 * gate for why the latter are opt-in rather than opt-out.
 *
 * Passive resolution is a RENDERING choice and nothing else: `Packet.source`
 * stays the address on every path, so filters, exports and the tshark parity
 * harness are untouched by it. A name in a column that a filter could not
 * match would be worse than no name at all.
 *
 * MAC vendor names are deliberately absent from this shape. They come from a
 * table compiled into the app - services/macVendors is three literals and two
 * pure functions - so nothing is sent and there is nothing to consent to.
 * Listing it beside two lookups that genuinely do phone out would misrepresent
 * all three.
 */
export const NAME_RESOLUTION_DEFAULTS: NameResolutionPrefs = {
  network: true,
  transport: true,
  geoIp: false,
  reverseDns: false,
};

export function normalizeNameResolution(raw: unknown): NameResolutionPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    network: typeof v.network === 'boolean' ? v.network : NAME_RESOLUTION_DEFAULTS.network,
    transport: typeof v.transport === 'boolean' ? v.transport : NAME_RESOLUTION_DEFAULTS.transport,
    geoIp: typeof v.geoIp === 'boolean' ? v.geoIp : NAME_RESOLUTION_DEFAULTS.geoIp,
    reverseDns:
      typeof v.reverseDns === 'boolean' ? v.reverseDns : NAME_RESOLUTION_DEFAULTS.reverseDns,
  };
}

export const nameResolutionStore = createPreferenceStore(
  'inwire.nameResolution',
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

// ---------------------------------------------------------------------------
// The Network panel
// ---------------------------------------------------------------------------

/**
 * What the Network panel remembers between openings.
 *
 * One field, and it earns a store rather than component state because of what
 * it is for: masking addresses and MACs while sharing a screen. Somebody who
 * shares their screen once tends to do it again, and a switch that reset every
 * time the panel closed is one they would forget to set the second time -
 * which is the time it matters.
 */
export interface NetworkPanelPrefs {
  hideSensitive: boolean;
}

export const NETWORK_PANEL_DEFAULTS: NetworkPanelPrefs = { hideSensitive: false };

export function normalizeNetworkPanel(raw: unknown): NetworkPanelPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const value = raw as Record<string, unknown>;
  return {
    hideSensitive: typeof value.hideSensitive === 'boolean'
      ? value.hideSensitive
      : NETWORK_PANEL_DEFAULTS.hideSensitive,
  };
}

export const networkPanelStore = createPreferenceStore(
  'inwire.networkPanel',
  normalizeNetworkPanel,
  NETWORK_PANEL_DEFAULTS,
);
