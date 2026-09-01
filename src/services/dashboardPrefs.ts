import { createPreferenceStore } from './preferenceStore';

/**
 * The analytics dashboard's arrangement.
 *
 * Deliberately a plain module with no React and no widget imports. The registry
 * that pairs these ids with components has to import GeoMap, which imports
 * `maplibre-gl` at module scope - so anything importing the registry cannot run
 * under `tsx`, and the validator below is exactly the sort of thing that should
 * be covered by an assertion script.
 */

export const DASHBOARD_WIDGET_IDS = ['geo', 'timeline', 'protocols', 'talkers', 'alerts'] as const;

export type DashboardWidgetId = (typeof DASHBOARD_WIDGET_IDS)[number];

/**
 * How much of the dashboard is showing.
 *
 * `icons` is not merely a smaller `full`. The full column needs about 384px and
 * is hidden below the `lg` breakpoint, so on a laptop-width window the
 * dashboard simply does not exist and nothing says so. A 48px rail fits where
 * the column cannot, which makes this the only way some users will see these
 * widgets at all.
 */
export type DashboardMode = 'full' | 'icons' | 'hidden';

/**
 * The widths the column moves between.
 *
 * `MORPH` is the interesting one: it is the width at which a column stops
 * being a column. Drag narrower than this and the widgets have less room than
 * their own headings need, so rather than showing five squeezed cards the
 * dashboard becomes the icon rail - and dragging back out past it turns it
 * into a column again. One gesture, both directions, no mode control involved.
 *
 * The rail width matches the packet detail window's own rail (FrameMetaRail),
 * because two 48px icon strips in one app that disagree by a few pixels is
 * something you only notice when they are on screen together.
 */
export const DASHBOARD_RAIL_WIDTH = 48;
export const DASHBOARD_MORPH_WIDTH = 200;
export const DASHBOARD_MAX_WIDTH = 640;

export interface DashboardPrefs {
  mode: DashboardMode;
  /**
   * How wide the full column is, in pixels.
   *
   * Kept while the rail is showing rather than collapsed to 48, so expanding
   * gives back the column the user had rather than a default one. That is also
   * why it is stored beside `mode` instead of being derived from it.
   */
  width: number;
  order: DashboardWidgetId[];
  /** Widgets the user has switched off. Stored as the exceptions, not the set. */
  disabled: DashboardWidgetId[];
}

export const DASHBOARD_DEFAULTS: DashboardPrefs = {
  mode: 'full',
  // What `lg:w-96` gave before the column could be dragged, so nobody's
  // dashboard changes size the first time they load a build with this in it.
  width: 384,
  order: [...DASHBOARD_WIDGET_IDS],
  disabled: [],
};

/** Clamped rather than rejected - see normalizeDashboard. */
export function clampDashboardWidth(value: number): number {
  return Math.round(Math.max(DASHBOARD_MORPH_WIDTH, Math.min(value, DASHBOARD_MAX_WIDTH)));
}

/**
 * Repairs a stored order into a real permutation of the registry.
 *
 * Three failures to survive, and the third is the one that bites hardest:
 *
 *   - an id this build no longer has, from an older version
 *   - an id this build has that the stored order predates, so it is missing
 *   - the SAME id twice
 *
 * A duplicate is not a cosmetic problem. The dashboard renders one component
 * per entry, so a repeated `geo` mounts two MapLibre instances - two WebGL
 * contexts, two tile streams, two sets of markers - from a value a user could
 * produce by hand-editing storage.
 *
 * Never returns null. There is no such thing as an order this cannot repair,
 * and returning null would throw away a perfectly good `mode` sitting beside it.
 */
export function normalizeWidgetOrder(raw: unknown): DashboardWidgetId[] {
  const known = new Set<string>(DASHBOARD_WIDGET_IDS);
  const seen = new Set<string>();
  const out: DashboardWidgetId[] = [];

  if (Array.isArray(raw)) {
    for (const value of raw) {
      if (typeof value === 'string' && known.has(value) && !seen.has(value)) {
        seen.add(value);
        out.push(value as DashboardWidgetId);
      }
    }
  }
  // Anything the stored order did not mention goes to the end, in registry
  // order, so adding a widget later does not strand anyone on a stale list.
  for (const id of DASHBOARD_WIDGET_IDS) if (!seen.has(id)) out.push(id);
  return out;
}

/** The same repair, for a set where order carries no meaning. */
export function normalizeWidgetSet(raw: unknown): DashboardWidgetId[] {
  const known = new Set<string>(DASHBOARD_WIDGET_IDS);
  const seen = new Set<string>();
  if (Array.isArray(raw)) {
    for (const value of raw) {
      if (typeof value === 'string' && known.has(value)) seen.add(value);
    }
  }
  // Registry order, so the stored value is stable rather than depending on the
  // order the user happened to click things.
  return DASHBOARD_WIDGET_IDS.filter((id) => seen.has(id));
}

export function normalizeDashboard(raw: unknown): DashboardPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    mode:
      v.mode === 'full' || v.mode === 'icons' || v.mode === 'hidden'
        ? v.mode
        : DASHBOARD_DEFAULTS.mode,
    // Clamped, not rejected: a width stored on a much wider monitor must not
    // leave the column occupying a screen it no longer fits, but throwing the
    // value away would take the widget order and the disabled set with it.
    width:
      typeof v.width === 'number' && Number.isFinite(v.width)
        ? clampDashboardWidth(v.width)
        : DASHBOARD_DEFAULTS.width,
    order: normalizeWidgetOrder(v.order),
    disabled: normalizeWidgetSet(v.disabled),
  };
}

export const dashboardStore = createPreferenceStore(
  'netview.dashboard',
  normalizeDashboard,
  DASHBOARD_DEFAULTS,
);
