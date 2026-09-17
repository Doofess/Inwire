import { createPreferenceStore } from './preferenceStore';

/**
 * What the Statistics pane's Graphs tab is currently drawing.
 *
 * ## Why this key exists at all
 *
 * It is the surviving half of `inwire.dashboard`. Two widgets carried these
 * settings - Traffic timeline and Packet sizes - and both were deleted with the
 * dock; their charts moved onto a Statistics tab, and the settings had to land
 * somewhere. This is that somewhere, and it is a new key rather than a rename
 * because the old one described a widget's `config` bag: a
 * `Record<string, string | number>` validated against a catalogue, shaped that
 * way so a settings list could be generated from data. There is no catalogue
 * any more and no list to generate, so the fields are fields.
 *
 * ## Why the controls are persisted rather than local state
 *
 * The same argument the widgets made, and it still holds: **there is no such
 * thing as a temporary view here.** Switch the throughput chart to bytes and it
 * is a bytes chart - next time you open the tab, and after a reload. A control
 * that silently reverts is one the user has to re-set every session, and the
 * thing being set is what the chart MEANS rather than how it is dressed.
 *
 * ## The overlay filter is the one worth knowing about
 *
 * It is what makes the throughput chart an I/O graph rather than a plain
 * throughput plot: a second series drawn over the first, showing how much of
 * the traffic matches an expression. That question cannot be answered by the
 * app's own display filter, because filtering the app removes the total the
 * answer is measured against. It was a configurable field buried in
 * Settings -> Interface on a 352px card; it is a control on the chart now.
 */
export type GraphMetric = 'packets' | 'bytes';
export type GraphChart = 'area' | 'bars';
export type SizeChartKind = 'bars' | 'table';

/** The bucket widths offered, in seconds. */
export const GRAPH_INTERVALS: readonly number[] = [1, 5, 30, 60];

/** How long an overlay expression may be. The same cap the widget's field had. */
export const OVERLAY_FILTER_MAX = 200;

export interface GraphPrefs {
  /** What the throughput chart's Y axis counts. */
  metric: GraphMetric;
  /** How the throughput series is drawn. */
  chart: GraphChart;
  /** Bucket width in seconds. One of `GRAPH_INTERVALS`. */
  interval: number;
  /** A display filter for a second series over the first. Empty means one. */
  overlayFilter: string;
  /** How the frame-size distribution is drawn. */
  sizeChart: SizeChartKind;
}

export const GRAPH_DEFAULTS: GraphPrefs = {
  metric: 'packets',
  chart: 'area',
  interval: 1,
  overlayFilter: '',
  sizeChart: 'bars',
};

/**
 * Repairs a stored value field by field.
 *
 * Repaired rather than rejected, which is this repository's rule for every
 * preference and the opposite of how the update feed is read: a preference is a
 * bag of primitives out of `localStorage`, so the alternative to clamping each
 * field is a chart rendering `undefined` as a chart type. The update feed is
 * rejected whole because a defaulted field there could mean "download this URL
 * with no hash"; nothing here can do worse than draw the wrong axis.
 *
 * A non-object is refused outright, though - that is a key somebody has replaced
 * rather than one that has drifted, and there is nothing in it to keep.
 */
export function normalizeGraphPrefs(raw: unknown): GraphPrefs | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  return {
    metric: v.metric === 'bytes' ? 'bytes' : 'packets',
    chart: v.chart === 'bars' ? 'bars' : 'area',
    // Snapped to an offered value rather than clamped into a range: the control
    // is a set of pills, so a stored 7 would light none of them and read as a
    // broken control rather than as an unusual bucket width.
    interval: GRAPH_INTERVALS.includes(v.interval as number) ? (v.interval as number) : 1,
    overlayFilter: typeof v.overlayFilter === 'string'
      ? v.overlayFilter.slice(0, OVERLAY_FILTER_MAX)
      : '',
    sizeChart: v.sizeChart === 'table' ? 'table' : 'bars',
  };
}

export const graphStore = createPreferenceStore('inwire.graphs', normalizeGraphPrefs, GRAPH_DEFAULTS);
