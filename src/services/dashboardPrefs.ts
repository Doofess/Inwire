import { createPreferenceStore } from './preferenceStore';

/**
 * The analytics dashboard's contents and arrangement.
 *
 * Deliberately a plain module with no React and no widget imports. The registry
 * that pairs these types with components has to import GeoMap, which imports
 * `maplibre-gl` at module scope - so anything importing the registry cannot run
 * under `tsx`, and the validators below are exactly the sort of thing that
 * should be covered by an assertion script.
 *
 * The dashboard is a FIXED set: one widget of each type below, in an order the
 * user chooses, each switched on or off and configured on its own terms. There
 * is nothing to add and nothing to delete.
 *
 * The catalogue is data because the settings controls in Settings -> Interface
 * are generated from `options`, so adding a setting is one entry here rather
 * than a control, a default and a validator in three files that can drift
 * apart. Labels live here too - they are plain strings,
 * and keeping them beside the values they name is what stops a choice being
 * renamed in the UI but not in storage. Icons and components do NOT: those are
 * the registry's, because they are the half that cannot run under `tsx`.
 */

export const WIDGET_TYPE_IDS = [
  'geo',
  'timeseries',
  'breakdown',
  'sizes',
  'talkers',
] as const;

export type WidgetTypeId = (typeof WIDGET_TYPE_IDS)[number];

// ---------------------------------------------------------------------------
// What a widget type can be configured with
// ---------------------------------------------------------------------------

export interface WidgetChoice {
  value: string;
  label: string;
}

/** One of a fixed set - rendered as a Segmented control. */
export interface WidgetChoiceOption {
  kind: 'choice';
  id: string;
  label: string;
  choices: readonly WidgetChoice[];
  fallback: string;
  /**
   * Also offered in the widget's own header, not only in Settings.
   *
   * At most one option per type, and the check script enforces that: a 352px
   * card header holds a title and one control, and the second one pushes the
   * title into an ellipsis. The one chosen is whichever gets switched while
   * reading rather than while configuring - packets against bytes, flows
   * against hosts - so the toggles that shipped on these widgets are still
   * one click away.
   *
   * A header control writes the same stored config the settings list does.
   * There is no such thing as a temporary view here: switch a card to bytes and
   * it is a bytes card, in the column, in its popout bubble, and after a
   * reload. That is what makes "whatever you leave it on is what it shows"
   * true rather than a promise about one of the two places it can be set.
   */
  inHeader?: boolean;
}

/** A whole number in a range - rendered as a stepper. */
export interface WidgetCountOption {
  kind: 'count';
  id: string;
  label: string;
  min: number;
  max: number;
  fallback: number;
}

/**
 * A free-text value - rendered as a plain input.
 *
 * Added for the traffic timeline's overlay filter, which is the one widget
 * setting that cannot be a fixed list: the point of an I/O graph's second
 * series is that it answers a question nobody anticipated.
 */
export interface WidgetTextOption {
  kind: 'text';
  id: string;
  label: string;
  placeholder?: string;
  fallback: string;
  /** Longest accepted value; a stored string is untrusted input. */
  maxLength: number;
}

export type WidgetOption = WidgetChoiceOption | WidgetCountOption | WidgetTextOption;

export interface WidgetTypeSpec {
  readonly id: WidgetTypeId;
  readonly label: string;
  /** One line, under the widget's name in the settings list. */
  readonly description: string;
  readonly options: readonly WidgetOption[];
}

const METRIC: WidgetChoiceOption = {
  kind: 'choice',
  id: 'metric',
  label: 'Measure',
  choices: [
    { value: 'packets', label: 'Packets' },
    { value: 'bytes', label: 'Bytes' },
  ],
  fallback: 'packets',
  inHeader: true,
};

/**
 * How many rows a ranked list shows.
 *
 * Five is what `TOP_PROTOCOLS` and `TOP_ROWS` were hardcoded to, so an
 * untouched dashboard is unchanged. The ceiling is twenty because these are
 * cards in a column, not tables: past that the list is taller than the widget
 * and the ranking stops being readable at a glance, which is the only thing a
 * ranked card is for.
 */
const ROWS: WidgetCountOption = {
  kind: 'count',
  id: 'top',
  label: 'Rows',
  min: 3,
  max: 20,
  fallback: 5,
};

export const WIDGET_TYPES: Record<WidgetTypeId, WidgetTypeSpec> = {
  geo: {
    id: 'geo',
    label: 'Geo map',
    description: 'Where the traffic is going, as arcs on a globe.',
    options: [],
  },
  timeseries: {
    id: 'timeseries',
    label: 'Traffic timeline',
    description: 'Throughput over time, with anomalies marked.',
    options: [
      METRIC,
      {
        kind: 'choice',
        id: 'chart',
        label: 'Chart',
        choices: [
          { value: 'area', label: 'Area' },
          { value: 'bars', label: 'Bars' },
        ],
        fallback: 'area',
      },
      {
        // The bucket width. One second is what the chart was hardcoded to;
        // 100 ms is where a microburst becomes visible at all, and a minute is
        // what makes an hour-long capture readable in one screen.
        kind: 'choice',
        id: 'interval',
        label: 'Interval',
        choices: [
          { value: '0.1', label: '100 ms' },
          { value: '1', label: '1 s' },
          { value: '10', label: '10 s' },
          { value: '60', label: '1 min' },
        ],
        fallback: '1',
      },
      {
        // A second series, drawn over the first: "how much of this is X".
        // Empty means one series, which is what the chart has always drawn.
        kind: 'text',
        id: 'filter',
        label: 'Overlay',
        placeholder: 'display filter, e.g. tcp.analysis.flags',
        fallback: '',
        maxLength: 200,
      },
    ],
  },
  breakdown: {
    id: 'breakdown',
    label: 'Protocol breakdown',
    description: 'Which protocols the capture is made of.',
    options: [
      METRIC,
      {
        kind: 'choice',
        id: 'chart',
        label: 'Chart',
        choices: [
          { value: 'bars', label: 'Bars' },
          { value: 'donut', label: 'Donut' },
          { value: 'table', label: 'Table' },
        ],
        fallback: 'bars',
      },
      ROWS,
    ],
  },
  sizes: {
    id: 'sizes',
    label: 'Packet sizes',
    description: 'How frame lengths are distributed.',
    options: [
      {
        kind: 'choice',
        id: 'chart',
        label: 'Chart',
        choices: [
          { value: 'bars', label: 'Bars' },
          { value: 'table', label: 'Table' },
        ],
        fallback: 'bars',
      },
    ],
  },
  talkers: {
    id: 'talkers',
    label: 'Top talkers',
    description: 'The busiest conversations and hosts.',
    options: [
      {
        kind: 'choice',
        id: 'view',
        label: 'Show',
        choices: [
          { value: 'flows', label: 'Flows' },
          { value: 'hosts', label: 'Hosts' },
        ],
        fallback: 'flows',
        inHeader: true,
      },
      ROWS,
    ],
  },
};

/** The one option a type also offers in its card header, if it has one. */
export function headerOption(type: WidgetTypeId): WidgetChoiceOption | undefined {
  return WIDGET_TYPES[type].options.find(
    (o): o is WidgetChoiceOption => o.kind === 'choice' && !!o.inHeader,
  );
}

export type WidgetConfig = Record<string, string | number>;

export function defaultConfig(type: WidgetTypeId): WidgetConfig {
  const config: WidgetConfig = {};
  for (const option of WIDGET_TYPES[type].options) config[option.id] = option.fallback;
  return config;
}

/**
 * A stored config, repaired against its type's catalogue.
 *
 * Repairs rather than rejects, and drops anything the type does not declare: a
 * config is a bag of primitives out of localStorage, so the alternative to
 * clamping every field is a widget rendering `undefined` as a chart type.
 */
export function normalizeConfig(type: WidgetTypeId, raw: unknown): WidgetConfig {
  const source = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
  const config: WidgetConfig = {};
  for (const option of WIDGET_TYPES[type].options) {
    const value = source[option.id];
    if (option.kind === 'choice') {
      config[option.id] = option.choices.some((c) => c.value === value)
        ? (value as string)
        : option.fallback;
    } else if (option.kind === 'text') {
      config[option.id] = typeof value === 'string' ? value.slice(0, option.maxLength) : option.fallback;
    } else {
      config[option.id] =
        typeof value === 'number' && Number.isFinite(value)
          ? Math.round(Math.max(option.min, Math.min(value, option.max)))
          : option.fallback;
    }
  }
  return config;
}

// ---------------------------------------------------------------------------
// Instances
// ---------------------------------------------------------------------------

/**
 * One widget on the dashboard.
 *
 * **The type is the identity.** The dashboard holds exactly one widget of each
 * type, in an order the user chooses, and there is no way to add or remove one
 * - so an id would be a second name for something that already has one.
 *
 * This was briefly a list the user built, with generated ids and the same type
 * allowed several times over. That is gone, and one thing it was guarding goes
 * with it for free: every GeoMap is a MapLibre instance, so two of them are two
 * WebGL contexts, two tile streams and two sets of pins fed by one session. A
 * model where a type cannot appear twice makes that unrepresentable rather than
 * merely validated against.
 */
export interface WidgetInstance {
  type: WidgetTypeId;
  /** What the user renamed it to. Absent means "use the type's label". */
  title?: string;
  /**
   * Switched off rather than deleted - there is no deleting.
   *
   * A disabled widget is not rendered at all, so it stops recalculating as
   * packets arrive. That is the whole of what removing one used to do, without
   * the half that could not be undone.
   */
  enabled: boolean;
  config: WidgetConfig;
}

export function createWidget(type: WidgetTypeId): WidgetInstance {
  return { type, enabled: true, config: defaultConfig(type) };
}

/** The name to show: what the user called it, or what it is. */
export function widgetTitle(widget: WidgetInstance): string {
  const custom = widget.title?.trim();
  return custom || WIDGET_TYPES[widget.type].label;
}

// ---------------------------------------------------------------------------
// The stored preference
// ---------------------------------------------------------------------------

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
 * their own headings need, so rather than showing squeezed cards the dashboard
 * becomes the icon rail - and dragging back out past it turns it into a column
 * again. One gesture, both directions, no mode control involved.
 *
 * The rail width matches the packet detail window's own rail (FrameMetaRail),
 * because two 48px icon strips in one app that disagree by a few pixels is
 * something you only notice when they are on screen together.
 */
export const DASHBOARD_RAIL_WIDTH = 48;
export const DASHBOARD_MORPH_WIDTH = 200;
export const DASHBOARD_MAX_WIDTH = 640;

/**
 * How wide a widget is at the default column width, in pixels.
 *
 * This is the size the rail's popout bubbles are drawn at: the point of the
 * bubble is that it IS the widget rather than a shrunken preview of it, so it
 * is the width that widget has in a column nobody has resized - 384 less the
 * column's own 16px of padding on each side. Exported because the bubble lives
 * in a portalled popover and so cannot measure the column it came from.
 */
export const WIDGET_CARD_WIDTH = 352;

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
  widgets: WidgetInstance[];
}

/**
 * The dashboard a fresh install gets: every widget, in registry order, on.
 *
 * There is no separate default list any more. With nothing to add and nothing
 * to delete, "which widgets exist" and "which widgets you get" are the same
 * question, and keeping two lists that had to agree was just somewhere for them
 * to disagree.
 */
export function defaultWidgets(): WidgetInstance[] {
  return WIDGET_TYPE_IDS.map((type) => createWidget(type));
}

export const DASHBOARD_DEFAULTS: DashboardPrefs = {
  mode: 'full',
  // What `lg:w-96` gave before the column could be dragged, so nobody's
  // dashboard changes size the first time they load a build with this in it.
  width: 384,
  // Built once, and never handed out to be edited. It has to be a stable
  // reference rather than a getter returning a fresh list: this object IS the
  // store's value when nothing is stored yet, so a getter would hand every
  // reader a new array identity on every read, and the memo in DashboardAside
  // that keys on the widget list would rebuild the whole column forever.
  // Callers that want a fresh copy call `defaultWidgets()`, which is what this
  // was built from.
  widgets: defaultWidgets(),
};

/** Clamped rather than rejected - see normalizeDashboard. */
export function clampDashboardWidth(value: number): number {
  return Math.round(Math.max(DASHBOARD_MORPH_WIDTH, Math.min(value, DASHBOARD_MAX_WIDTH)));
}

/**
 * What the widget ids meant before the dashboard was user-built.
 *
 * The old shape was `{ order: id[], disabled: id[] }` over a FIXED list of five
 * widgets, where the id was both the type and the identity. Two of those names
 * changed when the types gained settings of their own - `timeline` became a
 * time series that can also be drawn as bars, `protocols` became a breakdown
 * that can also be a donut or a table - so a stored order has to be translated
 * rather than merely validated.
 */
const LEGACY_TYPES: Record<string, WidgetTypeId> = {
  geo: 'geo',
  timeline: 'timeseries',
  protocols: 'breakdown',
  talkers: 'talkers',
  // `alerts` is deliberately absent. The widget is gone - it showed the newest
  // of two hard-coded TCP anomalies, which are now ordinary expert findings
  // like every other - so a stored layout naming it drops the entry rather
  // than mapping it to something that no longer exists.
};

/**
 * Repairs a stored widget list into exactly one entry per type.
 *
 * Repairs rather than rejects, because there is no such thing as a list this
 * cannot fix and rejecting would throw away the perfectly good `mode` and
 * `width` sitting beside it in the same key.
 *
 * The postcondition is the whole point, and it is worth stating as one thing
 * rather than as a list of failures handled: **whatever goes in, what comes out
 * is a permutation of `WIDGET_TYPE_IDS`, each exactly once.** Order is the
 * user's and is preserved; anything unrecognised is dropped; a repeat is
 * ignored; anything missing is appended in registry order; and every config is
 * clamped to what its own controls offer.
 *
 * That last rule - append what is missing - is what the very first version of
 * this file did, and it is right again for the same reason: a type the stored
 * list does not mention means this build is newer, not that the user removed
 * it. There is no removing. It also means the "doubled widgets" report has no
 * expression left in the model: a second `geo` is not repaired, it is
 * unrepresentable.
 */
export function normalizeWidgets(raw: unknown): WidgetInstance[] {
  const out: WidgetInstance[] = [];
  const seen = new Set<WidgetTypeId>();

  for (const entry of Array.isArray(raw) ? raw : []) {
    if (typeof entry !== 'object' || entry === null) continue;
    const v = entry as Record<string, unknown>;
    if (!WIDGET_TYPE_IDS.includes(v.type as WidgetTypeId)) continue;
    const type = v.type as WidgetTypeId;
    // The first of a repeated type wins, so a hand edit - or a list written by
    // the short-lived build that allowed duplicates - collapses to the one the
    // user would have been looking at.
    if (seen.has(type)) continue;
    seen.add(type);

    const title =
      typeof v.title === 'string' && v.title.trim() ? v.title.trim().slice(0, 40) : undefined;
    out.push({
      type,
      ...(title ? { title } : {}),
      // Absent means shown. Only an explicit `false` switches a widget off, so
      // a list written by a build that predates the field comes back with
      // everything visible rather than everything hidden.
      enabled: v.enabled !== false,
      config: normalizeConfig(type, v.config),
    });
  }

  for (const type of WIDGET_TYPE_IDS) {
    if (!seen.has(type)) out.push(createWidget(type));
  }

  return out;
}

/**
 * The old `{ order, disabled }` pair, translated.
 *
 * Only the very first shape needs this. The intermediate build that stored
 * `{ widgets: [{ id, type, ... }] }` needs nothing: `normalizeWidgets` reads
 * `type` and ignores `id`, so those lists - duplicates and all - already land
 * on one widget per type with their order intact.
 */
function migrateLegacyWidgets(order: unknown, disabled: unknown): WidgetInstance[] {
  const off = new Set(Array.isArray(disabled) ? disabled.filter((d) => typeof d === 'string') : []);
  const seen = new Set<WidgetTypeId>();
  const out: WidgetInstance[] = [];

  for (const legacy of Array.isArray(order) ? order : []) {
    if (typeof legacy !== 'string') continue;
    const type = LEGACY_TYPES[legacy];
    if (!type || seen.has(type)) continue;
    seen.add(type);
    out.push({ type, enabled: !off.has(legacy), config: defaultConfig(type) });
  }

  // Whatever that build did not have. `normalizeWidgets` would do this anyway;
  // doing it here keeps this function's own result complete rather than
  // correct-only-once-something-else-has-run.
  for (const type of WIDGET_TYPE_IDS) {
    if (!seen.has(type)) out.push(createWidget(type));
  }

  return out;
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
    // value away would take the widget list with it.
    width:
      typeof v.width === 'number' && Number.isFinite(v.width)
        ? clampDashboardWidth(v.width)
        : DASHBOARD_DEFAULTS.width,
    // The legacy branch is keyed on the ABSENCE of `widgets` rather than on the
    // presence of `order`, so a half-written key - one this app wrote, then a
    // hand edit stripped a field from - still lands on the modern shape.
    widgets:
      v.widgets === undefined
        ? migrateLegacyWidgets(v.order, v.disabled)
        : normalizeWidgets(v.widgets),
  };
}

export const dashboardStore = createPreferenceStore(
  'inwire.dashboard',
  normalizeDashboard,
  DASHBOARD_DEFAULTS,
);
