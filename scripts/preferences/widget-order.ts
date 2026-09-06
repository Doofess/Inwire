/**
 * Assertion tests for the dashboard's widget list.
 *
 *   npx tsx scripts/preferences/widget-order.ts
 *
 * The dashboard holds exactly one widget of each type, in an order the user
 * chooses. Nothing can be added and nothing can be deleted, so the validator's
 * whole job is to turn any stored value into a permutation of the registry.
 *
 * That postcondition is what most of this file asserts, because everything
 * downstream depends on it. React keys the column by type; two entries sharing
 * one would render as a single widget and lose whichever was second. And a
 * second `geo` would be a second MapLibre instance - a second WebGL context, a
 * second tile stream, a second set of pins fed by one session - which is a real
 * cost rather than a cosmetic repeat.
 *
 * Two stored shapes have to migrate, and both have shipped:
 *
 *   - `{ order: id[], disabled: id[] }` over a fixed five, where two of the ids
 *     no longer exist under those names (`timeline`, `protocols`).
 *   - `{ widgets: [{ id, type, ... }] }` from the short-lived build that let the
 *     user create widgets, which could contain the same type twice.
 *
 * Note this file imports from services/dashboardPrefs and not from the widget
 * registry. The registry imports GeoMap, which imports maplibre-gl at module
 * scope; under tsx there is no browser for it to attach to. Keeping the types
 * and the validators in a plain module is what makes them testable at all.
 */
import {
  DASHBOARD_MAX_WIDTH,
  DASHBOARD_MORPH_WIDTH,
  DASHBOARD_RAIL_WIDTH,
  DASHBOARD_DEFAULTS,
  WIDGET_TYPES,
  WIDGET_TYPE_IDS,
  clampDashboardWidth,
  createWidget,
  defaultConfig,
  defaultWidgets,
  headerOption,
  normalizeConfig,
  normalizeDashboard,
  normalizeWidgets,
  widgetTitle,
  type WidgetInstance,
} from '../../src/services/dashboardPrefs';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

/** The shape assertions care about, without the config noise. */
const shape = (widgets: WidgetInstance[]) =>
  widgets.map((w) => `${w.type}${w.enabled ? '' : ':off'}`);

const ALL = [...WIDGET_TYPE_IDS];

// --- The catalogue itself ---------------------------------------------------

check(
  'every type id has a spec, and every spec is filed under its own id',
  WIDGET_TYPE_IDS.filter((id) => WIDGET_TYPES[id]?.id !== id),
  [],
);

check(
  'every type has a label and a one-line description',
  WIDGET_TYPE_IDS.filter((id) => !WIDGET_TYPES[id].label || !WIDGET_TYPES[id].description),
  [],
);

{
  // A choice whose fallback is not one of its own choices would mean a fresh
  // widget renders a chart type its control cannot show as selected.
  const broken: string[] = [];
  for (const id of WIDGET_TYPE_IDS) {
    for (const option of WIDGET_TYPES[id].options) {
      if (option.kind === 'choice') {
        if (!option.choices.some((c) => c.value === option.fallback)) broken.push(`${id}.${option.id}`);
        if (option.choices.length < 2) broken.push(`${id}.${option.id} (only one choice)`);
      } else if (option.kind === 'text') {
        if (option.fallback.length > option.maxLength) broken.push(`${id}.${option.id} (fallback too long)`);
      } else if (option.fallback < option.min || option.fallback > option.max) {
        broken.push(`${id}.${option.id}`);
      }
    }
  }
  check('every option fallback is a value that option actually allows', broken, []);
}

{
  // Two options sharing an id on one type would silently overwrite each other
  // in the config bag, which is a flat record.
  const clashes = WIDGET_TYPE_IDS.filter((id) => {
    const ids = WIDGET_TYPES[id].options.map((o) => o.id);
    return new Set(ids).size !== ids.length;
  });
  check('no type declares two options under one id', clashes, []);
}

{
  // A 352px card header holds a title and ONE control. A second one does not
  // wrap, it pushes the title into an ellipsis - so this is a layout invariant
  // rather than a style preference, and it is the sort that gets broken by
  // adding an option to a type without looking at the card.
  const crowded = WIDGET_TYPE_IDS.filter(
    (id) => WIDGET_TYPES[id].options.filter((o) => o.kind === 'choice' && o.inHeader).length > 1,
  );
  check('no type puts two controls in its card header', crowded, []);

  check(
    'the header control is the one you switch while reading, not while configuring',
    WIDGET_TYPE_IDS.map((id) => `${id}:${headerOption(id)?.id ?? '-'}`),
    ['geo:-', 'timeseries:metric', 'breakdown:metric', 'sizes:-', 'talkers:view'],
  );

  const stepper = WIDGET_TYPE_IDS.filter((id) =>
    WIDGET_TYPES[id].options.some((o) => o.kind === 'count' && 'inHeader' in o),
  );
  check('a count option is never offered in a card header', stepper, []);
}

// --- Config repair ----------------------------------------------------------

check(
  'a config is filled in from the type when it is missing entirely',
  normalizeConfig('breakdown', undefined),
  { metric: 'packets', chart: 'bars', top: 5 },
);

check(
  'a choice this build does not offer falls back',
  normalizeConfig('breakdown', { chart: 'sunburst', metric: 'bytes', top: 9 }),
  { metric: 'bytes', chart: 'bars', top: 9 },
);

check(
  'a count is clamped into range rather than dropped',
  [
    normalizeConfig('breakdown', { top: 999 }).top,
    normalizeConfig('breakdown', { top: -4 }).top,
    normalizeConfig('breakdown', { top: 7.6 }).top,
    normalizeConfig('breakdown', { top: 'lots' }).top,
    normalizeConfig('breakdown', { top: NaN }).top,
  ],
  [20, 3, 8, 5, 5],
);

check(
  'fields the type does not declare are dropped, not carried',
  // Phrased as "the undeclared keys are absent" rather than "the result is
  // empty": every surviving widget type declares at least one option, so an
  // empty result would only be asserting that this type has none.
  Object.keys(normalizeConfig('talkers', { chart: 'donut', nonsense: true }))
    .filter((k) => k === 'chart' || k === 'nonsense'),
  [],
);

{
  // Every type's own defaults must survive its own normalizer untouched, or
  // every load quietly rewrites the key.
  const unstable = WIDGET_TYPE_IDS.filter(
    (id) => JSON.stringify(normalizeConfig(id, defaultConfig(id))) !== JSON.stringify(defaultConfig(id)),
  );
  check('a default config is a fixed point of its own normalizer', unstable, []);
}

// --- The fresh dashboard ----------------------------------------------------

check('a fresh dashboard is every widget, in registry order, on', shape(defaultWidgets()), ALL);

check(
  'a fresh dashboard has each widget exactly ONCE',
  defaultWidgets().length,
  WIDGET_TYPE_IDS.length,
);

check(
  '...and the stored defaults agree with it',
  shape(DASHBOARD_DEFAULTS.widgets),
  shape(defaultWidgets()),
);

check(
  'the stored defaults are a stable reference, not a fresh list per read',
  DASHBOARD_DEFAULTS.widgets === DASHBOARD_DEFAULTS.widgets,
  true,
);

check(
  'a new widget of a type carries that type defaults',
  createWidget('talkers'),
  { type: 'talkers', enabled: true, config: { view: 'flows', top: 5 } },
);

check(
  'an untitled widget shows its type name',
  widgetTitle({ type: 'breakdown', enabled: true, config: {} }),
  'Protocol breakdown',
);

// --- The repairs ------------------------------------------------------------

check(
  'a well-formed list is left in the order it was given',
  shape(normalizeWidgets([
    { type: 'sizes', enabled: true },
    { type: 'geo', enabled: false },
  ])),
  ['sizes', 'geo:off', 'timeseries', 'breakdown', 'talkers'],
);

check(
  'a type this build does not have is dropped',
  shape(normalizeWidgets([{ type: 'weather' }, { type: 'sizes' }])).slice(0, 2),
  ['sizes', 'geo'],
);

check(
  'a repeated type collapses to its first appearance',
  shape(normalizeWidgets([
    { type: 'talkers', enabled: false },
    { type: 'talkers', enabled: true },
    { type: 'talkers', enabled: true },
  ])).slice(0, 1),
  ['talkers:off'],
);

check(
  'a second map is dropped - two MapLibre instances is the hazard this guards',
  normalizeWidgets([{ type: 'geo' }, { type: 'geo' }, { type: 'geo' }])
    .filter((w) => w.type === 'geo').length,
  1,
);

check(
  'ids from the build that had them are ignored, not carried',
  Object.keys(normalizeWidgets([{ id: 'talkers-7', type: 'talkers' }])[0]).sort(),
  ['config', 'enabled', 'type'],
);

check(
  'a widget with no enabled field is shown, not hidden',
  normalizeWidgets([{ type: 'sizes' }])[0].enabled,
  true,
);

check(
  'an empty list is filled in - there is no way to have deleted anything',
  shape(normalizeWidgets([])),
  ALL,
);

check(
  'a title is trimmed and capped, and a blank one is dropped',
  normalizeWidgets([
    { type: 'sizes', title: '   ' },
    { type: 'geo', title: '  Egress  ' },
    { type: 'talkers', title: 'x'.repeat(90) },
  ]).slice(0, 3).map((w) => w.title ?? null),
  [null, 'Egress', 'x'.repeat(40)],
);

// --- Junk of every shape ----------------------------------------------------

for (const junk of [null, undefined, 'geo', 7, {}, [[]], [null], [{ id: 'geo' }], [{ type: 9 }]]) {
  check(
    `${JSON.stringify(junk) ?? 'undefined'} yields the full set, never a throw`,
    shape(normalizeWidgets(junk)),
    ALL,
  );
}

// --- The property that has to hold for every input --------------------------

{
  // Stated once as a property rather than as a handful of examples: whatever
  // goes in, what comes out is a permutation of the registry, each type exactly
  // once. Every rendering assumption downstream depends on exactly that.
  const adversarial: unknown[] = [
    null, undefined, [], {}, 'geo', 42, true,
    [{ type: 'geo' }, { type: 'geo' }, { type: 'geo' }],
    [{ type: 'nope' }, { type: 'also-nope' }],
    ALL.map((t) => ({ type: t })),
    [...ALL, ...ALL].map((t) => ({ type: t })),
    [...ALL].reverse().map((t) => ({ type: t })),
    [{ type: 'breakdown', config: 'not-an-object' }],
    [null, { type: 'talkers' }, undefined, { type: 'talkers' }],
    // The intermediate build's shape, duplicates and all.
    [{ id: 'geo', type: 'geo' }, { id: 'geo-2', type: 'geo' }, { id: 'talkers', type: 'talkers' }],
  ];
  const bad = adversarial.filter((input) => {
    const out = normalizeWidgets(input);
    const types = out.map((w) => w.type);
    return (
      types.length !== ALL.length ||
      new Set(types).size !== types.length ||
      !types.every((t) => (ALL as string[]).includes(t))
    );
  });
  check('every input yields each type exactly once', bad.length, 0);
}

// --- Migration from the fixed five ------------------------------------------

{
  // The upgrade everyone actually performs: an untouched dashboard from the
  // build before any of this. Same widgets, same order, two ids translated,
  // and the one type that build did not have appended rather than lost.
  const out = normalizeDashboard({
    mode: 'full',
    width: 512,
    order: ['geo', 'timeline', 'protocols', 'talkers'],
    disabled: [],
  });
  check('a legacy order keeps its order, with the renamed types translated', shape(out!.widgets), [
    'geo',
    'timeseries',
    'breakdown',
    'talkers',
    'sizes',
  ]);
  check('...at the width it was stored at', out!.width, 512);
}

check(
  'a reordered legacy list keeps the order the user put it in',
  shape(normalizeDashboard({ order: ['talkers', 'geo', 'protocols', 'timeline'] })!.widgets),
  ['talkers', 'geo', 'breakdown', 'timeseries', 'sizes'],
);

check(
  'legacy widgets that were switched off are still switched off',
  shape(normalizeDashboard({ order: ['geo', 'timeline'], disabled: ['timeline'] })!.widgets),
  ['geo', 'timeseries:off', 'breakdown', 'sizes', 'talkers'],
);

check(
  'a repeated legacy id is taken once',
  shape(normalizeDashboard({ order: ['geo', 'geo', 'geo', 'talkers'] })!.widgets),
  ['geo', 'talkers', 'timeseries', 'breakdown', 'sizes'],
);

check(
  'migrated widgets carry their type defaults, not an empty config',
  normalizeDashboard({ order: ['protocols'] })!.widgets[0].config,
  { metric: 'packets', chart: 'bars', top: 5 },
);

{
  // A dashboard already on the new shape must not be re-migrated: the presence
  // of `widgets` is what decides, so a stale `order` sitting beside it - which
  // is exactly what one upgrade-then-downgrade leaves behind - is ignored.
  const out = normalizeDashboard({
    widgets: [{ type: 'sizes', enabled: true, config: {} }],
    order: ['geo', 'timeline', 'protocols', 'talkers'],
  });
  check('a modern list wins over a stale legacy order beside it', shape(out!.widgets)[0], 'sizes');
}

{
  // The intermediate build stored generated ids and allowed duplicates. Its
  // lists have to arrive intact, deduped, in the order they were in.
  const out = normalizeDashboard({
    mode: 'full',
    width: 384,
    widgets: [
      { id: 'talkers', type: 'talkers', enabled: true, config: { view: 'hosts', top: 8 } },
      { id: 'breakdown', type: 'breakdown', enabled: true, config: {} },
      { id: 'breakdown-2', type: 'breakdown', enabled: true, config: { chart: 'donut' } },
    ],
  });
  check('the builder build migrates, deduped and in order', shape(out!.widgets), [
    'talkers',
    'breakdown',
    'geo',
    'timeseries',
    'sizes',
  ]);
  check('...keeping the FIRST of a duplicated type, settings and all',
    out!.widgets[1].config, { metric: 'packets', chart: 'bars', top: 5 });
  check('...and the settings of the ones that were not duplicated',
    out!.widgets[0].config, { view: 'hosts', top: 8 });
}

// --- The whole preference ---------------------------------------------------

{
  // The sibling-survival property: a broken list must not take `mode` down with
  // it, or a corrupt widget silently un-minimizes the dashboard.
  const out = normalizeDashboard({ mode: 'icons', widgets: 'nonsense' });
  check('a broken list does not discard the mode beside it',
    [out!.mode, shape(out!.widgets)], ['icons', ALL]);
}

{
  const out = normalizeDashboard({ mode: 'sideways', widgets: [{ type: 'sizes' }] });
  check('an unknown mode falls back while the list survives',
    [out!.mode, shape(out!.widgets)[0]], [DASHBOARD_DEFAULTS.mode, 'sizes']);
}

check('a non-object is rejected outright so the caller uses defaults', normalizeDashboard('icons'), null);

// --- The dragged width ------------------------------------------------------

{
  // Clamped rather than rejected, and the reason is the same as everywhere else
  // on this tab: a width stored on a 34-inch monitor must not leave the column
  // occupying most of a laptop screen, but discarding it would take the whole
  // widget list with it.
  check('a width wider than the maximum is clamped',
    normalizeDashboard({ width: 5000 })?.width, DASHBOARD_MAX_WIDTH);
  check('...and one below the morph point is clamped up to it',
    normalizeDashboard({ width: 10 })?.width, DASHBOARD_MORPH_WIDTH);
  // 48 is the RAIL's width, and it is not a column width. Storing it as one
  // would mean expanding the rail produced a 48px column - a dashboard that
  // appears to refuse to open.
  check('the rail width is not a legal column width',
    clampDashboardWidth(DASHBOARD_RAIL_WIDTH), DASHBOARD_MORPH_WIDTH);
}

check('a width that is not a number defaults rather than throwing',
  [
    normalizeDashboard({ width: 'wide' })?.width,
    normalizeDashboard({ width: NaN })?.width,
    normalizeDashboard({ width: Infinity })?.width,
    normalizeDashboard({ width: null })?.width,
  ],
  [
    DASHBOARD_DEFAULTS.width, DASHBOARD_DEFAULTS.width,
    DASHBOARD_DEFAULTS.width, DASHBOARD_DEFAULTS.width,
  ]);

{
  // The morph point has to sit inside the legal range, or there is a band of
  // widths the column can be dragged to and never stored at.
  check('the morph point is the narrowest column, not a value below it',
    DASHBOARD_MORPH_WIDTH < DASHBOARD_MAX_WIDTH && DASHBOARD_RAIL_WIDTH < DASHBOARD_MORPH_WIDTH,
    true);
  check('a valid width survives a round trip unchanged',
    normalizeDashboard({ width: 421 })?.width, 421);
}

// --- Round trip -------------------------------------------------------------

{
  // What the app writes, the app must read back unchanged - otherwise every
  // load quietly rewrites the key and the debounced writer never settles.
  //
  // Stated as idempotence rather than as equality against a hand-built list,
  // and the distinction is not pedantic: `preferenceStore.set` compares with
  // JSON.stringify, so KEY ORDER is part of "unchanged". Comparing against a
  // literal would only prove the literal was typed in the writer's field order.
  const built = defaultWidgets();
  built[1].title = 'Egress';
  built[2].enabled = false;
  built[2].config = { ...built[2].config, chart: 'donut', metric: 'bytes' };

  const once = normalizeDashboard(JSON.parse(JSON.stringify({ mode: 'icons', width: 421, widgets: built })));
  const twice = normalizeDashboard(JSON.parse(JSON.stringify(once)));
  check('normalizing an already-normalized dashboard changes nothing at all', twice, once);

  // ...and that the round trip actually kept everything, rather than settling
  // on some other list that would also be idempotent.
  check('the round trip keeps every widget, its name and its switch',
    shape(once!.widgets), ['geo', 'timeseries', 'breakdown:off', 'sizes', 'talkers']);
  check('...including the rename', once!.widgets[1].title, 'Egress');
  check('...including the settings', once!.widgets[2].config,
    { metric: 'bytes', chart: 'donut', top: 5 });
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
