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
 * **`mode`, `width` and `enabled` are no longer here.** They described the
 * right-hand column - three-way full/icons/hidden, a width that morphed into a
 * 48px rail, and a per-widget switch - and they moved to `inwire.dock` with it.
 * `scripts/session/dock.ts` covers them now, including the one-time migration out
 * of this key. What is left here is what a widget IS: its type, its name and its
 * config, and the postcondition below that the list is always a permutation of
 * the registry.
 *
 * Note this file imports from services/dashboardPrefs and not from the widget
 * registry. The registry imports GeoMap, which imports maplibre-gl at module
 * scope; under tsx there is no browser for it to attach to. Keeping the types
 * and the validators in a plain module is what makes them testable at all.
 */
import {
  DASHBOARD_DEFAULTS,
  WIDGET_TYPES,
  WIDGET_TYPE_IDS,
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
  widgets.map((w) => w.type);

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
    ['geo:-', 'timeseries:metric', 'breakdown:metric', 'sizes:-', 'talkers:view',
      // `counts` has no options at all: it is two numbers and a percentage,
      // and there is nothing about that to configure.
      'counts:-'],
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
  { type: 'talkers', config: { view: 'flows', top: 5 } },
);

check(
  'an untitled widget shows its type name',
  widgetTitle({ type: 'breakdown', config: {} }),
  'Protocol breakdown',
);

// --- The repairs ------------------------------------------------------------

check(
  'a well-formed list is left in the order it was given',
  shape(normalizeWidgets([
    { type: 'sizes' },
    { type: 'geo' },
  ])),
  ['sizes', 'geo', 'timeseries', 'breakdown', 'talkers', 'counts'],
);

check(
  'a type this build does not have is dropped',
  shape(normalizeWidgets([{ type: 'weather' }, { type: 'sizes' }])).slice(0, 2),
  ['sizes', 'geo'],
);

check(
  'a repeated type collapses to its first appearance',
  shape(normalizeWidgets([
    { type: 'talkers' },
    { type: 'talkers' },
    { type: 'talkers' },
  ])).slice(0, 1),
  ['talkers'],
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
  ['config', 'type'],
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
    'counts',
  ]);
}

check(
  'a reordered legacy list keeps the order the user put it in',
  shape(normalizeDashboard({ order: ['talkers', 'geo', 'protocols', 'timeline'] })!.widgets),
  ['talkers', 'geo', 'breakdown', 'timeseries', 'sizes', 'counts'],
);

// Which widgets were switched off is `inwire.dock`'s answer now, and
// `scripts/session/dock.ts` asserts that the migration carries it. What this
// one still guards is that a legacy `disabled` list does not disturb the ORDER.
check(
  'a legacy disabled list leaves the order alone',
  shape(normalizeDashboard({ order: ['geo', 'timeline'], disabled: ['timeline'] })!.widgets),
  ['geo', 'timeseries', 'breakdown', 'sizes', 'talkers', 'counts'],
);

check(
  'a repeated legacy id is taken once',
  shape(normalizeDashboard({ order: ['geo', 'geo', 'geo', 'talkers'] })!.widgets),
  ['geo', 'talkers', 'timeseries', 'breakdown', 'sizes', 'counts'],
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
    widgets: [{ type: 'sizes', config: {} }],
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
      { id: 'talkers', type: 'talkers', config: { view: 'hosts', top: 8 } },
      { id: 'breakdown', type: 'breakdown', config: {} },
      { id: 'breakdown-2', type: 'breakdown', config: { chart: 'donut' } },
    ],
  });
  check('the builder build migrates, deduped and in order', shape(out!.widgets), [
    'talkers',
    'breakdown',
    'geo',
    'timeseries',
    'sizes',
    'counts',
  ]);
  check('...keeping the FIRST of a duplicated type, settings and all',
    out!.widgets[1].config, { metric: 'packets', chart: 'bars', top: 5 });
  check('...and the settings of the ones that were not duplicated',
    out!.widgets[0].config, { view: 'hosts', top: 8 });
}

// --- The whole preference ---------------------------------------------------

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
