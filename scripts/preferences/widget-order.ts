/**
 * Assertion tests for the dashboard's widget order.
 *
 *   npx tsx scripts/preferences/widget-order.ts
 *
 * This validator repairs rather than rejects, because there is no such thing as
 * an order it cannot fix and rejecting would throw away the perfectly good
 * `mode` sitting beside it in the same key.
 *
 * The duplicate case is the one with teeth. The dashboard renders one component
 * per entry, so a repeated `geo` mounts TWO MapLibre instances - two WebGL
 * contexts, two tile streams - from a value anyone can produce by hand-editing
 * localStorage.
 *
 * Note this file imports from services/dashboardPrefs and not from the widget
 * registry. The registry imports GeoMap, which imports maplibre-gl at module
 * scope; under tsx there is no browser for it to attach to. Keeping the ids and
 * the validator in a plain module is what makes them testable at all.
 */
import {
  DASHBOARD_MAX_WIDTH,
  DASHBOARD_MORPH_WIDTH,
  DASHBOARD_RAIL_WIDTH,
  clampDashboardWidth,
  DASHBOARD_DEFAULTS,
  DASHBOARD_WIDGET_IDS,
  normalizeDashboard,
  normalizeWidgetOrder,
  normalizeWidgetSet,
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

const ALL = [...DASHBOARD_WIDGET_IDS];

// --- The three repairs ------------------------------------------------------

check('a complete order is left alone', normalizeWidgetOrder(ALL), ALL);

check(
  'a reordered list keeps the order it was given',
  normalizeWidgetOrder(['alerts', 'geo', 'talkers', 'protocols', 'timeline']),
  ['alerts', 'geo', 'talkers', 'protocols', 'timeline'],
);

check(
  'an id this build does not have is dropped',
  normalizeWidgetOrder(['geo', 'weather', 'alerts']),
  ['geo', 'alerts', 'timeline', 'protocols', 'talkers'],
);

check(
  'ids the stored order predates are appended in registry order',
  normalizeWidgetOrder(['alerts']),
  ['alerts', 'geo', 'timeline', 'protocols', 'talkers'],
);

check(
  'a duplicate is kept once, at its first position',
  normalizeWidgetOrder(['geo', 'alerts', 'geo', 'geo']),
  ['geo', 'alerts', 'timeline', 'protocols', 'talkers'],
);

// --- Junk of every shape ----------------------------------------------------

for (const junk of [null, undefined, 'geo', 7, {}, [[]], [null], [{ id: 'geo' }]]) {
  check(`${JSON.stringify(junk) ?? 'undefined'} yields the full default order`,
    normalizeWidgetOrder(junk), ALL);
}

// --- The property that has to hold for every input --------------------------

{
  // Stated once as a property rather than as a handful of examples: whatever
  // goes in, what comes out must be a permutation of the registry. Every
  // rendering assumption downstream depends on exactly that.
  const adversarial: unknown[] = [
    null, undefined, [], {}, 'geo', 42, true,
    ['geo', 'geo', 'geo'],
    ['nope', 'also-nope'],
    [...ALL, ...ALL],
    [...ALL].reverse(),
    ['alerts', null, 'geo', undefined, 'talkers', 'talkers'],
  ];
  const bad = adversarial.filter((input) => {
    const out = normalizeWidgetOrder(input);
    return (
      out.length !== ALL.length ||
      new Set(out).size !== out.length ||
      !out.every((id) => (ALL as string[]).includes(id))
    );
  });
  check('every input produces a permutation of the registry, exactly once each', bad.length, 0);
}

// --- The disabled set -------------------------------------------------------

check('an unknown id is dropped from the disabled set', normalizeWidgetSet(['geo', 'nope']), ['geo']);
check('the disabled set is deduped', normalizeWidgetSet(['geo', 'geo']), ['geo']);
check(
  'the disabled set is stored in registry order, not click order',
  normalizeWidgetSet(['alerts', 'geo']),
  ['geo', 'alerts'],
);
check('junk yields an empty disabled set', normalizeWidgetSet('geo'), []);

// --- The whole preference ---------------------------------------------------

{
  // The sibling-survival property again: a broken order must not take `mode`
  // down with it, or a corrupt list silently un-minimizes the dashboard.
  const out = normalizeDashboard({ mode: 'icons', order: 'nonsense', disabled: null });
  check('a broken order does not discard the mode beside it', out, {
    mode: 'icons',
    width: DASHBOARD_DEFAULTS.width,
    order: ALL,
    disabled: [],
  });
}

{
  const out = normalizeDashboard({ mode: 'sideways', order: ['alerts'] });
  check('an unknown mode falls back while the order survives', out, {
    mode: DASHBOARD_DEFAULTS.mode,
    width: DASHBOARD_DEFAULTS.width,
    order: ['alerts', 'geo', 'timeline', 'protocols', 'talkers'],
    disabled: [],
  });
}

check('a non-object is rejected outright so the caller uses defaults',
  normalizeDashboard('icons'), null);

// --- The dragged width ------------------------------------------------------

{
  // Clamped rather than rejected, and the reason is the same as everywhere else
  // on this tab: a width stored on a 34-inch monitor must not leave the column
  // occupying most of a laptop screen, but discarding it would take the widget
  // order and the disabled set with it.
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

{
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
}

{
  // The morph point has to sit inside the legal range, or there is a band of
  // widths the column can be dragged to and never stored at.
  check('the morph point is the narrowest column, not a value below it',
    DASHBOARD_MORPH_WIDTH < DASHBOARD_MAX_WIDTH
      && DASHBOARD_RAIL_WIDTH < DASHBOARD_MORPH_WIDTH,
    true);
  check('a valid width survives a round trip unchanged',
    normalizeDashboard({ width: 421 })?.width, 421);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
