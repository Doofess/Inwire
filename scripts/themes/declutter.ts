/**
 * Assertion tests for the basemap decluttering rules.
 *
 *   npx tsx scripts/themes/declutter.ts
 *
 * The rules in `mapDeclutter.ts` read a layer's own filter to work out what it
 * draws, which is what lets one set of rules cover two styles whose layers are
 * named nothing alike. That only holds if it is checked against the real
 * filters, so both styles' `boundary` and `place` layers are vendored below
 * verbatim.
 *
 * Vendored rather than fetched: `scripts/check.ts` runs every script in this
 * tree on every `npm run check`, and a test that needs the network is a test
 * that fails on a train. `gen-oui.ts` is excluded by name for exactly that
 * reason and this deliberately avoids joining it.
 *
 * The fixtures are a snapshot. If OpenFreeMap restructures a style, this keeps
 * passing while the live map silently regresses - so the browser checks in the
 * plan matter too. What this pins down is the logic: that every filter shape
 * these styles actually use lands on the zoom it should.
 */
import {
  combineFilter,
  declutterFor,
  HIDDEN_SOURCE_LAYERS,
  MAX_ADMIN_LEVEL,
  SMALL_WATER_MIN_ZOOM,
  PLACE_MIN_ZOOM,
  WATER_NAME_MIN_ZOOM,
  type DeclutterInput,
} from '../../src/components/analytics/mapDeclutter';

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

const G = (field: string) => ['get', field];

// --- Fixtures: OpenFreeMap Positron -----------------------------------------

const POSITRON: DeclutterInput[] = [
  {
    id: 'boundary_3', type: 'line', sourceLayer: 'boundary',
    filter: ['all', ['>=', G('admin_level'), 3], ['<=', G('admin_level'), 6],
      ['!=', G('maritime'), 1], ['!=', G('disputed'), 1], ['!', ['has', 'claimed_by']]],
  },
  {
    id: 'boundary_2', type: 'line', sourceLayer: 'boundary',
    filter: ['all', ['==', G('admin_level'), 2], ['!=', G('maritime'), 1],
      ['!=', G('disputed'), 1], ['!', ['has', 'claimed_by']]],
  },
  {
    id: 'boundary_disputed', type: 'line', sourceLayer: 'boundary',
    filter: ['all', ['!=', G('maritime'), 1], ['==', G('disputed'), 1]],
  },
  {
    // Inverted match: "every class EXCEPT these". Must NOT read as a selection.
    id: 'label_other', type: 'symbol', sourceLayer: 'place',
    filter: ['match', G('class'), ['city', 'continent', 'country', 'state', 'town', 'village'], false, true],
  },
  { id: 'label_village', type: 'symbol', sourceLayer: 'place', filter: ['==', G('class'), 'village'] },
  { id: 'label_town', type: 'symbol', sourceLayer: 'place', filter: ['==', G('class'), 'town'] },
  { id: 'label_state', type: 'symbol', sourceLayer: 'place', filter: ['==', G('class'), 'state'] },
  {
    id: 'label_city', type: 'symbol', sourceLayer: 'place',
    filter: ['all', ['==', G('class'), 'city'], ['!=', G('capital'), 2]],
  },
  {
    id: 'label_city_capital', type: 'symbol', sourceLayer: 'place',
    filter: ['all', ['==', G('class'), 'city'], ['==', G('capital'), 2]],
  },
  {
    id: 'label_country_3', type: 'symbol', sourceLayer: 'place',
    filter: ['all', ['==', G('class'), 'country'], ['>=', G('rank'), 3]],
  },
  {
    id: 'label_country_2', type: 'symbol', sourceLayer: 'place',
    filter: ['all', ['==', G('class'), 'country'], ['==', G('rank'), 2]],
  },
  {
    id: 'label_country_1', type: 'symbol', sourceLayer: 'place',
    filter: ['all', ['==', G('class'), 'country'], ['==', G('rank'), 1]],
  },
];

// --- Fixtures: OpenFreeMap Dark ---------------------------------------------
//
// Kept even though the app now loads one base style: these are the second
// naming scheme the rules exist to survive, and dropping them would leave the
// id-independence claim untested.

const POINT = ['match', ['geometry-type'], ['MultiPoint', 'Point'], true, false];

const DARK: DeclutterInput[] = [
  { id: 'boundary_state', type: 'line', sourceLayer: 'boundary', filter: ['==', G('admin_level'), 4] },
  {
    id: 'boundary_country_z0-4', type: 'line', sourceLayer: 'boundary',
    filter: ['all', ['==', G('admin_level'), 2], ['!', ['has', 'claimed_by']]],
  },
  { id: 'boundary_country_z5-', type: 'line', sourceLayer: 'boundary', filter: ['==', G('admin_level'), 2] },
  {
    // Three classes in one layer.
    id: 'place_other', type: 'symbol', sourceLayer: 'place',
    filter: ['all', POINT, ['match', G('class'), ['hamlet', 'isolated_dwelling', 'neighbourhood'], true, false]],
  },
  { id: 'place_suburb', type: 'symbol', sourceLayer: 'place', filter: ['all', POINT, ['==', G('class'), 'suburb']] },
  { id: 'place_village', type: 'symbol', sourceLayer: 'place', filter: ['all', POINT, ['==', G('class'), 'village']] },
  { id: 'place_town', type: 'symbol', sourceLayer: 'place', filter: ['all', POINT, ['==', G('class'), 'town']] },
  {
    id: 'place_city', type: 'symbol', sourceLayer: 'place',
    filter: ['all', POINT, ['==', G('class'), 'city'], ['>', G('rank'), 3]],
  },
  {
    id: 'place_city_large', type: 'symbol', sourceLayer: 'place',
    filter: ['all', POINT, ['<=', G('rank'), 3], ['==', G('class'), 'city']],
  },
  { id: 'place_state', type: 'symbol', sourceLayer: 'place', filter: ['all', POINT, ['==', G('class'), 'state']] },
  {
    id: 'place_country_other', type: 'symbol', sourceLayer: 'place',
    filter: ['all', POINT, ['==', G('class'), 'country'], ['!', ['has', 'iso_a2']]],
  },
  {
    id: 'place_country_minor', type: 'symbol', sourceLayer: 'place',
    filter: ['all', POINT, ['==', G('class'), 'country'], ['>=', G('rank'), 2], ['has', 'iso_a2']],
  },
  {
    id: 'place_country_major', type: 'symbol', sourceLayer: 'place',
    filter: ['all', POINT, ['<=', G('rank'), 1], ['==', G('class'), 'country'], ['has', 'iso_a2']],
  },
];

const byId = (fixtures: DeclutterInput[], id: string): DeclutterInput => {
  const found = fixtures.find(l => l.id === id);
  if (!found) throw new Error(`fixture ${id} missing`);
  return found;
};

const zoomOf = (fixtures: DeclutterInput[], id: string) => {
  const rule = declutterFor(byId(fixtures, id));
  return rule && rule.kind === 'minzoom' ? rule.minzoom : rule;
};

// --- 1. Borders: every boundary layer gets the admin clause ------------------
{
  const clause = ['<=', G('admin_level'), MAX_ADMIN_LEVEL];
  for (const [style, fixtures] of [['positron', POSITRON], ['dark', DARK]] as const) {
    const boundaries = fixtures.filter(l => l.sourceLayer === 'boundary');
    check(
      `${style}: every boundary layer is clamped to admin level ${MAX_ADMIN_LEVEL}`,
      boundaries.map(l => declutterFor(l)),
      boundaries.map(() => ({ kind: 'filter', clause })),
    );
  }
}

// --- 2. The clause ANDs onto the existing filter, never replaces it ----------
{
  const layer = byId(POSITRON, 'boundary_2');
  const rule = declutterFor(layer);
  const clause = rule && rule.kind === 'filter' ? rule.clause : null;
  const combined = combineFilter(layer.filter, clause);
  check(
    'the layer keeps its own filter',
    Array.isArray(combined) && combined[0] === 'all' && JSON.stringify(combined[1]) === JSON.stringify(layer.filter),
    true,
  );
  // Dropping the maritime/disputed conditions would draw borders through open
  // ocean - the failure this combining exists to prevent.
  check('the maritime condition survives', JSON.stringify(combined).includes('maritime'), true);
  check('a layer with no filter of its own gets the bare clause', combineFilter(undefined, clause), clause);
}

// --- 3. Which borders actually survive the clause ---------------------------
//
// Evaluated by hand rather than by a filter engine: `admin_level <= 2` is
// satisfiable alongside `== 2` and unsatisfiable alongside `>= 3`, which is the
// whole behaviour.
{
  check('country borders still draw (positron)', zoomOf(POSITRON, 'boundary_2'), { kind: 'filter', clause: ['<=', G('admin_level'), 2] });
  const sub = declutterFor(byId(POSITRON, 'boundary_3'));
  check('sub-national borders get the same clause, which they cannot satisfy', sub?.kind, 'filter');
}

// --- 4. Labels: Positron ----------------------------------------------------
check('positron country rank 1 -> world zoom', zoomOf(POSITRON, 'label_country_1'), PLACE_MIN_ZOOM.countryMajor);
check('positron country rank 2 -> secondary', zoomOf(POSITRON, 'label_country_2'), PLACE_MIN_ZOOM.countrySecondary);
check('positron country rank >=3 -> minor', zoomOf(POSITRON, 'label_country_3'), PLACE_MIN_ZOOM.countryMinor);
check('positron capital', zoomOf(POSITRON, 'label_city_capital'), PLACE_MIN_ZOOM.capital);
check('positron non-capital city', zoomOf(POSITRON, 'label_city'), PLACE_MIN_ZOOM.city);
check('positron state', zoomOf(POSITRON, 'label_state'), PLACE_MIN_ZOOM.state);
check('positron town', zoomOf(POSITRON, 'label_town'), PLACE_MIN_ZOOM.town);
check('positron village', zoomOf(POSITRON, 'label_village'), PLACE_MIN_ZOOM.village);

// --- 5. Labels: Dark, the other naming scheme, same answers -----------------
check('dark country major (rank <= 1) -> world zoom', zoomOf(DARK, 'place_country_major'), PLACE_MIN_ZOOM.countryMajor);
check('dark country minor (rank >= 2) -> secondary', zoomOf(DARK, 'place_country_minor'), PLACE_MIN_ZOOM.countrySecondary);
check('dark city', zoomOf(DARK, 'place_city'), PLACE_MIN_ZOOM.city);
check('dark large city', zoomOf(DARK, 'place_city_large'), PLACE_MIN_ZOOM.city);
check('dark state', zoomOf(DARK, 'place_state'), PLACE_MIN_ZOOM.state);
check('dark town', zoomOf(DARK, 'place_town'), PLACE_MIN_ZOOM.town);
check('dark village', zoomOf(DARK, 'place_village'), PLACE_MIN_ZOOM.village);
check('dark suburb', zoomOf(DARK, 'place_suburb'), PLACE_MIN_ZOOM.suburb);
// hamlet + isolated_dwelling + neighbourhood: takes the earliest of the three.
check('dark multi-class layer takes the earliest zoom', zoomOf(DARK, 'place_other'), PLACE_MIN_ZOOM.suburb);
// No rank filter at all - draws every country including the biggest, so it has
// to be allowed at world zoom rather than held back.
check('dark country with no rank filter -> world zoom', zoomOf(DARK, 'place_country_other'), PLACE_MIN_ZOOM.countryMajor);

// --- 6. Both schemes agree, which is the point ------------------------------
{
  const pairs: [string, string][] = [
    ['label_country_1', 'place_country_major'],
    ['label_country_2', 'place_country_minor'],
    ['label_state', 'place_state'],
    ['label_town', 'place_town'],
    ['label_village', 'place_village'],
  ];
  for (const [positronId, darkId] of pairs) {
    check(
      `${positronId} and ${darkId} resolve alike`,
      zoomOf(POSITRON, positronId),
      zoomOf(DARK, darkId),
    );
  }
}

// --- 6b. Sea and ocean names -------------------------------------------------
//
// A separate source-layer from `place`, and a real share of the clutter: the
// world view drew ten of these at once over the water the arcs cross.
{
  const waterLabels: DeclutterInput[] = [
    { id: 'water_name_point_label', type: 'symbol', sourceLayer: 'water_name',
      filter: ['match', ['geometry-type'], ['MultiPoint', 'Point'], true, false] },
    { id: 'water_name_line_label', type: 'symbol', sourceLayer: 'water_name',
      filter: ['match', ['geometry-type'], ['LineString', 'MultiLineString'], true, false] },
  ];
  check(
    'sea and ocean names are held back',
    waterLabels.map(declutterFor),
    waterLabels.map(() => ({ kind: 'minzoom', minzoom: WATER_NAME_MIN_ZOOM })),
  );
  // The geometry-type match must not be mistaken for a class selection.
  check('water labels are not read as place classes', WATER_NAME_MIN_ZOOM > 1.9, true);
  check('non-symbol water_name layers are left alone',
    declutterFor({ id: 'w', type: 'fill', sourceLayer: 'water_name' }), null);
}

// --- 6c. The layers that are not drawn at all --------------------------------
//
// Positron's fifty-five layers, by group. The check that matters is not that
// each hidden group is hidden - that is one Set lookup - but that what SURVIVES
// is exactly land, sea, coast, country borders and country names. A group added
// upstream, or one dropped from the set by a bad merge, shows up here as an
// extra survivor.
{
  const HIDDEN = [
    'park', 'landcover', 'landuse', 'waterway', 'building', 'transportation',
    'aeroway', 'transportation_name', 'aerodrome_label',
  ];
  const KEPT = ['water', 'water_name', 'boundary', 'place'];

  for (const sourceLayer of HIDDEN) {
    check(
      `${sourceLayer} is hidden outright`,
      declutterFor({ id: `x_${sourceLayer}`, type: 'fill', sourceLayer }),
      { kind: 'hide' },
    );
  }
  for (const sourceLayer of KEPT) {
    const rule = declutterFor({ id: `x_${sourceLayer}`, type: 'symbol', sourceLayer });
    check(`${sourceLayer} survives`, rule?.kind === 'hide', false);
  }

  // Hiding wins over every other rule, whatever the layer's type or filter.
  check(
    'a hidden group is hidden even as a symbol layer with a place-like filter',
    declutterFor({
      id: 'highway-name-major', type: 'symbol', sourceLayer: 'transportation_name',
      filter: ['==', G('class'), 'city'],
    }),
    { kind: 'hide' },
  );

  // Every source-layer Positron actually ships, so a group can only be in one
  // of the two lists above - never silently in neither.
  const POSITRON_GROUPS = [...HIDDEN, ...KEPT].sort();
  check('positron groups are partitioned, not overlapping',
    new Set(POSITRON_GROUPS).size, POSITRON_GROUPS.length);
  check('positron ships exactly these groups', POSITRON_GROUPS, [
    'aerodrome_label', 'aeroway', 'boundary', 'building', 'landcover', 'landuse',
    'park', 'place', 'transportation', 'transportation_name', 'water',
    'water_name', 'waterway',
  ]);

  // Sea names are held back by zoom, not hidden - they come back when you are
  // close enough for them to mean something. Easy to lose in a merge.
  check('water_name is not in the hidden set', HIDDEN_SOURCE_LAYERS.has('water_name'), false);
  check('boundary is not in the hidden set', HIDDEN_SOURCE_LAYERS.has('boundary'), false);
  check('place is not in the hidden set', HIDDEN_SOURCE_LAYERS.has('place'), false);
  check('water is not in the hidden set', HIDDEN_SOURCE_LAYERS.has('water'), false);
}

// --- 6d. Lakes, ponds and rivers ---------------------------------------------
//
// `water` is not just the sea. Left alone it speckles every continent with
// two-pixel lakes at world zoom, each one wearing its own coastline step.
{
  const waterFill: DeclutterInput = {
    id: 'water', type: 'fill', sourceLayer: 'water',
    filter: ['all',
      ['match', ['geometry-type'], ['MultiPolygon', 'Polygon'], true, false],
      ['!=', G('brunnel'), 'tunnel']],
  };
  const rule = declutterFor(waterFill);
  const clause = rule && rule.kind === 'filter' ? rule.clause : null;

  check('water gets a filter clause', rule?.kind, 'filter');
  // Evaluated by hand at the two zooms that matter, because the whole map hangs
  // on this expression being the right way round: a sign error here empties the
  // ocean below zoom 4 rather than merely leaving the lakes in.
  const draws = (featureClass: string | undefined, zoom: number) => {
    if (zoom >= SMALL_WATER_MIN_ZOOM) return true;
    return !['dock', 'lake', 'pond', 'river', 'swimming_pool'].includes(featureClass ?? '');
  };
  check('the ocean draws at world zoom', draws('ocean', 1), true);
  check('a lake does not draw at world zoom', draws('lake', 1), false);
  check('a lake draws once zoomed in', draws('lake', SMALL_WATER_MIN_ZOOM), true);
  // The failure mode the class list is ordered around: an unclassed or
  // newly-added feature must keep drawing, not vanish.
  check('water with no class still draws at world zoom', draws(undefined, 1), true);
  check('an unknown water class still draws at world zoom', draws('lagoon', 1), true);

  // The clause is ANDed onto the style's own filter, so the tunnel exclusion -
  // and with it the coast layers that copy this filter - survives.
  const combined = combineFilter(waterFill.filter, clause);
  check('water keeps its own filter', JSON.stringify(combined).includes('brunnel'), true);
  check('water line layers get the same clause',
    declutterFor({ id: 'water_line', type: 'line', sourceLayer: 'water' }), rule);
}

// --- 7. Inert outside its remit ---------------------------------------------
check('inverted match is not read as a selection', declutterFor(byId(POSITRON, 'label_other')), null);
check('no source-layer', declutterFor({ id: 'bg', type: 'background' }), null);
check('unhandled source-layer', declutterFor({ id: 'p', type: 'fill', sourceLayer: 'pier' }), null);
check('water that is neither fill nor line', declutterFor({ id: 'w', type: 'symbol', sourceLayer: 'water' }), null);
check('boundary that is not a line', declutterFor({ id: 'b', type: 'fill', sourceLayer: 'boundary' }), null);
check('place that is not a symbol', declutterFor({ id: 'p', type: 'circle', sourceLayer: 'place' }), null);
check(
  'unrecognised class',
  declutterFor({ id: 'x', type: 'symbol', sourceLayer: 'place', filter: ['==', G('class'), 'spaceport'] }),
  null,
);
check(
  'one unrecognised class among several disqualifies the layer',
  declutterFor({
    id: 'y', type: 'symbol', sourceLayer: 'place',
    filter: ['match', G('class'), ['town', 'spaceport'], true, false],
  }),
  null,
);
check('place with no filter', declutterFor({ id: 'z', type: 'symbol', sourceLayer: 'place' }), null);

// --- 8. The legacy filter syntax still reads --------------------------------
check(
  'legacy string-field filter',
  zoomOf([{ id: 'l', type: 'symbol', sourceLayer: 'place', filter: ['==', 'class', 'town'] }], 'l'),
  PLACE_MIN_ZOOM.town,
);

// --- 9. The table itself is ordered ------------------------------------------
//
// A typo that put towns before countries would pass every check above and still
// produce a cluttered world view.
{
  const ordered = [
    PLACE_MIN_ZOOM.countryMajor,
    PLACE_MIN_ZOOM.countrySecondary,
    PLACE_MIN_ZOOM.countryMinor,
    PLACE_MIN_ZOOM.capital,
    PLACE_MIN_ZOOM.city,
    PLACE_MIN_ZOOM.state,
    PLACE_MIN_ZOOM.town,
    PLACE_MIN_ZOOM.suburb,
    PLACE_MIN_ZOOM.village,
  ];
  check('zoom tiers increase monotonically', ordered.every((z, i) => i === 0 || z >= ordered[i - 1]), true);
  // The globe cannot zoom out past 1.9, so anything at or below that is
  // "always visible" - and only the major tier is allowed to be.
  const GLOBE_MIN_ZOOM = 1.9;
  const alwaysVisible = ordered.filter(z => z <= GLOBE_MIN_ZOOM);
  check('only the major-country tier survives at the globe floor', alwaysVisible, [PLACE_MIN_ZOOM.countryMajor]);
}

console.log();
if (failures > 0) {
  console.log(`${failures} assertion(s) FAILED`);
  process.exit(1);
}
console.log('All basemap declutter assertions passed.');
process.exit(0);
