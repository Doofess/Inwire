/**
 * Deciding which basemap layers are clutter.
 *
 * A world map drawn for its connection arcs does not need province lines or
 * forty country names at once. The stock styles draw both: OpenMapTiles puts
 * admin levels 2 through 6 in one `boundary` source, and the place labels for
 * country ranks 1, 2 and 3 all reach the screen by zoom 2.
 *
 * **Matched by `source-layer` and by the layer's own filter, never by layer
 * id** - the same rule `mapTheme.ts` states and for the same reason: ids like
 * `label_country_3` are style-specific and free to change upstream, while the
 * `admin_level`, `class` and `rank` fields these rules read are part of the
 * OpenMapTiles schema. That is what lets one set of rules cover two styles
 * whose layers are named nothing alike (`boundary_3` and `boundary_state`,
 * `label_country_2` and `place_country_minor`).
 *
 * Pure on purpose. Everything here is a function of one layer's metadata, so
 * the rules can be asserted against real style definitions without a WebGL
 * context - see `scripts/themes/declutter.ts`.
 */

/** The parts of a style layer these rules read. */
export interface DeclutterInput {
  id: string;
  type: string;
  /** OpenMapTiles source layer: `boundary`, `place`, `water`, ... */
  sourceLayer?: string;
  /** The layer's own filter expression, whatever shape the style author used. */
  filter?: unknown;
}

export type DeclutterRule =
  | {
      /** AND this onto the layer's existing filter - never replace it. */
      kind: 'filter';
      clause: unknown;
    }
  | {
      /** Hold this layer back until the map is at least this zoomed in. */
      kind: 'minzoom';
      minzoom: number;
    }
  | {
      /** Never draw this layer at all. */
      kind: 'hide';
    }
  | null;

/**
 * Source layers this map does not draw at all.
 *
 * The stock styles are general-purpose street maps: motorway casings, railway
 * dashes, runway markings, building footprints, residential landuse, park
 * fills, river lines and their labels. All of it is drawn for someone reading
 * the map for its own sake.
 *
 * Nobody reads this one that way. It is a backdrop for connection arcs between
 * countries, viewed at world zoom in a 256px dashboard card most of the time,
 * and every one of those layers is texture competing with the arcs at exactly
 * the scale where the arcs are hardest to follow. What the subject actually
 * needs is land, sea, the coast between them, country borders and country
 * names - which is what is left once this set is gone.
 *
 * Hidden rather than recoloured into the ground. `applyBasemapPalette` used to
 * flatten most of these to a tint of the background, which costs a fetch, a
 * tessellation and a draw call per layer per tile to produce something
 * invisible. `visibility: none` skips all three, and roughly forty of the
 * style's fifty-five layers with it.
 *
 * `water_name` is deliberately NOT here: sea names are held back by zoom
 * instead, so they return once you are close enough for them to be useful.
 */
export const HIDDEN_SOURCE_LAYERS: ReadonlySet<string> = new Set([
  'aerodrome_label',
  'aeroway',
  'building',
  'housenumber',
  'landcover',
  'mountain_peak',
  'park',
  'poi',
  'transportation_name',
  'waterway',
]);

/**
 * A city's layout, once you are close enough to be looking at one.
 *
 * `transportation` and `landuse` were hidden with the rest, and that was right
 * at world zoom and wrong at city zoom: zoomed onto the city an endpoint
 * resolved to, the map showed a green plate with a name on it, where the
 * question being asked is "where in this city". The owner asked for "a little
 * bit of city layout, not something too detailed". So the two come back, held
 * by zoom and by class, in a hierarchy that grows as you close in:
 *
 * - the built-up area (`landuse` residential) as a faint tint, from `urban`;
 * - motorways, trunk and primary roads from `major` - a city's skeleton;
 * - secondary and tertiary roads from `secondary`;
 * - minor streets from `minor`, where the grid is the layout.
 *
 * Never service roads, tracks, paths, rail, piers, buildings or road names: a
 * street map's detail, and the arcs' clutter. Road casings are not drawn either
 * - each road is one line, not an outlined one (see `declutterFor`).
 */
export const CITY_MIN_ZOOM = {
  urban: 7,
  major: 7,
  secondary: 9,
  minor: 12,
} as const;
// **These are TILE zooms, one below what the map's zoom readout says.** A
// `['zoom']` inside a filter is evaluated per tile, at the tile's own integer
// zoom, and OpenFreeMap's 512-pixel tiles are fetched a level below the map's
// zoom - so `major: 7` draws from map zoom 8, `minor: 12` from 13. Measured in
// screenshots: at the first values written here, 8/10/13, the roads arrived a
// whole level late and the street grid only at the map's maximum.

/**
 * The water the land's relief rim is drawn for: everything but lakes.
 *
 * The rim (`LAND_LIFT` in GeoMap) is what makes the coast read as a step. Around
 * a lake it ringed every small one in a dark band, which at zoom 8 over the
 * Canadian Shield was a field of hundreds of rimmed specks - the "too detailed"
 * the owner reported. A lake is a flat blue shape; only coasts get the step.
 */
//
// Written as `!=` on purpose, not as the `['!', ['match', ...]]` the small-water
// clause uses: `combineFilter` skips a clause whose text already appears in the
// filter, and that spelling of "not a lake" is already inside the water filter
// the rim copies - so it was taken as applied and the rims stayed. Measured in
// the running map, not assumed.
export const RIM_CLAUSE = ['!=', ['get', 'class'], 'lake'];

const MAJOR_ROADS = ['motorway', 'trunk', 'primary'];
const SECONDARY_ROADS = ['secondary', 'tertiary'];
const STREETS = ['minor'];
/** Every road class the layout draws at some zoom - anything else in `transportation` is hidden. */
const LAYOUT_ROADS = new Set([...MAJOR_ROADS, ...SECONDARY_ROADS, ...STREETS]);

/** The filter clause every kept road layer takes: each class from its own zoom. */
export const ROAD_CLAUSE = [
  'any',
  ['all', ['>=', ['zoom'], CITY_MIN_ZOOM.major], ['match', ['get', 'class'], MAJOR_ROADS, true, false]],
  ['all', ['>=', ['zoom'], CITY_MIN_ZOOM.secondary], ['match', ['get', 'class'], SECONDARY_ROADS, true, false]],
  ['all', ['>=', ['zoom'], CITY_MIN_ZOOM.minor], ['match', ['get', 'class'], STREETS, true, false]],
];

/**
 * The highest admin level that still draws.
 *
 * 2 is the country border. 3 through 6 are regions, provinces, counties and
 * districts - the "sub borders" that turn a world view into a mesh.
 */
export const MAX_ADMIN_LEVEL = 2;

/**
 * When each kind of place name is allowed on screen.
 *
 * Read against the globe's own floor of zoom 1.9: at that zoom only rank-1
 * countries and continents survive, which is roughly fifteen labels rather
 * than the forty the stock styles draw. Everything else is spaced so the count
 * on screen stays roughly constant as you zoom in, instead of every tier
 * arriving at once.
 */
export const PLACE_MIN_ZOOM = {
  continent: 0,
  /** By rank - see `countryMinZoom`. */
  countryMajor: 0,
  countrySecondary: 3,
  countryMinor: 4,
  capital: 4.5,
  city: 5.5,
  state: 6,
  town: 7.5,
  suburb: 8.5,
  village: 9.5,
} as const;

/**
 * When lakes join the ocean.
 *
 * The `water` source layer is not just the sea: it carries every lake, pond,
 * reservoir, dock and wide river on Earth, with no size threshold. Drawn at
 * world zoom that is a few thousand speckles scattered across the continents -
 * which was tolerable while the map also drew roads and landcover over them,
 * and is the most conspicuous thing on the map once those are gone. Each one
 * also picks up its own side wall from `LAND_LIFT`, so a two-pixel lake
 * arrives as a two-pixel lake wearing a shadow.
 *
 * Held back rather than hidden: a lake is real geography and worth drawing
 * once you are close enough for it to be more than a speck.
 */
export const SMALL_WATER_MIN_ZOOM = 4;

/**
 * Water this map never draws, at any zoom: rivers drawn as areas, ponds, docks
 * and pools. At city zoom they were the most detailed thing on the map - every
 * pond and the banks of every river, on a map that otherwise shows a city's
 * roads and nothing finer (the owner's report: "lakes and rivers ... too
 * detailed ... unnecessary for this use case"). Lakes stay, from
 * `SMALL_WATER_MIN_ZOOM`: they are geography at the scale this map is read.
 */
const NEVER_WATER_CLASSES = ['dock', 'pond', 'river', 'swimming_pool'];

/**
 * The water classes that wait for `SMALL_WATER_MIN_ZOOM`.
 *
 * Listed positively - "these are small" - rather than as "everything except
 * ocean", and the difference is the failure mode. A feature with no `class` at
 * all, or one OpenMapTiles adds later, matches neither list; naming the small
 * ones means such a feature keeps drawing, while keeping only `ocean` would
 * make it vanish. Getting this backwards empties the sea below zoom 4, which is
 * the entire map.
 */
const SMALL_WATER_CLASSES = ['lake'];

/**
 * When sea and ocean names may appear.
 *
 * These come from `water_name`, not `place`, and they are a surprising share of
 * the clutter: a world view drew "Laptev Sea", "Norwegian Sea", "Labrador Sea",
 * "Sargasso Sea", "Caribbean Sea", "Maldive Sea" and half a dozen more, all at
 * once, over the empty space the connection arcs cross.
 *
 * The schema gives no way to tell an ocean from a minor sea - both are plain
 * `water_name` features with no class to filter on - so this holds all of them
 * back together rather than trying to keep the big ones. On a map about traffic
 * between countries that is the right trade: the arcs cross the water, and the
 * water is where there is room for them.
 */
export const WATER_NAME_MIN_ZOOM = 3.5;

// --- Reading a filter --------------------------------------------------------

/** A comparison pulled out of a filter: `['>=', ['get','rank'], 3]`. */
interface Comparison {
  op: string;
  value: number;
}

interface FilterFacts {
  /** Values compared equal to `class`. */
  classes: string[];
  /** Comparisons against `rank`. */
  rank: Comparison[];
  /** Comparisons against `capital`. */
  capital: Comparison[];
}

/**
 * The field an operand refers to, if it refers to one.
 *
 * Handles both the expression form (`['get', 'class']`) and the legacy string
 * form (`'class'`) that older styles still use. Tolerating the second costs
 * three lines, and a style using it would otherwise fall silently through
 * every rule below.
 */
function fieldOf(operand: unknown): string | null {
  if (typeof operand === 'string') return operand;
  if (
    Array.isArray(operand)
    && operand.length === 2
    && operand[0] === 'get'
    && typeof operand[1] === 'string'
  ) {
    return operand[1];
  }
  return null;
}

const COMPARISON_OPS = new Set(['==', '!=', '<', '<=', '>', '>=']);

/** Walks a filter of any shape, collecting the comparisons these rules care about. */
function readFilter(
  filter: unknown,
  facts: FilterFacts = { classes: [], rank: [], capital: [] },
): FilterFacts {
  if (!Array.isArray(filter) || filter.length === 0) return facts;
  const [op, ...rest] = filter;
  if (typeof op !== 'string') return facts;

  if (op === 'all' || op === 'any' || op === '!') {
    for (const sub of rest) readFilter(sub, facts);
    return facts;
  }

  if (COMPARISON_OPS.has(op) && rest.length === 2) {
    const field = fieldOf(rest[0]);
    const value = rest[1];
    if (field === 'class' && op === '==' && typeof value === 'string') facts.classes.push(value);
    if (field === 'rank' && typeof value === 'number') facts.rank.push({ op, value });
    if (field === 'capital' && typeof value === 'number') facts.capital.push({ op, value });
    return facts;
  }

  // `['match', ['get','class'], [...], out, fallback]`. Only read as a class
  // selector when the matched output is truthy - the styles also use `match`
  // inverted, to mean "any class EXCEPT these", and reading that as a positive
  // selection would hold back exactly the labels it lists.
  if (op === 'match' && rest.length >= 4) {
    const field = fieldOf(rest[0]);
    const labels = rest[1];
    const matchedOutput = rest[2];
    if (field === 'class' && Array.isArray(labels) && matchedOutput === true) {
      for (const label of labels) if (typeof label === 'string') facts.classes.push(label);
    }
    return facts;
  }

  return facts;
}

/**
 * The most important country a layer can draw, as a rank.
 *
 * Rank 1 is the largest countries. A layer filtered `rank <= 2` draws ranks 1
 * and 2, so its most important country is rank 1 and it must appear early; a
 * layer filtered `rank >= 3` starts at 3 and can wait. Reducing every filter
 * shape to this one number is what makes the two styles' different conventions
 * - `== 2` in one, `<= 2` in the other - land on the same answer.
 */
function smallestRank(comparisons: Comparison[]): number {
  let smallest: number | null = null;
  for (const { op, value } of comparisons) {
    const candidate = op === '<' || op === '<=' ? 1 : value;
    smallest = smallest === null ? candidate : Math.min(smallest, candidate);
  }
  // No rank filter at all means the layer draws every country, including the
  // biggest - so it has to be allowed at world zoom.
  return smallest ?? 1;
}

function countryMinZoom(facts: FilterFacts): number {
  const rank = smallestRank(facts.rank);
  if (rank <= 1) return PLACE_MIN_ZOOM.countryMajor;
  if (rank === 2) return PLACE_MIN_ZOOM.countrySecondary;
  return PLACE_MIN_ZOOM.countryMinor;
}

function cityMinZoom(facts: FilterFacts): number {
  // `capital == 2` is a national capital; `capital != 2` is the everything-else
  // layer that sits beside it. Only the first earns an earlier zoom.
  const isCapital = facts.capital.some(c => c.op === '==');
  return isCapital ? PLACE_MIN_ZOOM.capital : PLACE_MIN_ZOOM.city;
}

/** The zoom one place class earns, or null if it is not one we reason about. */
function zoomForClass(placeClass: string, facts: FilterFacts): number | null {
  switch (placeClass) {
    case 'continent':
      return PLACE_MIN_ZOOM.continent;
    case 'country':
      return countryMinZoom(facts);
    case 'city':
      return cityMinZoom(facts);
    case 'state':
    case 'province':
      return PLACE_MIN_ZOOM.state;
    case 'town':
      return PLACE_MIN_ZOOM.town;
    case 'suburb':
    case 'neighbourhood':
    case 'quarter':
      return PLACE_MIN_ZOOM.suburb;
    case 'village':
    case 'hamlet':
    case 'isolated_dwelling':
      return PLACE_MIN_ZOOM.village;
    default:
      return null;
  }
}

// --- The rule ----------------------------------------------------------------

/**
 * What to do with one layer, or null to leave it exactly as the style author
 * wrote it.
 *
 * Returning null is the common case and the safe one: anything this does not
 * positively recognise keeps its stock behaviour, which is the same graceful
 * degradation `applyBasemapPalette` is built around.
 */
export function declutterFor(layer: DeclutterInput): DeclutterRule {
  // First, because it is unconditional: a hidden group is hidden whatever type
  // its layers are, fills and labels alike.
  if (layer.sourceLayer !== undefined && HIDDEN_SOURCE_LAYERS.has(layer.sourceLayer)) {
    return { kind: 'hide' };
  }

  if (layer.sourceLayer === 'boundary') {
    if (layer.type !== 'line') return null;
    // Country borders keep drawing; 3 through 6 match nothing and vanish.
    return { kind: 'filter', clause: ['<=', ['get', 'admin_level'], MAX_ADMIN_LEVEL] };
  }

  if (layer.sourceLayer === 'water') {
    if (layer.type !== 'fill' && layer.type !== 'line') return null;
    return {
      kind: 'filter',
      // `['zoom']` inside a filter is legal and is evaluated at integer zoom
      // levels only, which is exactly the granularity this needs - it is the
      // difference between "speckled" and "not" across a whole zoom level, not
      // something that has to animate smoothly through one.
      clause: [
        'all',
        ['!', ['match', ['get', 'class'], NEVER_WATER_CLASSES, true, false]],
        [
          'any',
          ['>=', ['zoom'], SMALL_WATER_MIN_ZOOM],
          ['!', ['match', ['get', 'class'], SMALL_WATER_CLASSES, true, false]],
        ],
      ],
    };
  }

  if (layer.sourceLayer === 'landuse') {
    // The built-up area and nothing else: a residential fill is what shows a
    // city's footprint. Any other landuse layer a style ships stays hidden.
    if (layer.type !== 'fill') return { kind: 'hide' };
    const facts = readFilter(layer.filter);
    if (!facts.classes.includes('residential')) return { kind: 'hide' };
    return { kind: 'filter', clause: ['>=', ['zoom'], CITY_MIN_ZOOM.urban] };
  }

  if (layer.sourceLayer === 'transportation') {
    // One line per road. A casing is the outline a street map draws around
    // each road; here it would double every line's weight for no meaning.
    // Matched by id because the casing and its road share a filter exactly -
    // nothing in the schema tells them apart - and OpenMapTiles styles name
    // casings `*_casing` throughout.
    if (layer.type !== 'line' || /casing/.test(layer.id)) return { kind: 'hide' };
    // A layer that draws none of the layout's classes - rail, paths, piers -
    // goes entirely rather than being filtered to nothing tile by tile.
    const facts = readFilter(layer.filter);
    if (!facts.classes.some(c => LAYOUT_ROADS.has(c))) return { kind: 'hide' };
    return { kind: 'filter', clause: ROAD_CLAUSE };
  }

  if (layer.sourceLayer === 'water_name') {
    if (layer.type !== 'symbol') return null;
    return { kind: 'minzoom', minzoom: WATER_NAME_MIN_ZOOM };
  }

  if (layer.sourceLayer === 'place') {
    if (layer.type !== 'symbol') return null;
    const facts = readFilter(layer.filter);
    if (facts.classes.length === 0) return null;

    // A layer may draw several classes at once - Dark's `place_other` covers
    // hamlets, isolated dwellings and neighbourhoods in one. It takes the
    // EARLIEST zoom among them, because the alternative is holding back a place
    // the style meant to show. Erring toward drawing is the right way round: a
    // label too early is noise, a label missing is a hole in the map.
    let earliest: number | null = null;
    for (const placeClass of facts.classes) {
      const zoom = zoomForClass(placeClass, facts);
      // One unrecognised class and the layer stops being something we can
      // reason about as a whole. Leave it entirely alone.
      if (zoom === null) return null;
      earliest = earliest === null ? zoom : Math.min(earliest, zoom);
    }
    return earliest === null ? null : { kind: 'minzoom', minzoom: earliest };
  }

  return null;
}

/**
 * Combines a declutter clause with a layer's own filter.
 *
 * Kept beside the rules because getting it wrong is silent: calling `setFilter`
 * with the clause alone would discard whatever the style author wrote, and a
 * boundary layer stripped of its own `maritime`/`disputed` conditions draws
 * lines through oceans rather than failing visibly.
 */
export function combineFilter(existing: unknown, clause: unknown): unknown {
  if (existing === undefined || existing === null) return clause;
  // Idempotent. Applying twice would otherwise nest `['all', ['all', ...]]`
  // deeper on every call - harmless to render but unreadable in a debugger, and
  // it would quietly hide the fact that something is running this more often
  // than it should.
  if (JSON.stringify(existing).includes(JSON.stringify(clause))) return existing;
  return ['all', existing, clause];
}
