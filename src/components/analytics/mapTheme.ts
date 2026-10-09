import type { FilterSpecification, Map as MapLibreMap, SkySpecification } from 'maplibre-gl';
import { contrastRatio, mixHex } from '../../lib/colorMix';
import { themePalette } from '../../services/themePalettes';
import type { MapSkin } from '../../services/mapPrefs';
import { combineFilter, declutterFor } from './mapDeclutter';

/**
 * Painting the basemap, in either of two skins.
 *
 * **The colourful skin does not follow the app's theme, and that is
 * deliberate.** The map used to: land was `--background`, sea was a neutral
 * mixed over it, and every colour on the map was derived from whichever of the
 * four themes was active. The result was a map made of the same greys as the
 * panel around it, which is a reasonable thing for a dashboard widget to be and
 * a bad thing for a map to be. Sea and land are not a surface hierarchy, they
 * are the two halves of a categorical distinction, and deriving them from a
 * chrome ramp meant spending real effort - a contrast search, a floor, an
 * assertion script - just to keep them far enough apart to tell which was which.
 *
 * So the default map is a map: green land, blue sea, fixed. `BASEMAP_PALETTE`
 * below is the whole of it, and nothing in it is a function of the theme.
 *
 * That argument settles which skin should be the DEFAULT. It was never an
 * argument that the theme-synced one should not exist - a dashboard whose map
 * recedes into the panel around it is a legitimate thing to want, and it is the
 * only skin that changes when the theme does. So it is back, unretired rather
 * than reinvented, as `applyMutedBasemap` at the foot of this file, and the
 * contrast search and the assertion script came back with it because they are
 * exactly what that skin needs to stay legible.
 *
 * The two passes are **property-for-property symmetric**, and that is a
 * requirement rather than a tidiness: switching skins repaints the live style
 * in place (there is no `setStyle` - see GeoMap.tsx for why not), so any paint
 * property one pass writes and the other does not is residue of the old skin
 * left sitting on the new one.
 *
 * The one thing that follows the theme in BOTH skins is the SKY, which is the
 * right division: the sky is the space the globe sits in, so it belongs to the
 * panel rather than to the planet. Light themes get daylight, dark themes get
 * night.
 *
 * **Matched by `source-layer`, not by layer id.** The OpenMapTiles schema the
 * stock style is built on groups layers into a handful of sources: `water`,
 * `landcover`, `landuse`, `building`, `transportation`, `boundary`, `place`.
 * There are 55 layers but only those few groups, and the ids within a group
 * (`highway_motorway_casing`, `highway_minor`, ...) are style-specific and free
 * to change upstream. Matching the group survives that; matching ids would not.
 * `mapDeclutter.ts` follows the same rule for the same reason.
 */

/**
 * The map's colours. Not themed, not derived, not configurable.
 *
 * A globe seen from orbit, in the flat storybook register rather than the
 * photographic one: one green for all land, one blue for all sea, and a step
 * between them. Nothing here is a tint of anything else, so there is no
 * expression to get wrong and no ground to be too close to.
 *
 * Muted on purpose. The first pass was the storybook globe's own colours - a
 * bright yellow-green on a saturated cyan - and at full strength they were the
 * loudest thing in the dashboard, which is exactly backwards for a surface
 * whose job is to sit under the connection arcs. These are the same two hues
 * pulled toward their neutrals: sage and slate rather than grass and cyan. The
 * ratios in `scripts/themes/basemap.ts` are what stop that going one step
 * further and washing the coastline out.
 */
export const BASEMAP_PALETTE = {
  /** Every landmass, everywhere, at every zoom. */
  land: '#9fae7e',
  /** Every sea, ocean and (once you are close enough) lake. */
  sea: '#42768a',
  /**
   * The two tones of the land's side wall, from `LAND_LIFT`.
   *
   * Both are the land green stepped down in value - the same face turning away
   * from the light, not a border colour - and `wallLower` is the darker of the
   * two because it sits at the waterline, deepest in the slab's own shadow.
   *
   * Their ORDER is load-bearing and asserted: lower darker than upper, upper
   * darker than the land. Swap any pair and the wall lights from underneath.
   */
  wallUpper: '#77894f',
  wallLower: '#576a3a',
  /** Country borders. A shade off the land, because they are context. */
  boundary: '#7f8d61',
  /** Place names. Dark enough to read on the land, which is where they sit. */
  label: '#2c3327',
  /** Punched behind the labels, so the few that fall on water still read. */
  labelHalo: '#e9edda',
  /**
   * Buildings and runways.
   *
   * Every layer this colours is hidden outright by `HIDDEN_SOURCE_LAYERS`, so
   * it paints nothing on the style that ships today. Kept as the fallback for
   * the day one of those groups is unhidden or a different style is loaded -
   * the alternative being that they arrive in OpenFreeMap's own grey, on green.
   */
  structure: '#94a274',
  /**
   * A city's built-up area, from zoom 8 (`CITY_MIN_ZOOM.urban`). A breath off
   * the land - 1.1:1 - so a city's footprint shows without becoming a shape
   * that competes with the arcs.
   */
  urban: '#aab58f',
  /**
   * Roads, from the major ones at zoom 8 to the streets at 13. Lighter than the
   * land and the built-up area both, so a city's layout reads as pale lines
   * on green the way a street plan does - asserted visible and still a
   * backdrop by `scripts/themes/basemap.ts`.
   */
  road: '#cfd6b6',
} as const;

/**
 * The sky behind the globe, and the only part of the map the theme touches.
 *
 * Only visible in globe projection, where the planet no longer fills the
 * viewport and something has to occupy the space around it. Left to itself
 * MapLibre draws its own blue atmosphere with a bright halo on the limb.
 *
 * Two skies, chosen by whether the app is in a light theme or a dark one:
 * daylight, or night. `fog-color` and `fog-ground-blend` are what carry it onto
 * the planet itself - the globe's limb picks up the sky it is sitting in, which
 * is what stops a daylit Earth from looking pasted onto a night sky.
 *
 * Deliberately not the theme's accent. The halo was tried in it and it was the
 * wrong call: a large, soft, saturated area wrapped around the one element on
 * screen that is supposed to be read for its content, washing over the arcs
 * that cross the limb.
 *
 * **`atmosphere-blend` is 0.** MapLibre's globe atmosphere is a physically
 * based Rayleigh/Mie scattering shader - a 5x3-step ray march with `sqrt` and
 * `exp` per step, in `highp`, over every pixel, every frame. On a discrete GPU
 * it is nearly free (ABAB during a drag on an RTX 4080: ~0.05 ms/frame). On a
 * software rasterizer it is not: about 10% of the frame at 1598x969 on WARP,
 * on a map that has to run on low-end hardware. What it buys is a soft glow
 * on the limb, which the reference this globe is drawn to does not have.
 * `sky-color`/`horizon-color` stay because they cost nothing and still tint
 * the limb; the space behind the planet is painted by `spaceColorFor`, which
 * was never the atmosphere's job.
 *
 * A first measurement blamed this pass for 97% of the frame. That number was
 * a transient - tile fade and label placement still settling after the
 * gesture - read off a single `_render()` timed after the drag instead of
 * the frames during it. Recorded here so the next person measures the frames
 * the user actually sees; see `scripts/perf/map-bench.browser.js`.
 */
export function skyFor(isDark: boolean): SkySpecification {
  return isDark
    ? {
        'sky-color': '#050810',
        'sky-horizon-blend': 0.5,
        'horizon-color': '#16202f',
        'horizon-fog-blend': 0.6,
        'fog-color': '#0a1018',
        'fog-ground-blend': 0.75,
        'atmosphere-blend': 0,
      }
    : {
        'sky-color': '#8fb4cf',
        // Lower than the night sky's, so the blue survives instead of being
        // washed into the horizon across most of the visible arc. A first pass
        // at 0.6 rendered a daytime sky that was, in practice, white.
        'sky-horizon-blend': 0.3,
        'horizon-color': '#cadeeb',
        'horizon-fog-blend': 0.5,
        'fog-color': '#dfeaf1',
        'fog-ground-blend': 0.85,
        'atmosphere-blend': 0,
      };
}

/**
 * The colour of space behind the globe.
 *
 * `setSky` alone does not get you this, which is worth knowing before reaching
 * for it: MapLibre's sky in globe projection is the ATMOSPHERE - the soft halo
 * on the limb - and everything beyond it is left transparent, so what fills the
 * panel is whatever is behind the canvas. Set the sky and nothing else, and a
 * daylit globe sits on a sheet of the app's own background colour.
 *
 * So the backdrop is painted on the map container itself, and these two are
 * kept beside each other deliberately: the halo and the space it fades into
 * have to be the same sky or the limb reads as a ring drawn around the planet.
 *
 * This is also what makes the flat projection work, where there is no
 * atmosphere at all and the space above and below the world is all there is.
 */
export function spaceColorFor(isDark: boolean): string {
  return isDark ? '#070b13' : '#c3d9ea';
}

/**
 * Land as a slab standing above the sea.
 *
 * Two attempts came before this one and both were outlines, which is why this
 * is worth explaining rather than just reading.
 *
 * A DEM came first: real elevation, hillshaded. Accurate, and the wrong subject
 * - the mountains of Asia are not what this map is about, the arcs crossing
 * them are, and it cost a second tile pyramid streaming continuously. Then a
 * soft dark band inside the water hugging every coast. That failed for a
 * deeper reason: it was the same on every side of every landmass. **A bevel
 * with no light direction is a border.** Nothing in the eye reads a uniform
 * ring as height, however carefully it is blurred.
 *
 * A raised slab, lit from one side, does not look like that. Its top face is
 * displaced toward the light; on the far side the top no longer covers the
 * base, and the strip left over is the wall. So there IS no outline - there is
 * a green face on one side of each landmass and nothing at all on the other.
 *
 * That is exactly what this draws, and by construction rather than by
 * imitation. Write `W` for the water polygon and `L` for the land, which is its
 * complement, and `u` for the top face's screen displacement:
 *
 *   1. the background paints everything `land`
 *   2. `W + u` paints over it in the wall tone
 *   3. the style's own water fill paints `W` in `sea`
 *
 * and what survives is: `L + u` in land green (the displaced top face),
 * `(W + u) \ W` in the wall tone (which is precisely `L` minus `L + u`, the
 * base the top no longer covers), and `W` as sea. A slab, from three fills.
 *
 * Two wall steps rather than one, so the face has depth: `u` and half of it,
 * the shorter one darker and drawn on top, which puts the darkest tone at the
 * waterline where a wall's own shadow is deepest.
 *
 * `fill-translate-anchor: 'viewport'` is what makes `u` a screen displacement
 * rather than a ground one - the light stays where it is when the globe spins,
 * the same choice the old hillshade made and for the same reason. Legibility
 * over realism: this is a map being read, not a render.
 *
 * Seams are safe, though they look like they should not be. Water polygons are
 * clipped per tile, but every tile's copy moves by the same `u`, so the union
 * still meets edge to edge.
 *
 * `['literal', [x, y]]` around every stop value, and it is not optional. An
 * interpolate whose outputs are bare arrays parses the array as an expression
 * and reports "Expression name must be a string, but found number instead" -
 * on an `error` event, not a throw, so `addLayer` quietly declines and the map
 * renders perfectly well with no wall at all.
 */
export const LAND_LIFT = [
  {
    /** The upper wall: the longer displacement, so it reaches further inland. */
    suffix: 'upper',
    color: BASEMAP_PALETTE.wallUpper,
    // How tall the slab reads. In screen pixels and only mildly zoom-dependent,
    // because a slab's height is a property of the slab, not of how close you
    // are standing to it - the flat-design register this is drawn in keeps it
    // roughly constant rather than scaling it like ground distance.
    translate: [
      'interpolate', ['linear'], ['zoom'],
      0, ['literal', [-6, -6]],
      4, ['literal', [-9, -9]],
      8, ['literal', [-12, -12]],
    ],
  },
  {
    /** The lower wall, at the waterline. Darker, shorter, and drawn on top. */
    suffix: 'lower',
    color: BASEMAP_PALETTE.wallLower,
    translate: [
      'interpolate', ['linear'], ['zoom'],
      0, ['literal', [-3, -3]],
      4, ['literal', [-4.5, -4.5]],
      8, ['literal', [-6, -6]],
    ],
  },
] as const;

/**
 * Where the light is.
 *
 * Negative on both axes is up and left in screen space, which is where every
 * map since the first hachured survey has put its light - and the direction the
 * retired hillshade used too, at 335 degrees. The wall therefore appears on the
 * lower-right of each landmass, and `LAND_LIFT`'s translations all point this
 * way. Asserted in `scripts/themes/basemap.ts`, because a sign flip here lights
 * the world from below and still looks deliberate.
 */
export const LIGHT_FROM_UPPER_LEFT = true;

/**
 * How wide a country border is drawn, in both skins.
 *
 * A hairline that grows only slightly with zoom. The stock styles draw borders
 * thick enough to read on their own; here they are context behind the
 * connection arcs, and a 2px border competes with a 2px arc for the same
 * attention. Interpolated rather than fixed so it does not vanish entirely on a
 * high-DPI world view.
 *
 * Shared by the two skins rather than duplicated, because it is the one paint
 * property they write for a reason that has nothing to do with colour - and a
 * property only one of them wrote would survive a skin switch as residue.
 */
const BOUNDARY_LINE_WIDTH = [
  'interpolate', ['linear'], ['zoom'],
  2, 0.4,
  6, 0.8,
  12, 1.2,
];

/**
 * Paints the stock style in `BASEMAP_PALETTE`.
 *
 * Every write is guarded individually. A style whose layers do not match the
 * schema - an upstream change, or a different basemap later - should leave the
 * map looking stock rather than throwing halfway through and leaving it half
 * recoloured.
 *
 * Runs once per `style.load` and never again. It used to re-run on every theme
 * change, because every colour it wrote was a function of the theme's tokens;
 * with a fixed palette there is nothing for a theme change to update here. The
 * sky is the exception and is set separately - see `GeoMap.tsx`.
 */
export function applyBasemapPalette(map: MapLibreMap): void {
  let style;
  try {
    style = map.getStyle();
  } catch {
    return; // Style not ready. The `style.load` handler will call again.
  }
  if (!style?.layers) return;

  const set = (id: string, property: string, value: unknown) => {
    try {
      // Cast because the property name is chosen from a layer's runtime type
      // rather than being known statically; MapLibre's own typing wants a
      // literal key, and the try/catch below is the real guard either way.
      (map.setPaintProperty as (i: string, p: string, v: unknown) => void)(id, property, value);
    } catch {
      // A layer that does not support this property, or is gone. Skipping one
      // layer is a cosmetic gap; letting it throw abandons every layer after it.
    }
  };

  for (const layer of style.layers) {
    // Our own layers - the coast relief, the connection arcs - are painted by
    // whoever added them, and they carry their own colour logic. Left in, the
    // coast shadow would match the `water` case below and be repainted flat.
    if (layer.id.startsWith(OWN_LAYER_PREFIX)) continue;

    const sourceLayer = 'source-layer' in layer ? layer['source-layer'] : undefined;

    if (layer.type === 'background') {
      set(layer.id, 'background-color', BASEMAP_PALETTE.land);
      continue;
    }

    if (layer.type === 'symbol') {
      set(layer.id, 'text-color', BASEMAP_PALETTE.label);
      set(layer.id, 'text-halo-color', BASEMAP_PALETTE.labelHalo);
      set(layer.id, 'text-halo-width', 1.2);
      continue;
    }

    switch (sourceLayer) {
      case 'water':
      case 'waterway':
        if (layer.type === 'fill') set(layer.id, 'fill-color', BASEMAP_PALETTE.sea);
        // A stock water outline, if the style has one. Positron does not - it
        // draws water as a bare fill - and this map wants none: the land/sea
        // edge is a colour change and a wall, never a stroke. Painted in the
        // sea's own colour so a style which DOES carry one contributes nothing
        // visible rather than drawing the outline back on.
        if (layer.type === 'line') set(layer.id, 'line-color', BASEMAP_PALETTE.sea);
        break;

      // The built-up area, which `mapDeclutter` keeps from zoom 8 - the only
      // landuse that draws. Opaque, because the stock style fades it in with
      // an opacity ramp of its own made for a white map.
      case 'landuse':
        if (layer.type === 'fill') {
          set(layer.id, 'fill-color', BASEMAP_PALETTE.urban);
          set(layer.id, 'fill-opacity', 1);
        }
        break;

      case 'landcover':
      // `park` is its own source-layer in Positron, and it was the single layer
      // in the whole style the colour pass did not cover - which is invisible
      // while the light themes use a light-built style, and a stock green blob
      // the moment one style serves all four.
      case 'park':
        if (layer.type === 'fill') set(layer.id, 'fill-color', BASEMAP_PALETTE.land);
        break;

      // The roads `mapDeclutter` keeps for a city's layout. One colour for the
      // whole hierarchy: the stock widths already say which road is which.
      case 'transportation':
        if (layer.type === 'line') {
          set(layer.id, 'line-color', BASEMAP_PALETTE.road);
          set(layer.id, 'line-opacity', 1);
        }
        break;

      case 'building':
      case 'aeroway':
        if (layer.type === 'fill') set(layer.id, 'fill-color', BASEMAP_PALETTE.structure);
        if (layer.type === 'line') set(layer.id, 'line-color', BASEMAP_PALETTE.structure);
        break;

      case 'boundary':
        if (layer.type === 'line') {
          set(layer.id, 'line-color', BASEMAP_PALETTE.boundary);
          set(layer.id, 'line-opacity', 0.7);
          set(layer.id, 'line-width', BOUNDARY_LINE_WIDTH);
        }
        break;

      default:
        // Anything unrecognised keeps the stock style's own colour. That is the
        // graceful degradation this function is built around.
        break;
    }
  }
}

/**
 * Layers this app owns, rather than the style author.
 *
 * A prefix rather than a list, so a new one is inert to the colour pass the
 * moment it is named - which is the failure mode worth designing out, since
 * getting repainted by a rule meant for somebody else's layer is silent.
 */
const OWN_LAYER_PREFIX = 'inwire-';

// --- The muted skin ----------------------------------------------------------

/**
 * The four theme values the muted skin is built out of.
 *
 * Taken from `themePalettes` rather than read off the document, so the
 * assertion script can hold every theme to the water floor without a browser -
 * which is the whole reason that bug shipped in the first place: nothing could
 * check it. `--primary` is the exception and has to be passed in, because it is
 * the one token with no counterpart in the palette.
 */
export interface BasemapTokens {
  /** `--background`: land, and the ground everything else sits on. */
  background: string;
  /** `--muted-foreground`: boundaries, roads and label text. */
  mutedForeground: string;
  /**
   * `--primary`: the coastline, and nothing else.
   *
   * The one saturated thing on this skin. Sea and land are both neutral steps
   * of the same ramp (see `waterColorFor`), so the accent is what stops the
   * result reading as a map that failed to load - and a hairline is the right
   * place to spend it, because a line costs almost no area. Admin boundaries
   * deliberately do NOT get it: at low zoom there are enough of them to turn
   * the map into a coloured mesh.
   */
  accent: string;
  /** The palette's green, for parks and landcover. */
  landHue: string;
}

/**
 * The muted skin's tokens for a theme.
 *
 * `hues.neutral` IS `--muted-foreground` in all four themes - the palettes were
 * authored that way - and `scripts/themes/basemap.ts` asserts it against
 * index.css rather than leaving it as a coincidence somebody could break by
 * retouching one of the two copies.
 */
export function basemapTokensFor(resolvedTheme: string | undefined, accent: string): BasemapTokens {
  const palette = themePalette(resolvedTheme);
  return {
    background: palette.surface.background,
    mutedForeground: palette.hues.neutral,
    accent,
    landHue: palette.hues.green,
  };
}

/**
 * How far each layer group moves off the background.
 *
 * Everything is a tint *of the background* rather than the raw colour, because
 * a basemap has to stay a backdrop: roads at full strength compete with the
 * connection arcs drawn over them, which are the actual content of this panel.
 */
const WATER_TINT = 0.1;
const LAND_TINT = 0.08;
const STRUCTURE_TINT = 0.22;
/** How far a city's built-up area steps from the land toward the roads, in the muted skin. */
const URBAN_TINT = 0.3;
const BOUNDARY_TINT = 0.5;

/**
 * The floor on how alike water and land may look.
 *
 * A contrast ratio rather than a luminance difference, because luminance is
 * badly non-linear near black: a dark theme's water and land can differ by 0.02
 * in luminance and be perfectly legible, while two near-whites can differ by
 * more than that and be indistinguishable.
 *
 * 2.0 rather than the 1.35 this shipped as. At 1.35 the coastline was visible
 * if you went looking for it, which is not the same as telling sea from land at
 * a glance - and this map is read at 256px in a dashboard card far more often
 * than it is read full-screen. 2.0 is still well under anything that would make
 * the basemap compete with the arcs over it, and the 4.5 cap in the assertion
 * script is what holds that line.
 */
const MIN_WATER_CONTRAST = 2.0;

/**
 * Water: a step of the theme's own neutral ladder, not a blue.
 *
 * Water used to be tinted from the palette's blue, which meant every theme had
 * a blue sea regardless of what it was doing everywhere else - and on a warm
 * theme that is the one element visibly not part of the design.
 *
 * Mixing `--muted-foreground` over `--background` instead gives sea and land as
 * two steps of the same neutral ramp, which is how Carto Positron and Mapbox
 * Monochrome do it: the map recedes to a substrate, and the only colour on it
 * is the coastline and the pins - which are the content.
 *
 * Still a SEARCH rather than a fixed mix. A mid neutral over a near-white
 * ground moves very slowly while over a near-black it moves fast, so one
 * constant cannot serve both - and assuming one did is the original bug this
 * function exists to fix: `#f1f5f9` over `#f4f7f9` is three RGB steps, and Day
 * shipped as a single flat sheet with no coastline on it at all.
 *
 * Exported so the assertion script can hold every theme to the floor without
 * needing a map instance.
 */
export function waterColorFor(background: string, neutral: string): string {
  for (let tint = WATER_TINT; tint <= 0.9; tint += 0.05) {
    const candidate = mixHex(neutral, background, tint);
    if (contrastRatio(candidate, background) >= MIN_WATER_CONTRAST) return candidate;
  }
  return mixHex(neutral, background, 0.9);
}

/**
 * The land slab's two wall tones, per skin.
 *
 * The colourful skin's are hand-picked and fixed: the land green stepped down
 * in value twice, a face turning away from a light in the upper left, darkest
 * at the waterline where its own shadow is deepest.
 *
 * The muted skin cannot do that, and the reason is worth stating because the
 * obvious fix does not work. Its land IS the theme's `--background`, which on
 * Night is `#161616` and near enough the floor. A wall derived by darkening
 * would be invisible on a dark theme and the slab would simply not exist there.
 *
 * So the muted wall steps from the land TOWARD THE SEA instead: monotone, in
 * whichever direction that theme's water lies, with the lower step nearest the
 * water. On a light theme that darkens, exactly as the colourful skin does; on
 * a dark theme it lightens, and reads as a rim-lit edge rather than a shadowed
 * one. Less literal, and the only version that survives all four grounds.
 * `scripts/themes/basemap.ts` asserts the ordering as monotone-and-perceptible
 * rather than as always-darker, for that reason.
 */
export function wallTonesFor(skin: MapSkin, tokens: BasemapTokens): { upper: string; lower: string } {
  if (skin === 'colorful') {
    return { upper: BASEMAP_PALETTE.wallUpper, lower: BASEMAP_PALETTE.wallLower };
  }
  const sea = waterColorFor(tokens.background, tokens.mutedForeground);
  return {
    upper: mixHex(sea, tokens.background, 0.3),
    lower: mixHex(sea, tokens.background, 0.55),
  };
}

/**
 * Paints the stock style in the app's own tokens.
 *
 * The mirror of `applyBasemapPalette`, and deliberately its mirror: every paint
 * property one writes, the other writes too, so switching skins on a live style
 * leaves nothing of the old one behind. Both skip `inwire-` layers for the
 * same reason - the land wall's source-layer is `water`, so an unguarded pass
 * would repaint the wall flat and delete the slab.
 *
 * Unlike `applyBasemapPalette` this DOES have to re-run when the theme changes,
 * because every colour it writes is a function of the tokens. See GeoMap.tsx,
 * where that effect is keyed on the skin and the tokens together.
 */
export function applyMutedBasemap(map: MapLibreMap, tokens: BasemapTokens): void {
  let style;
  try {
    style = map.getStyle();
  } catch {
    return; // Style not ready. The `style.load` handler will call again.
  }
  if (!style?.layers) return;

  const { background } = tokens;
  const water = waterColorFor(background, tokens.mutedForeground);
  const land = mixHex(tokens.landHue, background, LAND_TINT);
  const structure = mixHex(tokens.mutedForeground, background, STRUCTURE_TINT);
  const boundary = mixHex(tokens.mutedForeground, background, BOUNDARY_TINT);
  // Labels are the one thing that must NOT recede - a map whose place names are
  // unreadable is worse than one that is the wrong colour - so they take the
  // token itself, with a halo of the ground punched behind them.
  const label = tokens.mutedForeground;
  const halo = background;

  const set = (id: string, property: string, value: unknown) => {
    try {
      (map.setPaintProperty as (i: string, p: string, v: unknown) => void)(id, property, value);
    } catch {
      // One layer skipped. See the note on the same helper above.
    }
  };

  for (const layer of style.layers) {
    if (layer.id.startsWith(OWN_LAYER_PREFIX)) continue;

    const sourceLayer = 'source-layer' in layer ? layer['source-layer'] : undefined;

    if (layer.type === 'background') {
      set(layer.id, 'background-color', background);
      continue;
    }

    if (layer.type === 'symbol') {
      set(layer.id, 'text-color', label);
      set(layer.id, 'text-halo-color', halo);
      set(layer.id, 'text-halo-width', 1.2);
      continue;
    }

    switch (sourceLayer) {
      case 'water':
      case 'waterway':
        if (layer.type === 'fill') set(layer.id, 'fill-color', water);
        // The COASTLINE, in the accent. Water's line layers are the edge of the
        // fill beside them, so this is the one stroke on the map that traces
        // where sea meets land - exactly the distinction a neutral sea needs
        // help making, and the only place the accent buys anything.
        if (layer.type === 'line') set(layer.id, 'line-color', tokens.accent);
        break;

      // The built-up area, a step from the land toward the roads, so a city's
      // footprint shows in this skin as it does in the colourful one.
      case 'landuse':
        if (layer.type === 'fill') {
          set(layer.id, 'fill-color', mixHex(structure, land, URBAN_TINT));
          set(layer.id, 'fill-opacity', 1);
        }
        break;

      case 'landcover':
      case 'park':
        if (layer.type === 'fill') set(layer.id, 'fill-color', land);
        break;

      case 'transportation':
        if (layer.type === 'line') {
          set(layer.id, 'line-color', structure);
          set(layer.id, 'line-opacity', 1);
        }
        break;

      case 'building':
      case 'aeroway':
        if (layer.type === 'fill') set(layer.id, 'fill-color', structure);
        if (layer.type === 'line') set(layer.id, 'line-color', structure);
        break;

      case 'boundary':
        if (layer.type === 'line') {
          set(layer.id, 'line-color', boundary);
          set(layer.id, 'line-opacity', 0.6);
          // The same hairline the colourful skin draws. Symmetry, not taste:
          // leave it out and switching from colourful to muted keeps the thin
          // borders while switching back cannot restore the stock thick ones.
          set(layer.id, 'line-width', BOUNDARY_LINE_WIDTH);
        }
        break;

      default:
        break;
    }
  }
}

/** The skin's repaint pass, chosen by name. */
export function applySkin(map: MapLibreMap, skin: MapSkin, tokens: BasemapTokens): void {
  if (skin === 'muted') applyMutedBasemap(map, tokens);
  else applyBasemapPalette(map);
}

/**
 * Thins out borders and place names, and drops whole groups.
 *
 * Kept separate from `applyBasemapPalette` and called only on `style.load`,
 * because the two answer different questions. Running the filter half
 * repeatedly would also mean combining a clause onto a filter that already has
 * it - which `combineFilter` now tolerates, but which would still be a sign of
 * something being called more often than it should.
 *
 * Every write is guarded individually, on the same principle as the paint
 * writes: a style that does not match the schema should look stock rather than
 * throw halfway through and leave half the map decluttered.
 */
export function applyDeclutter(map: MapLibreMap): void {
  let style;
  try {
    style = map.getStyle();
  } catch {
    return; // Style not ready. The `style.load` handler will call again.
  }
  if (!style?.layers) return;

  for (const layer of style.layers) {
    const sourceLayer = 'source-layer' in layer ? layer['source-layer'] : undefined;
    const rule = declutterFor({
      id: layer.id,
      type: layer.type,
      sourceLayer: typeof sourceLayer === 'string' ? sourceLayer : undefined,
      filter: 'filter' in layer ? layer.filter : undefined,
    });
    if (!rule) continue;

    try {
      if (rule.kind === 'hide') {
        map.setLayoutProperty(layer.id, 'visibility', 'none');
      } else if (rule.kind === 'filter') {
        const combined = combineFilter(map.getFilter(layer.id), rule.clause);
        map.setFilter(layer.id, combined as FilterSpecification);
      } else {
        // setLayerZoomRange wants both ends, so the layer's own ceiling has to
        // be carried through rather than defaulted away - dropping it would
        // make layers the style deliberately retires at high zoom draw forever.
        const maxzoom = 'maxzoom' in layer && typeof layer.maxzoom === 'number' ? layer.maxzoom : 24;
        map.setLayerZoomRange(layer.id, rule.minzoom, maxzoom);
      }
    } catch {
      // One layer skipped. See the note on `set` above.
    }
  }
}
