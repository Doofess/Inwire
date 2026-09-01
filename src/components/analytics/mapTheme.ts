import type { Map as MapLibreMap, SkySpecification } from 'maplibre-gl';
import { mixHex, isDarkColor, contrastRatio } from '../../lib/colorMix';

/**
 * Repainting the basemap in the app's own colours.
 *
 * The map used to pick between two stock OpenFreeMap styles - Positron for
 * light, Dark for everything else - which meant that of the eight app themes,
 * four rendered an identical grey-blue map. Mono, a deliberately monochrome
 * theme, showed a blue-and-green world; Dracula and Solarized Dark showed the
 * same map as plain Dark. The basemap was the one surface that never followed
 * the theme.
 *
 * The stock styles are still the starting point - they carry the geometry, the
 * label placement and the zoom rules, none of which is worth reimplementing -
 * and this recolours them afterwards.
 *
 * **Matched by `source-layer`, not by layer id.** The OpenMapTiles schema those
 * styles are built on groups layers into a handful of sources: `water`,
 * `landcover`, `landuse`, `building`, `transportation`, `boundary`, `place`.
 * There are 47 layers but only those few groups, and the ids within a group
 * (`highway_motorway_casing`, `highway_minor`, ...) are style-specific and free
 * to change upstream. Matching the group survives that; matching ids would not.
 */

export interface BasemapTokens {
  /** `--background`: land, and the ground everything else sits on. */
  background: string;
  /** `--muted-foreground`: boundaries, roads and label text. */
  mutedForeground: string;
  /**
   * `--primary`: the coastline, and nothing else.
   *
   * The one saturated thing on the map. Sea and land are both neutral steps of
   * the same ramp (see waterColorFor), so the accent is what stops the result
   * reading as a map that failed to load - and a hairline is the right place to
   * spend it, because a line costs almost no area. Admin boundaries deliberately
   * do NOT get it: at low zoom there are enough of them to turn the map into a
   * coloured mesh.
   */
  accent: string;
  /** The palette's green, for parks and landcover. */
  landHue: string;
}

/**
 * How far each layer group moves off the background.
 *
 * Everything is a tint *of the background* rather than the raw colour, because
 * a basemap has to stay a backdrop: roads at full strength compete with the
 * connection lines drawn over them, which are the actual content of this panel.
 */
const WATER_TINT = 0.1;
const LAND_TINT = 0.08;
const STRUCTURE_TINT = 0.22;
const BOUNDARY_TINT = 0.5;

/**
 * The floor on how alike water and land may look.
 *
 * A contrast ratio rather than a luminance difference, because luminance is
 * badly non-linear near black: a dark theme's water and land can differ by 0.02
 * in luminance and be perfectly legible, while two near-whites can differ by
 * more than that and be indistinguishable.
 *
 * Raised from 1.35 to 2.0. At 1.35 the coastline was visible if you went
 * looking for it, which is not the same as being able to tell sea from land at
 * a glance - and this map is read at 256px in a dashboard card far more often
 * than it is read full-screen. 2.0 is still well under anything that would make
 * the basemap compete with the connection lines drawn over it, and the 4.5 cap
 * in the assertion script is what holds that line.
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
 * Still a SEARCH rather than a fixed mix, and that matters more now than it
 * did. A mid neutral over a near-white ground moves very slowly (Day needs a
 * tint of 0.65 to clear the floor) while over a near-black it moves fast
 * (Graphite needs 0.15). One constant could not serve both, and assuming one
 * did is the original bug this function was written to fix.
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
 * The sky behind the globe, and the haze on its horizon.
 *
 * Only visible in globe projection, where the planet no longer fills the
 * viewport and something has to occupy the space around it. Left to itself
 * MapLibre draws a fixed blue atmosphere, which is the same mistake the stock
 * basemap made: one theme's colours imposed on all four.
 *
 * The composition, from outside in:
 *
 *   `sky-color`      the void. A step DARKER than the app background on light
 *                    themes and the background itself on dark ones - space
 *                    reads as space by being darker than the thing in front of
 *                    it, and on Day a literal white void makes the globe look
 *                    like a hole rather than a planet.
 *   `horizon-color`  the accent, at the one place it pays for itself. This is
 *                    the rim-light around the planet's edge, and it is the same
 *                    argument as the coastline in `applyThemeToBasemap`: a
 *                    hairline of the theme's colour is what stops a neutral map
 *                    reading as a map that failed to load.
 *   `fog-color`      the haze the surface fades into near the limb, mixed off
 *                    the background so the terminator is a gradient rather than
 *                    a cut edge.
 *
 * `atmosphere-blend` is deliberately below 1: at full strength the glow washes
 * over the coastline the basemap just spent its only saturated colour on.
 */
export function skyFor(tokens: BasemapTokens): SkySpecification {
  const dark = isDarkColor(tokens.background);
  return {
    // Light themes get a deepened ground so the planet sits IN something.
    'sky-color': dark ? tokens.background : mixHex(tokens.mutedForeground, tokens.background, 0.55),
    'sky-horizon-blend': 0.6,
    'horizon-color': tokens.accent,
    'horizon-fog-blend': 0.55,
    'fog-color': mixHex(tokens.mutedForeground, tokens.background, 0.35),
    'fog-ground-blend': 0.7,
    'atmosphere-blend': dark ? 0.75 : 0.55,
  };
}

/**
 * Applies the theme to whatever style is currently loaded.
 *
 * Every write is guarded individually. A style whose layers do not match the
 * schema - an upstream change, or a different basemap later - should leave the
 * map looking stock rather than throwing halfway through and leaving it half
 * recoloured.
 *
 * Must run on every `style.load`: `setStyle` replaces the whole style object,
 * so a theme switch discards these paint properties along with the custom
 * layers, and both have to be reapplied together.
 */
export function applyThemeToBasemap(map: MapLibreMap, tokens: BasemapTokens): void {
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
        // The COASTLINE, in the accent. Water's line layers are the edge of
        // the fill beside them, so this is the one stroke on the map that
        // traces where sea meets land - which is exactly the distinction a
        // neutral sea needs help making, and the only place the accent buys
        // anything. Admin boundaries stay muted below: painting those in the
        // accent too turned the whole map into a coloured mesh.
        if (layer.type === 'line') set(layer.id, 'line-color', tokens.accent);
        break;

      case 'landcover':
      case 'landuse':
        if (layer.type === 'fill') set(layer.id, 'fill-color', land);
        break;

      case 'building':
      case 'transportation':
      case 'aeroway':
        if (layer.type === 'fill') set(layer.id, 'fill-color', structure);
        if (layer.type === 'line') set(layer.id, 'line-color', structure);
        break;

      case 'boundary':
        if (layer.type === 'line') {
          set(layer.id, 'line-color', boundary);
          set(layer.id, 'line-opacity', 0.6);
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
 * Which stock style to start from.
 *
 * Still worth choosing correctly even though everything gets repainted: the two
 * styles differ in label *placement* and halo strategy as well as colour, and
 * starting from the one built for the right ground gives legible labels before
 * a single paint property is touched.
 */
export function baseStyleFor(background: string): 'dark' | 'light' {
  return isDarkColor(background) ? 'dark' : 'light';
}
