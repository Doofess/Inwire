import React, { useEffect, useRef, useState } from "react";
import * as maplibregl from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { Packet } from "../../types/packet";
import {
  resolveIP,
  resolveHostname,
  resolveSelfLocation,
  onNameResolutionEnabled,
  GeoLocation,
  isLocatable,
} from "../../services/geoIpService";
import { MapPin, MapPinOff } from "lucide-react";
import { useThemeToken } from '../../lib/themeColor';
import { protocolColor } from '../../services/protocolColors';
import { greatCircleArc, splitAtAntimeridian } from '../../lib/greatCircle';
import { ArcLayer, type Arc } from './arcLayer';
import { addPacketToPairs, aggregateRoutes, type AddressPair, type Route, type GeoPlace } from './geoRoutes';
import { useIncrementalAggregate } from '../../lib/useIncrementalAggregate';
import {
  applySkin,
  applyDeclutter,
  basemapTokensFor,
  wallTonesFor,
  LAND_LIFT,
  skyFor,
  spaceColorFor,
  type BasemapTokens,
} from './mapTheme';
import { probeRenderTier, TIER_SETTINGS } from './renderTier';
import { PinLayer, type Pin } from './pinLayer';
import { themePalette } from '../../services/themePalettes';
import { GeoMapHelp } from './GeoMapHelp';
import { geoSession, onGeoSessionReset } from './geoSession';
import { prefersReducedMotion } from '../../lib/motion';
import { nameResolutionStore } from '../../services/interfacePrefs';
import { usePreferenceStore, usePreferenceValue } from '../../services/preferenceStore';
import {
  arcProtocolColorStore,
  mapSkinStore,
  type MapSkin,
} from '../../services/mapPrefs';
/**
 * **There was a `GeoMapVariant` here, and there is one size.**
 *
 * It was `WidgetVariant`, from the widget registry, back when this was a dock
 * widget with a shared overlay for its full size; it outlived the registry
 * because the two sizes were about THIS component - `card` decided whether a
 * marker opened a popup or a popover, and whether the places list, the help
 * card and the zoom buttons appeared at all.
 *
 * `card` was the map's pane in the Packets view's bottom row, and that pane is
 * deleted. What the prop is worth keeping a note of is what it was ARBITRATING:
 * every one of those decisions was "is there room for this?", and with one
 * surface the answer is yes. A second size arriving later is a reason to bring
 * the prop back, not a reason to keep a two-valued union with one value.
 */
import { ZoomControls } from './ZoomControls';
import { createDoubleRightClick } from '../../lib/doubleRightClick';

/**
 * Where maplibre's tile worker actually is.
 *
 * Without this the map renders **nothing at all** under the desktop app's
 * `app://` scheme, and says nothing about it. MapLibre's `defaultWorkerUrl()`
 * is:
 *
 *     const moduleUrl = import.meta.url;
 *     if (!/^https?:/.test(moduleUrl)) return "";
 *
 * Under `app://inwire/assets/index-*.js` that test fails, the worker URL comes
 * back as the empty string, and `new Worker("")` resolves against the document
 * base - so the browser loads **index.html as an ES module worker**, which
 * dies before registering a message handler. Every tile then sits in `loading`
 * for ever with no error beyond one strict-MIME line in a console nobody reads
 * in a packaged build.
 *
 * This is the *third* time the same failure has arrived from a different
 * direction: Vite's dependency pre-bundler mangled the worker's URL (fixed by
 * `optimizeDeps.exclude`), the Express SPA fallback answered the worker request
 * with HTML (fixed by the `maplibreWorker` build plugin), and now a
 * non-http scheme defeats the library's own URL detection. The comments in
 * `vite.config.ts` describe the first two at length.
 *
 * The path is the one `maplibreWorker()` emits, **unhashed on purpose**: the
 * worker imports `./maplibre-gl-shared.mjs` by literal specifier, so the pair
 * has to keep its names and stay adjacent.
 *
 * The guard is maplibre's own test, inverted: under the Vite dev server
 * `import.meta.url` **is** `http://127.0.0.1:3000/node_modules/...`, so the
 * library resolves its worker correctly out of `node_modules` and a hardcoded
 * `/assets/` path - which the dev server does not serve - would break dev to
 * fix production. Measured: it did, and the symptom was the same silent
 * strict-MIME line.
 *
 * **This must come before `setRTLTextPlugin`, and that ordering is the whole
 * fix.** Setting the plugin broadcasts to the workers, which builds the global
 * dispatcher, which acquires the worker pool - so the pool is already running
 * by the time the next statement executes. Written the other way round it
 * still compiles, the call still appears in the bundle, and the worker is
 * still constructed with an empty URL: measured, with `Worker` instrumented in
 * a packaged build, the construction came from `setRTLTextPlugin` one line
 * earlier.
 */
if (!/^https?:/.test(import.meta.url)) {
  maplibregl.setWorkerUrl('/assets/maplibre-gl-worker.mjs');
}

// MapLibre's glyph renderer doesn't shape or bidi-reorder Arabic/Hebrew
// script on its own - without this plugin, place labels in RTL languages
// (Saudi Arabia, Egypt, Israel, etc.) render as disconnected, wrongly-
// ordered letterforms instead of properly joined right-to-left text.
// Loaded from a CDN URL (the standard way to wire this up - the plugin's
// own npm package restricts its "exports" to an ES module entry point that
// isn't a loadable script URL, so it can't be bundled locally the way
// maplibre-gl itself is). `lazy: true` defers fetching the ~130KB shaping
// bundle until a tile actually contains RTL text. Must be called at most
// once per page load, so this sits at module scope, not inside the
/**
 * MapLibre's right-to-left text shaper, shipped with the app.
 *
 * It used to be fetched from unpkg at first use, which is what every example
 * does and what the plugin's own `exports` map pushes you toward. That is a CDN
 * dependency in a web page and something worse in a signed desktop installer:
 * unsigned third-party JavaScript, downloaded and executed on launch, showing
 * up as an unexplained outbound request in the capture of the very person
 * running a packet analyzer.
 *
 * `vite.config.ts`'s `bundledMapAssets()` copies the real file out of
 * `node_modules` at build time, the same way it does maplibre's own worker.
 * `lazy: true` still defers *running* it until a tile actually contains RTL
 * text; what changed is where the 133 kB comes from.
 */
const RTL_TEXT_PLUGIN_URL = '/assets/mapbox-gl-rtl-text.js';

// component. Guarded by status check because Vite HMR re-executes module
// top-level code on every edit-triggered reload in dev, and MapLibre throws
// if this is ever called a second time in the same page session.
if (maplibregl.getRTLTextPluginStatus() === "unavailable") {
  maplibregl.setRTLTextPlugin(RTL_TEXT_PLUGIN_URL, true);
}

// OpenFreeMap: free, no API key, no request limits (donation-supported).
//
// ONE style for all four themes, not the light/dark pair this used to load.
// Everything visible is repainted by `applyBasemapPalette`, so a second style
// bought nothing but a second set of layer names to keep working - and the two
// name their layers nothing alike (`boundary_3` against `boundary_state`,
// `label_country_2` against `place_country_minor`), which is two chances for a
// rule to be written once and silently apply to half the themes.
//
// Positron is the leanest of OpenFreeMap's styles at 55 layers, and an audit of
// every source-layer in it against `applyBasemapPalette` found exactly one it
// did not already recolour (`park`, now covered) - which is what made
// collapsing to a single style cheap.
const BASE_STYLE = "https://tiles.openfreemap.org/styles/positron";

/**
 * The layers that lift the land out of the sea.
 *
 * There is no elevation data behind them, and that is the point. This map used
 * to stream a real DEM from AWS Terrain Tiles, drive a terrain mesh off it and
 * shade it with a hillshade layer - accurate, and the wrong answer for a map
 * whose subject is the arcs drawn over it. Every ridge on Earth rendered
 * underneath the one line you were trying to follow, plus a second tile
 * pyramid downloading continuously to produce it.
 *
 * These are copies of the style's own water polygon, displaced in screen space
 * and painted underneath the real one, which leaves the side wall of a slab
 * standing where the two disagree. See `LAND_LIFT` in `mapTheme.ts` for why
 * that works; the cost is two extra fills of geometry the map has already
 * loaded, and no network at all.
 */
const LAND_WALL_LAYER = (suffix: string) => `inwire-land-wall-${suffix}`;


// The glow that used to be a second, blurred line layer now lives in the arc
// layer's own two-pass draw - `line-blur` has no equivalent in raw WebGL.
const CONNECTIONS_SYNC_THROTTLE_MS = 600;

/**
 * How long to wait before asking again when the style is not built yet.
 *
 * Much shorter than the throttle above, because it is answering a different
 * question. The throttle exists to coalesce a burst of updates that would each
 * cost real work; this is a map that has been open for a few frames and has
 * nothing to draw on yet, where the only cost of asking again is asking again.
 */
const STYLE_WAIT_RETRY_MS = 50;

// How many points to sample along each great circle. Enough that the curve is
// smooth at continental scale without turning sixty routes into thousands of
// coordinates the source has to re-serialise on every sync.
/*
 * **`MERCATOR_BOUNDS` was here and went with the flat map.** It penned the flat
 * projection inside +/-85 latitude (where Web Mercator ends - the poles are at
 * infinity in it) and +/-179.9 longitude.
 *
 * That second number is the one worth keeping written down, because it is a
 * live maplibre-gl bug rather than a fact about projections: a longitude range
 * spanning the full 360 degrees crashes maplibre-gl 6.5.0 outright with
 * "Cannot read properties of null (reading '0')" out of
 * `Transform._calcMatrices` during the first resize, taking the whole React
 * tree with it. Verified by bisection - the throw depends only on the span
 * reaching 360. Anything that sets `maxBounds` here again has to know that.
 *
 * The globe never had an extent: it must be free to spin all the way round, so
 * `applyProjectionMode` clears bounds and never sets them.
 */


/*
 * Far-side occlusion used to be MapLibre's own `opacityWhenCovered`, set to 0
 * because its default (0.2) left a scatter of ghost markers showing through the
 * planet - which reads as a rendering fault rather than as depth. The pins are
 * geometry in a custom layer now and MapLibre does not hide those for us, so
 * the same decision lives in `HORIZON_COS` in pinLayer.ts: a pin past the limb
 * is not drawn at all.
 */

/** Globe: close enough that the planet fills the frame rather than floating in it. */
const GLOBE_MIN_ZOOM = 1.9;

/**
 * Degrees of bearing per pixel dragged, matching MapLibre's own feel.
 *
 * The SIGN is applied at the call site rather than baked in here, so that the
 * one line performing the inversion is visible next to the one that does not.
 */
const BEARING_DEGREES_PER_PIXEL = 0.8;

/** Degrees of tilt per pixel dragged, also MapLibre's value. */
const PITCH_DEGREES_PER_PIXEL = 0.5;

/**
 * Where the map looks when it has never been moved, and where a double
 * right-click puts it back: the whole world, level, north up. The zoom is the
 * constructor's; the projection's floor (`GLOBE_MIN_ZOOM`) wins over it.
 */
const HOME_CENTER: [number, number] = [15, 20];
const HOME_ZOOM = 1;

const ARC_STEPS = 48;

/**
 * How much of the great circle's bow to keep.
 *
 * The true arc is geographically honest and, at this scale, overstated: a dozen
 * routes leaving one city fan out into wide overlapping loops, and what the eye
 * reads is the projection rather than the traffic. Half keeps the arc reading
 * as a route rather than a chord while letting parallel routes stay legible
 * next to each other.
 */
const ARC_CURVATURE = 0.5;

/**
 * Puts the map into the globe.
 *
 * **There was a flat projection and it is gone.** `mapProjectionStore` offered
 * `mercator` or `globe`, with a switcher in the zoom stack; this function
 * branched on it, and half of what it did was undoing the other half - clearing
 * `maxBounds` on the way into globe and restoring them on the way out, swapping
 * the zoom anchor between centre and pointer, and carrying two different
 * minimum zooms because the two projections fail differently at the far end.
 *
 * The globe was always the default and always the better answer for what this
 * map draws: a sphere has no edge for a route to be cut in half by, and no
 * Mercator distortion making a northern hop look like a continental crossing.
 * The flat map's own justification was the whole world at once, which the globe
 * gives at `GLOBE_MIN_ZOOM` anyway.
 *
 * **What has NOT been removed is Mercator arithmetic**, and the distinction
 * matters before somebody deletes more: `arcLayer.ts` and `pinLayer.ts` work in
 * Web Mercator coordinates because that is the space MapLibre's shaders use,
 * and the globe itself crossfades into a flat projection at high zoom. Those
 * are MapLibre's internals, not a user-facing mode.
 *
 * Still a plain function over a map instance rather than an effect body,
 * because it has two callers that must not drift: the effect below, and map
 * creation, where the same settings have to reach a brand new instance.
 */
function applyProjectionMode(
  map: maplibregl.Map,
  styleReady: boolean,
): void {
  // Where a zoom is anchored.
  //
  // MapLibre zooms toward the POINTER by default, which is right for a flat map
  // - you point at a city and it comes to you - and wrong for a globe, where it
  // walks the planet off centre a little on every wheel notch until it is
  // sitting in a corner of the frame with empty space around it. On a sphere
  // the thing being zoomed IS the subject, so the zoom is anchored to the
  // centre and the globe stays put.
  const zoomAnchor = { around: 'center' as const };
  map.scrollZoom.enable(zoomAnchor);
  map.touchZoomRotate.enable(zoomAnchor);

  // A floor on zoom, so a HIGHER number means less zooming out. A globe pulled
  // too far back recedes into a small ball adrift in empty space, which is both
  // useless and unflattering.
  map.setMinZoom(GLOBE_MIN_ZOOM);
  // Always cleared, never set. A bounded globe cannot be rotated past its own
  // edge, and the extent this used to restore belonged to the flat map - which
  // needed it because there are no world copies to pan into. Kept as an
  // explicit call rather than dropped: `setStyle` on a theme change does not
  // reset bounds, so a stale extent from any other source would survive.
  map.setMaxBounds(null);

  // `setProjection` is style state and throws "Style is not done loading"
  // outright if the style is not ready - which, on a freshly constructed map,
  // it is not. React commits the mode effect long before MapLibre has fetched
  // a style over the network, so calling it unguarded took the whole GeoMap
  // subtree down with an uncaught error.
  //
  // The readiness flag is passed in rather than read from `map.isStyleLoaded()`
  // because those are two different questions, and using the second to answer
  // the first is a bug that already cost an afternoon: `isStyleLoaded()` is
  // TRUE only once every source has loaded too, while `setProjection` needs
  // nothing more than the style object itself, which exists the moment
  // `style.load` fires. Guarding on `isStyleLoaded()` therefore rejected the
  // one call that matters - the reapply inside the `style.load` handler - and
  // a theme change silently dropped the map back to Mercator while the
  // preference still said globe.
  //
  // Skipping is safe rather than lossy: `style.load` calls this again, and has
  // to anyway, since setStyle resets the projection on every theme change.
  if (styleReady) map.setProjection({ type: 'globe' });
}

/**
 * Draws the land's side wall.
 *
 * Idempotent - it adds on the first call and sets paint properties on every one
 * after - which costs three lines and means a second `style.load` cannot
 * double-add.
 *
 * Must run on every `style.load`, not once at construction: `setStyle` replaces
 * the whole style object, and added layers go with it. That is the same reason
 * the sky, the projection and the connection layers are all reapplied there,
 * and this joins them rather than being clever about it.
 *
 * Everything is individually guarded. A style whose water is not where this
 * expects should cost the relief and nothing else.
 */
function applyLandLift(
  map: maplibregl.Map,
  wallSteps: number,
  tones: { upper: string; lower: string },
): void {
  let style;
  try {
    style = map.getStyle();
  } catch {
    return; // Style not ready. The `style.load` handler will call again.
  }
  const layers = style?.layers;
  if (!layers) return;

  // The water fill these sit under, found by `source-layer` and never by id -
  // the rule the rest of this basemap code follows, and for the same reason.
  //
  // The FIRST such layer, not the last: the whole effect is that the real water
  // paints back over the displaced copies, so the copies have to go beneath
  // every pass of it. Beneath the first is beneath all of them.
  const waterIndex = layers.findIndex(layer => (
    ('source-layer' in layer ? layer['source-layer'] : undefined) === 'water'
    && layer.type === 'fill'
  ));
  if (waterIndex === -1) return;

  const waterFill = layers[waterIndex] as { id: string; source?: string; filter?: unknown };
  if (!waterFill.source) return;

  // Fewer steps on a software rasterizer: each is a full fill of the water
  // polygon per frame, and the first one alone still reads as a wall.
  for (const step of LAND_LIFT.slice(0, wallSteps)) {
    const id = LAND_WALL_LAYER(step.suffix);
    // The geometry is the skin's business, the colour is not: LAND_LIFT owns
    // how far each step is displaced and in which order they stack, while the
    // two tones come from `wallTonesFor` because the muted skin has to derive
    // them from the theme. See mapTheme.ts for why they cannot simply darken.
    const color = tones[step.suffix];
    try {
      if (map.getLayer(id)) {
        (map.setPaintProperty as (i: string, p: string, v: unknown) => void)(
          id, 'fill-color', color,
        );
        (map.setPaintProperty as (i: string, p: string, v: unknown) => void)(
          id, 'fill-translate', step.translate,
        );
        continue;
      }
      map.addLayer(
        {
          id,
          type: 'fill',
          source: waterFill.source as string,
          'source-layer': 'water',
          // The water fill's own filter, carried across rather than reinvented.
          // It is not the stock one either: `applyDeclutter` has already ANDed
          // the small-water clause onto it by the time this runs, so the walls
          // appear and disappear with the lakes they belong to instead of
          // outlining ghosts of them at world zoom.
          ...(waterFill.filter === undefined ? {} : { filter: waterFill.filter as never }),
          paint: {
            'fill-color': color,
            'fill-translate': step.translate as never,
            // Screen space, not ground space. See LAND_LIFT.
            'fill-translate-anchor': 'viewport',
            // Off, deliberately. The wall's outer edge is covered by the real
            // water fill drawn over it, and an antialiased edge underneath an
            // opaque one blends the wall tone into the sea a pixel early -
            // which reads as exactly the soft outline this replaced.
            'fill-antialias': false,
          },
        },
        // LAND_LIFT is ordered longest displacement first, and each new layer
        // goes immediately under the water fill - so the later, shorter, darker
        // step lands on top of the earlier one. That is what puts the darkest
        // tone at the waterline.
        waterFill.id,
      );
    } catch {
      // One step short of the full wall still leaves a legible map.
    }
  }
}

export interface GeoMapProps {
  packets: Packet[];
  isDark: boolean;
  /** See TrafficTimelineChart: forces a redraw when the theme changes, which
   *  isDark cannot signal between two dark themes. */
  themeKey?: string;
  // **There was a `variant` here and there is one size.** See the note at the
  // top of the file: it chose between the Routing Map view and a pane-sized
  // copy in the Packets view's bottom row, and that pane is deleted.
  //
  // **There was an `onExpand` here and there is no expand button any more.**
  // The card drew one and the dock owned the overlay it opened. Both are gone:
  // the map is a rail VIEW now (`AppView` 'geo', Ctrl+4), which is a pane rather
  // than a modal and is the only size there is - so there is nothing to expand
  // INTO. A button that reopened the same drawing larger was already the thing
  // `hasFullView` existed to ration.
}

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (c) => {
    switch (c) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      default: return "&#39;";
    }
  });

function buildPopupHtml(
  ip: string,
  loc: GeoLocation,
  hostname: string | null,
  /**
   * Set only for this machine's own marker. It names what the point actually
   * is - where this network reaches the internet - because the coordinate
   * belongs to the connection rather than to any host behind it, and a popup
   * that just showed an address would imply otherwise.
   */
  kicker?: string,
) {
  // `city` is null exactly when the provider could only place this at country
  // level, which reads better than the "Unknown" sentinel it replaces.
  const locationLabel = loc.city ? `${loc.city}, ${loc.country}` : loc.country;
  return `
    <div class="font-mono text-xs min-w-[150px] max-w-[220px]">
      ${kicker ? `<div class="text-[9px] uppercase tracking-wider text-muted-foreground mb-0.5">${escapeHtml(kicker)}</div>` : ""}
      <div class="font-bold text-primary break-all mb-1">${escapeHtml(ip)}</div>
      <div class="text-foreground mb-1">${escapeHtml(locationLabel)}</div>
      ${hostname ? `<a href="https://${escapeHtml(hostname)}" target="_blank" rel="noopener noreferrer" class="text-[10px] text-sky-500 hover:underline break-all block">${escapeHtml(hostname)}</a>` : ""}
    </div>
  `;
}

/**
 * What counts as one place, to two decimal places - a little over a kilometre.
 *
 * The same rounding the route aggregation and the locations list use, and
 * deliberately shared: three consumers each deciding for themselves what "the
 * same place" means is how a marker, a line endpoint and a list row end up
 * disagreeing about a single datacentre.
 */
function placeKeyFor(latitude: number, longitude: number): string {
  return `${latitude.toFixed(2)},${longitude.toFixed(2)}`;
}


export const GeoMap: React.FC<GeoMapProps> = ({
  packets,
  isDark,
  themeKey,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  /**
   * Host markers, keyed by PLACE rather than by address.
   *
   * Keyed by IP, this drew one marker per host - so ten servers in one
   * datacentre stacked ten icons on the same pixel, each glowing into the next,
   * and any host that resolved to this machine's own city put a server icon
   * underneath the house. The routes and the locations list had both been
   * collapsing by place since they were written; this is the third consumer
   * finally doing the same.
   */
  /**
   * The 3D pins, and what each one is a pin FOR.
   *
   * The layer knows only where its pins stand; the popup needs the address, the
   * place and the hostname behind one. Kept beside it in a ref rather than in
   * the layer because it is React's data, and because a hover has to read the
   * newest hostname rather than whichever one had resolved when the pin was
   * built.
   */
  const pinLayerRef = useRef<PinLayer | null>(null);
  const pinMetaRef = useRef<Map<string, { ip: string; loc: GeoLocation; kicker?: string }>>(new Map());
  /** The pin the pointer is currently over, so the popup is not rebuilt per frame. */
  const hoveredPinRef = useRef<string | null>(null);
  const popupRef = useRef<maplibregl.Popup | null>(null);
  /** What `arcsForSync` needs to build a frame's worth of arcs. */
  interface ArcInput {
    routes: Route[];
    themeKey: string | undefined;
    arcProtocolColors: boolean;
    accent: string;
  }

  /**
   * The arcs, and the inputs they were built from.
   *
   * Split in two because the build is expensive and its only consumer is
   * throttled. `routes` gets a new identity on every dashboard tick (~10 Hz
   * while capturing), and building here produced up to `MAX_ROUTES` great
   * circles of `ARC_STEPS` points each - about 2,880 coordinate arrays plus 60
   * antimeridian splits - for a `syncConnectionsLayer` that runs at most once
   * per `CONNECTIONS_SYNC_THROTTLE_MS`. Five builds in six were discarded
   * before anything read them, and the two early returns in the sync (style
   * not ready, camera moving) discarded more.
   *
   * So the effect now stores its inputs, which is a property assignment, and
   * `arcsForSync` builds at the point of use and memoises on the input
   * identity. The invariant the throttle relies on is unchanged: whatever the
   * sync reads is the newest data, because it reads the newest inputs.
   */
  const arcInputRef = useRef<ArcInput | null>(null);
  /**
   * The arcs last built, and the signature of the input they were built from.
   *
   * A signature rather than the input object: see `arcsForSync`. `null` means
   * nothing has been built yet, which is also what tells the effect below that
   * its first sync has no burst to coalesce and should not wait for one.
   */
  const connectionsRef = useRef<{ signature: string | null; arcs: Arc[] }>(
    { signature: null, arcs: [] },
  );
  /**
   * The arc layer instance, kept across style reloads.
   *
   * `setStyle` discards the layer but not this object, so the geometry it
   * holds survives a theme change and is re-uploaded by `onAdd` rather than
   * being rebuilt from routes that may not have changed.
   */
  const arcLayerRef = useRef<ArcLayer | null>(null);
  const connectionsSyncTimeoutRef = useRef<number | null>(null);
  const isCameraMovingRef = useRef(false);
  /**
   * Whether the current style object exists yet.
   *
   * Not the same as `map.isStyleLoaded()` - see applyProjectionMode. Set when
   * `style.load` fires, and never cleared, because nothing calls `setStyle`
   * any more: skins and themes repaint the loaded style in place. Its false
   * value is therefore only ever the initial one.
   *
   * That is safe because this is a REF ON THE COMPONENT, not on the map. Every
   * path that builds a new MapLibre instance - expanding the map into its
   * window, collapsing it back, toggling location lookup - unmounts and
   * remounts this component, so a fresh instance always starts against a fresh
   * `false`. Verified from the effect ordering rather than assumed.
   */
  const styleReadyRef = useRef(false);
  /**
   * Bumped every time a NEW MapLibre instance is built.
   *
   * The markers below are attached to a map, not to this component, and the
   * map can be rebuilt without the component unmounting - the init effect
   * depends on the location-lookup setting, so toggling it off and on again
   * destroys one map and builds another. `markersRef` survived that, so the
   * marker sync saw its keys already present, skipped every one of them, and
   * the new map came up with no pins on it and no way to ever get any.
   *
   * A ref cannot express that, because a ref changing does not re-run an
   * effect. This is the same fact as `mapRef.current` in state form, which is
   * what the marker effects actually need to depend on.
   */
  const [mapEpoch, setMapEpoch] = useState(0);

  /**
   * Bumped whenever a new PinLayer is added to the style.
   *
   * Separate from `mapEpoch`, which counts MAP instances. A style reload keeps
   * the map and replaces every custom layer on it, so the pins need waking on
   * an event the map epoch never sees - which is how switching basemap skin
   * used to leave the globe with no pins on it until a location resolved.
   */
  const [pinEpoch, setPinEpoch] = useState(0);

  // See useThemeToken: read inline while a pin is built this could resolve to
  // nothing and bake the fallback accent into a mesh that is then never
  // rebuilt, since a pin is created once per newly-seen place.
  const accent = useThemeToken('--primary', '#f97316');

  // Under the colourful skin the basemap is NOT themed - see mapTheme.ts - and
  // the sky is the only thing the theme touches, to the extent of day against
  // night. Under the muted skin every colour on the map is a function of the
  // theme, which is the whole point of it.
  //
  // Read through refs by the `style.load` handler, which is registered once and
  // must not be re-registered on every theme change.
  const isDarkRef = useRef(isDark);
  isDarkRef.current = isDark;

  const [skin] = usePreferenceValue(mapSkinStore);
  const [arcProtocolColors] = usePreferenceValue(arcProtocolColorStore);

  // The muted skin's four colours. Three come from the palette, which needs no
  // document; `--primary` has no palette counterpart and comes from the token
  // the markers already read. Computed for both skins because it is four table
  // lookups, and a branch here would only move the cost to the reader.
  const basemapTokens: BasemapTokens = basemapTokensFor(themeKey, accent);
  const skinRef = useRef<MapSkin>(skin);
  skinRef.current = skin;
  const basemapTokensRef = useRef(basemapTokens);
  basemapTokensRef.current = basemapTokens;

  /**
   * How many wall steps this machine can afford, captured where the tier is
   * probed.
   *
   * A ref rather than a second `probeRenderTier()` call: the probe builds a
   * throwaway WebGL context to ask what it is running on, and the skin effect
   * needs the answer without paying for it again.
   */
  const wallStepsRef = useRef<number>(LAND_LIFT.length);

  /**
   * Which distinct PLACES have been seen, not which hosts.
   *
   * Kept in a ref so it only ever grows: the question is "which places have
   * talked to this machine this session", which a list of what is currently
   * plotted would answer differently every time old traffic aged out.
   *
   * A map rather than the set of keys it used to be, because the expanded
   * counter now names these places rather than only counting them - and the
   * count is still just its size, so the two cannot disagree.
   */
  // All of this lives in a module-level session rather than in the component,
  // because this component is unmounted whenever the Routing Map is not the
  // active view. See geoSession for what that costs when it is not.
  const [nameResolution] = usePreferenceStore(nameResolutionStore);

  const sessionRef = useRef(geoSession());
  /**
   * One state commit per burst of resolutions, not one per resolution.
   *
   * Each answer used to do `setLocations(new Map(...))` and, for the hostname,
   * a second one - so a lookup batch (up to `MAX_BATCH`, 25 in `geoIpService`)
   * cost up to fifty O(n) Map copies and fifty renders of this component,
   * arriving in a burst at capture start, which is exactly when the map is
   * least responsive. `sessionRef` already holds the authoritative maps; these
   * `setState` calls only exist to tell React they changed.
   *
   * `setTimeout` rather than `requestAnimationFrame`: a hidden tab gets no
   * animation frames (measured elsewhere in this repo at zero callbacks over
   * 3.8 s), and these maps feed `routes` and the location list, not just paint.
   * The trailing commit always lands, which is what the late-answer rule above
   * requires - a lookup that resolves after the scan has moved on must still
   * draw.
   */
  const resolutionCommitRef = useRef<number | null>(null);
  const placesRef = { current: sessionRef.current.places };
  const unresolvedRef = { current: sessionRef.current.unresolved };
  const seenIps = { current: sessionRef.current.seenIps };
  const scanStateRef = { current: sessionRef.current.scan };

  // State mirrors of the session, so React re-renders when they change. Seeded
  // FROM the session rather than empty, which is what makes a remount paint the
  // map it had rather than an empty one that fills in again.
  const [geoStats, setGeoStats] = useState<{
    places: GeoPlace[];
    unresolved: number;
  }>(() => ({
    places: Array.from(sessionRef.current.places.values(), (place) => ({ ...place })),
    unresolved: sessionRef.current.unresolved.size,
  }));
  const [locations, setLocations] = useState<Map<string, GeoLocation>>(
    () => new Map(sessionRef.current.locations),
  );
  const [hostnames, setHostnames] = useState<Map<string, string | null>>(
    () => new Map(sessionRef.current.hostnames),
  );
  /**
   * The same map, for the hover handler to read.
   *
   * The handler is registered once per map instance, so it closes over the
   * hostnames that had resolved at that moment - and reverse DNS arrives
   * whenever it arrives. Re-registering on every resolution would rebind two
   * map listeners per name; a ref is the cheaper half of that trade.
   */
  const hostnamesRef = useRef(hostnames);
  hostnamesRef.current = hostnames;
  const [ispLocation, setIspLocation] = useState<GeoLocation | null>(null);

  /**
   * Re-scan everything when a lookup is switched back on.
   *
   * The scan marks an address as asked BEFORE the answer comes back, so with a
   * lookup disabled every address in the buffer is permanently recorded as
   * already handled. Without this, turning the setting on resolves nothing that
   * has already been captured - the map stays empty until the buffer is cleared
   * - and the feature looks broken in exactly the way that makes someone turn
   * it off again.
   */
  useEffect(() => {
    return onNameResolutionEnabled(() => {
      const session = sessionRef.current;
      session.seenIps.clear();
      session.unresolved.clear();
      session.scan.scannedCount = 0;
      session.scan.firstPacketId = -1;
      setLocations(new Map(session.locations));
      setGeoStats({
        places: Array.from(session.places.values(), (place) => ({ ...place })),
        unresolved: 0,
      });
      // Ask again for this machine's own location, which was skipped while the
      // lookup was off.
      resolveSelfLocation().then((loc) => {
        if (loc) setIspLocation(loc);
      });
    });
  }, []);

  /**
   * Empty the map when the capture it was describing is cleared.
   *
   * The session is emptied in place by `resetGeoSession`, so everything read
   * through `sessionRef` is already right by the time this runs; what it cannot
   * do is re-render a component, because `locations`, `hostnames` and the stats
   * were copied into React state when they were learned. This copies the now
   * empty maps back over them.
   *
   * Without it, clearing the buffer left the previous capture's pins standing
   * while its arcs vanished - the arcs are folded from the packet buffer, which
   * really had emptied.
   */
  useEffect(() => onGeoSessionReset(() => {
    const session = sessionRef.current;
    setLocations(new Map(session.locations));
    setHostnames(new Map(session.hostnames));
    setGeoStats({ places: [], unresolved: 0 });
    setIspLocation(null);
  }), []);

  // This machine's own public location, from the service rather than a fetch
  // here. The request is memoized there, so this component mounting again -
  // which it does every time the Routing Map view is returned to - reuses the
  // answer instead of asking a third party where the user is a second time.
  useEffect(() => {
    let cancelled = false;
    resolveSelfLocation().then((loc) => {
      if (!cancelled && loc) setIspLocation(loc);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Refs are what keep the counts monotonic; this mirrors them into state so
  // the counter re-renders. Cheap, and only called when a lookup settles.
  const publishStats = React.useCallback(() => {
    setGeoStats({
      // Copied out on publish rather than shared: the ref is mutated in place
      // as lookups settle, and handing React the live map would mean a render
      // that reads a list already changed underneath it.
      places: Array.from(placesRef.current.values(), (place) => ({ ...place })),
      unresolved: unresolvedRef.current.size,
    });
  }, []);

  /**
   * Records one resolved host against the place it belongs to.
   *
   * Both precisions land here, keyed differently: a city-level result by its
   * rounded coordinates, so ten servers in one datacentre are one row, and a
   * country-level result by its country, so every host the provider could only
   * put in Germany is one Germany row rather than thirty. The `precision` field
   * is what the list reads to decide whether the row can be flown to and what
   * the map is allowed to draw.
   */
  const recordPlace = React.useCallback((location: GeoLocation) => {
    const key = location.precision === 'city'
      ? `${location.latitude.toFixed(2)},${location.longitude.toFixed(2)}`
      : `country:${location.countryCode || location.country}`;

    const existing = placesRef.current.get(key);
    if (existing) {
      existing.hosts += 1;
    } else {
      placesRef.current.set(key, {
        key,
        latitude: location.latitude,
        longitude: location.longitude,
        // `city` is null exactly when the provider could only reach country
        // level, which is the case this label falls back for.
        label: location.city ?? location.country,
        country: location.country,
        countryCode: location.countryCode,
        hosts: 1,
        precision: location.precision,
      });
    }
    publishStats();
  }, [publishStats]);

  /** See `resolutionCommitRef`: coalesces a burst of answers into one render. */
  const commitResolutions = () => {
    if (resolutionCommitRef.current !== null) return;
    resolutionCommitRef.current = window.setTimeout(() => {
      resolutionCommitRef.current = null;
      setLocations(new Map(sessionRef.current.locations));
      setHostnames(new Map(sessionRef.current.hostnames));
    }, 0);
  };

  // Resolve geolocation + reverse-DNS hostname for newly-seen public IPs.
  //
  // Scans the packets appended since the last run rather than a fixed
  // slice(-20). The old slice silently dropped IPs at any rate above roughly
  // 200 packets/second - more than twenty could arrive between two runs, and
  // whatever fell outside the window was never looked up at all. Now that the
  // buffer arrives here on a 500ms throttle that window is always overrun, so
  // the fixed slice would have turned an intermittent gap into a constant one.
  useEffect(() => {
    const state = scanStateRef.current;

    // The same reset test the packet list's auto-size effect uses: the live
    // buffer keeps appending while dropping its oldest, so length alone cannot
    // tell a genuine reset from a trim - a *changed* first packet id can.
    const firstPacketId = packets.length > 0 ? packets[0].id : -1;
    if (packets.length < state.scannedCount || firstPacketId !== state.firstPacketId) {
      state.firstPacketId = firstPacketId;
      state.scannedCount = 0;
    }
    if (packets.length === state.scannedCount) return;

    const newPackets = packets.slice(state.scannedCount);
    state.scannedCount = packets.length;

    newPackets.forEach((p) => {
      [p.source, p.destination].forEach((ip) => {
        if (!seenIps.current.has(ip) && isLocatable(ip)) {
          seenIps.current.add(ip);
          resolveIP(ip).then((result) => {
            // A network-level failure leaves the address unmarked so a later
            // packet from the same host tries again. Without this, one blip
            // meant that host was never located for the life of the page,
            // because this scan only ever asks once per address.
            if (result.kind === "failed" && result.retryable) {
              seenIps.current.delete(ip);
              return;
            }
            if (result.kind === "failed") {
              unresolvedRef.current.add(ip);
              publishStats();
              return;
            }
            if (result.kind !== "resolved") return;
            // Every resolved host is listed, whatever precision it came back
            // at. What precision decides is whether it is DRAWN.
            recordPlace(result.location);

            // The accuracy bar, unchanged: a country-level answer is the
            // provider's centroid for the whole country - a real coordinate,
            // but not this host's - so plotting it is what puts a pin in a
            // field in Kansas and gives it the same weight as a real fix. It
            // stays out of `locations`, which is what markers and routes are
            // built from; the list above is where it becomes visible instead.
            if (result.location.precision !== "city") return;

            sessionRef.current.locations.set(ip, result.location);
            commitResolutions();
          });
          resolveHostname(ip).then((hostname) => {
            sessionRef.current.hostnames.set(ip, hostname);
            commitResolutions();
          });
        }
      });
    });
  }, [packets]);

  /**
   * Who is talking to whom, folded one packet at a time.
   *
   * Deliberately knows nothing about geography. Counting packets per address
   * pair is fixed the moment a packet arrives, so it is kept across ticks and
   * only the newly arrived packets are read; where those addresses ARE is
   * still being looked up, and answers land seconds later and out of order.
   * Keeping the two apart is what lets a lookup that arrives late still draw
   * its line, without the whole buffer being re-read to find out. See
   * geoRoutes for the split and useIncrementalAggregate for the fold.
   */
  const pairs = useIncrementalAggregate(
    packets,
    () => new Map<string, AddressPair>(),
    addPacketToPairs,
    // A COPY, not the accumulator itself. The fold mutates one Map in place
    // for the life of the capture, so handing that Map back gives a value
    // whose identity never changes - and `routes` below is a useMemo keyed on
    // it. Returning the accumulator froze every arc: once each address had
    // resolved, `locations` stopped changing too and nothing in the dependency
    // list ever moved again, so new traffic between two already-located hosts
    // drew nothing and the weights stood still for the rest of the capture.
    // The copy is O(distinct pairs) once a tick, which is the budget
    // `finalize` is explicitly allowed to spend; the fold it protects is
    // O(packets).
    (map) => new Map(map),
  );

  // The lines themselves. Redone whenever a lookup lands, which is what makes
  // a late answer appear - and affordable, because it is a pass over the pairs
  // rather than over the buffer.
  const routes = React.useMemo(() => {
    const locate = (ip: string): [number, number] | null => {
      // An address with no geography of its own - a LAN host, this machine -
      // is drawn from where its traffic actually enters the internet. That is
      // the one honest coordinate available for it, and the marker there is
      // shaped differently so it does not pass as a located host.
      if (!isLocatable(ip) && ispLocation && !isNaN(ispLocation.longitude)) {
        return [ispLocation.longitude, ispLocation.latitude];
      }
      const loc = locations.get(ip);
      if (loc && !isNaN(loc.longitude)) {
        return [loc.longitude, loc.latitude];
      }
      return null;
    };
    return aggregateRoutes(pairs.values(), locate);
  }, [pairs, locations, ispLocation]);

  /**
   * The arcs for `arcInputRef`'s current contents, built at most once each.
   *
   * Called from the sync rather than from the effect - see `connectionsRef`.
   * The identity check is what makes repeated syncs free: a sync that bails on
   * a moving camera and reschedules does not rebuild anything.
   */
  const arcsForSync = (): Arc[] => {
    const input = arcInputRef.current;
    if (input === null) return connectionsRef.current.arcs;
    // **By content, not by identity, and that is the whole of this fix.**
    //
    // `arcInputRef.current` is assigned a fresh object literal every time the
    // effect below runs, and `routes` inside it is a fresh array every time -
    // `useIncrementalAggregate`'s `finalize` returns a COPY, deliberately,
    // because returning the accumulator froze every arc. So an identity check
    // here could never hit on a data-driven sync, only on a camera-driven one.
    //
    // The consequence was invisible and constant: during a live capture with
    // the map open, the arcs were rebuilt every CONNECTIONS_SYNC_THROTTLE_MS
    // whether or not a single route had changed - ~2,880 great-circle samples,
    // each a pair of trig calls, and a fresh ~829 kB Float32Array uploaded to
    // the GPU, three times a second at the default refresh. `arcRebuilds` in
    // `scripts/perf/map-bench.browser.js` is the counter for exactly this, and
    // its header says driving it to zero is what that bench exists for.
    //
    // The signature is cheap because the input is small: MAX_ROUTES caps this
    // at 60 entries, and `key` is already the canonical direction-independent
    // identity of a pair of places. `total` is in it because the line weight is
    // normalised against the busiest route, and `dominantProtocol` because it
    // picks the colour - those are the only two fields of a route the geometry
    // reads.
    const signature = `${input.themeKey}\u0000${input.arcProtocolColors}\u0000${input.accent}\u0000`
      + input.routes.map((r) => `${r.key}:${r.total}:${r.dominantProtocol}`).join('|');
    if (connectionsRef.current.signature === signature) return connectionsRef.current.arcs;

    const { routes: forRoutes, themeKey: forTheme, arcProtocolColors: byProtocol, accent: forAccent } = input;
    // Weight is normalised against the busiest route rather than an absolute
    // packet count: what the line width should say is "this one is busier than
    // that one", and an absolute scale would render every line hairline-thin
    // on a quiet capture and uniformly fat on a loud one.
    const busiest = Math.max(1, ...forRoutes.map((r) => r.total));

    const arcs = forRoutes.flatMap((route) => {
      // Two questions, and only one of them is worth colour at a time. Coloured
      // by protocol, an arc answers "what is this route carrying" in the same
      // nine hues the protocol donut uses. Painted the accent, it answers "where
      // is my traffic going" and spends no attention on the first - which is
      // often the question being asked, and colour encoding something nobody is
      // reading is noise. See services/mapPrefs.
      const color = byProtocol
        ? protocolColor(route.dominantProtocol, forTheme)
        : forAccent;
      const weight = route.total / busiest;
      // Still split at the antimeridian, in BOTH projections. On the globe the
      // two halves meet at the same point on the sphere, so the cut is
      // invisible; under Mercator, with world copies disabled, a single
      // unsplit route would be drawn back across the whole map instead of over
      // the Pacific. One geometry for both is also what makes the shader's
      // mercator-globe crossfade safe, since the same vertices have to be
      // valid at every point of the transition.
      return splitAtAntimeridian(
        greatCircleArc(route.from, route.to, ARC_STEPS, ARC_CURVATURE),
      ).map((points) => ({ points, color, weight }));
    });

    connectionsRef.current = { signature, arcs };
    return arcs;
  };

  // Sync the connections GeoJSON source/layer with the map's currently loaded
  // style. Re-invoked on every style load (including after theme switches,
  // since setStyle() tears down all custom sources/layers) as well as
  // whenever the connections data itself changes.
  const syncConnectionsLayer = () => {
    const map = mapRef.current;
    // No map at all: nothing to retry into, and a retry loop would outlive the
    // component. Every other bail below reschedules.
    if (!map) return;

    // The style is what the connection layers are added to, and until
    // `style.load` there is no style object to add them to. This used to return
    // and drop the update on the floor: the next attempt only came when
    // `routes` changed again, so on a capture that had already stopped the
    // lines simply never came back.
    //
    // `styleReadyRef`, NOT `map.isStyleLoaded()` - the same distinction the
    // theme effect documents, and the reason the arcs took seconds to appear on
    // a freshly built map. `isStyleLoaded()` is true only once every SOURCE has
    // finished loading too, so on a map that has just opened at overlay size
    // and is streaming a screenful of tiles it is false for as long as that
    // takes, and each attempt backed off another CONNECTIONS_SYNC_THROTTLE_MS
    // before asking again. Adding a custom WebGL layer needs the style object
    // to exist and nothing more; whether the basemap underneath it has finished
    // downloading is a different question, and not this one.
    if (!styleReadyRef.current) {
      scheduleConnectionsSync(STYLE_WAIT_RETRY_MS);
      return;
    }

    // A GeoJSON setData() re-tessellates and repaints the line layer -
    // real main-thread work. Doing that on the same frame as an in-progress
    // pan/zoom gesture is exactly what caused the map to visibly stutter
    // when packets kept arriving while the user was moving the camera.
    //
    // Rescheduled rather than dropped, for the same reason, plus a sharper
    // one: `isCameraMovingRef` is set by `movestart` and cleared by `moveend`,
    // and a move that is interrupted - by a style swap, or by the map being
    // torn down mid-gesture - never delivers its `moveend`. The flag then
    // stays true for the life of the map and every future sync silently
    // returns. With a retry the worst case is a late redraw instead of a
    // permanently empty layer.
    if (isCameraMovingRef.current) {
      scheduleConnectionsSync();
      return;
    }

    if (!arcLayerRef.current) arcLayerRef.current = new ArcLayer();
    const layer = arcLayerRef.current;

    // `setStyle` removes the layer but leaves this object holding its
    // geometry, so re-adding is enough - onAdd rebuilds the buffer.
    if (!map.getLayer(layer.id)) map.addLayer(layer);
    layer.setArcs(arcsForSync());
  };

  // During active capture `packets` (and therefore `routes`)
  // changes on literally every incoming packet, which could otherwise mean
  // calling MapLibre's setData() - re-tessellating and repainting the line
  // layer - many times a second. Coalesce bursts into one update per
  // CONNECTIONS_SYNC_THROTTLE_MS: the ref always holds the latest data, but
  // only one sync is scheduled at a time.
  //
  // Deliberately no cleanup/clearTimeout here (and no separate unmount-only
  // effect for it either - that was tried and is exactly what broke this):
  // under StrictMode, React double-invokes every effect once in dev
  // (mount -> cleanup -> mount), including a *separate* `useEffect(() => ()
  // => clearTimeout(...), [])`. That cleanup fired between the two mount
  // passes and cancelled the timeout THIS effect had just scheduled, without
  // resetting the ref to null - so the `!== null` guard below stayed
  // permanently tripped and no sync ever ran again for the component's
  // whole lifetime (confirmed via logging: the effect kept re-running, but
  // its scheduled timeout callback never once fired). Skipping cleanup is
  // safe here: `syncConnectionsLayer` already no-ops once `mapRef.current`
  // is torn down, so a stray timeout firing after unmount is harmless.
  /**
   * One pending sync at a time, with the latest data.
   *
   * `connectionsRef` always holds the newest FeatureCollection, so a coalesced
   * burst loses nothing - the trailing call reads the same ref.
   */
  const scheduleConnectionsSync = (delay: number = CONNECTIONS_SYNC_THROTTLE_MS) => {
    if (connectionsSyncTimeoutRef.current !== null) return;
    connectionsSyncTimeoutRef.current = window.setTimeout(() => {
      // Cleared BEFORE the sync, so a sync that decides to reschedule itself
      // is able to.
      connectionsSyncTimeoutRef.current = null;
      syncConnectionsLayer();
    }, delay);
  };

  useEffect(() => {
    arcInputRef.current = { routes, themeKey, arcProtocolColors, accent };
    // **Leading edge on the first one.** The throttle exists to coalesce
    // bursts, and on mount there is no burst to coalesce - it is the first
    // call. Scheduling it at the full CONNECTIONS_SYNC_THROTTLE_MS meant the
    // ArcLayer was not built or added to the style until 600ms after the map
    // mounted, every single time the map was opened, waiting for a second call
    // that had not been made.
    //
    // `style.load` also calls `syncConnectionsLayer` directly and rescued
    // this - but only when it fired AFTER this effect, which on a warm HTTP
    // cache it may not. So the 600ms was paid sometimes, which is worse than
    // always: it is the shape of delay that gets blamed on the network.
    //
    // The argument is already written down one directory over, in
    // `useThrottledValue.ts`: "a panel fills in the moment a capture starts
    // rather than after a blank interval".
    scheduleConnectionsSync(connectionsRef.current.signature === null ? 0 : undefined);
    // `accent` and the switch join the dependencies because the arc colours are
    // baked into a vertex buffer rather than read at draw time - the sync is
    // what rebuilds it, so anything that changes a colour has to wake this.
  }, [routes, themeKey, arcProtocolColors, accent]);

  /**
   * Puts a map into the globe, and levels the camera.
   *
   * It followed a projection PREFERENCE until there was only one projection, so
   * what is left is the half that still has work to do: `mapEpoch`. A rebuilt
   * map - a lost GPU context, a theme change that calls `setStyle` - is a new
   * instance that has never been told which projection it is in, and
   * `setProjection` is style state that does not survive a `setStyle`.
   *
   * The camera move is separate from the projection and deliberately modest -
   * flattening the pitch and squaring the bearing, not flying anywhere. The
   * whole point of `geoSession`'s stored camera is that the map stays where you
   * left it.
   */
  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;

    applyProjectionMode(map, styleReadyRef.current);

    const settled = { pitch: 0, bearing: 0 };
    // Already level: nothing to fly to. Without this check every run of this
    // effect - including the one on mount - played a 600 ms animation from
    // 0/0 to 0/0, and every frame of it fired `move`, and every `move`
    // repositioned every marker.
    if (Math.abs(map.getPitch()) < 0.01 && Math.abs(map.getBearing()) < 0.01) return;
    // A camera flight is the most vestibular-hostile thing this panel does, and
    // it is JavaScript rather than CSS, so the blanket reduced-motion rule
    // cannot reach it - the same reasoning as the location counter's flight.
    if (prefersReducedMotion()) map.jumpTo(settled);
    else map.easeTo({ ...settled, duration: 600 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mapEpoch]);

  /**
   * Drag to rotate, with the bearing reversed.
   *
   * MapLibre's own `DragRotateHandler` is disabled, because it exposes exactly
   * two controls - `enable()` and `disable()` - and no way to change which way
   * a drag turns the map. Reversing it therefore means owning the gesture.
   *
   * Only the BEARING is reversed. Tilt keeps MapLibre's convention, where
   * dragging up tilts the camera down toward the horizon: that one has a
   * physical logic to it (the ground is being pushed away from you) that the
   * compass does not, and inverting both would have made the gesture feel
   * broken in a second way while fixing the first.
   *
   * The gesture is the same one MapLibre uses - right-drag, or ctrl with the
   * left button - so nothing has to be relearned except the direction. The
   * context menu is suppressed for the duration, which is what MapLibre does
   * too and the reason a right-drag is usable as a gesture at all.
   *
   * **A double right-click goes home** - the whole world, level, north up -
   * because a right-drag is exactly what leaves a globe at an angle nobody can
   * find their way back from. It lives here because it is the same button;
   * `lib/doubleRightClick.ts` decides which presses were clicks.
   */
  useEffect(() => {
    const map = mapRef.current;
    const surface = map?.getCanvasContainer();
    if (!map || !surface) return;

    let rotating = false;
    let lastX = 0;
    let lastY = 0;
    const rightClicks = createDoubleRightClick();

    const goHome = () => {
      const home = {
        center: HOME_CENTER,
        zoom: Math.max(HOME_ZOOM, map.getMinZoom()),
        pitch: 0,
        bearing: 0,
      };
      // Reduced motion: a jump, for the reason the settle effect above gives.
      if (prefersReducedMotion()) map.jumpTo(home);
      else map.easeTo({ ...home, duration: 800 });
    };

    // The same test MapLibre applies, so the gesture is unchanged and only
    // its direction differs: `(button === 0 && ctrlKey) || (button === 2 &&
    // !ctrlKey)`. metaKey is added for the Mac equivalent.
    const isRotateGesture = (e: PointerEvent) =>
      (e.button === 0 && (e.ctrlKey || e.metaKey)) ||
      (e.button === 2 && !e.ctrlKey && !e.metaKey);

    const onDown = (e: PointerEvent) => {
      if (!isRotateGesture(e)) return;
      if (e.button === 2) rightClicks.press({ x: e.clientX, y: e.clientY, at: performance.now() });
      rotating = true;
      lastX = e.clientX;
      lastY = e.clientY;
      // Capture, so a drag that leaves the canvas keeps rotating rather than
      // stopping dead at the edge.
      surface.setPointerCapture?.(e.pointerId);
      e.preventDefault();
    };

    const onMove = (e: PointerEvent) => {
      if (!rotating) return;
      const dx = e.clientX - lastX;
      const dy = e.clientY - lastY;
      lastX = e.clientX;
      lastY = e.clientY;
      // MINUS is the inversion. MapLibre's own handler ADDS here - its move
      // function reduces to `bearingDelta = (current.x - previous.x) * 0.8` -
      // so dragging right turns the map one way by default and the other way
      // now. Worth stating as fact rather than intuition: the first attempt at
      // this reversed the sign the wrong way round, faithfully reproducing the
      // default, and only reading MapLibre's own source settled it.
      map.setBearing(map.getBearing() - dx * BEARING_DEGREES_PER_PIXEL);
      // Tilt keeps the default direction and so keeps the default sign.
      map.setPitch(map.getPitch() - dy * PITCH_DEGREES_PER_PIXEL);
    };

    const stop = (e: PointerEvent) => {
      if (!rotating) return;
      rotating = false;
      surface.releasePointerCapture?.(e.pointerId);
      if (e.type !== 'pointerup' || e.button !== 2) return;
      if (rightClicks.release({ x: e.clientX, y: e.clientY, at: performance.now() }) === 'double') goHome();
    };

    // Only while the gesture is running - a plain right-click on the map
    // should still open the browser's menu.
    const onContextMenu = (e: MouseEvent) => {
      if (rotating) e.preventDefault();
    };

    surface.addEventListener('pointerdown', onDown);
    surface.addEventListener('pointermove', onMove);
    surface.addEventListener('pointerup', stop);
    surface.addEventListener('pointercancel', stop);
    surface.addEventListener('contextmenu', onContextMenu);
    return () => {
      surface.removeEventListener('pointerdown', onDown);
      surface.removeEventListener('pointermove', onMove);
      surface.removeEventListener('pointerup', stop);
      surface.removeEventListener('pointercancel', stop);
      surface.removeEventListener('contextmenu', onContextMenu);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mapEpoch]);

  // Create the map once on mount.
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;

    // Which kind of renderer this is about to draw on - see renderTier.ts.
    // Asked before construction because two of the answers are constructor
    // options. On a GPU every value below is the default.
    const tier = TIER_SETTINGS[probeRenderTier()];
    // Handed to the skin effect, which needs the number without paying for a
    // second WebGL probe to get it.
    wallStepsRef.current = tier.wallSteps;

    const map = new maplibregl.Map({
      container: containerRef.current,
      style: BASE_STYLE,
      // No `pixelRatio` override, on any renderer. The map always draws at the
      // display's own resolution - see renderTier.ts for why the software tier
      // does not buy frames by going soft.
      //
      // Tile cross-fade. MapLibre's default of 300 ms means every tile arrival
      // drives ~18 animated frames; on a renderer that cannot afford frames
      // that is pure cost for an effect nobody is watching.
      fadeDuration: tier.fadeDuration,
      // Where the map was last pointing, if it has been open before this
      // session. Someone who flew to a city and then left for another view
      // should not come back to the world view.
      center: geoSession().camera?.center ?? HOME_CENTER,
      zoom: geoSession().camera?.zoom ?? HOME_ZOOM,
      // `applyProjectionMode` sets the real floor a moment later; this is
      // only what the map is constructed with, before its style exists. Kept
      // looser than `GLOBE_MIN_ZOOM` deliberately - a constructor value that
      // was already the final floor would silently hide a failure to call
      // `applyProjectionMode` at all.
      minZoom: 1.1,
      maxZoom: 14,
      // One world, not an endless ribbon of them. MapLibre repeats the map
      // horizontally by default, so panning east just kept handing back
      // another copy of the same continents.
      renderWorldCopies: false,
      // Added by hand below rather than here, so it can be positioned away
      // from the zoom controls and the location counter. See addControl.
      attributionControl: false,
      // MapLibre's own resize observer is off, because this component runs a
      // better one below. Left on, the two both call resize() and the canvas is
      // cleared twice per frame instead of once - see the note there.
      trackResize: false,
      // Rotation and tilt, previously off outright. A globe that cannot be
      // spun is a picture of a globe, and the flat map gains the same depth
      // from being tilted - the great circles stop reading as decoration and
      // start reading as paths over a surface.
      maxPitch: 85,
      // Rotation is handled by this component, not by MapLibre - see the
      // drag-to-rotate effect. MapLibre's own handler has no way to reverse
      // its bearing direction, and that is the whole reason ours exists.
      dragRotate: false,
      // No cooperative gestures, in either size. They existed to stop the wheel
      // being swallowed by the compact card while the sidebar around it is
      // being scrolled, and the price was a "use ctrl + scroll to zoom" overlay
      // on every wheel event over the one panel whose whole purpose is being
      // zoomed into. The wheel now zooms the map directly; scrolling the
      // sidebar means putting the pointer beside the map rather than on it.
    });

    // No AttributionControl. The credit is a licence condition, not a widget,
    // and it lives in GeoMapHelp, which renders on every map there is - which
    // is what deleting the pane-sized copy settled. The old note here was an
    // argument for why a 256px card could show tiles with no visible credit on
    // it (one click away, through its own expand control); there is no card and
    // no click, so the credit is simply on screen.
    //
    // and MapLibre's compact control could only ever say that one thing - in
    // the corner where a question mark is far more use. It lives in
    // GeoMapHelp's panel now, under the two things somebody actually opens that
    // corner to find out: what the pins mean, and how to move the camera.
    //
    // What went with it: three MapLibre states that all had to be undone by
    // hand (it arrives expanded, re-expands from `_updateCompact()` on every
    // resize, and its click handler moves `maplibregl-compact-show` and the
    // `<details>` `open` attribute in opposite directions), a click handler, a
    // mousedown click-away, a class of our own and three CSS rules keyed on it.

    // Both have to happen on every style load: setStyle replaces the entire
    // style object, discarding the custom layers AND every paint property this
    // has written.
    map.on("style.load", () => {
      styleReadyRef.current = true;
      // Refs, not the values closed over: this handler is registered once, and
      // by the time it fires the skin or the theme may already have moved.
      applySkin(map, skinRef.current, basemapTokensRef.current);
      // Borders and labels, thinned. Style structure rather than theme colour,
      // so unlike the repaint above this belongs only here - it has nothing to
      // redo when the skin or the tokens change.
      applyDeclutter(map);
      // The land's side wall. Layers are style state and were discarded with
      // everything else.
      applyLandLift(
        map,
        tier.wallSteps,
        wallTonesFor(skinRef.current, basemapTokensRef.current),
      );
      // The sky is part of the style, so setStyle discards it exactly like the
      // basemap paint and the connection layers. Everything that has to be
      // reapplied together is reapplied here, together.
      map.setSky(skyFor(isDarkRef.current));
      // Projection is a property of the style, not of the map, so a theme
      // change resets it to Mercator. Reapplied here for the same reason the
      // sky and the connection layers are.
      applyProjectionMode(map, true);
      syncConnectionsLayer();
      // The pins are a custom layer, so they go the way of every other one on a
      // style reload. Added LAST, after the arcs, because a pin standing on the
      // surface should be drawn over the routes leaving it rather than sliced
      // through by them.
      const pinLayer = new PinLayer();
      map.addLayer(pinLayer);
      pinLayerRef.current = pinLayer;
      // A fresh layer holds no pins; this wakes the sync effect that fills it.
      setPinEpoch((n) => n + 1);
    });
    map.on("movestart", () => {
      isCameraMovingRef.current = true;
    });
    map.on("moveend", () => {
      isCameraMovingRef.current = false;
      syncConnectionsLayer();
    });

    /**
     * The GPU context can go away under a running map, and the style goes with
     * it.
     *
     * A driver reset, a GPU process crash, a laptop switching graphics adapter:
     * Chromium reports it to the renderer as a lost context, and the log line
     * that gives it away in a terminal is `command_buffer_proxy_impl.cc ... GPU
     * state invalid`. MapLibre handles the WebGL half itself and handles it
     * well - `_contextLost` calls `preventDefault()` so the browser will
     * restore, snapshots the style, and `_contextRestored` puts it back with
     * `setStyle(..., { diff: false })`. That reload fires `style.load`, which is
     * this component's existing recovery path: the skin, the declutter, the land
     * wall, the sky, the projection, the arcs, and a fresh `PinLayer`. So the
     * map really does come back on its own.
     *
     * **What MapLibre cannot know is that this component caches the answer.**
     * `_contextLost` ends with `style.destroy(); this.style = null`, and every
     * "may I touch the style?" question here is asked of `styleReadyRef`, not of
     * MapLibre. Left true across the gap, each guard waves through a call
     * against a style that no longer exists.
     *
     * That is not theoretical. `_contextRestored` calls `resize()` before the
     * new style has loaded; `resize()` fires `moveend`; the handler directly
     * above calls `syncConnectionsLayer()`; and `addLayer` throws **Style is
     * not done loading.** - out of `_contextRestored` itself, so MapLibre's own
     * restore is abandoned partway, before its closing `_update()`.
     *
     * **Be accurate about what that costs, because it is narrower than it
     * looks.** The layers still come back: `style.load` fires from the
     * `setStyle` regardless, and its handler re-adds the arcs and builds a new
     * `PinLayer`. Measured by losing the context a second time and reading
     * which custom layers MapLibre names, both are present either way. What the
     * stale flag actually buys is an uncaught exception in the renderer on
     * every GPU recovery, and the tail of MapLibre's restore not running. Worth
     * fixing; not worth describing as lost data.
     *
     * Setting it false is the whole fix. `syncConnectionsLayer` already knows
     * what to do with a style that is not ready - it reschedules - and
     * `style.load` sets this back to true when the reload lands.
     */
    map.on("webglcontextlost", () => {
      styleReadyRef.current = false;
      // The pin layer went with the style: `style.destroy()` ran its
      // `onRemove`, and `style.load` builds a new one. Dropped here for exactly
      // the reason the unmount path drops it - a pin sync that found this ref
      // populated would write into a disposed renderer.
      //
      // The ARC layer is deliberately kept. It survives a style swap the same
      // way, holding its geometry while `onAdd` rebuilds the GL buffer, which
      // is what the theme-change path already relies on; re-adding it is enough.
      pinLayerRef.current = null;
      hoveredPinRef.current = null;
      // A gesture in flight when the context went never delivers its `moveend`,
      // and this flag latching true makes every later sync a no-op.
      isCameraMovingRef.current = false;
    });

    popupRef.current = new maplibregl.Popup({
      closeButton: false,
      closeOnClick: false,
      offset: 14,
      className: "inwire-geo-popup",
    });

    mapRef.current = map;
    // A handle for measuring, dev builds only. Every performance change to this
    // map is judged by the same numbers - render cost, arc buffer rebuilds,
    // marker counts - and those need the live instance, which nothing else
    // exposes. Compiled out of production: `import.meta.env.DEV` is a build-time
    // constant, so the branch and the global vanish together.
    if (import.meta.env.DEV) (window as unknown as { __inwireMap?: maplibregl.Map }).__inwireMap = map;
    // Bounds and pitch for whichever projection the constructor just opened in.
    applyProjectionMode(map, styleReadyRef.current);
    // A fresh instance. The marker effects key on this rather than on
    // `mapRef`, which cannot wake them.
    setMapEpoch((n) => n + 1);

    return () => {
      // Read the camera off the live map rather than tracking it on every
      // move: this runs once, and a `moveend` listener would run continuously
      // to answer a question nobody asks until now.
      const center = map.getCenter();
      geoSession().camera = { center: [center.lng, center.lat], zoom: map.getZoom() };
      map.remove();
      mapRef.current = null;
      if (import.meta.env.DEV) delete (window as unknown as { __inwireMap?: maplibregl.Map }).__inwireMap;

      // Everything below belongs to the MAP, not to this component, and
      // `map.remove()` has just invalidated all of it. Leaving the refs
      // populated is what made a rebuilt map come up bare: the pin sync found
      // its keys already present and added nothing.
      //
      // `map.remove()` has already called the layer's own `onRemove`, which
      // disposes the renderer and the cloned meshes; dropping the reference is
      // what stops the pin effects writing into a dead GL context afterwards.
      pinLayerRef.current = null;
      pinMetaRef.current.clear();
      hoveredPinRef.current = null;
      // A gesture interrupted by this teardown never delivered its `moveend`.
      isCameraMovingRef.current = false;
    };
    // Depends on the setting, not because the map reads it, but because the
    // CONTAINER only exists when it is on. With an empty dependency list this
    // effect ran once against the opt-in card, found no element to attach to,
    // and bailed - so turning location lookup on stored the preference, showed
    // the map's chrome, and never actually built a map.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nameResolution.geoIp]);

  /**
   * Repaints the basemap when the skin changes - or, under the muted skin, when
   * the theme does.
   *
   * **No `setStyle`, and that is the whole design.** Switching skins is a
   * repaint of the style that is already loaded, exactly like the first paint
   * in `style.load`. Reloading a style to change its colours is what this
   * component used to do for theme changes and it is documented below as the
   * single most destructive thing it did; a skin switch is the same question
   * and gets the same answer. Nothing is torn down, so the arcs, the markers,
   * the projection and the camera all survive the switch untouched.
   *
   * What makes an in-place repaint sufficient is that the two passes write the
   * same set of paint properties - see mapTheme.ts, where that symmetry is a
   * stated requirement rather than a coincidence. The land wall is reapplied
   * with it because its two tones are part of the skin, and `applyLandLift` is
   * idempotent, so this sets colours on layers that already exist rather than
   * adding a second pair.
   *
   * `applyDeclutter` deliberately does not run here: what it hides and thins is
   * style structure, which no skin changes, and re-running it would AND a
   * filter clause onto a filter that already carries it.
   */
  useEffect(() => {
    const map = mapRef.current;
    // Same `styleReadyRef` distinction as the sky effect below - see the note
    // there, and on applyProjectionMode. A map streaming tiles reports
    // `isStyleLoaded()` false, and gating on it would make the toggle work only
    // sometimes.
    if (!map || !styleReadyRef.current) return;
    applySkin(map, skin, basemapTokens);
    applyLandLift(map, wallStepsRef.current, wallTonesFor(skin, basemapTokens));
    // Spread rather than passed whole: `basemapTokens` is rebuilt every render,
    // so depending on the object would repaint the world on every packet.
  }, [skin, basemapTokens.background, basemapTokens.mutedForeground,
      basemapTokens.accent, basemapTokens.landHue, mapEpoch]);

  // A theme change touches exactly one thing on this map under the colourful
  // skin: the sky. (Under the muted skin it also drives the repaint above.)
  //
  // It used to call `setStyle` to move between Positron and Dark, and that call
  // was the single most destructive thing the component did: `setStyle`
  // replaces the whole style object, so every theme change tore down the sky,
  // the projection, the connection arcs and the coast relief, then rebuilt them
  // from the `style.load` handler while the map flashed through a half-styled
  // state. Every "the markers vanished when I changed theme" bug in this file's
  // history traces back to it. Then it became a full repaint of every layer in
  // the style, which was correct and still more work than the question needs.
  //
  // The basemap's colours are fixed now, so day-against-night is the entire
  // difference a theme makes here.
  useEffect(() => {
    const map = mapRef.current;
    // `styleReadyRef`, NOT `map.isStyleLoaded()`. They are different questions
    // and the difference is load-bearing: `isStyleLoaded()` is true only once
    // every SOURCE has finished loading too, and a map streaming tiles is false
    // much of the time. Gating on it made a theme change do nothing at all -
    // the chrome went dark and the map stayed light - and it did so
    // intermittently, depending on whether tiles happened to be in flight.
    //
    // The same mistake, for the same reason, is documented on
    // `applyProjectionMode`. What this actually needs is "does a style object
    // exist", which is what `style.load` sets this flag to say.
    if (!map || !styleReadyRef.current) return;
    map.setSky(skyFor(isDark));
  }, [isDark]);


  // MapLibre does not notice its container resizing - the canvas stays clipped
  // to whatever size it was built at - so something has to tell it.
  //
  // A ResizeObserver rather than an effect keyed on a size flag. There was such
  // a flag - it knew about the two sizes this component chose for itself and
  // nothing else - and the container changes for reasons it could not see: the
  // window resizing, the rail's view switching, an animation in flight. Watching
  // the element covers every one of those, including the ones nobody has thought
  // of yet, and it answers correctly at every intermediate size rather than on
  // one frame at the end.
  //
  // Resized AND repainted in the same frame, which is the whole trick.
  //
  // `map.resize()` reallocates the WebGL drawing buffer, and reallocating
  // CLEARS it. On its own, resize only *schedules* a repaint for the following
  // frame, so every resize leaves one frame with an empty canvas. One resize is
  // one blank frame and nobody notices; the dashboard's drag handle resizes on
  // every pointer move, so every frame was blank and the map strobed white for
  // the length of the gesture.
  //
  // Debouncing was tried first and is the wrong shape: it stops the strobing by
  // not resizing during the drag at all, which leaves the canvas stretched and
  // then snapping - no longer flickering, but not tracking the drag either.
  // `redraw()` is a synchronous repaint, so the buffer is refilled before the
  // frame is presented and the map follows the handle smoothly at full
  // resolution.
  //
  // Coalesced to one pass per frame, because a burst of observer callbacks
  // within one frame would otherwise pay for the reallocation several times
  // over.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    let frame = 0;
    const observer = new ResizeObserver(() => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        const map = mapRef.current;
        if (!map) return;
        map.resize();
        // Same frame, not the next one. This is what keeps the canvas from
        // ever being presented empty.
        map.redraw();
      });
    });
    observer.observe(el);
    return () => {
      if (frame) cancelAnimationFrame(frame);
      observer.disconnect();
    };
  }, []);

  /**
   * Keeps the pin layer's set of pins in step with the resolved locations.
   *
   * One pin per PLACE, not per host: ten servers in one datacentre are one
   * point on the map, and the locations list is where the full roster lives.
   * The place this machine's own network sits on is claimed by the home pin, so
   * a host there gets none of its own - two pins on one coordinate is not two
   * pieces of information.
   *
   * Keyed on `mapEpoch` like the layers themselves: a rebuilt map has a new
   * PinLayer with nothing in it.
   */
  useEffect(() => {
    const layer = pinLayerRef.current;
    if (!layer) return;

    const homeKey = ispLocation && !isNaN(ispLocation.latitude) && !isNaN(ispLocation.longitude)
      ? placeKeyFor(ispLocation.latitude, ispLocation.longitude)
      : null;

    const pins: Pin[] = [];
    const seen = new Set<string>();
    if (ispLocation && homeKey) {
      pins.push({ id: homeKey, lngLat: [ispLocation.longitude, ispLocation.latitude], kind: 'home' });
      seen.add(homeKey);
      pinMetaRef.current.set(homeKey, { ip: ispLocation.ip, loc: ispLocation, kicker: 'Your network' });
    }
    locations.forEach((loc, ip) => {
      const key = placeKeyFor(loc.latitude, loc.longitude);
      if (seen.has(key)) return;
      seen.add(key);
      pins.push({ id: key, lngLat: [loc.longitude, loc.latitude], kind: 'host' });
      pinMetaRef.current.set(key, { ip, loc });
    });

    for (const key of pinMetaRef.current.keys()) {
      if (!seen.has(key)) pinMetaRef.current.delete(key);
    }
    layer.setPins(pins);
  }, [locations, ispLocation, mapEpoch, pinEpoch]);

  /**
   * Hover popups, which the pins can no longer raise for themselves.
   *
   * A DOM marker got `mouseenter` for free; a mesh in a WebGL layer gets
   * nothing, so the pointer is tested against the pin positions the layer
   * recorded on its last frame - see PinLayer.hitTest. Screen-space distance
   * rather than a raycast, because the camera here has a projection matrix
   * handed to it by MapLibre and no view transform of its own, which is exactly
   * what a raycaster needs and does not have.
   *
   * The hovered id is remembered so a pointer moving ACROSS one pin does not
   * rebuild its popup on every mousemove.
   */
  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;

    const onMove = (e: maplibregl.MapMouseEvent) => {
      const layer = pinLayerRef.current;
      const popup = popupRef.current;
      if (!layer || !popup) return;
      // There used to be an `isExpandedRef` guard here - popups only at full
      // size, because at card size the popup was wider than the map it covered.
      // There is no card size.

      const hit = layer.hitTest(e.point.x, e.point.y);
      if (!hit) {
        if (hoveredPinRef.current !== null) {
          hoveredPinRef.current = null;
          popup.remove();
        }
        map.getCanvas().style.cursor = '';
        return;
      }
      map.getCanvas().style.cursor = 'pointer';
      if (hoveredPinRef.current === hit.id) return;
      hoveredPinRef.current = hit.id;

      const meta = pinMetaRef.current.get(hit.id);
      if (!meta) return;
      popup
        .setLngLat(hit.lngLat)
        .setHTML(buildPopupHtml(meta.ip, meta.loc, hostnamesRef.current.get(meta.ip) ?? null, meta.kicker))
        .addTo(map);
    };

    const onLeave = () => {
      hoveredPinRef.current = null;
      popupRef.current?.remove();
    };

    map.on('mousemove', onMove);
    map.on('mouseout', onLeave);
    return () => {
      map.off('mousemove', onMove);
      map.off('mouseout', onLeave);
    };
  }, [mapEpoch]);

  /**
   * The two pin colours.
   *
   * Host pins take the app accent, the same colour the arcs fall back to. This
   * machine's own network takes the palette's green instead, and that is the
   * whole of what tells them apart now that both are the same object - the
   * house-against-server glyph the DOM markers used has no equivalent in one
   * shared model. Green because it is the one hue no theme spends its accent
   * on, so the home pin stays the odd one out on all four.
   */
  useEffect(() => {
    // `isDark` covers both dark themes, and does not need to tell them apart -
    // the clamp it turns on is derived from each theme's own accent.
    pinLayerRef.current?.setColors(accent, themePalette(themeKey).hues.green, isDark);
  }, [accent, themeKey, isDark, mapEpoch, pinEpoch]);


  /**
   * With location lookup off, this renders an explanation instead of a map.
   *
   * Not an empty map: a blank card with a title reads as something that failed,
   * and the natural response to a broken-looking feature is to stop using it
   * rather than to go and find the setting.
   *
   * The map is not CONSTRUCTED either, which matters beyond tidiness. MapLibre
   * fetches its style, glyphs and vector tiles from a third party as soon as it
   * exists, and the tiles disclose which part of the world is being looked at -
   * a coarse version of the thing the setting is there to control. Refusing to
   * build it closes that channel too, without needing a switch of its own.
   */
  /**
   * The protocols actually on screen, most-carried first.
   *
   * There has never been a legend anywhere in this app. That was survivable
   * while every arc was one colour and stopped being survivable the moment they
   * were coloured by protocol: the map became the only surface that encodes a
   * variable without saying what the encoding is.
   *
   * Built from the routes rather than from the protocol table, so it lists what
   * is drawn rather than the twelve protocols that could be.
   */
  const legend = React.useMemo(() => {
    if (!arcProtocolColors) return [];
    const totals = new Map<string, number>();
    for (const route of routes) {
      totals.set(route.dominantProtocol, (totals.get(route.dominantProtocol) ?? 0) + route.total);
    }
    return Array.from(totals, ([protocol, total]) => ({ protocol, total })).sort(
      (a, b) => b.total - a.total,
    );
  }, [routes, arcProtocolColors]);

  // `aggregateRoutes` already returns these sorted by total, descending
  // (`geoRoutes.ts`), so the copy and the re-sort this used to do were both
  // dead work on every dashboard tick.
  const topRoutes = React.useMemo(() => routes.slice(0, 8), [routes]);

  /**
   * **Every hook in this component is above this line, and must stay there.**
   *
   * The early return below is the off state, and it used to sit above these two
   * `useMemo` calls. React counts hooks per render: 45 with location lookup
   * off, 47 with it on. Turning the setting on therefore rendered more hooks
   * than the previous render and threw React error #310 - which is not a
   * message anybody sees, because the error unmounts the tree. The whole
   * window went black, on the one click the off state exists to invite.
   *
   * Nothing in the suite could catch it: `smoke.ts` never turns the setting on,
   * and `gpu-restore-drive.ts` skips outright when the map is absent - which it
   * is until geo-IP has been consented to. The bug lived in the gap between a
   * test that does not enable the feature and a test that requires it enabled.
   */
  if (!nameResolution.geoIp) {
    return (
      <div className="w-full h-full flex flex-col bg-card text-card-foreground">
        <div className="flex-1 min-h-0 flex flex-col items-center justify-center gap-3 p-6 text-center">
          <MapPinOff className="w-8 h-8 text-muted-foreground/50" />
          <p className="text-[11px] text-muted-foreground leading-snug max-w-xs">
            Location lookup is off. Inwire can show where the public addresses in your capture are
            by sending them to <span className="font-mono">get.geojs.io</span>.
          </p>
          <button
            type="button"
            onClick={() => nameResolutionStore.set({ ...nameResolutionStore.get(), geoIp: true })}
            className="rounded-full px-3 py-1.5 text-[11px] font-semibold bg-primary text-primary-foreground hover:bg-primary/90 transition-colors cursor-pointer"
          >
            Turn on location lookup
          </button>
          <p className="text-[10px] text-muted-foreground/70">
            Change this any time in Settings, under Interface.
          </p>
        </div>
      </div>
    );
  }



  /**
   * Picking a place, and the camera move that goes with it.
   *
   * Called from the side panel's place list. It was shared with a popover on
   * the pane-sized copy of this map, which is what "the same list at two sizes"
   * bought; there is one size, and the list simply stays open.
   */
  const flyToPlace = (place: { latitude: number; longitude: number }) => {
    // Zoom 5 is city scale - close enough that the place is the subject rather
    // than a dot in a continent, far enough that its neighbours are in frame.
    const target = {
      center: [place.longitude, place.latitude] as [number, number],
      zoom: Math.max(mapRef.current?.getZoom() ?? 1, 5),
    };
    // A camera flight across a full-viewport map is the most vestibular-hostile
    // thing in this app, and it is JavaScript rather than CSS, so the blanket
    // reduced-motion rule cannot reach it. Jump instead: same destination, no
    // journey.
    if (prefersReducedMotion()) mapRef.current?.jumpTo(target);
    else mapRef.current?.flyTo({ ...target, speed: 1.2 });
  };

  /** Where this machine is, as one line. Null when the lookup gave nothing. */
  const ispLabel = ispLocation
    ? `${ispLocation.city !== 'Unknown' ? ispLocation.city + ', ' : ''}${ispLocation.country}`
    : null;

  const map = (
    <div className="flex-1 min-h-0 relative overflow-hidden">
      {/* MapLibre forces position:relative on any element bearing its own
          .maplibregl-map class (added imperatively once the map mounts), which
          silently wins over an "absolute inset-0" utility at equal specificity
          and collapses this div to its (near-zero) content height. w-full/h-full
          sizing works regardless of which position value ends up applied, since
          the parent above already has a resolved height. */}
      {/* The backdrop is on the container, not in the style. MapLibre's sky in
          globe projection is only the atmosphere on the limb; everything past
          it is transparent canvas, and in flat projection there is no sky at
          all. See spaceColorFor. */}
      <div ref={containerRef} className="w-full h-full" style={{ background: spaceColorFor(isDark) }} />

      {/* One stack, one corner, one visual language. The map's furniture used to
          be scattered across three corners of a 1500px panel - close top-right,
          locations bottom-left, zoom and projection bottom-right - with a void
          between them. The place list has moved into the side panel, which
          leaves these the only things floating over the map.

          Both used to be conditional, and the condition was size: the 256px
          card showed the whole world, so there was nothing on it to look closer
          at and three stacked buttons would have been a third of its height.
          One surface, one answer - there is room. */}

      {/* Top-right, where MapLibre's (i) used to be - the corner people already
          look in to find out what a map is. The licence credit goes with it;
          see the note where the AttributionControl used to be added. */}
      <GeoMapHelp />

      {/* The projection switcher was `leading` here, on the argument that
          "which projection the map is in is worth deciding without expanding
          first". There is one projection now. */}
      <ZoomControls
        onZoomIn={() => mapRef.current?.zoomIn()}
        onZoomOut={() => mapRef.current?.zoomOut()}
      />

      {/* **A floating locations counter was here**, and then a pane title bar
          carried the count, and now neither does: both belonged to the copy of
          this map that sat in the Packets view's bottom row. The side panel's
          heading is where the number lives. */}
    </div>
  );

  /**
   * Expanded: a side panel, and the globe in what is left.
   *
   * The globe is bounded by the panel's HEIGHT, because it is a circle - so on a
   * 1490x860 window it filled a 630px disc and left more than half the panel
   * empty. Meanwhile the three things worth reading at that size had nowhere to
   * be: the place list was folded into a pill, the routes were not listed at
   * all, and the arc colours had no legend. They go in the space the globe was
   * never going to use.
   */
  return (
    <div className="w-full h-full flex bg-card text-card-foreground">
      <aside
        aria-label="Map details"
        className="flex w-[300px] shrink-0 flex-col border-r border-border overflow-y-auto custom-scrollbar"
      >
        <div className="px-4 py-3 border-b border-border">
          <div className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
            This machine
          </div>
          <div className="flex items-center gap-1.5 text-primary mt-1 min-w-0">
            <MapPin className="w-4 h-4 shrink-0 fill-current" />
            <span className="text-xs truncate">{ispLabel ?? 'Location unknown'}</span>
          </div>
        </div>

        <section className="px-4 py-3 border-b border-border">
          <div className="flex items-baseline justify-between gap-2">
            <h4 className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
              Locations
            </h4>
            <span className="text-[10px] font-mono text-muted-foreground">
              {geoStats.places.length}
              {geoStats.unresolved > 0 ? ` (+${geoStats.unresolved} unresolved)` : ''}
            </span>
          </div>
          {geoStats.places.length === 0 ? (
            <p className="text-[11px] text-muted-foreground/80 mt-2 leading-snug">
              Nothing located yet.
            </p>
          ) : (
            <ul className="mt-2 space-y-0.5">
              {geoStats.places.map((place) => (
                <li key={place.key}>
                  <button
                    type="button"
                    onClick={() => flyToPlace(place)}
                    // A country-level row is the provider's centroid for a whole
                    // country rather than this host's position, so it is listed
                    // and never flown to as though it were a fix.
                    disabled={place.precision === 'country'}
                    title={
                      place.precision === 'country'
                        ? `${place.label} - country-level only, not plotted`
                        : `Centre the map on ${place.label}`
                    }
                    className="w-full flex items-center gap-1.5 px-1 py-1 rounded text-[11px] text-left transition-colors hover:bg-accent disabled:hover:bg-transparent disabled:cursor-default cursor-pointer"
                  >
                    {place.precision === 'country' ? (
                      <MapPinOff className="w-3.5 h-3.5 shrink-0 text-muted-foreground/60" />
                    ) : (
                      <MapPin className="w-3.5 h-3.5 shrink-0 text-primary fill-current" />
                    )}
                    <span className="truncate text-foreground/90">{place.label}</span>
                    <span className="ml-auto shrink-0 font-mono text-muted-foreground">
                      {place.hosts}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Gated on the setting, not merely on having routes. With arc colouring
            off every line is the accent, and a legend mapping protocols to
            colours would be describing an encoding that is not there. */}
        {legend.length > 0 && (
          <section className="px-4 py-3 border-b border-border">
            <h4 className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
              Protocols
            </h4>
            <ul className="mt-2 space-y-0.5">
              {legend.map(({ protocol, total }) => (
                <li key={protocol} className="flex items-center gap-1.5 px-1 py-0.5 text-[11px]">
                  <span
                    aria-hidden
                    className="w-2.5 h-1 rounded-full shrink-0"
                    style={{ background: protocolColor(protocol, themeKey) }}
                  />
                  <span className="truncate text-foreground/90">{protocol}</span>
                  <span className="ml-auto shrink-0 font-mono text-muted-foreground">{total}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        {topRoutes.length > 0 && (
          <section className="px-4 py-3">
            <h4 className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
              Busiest routes
            </h4>
            <ul className="mt-2 space-y-0.5">
              {topRoutes.map((route) => (
                <li key={route.key} className="flex items-center gap-1.5 px-1 py-0.5 text-[11px]">
                  <span
                    aria-hidden
                    className="w-2.5 h-1 rounded-full shrink-0"
                    style={{
                      background: arcProtocolColors
                        ? protocolColor(route.dominantProtocol, themeKey)
                        : accent,
                    }}
                  />
                  <span className="truncate font-mono text-foreground/90">
                    {route.dominantProtocol}
                  </span>
                  <span className="ml-auto shrink-0 font-mono text-muted-foreground">
                    {route.total}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        )}
      </aside>

      <div className="flex-1 min-w-0 flex flex-col">{map}</div>
    </div>
  );
};
