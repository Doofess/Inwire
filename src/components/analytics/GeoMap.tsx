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
import { TbWorld, TbMapPinFilled, TbMapPinOff, TbMaximize } from "react-icons/tb";
import { useThemeToken } from '../../lib/themeColor';
import { themePalette } from '../../services/themePalettes';
import { protocolColor } from '../../services/protocolColors';
import { greatCirclePath, splitAtAntimeridian } from '../../lib/greatCircle';
import { aggregateRoutes } from './geoRoutes';
import { applyThemeToBasemap } from './mapTheme';
import { GeoLocationCounter, type GeoPlace } from './GeoLocationCounter';
import { geoSession } from './geoSession';
import { prefersReducedMotion } from '../../lib/motion';
import { nameResolutionStore } from '../../services/interfacePrefs';
import { usePreferenceStore } from '../../services/preferenceStore';
import type { WidgetVariant } from './dashboardWidgets';
import { ZoomControls } from './ZoomControls';

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
// component. Guarded by status check because Vite HMR re-executes module
// top-level code on every edit-triggered reload in dev, and MapLibre throws
// if this is ever called a second time in the same page session.
if (maplibregl.getRTLTextPluginStatus() === "unavailable") {
  maplibregl.setRTLTextPlugin(
    "https://unpkg.com/@mapbox/mapbox-gl-rtl-text@0.4.0/dist/mapbox-gl-rtl-text.js",
    true
  );
}

// OpenFreeMap: free, no API key, no request limits (donation-supported).
// Positron/Dark are minimal, label-forward styles that keep focus on our
// own markers rather than competing with a busy basemap.
const LIGHT_STYLE = "https://tiles.openfreemap.org/styles/positron";
const DARK_STYLE = "https://tiles.openfreemap.org/styles/dark";

const CONNECTIONS_SOURCE_ID = "netview-connections";
const CONNECTIONS_LAYER_ID = "netview-connections-line";
// Drawn under the line in the same colour, wider and blurred. Two static
// layers rather than an animation loop: the glow is what makes a thin line
// read as lit rather than drawn, and it costs nothing per frame.
const CONNECTIONS_GLOW_LAYER_ID = "netview-connections-glow";
const CONNECTIONS_SYNC_THROTTLE_MS = 600;

// How many points to sample along each great circle. Enough that the curve is
// smooth at continental scale without turning sixty routes into thousands of
// coordinates the source has to re-serialise on every sync.
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

interface GeoMapProps {
  packets: Packet[];
  isDark: boolean;
  /** See TrafficTimelineChart: forces a redraw when the theme changes, which
   *  isDark cannot signal between two dark themes. */
  themeKey?: string;
  /**
   * How much room this has been given.
   *
   * `card` is the dashboard column: a 256px panel with an expand button.
   *
   * `full` means a full-screen frame - which is now always a `WidgetOverlay`,
   * whether this component opened it from its own expand button or the icon
   * rail opened it from outside. Both render exactly this branch, which is what
   * makes the two doors lead to the same window.
   */
  variant?: WidgetVariant;
  /**
   * Open this widget in the dashboard's shared overlay.
   *
   * The card draws the button; the DASHBOARD owns the window it opens. That
   * split is the point: this component used to own an expanded panel of its
   * own, so the map you got from the card and the map you got from the icon
   * rail were two different windows built from two sets of class names. There
   * is one now, and neither door can drift from it.
   *
   * Absent in `full` - the window is already open - and absent wherever the
   * parent has nowhere to put it.
   */
  onExpand?: () => void;
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
 * The two glyphs a marker can be, as Tabler's own `home` and `server` paths.
 *
 * Inlined rather than rendered from `react-icons` because MapLibre takes a DOM
 * element, not a React node - rendering a component per marker would mean a
 * root per marker, or pulling `react-dom/server` into the bundle to stringify
 * two icons. The markup is copied verbatim from the installed package's output,
 * so these are the same glyphs the rest of the app draws, and `currentColor`
 * means the colour is set once on the element and inherited.
 */
const MARKER_ICONS = {
  home:
    '<path d="M5 12l-2 0l9 -9l9 9l-2 0"></path>'
    + '<path d="M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-7"></path>'
    + '<path d="M9 21v-6a2 2 0 0 1 2 -2h2a2 2 0 0 1 2 2v6"></path>',
  host:
    '<path d="M3 7a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3"></path>'
    + '<path d="M3 15a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3l0 -2"></path>'
    + '<path d="M7 8l0 .01"></path>'
    + '<path d="M7 16l0 .01"></path>',
} as const;

type MarkerKind = keyof typeof MARKER_ICONS;

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

/**
 * The light a marker gives off.
 *
 * One soft shadow at partial alpha, and deliberately only one. The first
 * version stacked a wide 4px glow with a tight 1px one, and the tight one is
 * what made the icons unreadable: at 18px a server glyph's bars are about two
 * pixels apart, so a shadow with a one-pixel radius fills the gaps between them
 * and the whole thing collapses into a bright blob. A single wide shadow lights
 * the shape from outside without touching the space inside it.
 *
 * Alpha rather than a smaller radius, because the glow still has to be visible
 * against a pale basemap - the fix is for it to be dimmer, not tighter.
 */
function markerGlow(color: string): string {
  return `drop-shadow(0 0 5px ${color}80)`;
}

/**
 * A marker: a glyph over a pulsing halo.
 *
 * `home` is not a cosmetic variant. It marks this machine's own network, which
 * is the one point on the map that is not a located host: LAN addresses have no
 * geography, so their traffic is anchored where it actually enters the internet.
 * A house says that in one glance; the hollow ring it replaces said only "this
 * dot is not like the others" and left you to open the popup to find out why.
 * Everything else is a server, which is what those points are.
 *
 * The halo behind the glyph is the same `animate-ping` circle the plain dots
 * used, so the markers still pulse and still read as live rather than as pins
 * dropped on a static map. Both markers take the app's accent now - what tells
 * them apart is the shape, which does not depend on the theme having two
 * distinguishable colours to spare.
 */
function createMarkerElement(color: string, size: number, kind: MarkerKind = 'host') {
  const el = document.createElement("div");
  el.style.width = `${size}px`;
  el.style.height = `${size}px`;
  // No inline `position` here: this element becomes MapLibre's own
  // `.maplibregl-marker` node (MapLibre uses the element we pass in
  // directly rather than wrapping it), which MapLibre's stylesheet already
  // positions with `position: absolute` + a `transform: translate(...)` for
  // geographic placement. An inline `position: relative` here used to beat
  // that stylesheet rule (inline styles always win), which put the marker
  // back into normal document flow - so every marker also stacked vertically
  // beneath the previous one in DOM order, on top of its correct transform
  // offset. That's what produced the "markers scattered in a diagonal/ocean
  // line" bug: `position: absolute` from MapLibre's own CSS is just as valid
  // a containing block for the `inset: 0` ping/dot children below, so no
  // inline override is needed at all.
  el.style.cursor = "pointer";

  // Both children are tagged so the accent can be re-applied later without
  // rebuilding the marker - see the recolour effect below.
  //
  // The halo sits INSIDE the glyph's box rather than filling it: a ping circle
  // the full size of a 20px icon reads as a disc with something drawn on it,
  // where the glyph should be the marker and the halo only its light. Kept
  // faint and small for the same reason the drop-shadow is - anything brighter
  // sits behind the glyph and washes out the strokes it is meant to light.
  const ping = document.createElement("span");
  ping.style.position = "absolute";
  ping.style.inset = "30%";
  ping.style.borderRadius = "9999px";
  ping.style.background = color;
  ping.style.opacity = "0.25";
  ping.className = "animate-ping";
  ping.dataset.accent = "fill";

  const glyph = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  glyph.setAttribute("viewBox", "0 0 24 24");
  glyph.setAttribute("fill", "none");
  glyph.setAttribute("stroke", "currentColor");
  // Heavier than the 2 the icon set ships, because these are drawn at 18-20px
  // over a photographic basemap rather than on a flat panel.
  glyph.setAttribute("stroke-width", "2.5");
  glyph.setAttribute("stroke-linecap", "round");
  glyph.setAttribute("stroke-linejoin", "round");
  glyph.innerHTML = MARKER_ICONS[kind];
  glyph.style.position = "absolute";
  glyph.style.inset = "0";
  glyph.style.width = "100%";
  glyph.style.height = "100%";
  glyph.style.color = color;
  // The glow the dots had, moved onto the glyph itself. A box-shadow would
  // trace the element's square box; drop-shadow follows the drawn strokes, so
  // the light comes off the shape rather than off a rectangle around it.
  glyph.style.filter = markerGlow(color);
  glyph.dataset.accent = "glow";

  el.appendChild(ping);
  el.appendChild(glyph);
  return el;
}

export const GeoMap: React.FC<GeoMapProps> = ({
  packets,
  isDark,
  themeKey,
  variant = 'card',
  onExpand,
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
  const markersRef = useRef<Map<string, maplibregl.Marker>>(new Map());
  const ispMarkerRef = useRef<maplibregl.Marker | null>(null);
  const popupRef = useRef<maplibregl.Popup | null>(null);
  const isExpandedRef = useRef(false);
  const isFirstStyleRun = useRef(true);
  const connectionsRef = useRef<GeoJSON.FeatureCollection>({ type: "FeatureCollection", features: [] });
  const connectionsSyncTimeoutRef = useRef<number | null>(null);
  const isCameraMovingRef = useRef(false);
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

  // See useThemeToken: read inline during marker creation this could resolve to
  // nothing and bake the fallback accent into a marker that is then never
  // recreated, since markers are only built once per newly-seen location.
  const accent = useThemeToken('--primary', '#f97316');
  // The basemap is repainted from the app's own tokens rather than being one of
  // two stock styles, so the themes do not all render an identical grey-blue
  // world. Read through useThemeToken for the same reason the accent
  // is: MapLibre wants a concrete colour, not a CSS variable.
  const mapBackground = useThemeToken('--background', '#0c0a09');
  const mapMutedForeground = useThemeToken('--muted-foreground', '#94a3b8');

  // Sea and land are two steps of the theme's own neutral ramp, and the
  // coastline is the accent - see mapTheme.ts. Water used to be tinted from
  // the palette's blue, which gave every theme a blue sea whatever else it was
  // doing; only `landHue` still comes from the palette, for parks.
  const basemapTokens = React.useMemo(() => {
    const palette = themePalette(themeKey);
    return {
      background: mapBackground,
      mutedForeground: mapMutedForeground,
      accent,
      landHue: palette.hues.green,
    };
  }, [mapBackground, mapMutedForeground, accent, themeKey]);

  // Read by the `style.load` handler, which is registered once and must not be
  // re-registered on every theme change.
  const basemapTokensRef = useRef(basemapTokens);
  basemapTokensRef.current = basemapTokens;

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
  // because this component is unmounted whenever the dashboard is minimized or
  // the widget is switched off. See geoSession for what that used to cost.
  const [nameResolution] = usePreferenceStore(nameResolutionStore);

  const sessionRef = useRef(geoSession());
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
  const [ispLocation, setIspLocation] = useState<GeoLocation | null>(null);
  useEffect(() => {
    // Tracks "has room for a popup", not "is expanded" - a map filling the
    // dashboard overlay has just as much room as one this component expanded
    // itself, and the marker handlers that read this cannot tell the
    // difference from where they sit.
    isExpandedRef.current = variant === 'full';
  }, [variant]);

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

  // This machine's own public location, from the service rather than a fetch
  // here. The request is memoized there, so this component mounting again -
  // which it does every time the dashboard is un-minimized - reuses the answer
  // instead of asking a third party where the user is a second time.
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
            setLocations(new Map(sessionRef.current.locations));
          });
          resolveHostname(ip).then((hostname) => {
            sessionRef.current.hostnames.set(ip, hostname);
            setHostnames(new Map(sessionRef.current.hostnames));
          });
        }
      });
    });
  }, [packets]);

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
    return aggregateRoutes(packets, locate);
  }, [packets, locations, ispLocation]);

  // Sync the connections GeoJSON source/layer with the map's currently loaded
  // style. Re-invoked on every style load (including after theme switches,
  // since setStyle() tears down all custom sources/layers) as well as
  // whenever the connections data itself changes.
  const syncConnectionsLayer = () => {
    const map = mapRef.current;
    // No map at all: nothing to retry into, and a retry loop would outlive the
    // component. Every other bail below reschedules.
    if (!map) return;

    // The style is what the connection layers are added to, and after a
    // `setStyle` - which every theme change performs - it is briefly not there.
    // This used to return and drop the update on the floor: the next attempt
    // only came when `routes` changed again, so on a capture that had already
    // stopped the lines simply never came back.
    if (!map.isStyleLoaded()) {
      scheduleConnectionsSync();
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

    const existingSource = map.getSource(CONNECTIONS_SOURCE_ID) as maplibregl.GeoJSONSource | undefined;
    if (existingSource) {
      existingSource.setData(connectionsRef.current);
      return;
    }

    map.addSource(CONNECTIONS_SOURCE_ID, { type: "geojson", data: connectionsRef.current });
    // Glow first, so it sits beneath. Same colour, wider and blurred - which is
    // what makes a 1.5px line read as lit rather than merely drawn, without a
    // per-frame animation.
    map.addLayer({
      id: CONNECTIONS_GLOW_LAYER_ID,
      type: "line",
      source: CONNECTIONS_SOURCE_ID,
      paint: {
        "line-color": ["get", "color"],
        "line-width": 5,
        "line-opacity": 0.18,
        "line-blur": 4,
      },
    });
    map.addLayer({
      id: CONNECTIONS_LAYER_ID,
      type: "line",
      source: CONNECTIONS_SOURCE_ID,
      paint: {
        // Data-driven: each feature carries the colour of the protocol
        // carrying most of its traffic. The dasharray is gone with the flat
        // colour it compensated for - a solid line reads as a route, and the
        // colour is what carries the information now.
        "line-color": ["get", "color"],
        // Busy routes draw heavier, so the map shows where the traffic is and
        // not merely who was contacted.
        "line-width": ["interpolate", ["linear"], ["get", "weight"], 0, 0.8, 1, 2.6],
        "line-opacity": 0.75,
      },
    });
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
    // Weight is normalised against the busiest route rather than an absolute
    // packet count: what the line width should say is "this one is busier than
    // that one", and an absolute scale would render every line hairline-thin
    // on a quiet capture and uniformly fat on a loud one.
    const busiest = Math.max(1, ...routes.map((r) => r.total));

    connectionsRef.current = {
      type: "FeatureCollection",
      features: routes.flatMap((route) => {
        const color = protocolColor(route.dominantProtocol, themeKey);
        const weight = route.total / busiest;
        // One feature per segment: a route crossing the antimeridian is two
        // pieces, because with world copies disabled a single feature would be
        // drawn back across the whole map instead of over the Pacific.
        return splitAtAntimeridian(
          greatCirclePath(route.from, route.to, ARC_STEPS, ARC_CURVATURE),
        ).map(
          (coordinates, i) => ({
            type: "Feature" as const,
            properties: {
              id: `${route.key}#${i}`,
              color,
              weight,
              protocol: route.dominantProtocol,
            },
            geometry: { type: "LineString" as const, coordinates },
          }),
        );
      }),
    };

    scheduleConnectionsSync();
  }, [routes, themeKey]);

  // Create the map once on mount.
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;

    const map = new maplibregl.Map({
      container: containerRef.current,
      style: isDark ? DARK_STYLE : LIGHT_STYLE,
      // Where the map was last pointing, if it has been open before this
      // session. Someone who flew to a city and then collapsed the dashboard
      // should not come back to the world view.
      center: geoSession().camera?.center ?? [15, 20],
      zoom: geoSession().camera?.zoom ?? 1,
      minZoom: 0.6,
      maxZoom: 14,
      // One world, not an endless ribbon of them. MapLibre repeats the map
      // horizontally by default, so panning east just kept handing back
      // another copy of the same continents.
      renderWorldCopies: false,
      // With the copies gone the lone world can be dragged off into empty
      // space, so pen the camera inside the map's own extent. Two constants
      // here are load-bearing and neither is a typo:
      //   +/-85, not +/-90, because that is where Web Mercator ends - the
      //   poles sit at infinity in this projection.
      //   +/-179.9, not +/-180, because a longitude range spanning the full
      //   360 degrees crashes maplibre-gl 6.5.0 outright: it throws
      //   "Cannot read properties of null (reading '0')" out of
      //   Transform._calcMatrices during the very first resize, which takes
      //   the whole React tree down with it. Verified by bisection - the
      //   throw depends only on the longitude span reaching 360, not on the
      //   latitude range and not on renderWorldCopies. The 0.1 degree sliver
      //   this gives up is sub-pixel at every zoom this map allows.
      maxBounds: [
        [-179.9, -85],
        [179.9, 85],
      ],
      attributionControl: false,
      dragRotate: false,
      pitchWithRotate: false,
      touchPitch: false,
      // No cooperative gestures, in either size. They existed to stop the wheel
      // being swallowed by the compact card while the sidebar around it is
      // being scrolled, and the price was a "use ctrl + scroll to zoom" overlay
      // on every wheel event over the one panel whose whole purpose is being
      // zoomed into. The wheel now zooms the map directly; scrolling the
      // sidebar means putting the pointer beside the map rather than on it.
    });

    map.touchZoomRotate.disableRotation();
    // Both have to happen on every style load: setStyle replaces the entire
    // style object, discarding the custom layers AND every paint property this
    // has written.
    map.on("style.load", () => {
      applyThemeToBasemap(map, basemapTokensRef.current);
      syncConnectionsLayer();
    });
    map.on("movestart", () => {
      isCameraMovingRef.current = true;
    });
    map.on("moveend", () => {
      isCameraMovingRef.current = false;
      syncConnectionsLayer();
    });

    popupRef.current = new maplibregl.Popup({
      closeButton: false,
      closeOnClick: false,
      offset: 14,
      className: "netview-geo-popup",
    });

    mapRef.current = map;
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

      // Everything below belongs to the MAP, not to this component, and
      // `map.remove()` has just invalidated all of it. Leaving the refs
      // populated is what made a rebuilt map come up bare: the marker sync
      // found its keys already present and added nothing.
      for (const marker of markersRef.current.values()) marker.remove();
      markersRef.current.clear();
      ispMarkerRef.current?.remove();
      ispMarkerRef.current = null;
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

  // Swap the basemap style on theme change (skip the redundant call on mount).
  useEffect(() => {
    if (!mapRef.current) return;
    if (isFirstStyleRun.current) {
      isFirstStyleRun.current = false;
      return;
    }
    // Still worth picking the right stock style even though it is repainted
    // immediately: the two differ in label placement and halo strategy, not
    // only in colour, so starting from the one built for this ground gives
    // legible labels before a single paint property is touched.
    mapRef.current.setStyle(isDark ? DARK_STYLE : LIGHT_STYLE);
  }, [isDark, themeKey]);

  // Repaint without a style swap - which is the common case, since four of the
  // eight themes share a stock style and would otherwise all look identical.
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !map.isStyleLoaded()) return;
    applyThemeToBasemap(map, basemapTokens);
  }, [basemapTokens]);


  // MapLibre does not notice its container resizing - the canvas stays clipped
  // to whatever size it was built at - so something has to tell it.
  //
  // A ResizeObserver rather than an effect keyed on the expanded flag. The flag
  // only knows about the two sizes this component chooses for itself, and the
  // container now also changes when the dashboard overlay opens around it, when
  // the pane divider is dragged, and while any of those animate. Watching the
  // element covers every one of those, including the ones nobody has thought of
  // yet, and it replaces a single post-expand frame with a correct answer at
  // every intermediate size.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver(() => mapRef.current?.resize());
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  /**
   * Repaints every marker when the accent changes.
   *
   * One effect for both kinds now that both take the accent. It is needed
   * because markers are built once - per newly-seen location, or keyed on
   * `ispLocation` - so any marker created before a theme switch would otherwise
   * keep the colour it was born with forever.
   */
  useEffect(() => {
    const repaint = (marker: maplibregl.Marker | null) => {
      if (!marker) return;
      const el = marker.getElement();
      const fill = el.querySelector<HTMLElement>('[data-accent="fill"]');
      const glow = el.querySelector<SVGElement>('[data-accent="glow"]');
      if (fill) fill.style.background = accent;
      if (glow) {
        glow.style.color = accent;
        glow.style.filter = markerGlow(accent);
      }
    };
    for (const marker of markersRef.current.values()) repaint(marker);
    repaint(ispMarkerRef.current);
  }, [accent]);

  // Keep ping-source markers in sync with resolved locations.
  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;

    // The place this machine's own marker occupies. A host there gets no
    // marker of its own: the house is already standing on that coordinate, and
    // two icons on one pixel is not two pieces of information.
    const homeKey = ispLocation && !isNaN(ispLocation.latitude) && !isNaN(ispLocation.longitude)
      ? placeKeyFor(ispLocation.latitude, ispLocation.longitude)
      : null;

    // One entry per place. The first host to resolve there owns the marker and
    // its popup; the locations list is where the full roster of hosts lives.
    const wanted = new Map<string, { ip: string; loc: GeoLocation }>();
    locations.forEach((loc, ip) => {
      const key = placeKeyFor(loc.latitude, loc.longitude);
      if (key === homeKey || wanted.has(key)) return;
      wanted.set(key, { ip, loc });
    });

    for (const [key, marker] of markersRef.current) {
      if (!wanted.has(key)) {
        marker.remove();
        markersRef.current.delete(key);
      }
    }

    wanted.forEach(({ ip, loc }, key) => {
      if (markersRef.current.has(key)) return;

      // The app's accent, the same as this machine's own marker. The two are
      // told apart by their glyph - a server against a house - which works on
      // every theme, including the ones with no second distinguishable colour
      // to spare.
      const el = createMarkerElement(accent, 18, 'host');
      const marker = new maplibregl.Marker({ element: el }).setLngLat([loc.longitude, loc.latitude]).addTo(map);

      el.addEventListener("mouseenter", () => {
        if (!isExpandedRef.current || !popupRef.current) return;
        const hostname = hostnames.get(ip) ?? null;
        popupRef.current.setLngLat([loc.longitude, loc.latitude]).setHTML(buildPopupHtml(ip, loc, hostname)).addTo(map);
      });
      el.addEventListener("mouseleave", () => {
        popupRef.current?.remove();
      });

      markersRef.current.set(key, marker);
    });
    // `mapEpoch`, because these markers live on the map instance: a rebuilt
    // map needs them all added again, and nothing else in this list changes
    // when it is rebuilt.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [locations, accent, ispLocation, mapEpoch]);

  // ISP ("home") marker.
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !ispLocation || isNaN(ispLocation.latitude) || isNaN(ispLocation.longitude)) return;

    ispMarkerRef.current?.remove();

    const el = createMarkerElement(accent, 20, 'home');
    const marker = new maplibregl.Marker({ element: el })
      .setLngLat([ispLocation.longitude, ispLocation.latitude])
      .addTo(map);

    el.addEventListener("mouseenter", () => {
      if (!isExpandedRef.current || !popupRef.current) return;
      popupRef.current
        .setLngLat([ispLocation.longitude, ispLocation.latitude])
        .setHTML(buildPopupHtml(ispLocation.ip, ispLocation, null, "Your network"))
        .addTo(map);
    });
    el.addEventListener("mouseleave", () => {
      popupRef.current?.remove();
    });

    ispMarkerRef.current = marker;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ispLocation, accent, mapEpoch]);

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
  if (!nameResolution.geoIp) {
    return (
      <div className="w-full h-full flex flex-col bg-card text-card-foreground">
        <div className="px-3.5 py-1.5 border-b border-border flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-widest text-muted-foreground shrink-0">
          <TbWorld className="w-4 h-4" />
          <span>Live Geo-IP map</span>
        </div>
        <div className="flex-1 min-h-0 flex flex-col items-center justify-center gap-3 p-6 text-center">
          <TbMapPinOff className="w-8 h-8 text-muted-foreground/50" />
          <p className="text-[11px] text-muted-foreground leading-snug max-w-xs">
            Location lookup is off. NetView can show where the public addresses in your capture are
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

  const roomy = variant === 'full';

  return (
    <div className="w-full h-full flex flex-col bg-card text-card-foreground">
        {/* Taller than the other panel headings, but only a little. This one is
            not just a title: it also reports where this machine sits on the map
            and carries the expand control, and at 10px inside a 22px bar those
            read as a caption rather than as the panel's own chrome. The type and
            icons carry that now; the padding stays tight, because the height
            comes straight off a map that only has 256px to begin with. */}
        {/* `border-border`, not `border-inherit border-opacity-10`, which drew a
            near-white rule across the top of the map on every dark theme. Two
            faults compounding: `border-inherit` inherits a border colour that
            resolves up the tree to `currentColor` - the CARD'S TEXT colour, so
            the divider was painted in `--foreground` (#cbd5e1 on dark) rather
            than in `--border`; and `border-opacity-10`, which was there to knock
            that back to a hint, is a Tailwind v3 utility that v4 does not emit
            at all, so it silently did nothing and the line stayed at full
            strength. This is the token every other panel header in the app
            already uses. */}
        <div
          className={`flex items-center justify-between gap-3 py-1.5 text-[11px] font-bold uppercase tracking-wider opacity-80 border-b border-border shrink-0 ${
            // Room for the overlay's close control, which floats over the
            // top-right corner. Without it the ISP readout runs underneath and
            // loses its last few characters.
            roomy ? 'pl-3.5 pr-12' : 'px-3.5'
          }`}
        >
          <div className="flex items-center gap-2">
            <TbWorld className="w-4 h-4" />
            Live Geo-IP Map
          </div>
          <div className="flex items-center gap-2.5 min-w-0">
            {/* A dropped map pin rather than the house this used to show, and
                no "ISP:" label: the pin already says "this is a place", which
                is the only thing the prefix was adding. Filled rather than
                outlined because at this size an outlined pin's interior hole
                closes up and it stops reading as a pin at all. The full
                wording stays in the tooltip for anyone who wants it. */}
            {ispLocation && (
              <div
                className="flex items-center gap-1.5 text-primary min-w-0"
                title={`ISP location: ${
                  ispLocation.city !== "Unknown" ? ispLocation.city + ", " : ""
                }${ispLocation.country}`}
              >
                <TbMapPinFilled className="w-4 h-4 shrink-0" />
                <span className="truncate">
                  {ispLocation.city !== "Unknown" ? ispLocation.city + ", " : ""}
                  {ispLocation.country}
                </span>
              </div>
            )}
            {/* Expand only, and only in the card. The overlay draws the single
                close control, in the same place for every widget, so this
                header is identical in the expanded window however it was
                opened. */}
            {onExpand && !roomy && (
              <button
                onClick={onExpand}
                // Where focus returns when the panel this opens is closed. The
                // card is unmounted while the panel is up, so the element that
                // opened it no longer exists by the time it closes.
                data-widget-expand=""
                className="p-1 -m-1 rounded shrink-0 hover:bg-accent text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
                aria-label="Expand map"
                title="Expand map"
              >
                <TbMaximize className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
        <div className="flex-1 min-h-0 relative overflow-hidden">
          {/* MapLibre forces position:relative on any element bearing its own
              .maplibregl-map class (added imperatively once the map mounts),
              which silently wins over an "absolute inset-0" utility at equal
              specificity and collapses this div to its (near-zero) content
              height. w-full/h-full sizing works regardless of which position
              value ends up applied, since the parent above already has a
              resolved height. */}
          <div ref={containerRef} className="w-full h-full" />
          {/* Zoom buttons, but only in the expanded view. The compact card is
              256px tall and already carries a title bar, an ISP readout, an
              expand button and the location counter; a stacked pair on top of
              that is the fifth piece of chrome competing for a map barely twice
              as tall as it is - and there is nothing to zoom into at that size,
              since the card shows the whole world.

              Conditional rendering rather than hiding: a control that is
              present but invisible still takes keyboard focus in tab order. */}
          {roomy && (
            <ZoomControls
              onZoomIn={() => mapRef.current?.zoomIn()}
              onZoomOut={() => mapRef.current?.zoomOut()}
            />
          )}
          <GeoLocationCounter
            places={geoStats.places}
            unresolved={geoStats.unresolved}
            expandable={roomy}
            onSelectPlace={(place) => {
              // Zoom 5 is city scale - close enough that the place is the
              // subject rather than a dot in a continent, far enough that its
              // neighbours are still in frame.
              const target = {
                center: [place.longitude, place.latitude] as [number, number],
                zoom: Math.max(mapRef.current?.getZoom() ?? 1, 5),
              };
              // A camera flight across a full-viewport map is the most
              // vestibular-hostile thing in this app, and it is JavaScript
              // rather than CSS, so the blanket reduced-motion rule cannot
              // reach it. Jump instead: same destination, no journey.
              if (prefersReducedMotion()) mapRef.current?.jumpTo(target);
              else mapRef.current?.flyTo({ ...target, speed: 1.2 });
            }}
          />
        </div>
    </div>
  );
};
