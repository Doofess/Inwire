import React, { useEffect, useRef, useState } from "react";
import * as maplibregl from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { Packet } from "../../types/packet";
import {
  resolveIP,
  resolveHostname,
  GeoLocation,
  isPrivateIP,
} from "../../services/geoIpService";
import { TbWorld, TbHome, TbMaximize, TbX } from "react-icons/tb";
import { themeColor } from '../../lib/themeColor';

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
const CONNECTIONS_SYNC_THROTTLE_MS = 600;

interface GeoMapProps {
  packets: Packet[];
  isDark: boolean;
  /** See TrafficTimelineChart: forces a redraw when the theme changes, which
   *  isDark cannot signal between two dark themes. */
  themeKey?: string;
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

function buildPopupHtml(ip: string, loc: GeoLocation, hostname: string | null) {
  const locationLabel = loc.city !== "Unknown" ? `${loc.city}, ${loc.country}` : loc.country;
  return `
    <div class="font-mono text-xs min-w-[150px] max-w-[220px]">
      <div class="font-bold text-primary break-all mb-1">${escapeHtml(ip)}</div>
      <div class="text-foreground mb-1">${escapeHtml(locationLabel)}</div>
      ${hostname ? `<a href="https://${escapeHtml(hostname)}" target="_blank" rel="noopener noreferrer" class="text-[10px] text-sky-500 hover:underline break-all block">${escapeHtml(hostname)}</a>` : ""}
    </div>
  `;
}

function createMarkerElement(color: string, size: number) {
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

  const ping = document.createElement("span");
  ping.style.position = "absolute";
  ping.style.inset = "0";
  ping.style.borderRadius = "9999px";
  ping.style.background = color;
  ping.style.opacity = "0.4";
  ping.className = "animate-ping";

  const dot = document.createElement("span");
  dot.style.position = "absolute";
  dot.style.inset = "0";
  dot.style.borderRadius = "9999px";
  dot.style.background = color;
  dot.style.boxShadow = `0 0 6px ${color}`;

  el.appendChild(ping);
  el.appendChild(dot);
  return el;
}

export const GeoMap: React.FC<GeoMapProps> = ({ packets, isDark, themeKey }) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const markersRef = useRef<Map<string, maplibregl.Marker>>(new Map());
  const ispMarkerRef = useRef<maplibregl.Marker | null>(null);
  const popupRef = useRef<maplibregl.Popup | null>(null);
  const isExpandedRef = useRef(false);
  const isFirstStyleRun = useRef(true);
  const connectionsRef = useRef<GeoJSON.FeatureCollection>({ type: "FeatureCollection", features: [] });
  const connectionsSyncTimeoutRef = useRef<number | null>(null);
  const isCameraMovingRef = useRef(false);

  const [locations, setLocations] = useState<Map<string, GeoLocation>>(new Map());
  const [hostnames, setHostnames] = useState<Map<string, string | null>>(new Map());
  const [ispLocation, setIspLocation] = useState<GeoLocation | null>(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const seenIps = useRef<Set<string>>(new Set());

  useEffect(() => {
    isExpandedRef.current = isExpanded;
  }, [isExpanded]);

  // Fetch ISP (own public IP) location once on mount.
  useEffect(() => {
    fetch("https://get.geojs.io/v1/ip/geo.json")
      .then((res) => res.json())
      .then((data) => {
        setIspLocation({
          ip: data.ip,
          latitude: parseFloat(data.latitude),
          longitude: parseFloat(data.longitude),
          city: data.city || "Unknown",
          country: data.country || "Unknown",
        });
      })
      .catch((err) => console.error("Failed to fetch ISP location", err));
  }, []);

  // Resolve geolocation + reverse-DNS hostname for newly-seen public IPs.
  useEffect(() => {
    const recentPackets = packets.slice(-20);

    recentPackets.forEach((p) => {
      [p.source, p.destination].forEach((ip) => {
        if (!seenIps.current.has(ip) && !isPrivateIP(ip)) {
          seenIps.current.add(ip);
          resolveIP(ip).then((loc) => {
            if (loc && !isNaN(loc.latitude) && !isNaN(loc.longitude)) {
              if (Math.abs(loc.latitude) > 0.1 || Math.abs(loc.longitude) > 0.1) {
                setLocations((prev) => {
                  const next = new Map(prev);
                  next.set(ip, loc);
                  return next;
                });
              }
            }
          });
          resolveHostname(ip).then((hostname) => {
            setHostnames((prev) => {
              const next = new Map(prev);
              next.set(ip, hostname);
              return next;
            });
          });
        }
      });
    });
  }, [packets]);

  const activeConnections = React.useMemo(() => {
    const getCoords = (ip: string): [number, number] | null => {
      if (isPrivateIP(ip) && ispLocation && !isNaN(ispLocation.longitude)) {
        return [ispLocation.longitude, ispLocation.latitude];
      }
      const loc = locations.get(ip);
      if (loc && !isNaN(loc.longitude)) {
        return [loc.longitude, loc.latitude];
      }
      return null;
    };

    return packets
      .slice(-20)
      .map((p) => {
        const from = getCoords(p.source);
        const to = getCoords(p.destination);
        if (from && to && (from[0] !== to[0] || from[1] !== to[1])) {
          return { id: String(p.id), from, to };
        }
        return null;
      })
      .filter(Boolean) as { id: string; from: [number, number]; to: [number, number] }[];
  }, [packets, locations, ispLocation]);

  // Sync the connections GeoJSON source/layer with the map's currently loaded
  // style. Re-invoked on every style load (including after theme switches,
  // since setStyle() tears down all custom sources/layers) as well as
  // whenever the connections data itself changes.
  const syncConnectionsLayer = () => {
    const map = mapRef.current;
    if (!map || !map.isStyleLoaded()) return;
    // A GeoJSON setData() re-tessellates and repaints the line layer -
    // real main-thread work. Doing that on the same frame as an in-progress
    // pan/zoom gesture is exactly what caused the map to visibly stutter
    // when packets kept arriving while the user was moving the camera.
    // Skip it mid-gesture; the 'moveend' listener below runs one catch-up
    // sync as soon as the camera settles.
    if (isCameraMovingRef.current) return;

    const existingSource = map.getSource(CONNECTIONS_SOURCE_ID) as maplibregl.GeoJSONSource | undefined;
    if (existingSource) {
      existingSource.setData(connectionsRef.current);
      return;
    }

    map.addSource(CONNECTIONS_SOURCE_ID, { type: "geojson", data: connectionsRef.current });
    map.addLayer({
      id: CONNECTIONS_LAYER_ID,
      type: "line",
      source: CONNECTIONS_SOURCE_ID,
      paint: {
        "line-color": "#38bdf8",
        "line-width": 1.5,
        "line-opacity": 0.6,
        "line-dasharray": [2, 2],
      },
    });
  };

  // During active capture `packets` (and therefore `activeConnections`)
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
  useEffect(() => {
    connectionsRef.current = {
      type: "FeatureCollection",
      features: activeConnections.map((c) => ({
        type: "Feature",
        properties: { id: c.id },
        geometry: { type: "LineString", coordinates: [c.from, c.to] },
      })),
    };

    if (connectionsSyncTimeoutRef.current !== null) return;
    connectionsSyncTimeoutRef.current = window.setTimeout(() => {
      syncConnectionsLayer();
      connectionsSyncTimeoutRef.current = null;
    }, CONNECTIONS_SYNC_THROTTLE_MS);
  }, [activeConnections]);

  // Create the map once on mount.
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;

    const map = new maplibregl.Map({
      container: containerRef.current,
      style: isDark ? DARK_STYLE : LIGHT_STYLE,
      center: [15, 20],
      zoom: 1,
      minZoom: 0.6,
      maxZoom: 14,
      attributionControl: false,
      dragRotate: false,
      pitchWithRotate: false,
      touchPitch: false,
      cooperativeGestures: true,
    });

    map.touchZoomRotate.disableRotation();
    map.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right");
    map.on("style.load", syncConnectionsLayer);
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

    return () => {
      map.remove();
      mapRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Swap the basemap style on theme change (skip the redundant call on mount).
  useEffect(() => {
    if (!mapRef.current) return;
    if (isFirstStyleRun.current) {
      isFirstStyleRun.current = false;
      return;
    }
    mapRef.current.setStyle(isDark ? DARK_STYLE : LIGHT_STYLE);
  }, [isDark, themeKey]);

  // Cooperative gestures only make sense in the small, scroll-competing
  // compact card - the expanded view is a full-screen focused surface.
  useEffect(() => {
    if (!mapRef.current) return;
    if (isExpanded) {
      mapRef.current.cooperativeGestures.disable();
    } else {
      mapRef.current.cooperativeGestures.enable();
    }
  }, [isExpanded]);

  // MapLibre doesn't auto-detect the container resizing when toggling
  // expand/collapse (the canvas would otherwise stay clipped to its old
  // size) - nudge it once the new layout has painted.
  useEffect(() => {
    const raf = requestAnimationFrame(() => mapRef.current?.resize());
    return () => cancelAnimationFrame(raf);
  }, [isExpanded]);

  // Keep ping-source markers in sync with resolved locations.
  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;

    for (const [ip, marker] of markersRef.current) {
      if (!locations.has(ip)) {
        marker.remove();
        markersRef.current.delete(ip);
      }
    }

    locations.forEach((loc, ip) => {
      if (markersRef.current.has(ip)) return;

      const el = createMarkerElement("#10b981", 12);
      const marker = new maplibregl.Marker({ element: el }).setLngLat([loc.longitude, loc.latitude]).addTo(map);

      el.addEventListener("mouseenter", () => {
        if (!isExpandedRef.current || !popupRef.current) return;
        const hostname = hostnames.get(ip) ?? null;
        popupRef.current.setLngLat([loc.longitude, loc.latitude]).setHTML(buildPopupHtml(ip, loc, hostname)).addTo(map);
      });
      el.addEventListener("mouseleave", () => {
        popupRef.current?.remove();
      });

      markersRef.current.set(ip, marker);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [locations]);

  // ISP ("home") marker.
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !ispLocation || isNaN(ispLocation.latitude) || isNaN(ispLocation.longitude)) return;

    ispMarkerRef.current?.remove();

    const el = createMarkerElement(themeColor('--primary', '#06b6d4'), 14);
    const marker = new maplibregl.Marker({ element: el })
      .setLngLat([ispLocation.longitude, ispLocation.latitude])
      .addTo(map);

    el.addEventListener("mouseenter", () => {
      if (!isExpandedRef.current || !popupRef.current) return;
      popupRef.current.setLngLat([ispLocation.longitude, ispLocation.latitude]).setHTML(buildPopupHtml(ispLocation.ip, ispLocation, null)).addTo(map);
    });
    el.addEventListener("mouseleave", () => {
      popupRef.current?.remove();
    });

    ispMarkerRef.current = marker;
  }, [ispLocation]);

  return (
    <>
      {isExpanded && (
        <div
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm"
          onClick={() => setIsExpanded(false)}
        />
      )}
      <div
        className={
          isExpanded
            ? "fixed inset-4 md:inset-10 z-50 rounded-xl border bg-card border-border text-card-foreground shadow-2xl flex flex-col overflow-hidden"
            : "w-full h-full flex flex-col bg-card text-card-foreground"
        }
      >
        <div className="flex items-center justify-between px-3 py-1 text-[10px] font-bold uppercase tracking-wider opacity-70 border-b border-inherit border-opacity-10 shrink-0">
          <div className="flex items-center gap-2">
            <TbWorld className="w-3.5 h-3.5" />
            Live Geo-IP Map
          </div>
          <div className="flex items-center gap-2">
            {ispLocation && (
              <div className="flex items-center gap-1.5 text-primary">
                <TbHome className="w-3 h-3" />
                <span>
                  ISP:{" "}
                  {ispLocation.city !== "Unknown" ? ispLocation.city + ", " : ""}
                  {ispLocation.country}
                </span>
              </div>
            )}
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="p-1 -m-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground transition-colors"
              title={isExpanded ? "Close expanded view" : "Expand map"}
            >
              {isExpanded ? <TbX className="w-3.5 h-3.5" /> : <TbMaximize className="w-3.5 h-3.5" />}
            </button>
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
        </div>
      </div>
    </>
  );
};
