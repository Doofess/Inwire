import React, { useEffect, useState, useRef } from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup,
  Line,
} from "react-simple-maps";
import { Packet } from "../../types/packet";
import {
  resolveIP,
  GeoLocation,
  isPrivateIP,
} from "../../services/geoIpService";
import { Globe, Home, Plus, Minus } from "lucide-react";

const geoUrl = "https://unpkg.com/world-atlas@2.0.2/countries-110m.json";

interface GeoMapProps {
  packets: Packet[];
  isDark: boolean;
}

export const GeoMap: React.FC<GeoMapProps> = ({ packets, isDark }) => {
  const [locations, setLocations] = useState<Map<string, GeoLocation>>(
    new Map(),
  );
  const [ispLocation, setIspLocation] = useState<GeoLocation | null>(null);
  const [position, setPosition] = useState({
    coordinates: [0, 0] as [number, number],
    zoom: 1,
  });
  const [isZooming, setIsZooming] = useState(false);
  const seenIps = useRef<Set<string>>(new Set());

  const handleZoomIn = () => {
    if (position.zoom >= 4) return;
    setIsZooming(true);
    setPosition((pos) => ({ ...pos, zoom: pos.zoom * 1.5 }));
    setTimeout(() => setIsZooming(false), 500);
  };

  const handleZoomOut = () => {
    if (position.zoom <= 1) return;
    setIsZooming(true);
    setPosition((pos) => ({ ...pos, zoom: pos.zoom / 1.5 }));
    setTimeout(() => setIsZooming(false), 500);
  };

  const handleMoveEnd = (position: {
    coordinates: [number, number];
    zoom: number;
  }) => {
    setPosition(position);
  };

  useEffect(() => {
    // Fetch ISP location on mount
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

  useEffect(() => {
    // Process only the latest 20 packets to prevent excessive state updates/loops
    const recentPackets = packets.slice(-20);

    recentPackets.forEach((p) => {
      [p.source, p.destination].forEach((ip) => {
        if (!seenIps.current.has(ip) && !isPrivateIP(ip)) {
          seenIps.current.add(ip);
          resolveIP(ip).then((loc) => {
            if (loc && !isNaN(loc.latitude) && !isNaN(loc.longitude)) {
              // Filter out obvious invalid 0,0 locations which cause off-map pins
              if (
                Math.abs(loc.latitude) > 0.1 ||
                Math.abs(loc.longitude) > 0.1
              ) {
                setLocations((prev) => {
                  const next = new Map(prev);
                  next.set(ip, loc);
                  return next;
                });
              }
            }
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
      .filter(Boolean) as {
      id: string;
      from: [number, number];
      to: [number, number];
    }[];
  }, [packets, locations, ispLocation]);

  return (
    <div
      className={`w-full h-full flex flex-col ${isDark ? "bg-zinc-950 text-zinc-300" : "bg-white text-slate-700"}`}
    >
      <style>{`
        @keyframes flow-dash {
          from { stroke-dashoffset: 20; }
          to { stroke-dashoffset: 0; }
        }
        .animate-flow-line {
          stroke-dasharray: 4 6;
          animation: flow-dash 1s linear infinite;
        }
      `}</style>
      <div className="flex items-center justify-between px-3 py-1 text-[10px] font-bold uppercase tracking-wider opacity-70 border-b border-inherit border-opacity-10 shrink-0">
        <div className="flex items-center gap-2">
          <Globe className="w-3.5 h-3.5" />
          Live Geo-IP Map
        </div>
        {ispLocation && (
          <div className="flex items-center gap-1.5 text-cyan-500">
            <Home className="w-3 h-3" />
            <span>
              ISP:{" "}
              {ispLocation.city !== "Unknown" ? ispLocation.city + ", " : ""}
              {ispLocation.country}
            </span>
          </div>
        )}
      </div>
      <div className="flex-1 min-h-0 relative overflow-hidden bg-transparent">
        <div className="absolute top-2 right-2 flex flex-col gap-1 z-10">
          <button
            onClick={handleZoomIn}
            className={`p-1 rounded border transition-colors ${isDark ? "bg-zinc-800 border-zinc-700 hover:bg-zinc-700 text-zinc-300" : "bg-white border-slate-300 hover:bg-slate-100 text-slate-600"}`}
          >
            <Plus className="w-4 h-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className={`p-1 rounded border transition-colors ${isDark ? "bg-zinc-800 border-zinc-700 hover:bg-zinc-700 text-zinc-300" : "bg-white border-slate-300 hover:bg-slate-100 text-slate-600"}`}
          >
            <Minus className="w-4 h-4" />
          </button>
        </div>
        <ComposableMap
          projectionConfig={{ scale: 140 }}
          width={800}
          height={400}
          style={{ width: "100%", height: "100%", overflow: "visible" }}
        >
          <ZoomableGroup
            zoom={position.zoom}
            center={position.coordinates}
            onMoveEnd={handleMoveEnd}
            className={
              isZooming ? "transition-transform duration-500 ease-in-out" : ""
            }
          >
            <Geographies geography={geoUrl}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill={isDark ? "#27272a" : "#e2e8f0"}
                    stroke={isDark ? "#3f3f46" : "#cbd5e1"}
                    strokeWidth={0.5}
                    style={{
                      default: { outline: "none" },
                      hover: {
                        fill: isDark ? "#3f3f46" : "#cbd5e1",
                        outline: "none",
                      },
                      pressed: { outline: "none" },
                    }}
                  />
                ))
              }
            </Geographies>
            {Array.from(locations.values()).map((loc) => (
              <Marker key={loc.ip} coordinates={[loc.longitude, loc.latitude]}>
                <circle
                  r={8}
                  fill="#10b981"
                  fillOpacity={0.2}
                  className="animate-ping"
                />
                <circle r={3} fill="#10b981" />
              </Marker>
            ))}
            {ispLocation &&
              !isNaN(ispLocation.latitude) &&
              !isNaN(ispLocation.longitude) && (
                <Marker
                  key="isp-location"
                  coordinates={[ispLocation.longitude, ispLocation.latitude]}
                >
                  <circle r={4} fill="#06b6d4" />
                  <circle
                    r={12}
                    fill="#06b6d4"
                    fillOpacity={0.3}
                    className="animate-pulse"
                  />
                </Marker>
              )}
            {activeConnections.map((conn) => (
              <Line
                key={conn.id}
                from={conn.from}
                to={conn.to}
                stroke={isDark ? "#38bdf8" : "#0ea5e9"}
                strokeWidth={1.5}
                strokeLinecap="round"
                className="animate-flow-line opacity-60"
              />
            ))}
          </ZoomableGroup>
        </ComposableMap>

        {/* Real-time coordinates overlay */}
        <div className="absolute bottom-1 right-2 flex flex-col items-end pointer-events-none">
          {Array.from(locations.values())
            .slice(-3)
            .reverse()
            .map((loc, i) => (
              <div
                key={loc.ip}
                className={`text-[9px] font-mono whitespace-nowrap mb-0.5 opacity-${100 - i * 30}`}
              >
                <span className="text-emerald-500 font-bold">{loc.ip}</span>{" "}
                {loc.city !== "Unknown" ? loc.city + ", " : ""}
                {loc.country}
              </div>
            ))}
        </div>
      </div>
    </div>
  );
};
