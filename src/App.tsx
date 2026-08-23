/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef } from "react";
import { useTheme } from "next-themes";
import { Packet, UserRole } from "./types/packet";
import { PacketGenerator } from "./services/packetGenerator";
import { decodeRawEthernetPacket } from "./services/pcapParser";
import { FilterEngine } from "./services/filterEngine";
import { CustomDissectorEngine } from "./services/customDissectorEngine";
import { ColorRulesEngine } from "./services/colorRules";
import { ROLE_PERMISSIONS } from "./services/rbacService";

// UI Components
import { Header } from "./components/common/Header";
import { FilterBar } from "./components/common/FilterBar";
import { PacketList } from "./components/packet-list/PacketList";
import { PacketDetailsTree } from "./components/packet-details/PacketDetailsTree";
import { HexViewer } from "./components/packet-details/HexViewer";
import { TrafficTimelineChart } from "./components/analytics/TrafficTimelineChart";
import { ProtocolDonutChart } from "./components/analytics/ProtocolDonutChart";
import { NetworkMatrix } from "./components/analytics/NetworkMatrix";
import { AnomalyAlertsPanel } from "./components/analytics/AnomalyAlertsPanel";
import { StreamFollowerModal } from "./components/stream-follower/StreamFollowerModal";
import { CustomDissectorModal } from "./components/dissectors/CustomDissectorModal";
import { StatisticsModal } from "./components/statistics/StatisticsModal";
import { ExportImportModal } from "./components/export/ExportImportModal";
import { ColorRulesModal } from "./components/common/ColorRulesModal";
import { IspStatsModal } from "./components/isp/IspStatsModal";

import { Group as PanelGroup, Panel, Separator as PanelResizeHandle } from "react-resizable-panels";
import { FloatingToolbar } from "./components/common/FloatingToolbar";
import { LiveIOGraph } from "./components/analytics/LiveIOGraph";
import { GeoMap } from "./components/analytics/GeoMap";

import {
  Zap,
  Activity,
  ShieldAlert,
  Code,
  Download,
  BarChart2,
  List,
  Layers,
  Binary,
  Palette,
  Shield,
  LayoutGrid,
  ChevronRight,
  Maximize2,
  Sliders,
  Cpu,
  Globe,
} from "lucide-react";

export default function App() {
  // Theme & Layout
  // Bridge to next-themes (the real source of truth) for the ~20 not-yet-migrated
  // components still reading a plain isDark boolean prop. resolvedTheme is
  // undefined for one tick before next-themes' mount effect runs; defaulting
  // to "dark" during that gap avoids a flash-to-light regression versus the
  // previous hardcoded-dark default. Remove this bridge once every component
  // reads useTheme() directly (Phase 5 of the theming migration).
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme !== "light";
  const [showRightAnalytics, setShowRightAnalytics] = useState(true);
  const [mobileTab, setMobileTab] = useState<
    "packets" | "tree" | "hex" | "graphs" | "alerts"
  >("packets");
  const [sidebarActiveView, setSidebarActiveView] = useState<
    "capture" | "graphs" | "threats" | "dissectors" | "stats"
  >("capture");

  // Stream & Capturing State
  const [isCapturing, setIsCapturing] = useState(false);

  // Packets Buffer & Selection
  const [packets, setPackets] = useState<Packet[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [activeByteRange, setActiveByteRange] = useState<
    [number, number] | null
  >(null);

  // Filter State
  const [filterText, setFilterText] = useState("");
  const [appliedFilter, setAppliedFilter] = useState("");

  // Modals
  const [streamToFollow, setStreamToFollow] = useState<number | null>(null);
  const [showDissectorModal, setShowDissectorModal] = useState(false);
  const [showStatsModal, setShowStatsModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showColorRulesModal, setShowColorRulesModal] = useState(false);
  const [showIspModal, setShowIspModal] = useState(false);
  const [agentStatus, setAgentStatus] = useState<
    "disconnected" | "connecting" | "connected" | "error"
  >("disconnected");

  // RBAC Role (Simplified: Always Admin)
  const permissions = {
    canCapture: true,
    canExportPcap: true,
    canViewPayloads: true,
    canEditDissectors: true,
    canConfigureAlerts: true,
    canChangeColorRules: true,
    canClearBuffer: true,
  };

  // Resizable Bottom Pane
  const [bottomPaneHeight, setBottomPaneHeight] = useState(280);
  const isDraggingRef = useRef(false);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDraggingRef.current) return;
      const footerHeight = 28;
      const newHeight = window.innerHeight - e.clientY - footerHeight;
      setBottomPaneHeight(
        Math.max(100, Math.min(newHeight, window.innerHeight - 200)),
      );
    };
    const handleMouseUp = () => {
      if (isDraggingRef.current) {
        isDraggingRef.current = false;
        document.body.style.cursor = "";
      }
    };
    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseup", handleMouseUp);
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, []);

  // Engines
  const dissectorEngine = useMemo(() => new CustomDissectorEngine(), []);
  const colorEngine = useMemo(() => new ColorRulesEngine(), []);
  const packetGenerator = useMemo(
    () => new PacketGenerator(dissectorEngine),
    [dissectorEngine],
  );

  // Track the latest isCapturing value for the always-on agent connection
  // below, whose handlers are set up once and must not go stale.
  const isCapturingRef = useRef(isCapturing);
  useEffect(() => {
    isCapturingRef.current = isCapturing;
  }, [isCapturing]);

  // Live-capture relative-time clock (Wireshark-style): resets whenever the
  // packet buffer is emptied and a fresh capture begins.
  const captureStartRef = useRef<number | null>(null);
  const lastPacketTimeRef = useRef<number | null>(null);

  // Local Agent Connection - always tries to reach ws://localhost:8999 so
  // the "Download Driver" button can auto-detect the agent running and
  // flip to "Agent Connected", independent of whether capture is active.
  // Packets are only recorded into the buffer while isCapturing is true.
  useEffect(() => {
    if (!permissions.canCapture) return;

    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout;
    let connectedDelay: NodeJS.Timeout | null = null;
    // Only the very first connection attempt shows "Connecting..." - once we
    // know the agent isn't there, silent background retries every 3s keep
    // the status calmly on "disconnected" instead of flashing "Connecting"
    // on every retry (which read as a repeating loop when the agent was
    // never running to begin with).
    let isFirstAttempt = true;

    const connect = () => {
      if (isFirstAttempt) {
        setAgentStatus("connecting");
      }
      ws = new WebSocket("ws://localhost:8999");

      ws.onopen = () => {
        console.log("[WirePulse] Connected to Local Agent");
        // Hold "Connecting..." for a beat after the handshake succeeds so
        // the button doesn't flash instantly - and so a socket that drops
        // right back off (e.g. a page reload racing the connection) reads
        // as still-connecting rather than a confusing connect/disconnect flicker.
        connectedDelay = setTimeout(() => setAgentStatus("connected"), 2000);
      };

      ws.onmessage = (event) => {
        if (!isCapturingRef.current) return; // agent detected, but capture not started yet

        try {
          const rawPkt = JSON.parse(event.data);
          if (!rawPkt || typeof rawPkt !== 'object') return;

          const epochMs = typeof rawPkt.timestamp === 'number' ? rawPkt.timestamp : Date.now();

          setPackets((prev) => {
            const isFirstOfCapture = prev.length === 0;
            if (isFirstOfCapture) {
              captureStartRef.current = epochMs;
              lastPacketTimeRef.current = null;
            }

            const relativeTime = captureStartRef.current !== null
              ? (epochMs - captureStartRef.current) / 1000
              : 0;
            const timeDelta = lastPacketTimeRef.current !== null
              ? Math.max(0, (epochMs - lastPacketTimeRef.current) / 1000)
              : 0;
            lastPacketTimeRef.current = epochMs;

            const id = packetGenerator.getNextId();

            let safePkt: Packet;
            if (typeof rawPkt.raw === 'string' && rawPkt.raw.length > 0) {
              // Authoritative path: dissect the real captured bytes exactly
              // like an imported pcap file would be dissected.
              const binaryString = atob(rawPkt.raw);
              const bytes = Uint8Array.from(binaryString, (c) => c.charCodeAt(0));
              safePkt = decodeRawEthernetPacket(bytes, id, epochMs, relativeTime, timeDelta, rawPkt.length ?? bytes.length);
            } else {
              // Fallback only: the agent did not send raw bytes. Use the
              // lightweight metadata fields and leave byte data genuinely
              // empty rather than fabricating fake content.
              const length = rawPkt.length || 0;
              safePkt = {
                id,
                timestamp: epochMs,
                relativeTime,
                timeDelta,
                source: rawPkt.source || '0.0.0.0',
                destination: rawPkt.destination || '0.0.0.0',
                sourcePort: rawPkt.sourcePort,
                destPort: rawPkt.destPort,
                protocol: rawPkt.protocol || 'TCP',
                length,
                info: rawPkt.info || 'Traffic',
                status: 'ok',
                layers: [
                  {
                    name: 'Frame',
                    summary: `Frame ${id}: ${length} bytes (no raw capture data was available)`,
                    fields: [
                      { name: 'Interface', value: 'Live Agent' },
                      { name: 'Length', value: `${length} bytes` }
                    ]
                  }
                ],
                rawBytes: new Uint8Array(0),
                hexDump: '',
                asciiDump: '',
                interfaceName: 'Live Agent'
              };
            }

            const updated = [...prev, safePkt];
            if (updated.length > 4000) {
              return updated.slice(updated.length - 4000);
            }
            return updated;
          });
        } catch (err) {
          console.warn("[WirePulse] Failed to parse agent packet", err);
        }
      };

      ws.onerror = (error) => {
        console.warn("[WirePulse] WebSocket connection failed. Agent might not be running.");
        if (connectedDelay) clearTimeout(connectedDelay);
        if (isFirstAttempt) setAgentStatus("error");
      };

      ws.onclose = () => {
        console.log(
          "[WirePulse] Disconnected from Local Agent. Reconnecting in 3s...",
        );
        if (connectedDelay) clearTimeout(connectedDelay);
        setAgentStatus("disconnected");
        isFirstAttempt = false;
        reconnectTimeout = setTimeout(connect, 3000);
      };
    };

    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      if (connectedDelay) clearTimeout(connectedDelay);
      if (ws) {
        ws.onclose = null; // prevent reconnect loop on intentional unmount/stop
        ws.close();
      }
      setAgentStatus("disconnected");
    };
  }, [permissions.canCapture, packetGenerator]);

  // Display Filter Evaluation
  const filteredPackets = useMemo(() => {
    if (!appliedFilter.trim()) return packets;
    return FilterEngine.filterPackets(packets, appliedFilter);
  }, [packets, appliedFilter]);

  // If selected packet is filtered out, fall back gracefully
  useEffect(() => {
    if (
      selectedPacket &&
      !filteredPackets.some((p) => p.id === selectedPacket.id)
    ) {
      if (filteredPackets.length > 0) {
        setSelectedPacket(filteredPackets[filteredPackets.length - 1]);
      }
    }
  }, [filteredPackets, selectedPacket]);

  // Global Keyboard Navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger if user is typing in an input
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement
      ) {
        return;
      }

      if (e.code === "Space") {
        e.preventDefault();
        setIsCapturing((prev) => {
          if (!permissions.canCapture) return false;
          return !prev;
        });
        return;
      }

      if (e.code === "ArrowDown") {
        e.preventDefault();
        if (filteredPackets.length === 0) return;
        if (!selectedPacket) {
          setSelectedPacket(filteredPackets[0]);
        } else {
          const idx = filteredPackets.findIndex(
            (p) => p.id === selectedPacket.id,
          );
          if (idx >= 0 && idx < filteredPackets.length - 1) {
            setSelectedPacket(filteredPackets[idx + 1]);
          }
        }
      } else if (e.code === "ArrowUp") {
        e.preventDefault();
        if (filteredPackets.length === 0) return;
        if (!selectedPacket) {
          setSelectedPacket(filteredPackets[filteredPackets.length - 1]);
        } else {
          const idx = filteredPackets.findIndex(
            (p) => p.id === selectedPacket.id,
          );
          if (idx > 0) {
            setSelectedPacket(filteredPackets[idx - 1]);
          }
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [selectedPacket, filteredPackets, permissions.canCapture]);

  // Actions
  const handleStartCapture = () => setIsCapturing(true);
  const handlePauseCapture = () => setIsCapturing(false);
  const handleStopCapture = () => setIsCapturing(false);

  const handleClearPackets = () => {
    packetGenerator.reset();
    setPackets([]);
    setSelectedPacket(null);
    setActiveByteRange(null);
  };

  const handleQuickFilter = (expression: string) => {
    setFilterText(expression);
    setAppliedFilter(expression);
  };

  const handleSelectProtocol = (proto: string) => {
    const expr = `proto == ${proto.toLowerCase()}`;
    setFilterText(expr);
    setAppliedFilter(expr);
  };

  const handleFilterHost = (ip: string) => {
    const expr = `ip.addr == "${ip}"`;
    setFilterText(expr);
    setAppliedFilter(expr);
  };

  const handleFollowStream = (streamId: number) => {
    setStreamToFollow(streamId);
  };

  const handleReplayPackets = (packetsToReplay: Packet[]) => {
    setPackets((prev) => {
      const replayedPackets = packetsToReplay.map((p) => {
        return {
          ...p,
          id: packetGenerator.getNextId(),
          timestamp: Date.now(),
          info: `[REPLAY] ${p.info}`,
        };
      });
      const updated = [...prev, ...replayedPackets];
      if (updated.length > 4000) {
        return updated.slice(updated.length - 4000);
      }
      return updated;
    });
  };

  const handleImportPackets = (imported: Packet[]) => {
    setIsCapturing(false);
    setPackets(imported);
    if (imported.length > 0) {
      setSelectedPacket(imported[0]);
    }
  };

  const handleUpdateDissectors = () => {
    packetGenerator.setDissectorEngine(dissectorEngine);
  };

  // Compute live telemetry for bottom footer
  const totalBytes = useMemo(
    () => packets.reduce((sum, p) => sum + p.length, 0),
    [packets],
  );
  const activeThreatsCount = useMemo(
    () => packets.filter((p) => p.anomaly || p.status === "alert").length,
    [packets],
  );

  return (
    <div className="h-screen w-screen flex font-sans overflow-hidden transition-colors bg-background text-foreground">
      {/* 1. Geometric Balance Geometric Aside Dock (Hidden on tiny mobile, visible on tablet+) */}
      <aside className="w-14 sm:w-16 border-r flex flex-col items-center py-4 space-y-6 shrink-0 z-30 transition-colors bg-card border-border shadow-sm">
        {/* Geometric Logo Badge */}
        <div
          onClick={() => setShowStatsModal(true)}
          className="w-10 h-10 bg-cyan-500 hover:bg-cyan-400 rounded-md flex items-center justify-center text-slate-950 font-black text-sm cursor-pointer shadow-md shadow-cyan-500/20 transition-transform active:scale-95"
          title="Net View Network Telemetry"
        >
          NV
        </div>

        {/* Action Icon Navigation */}
        <nav className="flex flex-col space-y-3">
          <button
            onClick={() => setSidebarActiveView("capture")}
            className={`p-2.5 rounded-md transition-all ${
              sidebarActiveView === "capture"
                ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
            }`}
            title="Live Packet Capture"
          >
            <Zap className="w-5 h-5" />
          </button>

          <button
            onClick={() => setShowRightAnalytics(!showRightAnalytics)}
            className={`p-2.5 rounded-md transition-all ${
              showRightAnalytics
                ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
            }`}
            title="Toggle Right Analytics Panel"
          >
            <Activity className="w-5 h-5" />
          </button>

          <button
            onClick={() => setShowDissectorModal(true)}
            className="p-2.5 rounded-md transition-all text-muted-foreground hover:bg-accent hover:text-accent-foreground"
            title="Custom Protocol Dissectors"
          >
            <Code className="w-5 h-5 text-cyan-400/80" />
          </button>

          <button
            onClick={() => setShowStatsModal(true)}
            className="p-2.5 rounded-md transition-all text-muted-foreground hover:bg-accent hover:text-accent-foreground"
            title="Protocol Hierarchy Statistics"
          >
            <BarChart2 className="w-5 h-5 text-purple-400/80" />
          </button>

          <button
            onClick={() => setShowExportModal(true)}
            className="p-2.5 rounded-md transition-all text-muted-foreground hover:bg-accent hover:text-accent-foreground"
            title="PCAP / JSON Import & Export"
          >
            <Download className="w-5 h-5 text-sky-400/80" />
          </button>

          <button
            onClick={() => setShowColorRulesModal(true)}
            className="p-2.5 rounded-md transition-all text-muted-foreground hover:bg-accent hover:text-accent-foreground"
            title="Color Highlighting Rules"
          >
            <Palette className="w-5 h-5 text-pink-400/80" />
          </button>

          <button
            onClick={() => setShowIspModal(true)}
            className="p-2.5 rounded-md transition-all text-muted-foreground hover:bg-accent hover:text-accent-foreground"
            title="ISP Network Statistics"
          >
            <Globe className="w-5 h-5 text-sky-400/80" />
          </button>
        </nav>

        {/* Bottom Sidebar Status indicator & RBAC */}
        <div className="mt-auto flex flex-col items-center space-y-3">
          {activeThreatsCount > 0 ? (
            <div
              className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"
              title={`${activeThreatsCount} Threats Detected`}
            />
          ) : (
            <div
              className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"
              title="Stream Healthy - Zero Threats"
            />
          )}
        </div>
      </aside>

      {/* 2. Main Workstation Body */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Command Bar & Stream Interface */}

        <Header
          isCapturing={isCapturing}
          onStartCapture={() => setIsCapturing(true)}
          onPauseCapture={() => setIsCapturing(false)}
          onStopCapture={() => setIsCapturing(false)}
          onClearPackets={() => setPackets([])}
          permissions={permissions}
          onOpenDissectorModal={() => setShowDissectorModal(true)}
          onOpenStatsModal={() => setShowStatsModal(true)}
          onOpenExportModal={() => setShowExportModal(true)}
          onOpenColorRulesModal={() => setShowColorRulesModal(true)}
          onOpenIspModal={() => setShowIspModal(true)}
          agentStatus={agentStatus}
          totalPacketsCount={packets.length}
          filteredPacketsCount={filteredPackets.length}
        />

        {/* Filter Toolbar (Geometric Balance style) */}
        <FilterBar
          filterText={filterText}
          onFilterChange={setFilterText}
          onApplyFilter={(newFilter?: string) =>
            setAppliedFilter(newFilter !== undefined ? newFilter : filterText)
          }
          totalPackets={packets.length}
          filteredPackets={filteredPackets.length}
          isDark={isDark}
        />

        {/* Mobile Tab Switcher */}
        <div className="flex md:hidden border-b border-border bg-card text-xs overflow-x-auto shrink-0">
          <button
            onClick={() => setMobileTab("packets")}
            className={`flex-1 py-2 px-3 flex items-center justify-center gap-1 font-bold tracking-tight whitespace-nowrap ${
              mobileTab === "packets"
                ? "border-b-2 border-cyan-400 text-cyan-400 bg-cyan-950/20"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <List className="w-3.5 h-3.5" />
            <span>Packets ({filteredPackets.length})</span>
          </button>

          <button
            onClick={() => setMobileTab("tree")}
            className={`flex-1 py-2 px-3 flex items-center justify-center gap-1 font-bold tracking-tight whitespace-nowrap ${
              mobileTab === "tree"
                ? "border-b-2 border-cyan-400 text-cyan-400 bg-cyan-950/20"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Protocol Tree</span>
          </button>

          <button
            onClick={() => setMobileTab("hex")}
            className={`flex-1 py-2 px-3 flex items-center justify-center gap-1 font-bold tracking-tight whitespace-nowrap ${
              mobileTab === "hex"
                ? "border-b-2 border-cyan-400 text-cyan-400 bg-cyan-950/20"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Binary className="w-3.5 h-3.5" />
            <span>Hex View</span>
          </button>

          <button
            onClick={() => setMobileTab("graphs")}
            className={`flex-1 py-2 px-3 flex items-center justify-center gap-1 font-bold tracking-tight whitespace-nowrap ${
              mobileTab === "graphs"
                ? "border-b-2 border-cyan-400 text-cyan-400 bg-cyan-950/20"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Analytics</span>
          </button>
        </div>

        {/* Central Inspection + Analytics Split Grid */}
        <div className="flex-1 flex min-h-0 overflow-hidden">
          {/* Main Packet Inspection Core */}
          <section className="flex-1 flex flex-col border-r border-border overflow-hidden min-w-0">
            {/* Upper Pane: High-Density Packet Table */}
            <div
              className={`flex-1 flex flex-col min-h-0 overflow-hidden ${
                mobileTab === "packets" ? "block" : "hidden md:flex"
              }`}
            >
              <PacketList
                packets={filteredPackets}
                selectedPacket={selectedPacket}
                onSelectPacket={(pkt) => {
                  setSelectedPacket(pkt);
                  if (window.innerWidth < 768) {
                    setMobileTab("tree");
                  }
                }}
                onFollowStream={handleFollowStream}
                onQuickFilter={handleQuickFilter}
                onReplayPackets={handleReplayPackets}
                colorEngine={colorEngine}
                permissions={permissions}
                isDark={isDark}
              />
            </div>

            {/* Resize Drag Handle */}
            <div
              className="hidden md:block h-1.5 w-full cursor-row-resize transition-colors shrink-0 z-10 bg-muted hover:bg-cyan-500/50"
              onMouseDown={() => {
                isDraggingRef.current = true;
                document.body.style.cursor = "row-resize";
              }}
            />

            {/* Lower Pane: Geometric Split of Protocol Details Tree & Hex Viewer */}
            <div
              style={
                {
                  "--bottom-pane-height": `${bottomPaneHeight}px`,
                } as React.CSSProperties
              }
              className={`h-56 md:h-[var(--bottom-pane-height)] border-t border-border flex flex-col md:flex-row overflow-hidden transition-colors shrink-0 bg-card ${mobileTab !== "packets" && mobileTab !== "graphs" ? "block" : "hidden md:flex"}`}
            >
              {/* Protocol Layers Inspection Tree */}
              <div
                className={`w-full md:w-1/2 h-full border-r border-border overflow-hidden ${
                  mobileTab === "tree" ? "block" : "hidden md:block"
                }`}
              >
                <PacketDetailsTree
                  packet={selectedPacket}
                  onHoverByteRange={setActiveByteRange}
                  activeByteRange={activeByteRange}
                  permissions={permissions}
                  isDark={isDark}
                />
              </div>

              {/* Raw Hex & ASCII Dump View */}
              <div
                className={`w-full md:w-1/2 h-full overflow-hidden ${
                  mobileTab === "hex" ? "block" : "hidden md:block"
                }`}
              >
                <HexViewer
                  packet={selectedPacket}
                  activeByteRange={activeByteRange}
                  onHoverByte={(byteIdx) => {
                    if (byteIdx !== null)
                      setActiveByteRange([byteIdx, byteIdx]);
                    else setActiveByteRange(null);
                  }}
                  permissions={permissions}
                  isDark={isDark}
                />
              </div>
            </div>
          </section>

          {/* Right Analytics Aside (Geometric Balance style) */}
          <aside
            className={`w-80 lg:w-96 border-l border-border p-4 space-y-4 flex flex-col overflow-y-auto custom-scrollbar shrink-0 transition-colors bg-background ${
              showRightAnalytics ? "hidden lg:flex" : "hidden"
            } ${mobileTab === "graphs" ? "!flex !w-full !border-l-0" : ""}`}
          >
            {/* Real-time D3 Throughput & Traffic Spikes */}
            <div>
              <TrafficTimelineChart
                packets={packets}
                isCapturing={isCapturing}
                onTimeWindowSelect={(t0, t1) => {
                  if (t0 !== null && t1 !== null) {
                    const expr = `time >= ${t0} && time <= ${t1}`;
                    setFilterText(expr);
                    setAppliedFilter(expr);
                  }
                }}
                onJumpToPacket={(pkt) => {
                  setSelectedPacket(pkt);
                  if (window.innerWidth < 768) setMobileTab("tree");
                }}
                isDark={isDark}
              />
            </div>

            {/* Protocol Distribution Breakdown */}
            <div>
              <ProtocolDonutChart
                packets={packets}
                onSelectProtocol={handleSelectProtocol}
                selectedProtocolFilter={appliedFilter}
                isDark={isDark}
              />
            </div>

            {/* Geo-IP Map */}
            <div className="h-64 shrink-0 rounded-lg overflow-hidden border border-border">
              <GeoMap packets={packets} isDark={isDark} />
            </div>
            {/* Flow Matrix & Top Talkers */}
            <div>
              <NetworkMatrix
                packets={packets}
                onFilterHost={handleFilterHost}
                isDark={isDark}
              />
            </div>

            {/* Threat & Anomaly Alert Card */}
            <div className="mt-auto">
              <AnomalyAlertsPanel
                packets={packets}
                onInspectPacket={(pkt) => {
                  setSelectedPacket(pkt);
                  if (window.innerWidth < 768) setMobileTab("tree");
                }}
                onFilterAnomaly={() => handleQuickFilter("anomaly")}
                isDark={isDark}
              />
            </div>
          </aside>
        </div>

        {/* 3. Geometric Balance Status Bar (High-Contrast Cyan Footer) */}
        <footer className="h-8 bg-cyan-600 text-slate-950 flex items-center px-4 justify-between text-[11px] font-bold font-mono tracking-wider select-none shrink-0">
          <div className="flex items-center space-x-4 sm:space-x-6">
            <span>PACKETS: {packets.length.toLocaleString()}</span>
            <span className="hidden sm:inline">DROPPED: 0</span>
            <span>FILTERED: {filteredPackets.length.toLocaleString()}</span>
            <span className="hidden md:inline">
              BUFFER: {((packets.length / 4000) * 100).toFixed(0)}%
            </span>
          </div>

          <div className="flex items-center space-x-3 sm:space-x-5 uppercase">
            <span className="hidden sm:inline">NIC: Live Agent</span>
            <span className="hidden lg:inline">
              VOL: {(totalBytes / 1024).toFixed(1)} KB
            </span>
          </div>
        </footer>
      </main>

      {/* 4. Modals */}
      {streamToFollow !== null && (
        <StreamFollowerModal
          streamId={streamToFollow}
          packets={packets}
          onClose={() => setStreamToFollow(null)}
          isDark={isDark}
        />
      )}

      {showDissectorModal && (
        <CustomDissectorModal
          dissectorEngine={dissectorEngine}
          onUpdateDissectors={handleUpdateDissectors}
          onClose={() => setShowDissectorModal(false)}
          permissions={permissions}
          isDark={isDark}
        />
      )}

      {showStatsModal && (
        <StatisticsModal
          packets={packets}
          onClose={() => setShowStatsModal(false)}
          isDark={isDark}
        />
      )}

      {showExportModal && (
        <ExportImportModal
          packets={packets}
          onImportPackets={handleImportPackets}
          onClose={() => setShowExportModal(false)}
          permissions={permissions}
          isDark={isDark}
        />
      )}

      {showColorRulesModal && (
        <ColorRulesModal
          colorEngine={colorEngine}
          onUpdateRules={() => setPackets([...packets])}
          onClose={() => setShowColorRulesModal(false)}
          permissions={permissions}
          isDark={isDark}
        />
      )}

      {showIspModal && (
        <IspStatsModal isDark={isDark} onClose={() => setShowIspModal(false)} />
      )}
    </div>
  );
}
