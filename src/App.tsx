/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef } from "react";
import { AnimatePresence } from "motion/react";
import { useTheme } from "next-themes";
import { Packet, UserRole } from "./types/packet";
import { PacketGenerator } from "./services/packetGenerator";
import { decodeRawEthernetPacket } from "./services/pcapParser";
import { TcpStreamTracker } from "./services/tcpStreamTracker";
import { IcmpEchoTracker } from "./services/icmpEchoTracker";
import { QuicFlowTracker } from "./services/quicFlowTracker";
import { FilterEngine } from "./services/filterEngine";
import { CustomDissectorEngine } from "./services/customDissectorEngine";
import { ColorRulesEngine } from "./services/colorRules";
import { ROLE_PERMISSIONS } from "./services/rbacService";
import { parseAgentMessage, encodeAgentCommand, isAgentOutdated, REQUIRED_AGENT_VERSION, getStoredPairingToken, storePairingToken, clearStoredPairingToken, type AgentCommand } from "./services/agentProtocol";

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
import { IspStatsModal } from "./components/isp/IspStatsModal";
import { SettingsModal } from "./components/common/SettingsModal";

import { Group as PanelGroup, Panel, Separator as PanelResizeHandle } from "react-resizable-panels";
import { FloatingToolbar } from "./components/common/FloatingToolbar";
import { LiveIOGraph } from "./components/analytics/LiveIOGraph";
import { GeoMap } from "./components/analytics/GeoMap";

import {
  TbActivity,
  TbList,
  TbStack2,
  TbBinary,
} from "react-icons/tb";

export default function App() {
  // Theme & Layout
  // Bridge to next-themes (the real source of truth) for the 4 remaining
  // components that need a plain isDark boolean for genuine non-Tailwind color
  // decisions (PacketList's colorEngine, TrafficTimelineChart's d3 code,
  // GeoMap's react-simple-maps fill/stroke props, ExportImportModal's accent
  // cards) rather than for Tailwind class branching. resolvedTheme is
  // undefined for one tick before next-themes' mount effect runs; defaulting
  // to "dark" during that gap avoids a flash-to-light regression versus the
  // previous hardcoded-dark default.
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme !== "light";
  const [mobileTab, setMobileTab] = useState<
    "packets" | "tree" | "hex" | "graphs" | "alerts"
  >("packets");

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
  const [packetSearchText, setPacketSearchText] = useState("");

  // Modals
  const [streamToFollow, setStreamToFollow] = useState<number | null>(null);
  const [showDissectorModal, setShowDissectorModal] = useState(false);
  const [showStatsModal, setShowStatsModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showIspModal, setShowIspModal] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [agentStatus, setAgentStatus] = useState<
    "disconnected" | "connecting" | "connected" | "error"
  >("disconnected");
  const [agentCaptureState, setAgentCaptureState] = useState<'idle' | 'sniffing'>('idle');
  const [agentVersion, setAgentVersion] = useState<string | null>(null);
  const [agentInterfaces, setAgentInterfaces] = useState<{ name: string; label: string }[]>([]);
  const [pairingRequired, setPairingRequired] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

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
  const tcpTracker = useMemo(() => new TcpStreamTracker(), []);
  const icmpTracker = useMemo(() => new IcmpEchoTracker(), []);
  const quicTracker = useMemo(() => new QuicFlowTracker(), []);

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
      wsRef.current = new WebSocket("ws://localhost:8999");

      wsRef.current.onopen = () => {
        console.log("[WirePulse] Connected to Local Agent");
        // Hold "Connecting..." for a beat after the handshake succeeds so
        // the button doesn't flash instantly - and so a socket that drops
        // right back off (e.g. a page reload racing the connection) reads
        // as still-connecting rather than a confusing connect/disconnect flicker.
        connectedDelay = setTimeout(() => setAgentStatus("connected"), 2000);

        const storedToken = getStoredPairingToken();
        if (storedToken) {
          wsRef.current?.send(encodeAgentCommand({ type: 'auth', token: storedToken }));
        }
      };

      wsRef.current.onmessage = (event) => {
        const message = parseAgentMessage(event.data);
        if (!message) return;

        if (message.type === 'hello') {
          setAgentVersion(message.version);
          setAgentCaptureState(message.state);
          setAgentInterfaces(message.interfaces);
          setPairingRequired(message.authRequired && !getStoredPairingToken());
          return;
        }

        if (message.type === 'state') {
          setAgentCaptureState(message.state);
          setAgentInterfaces(message.interfaces);
          return;
        }

        if (message.type === 'error') {
          console.warn('[WirePulse] Agent error:', message.message);
          // The only error the agent currently sends is an auth rejection
          // (wrong or stale token - e.g. the agent restarted and generated a
          // new pairing code since this token was stored). Clearing it and
          // re-showing the prompt is what makes Task 12's reconnect
          // walkthrough actually work, instead of the banner just never
          // coming back because a token *was* stored, even though it no
          // longer matches.
          clearStoredPairingToken();
          setPairingRequired(true);
          return;
        }

        // message.type === 'packet' from here on - the existing decode path.
        if (!isCapturingRef.current) return; // agent detected, but capture not started yet

        try {
          // AgentPacketMessage's extra fields are typed `unknown` (it only
          // guarantees `type: 'packet'`) - the decode logic below is
          // unchanged from before this task and still expects the same
          // loosely-typed shape JSON.parse used to hand it directly.
          const rawPkt = message as any;
          const epochMs = typeof rawPkt.timestamp === 'number' ? rawPkt.timestamp : Date.now();

          // Decoding (which mutates tcpTracker/icmpTracker with one-shot,
          // consume-on-match semantics) and id/ref bookkeeping must happen
          // exactly once per real packet - doing this inside the setPackets
          // updater breaks under React StrictMode's double-invocation in
          // development, since a second invocation would find the ICMP
          // tracker's match already consumed and keep that unpatched result.
          const isFirstOfCapture = captureStartRef.current === null;
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
          let icmpMatchedRequestFrameId: number | undefined;
          if (typeof rawPkt.raw === 'string' && rawPkt.raw.length > 0) {
            // Authoritative path: dissect the real captured bytes exactly
            // like an imported pcap file would be dissected.
            const binaryString = atob(rawPkt.raw);
            const bytes = Uint8Array.from(binaryString, (c) => c.charCodeAt(0));
            const decoded = decodeRawEthernetPacket(bytes, id, epochMs, relativeTime, timeDelta, rawPkt.length ?? bytes.length, tcpTracker, icmpTracker, quicTracker);
            safePkt = decoded.packet;
            icmpMatchedRequestFrameId = decoded.icmpMatchedRequestFrameId;
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

          setPackets((prev) => {
            const patchedPrev = icmpMatchedRequestFrameId !== undefined
              ? prev.map((p) => (p.id === icmpMatchedRequestFrameId ? { ...p, info: p.info + ` (reply in ${id})` } : p))
              : prev;
            const updated = [...patchedPrev, safePkt];
            if (updated.length > 4000) {
              return updated.slice(updated.length - 4000);
            }
            return updated;
          });
        } catch (err) {
          console.warn("[WirePulse] Failed to parse agent packet", err);
        }
      };

      wsRef.current.onerror = (error) => {
        console.warn("[WirePulse] WebSocket connection failed. Agent might not be running.");
        if (connectedDelay) clearTimeout(connectedDelay);
        if (isFirstAttempt) setAgentStatus("error");
      };

      wsRef.current.onclose = () => {
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
      if (wsRef.current) {
        wsRef.current.onclose = null; // prevent reconnect loop on intentional unmount/stop
        wsRef.current.close();
      }
      setAgentStatus("disconnected");
    };
  }, [permissions.canCapture, packetGenerator]);

  const sendAgentCommand = (command: AgentCommand) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(encodeAgentCommand(command));
    }
  };

  const agentOutdated = agentVersion !== null && isAgentOutdated(agentVersion, REQUIRED_AGENT_VERSION);

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
    tcpTracker.reset();
    icmpTracker.reset();
    quicTracker.reset();
    // Clearing the buffer is the only way a fresh capture begins, so this is
    // where the relative-time clock resets. captureStartRef === null is then
    // a reliable, side-effect-free "this is the first packet of a capture"
    // test in the live-packet handler.
    captureStartRef.current = null;
    lastPacketTimeRef.current = null;
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

  // Live capture telemetry, surfaced in the Header's buffer status badge
  const totalBytes = useMemo(
    () => packets.reduce((sum, p) => sum + p.length, 0),
    [packets],
  );
  return (
    <div className="h-screen w-screen flex font-sans overflow-hidden transition-colors bg-background text-foreground">
      {/* 1. Main Workstation Body */}
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
          onOpenIspModal={() => setShowIspModal(true)}
          onOpenSettingsModal={() => setShowSettingsModal(true)}
          agentStatus={agentStatus}
          agentOutdated={agentOutdated}
          pairingRequired={pairingRequired}
          onSubmitPairingToken={(token) => {
            storePairingToken(token);
            sendAgentCommand({ type: 'auth', token });
            setPairingRequired(false);
          }}
          totalPacketsCount={packets.length}
          filteredPacketsCount={filteredPackets.length}
          totalBytes={totalBytes}
          onApplyFilterPreset={handleQuickFilter}
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
          packetSearchText={packetSearchText}
          onPacketSearchChange={setPacketSearchText}
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
            <TbList className="w-3.5 h-3.5" />
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
            <TbStack2 className="w-3.5 h-3.5" />
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
            <TbBinary className="w-3.5 h-3.5" />
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
            <TbActivity className="w-3.5 h-3.5" />
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
                searchText={packetSearchText}
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
                />
              </div>
            </div>
          </section>

          {/* Right Analytics Aside (Geometric Balance style) */}
          <aside
            className={`w-80 lg:w-96 border-l border-border p-4 space-y-4 flex-col overflow-y-auto custom-scrollbar shrink-0 transition-colors bg-background hidden lg:flex ${
              mobileTab === "graphs" ? "!flex !w-full !border-l-0" : ""
            }`}
          >
            {/* Geo-IP Map */}
            <div className="h-64 shrink-0 rounded-lg overflow-hidden border border-border">
              <GeoMap packets={packets} isDark={isDark} />
            </div>

            {/* Real-time D3 Throughput & Traffic Spikes */}
            <div>
              <TrafficTimelineChart
                packets={packets}
                isCapturing={isCapturing}
                isDark={isDark}
              />
            </div>

            {/* Protocol Distribution Breakdown */}
            <div>
              <ProtocolDonutChart
                packets={packets}
                onSelectProtocol={handleSelectProtocol}
                selectedProtocolFilter={appliedFilter}
              />
            </div>

            {/* Flow Matrix & Top Talkers */}
            <div>
              <NetworkMatrix
                packets={packets}
                onFilterHost={handleFilterHost}
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
              />
            </div>
          </aside>
        </div>
      </main>

      {/* 4. Modals */}
      {streamToFollow !== null && (
        <StreamFollowerModal
          streamId={streamToFollow}
          packets={packets}
          onClose={() => setStreamToFollow(null)}
        />
      )}

      <AnimatePresence>
        {showDissectorModal && (
          <CustomDissectorModal
            key="dissector-modal"
            dissectorEngine={dissectorEngine}
            onUpdateDissectors={handleUpdateDissectors}
            onClose={() => setShowDissectorModal(false)}
            permissions={permissions}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showStatsModal && (
          <StatisticsModal
            key="stats-modal"
            packets={packets}
            onClose={() => setShowStatsModal(false)}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showExportModal && (
          <ExportImportModal
            key="export-modal"
            packets={packets}
            onImportPackets={handleImportPackets}
            onClose={() => setShowExportModal(false)}
            permissions={permissions}
            isDark={isDark}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showIspModal && (
          <IspStatsModal key="isp-modal" onClose={() => setShowIspModal(false)} />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showSettingsModal && (
          <SettingsModal key="settings-modal" onClose={() => setShowSettingsModal(false)} />
        )}
      </AnimatePresence>
    </div>
  );
}
