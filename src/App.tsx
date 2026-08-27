/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
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
import { parseAgentMessage, encodeAgentCommand, isAgentOutdated, REQUIRED_AGENT_VERSION, type AgentCommand } from "./services/agentProtocol";
import type { AgentLogEntry } from "./services/agentProtocol";
// Loopback is dropped here, at the single point where the agent's list
// enters app state, so every consumer below sees the same adapters.
import { filterCapturableInterfaces } from "./services/captureInterfaces";

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

// Bounded, oldest dropped first. A session left open for hours must not grow
// the log pane without limit.
const AGENT_LOG_BUFFER_LIMIT = 1000;

/**
 * How many captured packets the live buffer holds before the oldest are
 * dropped.
 *
 * Raised from 4,000 once two things stopped scaling with it: packets are now
 * committed to state in batches rather than one at a time, and hex/ASCII
 * dumps are derived on demand instead of stored per packet (which had cost
 * ~13KB of strings for every full-size frame). Both were required - the old
 * ingest path would have frozen the tab well before a buffer this size ever
 * filled.
 */
const PACKET_BUFFER_CAP = 50000;

/**
 * Capture stops on its own at this fraction of the buffer, so a full buffer
 * is a deliberate stop rather than packets silently falling off the back
 * while the user believes they are still recording everything.
 */
const AUTO_PAUSE_AT = 0.99;

/**
 * How often queued packets are committed to React state. Fast enough that
 * the list still reads as live, slow enough that a burst costs a handful of
 * renders rather than one per packet.
 */
const PACKET_FLUSH_MS = 100;

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
  // Set when a connection's socket opened but no `hello` arrived within the
  // grace period below - the only signal available for a pre-Task-4 agent,
  // which never sends `hello` at all (see final review finding #5).
  const [agentIncompatible, setAgentIncompatible] = useState(false);
  const [agentInterfaces, setAgentInterfaces] = useState<{ name: string; label: string }[]>([]);
  const [selectedInterfaces, setSelectedInterfaces] = useState<string[]>([]);
  const [agentLog, setAgentLog] = useState<AgentLogEntry[]>([]);
  // Set when capture stopped itself because the buffer filled, so the reason
  // is visible rather than the capture appearing to have stopped for no
  // reason. Cleared by anything that makes room or deliberately restarts.
  const [bufferAutoPaused, setBufferAutoPaused] = useState(false);
  // Whether the Driver Info panel currently wants log lines. Read inside the
  // WebSocket handlers, so it must be a ref: those close over their first
  // render's values and would otherwise never see this change.
  const logSubscribedRef = useRef(false);
  const wsRef = useRef<WebSocket | null>(null);
  // Packets arrive one WebSocket message at a time but are committed to state
  // in batches - see the ingest comment in the socket handler below.
  const pendingPacketsRef = useRef<Packet[]>([]);
  // ICMP replies patch an EARLIER packet's info text. Collected alongside the
  // new packets so the patch is applied once per flush over one array pass,
  // rather than mapping the whole buffer per reply.
  const pendingIcmpRepliesRef = useRef<{ requestFrameId: number; replyId: number }[]>([]);

  // Drains the ingest queue into state on a fixed cadence. Runs for the life
  // of the app rather than only while capturing, so packets queued in the
  // instant before a stop still land instead of being stranded.
  useEffect(() => {
    const flush = () => {
      const incoming = pendingPacketsRef.current;
      const replies = pendingIcmpRepliesRef.current;
      if (incoming.length === 0 && replies.length === 0) return;
      pendingPacketsRef.current = [];
      pendingIcmpRepliesRef.current = [];

      setPackets((prev) => {
        let next = prev;
        if (replies.length > 0) {
          const replyByFrameId = new Map(replies.map((r) => [r.requestFrameId, r.replyId]));
          next = next.map((p) => {
            const replyId = replyByFrameId.get(p.id);
            return replyId === undefined ? p : { ...p, info: p.info + ` (reply in ${replyId})` };
          });
        }
        next = next === prev ? prev.concat(incoming) : next.concat(incoming);
        if (next.length > PACKET_BUFFER_CAP) {
          next = next.slice(next.length - PACKET_BUFFER_CAP);
        }
        // Stopping is decided here, where the true post-trim size is known.
        // isCapturingRef rather than isCapturing: this effect is set up once
        // and its closure would otherwise never see a later capture start.
        if (isCapturingRef.current && next.length >= PACKET_BUFFER_CAP * AUTO_PAUSE_AT) {
          setIsCapturing(false);
          setBufferAutoPaused(true);
          sendAgentCommand({ type: 'stop_capture' });
        }
        return next;
      });
    };
    const timer = window.setInterval(flush, PACKET_FLUSH_MS);
    return () => window.clearInterval(timer);
  }, []);

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

  // Same reasoning as isCapturingRef: the post-reconnect resync in the
  // `hello` handler below needs the *current* interface selection, not
  // whatever it was when the WebSocket effect's handlers were created.
  const selectedInterfacesRef = useRef(selectedInterfaces);
  useEffect(() => {
    selectedInterfacesRef.current = selectedInterfaces;
  }, [selectedInterfaces]);

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
    // A pre-Task-4 agent never sends `hello` at all, so its absence within
    // this window (started on every fresh socket open, cleared the moment
    // `hello` arrives) is the only way to flag it as incompatible instead of
    // silently showing a normal "Agent Connected" with zero packets ever
    // arriving (final review finding #5).
    let helloTimeout: NodeJS.Timeout | null = null;
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
      // Captured in a local const and closed over by every handler below,
      // rather than re-reading wsRef.current from inside each handler -
      // closes a rapid-reconnect race where a handler could otherwise end up
      // reading a newer socket than the one it was actually attached to.
      const socket = new WebSocket("ws://localhost:8999");
      wsRef.current = socket;

      socket.onopen = () => {
        console.log("[WirePulse] Connected to Local Agent");
        // Hold "Connecting..." for a beat after the handshake succeeds so
        // the button doesn't flash instantly - and so a socket that drops
        // right back off (e.g. a page reload racing the connection) reads
        // as still-connecting rather than a confusing connect/disconnect flicker.
        connectedDelay = setTimeout(() => setAgentStatus("connected"), 2000);

        setAgentIncompatible(false);
        helloTimeout = setTimeout(() => {
          console.warn("[WirePulse] No hello received from agent within 5s - treating it as incompatible.");
          setAgentIncompatible(true);
        }, 5000);
      };

      socket.onmessage = (event) => {
        const message = parseAgentMessage(event.data);
        if (!message) return;

        if (message.type === 'hello') {
          if (helloTimeout) {
            clearTimeout(helloTimeout);
            helloTimeout = null;
          }
          setAgentIncompatible(false);
          setAgentVersion(message.version);
          setAgentCaptureState(message.state);
          setAgentInterfaces(filterCapturableInterfaces(message.interfaces));
          // Deliberately does NOT default to every interface. Capture is
          // single-interface and the user has to name the adapter before a
          // capture can start; pre-selecting all nine would hand Start a
          // ready-made selection and quietly defeat that. An existing
          // selection survives a reconnect untouched.
          setSelectedInterfaces((prev) => (prev.length > 1 ? [prev[0]] : prev));

          // Reconnect resync. A fresh connection always finds the agent idle
          // with every interface selected - it stops capturing when the last
          // client drops - so push our desired state back to it. Phase 1 hung
          // this off the post-auth `state` message; with pairing gone, `hello`
          // is the only per-connection signal there is.
          //
          // On a first-ever connection selectedInterfacesRef is still empty
          // (it gets populated from this very message), so nothing is sent and
          // the agent keeps its own default of every interface. That is correct.
          if (selectedInterfacesRef.current.length > 0) {
            socket.send(encodeAgentCommand({ type: 'set_interfaces', interfaces: selectedInterfacesRef.current }));
          }
          if (isCapturingRef.current) {
            socket.send(encodeAgentCommand({ type: 'start_capture' }));
          }
          // A log subscription lives on the agent's socket, so a reconnect
          // drops it. Resubscribing here, and clearing first, avoids showing
          // a fresh backlog stitched onto the tail of the dead connection's
          // timeline as though it were continuous.
          if (logSubscribedRef.current) {
            setAgentLog([]);
            socket.send(encodeAgentCommand({ type: 'subscribe_logs' }));
          }
          return;
        }

        if (message.type === 'state') {
          setAgentCaptureState(message.state);
          setAgentInterfaces(filterCapturableInterfaces(message.interfaces));
          return;
        }

        if (message.type === 'error') {
          console.warn('[WirePulse] Agent error:', message.message);
          return;
        }

        if (message.type === 'log') {
          setAgentLog((prev) => {
            const next = prev.concat(message.lines);
            return next.length > AGENT_LOG_BUFFER_LIMIT
              ? next.slice(next.length - AGENT_LOG_BUFFER_LIMIT)
              : next;
          });
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
              interfaceName: 'Live Agent'
            };
          }

          // Queued, not committed. Setting state per packet copied the whole
          // buffer on every arrival and re-ran every consumer that reads it -
          // two useMemos here plus eight analytics components - so the cost
          // per packet scaled with the buffer size. At loopback rates that
          // saturated the render loop and froze the tab. The queue is drained
          // on an interval instead, which decouples ingest rate from render
          // cost and is what lets the buffer be large.
          pendingPacketsRef.current.push(safePkt);
          if (icmpMatchedRequestFrameId !== undefined) {
            pendingIcmpRepliesRef.current.push({ requestFrameId: icmpMatchedRequestFrameId, replyId: id });
          }
        } catch (err) {
          console.warn("[WirePulse] Failed to parse agent packet", err);
        }
      };

      socket.onerror = (error) => {
        console.warn("[WirePulse] WebSocket connection failed. Agent might not be running.");
        if (connectedDelay) clearTimeout(connectedDelay);
        if (isFirstAttempt) setAgentStatus("error");
      };

      socket.onclose = () => {
        console.log(
          "[WirePulse] Disconnected from Local Agent. Reconnecting in 3s...",
        );
        if (connectedDelay) clearTimeout(connectedDelay);
        if (helloTimeout) {
          clearTimeout(helloTimeout);
          helloTimeout = null;
        }
        setAgentStatus("disconnected");
        setAgentIncompatible(false);
        isFirstAttempt = false;
        reconnectTimeout = setTimeout(connect, 3000);
      };
    };

    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      if (connectedDelay) clearTimeout(connectedDelay);
      if (helloTimeout) clearTimeout(helloTimeout);
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

  // Memoized with an empty dep array on purpose: DriverInfoPanel subscribes
  // in a mount effect keyed on these identities, so a fresh function each
  // render would drive an unsubscribe/subscribe loop. That is safe only
  // while sendAgentCommand reads nothing but wsRef (a ref) and module-level
  // helpers - if it ever depends on state, these captures go stale.
  const handleSubscribeAgentLog = useCallback(() => {
    logSubscribedRef.current = true;
    setAgentLog([]);
    sendAgentCommand({ type: 'subscribe_logs' });
    // A closed socket is not an error: the hello handler resubscribes on
    // reconnect, so opening the panel while the agent is down and having it
    // fill in when the agent returns is the intended behavior.
  }, []);

  const handleUnsubscribeAgentLog = useCallback(() => {
    logSubscribedRef.current = false;
    sendAgentCommand({ type: 'unsubscribe_logs' });
  }, []);

  const handleClearAgentLog = useCallback(() => setAgentLog([]), []);

  // Reuses the existing "outdated" amber pill for a second, related case: an
  // agent old enough to predate `hello` entirely can't be caught by the
  // version comparison below (agentVersion just stays null forever), so
  // agentIncompatible - set by the hello-grace-period timer above - folds
  // into the same flag rather than needing its own UI treatment.
  const agentOutdated = (agentVersion !== null && isAgentOutdated(agentVersion, REQUIRED_AGENT_VERSION)) || agentIncompatible;

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
        // Mirror the Header start/stop buttons: flip local state and tell the
        // agent, rather than just flipping local state (which used to be
        // enough when the old agent sniffed unconditionally from launch).
        const wasCapturing = isCapturingRef.current;
        // Starting needs an adapter, and a keyboard handler has nowhere to
        // pop a picker. So space resumes on whatever was already chosen and
        // otherwise does nothing - the first capture of a session has to be
        // started from a control that can ask. Stopping is always allowed:
        // being unable to stop a running capture from the keyboard would be
        // a far worse trade than being unable to start one.
        if (!wasCapturing && selectedInterfacesRef.current.length === 0) return;
        const next = permissions.canCapture ? !wasCapturing : false;
        setIsCapturing(next);
        if (next !== wasCapturing) {
          sendAgentCommand(next ? { type: "start_capture" } : { type: "stop_capture" });
        }
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
  //
  // Capture is single-interface: starting always names exactly one adapter,
  // so there is no way to begin capturing without having said where from.
  // set_interfaces is sent before start_capture because the agent restarts
  // its sniffer threads on a selection change - sending it after would spend
  // the first moments of the capture on the previous adapter.
  // Choosing an adapter without starting. A running capture follows the
  // change: the agent restarts its sniffer threads on set_interfaces, so
  // switching adapters mid-capture keeps capturing, just from the new one.
  const handleSelectInterface = (interfaceName: string) => {
    setSelectedInterfaces([interfaceName]);
    sendAgentCommand({ type: 'set_interfaces', interfaces: [interfaceName] });
  };


  // The no-agent path. With no connection there are no adapters to choose
  // from, so the controls start immediately rather than opening a picker
  // that would be empty and leave Start unable to start anything.
  const handleStartCapture = () => {
    setBufferAutoPaused(false);
    sendAgentCommand({ type: 'start_capture' });
    setIsCapturing(true);
  };

  const handlePauseCapture = () => {
    sendAgentCommand({ type: 'stop_capture' });
    setIsCapturing(false);
  };

  const handleClearPackets = () => {
    setBufferAutoPaused(false);
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
          onStartCapture={handleStartCapture}
          onPauseCapture={handlePauseCapture}
          onStopCapture={handlePauseCapture}
          onSendAgentCommand={sendAgentCommand}
          // Was `() => setPackets([])`, which emptied the list but left the
          // packet-number counter and the relative-time clock running, so a
          // cleared buffer kept counting from wherever the last one stopped.
          onClearPackets={handleClearPackets}
          agentInterfaces={agentInterfaces}
          selectedInterfaces={selectedInterfaces}
          onSelectInterface={handleSelectInterface}
          permissions={permissions}
          onOpenDissectorModal={() => setShowDissectorModal(true)}
          onOpenStatsModal={() => setShowStatsModal(true)}
          onOpenExportModal={() => setShowExportModal(true)}
          onOpenIspModal={() => setShowIspModal(true)}
          filterSlot={
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
          }
          onOpenSettingsModal={() => setShowSettingsModal(true)}
          agentStatus={agentStatus}
          agentCaptureState={agentCaptureState}
          agentOutdated={agentOutdated}
          totalPacketsCount={packets.length}
          filteredPacketsCount={filteredPackets.length}
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
          <SettingsModal
            key="settings-modal"
            onClose={() => setShowSettingsModal(false)}
            agentStatus={agentStatus}
            agentVersion={agentVersion}
            agentOutdated={agentOutdated}
            agentCaptureState={agentCaptureState}
            agentInterfaces={agentInterfaces}
            selectedInterfaces={selectedInterfaces}
            agentLog={agentLog}
            onSubscribeAgentLog={handleSubscribeAgentLog}
            onUnsubscribeAgentLog={handleUnsubscribeAgentLog}
            onClearAgentLog={handleClearAgentLog}
            totalPacketsCount={packets.length}
            totalBytes={totalBytes}
            packetBufferCap={PACKET_BUFFER_CAP}
            bufferAutoPaused={bufferAutoPaused}
            onClearPackets={handleClearPackets}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
