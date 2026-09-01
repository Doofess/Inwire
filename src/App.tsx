/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { AnimatePresence } from "motion/react";
import { useTheme } from "next-themes";
import { useMediaQuery } from "./lib/useMediaQuery";
import { useSystemThemePreference } from "./lib/useSystemTheme";
import { useMotionPreference } from "./lib/motion";
import { useNameResolutionPreference } from "./lib/nameResolution";
import { LAYOUT_DEFAULTS, layoutStore, performanceStore } from "./services/interfacePrefs";
import { usePreferenceStore } from "./services/preferenceStore";
import { resetGeoSession } from "./components/analytics/geoSession";
import { DashboardAside } from "./components/analytics/DashboardAside";
import { isDarkTheme } from "./lib/themeOptions";
import { getPacketThemeForApp } from "./services/packetThemes";
import { Packet, UserRole } from "./types/packet";
import { PacketGenerator } from "./services/packetGenerator";
import { decodeRawEthernetPacket } from "./services/pcapParser";
import { TcpStreamTracker } from "./services/tcpStreamTracker";
import { IcmpEchoTracker } from "./services/icmpEchoTracker";
import { QuicFlowTracker } from "./services/quicFlowTracker";
import { FilterEngine } from "./services/filterEngine";
import { filterIncrementally, type FilterCache } from "./services/incrementalFilter";
import {
  appendFrames,
  clearSession,
  countFrames,
  loadSessionMeta,
  readFrames,
  saveSessionMeta,
  trimFramesBelow,
} from "./services/sessionStore";
import { applyIcmpReplies, buildFallbackPacket, restoreBatch } from "./services/sessionRestore";
import {
  answerLivenessPings,
  prepareStoredSession,
  registerSessionWorker,
} from "./services/sessionLifecycle";
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
import { PacketDetailModal } from "./components/packet-details/PacketDetailModal";
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
import {
  FILTER_PRESETS_STORAGE_KEY,
  addPreset,
  loadFilterPresetLibrary,
  normalizeLibrary,
  saveFilterPresetLibrary,
} from "./services/filterPresets";
import {
  clearRetiredPreferences,
  loadPreference,
  useDebouncedPreference,
  usePreferenceSync,
} from "./services/preferences";
import { useThrottledValue } from "./lib/useThrottledValue";
import type { FilterPresetLibrary } from "./types/packet";

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

// Samples kept per interface for the picker's sparklines. At the agent's
// 500ms sampling period this is a 15-second window - long enough to show a
// burst arriving and passing, short enough that it still reads as "now".
const INTERFACE_RATE_SAMPLES = 30;

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
// The default only. The live value is a preference - see interfacePrefs -
// because the cap scales every O(buffer) pass in the app at once.
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

/**
 * How often the analytics aside is handed a new packet buffer.
 *
 * Separate from PACKET_FLUSH_MS on purpose: the packet list has to keep up
 * with ingest, but a protocol breakdown or a top-talkers table does not. See
 * `dashboardPackets` below for the measurements this comes from. Twice a
 * second still reads as live for a summary while cutting their cost fivefold.
 */
const DASHBOARD_REFRESH_MS = 500;
// Kept as the documented default; the live value comes from interfacePrefs.

/**
 * How many stored frames are decoded per chunk when restoring a session.
 *
 * Dissection is the expensive half of a restore - 115us per packet measured -
 * so a full 50,000-packet buffer is about 5.8 seconds of work. Doing it in
 * chunks that each take roughly 30ms, yielding to the browser between them,
 * is what turns that into a list filling in front of the user rather than a
 * locked-up tab.
 */
const RESTORE_CHUNK_SIZE = 250;

/**
 * The rest of what a refresh used to throw away.
 *
 * These are small, change on deliberate user action, and are per-preference
 * keys on the shared localStorage mechanism in services/preferences.ts - the
 * packet buffer is the only part of a session big enough to need IndexedDB.
 * Each validator is module scope so it keeps one identity across renders.
 */
const DISPLAY_FILTER_KEY = "netview.displayFilter";
const PACKET_SEARCH_KEY = "netview.packetSearch";
const SELECTED_PACKET_KEY = "netview.selectedPacketId";
// Preferences this build no longer reads are cleared here rather than left to
// sit in storage looking like live configuration. The list, and the reasoning,
// live in services/preferences.
clearRetiredPreferences();

function normalizeDisplayFilter(raw: unknown): { filterText: string; appliedFilter: string } | null {
  if (typeof raw !== "object" || raw === null) return null;
  const value = raw as Record<string, unknown>;
  return {
    filterText: typeof value.filterText === "string" ? value.filterText : "",
    appliedFilter: typeof value.appliedFilter === "string" ? value.appliedFilter : "",
  };
}

function normalizeString(raw: unknown): string | null {
  return typeof raw === "string" ? raw : null;
}


function normalizePacketId(raw: unknown): number | null {
  return typeof raw === "number" && Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : null;
}

export default function App() {
  // Theme & Layout
  // Bridge to next-themes (the real source of truth) for the components that
  // need a plain isDark boolean for genuine non-Tailwind color decisions
  // (TrafficTimelineChart's d3 code, GeoMap's tile style, ExportImportModal's
  // accent cards) rather than for Tailwind class branching.
  //
  // Answered from the theme registry, not by comparing against the string
  // "light". `resolvedTheme !== "light"` held only while `light` was the sole
  // light theme; with three of them it called the other two dark and drew them
  // with dark map tiles and axes. isDarkTheme also keeps the deliberate
  // dark-during-the-undefined-tick default that avoids a flash to light.
  // Writes data-motion onto <html>, and keeps it in step with the OS while the
  // setting defers to it. See lib/motion.
  useMotionPreference();
  // Pushes the two outbound-lookup switches into the service that performs
  // them, so the gate lives in one place rather than at every call site.
  useNameResolutionPreference();

  const { resolvedTheme } = useTheme();
  // Resolves the "System" picker entry into a concrete theme, and keeps
  // resolving it when the OS setting changes.
  useSystemThemePreference();
  const isDark = isDarkTheme(resolvedTheme);

  // The packet list's colours, derived from the app theme rather than chosen
  // separately. This was a second, independent axis with its own picker and its
  // own stored preference, which meant the default light theme shipped a dark
  // packet list. One theme decision now colours the list, the geo map and the
  // protocol chart alike - see services/themePalettes.
  const packetTheme = useMemo(() => getPacketThemeForApp(resolvedTheme), [resolvedTheme]);
  const [mobileTab, setMobileTab] = useState<
    "packets" | "tree" | "hex" | "graphs" | "alerts"
  >("packets");

  /**
   * Whether the analytics column has room to exist.
   *
   * Matches the `lg:` breakpoint the aside's own className uses, because the
   * two must agree: this decides whether the column is MOUNTED, the className
   * decides how it looks once it is. Read as a media query rather than left to
   * CSS because the difference between "hidden" and "not rendered" is, for
   * these five widgets, a full pass over the packet buffer twice a second.
   */
  const dashboardVisible = useMediaQuery("(min-width: 1024px)");
  /**
   * Whether the icon rail has room, which is a lower bar than the column.
   *
   * The full dashboard needs about 384px and is hidden below `lg`, so on a
   * laptop-width window it vanishes and nothing says it exists. A 48px rail
   * fits from `md`, which turns "minimize" from a way to hide the dashboard
   * into the only way some users will ever see it.
   */
  const railFits = useMediaQuery("(min-width: 768px)");

  // Stream & Capturing State
  const [isCapturing, setIsCapturing] = useState(false);

  // Packets Buffer & Selection
  const [packets, setPackets] = useState<Packet[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  // Stored as an id, not the packet: the object a refresh restores is a fresh
  // one decoded from bytes, so only its number survives the round trip.
  // Zero stands for "nothing selected" and is rejected by the validator.
  useDebouncedPreference(SELECTED_PACKET_KEY, selectedPacket?.id ?? 0);
  const restoreSelectionId = useMemo(
    () => loadPreference(SELECTED_PACKET_KEY, normalizePacketId, null),
    [],
  );
  const selectionRestoredRef = useRef(false);
  const [activeByteRange, setActiveByteRange] = useState<
    [number, number] | null
  >(null);

  // Filter State
  // Seeded from the last session rather than blank, so a refresh does not
  // silently drop the filter the user was looking through.
  const storedDisplayFilter = useMemo(
    () => loadPreference(DISPLAY_FILTER_KEY, normalizeDisplayFilter, { filterText: "", appliedFilter: "" }),
    [],
  );
  const [filterText, setFilterText] = useState(storedDisplayFilter.filterText);
  const [appliedFilter, setAppliedFilter] = useState(storedDisplayFilter.appliedFilter);
  const [packetSearchText, setPacketSearchText] = useState(() =>
    loadPreference(PACKET_SEARCH_KEY, normalizeString, ""),
  );

  useDebouncedPreference(DISPLAY_FILTER_KEY, useMemo(() => ({ filterText, appliedFilter }), [filterText, appliedFilter]));
  useDebouncedPreference(PACKET_SEARCH_KEY, packetSearchText);

  // The display-filter preset library, read once from localStorage and owned
  // here so the header's Presets dropdown and Settings > Display Filters are
  // two views of one value rather than two copies that drift.
  const [filterPresetLibrary, setFilterPresetLibrary] = useState<FilterPresetLibrary>(
    loadFilterPresetLibrary,
  );

  const handleFilterPresetLibraryChange = useCallback((next: FilterPresetLibrary) => {
    setFilterPresetLibrary(next);
    saveFilterPresetLibrary(next);
  }, []);

  // A preset added or reordered in another tab shows up in this one's Presets
  // dropdown without a reload. The `storage` event never fires in the tab that
  // wrote, so this cannot echo back on itself.
  usePreferenceSync(FILTER_PRESETS_STORAGE_KEY, normalizeLibrary, setFilterPresetLibrary);

  /**
   * The filter bar's bookmark button. Lands in the last group - the one the
   * defaults call "Custom" - because a quick save should not stop to ask
   * where; the Settings panel is where it gets filed properly.
   */
  const handleSaveCurrentFilter = useCallback(
    (filter: string) => {
      // Computed from the current library rather than inside a state updater.
      // React reserves the right to run an updater more than once - StrictMode
      // does it on every call in development - so persisting from inside one
      // wrote twice per saved filter and burned a preset id each time. An
      // updater has to be pure; the write belongs out here.
      const groups = filterPresetLibrary.groups;
      const lastGroupId = groups[groups.length - 1]?.id ?? "";
      handleFilterPresetLibraryChange(
        addPreset(filterPresetLibrary, lastGroupId, {
          name: filter.length > 32 ? `${filter.slice(0, 32)}...` : filter,
          filter,
          description: "Saved from the filter bar",
        }),
      );
    },
    [filterPresetLibrary, handleFilterPresetLibraryChange],
  );

  // Modals
  const [streamToFollow, setStreamToFollow] = useState<number | null>(null);
  // The frame the detail window is showing, or null when it is closed. Held as
  // a number rather than a Packet so the window keeps following the same frame
  // as the buffer around it changes.
  const [detailPacketId, setDetailPacketId] = useState<number | null>(null);
  const [showDissectorModal, setShowDissectorModal] = useState(false);
  const [showStatsModal, setShowStatsModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showIspModal, setShowIspModal] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [agentStatus, setAgentStatus] = useState<
    "disconnected" | "connecting" | "connected" | "error"
  >("disconnected");
  const [agentCaptureState, setAgentCaptureState] = useState<'idle' | 'sniffing'>('idle');
  /**
   * Whether the app should be holding a link to the agent at all.
   *
   * Distinct from agentStatus, which reports what the socket is actually
   * doing: "disconnected" covers both "you pressed Disconnect" and "the agent
   * is not running", and Driver Info has to tell those apart to say anything
   * useful. This is the intent; agentStatus is the outcome.
   *
   * Not persisted, on purpose. A reload reconnects - an app that comes back
   * permanently dead with no visible cause reads as broken, and everything
   * else about a reload here is built to look like continuity.
   */
  const [agentLinkEnabled, setAgentLinkEnabled] = useState(true);
  const [agentVersion, setAgentVersion] = useState<string | null>(null);
  // Set when a connection's socket opened but no `hello` arrived within the
  // grace period below - the only signal available for a pre-Task-4 agent,
  // which never sends `hello` at all (see final review finding #5).
  const [agentIncompatible, setAgentIncompatible] = useState(false);
  const [agentInterfaces, setAgentInterfaces] = useState<{ name: string; label: string }[]>([]);
  const [selectedInterfaces, setSelectedInterfaces] = useState<string[]>([]);
  const [agentLog, setAgentLog] = useState<AgentLogEntry[]>([]);
  /**
   * The agent's most recent rejection, surfaced in Driver Info.
   *
   * Agent errors only reached console.warn before, which was tolerable while
   * the sole one was an empty interface list the picker already prevented. A
   * refused Restart has no other visible outcome at all - the button would
   * simply appear to do nothing - so the reason has to reach the panel.
   */
  const [agentError, setAgentError] = useState<string | null>(null);
  // Recent packets/sec per interface, oldest first, for the picker's
  // sparklines. Only populated while the picker is open - the agent samples
  // nothing otherwise.
  const [interfaceRates, setInterfaceRates] = useState<Record<string, number[]>>({});
  // Set when capture stopped itself because the buffer filled, so the reason
  // is visible rather than the capture appearing to have stopped for no
  // reason. Cleared by anything that makes room or deliberately restarts.
  const [bufferAutoPaused, setBufferAutoPaused] = useState(false);
  // How far a session restore has got, or null when none is running. Drives
  // the header's progress readout; also the flag the UI uses to explain why
  // packets are appearing without a capture being started.
  const [restoreProgress, setRestoreProgress] = useState<{ done: number; total: number } | null>(null);

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
  /**
   * True while a stored session is being decoded back into the buffer. Read by
   * the effects that must not write a half-restored session back to disk.
   */
  const restoringRef = useRef(false);
  /** Whether the one restore this page load gets has been kicked off yet. */
  const restoreStartedRef = useRef(false);
  /** The highest packet id already written to disk, so a flush only appends. */
  const persistedThroughIdRef = useRef(0);

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

      // Persisted here rather than inside the updater below, because a state
      // updater has to be pure - React may run it more than once, and in
      // development StrictMode always does, which would write every batch to
      // disk twice. Not awaited: the write is fire-and-forget so the flush
      // cadence never waits on IndexedDB.
      if (incoming.length > 0) {
        const newest = incoming[incoming.length - 1].id;
        if (newest > persistedThroughIdRef.current) {
          persistedThroughIdRef.current = newest;
          appendFrames(incoming);
        }
      }

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
        const cap = packetBufferCapRef.current;
        if (next.length > cap) {
          next = next.slice(next.length - cap);
          // The stored session mirrors the live buffer, including its
          // forgetting: without this the database would keep every frame of a
          // multi-hour capture while the buffer held only the last 50,000.
          trimFramesBelow(next[0].id);
        }
        // Stopping is decided here, where the true post-trim size is known.
        // isCapturingRef rather than isCapturing: this effect is set up once
        // and its closure would otherwise never see a later capture start.
        if (isCapturingRef.current && next.length >= cap * AUTO_PAUSE_AT) {
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

  /**
   * Stored frames live exactly as long as the app is open.
   *
   * The service worker deletes the database a few seconds after the last window
   * closes; answering liveness pings is what stops a second window from being
   * mistaken for a new run and wiping a capture the first one is still showing.
   * Quitting the browser kills the worker mid-wait, and `prepareStoredSession`
   * in the restore effect below catches that case on the next launch.
   */
  useEffect(() => {
    const stopWorker = registerSessionWorker();
    const stopAnswering = answerLivenessPings();
    return () => {
      stopWorker();
      stopAnswering();
    };
  }, []);

  /**
   * The last time the user asked for a reload with the keyboard.
   *
   * `beforeunload` cannot tell a refresh from a close - the event is identical
   * for both, and the platform exposes nothing that distinguishes them, which
   * is the same limitation the cleanup service worker is built around. What CAN
   * be observed is the gesture: F5 and Ctrl/Cmd+R arrive as a keydown a moment
   * before the navigation starts, so a reload asked for that way can be
   * recognised in advance and left unprompted.
   *
   * The browser's own reload button is not detectable by any means, so it still
   * prompts. That is a partial fix rather than a complete one, and worth
   * knowing: the keyboard covers the common case, the toolbar does not.
   *
   * A timestamp rather than a boolean so the intent expires. If a keystroke
   * ever fails to produce a navigation, a boolean would leave the warning
   * disabled for the rest of the session.
   */
  const reloadIntentAt = useRef(0);
  useEffect(() => {
    const noteReloadIntent = (event: KeyboardEvent) => {
      const isReload =
        event.key === 'F5' ||
        ((event.ctrlKey || event.metaKey) && (event.key === 'r' || event.key === 'R'));
      if (isReload) reloadIntentAt.current = Date.now();
    };
    // Capture phase: an input with its own Ctrl+R handling must not be able to
    // swallow this before it is seen.
    window.addEventListener('keydown', noteReloadIntent, true);
    return () => window.removeEventListener('keydown', noteReloadIntent, true);
  }, []);

  /** How long a reload keystroke suppresses the warning for. */
  const RELOAD_INTENT_WINDOW_MS = 2000;

  /**
   * Warns before leaving while a capture is held, and stays silent otherwise.
   *
   * This is the counterpart to the cleanup above: closing the app deletes the
   * stored session, so leaving with packets in the buffer really does throw
   * them away. An empty buffer has nothing to lose, so prompting then would be
   * pure friction - which is why this is gated rather than always on.
   *
   * A REFRESH does not throw anything away: frames are written to IndexedDB as
   * they arrive, the service worker holds the store open across the gap, and
   * the startup guard restores the buffer on the way back in - which is what
   * the "Restoring n/m" pill in the header is reporting. So a recognised reload
   * gesture skips the prompt entirely; there is nothing to warn about.
   *
   * Keyed on the boolean, not on packets.length. The buffer changes on every
   * flush during capture, and depending on the count would tear down and
   * re-add this listener several times a second; the boolean only flips when
   * the buffer goes empty or stops being empty.
   *
   * The browser decides the wording - a page cannot supply its own text any
   * more - so the only choice available here is whether to ask at all.
   */
  const hasCapturedPackets = packets.length > 0;
  useEffect(() => {
    if (!hasCapturedPackets) return;
    const warnBeforeLeaving = (event: BeforeUnloadEvent) => {
      // A refresh the user just asked for. The session survives it, so asking
      // them to confirm is a prompt about nothing.
      if (Date.now() - reloadIntentAt.current < RELOAD_INTENT_WINDOW_MS) return;
      event.preventDefault();
      // Still required by older browsers, which show the prompt only when
      // returnValue has been assigned.
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warnBeforeLeaving);
    return () => window.removeEventListener("beforeunload", warnBeforeLeaving);
  }, [hasCapturedPackets]);

  /**
   * Rebuilds the previous session's buffer on load, so a refresh is not a
   * reset.
   *
   * Runs once, before anything is captured. That ordering is what keeps it
   * simple: the agent starts idle and this app only tells it to capture at the
   * end of this effect, and the live-packet handler drops anything that
   * arrives while `isCapturing` is false - so restored packets can never
   * interleave with new ones or collide over packet numbers.
   *
   * Decoded in chunks with a yield between them. A full 50,000-packet buffer
   * is about 5.8 seconds of dissection; spending it in ~30ms slices means the
   * app is usable immediately and the list visibly fills rather than the tab
   * freezing for six seconds on every reload.
   */
  useEffect(() => {
    // Runs exactly once per page load. Two things have to be true at the same
    // time and they pull against each other, so both are spelled out:
    //
    //   - StrictMode mounts every effect twice in development, so without a
    //     guard the second pass would replay the whole session on top of the
    //     first one's result and double the buffer.
    //   - There is deliberately NO cleanup cancelling the work in flight.
    //     StrictMode runs that cleanup *between* the two mount passes, so a
    //     `cancelled` flag would abort the only restore that the guard above
    //     then permits - which is exactly what happened here: the progress
    //     readout sat at 0/42,067 forever while the UI stayed perfectly
    //     responsive, because the loop had been cancelled before its first
    //     batch and the retry was refused. GeoMap's connection sync was killed
    //     by the same pairing once already.
    //
    // Letting the loop finish after a real unmount is harmless: it appends to
    // the state of a tree that is gone, which React ignores, and it terminates
    // on its own when the frames run out.
    if (restoreStartedRef.current) return;
    restoreStartedRef.current = true;
    restoringRef.current = true;

    (async () => {
      // Before a single frame is read: a session left behind by a closed run of
      // the app is deleted here rather than restored onto the screen. Awaited so
      // the reads below cannot race the wipe and resurrect part of it.
      await prepareStoredSession();

      const meta = await loadSessionMeta();
      const total = await countFrames();

      if (total > 0) {
        setRestoreProgress({ done: 0, total });
        const trackers = { tcpTracker, icmpTracker, quicTracker };
        // Rebuilt from the session's own interface table, so restored frames
        // name the adapter they were captured on rather than reporting
        // themselves as an imported capture.
        const interfaceIdByLabel = new Map(
          (meta?.interfaces ?? []).map((iface) => [iface.label, iface.name]),
        );
        let done = 0;
        let lastId = 0;

        await readFrames(RESTORE_CHUNK_SIZE, async (frames) => {
          // Same trackers across every chunk, in id order - see restoreBatch.
          const { packets: batch, icmpReplies } = restoreBatch(frames, trackers, interfaceIdByLabel);
          lastId = frames[frames.length - 1].id;
          done += frames.length;

          setPackets((prev) => {
            const merged = applyIcmpReplies(prev, icmpReplies).concat(batch);
            const cap = packetBufferCapRef.current;
            return merged.length > cap ? merged.slice(merged.length - cap) : merged;
          });
          setRestoreProgress({ done, total });
          // Yield so React can commit and the browser can paint this chunk.
          await new Promise((resolve) => setTimeout(resolve, 0));
        });

        // Numbering continues from the restored session rather than restarting
        // at 1 and colliding with packets already in the list.
        packetGenerator.resumeAfter(lastId);
        persistedThroughIdRef.current = lastId;
        // The relative-time clock is restored too, so a resumed capture's
        // timestamps continue the original timeline instead of jumping to 0.
        captureStartRef.current = meta?.captureStartMs ?? null;
        lastPacketTimeRef.current = meta?.lastPacketMs ?? null;
      }

      setRestoreProgress(null);
      restoringRef.current = false;

      if (meta?.selectedInterfaces.length) {
        setSelectedInterfaces(meta.selectedInterfaces);
        // The adapter is pushed to the agent even though capture stays paused.
        // Without it the agent would still be on its own default of every
        // interface, and the next Start would capture from the wrong one - the
        // selection would look restored in the UI while meaning nothing. The
        // `hello` reconnect resync sends the same thing, but only if it lands
        // after this point, so this closes that race rather than relying on it.
        sendAgentCommand({ type: 'set_interfaces', interfaces: meta.selectedInterfaces });
      }

      // Capture is not resumed, and nothing is said about it: a reload leaves
      // the app exactly as pressing Pause would - buffer intact, adapter and
      // filters intact, capture stopped. That is also what has already happened
      // underneath, since the agent stops sniffing the moment its last client
      // disconnects, so `isCapturing` starting false is simply the truth.
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Drives the session-metadata write below at a sane rate. Two seconds is far
  // more often than the values it guards actually change, and still cheap.
  const persistedPacketTick = useThrottledValue(packets.length, 2000);

  /**
   * Keeps the stored session's non-frame half current.
   *
   * The time refs are read at write time rather than being dependencies: they
   * are refs precisely because they change per packet and must not re-run
   * effects. `persistedPacketTick` exists only to make this run again as those
   * refs drift - and it is throttled hard, because packet count changes ten
   * times a second and the relative-time origin it is standing in for changes
   * once per capture.
   */
  useEffect(() => {
    if (restoringRef.current) return;
    void saveSessionMeta({
      selectedInterfaces,
      interfaces: agentInterfaces,
      captureStartMs: captureStartRef.current,
      lastPacketMs: lastPacketTimeRef.current,
      updatedAt: Date.now(),
    });
  }, [selectedInterfaces, agentInterfaces, isCapturing, persistedPacketTick]);

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
  //
  // Sizes, visibility and arrangement share one preference, because
  // `arrangement` changes what `detailsPaneRatio` means - a fraction of width
  // side by side, a fraction of height stacked. See services/interfacePrefs.
  // Named `perf`, not `performance`: the latter shadows the global timing API,
  // which is exactly the sort of shadowing that is fine until somebody adds a
  // `performance.now()` in this scope and gets a confusing type error.
  const [perf] = usePreferenceStore(performanceStore);
  usePreferenceSync(performanceStore.key, performanceStore.normalize, performanceStore.accept);
  const { packetBufferCap, dashboardRefreshMs } = perf;
  /**
   * The cap, for the ingest handler.
   *
   * That handler is registered once and its closure never sees a later render,
   * which is the same reason `isCapturingRef` exists beside it. Reading the cap
   * from state there would pin it at whatever it was when the socket opened.
   */
  const packetBufferCapRef = useRef(packetBufferCap);
  useEffect(() => {
    packetBufferCapRef.current = packetBufferCap;
  }, [packetBufferCap]);

  const [layout, patchLayout] = usePreferenceStore(layoutStore);
  const { bottomPaneHeight, detailsPaneRatio, panes: showPanes, arrangement } = layout;
  const stacked = arrangement === "stacked";
  usePreferenceSync(layoutStore.key, layoutStore.normalize, layoutStore.accept);

  const isDraggingRef = useRef(false);
  const isDraggingColumnRef = useRef(false);
  const bottomPaneRef = useRef<HTMLDivElement>(null);

  /**
   * The live size during a drag, before it is committed.
   *
   * A divider drag fires on every pointer move - 60 to 120 times a second - and
   * routing each one through state re-rendered the entire app, packet list
   * included, at that rate while the user was doing nothing but sliding a bar.
   *
   * The layout is already driven by two CSS custom properties, so a drag can
   * write those directly and skip React entirely; the value is committed to
   * state and to storage once, on release. Nothing renders differently, because
   * the properties are the same ones the committed values write.
   */
  const dragRef = useRef({ bottomPaneHeight, detailsPaneRatio });
  useEffect(() => {
    dragRef.current = { bottomPaneHeight, detailsPaneRatio };
  }, [bottomPaneHeight, detailsPaneRatio]);

  const applyLayoutVars = useCallback(() => {
    const el = bottomPaneRef.current;
    if (!el) return;
    el.style.setProperty("--bottom-pane-height", `${dragRef.current.bottomPaneHeight}px`);
    el.style.setProperty("--details-pane-size", `${dragRef.current.detailsPaneRatio * 100}%`);
  }, []);

  /** A floor that only stops either side being dragged to nothing. */
  const MIN_PANE_PX = 220;

  const resizeSplit = useCallback((clientX: number, clientY: number) => {
    const el = bottomPaneRef.current;
    if (!el) return;
    // Measured off the pane itself, not the window, so the ratio stays correct
    // no matter what sits to either side of it.
    const rect = el.getBoundingClientRect();
    const extent = stacked ? rect.height : rect.width;
    const offset = stacked ? clientY - rect.top : clientX - rect.left;
    if (extent < MIN_PANE_PX * 2) return;
    const minRatio = MIN_PANE_PX / extent;
    dragRef.current.detailsPaneRatio = Math.max(
      minRatio,
      Math.min(offset / extent, 1 - minRatio),
    );
    applyLayoutVars();
  }, [applyLayoutVars, stacked]);

  useEffect(() => {
    const handlePointerMove = (e: PointerEvent) => {
      if (isDraggingRef.current) {
        // No footer offset. There used to be one - a hardcoded 28px for a
        // footer element that does not exist anywhere in the tree - which put
        // every vertical drag 28px away from the pointer.
        const next = window.innerHeight - e.clientY;
        dragRef.current.bottomPaneHeight = Math.max(
          100,
          Math.min(next, window.innerHeight - 200),
        );
        applyLayoutVars();
        return;
      }
      if (isDraggingColumnRef.current) resizeSplit(e.clientX, e.clientY);
    };

    const endDrag = () => {
      if (!isDraggingRef.current && !isDraggingColumnRef.current) return;
      isDraggingRef.current = false;
      isDraggingColumnRef.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      // The one commit for the whole gesture.
      patchLayout({ ...dragRef.current });
    };

    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", endDrag);
    // A drag that ends outside the window - or is taken over by the browser -
    // used to leave the body stuck with `user-select: none` and a resize
    // cursor, because only mouseup ever cleaned up.
    window.addEventListener("pointercancel", endDrag);
    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerup", endDrag);
      window.removeEventListener("pointercancel", endDrag);
    };
  }, [applyLayoutVars, patchLayout, resizeSplit]);

  const beginDrag = useCallback((which: "height" | "split") => {
    if (which === "height") isDraggingRef.current = true;
    else isDraggingColumnRef.current = true;
    document.body.style.cursor = which === "height" ? "row-resize" : "col-resize";
    // Otherwise the drag selects packet rows as it passes over them.
    document.body.style.userSelect = "none";
  }, []);

  /**
   * The dividers, from the keyboard.
   *
   * They were `onMouseDown` handlers on bare divs: no role, no tab stop, and
   * nothing a keyboard or a pen could reach. A separator that can only be moved
   * by dragging a 6px target with a mouse is not a control everyone has.
   */
  const nudgeHeight = useCallback((deltaPx: number) => {
    patchLayout({
      bottomPaneHeight: Math.max(
        100,
        Math.min(bottomPaneHeight + deltaPx, window.innerHeight - 200),
      ),
    });
  }, [bottomPaneHeight, patchLayout]);

  const nudgeSplit = useCallback((delta: number) => {
    patchLayout({
      detailsPaneRatio: Math.max(0.1, Math.min(detailsPaneRatio + delta, 0.9)),
    });
  }, [detailsPaneRatio, patchLayout]);

  // Engines
  const dissectorEngine = useMemo(() => new CustomDissectorEngine(), []);
  const colorEngine = useMemo(() => new ColorRulesEngine(), []);
  const packetGenerator = useMemo(
    () => new PacketGenerator(dissectorEngine),
    [dissectorEngine],
  );
  /**
   * The colour of the row the selected packet was picked from.
   *
   * The two detail panes below the list, and the detail window, all label a
   * frame they did not draw. Labelling it in the app accent said the same thing
   * for every frame; labelling it in the frame's own colour ties the header to
   * the row the eye just left.
   */
  const selectedPacketAccent = useMemo(
    () => (selectedPacket ? colorEngine.getPacketAccent(selectedPacket, packetTheme) : null),
    [selectedPacket, colorEngine, packetTheme],
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

  // Same reasoning, for the Space shortcut: its handler is registered once and
  // needs to know whether there is a buffer that starting would discard. A ref
  // rather than a dependency, because re-registering a window listener on
  // every packet flush is ten new listeners a second during capture.
  const packetCountRef = useRef(0);
  useEffect(() => {
    packetCountRef.current = packets.length;
  }, [packets.length]);

  /**
   * Drops a selected adapter the agent does not offer.
   *
   * An effect on the interface list rather than a line inside the `hello`
   * handler, because a selection restored from a previous session can be set
   * either before or after that message arrives - and a name that was valid
   * yesterday can belong to an adapter that has since been unplugged or
   * renamed. Keyed on the list, this is correct in both orderings and is a
   * no-op when nothing is stale.
   */
  useEffect(() => {
    if (agentInterfaces.length === 0) return;
    setSelectedInterfaces((prev) => {
      const valid = prev.filter((name) => agentInterfaces.some((iface) => iface.name === name));
      return valid.length === prev.length ? prev : valid;
    });
  }, [agentInterfaces]);

  // Same reasoning as isCapturingRef: the post-reconnect resync in the
  // `hello` handler below needs the *current* interface selection, not
  // whatever it was when the WebSocket effect's handlers were created.
  const selectedInterfacesRef = useRef(selectedInterfaces);
  useEffect(() => {
    selectedInterfacesRef.current = selectedInterfaces;
  }, [selectedInterfaces]);

  // The adapter a live frame arrived on, named for the Frame layer's Interface
  // id / name / description rows. A ref for the same reason as above: the
  // decode happens inside the WebSocket message handler. Left undefined while
  // nothing is selected, so the dissector falls back to its imported-file
  // wording rather than naming an interface that was never captured on.
  const captureInterfaceRef = useRef<{ name: string; label: string } | undefined>(undefined);
  useEffect(() => {
    captureInterfaceRef.current = agentInterfaces.find(
      (iface) => iface.name === selectedInterfaces[0],
    );
  }, [agentInterfaces, selectedInterfaces]);

  // Live-capture relative-time clock (reference-analyzer style): resets whenever the
  // packet buffer is emptied and a fresh capture begins.
  const captureStartRef = useRef<number | null>(null);
  const lastPacketTimeRef = useRef<number | null>(null);

  // Local Agent Connection - always tries to reach ws://localhost:8999 so
  // the "Download Driver" button can auto-detect the agent running and
  // flip to "Agent Connected", independent of whether capture is active.
  // Packets are only recorded into the buffer while isCapturing is true.
  useEffect(() => {
    if (!permissions.canCapture) return;
    // Driver Info's Disconnect. Bailing out here rather than tearing the
    // socket down somewhere else is the point: React runs this effect's
    // existing cleanup on the way in, and that cleanup already does exactly
    // what disconnecting means - it nulls `onclose` so the 3s retry cannot
    // re-arm, closes the socket, and reports "disconnected". A second
    // teardown path would be a second thing to keep correct.
    if (!agentLinkEnabled) return;

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
          setAgentError(null);
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
          setAgentError(message.message);
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

        if (message.type === 'interface_stats') {
          setInterfaceRates((prev) => {
            const next: Record<string, number[]> = {};
            for (const rate of message.interfaces) {
              const series = prev[rate.name] ?? [];
              // A fixed-length window, so the sparkline scrolls rather than
              // compressing an ever-longer history into the same 68px.
              next[rate.name] = series.concat(rate.packetsPerSec).slice(-INTERFACE_RATE_SAMPLES);
            }
            return next;
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
            const decoded = decodeRawEthernetPacket(bytes, id, epochMs, relativeTime, timeDelta, rawPkt.length ?? bytes.length, tcpTracker, icmpTracker, quicTracker, captureInterfaceRef.current);
            safePkt = decoded.packet;
            icmpMatchedRequestFrameId = decoded.icmpMatchedRequestFrameId;
          } else {
            // Fallback only: the agent did not send raw bytes. Shared with the
            // session restore path so a metadata-only packet looks the same
            // whether it just arrived or came back off disk - byte data left
            // genuinely empty rather than fabricated.
            safePkt = buildFallbackPacket({
              id,
              timestamp: epochMs,
              relativeTime,
              timeDelta,
              length: rawPkt.length || 0,
              source: rawPkt.source,
              destination: rawPkt.destination,
              sourcePort: rawPkt.sourcePort,
              destPort: rawPkt.destPort,
              protocol: rawPkt.protocol,
              info: rawPkt.info,
            });
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
  }, [permissions.canCapture, packetGenerator, agentLinkEnabled]);

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

  /**
   * Driver Info's Connect / Disconnect.
   *
   * Both only set intent - the WebSocket effect above owns the socket, and
   * flipping this flag is what makes it run its cleanup or reconnect. Nothing
   * is sent to the agent on disconnect and nothing needs to be: the agent
   * stops its sniffer when the last client goes away (handle_disconnect in
   * agent.py), so closing the socket genuinely stops the capture rather than
   * just hiding it from this tab.
   *
   * Memoized like the log handlers above, because DriverInfoPanel keys effects
   * on these identities.
   */
  const handleDisconnectAgent = useCallback(() => setAgentLinkEnabled(false), []);
  const handleConnectAgent = useCallback(() => setAgentLinkEnabled(true), []);

  /**
   * Driver Info's Restart Agent.
   *
   * Fire and forget by design. The agent acks by dying, so there is no reply
   * to wait for - the socket drops, the existing 3s reconnect loop starts
   * retrying, and the agent comes back under it. If the agent refuses (it is
   * not running as the service, or no restart policy is in place) it answers
   * with an `error` message instead and the log pane shows why.
   */
  const handleRestartAgent = useCallback(() => {
    sendAgentCommand({ type: 'restart_agent' });
  }, []);

  const handleClearAgentLog = useCallback(() => setAgentLog([]), []);

  // Driven by the picker opening and closing. Sampling adapter counters is
  // cheap but not free, and nothing should be measured on the user's machine
  // while the menu that displays it is shut.
  const handleInterfacePickerOpenChange = useCallback((open: boolean) => {
    if (open) {
      // Cleared on open so a reopened menu draws from now rather than
      // stitching a fresh series onto samples from minutes ago as if the
      // intervening time had been idle.
      setInterfaceRates({});
      sendAgentCommand({ type: 'subscribe_interface_stats' });
    } else {
      sendAgentCommand({ type: 'unsubscribe_interface_stats' });
    }
  }, []);

  // Reuses the existing "outdated" amber pill for a second, related case: an
  // agent old enough to predate `hello` entirely can't be caught by the
  // version comparison below (agentVersion just stays null forever), so
  // agentIncompatible - set by the hello-grace-period timer above - folds
  // into the same flag rather than needing its own UI treatment.
  const agentOutdated = (agentVersion !== null && isAgentOutdated(agentVersion, REQUIRED_AGENT_VERSION)) || agentIncompatible;

  /**
   * The last display-filter result, so a growing buffer only filters what is
   * new. Held in a ref rather than state because it is a memo of the render
   * below, not a value anything renders from directly.
   */
  const filterCacheRef = useRef<FilterCache | null>(null);

  // Display Filter Evaluation. The incremental part - and why it is worth
  // having - lives in services/incrementalFilter.ts.
  const filteredPackets = useMemo(() => {
    const { result, cache } = filterIncrementally(packets, appliedFilter, filterCacheRef.current);
    // Writing a ref during render is only safe because this is idempotent: a
    // StrictMode double-invoke re-enters with cache.source === packets, finds
    // the prefix intact with nothing appended, and returns the very same array.
    // Keep that property if either side of this is ever changed.
    filterCacheRef.current = cache;
    return result;
  }, [packets, appliedFilter]);

  /**
   * The packet buffer as the summary panels see it: the same array, but
   * changing at most twice a second instead of ten times.
   *
   * Every panel in the analytics aside does at least one full pass over the
   * buffer when this identity changes. Measured together at a 21,903-packet
   * buffer they cost 16.6ms per flush - 166ms of every second, and about
   * 380ms/s at the 50,000 cap - to redraw summaries that no one can read at
   * 10Hz. Throttling the input is what makes that proportional to how fast the
   * information is actually consumed rather than to how fast packets arrive.
   *
   * Deliberately NOT used for the packet list (it is the live view), the header
   * counters (`.length` is O(1)), or the export and stream-follower modals,
   * which reconstruct exact data and must never see a stale snapshot.
   */
  // The analytics panels' feed.
  //
  // `dashboardRefreshMs` of 0 means paused: the panels keep the last buffer
  // they were given, so every memo keyed on it stops recomputing. That is the
  // whole cost of the dashboard, and pausing removes it without removing the
  // panels. The throttle still runs underneath at a slow rate rather than
  // being torn down, so resuming publishes immediately instead of waiting out
  // a fresh interval.
  const throttledDashboardPackets = useThrottledValue(
    packets,
    dashboardRefreshMs === 0 ? 2000 : dashboardRefreshMs,
  );
  const latestThrottledRef = useRef(throttledDashboardPackets);
  latestThrottledRef.current = throttledDashboardPackets;
  const [pausedDashboard, setPausedDashboard] = useState<Packet[] | null>(null);
  useEffect(() => {
    // Snapshot on the transition into paused, and drop it on the way out.
    setPausedDashboard(dashboardRefreshMs === 0 ? latestThrottledRef.current : null);
  }, [dashboardRefreshMs]);
  const dashboardPackets = pausedDashboard ?? throttledDashboardPackets;

  /**
   * Re-selects the packet that was selected before the refresh.
   *
   * Waits for the restore to finish rather than running on the first chunk,
   * because the wanted packet may be anywhere in the buffer. Runs at most
   * once - after that the user's own clicks own the selection.
   */
  useEffect(() => {
    if (selectionRestoredRef.current || restoreSelectionId === null) return;
    if (restoreProgress !== null || packets.length === 0) return;
    selectionRestoredRef.current = true;
    const hit = packets.find((p) => p.id === restoreSelectionId);
    if (hit) setSelectedPacket(hit);
  }, [restoreProgress, packets, restoreSelectionId]);

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
    // The packet detail window owns the keyboard while it is open: its own
    // arrows step frames, and Space must not reach the capture toggle
    // underneath it and start or stop a live capture nobody asked to change.
    if (detailPacketId !== null) return;

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
        // Nor does it start one that would DISCARD a buffer. A stopped capture
        // cannot be resumed, so starting again clears what is there - and that
        // is a question, asked by the header button's prompt. A keyboard
        // shortcut has nowhere to ask it and must not answer it silently:
        // Space would otherwise be one keystroke, with no undo, between a
        // finished capture and an empty list. Stopping stays unconditional.
        if (!wasCapturing && packetCountRef.current > 0) return;
        const next = permissions.canCapture ? !wasCapturing : false;
        setIsCapturing(next);
        if (next !== wasCapturing) {
          sendAgentCommand(next ? { type: "start_capture" } : { type: "stop_capture" });
        }
        return;
      }

      // Arrow keys only: the packet list handles its own, and handles them
      // better - it moves by index into the sorted buffer (so it can reach a
      // row the virtualizer has not rendered), scrolls the new row into view,
      // and decides whether to keep following the live tail. Without this
      // guard both handlers run and every press moves the selection two rows.
      //
      // Scoped to the arrows rather than bailing outright, because Space must
      // still start and stop capture while the list has focus - which is where
      // focus usually is.
      const insidePacketList =
        e.target instanceof Element && e.target.closest('[role="grid"]') !== null;

      if (e.code === "ArrowDown") {
        if (insidePacketList) return;
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
        if (insidePacketList) return;
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
  }, [selectedPacket, filteredPackets, permissions.canCapture, detailPacketId]);

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
    // The geo map's session describes traffic that is about to stop existing.
    // This is the one case where its deliberately monotonic place count should
    // go back to zero.
    resetGeoSession();
    tcpTracker.reset();
    icmpTracker.reset();
    quicTracker.reset();
    // Clearing the buffer is the only way a fresh capture begins, so this is
    // where the relative-time clock resets. captureStartRef === null is then
    // a reliable, side-effect-free "this is the first packet of a capture"
    // test in the live-packet handler.
    captureStartRef.current = null;
    lastPacketTimeRef.current = null;
    persistedThroughIdRef.current = 0;
    // Clearing the buffer clears what a refresh would restore. Anything else
    // would resurrect the packets the user just asked to be rid of.
    void clearSession();
    setPackets([]);
    setSelectedPacket(null);
    setActiveByteRange(null);
  };

  // The dashboard's callbacks are memoized, and the three below are the ones
  // that matter: they are handed to the analytics widgets, which is the part of
  // the tree about to sit behind a memo boundary. A handler rebuilt on every
  // render defeats that boundary entirely - and this component re-renders about
  // ten times a second while capturing, so the boundary is the whole point.
  //
  // Every setter used here is a `useState` setter, whose identity React
  // guarantees is stable, so the empty dependency list is correct rather than
  // merely convenient.
  const handleQuickFilter = useCallback((expression: string) => {
    setFilterText(expression);
    setAppliedFilter(expression);
  }, []);

  const handleSelectProtocol = useCallback((proto: string) => {
    const expr = `proto == ${proto.toLowerCase()}`;
    setFilterText(expr);
    setAppliedFilter(expr);
  }, []);

  const handleFilterHost = useCallback((ip: string) => {
    const expr = `ip.addr == "${ip}"`;
    setFilterText(expr);
    setAppliedFilter(expr);
  }, []);

  // Hoisted out of the aside's JSX for the same reason. The width check is the
  // one the mobile layout uses to follow a selection into the detail tab.
  const handleInspectFromDashboard = useCallback((pkt: Packet) => {
    setSelectedPacket(pkt);
    if (window.innerWidth < 768) setMobileTab("tree");
  }, []);

  const handleFilterAnomaly = useCallback(() => {
    handleQuickFilter("anomaly");
  }, [handleQuickFilter]);

  const handleOpenStatistics = useCallback(() => setShowStatsModal(true), []);

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

  /**
   * Everything the analytics widgets need, in one object.
   *
   * Memoized because `DashboardAside` sits behind `React.memo`, and a context
   * rebuilt on every render would defeat that boundary entirely - this
   * component re-renders about ten times a second while capturing, which is
   * the whole reason the boundary is there.
   *
   * The only field that churns is `packets`, which is the throttled dashboard
   * feed rather than the live buffer; every callback below is a stable
   * `useCallback`. So this changes at the dashboard's rate, not the capture's.
   */
  const dashboardContext = useMemo(
    () => ({
      packets: dashboardPackets,
      isDark,
      themeKey: resolvedTheme,
      isCapturing,
      appliedFilter,
      onSelectProtocol: handleSelectProtocol,
      onOpenStatistics: handleOpenStatistics,
      onFilterHost: handleFilterHost,
      onInspectPacket: handleInspectFromDashboard,
      onFilterAnomaly: handleFilterAnomaly,
    }),
    [
      dashboardPackets,
      isDark,
      resolvedTheme,
      isCapturing,
      appliedFilter,
      handleSelectProtocol,
      handleOpenStatistics,
      handleFilterHost,
      handleInspectFromDashboard,
      handleFilterAnomaly,
    ],
  );

  // Live capture telemetry, surfaced in the Settings modal's buffer badge.
  //
  // Off the throttled buffer, not the live one: this is a full O(buffer) reduce
  // and there is no reading of it that needs to be fresher than the panels
  // beside it.
  //
  // And only while that modal is actually open. It has exactly one consumer,
  // behind a modal that is closed almost all of the time, so computing it
  // otherwise is a full pass over up to 50,000 packets, twice a second, for a
  // number nobody can see. The `0` stands in while closed - nothing reads it.
  const totalBytes = useMemo(
    () => (showSettingsModal ? dashboardPackets.reduce((sum, p) => sum + p.length, 0) : 0),
    [dashboardPackets, showSettingsModal],
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
          // Was `() => setPackets([])`, which emptied the list but left the
          // packet-number counter and the relative-time clock running, so a
          // cleared buffer kept counting from wherever the last one stopped.
          onClearPackets={handleClearPackets}
          agentInterfaces={agentInterfaces}
          selectedInterfaces={selectedInterfaces}
          onSelectInterface={handleSelectInterface}
          interfaceRates={interfaceRates}
          onInterfacePickerOpenChange={handleInterfacePickerOpenChange}
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
            filterPresetLibrary={filterPresetLibrary}
            onSaveCurrentFilter={handleSaveCurrentFilter}
          />
          }
          onOpenSettingsModal={() => setShowSettingsModal(true)}
          agentStatus={agentStatus}
          agentLinkEnabled={agentLinkEnabled}
          agentOutdated={agentOutdated}
          totalPacketsCount={packets.length}
          restoreProgress={restoreProgress}
          filteredPacketsCount={filteredPackets.length}
        />


        {/* Mobile Tab Switcher */}
        <div className="flex md:hidden border-b border-border bg-card text-xs overflow-x-auto shrink-0">
          <button
            onClick={() => setMobileTab("packets")}
            className={`flex-1 py-2 px-3 flex items-center justify-center gap-1 font-bold tracking-tight whitespace-nowrap ${
              mobileTab === "packets"
                ? "border-b-2 border-primary text-primary bg-primary/15"
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
                ? "border-b-2 border-primary text-primary bg-primary/15"
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
                ? "border-b-2 border-primary text-primary bg-primary/15"
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
                ? "border-b-2 border-primary text-primary bg-primary/15"
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
                themeKey={resolvedTheme}
                selectedPacket={selectedPacket}
                onSelectPacket={(pkt) => {
                  setSelectedPacket(pkt);
                  if (window.innerWidth < 768) {
                    setMobileTab("tree");
                  }
                }}
                onInspectPacket={(pkt) => setDetailPacketId(pkt.id)}
                onFollowStream={handleFollowStream}
                onQuickFilter={handleQuickFilter}
                searchText={packetSearchText}
                colorEngine={colorEngine}
                permissions={permissions}
                packetTheme={packetTheme}
              />
            </div>

            {/* Resize Drag Handle */}
            {showPanes && (
            <div
              role="separator"
              aria-orientation="horizontal"
              aria-label="Resize packet detail panes"
              aria-valuenow={Math.round(bottomPaneHeight)}
              aria-valuemin={100}
              aria-valuemax={Math.max(100, window.innerHeight - 200)}
              tabIndex={0}
              title="Drag to resize - right-click to reset, Enter to hide the panes"
              className="hidden md:block h-1.5 w-full cursor-row-resize transition-colors shrink-0 z-10 bg-muted hover:bg-primary/50"
              onPointerDown={() => beginDrag("height")}
              // Right-click restores the default, on every draggable bar in the
              // app. A drag is easy to overshoot and there is nothing to undo
              // it with; the alternative is hunting for whatever number looked
              // right before, which is not something anyone can actually do.
              // preventDefault suppresses the browser's own menu, and
              // stopPropagation keeps the packet list's row menu out of it.
              onContextMenu={(e) => {
                e.preventDefault();
                e.stopPropagation();
                patchLayout({ bottomPaneHeight: LAYOUT_DEFAULTS.bottomPaneHeight });
              }}
              onKeyDown={(e) => {
                // Up grows the panes, because up is the direction the divider
                // moves to make them bigger.
                const step = e.shiftKey ? 64 : 16;
                if (e.key === "ArrowUp") { e.preventDefault(); nudgeHeight(step); }
                else if (e.key === "ArrowDown") { e.preventDefault(); nudgeHeight(-step); }
                else if (e.key === "Home") { e.preventDefault(); patchLayout({ bottomPaneHeight: 100 }); }
                else if (e.key === "End") { e.preventDefault(); patchLayout({ bottomPaneHeight: window.innerHeight - 200 }); }
                else if (e.key === "Enter") { e.preventDefault(); patchLayout({ panes: false }); }
              }}
            />
            )}

            {/* Lower Pane: Geometric Split of Protocol Details Tree & Hex Viewer */}
            {showPanes && (
            <div
              ref={bottomPaneRef}
              style={
                {
                  // Both sizes live here, on one element, so a drag can write
                  // them straight to the DOM without going through React.
                  "--bottom-pane-height": `${bottomPaneHeight}px`,
                  "--details-pane-size": `${detailsPaneRatio * 100}%`,
                } as React.CSSProperties
              }
              className={`h-56 md:h-[var(--bottom-pane-height)] border-t border-border flex flex-col ${stacked ? "md:flex-col" : "md:flex-row"} overflow-hidden transition-colors shrink-0 bg-card ${mobileTab !== "packets" && mobileTab !== "graphs" ? "block" : "hidden md:flex"}`}
            >
              {/* Protocol Layers Inspection Tree */}
              <div
                className={`w-full min-w-0 overflow-hidden md:shrink-0 ${
                  stacked
                    ? "md:w-full md:h-[var(--details-pane-size)]"
                    : "md:w-[var(--details-pane-size)] h-full"
                } ${mobileTab === "tree" ? "block" : "hidden md:block"}`}
              >
                <PacketDetailsTree
                  packet={selectedPacket}
                  accentColor={selectedPacketAccent}
                  onHoverByteRange={setActiveByteRange}
                  onSelectFrame={frameNumber => {
                    const target = packets.find(p => p.id === frameNumber);
                    if (target) setSelectedPacket(target);
                  }}
                  activeByteRange={activeByteRange}
                  permissions={permissions}
                />
              </div>

              {/* Split Drag Handle - doubles as the border between the panes */}
              <div
                role="separator"
                aria-orientation={stacked ? "horizontal" : "vertical"}
                aria-label="Resize protocol tree and byte view"
                aria-valuenow={Math.round(detailsPaneRatio * 100)}
                aria-valuemin={10}
                aria-valuemax={90}
                tabIndex={0}
                className={`hidden md:block transition-colors shrink-0 z-10 bg-muted hover:bg-primary/50 ${
                  stacked ? "h-1.5 w-full cursor-row-resize" : "w-1.5 h-full cursor-col-resize"
                }`}
                title="Drag to resize - right-click, double-click or Enter to even out"
                onPointerDown={() => beginDrag("split")}
                onDoubleClick={() => patchLayout({ detailsPaneRatio: 0.5 })}
                onContextMenu={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  patchLayout({ detailsPaneRatio: LAYOUT_DEFAULTS.detailsPaneRatio });
                }}
                onKeyDown={(e) => {
                  // Whichever pair of arrows points along the divider's axis.
                  const step = e.shiftKey ? 0.1 : 0.02;
                  const less = stacked ? "ArrowUp" : "ArrowLeft";
                  const more = stacked ? "ArrowDown" : "ArrowRight";
                  if (e.key === less) { e.preventDefault(); nudgeSplit(-step); }
                  else if (e.key === more) { e.preventDefault(); nudgeSplit(step); }
                  else if (e.key === "Home") { e.preventDefault(); patchLayout({ detailsPaneRatio: 0.1 }); }
                  else if (e.key === "End") { e.preventDefault(); patchLayout({ detailsPaneRatio: 0.9 }); }
                  else if (e.key === "Enter") { e.preventDefault(); patchLayout({ detailsPaneRatio: 0.5 }); }
                }}
              />

              {/* Raw Hex & ASCII Dump View */}
              <div
                className={`w-full md:flex-1 h-full min-w-0 overflow-hidden ${
                  mobileTab === "hex" ? "block" : "hidden md:block"
                }`}
              >
                <HexViewer
                  packet={selectedPacket}
                  accentColor={selectedPacketAccent}
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
            )}
          </section>

          {/* The analytics column, or the icon rail it collapses to.
              Mounted only when it can actually be seen: `hidden lg:flex` is
              CSS, and CSS does not stop React, so under 1024px every widget in
              here went on aggregating the whole packet buffer twice a second
              for a column nobody could look at. The rail is the exception - it
              fits from `md`, which is the point of it. */}
          {(dashboardVisible || railFits || mobileTab === "graphs") && (
            <DashboardAside
              context={dashboardContext}
              isMobileTabActive={mobileTab === "graphs"}
            />
          )}
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
        {detailPacketId !== null && (
          <PacketDetailModal
            key="packet-detail-modal"
            packets={packets}
            packetId={detailPacketId}
            filteredPackets={filteredPackets}
            onClose={() => setDetailPacketId(null)}
            onShowFrame={setDetailPacketId}
            onFollowStream={handleFollowStream}
            colorEngine={colorEngine}
            packetTheme={packetTheme}
            permissions={permissions}
            obscured={streamToFollow !== null}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showStatsModal && (
          <StatisticsModal
            key="stats-modal"
            packets={dashboardPackets}
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
            agentLinkEnabled={agentLinkEnabled}
            agentError={agentError}
            onConnectAgent={handleConnectAgent}
            onDisconnectAgent={handleDisconnectAgent}
            onRestartAgent={handleRestartAgent}
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
            packetBufferCap={packetBufferCap}
            bufferAutoPaused={bufferAutoPaused}
            onClearPackets={handleClearPackets}
            filterPresetLibrary={filterPresetLibrary}
            onFilterPresetLibraryChange={handleFilterPresetLibraryChange}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
