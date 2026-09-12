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
import { useFontPreference } from "./lib/font";
import { useChromePreference } from "./lib/chrome";
import { TourOverlay } from "./components/tour/TourOverlay";
import { tourStore } from "./services/tourPrefs";
import { useNameResolutionPreference } from "./lib/nameResolution";
import {
  LAYOUT_DEFAULTS,
  layoutStore,
  packetListStore,
  performanceStore,
} from "./services/interfacePrefs";
import { NameResolutionMap, snapshot as nameSnapshot } from "./services/nameResolution";
import type { StreamTarget } from "./services/followStream";
import { ExpertLog, expertSnapshot } from "./services/expertInfo";
import { useIncrementalAggregate } from "./lib/useIncrementalAggregate";
import { MAX_CUSTOM_COLUMNS } from "./lib/packetColumns";
import { usePreferenceStore, usePreferenceValue } from "./services/preferenceStore";
import { packetColorSetStore } from "./services/themePrefs";
import { resetGeoSession } from "./components/analytics/geoSession";
import { DashboardAside } from "./components/analytics/DashboardAside";
import { isDarkTheme } from "./lib/themeOptions";
import { getPacketThemeForApp } from "./services/packetThemes";
import { Capabilities, Packet } from "./types/packet";
import { PacketGenerator } from "./services/packetGenerator";
import { pipeline } from "./services/pipelineClient";
import { usePacketDetail } from "./lib/usePacketDetail";
import { bytesAreRecoverable } from './services/packetBytes';
import { flowAnnotations } from './services/flowAnnotations';
import { NO_HOST, type HostIdentity } from './services/direction';
import { useKeyboardNavigation } from './hooks/useKeyboardNavigation';
import { usePacketBuffer } from './hooks/usePacketBuffer';
import { useCaptureSchedule } from './hooks/useCaptureSchedule';
import { capturePresetStore } from './services/captureSchedulePrefs';
import {
  describeSchedule, EMPTY_SCHEDULE, type CaptureSchedule,
} from './services/captureSchedule';
import { useAgentConnection } from './hooks/useAgentConnection';
import { inferHostIdentity } from './services/hostIdentity';
import { rederiveDirections } from './services/redirect';
import { emptyNetworkFacts, NetworkFactsCollector, type NetworkFacts } from './services/networkFacts';
import {
  readLinkContext, watchLinkChanges, type LinkChange, type LinkContext,
} from './services/linkContext';
import { processForPacket, sendingProcessName, writeProcessFields } from './services/dissect/processFields';
import { fieldValue } from './services/dissect/fieldAccess';
import { filterIncrementally, type FilterCache } from "./services/incrementalFilter";
import {
  clearSession,
  loadSessionMeta,
  saveSessionMeta,
} from "./services/sessionStore";
import { CustomDissectorEngine } from "./services/customDissectorEngine";
import {
  ColorRulesEngine,
  COLOR_RULES_STORAGE_KEY,
  defaultColorRules,
  normalizeColorRules,
} from "./services/colorRules";
import {
  isAgentOutdated, REQUIRED_AGENT_VERSION, type AgentMessage,
} from "./services/agentProtocol";

// UI Components
import { Header } from "./components/common/Header";
import { FilterBar } from "./components/common/FilterBar";
import { PacketList } from "./components/packet-list/PacketList";
import { PacketDetailsTree } from "./components/packet-details/PacketDetailsTree";
import { HexViewer } from "./components/packet-details/HexViewer";
import { PacketDetailModal } from "./components/packet-details/PacketDetailModal";
import { StreamFollowerModal } from "./components/stream-follower/StreamFollowerModal";
import { findPacketIndexById, frameJumpRefusal } from "./components/packet-details/packetDetailModel";
import { CustomDissectorModal } from "./components/dissectors/CustomDissectorModal";
import { ExportImportModal } from "./components/export/ExportImportModal";
import { StatisticsModal } from "./components/statistics/StatisticsModal";
import { NetworkModal } from "./components/network/NetworkModal";
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
import type { ColorRule, FilterPresetLibrary } from "./types/packet";

import {
  TbActivity,
  TbList,
  TbStack2,
  TbBinary,
  TbAlertTriangle,
} from "react-icons/tb";
import { FieldBlockWriter } from './services/dissect/fieldSplit';
import { estimateSummaryBytes } from './services/bufferBudget';
import { captureStore, newCaptureId } from './services/capture/captureClient';
import { freshCaptureStorageState, type CaptureStorageState } from './services/capture/captureProtocol';

/**
 * How far back a socket-table DELTA is allowed to re-annotate.
 *
 * The agent reads the table once a second, so a socket first seen at T may
 * have opened at any point in the second before - and frames from that second
 * were dissected before anything knew who owned them. Beyond that window a
 * delta cannot tell us anything new about a frame, and sweeping the whole
 * buffer every second to prove it would cost more than the attribution is
 * worth. A full snapshot ignores this and sweeps everything, once.
 */
const SOCKET_RETRO_WINDOW_US = 3_000_000;

// The frame-count cap, its slack and `trimToCap` used to live here. The buffer
// is bounded by BYTES now (`services/bufferBudget.ts`: `planBufferTrim` against
// the `packetBufferBytes` preference), because a frame count cannot answer "how
// much memory is this" when a frame is anywhere from 60 bytes to 64 kB. The
// slack survives as `BUDGET_SLACK` there, for the same reason it existed here:
// trimming on every flush moves `packets[0]` ten times a second, and three
// caches take an O(buffer) fallback each time it moves.


// A restore used to need a chunk size, four stateful trackers and a
// re-dissection of every stored frame - 115us each, 5.8 seconds for a full
// buffer - because the disk held bytes and nothing else. It reads the rows the
// capture store wrote instead, so the chunk it yields between is the format's
// own 4,096-frame chunk and the trackers are gone from this file entirely.


/**
 * The rest of what a refresh used to throw away.
 *
 * These are small, change on deliberate user action, and are per-preference
 * keys on the shared localStorage mechanism in services/preferences.ts - the
 * packet buffer is the only part of a session big enough to need IndexedDB.
 * Each validator is module scope so it keeps one identity across renders.
 */
const DISPLAY_FILTER_KEY = "inwire.displayFilter";
const PACKET_SEARCH_KEY = "inwire.packetSearch";
const SELECTED_PACKET_KEY = "inwire.selectedPacketId";
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
  useFontPreference();
  useChromePreference();
  // The first-run walkthrough. `completed` is set by finishing it AND by
  // skipping it - see services/tourPrefs for why skipping counts.
  const [tour] = usePreferenceValue(tourStore);
  usePreferenceSync(tourStore.key, tourStore.normalize, tourStore.accept);
  // Pushes the two outbound-lookup switches into the service that performs
  // them, so the gate lives in one place rather than at every call site.
  const [nameResolution, patchNameResolution] = useNameResolutionPreference();

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
  //
  // The colour SET is the second axis, and it is a preference rather than
  // something derived: the theme decides which nine hues, the set decides how
  // loudly - or, for Colourblind, which nine instead. Memoized on both, because
  // this walks the whole rule chain through a Lab derivation and the result
  // feeds a component that re-renders on every packet.
  const [packetColorSet] = usePreferenceValue(packetColorSetStore);
  const packetTheme = useMemo(
    () => getPacketThemeForApp(resolvedTheme, packetColorSet),
    [resolvedTheme, packetColorSet],
  );
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

  // --- the packet buffer ----------------------------------------------------
  //
  // Hoisted above everything that reads `packets`, which is most of this file.
  // The pieces it needs come first for the same reason.
  // Named `perf`, not `performance`: the latter shadows the global timing API,
  // which is exactly the sort of shadowing that is fine until somebody adds a
  // `performance.now()` in this scope and gets a confusing type error.
  const [perf] = usePreferenceStore(performanceStore);
  usePreferenceSync(performanceStore.key, performanceStore.normalize, performanceStore.accept);
  const { packetBufferBytes, dashboardRefreshMs } = perf;
  // Track the latest isCapturing value for the always-on agent connection
  // below, whose handlers are set up once and must not go stale.
  const isCapturingRef = useRef(isCapturing);
  useEffect(() => {
    isCapturingRef.current = isCapturing;
  }, [isCapturing]);

  // Live-capture relative-time clock (reference-analyzer style): resets whenever the
  // packet buffer is emptied and a fresh capture begins.
  const captureStartRef = useRef<number | null>(null);
  /** Wall-clock ms when the running capture was started, for the schedule. */
  const captureStartedAtRef = useRef<number | null>(null);
  const lastPacketTimeRef = useRef<number | null>(null);
  /**
   * The auto-pause handler, held in a ref.
   *
   * The buffer hook has to be able to stop a capture, and stopping one needs
   * `sendAgentCommand` - which comes from the agent hook, which needs
   * `queueFrames` from the buffer hook. A ref breaks that circle the same way
   * `useAgentConnection` already breaks it for its own callbacks: the hook gets
   * one stable function, and what it points at is replaced every render.
   */
  const autoPauseRef = useRef<() => void>(() => {});
  const onAutoPause = useCallback(() => autoPauseRef.current(), []);
  const onFramesQueued = useCallback((firstTsUs: number, lastTsUs: number) => {
    if (captureStartRef.current === null) captureStartRef.current = firstTsUs;
    lastPacketTimeRef.current = lastTsUs;
  }, []);

  const {
    packets, setPackets, droppedBuffer, bufferAutoPaused, setBufferAutoPaused,
    queueFrames, adoptBuffer, residentBytes, budgetBytes, accountingRef, fieldWriter,
  } = usePacketBuffer({ packetBufferBytes, isCapturingRef, onAutoPause, onFramesQueued });


  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  /** Which view the stream window opens on - see handleFollowStream. */
  const [streamView, setStreamView] = useState<'dialogue' | 'ladder'>('dialogue');
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
  const [streamToFollow, setStreamToFollow] = useState<StreamTarget | null>(null);
  // The frame the detail window is showing, or null when it is closed. Held as
  // a number rather than a Packet so the window keeps following the same frame
  // as the buffer around it changes.
  const [detailPacketId, setDetailPacketId] = useState<number | null>(null);
  const [showDissectorModal, setShowDissectorModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showStatisticsModal, setShowStatisticsModal] = useState(false);
  const [showNetworkModal, setShowNetworkModal] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  /**
   * How this machine's adapters are configured, and who this machine is.
   *
   * The Network panel reads the first; the packet list's Direction column
   * reads the second - through `Packet.direction`, which the identity decides
   * at dissection, not by reading the identity itself.
   *
   * A ref and NOT a state, deliberately. There was a `hostIdentity` state
   * beside this ref and nothing ever read it, so each of the four places that
   * settle the identity - stored session, agent adapters, inference, override -
   * re-rendered a 2,900-line component to publish a value with no reader. The
   * ref is what the callbacks want anyway: they must not re-create themselves
   * every time it changes, the same pattern `isCapturingRef` uses. Anything
   * that later wants to *display* the identity should take the state back,
   * rather than reading the ref during render and getting a stale one.
   */
  const hostIdentityRef = useRef<HostIdentity>(NO_HOST);
  /**
   * Cancels a re-derive that is still running.
   *
   * The pass is sliced across animation frames, so a second import - or an
   * override while the first is still going - would otherwise leave two of
   * them writing different identities into the same frames.
   */
  const rederiveRef = useRef<(() => void) | null>(null);
  /** What the capture itself revealed, derived in the Worker and only read here. */
  const [networkFacts, setNetworkFacts] = useState<NetworkFacts>(() => emptyNetworkFacts());

  /**
   * How much of this capture is on disk, from the capture store itself.
   *
   * Shown because the stored capture outlives the app
   * (docs/decisions/0012-stored-captures-persist.md): bytes that persist
   * unasked and unseen would be the wrong trade, so the size is on screen
   * beside the one button that removes them. There used to be a second figure
   * beside it for the IndexedDB session; there is no second copy any more.
   */
  const [captureStorage, setCaptureStorage] = useState<CaptureStorageState>(freshCaptureStorageState);
  /** The capture directory this Start->Stop cycle is writing into. */
  const captureIdRef = useRef<string | null>(null);
  /**
   * The same number on a ref, plus the head id it was last counted at,
   * because the state can only be advanced from inside a `setPackets` updater
   * - which React runs twice under StrictMode, with the same `prev` both
   * times. `headId` is what makes the second run a no-op: trimming removes the
   * head by definition, so a changed head is exactly one trim, counted once.
   * See the trim in the packet-flush effect.
   */
  /**
   * What the browser says about the link, and every time it changed.
   *
   * Null on Firefox and Safari, which have no Network Information API - and
   * null is what is shown there, rather than numbers derived from timings and
   * presented as though the browser had reported them.
   */
  const [linkContext, setLinkContext] = useState<LinkContext | null>(() => readLinkContext());
  const [linkChanges, setLinkChanges] = useState<LinkChange[]>([]);

  /**
   * Records network transitions for the life of the page.
   *
   * The event is the valuable half of this API. A machine moving between
   * networks is what explains a gap with no frames in it, a burst of ARP and
   * DHCP, or a stream that stops dead - all of which read as faults and are
   * not. The estimates it carries alongside are context and are never shown
   * beside the capture's own measurements as if they were the same kind of
   * number.
   */
  useEffect(() => watchLinkChanges((change) => {
    setLinkContext(change.after);
    setLinkChanges((prev) => prev.concat(change).slice(-32));
  }), []);
  // How far a session restore has got, or null when none is running. Drives
  // the header's progress readout; also the flag the UI uses to explain why
  // packets are appearing without a capture being started.
  const [restoreProgress, setRestoreProgress] = useState<{ done: number; total: number } | null>(null);


  /**
   * What this build lets the user do.
   *
   * Every capability is on, and stated rather than derived: there is no auth,
   * so there is nobody to derive it from. It was read from a role table
   * (`services/rbacService.ts`) that shipped four roles and was never consulted
   * - the object below was already hardcoded beside the import. The table is
   * gone; this is the whole of the model.
   *
   * It is still threaded to the components rather than inlined at each gate,
   * because the seventeen `permissions.*` reads are where a real one would
   * plug in.
   */
  const permissions: Capabilities = {
    canCapture: true,
    canExportPcap: true,
    canViewPayloads: true,
    canEditDissectors: true,
    canChangeColorRules: true,
    canClearBuffer: true,
  };

  // Same reasoning, for the Space shortcut: its handler is registered once and
  // needs to know whether there is a buffer that starting would discard. A ref
  // rather than a dependency, because re-registering a window listener on
  // every packet flush is ten new listeners a second during capture.
  const packetCountRef = useRef(0);
  useEffect(() => {
    packetCountRef.current = packets.length;
  }, [packets.length]);




  /**
   * Re-annotating frames that were dissected before the socket table arrived.
   *
   * Lifted out of the agent message handler with the rest of it, but kept
   * here: the Worker annotates everything it dissects from now on, and this is
   * the part that reaches back into the buffer - which is this component's.
   */
  const applySocketTable = useCallback((message: Extract<AgentMessage, { type: 'socket_table' }>) => {
      // The Worker has its own copy and annotates every frame it dissects
      // from here on. This copy exists for the frames that were dissected
      // BEFORE the table arrived - the opening snapshot describes sockets
      // that have been open for minutes, and the connection they belong to
      // may already fill the buffer.
      flowAnnotations.apply(message, Date.now() * 1000);

      // A full snapshot is worth a pass over the whole buffer; it happens
      // once per subscription. A delta is one or two sockets a second, and
      // sweeping 100,000 frames every second to find the handful they might
      // touch is not - so a delta re-annotates only the frames captured
      // inside the polling window it is uncertain about, which is the only
      // stretch where a frame can predate the socket's discovery.
      const horizonUs = message.full
        ? -Infinity
        : Date.now() * 1000 - SOCKET_RETRO_WINDOW_US;
      setPackets((prev) => {
        let changed = false;
        const next = prev.map((packet) => {
          if (packet.tsUs < horizonUs) return packet;
          if (fieldValue(packet, 'inwire.process.name') !== undefined) return packet;
          const process = processForPacket(packet, flowAnnotations);
          if (!process) return packet;
          changed = true;
          // A copy, because a packet already handed to React is not ours to
          // mutate - a row that changed in place would not re-render.
          //
          // The spread carries `cols` and `row` across, which is what we
          // want: the copy shares the original's block and its row, and a row
          // is written once when the frame joins the buffer and never again,
          // so two packets reading it see the same values. What is written
          // HERE goes to the bag, because the process fields are declared
          // post-dissection and so are never dense (`dissect/denseFields.ts`,
          // asserted in `scripts/dissect/dense-fields.ts`).
          const copy: typeof packet = { ...packet, fields: { ...packet.fields } };
          writeProcessFields(copy, process);
          return copy;
        });
        return changed ? next : prev;
      });
  }, []);

  /**
   * A flush of dissected frames from the Worker. Queued, not committed: the

  /**
   * The link to the local capture agent.
   *
   * Sixteen pieces of state, four refs and five effects used to sit inline
   * here; `hooks/useAgentConnection.ts` holds them now. The four callbacks are
   * the seam: everything the connection has to do to the *buffer* stays on
   * this side, because the buffer is this component's.
   */
  const agent = useAgentConnection({
    canCapture: permissions.canCapture,
    isCapturingRef,
    onCaptureStopped: () => setIsCapturing(false),
    onFrames: queueFrames,
    onSocketTable: applySocketTable,
    onHostIdentity: (identity) => {
      hostIdentityRef.current = identity;
      pipeline.setHost(identity);
    },
    onNetworkFacts: setNetworkFacts,
  });
  const {
    agentStatus, agentCaptureState, agentClientId, captureOwner,
    agentHealth, startAgentService,
    agentLinkEnabled, setAgentLinkEnabled,
    agentVersion, agentIncompatible, agentInterfaces, captureStats, adapters,
    agentLog, agentError, interfaceRates, selectedInterfaces,
    setSelectedInterfaces, selectedInterfacesRef,
    sendAgentCommand, subscribeAgentLog, unsubscribeAgentLog,
    clearAgentLog, clearInterfaceRates, clearCaptureStats,
  } = agent;
  // The other half of auto-pause. The buffer hook owns the flag and cannot own
  // this, because stopping a capture needs the agent - and the agent needs the
  // buffer's `queueFrames`. Assigned every render, so it never goes stale.
  autoPauseRef.current = () => {
    setIsCapturing(false);
    sendAgentCommand({ type: 'stop_capture' });
  };

  // --- the capture schedule ---------------------------------------------------
  /**
   * Session-only, and NOT a stored preference like the presets beside it.
   *
   * A schedule is a decision about the next few minutes; a preset is a habit.
   * Persisting the first means an app opened tomorrow is still armed with a
   * stop somebody set today and has long forgotten - and the one thing worse
   * than a capture that will not stop is one that stops for a reason nobody
   * remembers choosing. Reset on close, and on reload, which is a superset of
   * what was asked and errs the safe way.
   */
  const [schedule, setSchedule] = useState<CaptureSchedule>(EMPTY_SCHEDULE);
  const [schedulePresets, setSchedulePresets] = usePreferenceValue(capturePresetStore);
  usePreferenceSync(capturePresetStore.key, capturePresetStore.normalize, capturePresetStore.accept);

  /**
   * Starts a capture the schedule asked for, or reports why it could not.
   *
   * It does what the header's own Start does - clear, then start - rather than
   * opening a second path into the same state. The discard is deliberate and
   * was consented to in the dropdown, which warns while the schedule is being
   * set precisely because a timer cannot answer a confirmation dialog.
   *
   * Refused rather than forced when there is no adapter or no agent: nothing
   * here can pop a picker, which is the same rule the Space shortcut follows.
   */
  const scheduledStart = (): boolean => {
    if (!permissions.canCapture || selectedInterfacesRef.current.length === 0) {
      setNavNotice('Scheduled capture skipped: no adapter selected.');
      return false;
    }
    if (agentStatus !== 'connected') {
      setNavNotice('Scheduled capture skipped: the agent is not connected.');
      return false;
    }
    handleClearPackets();
    void handleStartCapture();
    setNavNotice('Scheduled capture started.');
    return true;
  };

  const { now: scheduleNow } = useCaptureSchedule({
    schedule,
    isCapturingRef,
    captureStartedAtRef,
    onScheduledStart: scheduledStart,
    onScheduledStop: () => {
      handlePauseCapture();
      setNavNotice('Scheduled capture stopped.');
    },
  });
  /**
   * True while a stored session is being decoded back into the buffer. Read by
   * the effects that must not write a half-restored session back to disk.
   */
  const restoringRef = useRef(false);
  /** Whether the one restore this page load gets has been kicked off yet. */
  const restoreStartedRef = useRef(false);
  /** The highest packet id already written to disk, so a flush only appends. */

  // The capture store pushes its state, and is also asked on the same tick as
  // the session store below - pushed for the events (opened, failed) and polled
  // for the counters, because the counters move on every flush and a message
  // per flush would be a message ten times a second saying almost nothing.
  useEffect(() => {
    captureStore.onState = setCaptureStorage;
    const tick = window.setInterval(() => captureStore.askForStats(), 2000);
    return () => {
      captureStore.onState = () => {};
      window.clearInterval(tick);
    };
  }, []);


  /**
   * Whether quitting would cost the reader anything.
   *
   * Reported to the main process, which owns the confirmation. It used to be a
   * `beforeunload` handler here, and in Electron that is not merely the wrong
   * place - it is **broken**: a `beforeunload` that calls `preventDefault()`
   * refuses to close the window and shows **no dialog at all**, and
   * `WARN_BEFORE_LEAVING` was `!import.meta.env.DEV`, so a packaged build would
   * have been unclosable with a capture in the buffer.
   *
   * Everything that made the old version complicated goes with it. It kept a
   * capture-phase keydown listener recording F5 and Ctrl+R so a deliberate
   * reload could skip the prompt, because `beforeunload` cannot tell a refresh
   * from a close and the platform exposes nothing that distinguishes them. A
   * desktop app does not offer a reload in a packaged build (see
   * `electron/menu.ts`), so there is no second gesture to tell apart - and the
   * browser's untailorable wording, which that comment complained about, is
   * now ours to write.
   */
  const hasCapturedPackets = packets.length > 0;
  useEffect(() => {
    window.inwire?.setUnsavedCapture?.(hasCapturedPackets);
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
      const meta = await loadSessionMeta();

      // The session's frames are in the capture directory the metadata names,
      // and only that one. Pairing this metadata with a different capture's
      // frames would shift every timestamp in the list, because the
      // relative-time origin and the adapter table both belong to the run that
      // wrote them.
      const stored = meta?.captureId ? await captureStore.reopen(meta.captureId) : null;
      // Everything else on disk goes. One capture is the retention rule, and
      // it is the whole of it (`docs/decisions/0026`): a capture on disk is
      // 5 GB and twenty minutes at full rate, so wanting the previous one is
      // mostly wanting a longer current one, and a capture worth keeping past
      // a session is one to Export. Start wiped the previous capture out of
      // IndexedDB before this, so nothing about that changed with the
      // backend.
      captureStore.prune(stored === null ? [] : [stored.captureId]);
      captureIdRef.current = stored?.captureId ?? null;

      if (stored !== null && stored.frameCount > 0) {
        // Whose machine this was, read back rather than re-inferred. A session
        // written before this was saved has none, and restores the way it
        // always did.
        const storedHost: HostIdentity | undefined = meta?.host && {
          macs: new Set(meta.host.macs),
          addresses: new Set(meta.host.addresses),
          inferred: meta.host.inferred,
          confidence: meta.host.confidence,
          basis: meta.host.basis,
        };
        if (storedHost) {
          hostIdentityRef.current = storedHost;
          // The Worker rebuilds the detail tree by replaying the conversation
          // (`pipeline/replay.ts`), so it needs the same answer or the tree
          // will contradict the row that opened it.
          pipeline.setHost(storedHost);
        }

        // --- what to bring back ---------------------------------------------
        //
        // The newest chunks that fit the budget, read from the END backwards.
        // The old restore read the whole store forwards and trimmed the front
        // as it went, which on a capture larger than the buffer meant decoding
        // every frame in order to throw most of them away. A chunk is
        // self-contained, so the tail can be read first - and the tail is what
        // the reader was looking at.
        //
        // The rest of the capture is not lost. It is on disk and inside the
        // stored id range; what it is not yet is *reachable*, which is what
        // the row source in a later step is for.
        const chunks: Packet[][] = [];
        let restoring = 0;
        let bytes = 0;
        for (let c = stored.chunkCount - 1; c >= 0; c--) {
          const rows = await captureStore.readRows(c);
          if (rows.length === 0) continue;      // a torn tail; the rest still reads
          let chunkBytes = 0;
          for (const packet of rows) chunkBytes += estimateSummaryBytes(packet);
          // Always at least one chunk, whatever the budget says: a buffer that
          // restored nothing because the first chunk it looked at was large
          // would be worse than one slightly over.
          if (chunks.length > 0 && bytes + chunkBytes > budgetBytes()) break;
          chunks.unshift(rows);
          bytes += chunkBytes;
          restoring += rows.length;
        }

        setRestoreProgress({ done: 0, total: restoring });
        let done = 0;
        for (const rows of chunks) {
          // A restored session fills the buffer as full as a live capture ever
          // does, so its frames get the same treatment. The chunk codec hands
          // back the field bag, because the bag is the contract; the split into
          // columns belongs here, where the frames join the buffer.
          fieldWriter.current.absorb(rows);
          for (const packet of rows) accountingRef.current.residentBytes += estimateSummaryBytes(packet);
          done += rows.length;
          // No ICMP or Info patches to apply: the writer held each row behind
          // the patch horizon until no open reassembly could still reach it, so
          // what comes back is the row the reader actually saw. That is the
          // whole reason the summary is on disk - re-dissecting a frame from
          // the middle of a capture can produce a DIFFERENT Info line, and the
          // old restore did exactly that.
          setPackets((prev) => prev.concat(rows));
          setRestoreProgress({ done, total: restoring });
          // Yield so React can commit and the browser can paint this chunk.
          await new Promise((resolve) => setTimeout(resolve, 0));
        }

        // The direction pass an import takes. A restored row carries the
        // direction it was written with, but the host override, the resolved
        // names and the network facts are all rebuilt from the buffer, and
        // this is the pass that does it.
        //
        // Read through the ref rather than from inside a state updater. An
        // updater must be pure - StrictMode double-invokes it - and this one
        // would have started the derive pass twice.
        deriveForBuffer(packetsRef.current);

        // Numbering continues from the stored capture rather than restarting
        // at 1 and colliding with packets already in the list. `stored.lastId`
        // is the whole capture's last id, not the window's - the frames below
        // the window are still on disk and their ids are still taken.
        packetGenerator.resumeAfter(stored.lastId);
        accountingRef.current.persistedThroughId = stored.lastId;
        // The relative-time clock is restored too, so a resumed capture's
        // timestamps continue the original timeline instead of jumping to 0.
        // The clock refs are microseconds; the stored meta stays in
        // milliseconds so an older session file still reads.
        captureStartRef.current = meta?.captureStartMs != null ? meta.captureStartMs * 1000 : null;
        lastPacketTimeRef.current = meta?.lastPacketMs != null ? meta.lastPacketMs * 1000 : null;
        // A fresh column block, so live frames start one of their own rather
        // than extending the restored capture's - but NOT a fresh byte count.
        // The loop above added every restored frame to it, and those frames
        // are still in the buffer. Zeroing it here reported a full buffer as
        // "0 / 512 MB", and worse: `planBufferTrim` reads the same number, so
        // a restored session never trimmed until enough live frames had
        // arrived to rebuild a total from nothing.
        fieldWriter.current = new FieldBlockWriter();
        pipeline.reset(Math.floor(stored.lastId) + 1, captureStartRef.current, lastPacketTimeRef.current);
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
   * The capture directory the stored session belongs to.
   *
   * Read off the store's state rather than the ref, and pulled out on its own
   * so the metadata write below re-runs when it changes without depending on
   * the whole `captureStorage` object - which changes on every stats poll.
   */
  const storedCaptureId = captureStorage.captureId;

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
      captureStartMs: captureStartRef.current === null ? null : captureStartRef.current / 1000,
      lastPacketMs: lastPacketTimeRef.current === null ? null : lastPacketTimeRef.current / 1000,
      updatedAt: Date.now(),
      // Which capture directory these frames are in. Taken from the store's
      // own state rather than the ref beside it, because the store is what
      // knows the directory was actually opened - a captureId written here for
      // a capture the store failed to open would send the next startup looking
      // for frames that were never on disk.
      captureId: storedCaptureId,
      // Written from the ref rather than the state beside it: the identity
      // settles when the adapter list arrives or a buffer is scored, neither
      // of which is in this effect's dependency list, and the throttled
      // packet tick is what brings it back here. A host that names nothing is
      // stored as nothing (`readStoredHost`), so `NO_HOST` costs no bytes.
      host: {
        macs: [...hostIdentityRef.current.macs],
        addresses: [...hostIdentityRef.current.addresses],
        inferred: hostIdentityRef.current.inferred,
        confidence: hostIdentityRef.current.confidence,
        ...(hostIdentityRef.current.basis ? { basis: hostIdentityRef.current.basis } : {}),
      },
    });
  }, [selectedInterfaces, agentInterfaces, isCapturing, persistedPacketTick, storedCaptureId]);


  // Resizable Bottom Pane
  //
  // Sizes, visibility and arrangement share one preference, because
  // `arrangement` changes what `detailsPaneRatio` means - a fraction of width
  // side by side, a fraction of height stacked. See services/interfacePrefs.

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
  /**
   * The colouring chain, and the engine built from it.
   *
   * Rebuilt when the chain changes and at no other time: the engine holds a
   * per-packet match cache whose whole premise is that a packet's rule cannot
   * change, so editing the chain has to produce a NEW engine rather than
   * mutating this one.
   */
  const [colorRules, setColorRules] = useState<ColorRule[]>(
    () => loadPreference(COLOR_RULES_STORAGE_KEY, normalizeColorRules, defaultColorRules()),
  );
  useDebouncedPreference(COLOR_RULES_STORAGE_KEY, colorRules);
  usePreferenceSync(COLOR_RULES_STORAGE_KEY, normalizeColorRules, setColorRules);
  const colorEngine = useMemo(() => new ColorRulesEngine(colorRules), [colorRules]);
  const packetGenerator = useMemo(() => new PacketGenerator(), []);
  /**
   * The colour of the row the selected packet was picked from.
   *
   * The two detail panes below the list, and the detail window, all label a
   * frame they did not draw. Labelling it in the app accent said the same thing
   * for every frame; labelling it in the frame's own colour ties the header to
   * the row the eye just left.
   */
  // The docked tree pane and the hex view below it read the selected frame; the
  // tree is the only part of it that is not already in the buffer, so it is
  // fetched on selection (docs/decisions/0007). `selectedPacket` stays the
  // buffer's own object everywhere else - the list, the filters, the accent -
  // so nothing downstream has to know a hydrated copy exists.
  const { packet: selectedPacketDetail, state: selectedDetailState } =
    usePacketDetail(selectedPacket, packets);

  /**
   * A refusal to go somewhere, shown briefly and then gone.
   *
   * Every cross-reference between frames is a number written when its target
   * was in the buffer, and the buffer trims. Clicking a link to a frame that
   * has since been trimmed used to do nothing whatsoever - which is
   * indistinguishable from a broken link, and is the reason this exists rather
   * than the click simply being ignored.
   */
  const [navNotice, setNavNotice] = useState<string | null>(null);
  useEffect(() => {
    if (navNotice === null) return;
    const timer = window.setTimeout(() => setNavNotice(null), 6000);
    return () => window.clearTimeout(timer);
  }, [navNotice]);

  /**
   * Selects frame `id` in the list, or explains why it cannot.
   *
   * The one path every in-app jump takes: the detail tree's frame links, the
   * Statistics tables, and the detail window's own navigation. They each used
   * to do their own `packets.find` and silently drop the miss.
   */
  const goToFrame = useCallback((id: number) => {
    const refusal = frameJumpRefusal(packets, id);
    if (refusal !== null) { setNavNotice(refusal); return; }
    const index = findPacketIndexById(packets, id);
    if (index === -1) return;
    setNavNotice(null);
    setSelectedPacket(packets[index]);
  }, [packets]);

  /** The same, for the detail window, which navigates by id rather than object. */
  const showFrameInWindow = useCallback((id: number) => {
    const refusal = frameJumpRefusal(packets, id);
    if (refusal !== null) { setNavNotice(refusal); return; }
    setNavNotice(null);
    setDetailPacketId(id);
  }, [packets]);

  const selectedPacketAccent = useMemo(
    () => (selectedPacket ? colorEngine.getPacketAccent(selectedPacket, packetTheme) : null),
    [selectedPacket, colorEngine, packetTheme],
  );



  // The Worker gates dissection on this: the socket stays open whether or not
  // capture is running, because the agent is detected before anyone presses
  // Start.
  useEffect(() => {
    pipeline.setCapturing(isCapturing);
  }, [isCapturing]);



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

  // Driven by the picker opening and closing. Sampling adapter counters is
  // cheap but not free, and nothing should be measured on the user's machine
  // while the menu that displays it is shut.
  const handleInterfacePickerOpenChange = useCallback((open: boolean) => {
    if (open) {
      clearInterfaceRates();
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
   * What the capture says its addresses are called.
   *
   * Built from the WHOLE buffer, not the filtered view: a name a DNS answer
   * taught in frame 12 has to keep naming its address after a filter has
   * hidden frame 12. Folded one packet at a time, because a full pass over
   * 50,000 frames ten times a second is the thing this hook exists to avoid.
   */
  const nameMap = useIncrementalAggregate(
    packets,
    () => new NameResolutionMap(),
    (map, packet) => map.learnFromPacket(packet),
    (map) => nameSnapshot(map),
  );

  /**
   * Every finding the dissectors and the anomaly detector raised.
   *
   * Also folded over the whole buffer rather than the filtered view: the
   * Expert Information list is what a filter gets narrowed FROM, and one that
   * shrank as the filter tightened could never be used to find the thing worth
   * filtering on.
   */
  const expertLog = useIncrementalAggregate(
    packets,
    () => new ExpertLog(),
    (log, packet) => log.add(packet),
    (log) => expertSnapshot(log),
  );


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

  // If selected packet is filtered out, fall back gracefully.
  //
  // This runs on every flush, so it must not scan the buffer. Two cheap
  // answers cover it: with no display filter `filteredPackets` IS `packets`,
  // and ids only ever leave from the head, so "still present" is an id-range
  // check; with a filter the selection is almost always near the tail, so the
  // scan runs from the end and usually stops within a few steps.
  //
  // **Leaving the RAM window is no longer leaving the list.** With no filter
  // the list addresses the whole capture, so a frame below the window is a row
  // the reader can scroll to, click, and read the bytes of - and this effect
  // used to drag the selection back to the newest frame the moment they did.
  // The id range is still the right test for a frame the CAPTURE no longer
  // holds; what changed is that the window's range is not the capture's.
  useEffect(() => {
    if (!selectedPacket) return;
    let visible: boolean;
    if (filteredPackets === packets) {
      // Below the window, and readable from disk. `bytesAreRecoverable` is the
      // capture store's own id range, which only grows - so this says "the
      // capture still has this frame", where the test below says "memory does".
      if (packets.length > 0 && selectedPacket.id < packets[0].id
        && bytesAreRecoverable(selectedPacket.id)) {
        return;
      }
      // Both ends. The head test alone assumes ids only ever leave from the
      // front, which holds for live trimming and not for a buffer replaced
      // wholesale - an import, a restore - where a stale selection numbered
      // above the new head would be reported present.
      visible = packets.length > 0
        && selectedPacket.id >= packets[0].id
        && selectedPacket.id <= packets[packets.length - 1].id;
    } else {
      visible = false;
      for (let i = filteredPackets.length - 1; i >= 0; i--) {
        if (filteredPackets[i].id === selectedPacket.id) { visible = true; break; }
      }
    }
    if (!visible && filteredPackets.length > 0) {
      setSelectedPacket(filteredPackets[filteredPackets.length - 1]);
    }
  }, [filteredPackets, packets, selectedPacket]);

  // The keyboard handler below reads the live list and selection through refs
  // so that it is registered once per open/close of the detail window rather
  // than re-registered on every flush - which, with `filteredPackets` in its
  // dependency list, it was: ten window listener swaps a second for the whole
  // life of a capture.
  /**
   * The buffer, for the paths that need to read it outside a render.
   *
   * The restore loop finishes after many `setPackets` calls and then wants the
   * whole result. Reading it from inside a state updater would work and is
   * wrong: an updater must be pure, because StrictMode invokes it twice.
   */
  const packetsRef = useRef(packets);
  packetsRef.current = packets;
  const filteredPacketsRef = useRef(filteredPackets);
  filteredPacketsRef.current = filteredPackets;
  const selectedPacketRef = useRef(selectedPacket);
  selectedPacketRef.current = selectedPacket;

  // Window-level keyboard shortcuts - see hooks/useKeyboardNavigation.ts.
  useKeyboardNavigation({
    detailPacketId,
    canCapture: permissions.canCapture,
    filteredPacketsRef,
    selectedPacketRef,
    isCapturingRef,
    packetCountRef,
    selectedInterfacesRef,
    setIsCapturing,
    setSelectedPacket,
    sendAgentCommand,
  });

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
  /**
   * Starts a capture, and gives it a stored session of its own.
   *
   * The clear is the point. Before it, starting a capture wrote into whatever
   * the last one had left on disk: `handleClearPackets` rewinds the frame
   * numbering to 1 (`pipeline.reset(1)`) and the store keys frames by id, so
   * the new capture overwrote the old one's frames 1..N by `put` while
   * everything above N stayed exactly where it was. Nothing deleted it -
   * `resetWriteQueue` is reachable only from Discard, and
   * `prepareStoredSession` says in as many words that it performs no automatic
   * deletion - and a restore reads the whole store back. So a refresh after a
   * short second capture returned that capture *plus the tail of the previous
   * one*, interleaved and indistinguishable.
   *
   * This does not weaken `docs/decisions/0012`. That decision is that a stored
   * capture survives until the user asks; Clear View alone still keeps it, and
   * still says so. Starting a NEW capture is the asking - the button that does
   * it is labelled "Start a new capture, discarding the current one" and
   * confirms first.
   *
   * Awaited before the agent is told to start, so the store is empty before any
   * frame can be written to it. `clearSession` drops the pending write queue
   * synchronously for the same reason, so nothing already queued can land after
   * the clear and resurrect part of the previous capture.
   */
  const handleStartCapture = async () => {
    setBufferAutoPaused(false);
    clearCaptureStats();
    await clearSession();
    // Wall-clock, and NOT `captureStartRef`: that one holds the first packet's
    // capture time, so on a quiet adapter it stays null for as long as the
    // network is silent. A scheduled duration has to measure from the moment
    // the capture was asked for, or "capture for 5 minutes" on an idle link
    // would never end.
    captureStartedAtRef.current = Date.now();
    // One Start->Stop cycle is one capture on disk. Started here rather than on
    // the first frame so that an adapter that stays silent still produces a
    // capture directory - "you captured nothing" and "the store never opened"
    // are different facts and the panel has to be able to tell them apart.
    captureIdRef.current = newCaptureId();
    captureStore.begin(captureIdRef.current);
    // The previous capture's directory goes here, once the new one exists.
    // `clearSession` above has just forgotten the metadata that pointed at it,
    // so nothing could reach it again - and this is the same rule Start has
    // always had, which used to be spelled `clearSession` wiping the frames
    // out of IndexedDB.
    captureStore.prune([captureIdRef.current]);
    sendAgentCommand({ type: 'start_capture' });
    setIsCapturing(true);
  };

  const handlePauseCapture = () => {
    sendAgentCommand({ type: 'stop_capture' });
    setIsCapturing(false);
    captureStartedAtRef.current = null;
    // Seals the staging ring and flushes. Pause is one of the two moments the
    // whole capture is guaranteed to be on disk, and the user asked for that
    // explicitly - the other is stop.
    captureStore.finish();
  };

  /**
   * The program behind a frame's Source column, or null.
   *
   * Stable across renders, so the list is not handed a new function every time
   * anything else in this component changes. It reads the store rather than
   * closing over a value, which is what lets a row pick up an attribution that
   * arrived after the frame itself did.
   */
  const sourceProcessFor = useCallback(
    (packet: Packet) => sendingProcessName(packet, flowAnnotations),
    [],
  );

  const handleClearPackets = () => {
    setBufferAutoPaused(false);
    packetGenerator.reset();
    // The geo map's session describes traffic that is about to stop existing.
    // This is the one case where its deliberately monotonic place count should
    // go back to zero.
    resetGeoSession();
    // The trackers, the ordering window and the frame numbering all live in
    // the pipeline Worker now; one message forgets the lot. Without it the TCP
    // tracker would keep describing streams from a capture that no longer
    // exists, and the next frame would be numbered after frames that are gone.
    adoptBuffer([], 0);
    pipeline.reset(1);
    // Clearing the buffer is the only way a fresh capture begins, so this is
    // where the relative-time clock resets. captureStartRef === null is then
    // a reliable, side-effect-free "this is the first packet of a capture"
    // test in the live-packet handler.
    captureStartRef.current = null;
    lastPacketTimeRef.current = null;
    // The Worker forgets its copy on the same reset message. Keeping this one
    // would let a local port reused since the last capture be attributed to
    // whatever held it during a capture that is no longer on screen.
    flowAnnotations.clear();
    // The stored capture is deliberately NOT cleared here. Clearing the view
    // frees the memory the buffer is holding; it is not a request to destroy
    // the capture, and it used to be treated as one - so a user who cleared the
    // screen to get some room back also silently lost the ability to export
    // what they had captured. Discarding is its own action
    // (`handleDiscardCapture`), named as what it does
    // (docs/decisions/0012-stored-captures-persist.md).
    setSelectedPacket(null);
    setActiveByteRange(null);
  };

  /**
   * Throws the stored capture away, for good.
   *
   * The only thing in the app that deletes captured bytes from disk. Nothing
   * does it automatically any more - not closing the last window, not reopening
   * the app, not clearing the view - so this is the whole of the exit
   * (docs/decisions/0012-stored-captures-persist.md).
   */
  const handleDiscardCapture = useCallback(async () => {
    await clearSession();
    setSelectedPacket(null);
    setActiveByteRange(null);
    // The Worker's trackers describe streams from a capture that no longer
    // exists, and the next frame must not be numbered after frames that are
    // gone - the same reset Clear does.
    adoptBuffer([], 0);
    pipeline.reset(1);
    captureStartRef.current = null;
    lastPacketTimeRef.current = null;
    accountingRef.current.persistedThroughId = 0;
    flowAnnotations.clear();
    // The capture on disk goes with it. Discard is still the only thing in the
    // app that deletes stored frames, which is ADR 0012's rule and survives
    // this work unchanged.
    if (captureIdRef.current !== null) {
      captureStore.discard(captureIdRef.current);
      captureIdRef.current = null;
    }
    setCaptureStorage(freshCaptureStorageState());
  }, []);

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

  /**
   * "Apply as Filter" / "Prepare as Filter" from a row of the detail tree.
   *
   * Prepare puts the expression in the bar and leaves it there, which is the
   * whole point of having both: a filter built from three or four rows is
   * assembled one "…and Selected" at a time, and re-running the list after
   * each of them would throw away the rows the next one is picked from.
   */
  const handleFieldFilter = useCallback((expression: string, apply: boolean) => {
    setFilterText(expression);
    if (apply) setAppliedFilter(expression);
  }, []);

  /** "Apply as Column" - appends to the packet list's added-field columns. */
  const handleAddColumn = useCallback((abbrev: string) => {
    const prefs = packetListStore.get();
    if (prefs.customColumns.includes(abbrev)) return;
    packetListStore.set({
      ...prefs,
      customColumns: [...prefs.customColumns, abbrev].slice(0, MAX_CUSTOM_COLUMNS),
    });
  }, []);

  // Hoisted out of the aside's JSX for the same reason. The width check is the
  // one the mobile layout uses to follow a selection into the detail tab.
  const handleInspectFromDashboard = useCallback((pkt: Packet) => {
    setSelectedPacket(pkt);
    if (window.innerWidth < 768) setMobileTab("tree");
  }, []);


  /**
   * Opens the stream window, on whichever of its two views was asked for.
   *
   * "Follow stream" and "Show conversation" are the same window with a
   * different question in mind - content against shape - so the view is a
   * parameter rather than a second modal that would drift out of step.
   */
  const handleFollowStream = (
    target: StreamTarget, view: 'dialogue' | 'ladder' = 'dialogue',
  ) => {
    setStreamToFollow(target);
    setStreamView(view);
  };

  const handleImportPackets = (imported: Packet[]) => {
    setIsCapturing(false);
    // The same reset Clear does, and for the same reasons. Imported frames are
    // numbered 1..N by buildPacketsFromFrames; without this the Worker's
    // counter is untouched, so pressing Start after an import issues live
    // frames with ids the imported ones already hold - and every id lookup in
    // the app (Response In, the reassembly patches, the list's React keys)
    // then has two frames to choose from. It also drops the previous
    // capture's TCP/TLS/QUIC/DNS tracker state, which describes streams that
    // are no longer in the buffer.
    const lastId = imported.length > 0 ? imported[imported.length - 1].id : 0;
    // `adoptBuffer` counts what the imported frames actually cost. Setting the
    // total to zero and leaving it - which is what happened before - reported a
    // full buffer as empty and stopped it trimming: `planBufferTrim` reads that
    // number, so an import of a million frames sat over budget until enough
    // live frames had arrived to rebuild a total from scratch.
    //
    // `null` keeps `persistedThroughId` where it was, which is what this call
    // site has always done - unlike Clear and Discard, which reset it to 0.
    adoptBuffer(imported, null);
    pipeline.reset(Math.floor(lastId) + 1);
    captureStartRef.current = null;
    lastPacketTimeRef.current = null;
    // Always assigned, never left alone: a selection held over from the
    // previous buffer would keep the tree and hex views showing a frame that
    // is not in the list any more.
    setSelectedPacket(imported.length > 0 ? imported[0] : null);

    deriveForBuffer(imported);
  };

  /**
   * Decides direction, and collects what the capture reveals, for a whole
   * buffer that arrived at once.
   *
   * Both paths that fill the buffer without going through the Worker need
   * this: an **import**, and a **restored session**. Neither can decide
   * direction while it is dissecting - an imported file has no agent to ask
   * who took it, and the scoring that answers that needs the very frames the
   * dissection is producing - so it is a second pass over the finished buffer.
   *
   * Cheap, because it re-dissects nothing: it reads back the `eth.src` and
   * `eth.dst` dense columns and assigns a property. Chunked between animation
   * frames, because a synchronous pass over a full buffer is the stall ADR
   * 0015 recorded.
   */
  const deriveForBuffer = useCallback((frames: Packet[]) => {
    rederiveRef.current?.();
    rederiveRef.current = null;
    if (frames.length === 0) return;

    // A measured identity beats a scored one, and it is the common case: a
    // session restored - or a file imported - on the machine that captured it.
    const known = !hostIdentityRef.current.inferred && hostIdentityRef.current.macs.size > 0;
    let host = hostIdentityRef.current;
    if (!known) {
      const inferred = inferHostIdentity(frames);
      // NO_HOST rather than bailing out: the gateway needs a host to be sure
      // of, but the router advertisement, the DHCP server and the LLDP
      // neighbour are facts about the segment and do not.
      host = inferred ?? NO_HOST;
      hostIdentityRef.current = host;
      // The Worker too, and not as bookkeeping: it is what rebuilds the detail
      // tree on demand (`pipeline/replay.ts`), and a replay that does not know
      // whose machine this is decides `Bad checksum` where the summary decided
      // `Unverified`. Without this line an imported capture's tree contradicts
      // the row that opened it - only for frames the machine sent, which is
      // the half a reader is least likely to doubt.
      pipeline.setHost(host);
    }

    const collector = new NetworkFactsCollector();
    rederiveRef.current = rederiveDirections(frames, host, () => {
      rederiveRef.current = null;
      setNetworkFacts(collector.snapshot());
      // A new array, because the frames were mutated in place: React compares
      // by identity and would otherwise not re-read a single row. The frames
      // themselves are the same objects, which is the point - every cache in
      // the app keyed on frame identity survives this.
      setPackets((prev) => prev.slice());
    }, (packet, forHost) => collector.observe(packet, forHost));
  }, []);

  /**
   * Called by the Custom Dissectors modal after every edit.
   *
   * It has nothing to do, and that is a gap rather than a design: it used to
   * hand the engine to `PacketGenerator`, which never read it, and **nothing
   * else in the app consults `CustomDissectorEngine` either** - no dissection
   * path asks it about a frame. So the modal edits and stores rules that are
   * never applied. Left wired rather than deleted, because this is the seam a
   * working implementation would push through; the engine itself and its
   * storage are untouched.
   */
  const handleUpdateDissectors = () => {};

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
      onFilterHost: handleFilterHost,
      onInspectPacket: handleInspectFromDashboard,
    }),
    [
      dashboardPackets,
      isDark,
      resolvedTheme,
      isCapturing,
      appliedFilter,
      handleSelectProtocol,
      handleFilterHost,
      handleInspectFromDashboard,
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
          captureOwnedElsewhere={captureOwner !== null && captureOwner !== agentClientId}
          onInterfacePickerOpenChange={handleInterfacePickerOpenChange}
          schedule={schedule}
          onScheduleChange={setSchedule}
          schedulePresets={schedulePresets}
          onSchedulePresetsChange={setSchedulePresets}
          // Recomputed on the hook's own tick, which is what makes the
          // countdown advance without this component owning a timer.
          scheduleSummary={describeSchedule(
            schedule, scheduleNow, isCapturing, captureStartedAtRef.current,
            (epochMs) => new Date(epochMs).toLocaleString(undefined, {
              month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
            }),
          )}
          scheduleNow={scheduleNow}
          bufferedPackets={packets.length}
          permissions={permissions}
          onOpenDissectorModal={() => setShowDissectorModal(true)}
          onOpenExportModal={() => setShowExportModal(true)}
          onOpenStatisticsModal={() => setShowStatisticsModal(true)}
          nameResolution={nameResolution}
          onNameResolutionChange={patchNameResolution}
          onOpenNetworkModal={() => setShowNetworkModal(true)}
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
          agentHealth={agentHealth}
          totalPacketsCount={packets.length}
          restoreProgress={restoreProgress}
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
              // The tour highlights the pane rather than a row: it runs before
              // there are any rows. See components/tour/tourSteps.
              data-tour="list"
              className={`flex-1 flex flex-col min-h-0 overflow-hidden ${
                mobileTab === "packets" ? "block" : "hidden md:flex"
              }`}
            >
              <PacketList
                names={nameMap}
                resolveNames={nameResolution.network}
                sourceProcess={sourceProcessFor}
                packets={filteredPackets}
                // Whether the list may address the whole capture. A display
                // filter runs over the RAM window and only the window, so the
                // rows below it are not this list's rows while one is applied.
                // `filteredPackets === packets` is the same identity check the
                // selection-visibility effect above uses.
                unfiltered={filteredPackets === packets}
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
                // So a filter that finds nothing can say whether it searched
                // the capture or only what is left of it.
                droppedBuffer={droppedBuffer}
                colorEngine={colorEngine}
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
                // On the container, not inside PacketDetailsTree - that renders
                // two different trees for "a packet" and "no packet", and the
                // tour needs one anchor that exists in both states.
                data-tour="detail"
                className={`w-full min-w-0 overflow-hidden md:shrink-0 ${
                  stacked
                    ? "md:w-full md:h-[var(--details-pane-size)]"
                    : "md:w-[var(--details-pane-size)] h-full"
                } ${mobileTab === "tree" ? "block" : "hidden md:block"}`}
              >
                <PacketDetailsTree
                  packet={selectedPacketDetail}
                  accentColor={selectedPacketAccent}
                  onHoverByteRange={setActiveByteRange}
                  onSelectFrame={goToFrame}
                  activeByteRange={activeByteRange}
                  onFieldFilter={handleFieldFilter}
                  currentFilter={filterText}
                  onAddColumn={handleAddColumn}
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
                  packet={selectedPacketDetail}
                  bytesState={selectedDetailState}
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
          target={streamToFollow}
          packets={packets}
          onClose={() => setStreamToFollow(null)}
          initialTab={streamView}
          selectedId={selectedPacket?.id}
          // The window stays open. Selecting a frame from in here is usually
          // one of several - reading down a conversation and checking each
          // against the tree - and closing on the first would make that a
          // dozen round trips through the context menu.
          onSelectFrame={goToFrame}
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
            onShowFrame={showFrameInWindow}
            onFollowStream={handleFollowStream}
            colorEngine={colorEngine}
            packetTheme={packetTheme}
            permissions={permissions}
            obscured={streamToFollow !== null}
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
            // The modal derives its own filtered set from the full buffer above
            // rather than being handed `filteredPackets`: its filter is
            // editable independently of the main window's, and the deliberate
            // "export sees the live buffer, never dashboardPackets" rule stays
            // intact either way.
            appliedFilter={appliedFilter}
            filterPresetLibrary={filterPresetLibrary}
            // For the pcapng file's Interface Statistics Block: what the
            // driver and the agent dropped. A file that does not say it is
            // incomplete reads as complete.
            captureStats={captureStats}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showStatisticsModal && (
          <StatisticsModal
            key="statistics-modal"
            // The whole buffer, not `filteredPackets`: these tables count the
            // capture. A filter narrows what is being LOOKED at, and a
            // conversation table that silently answered for a subset would be
            // the same table with different numbers and no way to tell.
            packets={packets}
            names={nameMap}
            resolveNames={nameResolution.network}
            resolvePorts={nameResolution.transport}
            expert={expertLog}
            onApplyFilter={handleQuickFilter}
            onFollowStream={handleFollowStream}
            onSelectFrame={goToFrame}
            // What the tables could not count. The buffer is the capture until
            // it fills, and silently stops being it after that.
            droppedBuffer={droppedBuffer}
            onClose={() => setShowStatisticsModal(false)}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showNetworkModal && (
          <NetworkModal
            key="network-modal"
            onClose={() => setShowNetworkModal(false)}
            adapters={adapters}
            facts={networkFacts}
            captureInterfaces={selectedInterfaces}
            agentConnected={agentStatus === 'connected'}
            onRefresh={() => sendAgentCommand({ type: 'refresh_adapters' })}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showSettingsModal && (
          <SettingsModal
            key="settings-modal"
            onClose={() => setShowSettingsModal(false)}
            agentLinkEnabled={agentLinkEnabled}
            agentHealth={agentHealth}
            onStartAgentService={startAgentService}
            agentError={agentError}
            onConnectAgent={handleConnectAgent}
            onDisconnectAgent={handleDisconnectAgent}
            onRestartAgent={handleRestartAgent}
            agentStatus={agentStatus}
            agentVersion={agentVersion}
            agentOutdated={agentOutdated}
            agentCaptureState={agentCaptureState}
            agentInterfaces={agentInterfaces}
            captureStats={captureStats}
            droppedBuffer={droppedBuffer}
            linkContext={linkContext}
            linkChanges={linkChanges}
            selectedInterfaces={selectedInterfaces}
            agentLog={agentLog}
            onSubscribeAgentLog={subscribeAgentLog}
            onUnsubscribeAgentLog={unsubscribeAgentLog}
            onClearAgentLog={clearAgentLog}
            totalPacketsCount={packets.length}
            totalBytes={totalBytes}
            packetBufferBytes={packetBufferBytes}
            // Read off the ref during render rather than mirrored into state:
            // `packets` changes on every flush, so this render is the one that
            // follows each change and the ref is current by then. A state copy
            // would be a second thing to keep in step for a number only Driver
            // Info reads.
            bufferResidentBytes={residentBytes()}
            bufferAutoPaused={bufferAutoPaused}
            onClearPackets={handleClearPackets}
            captureStorage={captureStorage}
            onDiscardCapture={handleDiscardCapture}
            colorRules={colorRules}
            onColorRulesChange={setColorRules}
            packetTheme={packetTheme}
            permissions={permissions}
            filterPresetLibrary={filterPresetLibrary}
            onFilterPresetLibraryChange={handleFilterPresetLibraryChange}
          />
        )}
      </AnimatePresence>

      {/* A jump that could not happen, said out loud.
          Bottom-centre and above the modals, because the click that triggers
          it can come from inside one - the detail window's tree links point at
          frames the buffer may since have trimmed. It never takes the pointer:
          the notice explains a refusal, it does not ask for anything. */}
      {navNotice !== null && (
        <div
          role="status"
          aria-live="polite"
          className="pointer-events-none fixed bottom-6 left-1/2 -translate-x-1/2 z-[100] max-w-md px-3.5 py-2 rounded-md border border-amber-500/40 bg-amber-500/95 dark:bg-amber-950/95 backdrop-blur-sm shadow-lg text-[11px] font-mono leading-snug text-amber-950 dark:text-amber-200 flex items-start gap-2"
        >
          <TbAlertTriangle className="w-4 h-4 shrink-0 mt-px" />
          <span>{navNotice}</span>
        </div>
      )}

      {/* Outside the AnimatePresence above: the tour is not one of the modals
          that swap in and out of it, and being listed there would make opening
          any modal unmount it part-way through a step. */}
      {!tour.completed && (
        <TourOverlay onDone={() => tourStore.set({ completed: true })} />
      )}
    </div>
  );
}
