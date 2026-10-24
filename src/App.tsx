/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { useTheme } from "next-themes";
import { useSystemThemePreference } from "./lib/useSystemTheme";
import { useMotionPreference } from "./lib/motion";
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
import { summaryIsTarget, targetForPacket, type StreamTarget } from "./services/followStream";
import { ExpertLog, expertSnapshot } from "./services/expertInfo";
import { useIncrementalAggregate } from "./lib/useIncrementalAggregate";
import { useWindowOrdinal } from "./lib/useWindowOrdinal";
import { useCaptureFilter, uncoveredRows } from "./lib/useCaptureFilter";
import { matchesOnDisk } from "./lib/captureRowSpace";
import { MAX_CUSTOM_COLUMNS } from "./lib/packetColumns";
import { usePreferenceStore, usePreferenceValue } from "./services/preferenceStore";
import {
  captureOptionsStore, effectiveFilter, filterBlocksStart, filterVerdict, recordOf, ringProblem, startCaptureCommand,
} from "./services/captureOptions";
import { keptFiles, stopReasonText } from "./services/captureFiles";
import { packetColorSetStore } from "./services/themePrefs";
import { resetGeoSession } from "./components/analytics/geoSession";
import { publishPacketCounts } from "./services/packetCounts";
import { GeoMap, warmGeoMap } from "./components/analytics/geoMapLoader";
import { anchorSelection } from "./services/selectionAnchor";
import { startKeyLogFollow } from "./lib/keyLogFollow";
import { selectionLabel, toggleInterface } from "./services/captureInterfaces";
import { ActivityRail } from "./components/common/ActivityRail";
import { TitleRow } from "./components/common/TitleRow";
import { StatusBar } from "./components/status/StatusBar";
import { clearHoveredByte } from "./services/hoveredByte";
import { resetByteRange } from "./services/byteRange";
import {
  useWindowChrome, useWindowTheme, useWindowTitle, windowTitleFor,
} from "./lib/windowChrome";
import {
  APP_VIEWS, backTargetFor, restoredView, viewLabel, viewStore, type AppView,
} from "./services/viewPrefs";
import { isDarkTheme } from "./lib/themeOptions";
import type { CommandContext } from "./lib/commands";
import { captureKeyAction } from "./lib/captureKey";
import { CommandPalette } from "./components/common/CommandPalette";
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
  afterScheduledStop, describeSchedule, EMPTY_SCHEDULE, isScheduleEmpty, scheduleProblem,
  type CaptureSchedule,
} from './services/captureSchedule';
import { useAgentConnection } from './hooks/useAgentConnection';
import { useStreamDigest } from './hooks/useStreamDigest';
import { inferHostIdentity } from './services/hostIdentity';
import { rederiveDirections } from './services/redirect';
import { emptyNetworkFacts, NetworkFactsCollector, type NetworkFacts } from './services/networkFacts';
import { watchLinkChanges, type LinkChange } from './services/linkContext';
import { processForPacket, sendingProcessName, writeProcessFields } from './services/dissect/processFields';
import { fieldValue } from './services/dissect/fieldAccess';
import { LINKTYPE } from './services/dissect/types';
import { filterIncrementally, type FilterCache } from "./services/incrementalFilter";
import { PATCH_LOG } from "./services/patchLog";
import {
  clearSession,
  loadSessionMeta,
  saveSessionMeta,
  type SessionMeta,
} from "./services/sessionStore";
import { ColorRulesEngine, DEFAULT_COLOR_RULES } from "./services/colorRules";
import {
  isAgentMismatched, REQUIRED_AGENT_VERSION, type AgentMessage,
} from "./services/agentProtocol";

// UI Components
import { FilterBar } from "./components/common/FilterBar";
import { PacketList } from "./components/packet-list/PacketList";
import { LinkedDetailsTree, LinkedHexViewer } from "./components/packet-details/LinkedDetailPanes";
import { PacketDetailPane } from "./components/packet-details/PacketDetailPane";
import { StreamFollowerPane } from "./components/stream-follower/StreamFollowerPane";
import { findPacketIndexById, frameJumpRefusal } from "./components/packet-details/packetDetailModel";
import { StatisticsPane } from "./components/statistics/StatisticsPane";
import { SettingsPane } from "./components/common/SettingsPane";
import { SpeedTestSheet } from "./components/speedtest/SpeedTestSheet";
import { MonitoringSheet } from "./components/monitoring/MonitoringSheet";
import { NetworkPane, NetworkPanelActions } from './components/network/NetworkPane';
import { SideBar } from './components/sidebar/SideBar';
import { CaptureInterfacePanel } from './components/sidebar/CaptureInterfacePanel';
import { CaptureSchedulePanel } from './components/sidebar/CaptureSchedulePanel';
import { TransferPanel } from './components/sidebar/TransferPanel';
import {
  MAIN_RESERVE_PX, MAX_SIDE_BAR_PX, MIN_SIDE_BAR_PX, restoredPanel, SIDE_BAR_DEFAULTS, sideBarStore,
  usableSideBarWidth, type SideBarPanel,
} from './services/sideBarPrefs';
import {
  FILTER_PRESETS_STORAGE_KEY,
  addPreset,
  allPresets,
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
import type { FrameRecordEntry } from "./services/pcapParser";
import { DerivedStore, derivedBudgetFor } from "./services/pipeline/derivedStore";

import { TriangleAlert } from "lucide-react";
import { FieldBlockWriter } from './services/dissect/fieldSplit';
import { currentBufferBudget, estimateSummaryBytes } from './services/bufferBudget';
import { startRendererHeapGuard } from './services/rendererHeapGuard';
import { captureStore, newCaptureId } from './services/capture/captureClient';
import { freshCaptureStorageState, type CaptureStorageState } from './services/capture/captureProtocol';
import { shouldCheckOnLaunch, updateStore } from './services/updatePrefs';
import type { CaptureSource } from './services/export/captureMeta';
import type { CaptureFileFacts } from './services/captureFileFacts';
import { cancelExportForChange, cancelExportJob } from './services/export/exportJob';
import { FilterEngine } from './services/filterEngine';
import { pushRecentFilter, recentFiltersStore } from './services/recentFilters';

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
/**
 * How long typing pauses before the agent is asked whether the capture filter
 * compiles. Long enough that a filter typed at speed is asked about once;
 * short enough that the answer is there by the time the eye leaves the field.
 * A hostname in a filter is resolved by libpcap as it compiles, so this is
 * also what keeps half-typed names from each costing a DNS lookup.
 */
const CAPTURE_FILTER_CHECK_DELAY_MS = 400;

const DISPLAY_FILTER_KEY = "inwire.displayFilter";
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
  // The first-run walkthrough. `completed` is set by finishing it AND by
  // skipping it - see services/tourPrefs for why skipping counts.
  const [tour] = usePreferenceValue(tourStore);
  usePreferenceSync(tourStore.key, tourStore.normalize, tourStore.accept);
  // Pushes the two outbound-lookup switches into the service that performs
  // them, so the gate lives in one place rather than at every call site.
  // Read-only here now: the two passive switches moved into
  // Settings -> Interface with the menu that used to hold them, and that panel
  // patches the store itself. App still READS all four - they decide what the
  // list and the tables show.
  const [nameResolution] = useNameResolutionPreference();

  const { resolvedTheme } = useTheme();
  // Resolves the "System" picker entry into a concrete theme, and keeps
  // resolving it when the OS setting changes.
  useSystemThemePreference();
  // And tells main, which caches the ground the NEXT window opens on. Sends the
  // RESOLVED name: "system" is a rule, not a palette.
  useWindowTheme(resolvedTheme);
  // Maximized and focused are facts only main is told, and a window drawing its
  // own title bar has to draw what the frame used to.
  const { focused: windowFocused, maximized: windowMaximized } = useWindowChrome();
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

  /* **Two media queries stood here - "has the analytics column room?" and "has
     its icon rail room?" - and both are gone with the column.** They had already
     outlived their declarations and were documenting nothing.

     What survives them is the rule they were enforcing, and it is enforced by
     the component tree now rather than by a breakpoint: **hidden is not the same
     as not rendered**, because every summary surface is a full pass over the
     packet buffer when its input changes. So Statistics, the Routing Map and
     Frame Detail are unmounted unless their view is active - see the JSX below,
     where each says so - and the packet list is the deliberate exception,
     because its scroll offset and selection are worth more than the renders.
     That is a stronger guarantee than a media query, which only ever decided
     whether to mount a column that no longer exists. */

  // Stream & Capturing State
  const [isCapturing, setIsCapturing] = useState(false);
  /**
   * Where the frames in the buffer came from, for what an export says about
   * itself. Set where the buffer changes owner - Start, an import, a restore -
   * and read only by the Export panel. State rather than a ref because that
   * panel renders it, and it changes a handful of times a session, never per
   * flush.
   */
  const [captureSource, setCaptureSource] = useState<CaptureSource>({ kind: 'session' });

  // --- the packet buffer ----------------------------------------------------
  //
  // Hoisted above everything that reads `packets`, which is most of this file.
  // The pieces it needs come first for the same reason.
  // Named `perf`, not `performance`: the latter shadows the global timing API,
  // which is exactly the sort of shadowing that is fine until somebody adds a
  // `performance.now()` in this scope and gets a confusing type error.
  const [perf] = usePreferenceStore(performanceStore);
  usePreferenceSync(performanceStore.key, performanceStore.normalize, performanceStore.accept);
  const { packetBufferBytes: bufferSetting, dashboardRefreshMs, dissectionThreads } = perf;
  // The Worker holds it until the next capture starts (ADR 0053 phase 3).
  useEffect(() => {
    pipeline.setThreads(dissectionThreads);
  }, [dissectionThreads]);
  /**
   * The setting resolved to a number of bytes.
   *
   * `'auto'` is a stored preference, so everything downstream of here - the
   * buffer, the import cap, the settings panel's own "about N packets" line -
   * needs the figure it resolves to on THIS machine. Resolved once, here,
   * rather than at each of those, so they cannot disagree.
   *
   * `useMemo` with the setting as its only dependency: the two host facts are
   * fixed for the life of the window (V8's heap limit is set when the isolate
   * is created and the machine's RAM does not change under us), so re-reading
   * them per render would buy nothing.
   */
  const packetBufferBytes = useMemo(
    () => currentBufferBudget(bufferSetting), [bufferSetting],
  );
  // The Worker's store of decrypted answers is sized from the same budget, so
  // a frame's decrypted tree stays rebuildable about as long as the frame
  // stays in reach (ADR 0049).
  const derivedBudgetRef = useRef(derivedBudgetFor(packetBufferBytes));
  useEffect(() => {
    derivedBudgetRef.current = derivedBudgetFor(packetBufferBytes);
    pipeline.setDerivedBudget(derivedBudgetRef.current);
  }, [packetBufferBytes]);
  // Track the latest isCapturing value for the always-on agent connection
  // below, whose handlers are set up once and must not go stale.
  const isCapturingRef = useRef(isCapturing);
  useEffect(() => {
    isCapturingRef.current = isCapturing;
  }, [isCapturing]);

  /**
   * The one update check the app makes without being asked - and only if it
   * was asked once, in advance, and told yes.
   *
   * Read straight from storage rather than through a hook, because this must
   * run once and a subscribed value would re-run it when the switch is
   * flipped. `shouldCheckOnLaunch` is what decides; note it requires `asked`,
   * so silence is never consent.
   */
  useEffect(() => {
    if (!shouldCheckOnLaunch(updateStore.get())) return;
    void window.inwire?.checkForUpdates?.().catch(() => {});
  }, []);

  /**
   * Pull the map's chunk in once the app is idle.
   *
   * `GeoMap` is lazy now - maplibre-gl and `three` are the largest thing that
   * used to sit in the eager chunk, behind a rail button most launches never
   * press. Warming rather than waiting for the click is the whole design;
   * `geoMapLoader.tsx` has the argument, which is that MapLibre's worker pool
   * is acquired at that module's scope and must not spawn in front of the
   * map's own network path.
   */
  useEffect(() => {
    warmGeoMap();
  }, []);

  /**
   * Start receiving the followed TLS key log, if one was chosen.
   *
   * Here and not in the Decryption panel, because the panel only exists while
   * Settings is open and a follow that only ran while somebody was looking at
   * it would decrypt nothing. `lib/keyLogFollow.ts` has the rest.
   */
  useEffect(() => {
    startKeyLogFollow();
  }, []);

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

  /**
   * What the renderer's heap guard has said, or null.
   *
   * **The renderer had no heap guard at all until this**, which is what kept
   * the packet buffer capped at a number nobody could reach rather than at the
   * number that is actually dangerous. The store has had one since it was seen
   * to die at 4,060 MB (`electron/store/heapGuard.ts`); this is the same
   * watchdog in the process that holds the buffer, and it is what makes 'auto'
   * safe to ship. See `services/rendererHeapGuard.ts`.
   */
  const [heapNotice, setHeapNotice] = useState<string | null>(null);
  useEffect(() => startRendererHeapGuard({
    onWarn: setHeapNotice,
    onStop: (message) => {
      setHeapNotice(message);
      // The same stop the buffer's own auto-pause uses. Reusing it rather than
      // stopping the capture a second way is the point: there is one path out
      // of a running capture, and it already tells the agent.
      autoPauseRef.current();
    },
  }), []);
  const pipelineRowsTaken = useCallback((rows: number) => pipeline.rowsTaken(rows), []);
  const onFramesQueued = useCallback((firstTsUs: number, lastTsUs: number) => {
    if (captureStartRef.current === null) captureStartRef.current = firstTsUs;
    lastPacketTimeRef.current = lastTsUs;
  }, []);

  const {
    packets, setPackets, droppedBuffer, bufferAutoPaused, setBufferAutoPaused,
    queueFrames, adoptBuffer, residentBytes, budgetBytes, accountingRef, fieldWriter, flushNow,
    dropBelow,
  } = usePacketBuffer({
    packetBufferBytes, isCapturingRef, onAutoPause, onFramesQueued, onRowsTaken: pipelineRowsTaken,
  });


  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  /** Which view the stream pane opens on - see handleFollowStream. */
  const [streamView, setStreamView] = useState<'dialogue' | 'ladder'>('dialogue');
  /**
   * The frame the stream was entered from, so leaving can land back on it.
   *
   * An id rather than the packet, for the same reason the restored selection is:
   * the object is a fresh one decoded from bytes on the way back in, and only its
   * number survives. Null when a stream was opened with nothing selected, which a
   * conversation table can do.
   */
  const [streamOrigin, setStreamOrigin] = useState<number | null>(null);
  // Stored as an id, not the packet: the object a refresh restores is a fresh
  // one decoded from bytes, so only its number survives the round trip.
  // Zero stands for "nothing selected" and is rejected by the validator.
  useDebouncedPreference(SELECTED_PACKET_KEY, selectedPacket?.id ?? 0);
  const restoreSelectionId = useMemo(
    () => loadPreference(SELECTED_PACKET_KEY, normalizePacketId, null),
    [],
  );
  const selectionRestoredRef = useRef(false);
  /* **Neither the hovered byte nor the highlighted range is state here, and
     they left for different reasons.**

     `hoveredByte` was the one byte under the pointer, DERIVED from
     `activeByteRange` - which the protocol tree also publishes for a one-byte
     field, so the derivation answered "this byte" for a hover in a pane that
     was not the dump. `services/hoveredByte.ts` carries the byte's VALUE
     instead, which only a dump can supply.

     `activeByteRange` was ordinary App state and correct as such: it is the
     cross-highlight between two SIBLING panes, and sibling state belongs in the
     common parent. The common parent is this component, so a pointer moving
     across a large frame's dump re-rendered the whole application once per
     byte. `services/byteRange.ts` has the measurements;
     `components/packet-details/LinkedDetailPanes.tsx` is what subscribes. This
     file is no longer on that path and must not go back onto it. */

  // Filter State
  // Seeded from the last session rather than blank, so a refresh does not
  // silently drop the filter the user was looking through.
  const storedDisplayFilter = useMemo(
    () => loadPreference(DISPLAY_FILTER_KEY, normalizeDisplayFilter, { filterText: "", appliedFilter: "" }),
    [],
  );
  const [filterText, setFilterText] = useState(storedDisplayFilter.filterText);
  const [appliedFilter, setAppliedFilter] = useState(storedDisplayFilter.appliedFilter);
  useDebouncedPreference(DISPLAY_FILTER_KEY, useMemo(() => ({ filterText, appliedFilter }), [filterText, appliedFilter]));

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
  // **There is no `detailPacketId`.** The detail window held one - a frame of
  // its own, separate from the list's selection, so closing it dropped you back
  // wherever the list had been left. As a view it reads `selectedPacket` like
  // the bottom panes do, which is what makes stepping frames in there move the
  // list too, and what makes leaving for the list and coming back land on the
  // frame you were reading.
  /**
   * Which SHEET is over the workspace, or `null` for none.
   *
   * A sheet takes the workspace card without being a view: it covers what was
   * on screen, the view underneath is untouched, and closing it puts that view
   * back rather than navigating anywhere. It is here for the reason it is not
   * in `APP_VIEWS`: the view list answers "is this a way of looking at the
   * capture?", and nothing in Settings changes when a packet arrives.
   *
   * **There were two and now there is one.** Network was the other, and it is a
   * side bar panel - a surface that sits BESIDE the capture rather than over
   * it, which is what a panel comparing the OS's configuration against the
   * capture's own evidence wanted all along.
   *
   * **It stays a union at one member, rather than becoming a boolean.** With
   * one member the two are isomorphic, so this is a choice: the union is what
   * makes "the card holds exactly one surface" a fact the type carries. A
   * boolean invites a second boolean beside it, which makes "both open"
   * representable in a card that can show one, and every navigation that closes
   * a sheet would then have to remember to close both. That argument was won
   * once; a union is what stops it being re-litigated by an edit.
   */
  const [sheet, setSheet] = useState<'settings' | 'speedtest' | 'monitoring' | null>(null);
  const sheetOpen = sheet !== null;

  /**
   * The command palette (ADR 0057): the text it opened with, or null when it
   * is closed. Ctrl+K opens it empty, Ctrl+Shift+P on `>`, Ctrl+G on `:`.
   * `n` counts requests, so the same chord pressed again while it is open
   * still resets text the user has typed since.
   */
  const [palette, setPalette] = useState<{ text: string; n: number } | null>(null);
  const openPalette = useCallback(
    (text: string) => setPalette((p) => ({ text, n: (p?.n ?? 0) + 1 })),
    [],
  );
  /** The display filter's input, for Ctrl+/ and the palette. */
  const filterInputRef = useRef<HTMLInputElement | null>(null);
  const [recentFilters] = usePreferenceValue(recentFiltersStore);

  /**
   * Which of the five surfaces the rail says we are on.
   *
   * Persisted, and `restoredView` decides what is resumable - `stream` is a
   * legal stored value and is not a restorable one, because the conversation it
   * pointed at lived in a buffer that is being rebuilt.
   *
   * **All four non-Packets views are real panes now**, rendered as siblings of
   * the packet list in the row below. They were modals opened by an effect
   * keyed on this value, which was a deliberate intermediate step: routing the
   * rail through a view id first meant the conversion changed only what the JSX
   * renders and nothing here. That is why this block did not move when they
   * landed, and it is the argument for not wiring a future view straight to a
   * boolean.
   */
  const [viewPrefs, patchViewPrefs] = usePreferenceStore(viewStore);
  usePreferenceSync(viewStore.key, viewStore.normalize, viewStore.accept);
  const [view, setViewState] = useState<AppView>(() => restoredView(viewPrefs.view));
  const setView = useCallback((next: AppView) => {
    setViewState(next);
    patchViewPrefs({ view: next });
  }, [patchViewPrefs]);

  /**
   * The side bar: which panel is in the column beside the workspace.
   *
   * Wired exactly like `view` above, and for the same reason - persisted, with
   * a `restored*` seam deciding what a fresh window may resume. One slot, for
   * the reason `sheet` has one: the column holds one panel, so two flags would
   * make "both open" representable in a place that cannot show both.
   *
   * **Orthogonal to `sheet`, deliberately.** `sheet` answers what is IN the
   * workspace card; this answers what is BESIDE it. So a panel may be open
   * while Settings has the card, and that is not a tolerated side effect - it
   * is the thing that proves the side bar is a place rather than a sheet.
   */
  const [sideBarPrefs, patchSideBar] = usePreferenceStore(sideBarStore);
  usePreferenceSync(sideBarStore.key, sideBarStore.normalize, sideBarStore.accept);
  /**
   * Which panel, and whether it is showing - two facts, deliberately.
   *
   * They were one: `null` meant closed. That destroyed the record of which
   * panel you had been using at the moment you closed it, so `Ctrl+B` - whose
   * entire job is "reopen the last panel" - could only ever fall back to its
   * default. The key remembered a panel across a restart and forgot it across
   * a keystroke.
   */
  const [sideBarPanel, setSideBarPanel] = useState<SideBarPanel>(
    () => restoredPanel(sideBarPrefs.panel),
  );
  const [sideBarOpen, setSideBarOpen] = useState(() => sideBarPrefs.open);
  const sideBar = sideBarOpen ? sideBarPanel : null;

  const showSideBar = useCallback((next: SideBarPanel | null) => {
    if (next === null) {
      setSideBarOpen(false);
      patchSideBar({ open: false });
      return;
    }
    setSideBarPanel(next);
    setSideBarOpen(true);
    patchSideBar({ panel: next, open: true });
  }, [patchSideBar]);

  /**
   * A rail button shows its own panel, opening the column if it is closed, and
   * never closes it. Closing is the title row's toggle and `Ctrl+B` - one
   * control for "is the column there", and the rail only says WHICH panel. It
   * used to toggle, so pressing the lit icon to look again hid the column.
   */
  const openSideBarPanel = useCallback((which: SideBarPanel) => {
    showSideBar(which);
  }, [showSideBar]);

  /**
   * Opens or closes the column, on the panel that was last open - and
   * `interfaces` on a fresh profile, never "nothing". The title row's button
   * and `Ctrl+B` are this one handler.
   */
  const toggleSideBar = useCallback(() => {
    showSideBar(sideBarOpen ? null : sideBarPanel);
  }, [showSideBar, sideBarOpen, sideBarPanel]);

  // **The status bar's byte readout, cleared on a view change.**
  //
  // The packets section is HIDDEN rather than unmounted (`display: none`, so a
  // MapLibre instance and a scroll position survive a detour), which means
  // `HexViewer` stays mounted and its unmount cleanup never fires. A byte
  // hovered just before switching to Frame Detail would otherwise sit in the
  // bar describing a dump nobody is looking at. Chromium does not reliably fire
  // `pointerleave` when an ancestor becomes `display: none`, so the pointer path
  // cannot cover this one.
  //
  // `App` may EXTINGUISH the bar's byte and may never light one - the whole
  // reason this store exists is that the first bottom bar was fed a byte
  // DERIVED up here from a range the protocol tree also published.
  // `scripts/session/status-bar.ts` asserts that asymmetry: `clearHoveredByte`
  // is allowed in this file and `publishHoveredByte` is not.
  useEffect(() => {
    clearHoveredByte('packets-hex');
  }, [view]);

  // **The dock's whole state block was here and is gone.** Two preference keys
  // (`inwire.dock`, `inwire.dashboard`), nine callbacks, and the expanded-widget
  // window - all of it deleted with the dock itself.
  //
  // Where the three widgets went: the geo map is a VIEW now (`view === 'geo'`,
  // and the ONLY place it is mounted - the small copy that briefly sat beside
  // the hex dump is deleted too), and the traffic timeline and
  // the packet-size chart are a tab of the Statistics pane. What none of them
  // needed was a column, an open/closed flag, a pin, a drag-reorder or an
  // overlay - which is most of what this block was.
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
   * What the engine estimates about the link, and every time it changed.
   *
   * Null where a field is not reported rather than zero, which is the whole
   * discipline here: these are Chromium's inferences from its own recent
   * requests, and an absent one must read as "not said" and never as a
   * measurement the capture made. See `services/linkContext.ts`.
   */
  // **There is no `linkContext` state any more, and that is a deletion rather
  // than an oversight.** It held Chromium's own rounded guess at downlink and
  // RTT, and its only reader was Driver Info's "Link (estimated)" row - one
  // rounded estimate among rows of exact counts off the wire, which is the row
  // that teaches you to distrust the others. The CHANGE events are the half
  // worth keeping, and they carry their own before and after.
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
    setLinkChanges((prev) => prev.concat(change).slice(-32));
  }), []);
  // How far a session restore has got, or null when none is running. Drives
  // the filter row's progress readout; also the flag the UI uses to explain why
  // packets are appearing without a capture being started.
  const [restoreProgress, setRestoreProgress] = useState<{ done: number; total: number } | null>(null);
  /**
   * The previous capture, on disk and offered in the empty list rather than
   * loaded at launch. Null once it is reopened, replaced, or there was none.
   */
  const [lastCapture, setLastCapture] = useState<SessionMeta | null>(null);
  const lastCaptureRef = useRef(lastCapture);
  lastCaptureRef.current = lastCapture;
  /** True while `reopenLastCapture` runs, from its first read to its last row. */
  const [reopening, setReopening] = useState(false);
  /** "the capture from Oct 8, 02:23", for the offer and for Start's prompt. */
  const lastCaptureLabel = useMemo(() => {
    if (lastCapture === null) return null;
    const at = new Date(lastCapture.captureStartMs ?? lastCapture.updatedAt);
    const day = at.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const time = at.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    return `the capture from ${day}, ${time}`;
  }, [lastCapture]);


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
   * because the sixteen `permissions.*` reads are where a real one would
   * plug in.
   *
   * **`useMemo` with no deps, on an object whose fields are all literals.**
   * That looks like ceremony and is load-bearing: this is a prop of the memoized
   * hex pane, and a fresh object each render is a changed prop, which defeats
   * the memo on every one of App's ten renders a second during a capture. The
   * empty dep list is the honest description of what it is today, and the
   * moment a real gate arrives it becomes the list of what that gate reads.
   */
  const permissions: Capabilities = useMemo(() => ({
    canCapture: true,
    canExportPcap: true,
    canViewPayloads: true,
    canClearBuffer: true,
  }), []);

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

  /* **The flush handler was here, and the sentence describing it was left
     truncated mid-clause by the edit that moved it** - "A flush of dissected
     frames from the Worker. Queued, not committed: the". Whatever it went on to
     say is not recoverable from this file, and is not invented back here.

     What is certain is where the work went: `queueFrames` in
     `hooks/usePacketBuffer.ts` is the handler now - it is passed to the agent
     hook as `onFrames` below - and the reasoning the fragment was starting on
     survives beside it: a batch is appended and returned from, and one flush
     commits the whole batch in a single state update, which is what keeps
     ingest cost independent of buffer size. */

  /**
   * The link to the local capture agent.
   *
   * Sixteen pieces of state, four refs and five effects used to sit inline
   * here; `hooks/useAgentConnection.ts` holds them now. The four callbacks are
   * the seam: everything the connection has to do to the *buffer* stays on
   * this side, because the buffer is this component's.
   */
  /**
   * What the next capture asks the driver for: a capture filter and a snaplen
   * (`services/captureOptions.ts`, ADR 0050). Read through a ref by every way
   * a capture starts - the rail, Space, a schedule, a reconnect's resync - so
   * none of them can start one with options a render out of date.
   */
  const [captureOptions, patchCaptureOptions] = usePreferenceStore(captureOptionsStore);
  usePreferenceSync(captureOptionsStore.key, captureOptionsStore.normalize, captureOptionsStore.accept);
  const captureOptionsRef = useRef(captureOptions);
  captureOptionsRef.current = captureOptions;

  // `stopCaptureAndSeal`, which needs the agent this hook returns - so the
  // hook is handed a ref to it, assigned below every render.
  const stopCaptureRef = useRef<(tellAgent: boolean) => void>(() => {});
  const agent = useAgentConnection({
    canCapture: permissions.canCapture,
    // The reconnect's resync resumes the SAME capture, so it names the same
    // capture id; the agent writes its files beside the ones already there.
    startCommand: () => startCaptureCommand(captureOptionsRef.current, captureIdRef.current),
    isCapturingRef,
    // The agent ended it - an autostop, every adapter failing, another window
    // stopping it - and this window seals it exactly as its own Stop would.
    onCaptureStopped: () => stopCaptureRef.current(false),
    onFrames: queueFrames,
    onSocketTable: applySocketTable,
    onHostIdentity: (identity) => {
      hostIdentityRef.current = identity;
      pipeline.setHost(identity);
    },
    onNetworkFacts: setNetworkFacts,
  });
  const {
    agentStatus, agentClientId, captureOwner,
    agentHealth, startAgentService,
    agentVersion, agentNpcapAccess, agentIncompatible, agentInterfaces, captureStats, adapters,
    agentLog, agentError, interfaceRates, selectedInterfaces,
    setSelectedInterfaces, selectedInterfacesRef,
    sendAgentCommand, subscribeAgentLog, unsubscribeAgentLog,
    clearAgentLog, clearCaptureStats, setInterfaceStatsSubscribed, captureFilterCheck,
    captureStopReason, captureFiles,
  } = agent;

  // Whether the agent compiles the typed filter for the chosen adapters. Asked
  // on each pause in typing and on each change of adapters, because a filter
  // compiles against link types - `ether host` means nothing on the loopback.
  // The answer echoes the filter, so one that crossed a newer question is
  // recognised as stale (`filterVerdict`).
  const captureFilterVerdict = filterVerdict(captureOptions, captureFilterCheck);
  // Why Start must wait, or null: a filter the agent refused, or ring and stop
  // settings it would refuse - said here, with the reason, rather than by a
  // refusal after the click.
  const startBlockedReason = (reopening ? 'Reopening the last capture - Start waits for it.' : null)
    ?? filterBlocksStart(captureFilterVerdict) ?? ringProblem(captureOptions);
  const startBlockedRef = useRef(startBlockedReason);
  startBlockedRef.current = startBlockedReason;
  const filterToCheck = effectiveFilter(captureOptions);
  const adaptersToCheck = selectedInterfaces.join('\n');
  useEffect(() => {
    if (agentStatus !== 'connected' || filterToCheck === null) return;
    const timer = setTimeout(() => pipeline.command({
      type: 'check_capture_filter', filter: filterToCheck, interfaces: adaptersToCheck === '' ? [] : adaptersToCheck.split('\n'),
    }), CAPTURE_FILTER_CHECK_DELAY_MS);
    return () => clearTimeout(timer);
  }, [agentStatus, filterToCheck, adaptersToCheck]);
  // The other half of auto-pause. The buffer hook owns the flag and cannot own
  // this, because stopping a capture needs the agent - and the agent needs the
  // buffer's `queueFrames`. Assigned every render, so it never goes stale.
  /**
   * **Every way a capture ends goes through here**: the Stop button, Space,
   * the schedule, the buffer's disk reserve, the heap guard, and the agent
   * ending it itself - an autostop (ADR 0052), every adapter failing, another
   * window stopping it.
   *
   * Stop, then let the Worker release the frames it still holds, then flush
   * their rows, then seal the store. The auto-pause used to only send the stop,
   * and an agent that stopped by itself only flipped the button - so a capture
   * ended either way never had its tail written or its last chunk sealed, the
   * one moment it is meant to be whole on disk.
   *
   * `tellAgent` is false when the agent has already stopped. **Once per
   * capture**: Stop is answered by the agent's own `idle`, which arrives here
   * too, and a second seal would be a second `finish` racing the first.
   */
  const sealedCaptureRef = useRef<string | null>(null);
  const stopCaptureAndSeal = (tellAgent: boolean) => {
    if (tellAgent) sendAgentCommand({ type: 'stop_capture' });
    isCapturingRef.current = false;
    setIsCapturing(false);
    captureStartedAtRef.current = null;
    const id = captureIdRef.current;
    if (id !== null && sealedCaptureRef.current === id) return;
    sealedCaptureRef.current = id;
    // A finish sent straight away overtook the tail the Worker still held in
    // its ordering window, which then sat staged until the store next closed.
    // The drain puts the tail's bytes and records in the store and its rows in
    // the queue; `flushNow` sends those rows on this same port, ahead of the
    // finish.
    void pipeline.drain().then(() => {
      flushNow();
      captureStore.finish();
    });
  };
  stopCaptureRef.current = stopCaptureAndSeal;
  autoPauseRef.current = () => stopCaptureAndSeal(true);
  /**
   * An import replaces the capture, so a live one has to actually stop - not
   * only read as stopped. Setting `isCapturing` alone left the agent sniffing,
   * its drop counters refilled a second later, and every export of the
   * imported file then printed the live capture's losses as its own. The same
   * stop the Stop button sends. Assigned every render, like the one above,
   * because the import's batch callback is memoized with no deps.
   */
  const stopCaptureForImportRef = useRef<() => void>(() => {});
  stopCaptureForImportRef.current = () => {
    if (!isCapturingRef.current) return;
    sendAgentCommand({ type: 'stop_capture' });
    setIsCapturing(false);
    captureStartedAtRef.current = null;
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
   * It does what the rail's own Start does - clear, then start - rather than
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
    if (restoringRef.current) {
      setNavNotice('Scheduled capture skipped: the last capture was being reopened.');
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
      // Spent: the absolute times are cleared and the duration kept. Left
      // armed, the old start read as "already passed" two minutes later and
      // the old stop killed the next capture started by hand on its first
      // tick. See `afterScheduledStop`.
      setSchedule(afterScheduledStop);
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
   * At launch: keeps the previous session's capture on disk and OFFERS it, and
   * puts the adapter selection back. It does not load it - `reopenLastCapture`
   * does, when the reader asks.
   *
   * It used to load it, unasked, on every launch: the newest chunks that fit
   * the buffer budget, streamed into the list in slices. After a burst that was
   * 1.36 million rows arriving for fifteen seconds with nobody having pressed
   * Start, indistinguishable from a capture - and Start was not blocked while
   * it ran, so a capture started under it deleted the directory being read and
   * then had its numbering and clock moved onto the old capture's.
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

      // Everything on disk but the stored session's capture goes. One capture
      // is the retention rule, and it is the whole of it
      // (`docs/decisions/0026`): a capture on disk is 5 GB and twenty minutes
      // at full rate, so wanting the previous one is mostly wanting a longer
      // current one, and a capture worth keeping past a session is one to
      // Export. The stored one stays until a Start or an import replaces it.
      captureStore.prune(meta?.captureId ? [meta.captureId] : []);
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

      // The previous capture is OFFERED, not loaded. Loading it at launch
      // streamed up to the whole buffer budget of rows into the list - 1.36
      // million of them after a burst - which looked exactly like a capture
      // running nobody had started, and a Start pressed while it ran deleted
      // the capture it was still reading. Only a capture that ever received
      // a frame is offered.
      if (meta?.captureId && meta.lastPacketMs != null) setLastCapture(meta);

      // Capture is not resumed, and nothing is said about it: a launch leaves
      // the app exactly as pressing Pause would - adapter and filters intact,
      // capture stopped. That is also what has already happened underneath,
      // since the agent stops sniffing the moment its last client
      // disconnects, so `isCapturing` starting false is simply the truth.
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /**
   * Reopens the previous capture, on the reader's word - the empty list's
   * "Reopen". Its newest chunks come back into the buffer and the rest stays
   * reachable on disk, as a launch used to do unasked.
   *
   * Start is blocked while this runs (`reopening` is a reason in
   * `startBlockedReason`), because the two cannot interleave: a Start deletes
   * the capture this is reading, and this ends by moving the numbering and
   * the clock onto that capture's.
   */
  const reopenLastCapture = async (): Promise<void> => {
    const meta = lastCaptureRef.current;
    if (meta === null || isCapturingRef.current || restoringRef.current) return;
    restoringRef.current = true;
    setReopening(true);
    setLastCapture(null);
    try {
      // The session's frames are in the capture directory the metadata names,
      // and only that one. Pairing this metadata with a different capture's
      // frames would shift every timestamp in the list, because the
      // relative-time origin and the adapter table both belong to the run that
      // wrote them.
      const stored = meta.captureId ? await captureStore.reopen(meta.captureId) : null;
      captureIdRef.current = stored?.captureId ?? null;
      if (stored === null || stored.frameCount === 0) {
        setNavNotice('The last capture could not be reopened.');
      }

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
          // How to read each adapter's frames, from the session's own table.
          //
          // A restored row is already dissected and needs nothing - but the
          // detail pane rebuilds its tree by RE-dissecting the conversation
          // (`pipeline/replay.ts`), and both export writers ask the frame what
          // link layer it carries. Without this a restored loopback capture
          // shows a tree that contradicts the row that opened it, and exports a
          // file that declares Ethernet.
          //
          // Only adapters the table names a type for, and only when that type
          // is not Ethernet - so an ordinary session does nothing here and no
          // frame gains a property. See `SessionMeta.interfaces`, which also
          // states what this cannot cover.
          const restoredLinkTypes = new Map(
            (meta?.interfaces ?? [])
              .filter((i) => i.linkType !== undefined && i.linkType !== LINKTYPE.ETHERNET)
              .map((i) => [i.label, i.linkType as number]),
          );

          let done = 0;
          for (const rows of chunks) {
            // A restored session fills the buffer as full as a live capture ever
            // does, so its frames get the same treatment. The chunk codec hands
            // back the field bag, because the bag is the contract; the split into
            // columns belongs here, where the frames join the buffer.
            fieldWriter.current.absorb(rows);
            for (const packet of rows) {
              accountingRef.current.residentBytes += estimateSummaryBytes(packet);
              // Only where the row has none: a chunk written since link types
              // were stored with each row already carries the frame's own, and
              // the table - keyed by label, not by adapter - is the fallback for
              // older chunks, never an override.
              if (restoredLinkTypes.size > 0 && packet.linkType === undefined) {
                const linkType = restoredLinkTypes.get(packet.interfaceName);
                if (linkType !== undefined) packet.linkType = linkType;
              }
            }
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
        // An imported file keeps its name across a reload; anything else
        // restored is a session whose adapters may no longer exist.
        if (stored !== null && stored.frameCount > 0) {
          setCaptureSource(meta?.importedFrom
            ? { kind: 'import', fileName: meta.importedFrom }
            : { kind: 'session' });
        }
      setRestoreProgress(null);
      // An imported file keeps its name across a reload; anything else
      // restored is a session whose adapters may no longer exist.
      if (stored !== null && stored.frameCount > 0) {
        setCaptureSource(meta.importedFrom
          ? { kind: 'import', fileName: meta.importedFrom }
          : { kind: 'session' });
      }
    } finally {
      restoringRef.current = false;
      setReopening(false);
      setRestoreProgress(null);
    }
  };

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
    // Nor while a previous capture is only offered: writing now would replace
    // its metadata - the clock origin, the adapter table, which directory -
    // with this empty session's, and the offer would reopen nothing.
    if (restoringRef.current || lastCaptureRef.current !== null) return;
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
      // What a restored session tells an export about where it came from.
      ...(captureSource.kind === 'import' ? { importedFrom: captureSource.fileName } : {}),
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
  }, [selectedInterfaces, agentInterfaces, isCapturing, persistedPacketTick, storedCaptureId, captureSource]);


  // Resizable Bottom Pane
  //
  // Sizes, visibility and arrangement share one preference, because
  // `arrangement` changes what `detailsPaneRatio` means - a fraction of width
  // side by side, a fraction of height stacked. See services/interfacePrefs.

  const [layout, patchLayout] = usePreferenceStore(layoutStore);
  const { bottomPaneHeight, detailsPaneRatio, panes: showPanes, arrangement } = layout;
  const stacked = arrangement === "stacked";
  usePreferenceSync(layoutStore.key, layoutStore.normalize, layoutStore.accept);

  /**
   * The detail panes on and off, from the title row rather than from Settings.
   *
   * It was a switch in `Settings -> Interface` and is a control in the window's
   * own chrome now, beside the caption buttons - which is where every editor
   * puts its layout toggles, and which matters because this one is used while
   * looking at a capture rather than while configuring the app. A setting you
   * reach for mid-task is a control in the wrong place.
   *
   * The preference is unchanged and still persists: what moved is the way in,
   * not the state. `Settings -> Interface` keeps the pane ARRANGEMENT, which is
   * a real setting - it is chosen once and not toggled - and it still greys out
   * when the panes are off, which is now the only trace of the switch there.
   */
  const togglePanes = useCallback(
    () => patchLayout({ panes: !showPanes }),
    [patchLayout, showPanes],
  );

  const isDraggingRef = useRef(false);
  const isDraggingColumnRef = useRef(false);
  const isDraggingSideBarRef = useRef(false);
  const bottomPaneRef = useRef<HTMLDivElement>(null);
  /**
   * The cluster band, which is what a side bar drag measures against.
   *
   * The band rather than the window, so the gutter is outside the box and does
   * not have to be subtracted - the same reason `resizeSplit` measures the pane
   * it splits rather than the screen.
   */
  const bandRef = useRef<HTMLDivElement>(null);
  /** The rail's own width, the one number a side bar drag has to know about. */
  const RAIL_PX = 44;
  /**
   * The band's width, measured, because the point-of-use clamp needs it on the
   * RENDER path and not only during a drag.
   *
   * The split clamp is the dock's surviving rule - a width is stored unclamped
   * against the window and clamped where it is used, so narrowing the window
   * shrinks an open panel and widening gives back the width that was chosen.
   * The drag half of that was there from the start; the render half was not,
   * so `MAIN_RESERVE_PX` held for exactly as long as a pointer was down and
   * the stored width went to CSS raw everywhere else. A window narrowed with a
   * 600px panel open kept the 600px panel and squeezed the workspace to
   * nothing, which is the failure the rule exists to prevent.
   *
   * A `ResizeObserver` rather than a `resize` listener: the band is not the
   * window, and it changes height when the status bar or the title row does.
   */
  const [bandWidth, setBandWidth] = useState(0);
  useEffect(() => {
    const el = bandRef.current;
    if (el === null) return;
    const observer = new ResizeObserver(([entry]) => {
      setBandWidth(entry.contentRect.width);
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  /**
   * Where the layout's custom properties live.
   *
   * The root rather than the bottom pane, and the two are different jobs that
   * used to share one ref: the pane is what a drag MEASURES - its own
   * `getBoundingClientRect` is what makes a ratio a ratio, whatever sits either
   * side of it - and the root is what the properties are SET on.
   *
   * **The reason for the root was the window-spanning status bar, and that bar
   * is deleted.** It sat outside the pane and had to resolve a percentage
   * against the same base the panes were sized by, which only the root could
   * give it. Only the panes read these now, so the placement is no longer
   * load-bearing - it is kept because moving it back onto the pane would be a
   * layout change made for tidiness alone. What IS still load-bearing is the
   * split above: measure the pane, write the root.
   */
  const layoutVarsRef = useRef<HTMLDivElement>(null);

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
  const dragRef = useRef({ bottomPaneHeight, detailsPaneRatio, sideBarWidth: sideBarPrefs.width });
  useEffect(() => {
    dragRef.current = { bottomPaneHeight, detailsPaneRatio, sideBarWidth: sideBarPrefs.width };
  }, [bottomPaneHeight, detailsPaneRatio, sideBarPrefs.width]);

  const applyLayoutVars = useCallback(() => {
    const el = layoutVarsRef.current;
    if (!el) return;
    el.style.setProperty("--side-bar-width", `${dragRef.current.sideBarWidth}px`);
    el.style.setProperty("--bottom-pane-height", `${dragRef.current.bottomPaneHeight}px`);
    // One share and a remainder, so there is no interaction to clamp. There
    // were two - the map's and the tree's, with "the hex dump keeps at least a
    // tenth" enforced here rather than in the normalizer - and both went with
    // the map. The dump's floor is `MIN_PANE_PX` again, where it was before.
    el.style.setProperty("--details-pane-size", `${dragRef.current.detailsPaneRatio * 100}%`);
  }, []);

  /** A floor that only stops either side being dragged to nothing. */
  const MIN_PANE_PX = 220;

  /**
   * The row's one divider: between the tree and the dump, resizing the TREE.
   *
   * A plain offset from the leading edge, because the tree is the first pane in
   * the row. It briefly was not: with the map ahead of it this subtracted the
   * map's share from the offset, and read that share out of `dragRef` rather
   * than out of props because during a drag of the other divider the committed
   * value is a frame behind. Both went with the map.
   */
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

  /**
   * The side bar's width, from the pointer.
   *
   * Measured off the band rather than the window, so the rail and the gutter
   * come out of the arithmetic by being outside the box being measured - the
   * same reason `resizeSplit` measures the pane it is splitting.
   *
   * **The ceiling is applied here and never stored.** That is the dock's
   * surviving rule: a width is held unclamped against the window and clamped at
   * the point of use, so narrowing the window shrinks an open panel and
   * widening it gives back the width that was chosen. Clamped on the way out it
   * could never grow back.
   */
  const resizeSideBar = useCallback((clientX: number) => {
    const el = bandRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    dragRef.current.sideBarWidth = usableSideBarWidth(
      clientX - rect.left - RAIL_PX,
      rect.width - RAIL_PX,
    );
    applyLayoutVars();
  }, [applyLayoutVars]);

  useEffect(() => {
    const handlePointerMove = (e: PointerEvent) => {
      if (isDraggingSideBarRef.current) { resizeSideBar(e.clientX); return; }
      if (isDraggingRef.current) {
        // Measured off the pane's own bottom edge, not the window's.
        //
        // The two are the same number again - the byte inspector is back inside
        // the Hex View pane, so the rail-and-panes row runs to the bottom of the
        // window - and this still measures, deliberately.
        //
        // The history is the argument. There was a hardcoded 28px offset here
        // once, for a footer that had been deleted; it was removed for good
        // reason and the footer came back. Then the footer became a
        // window-spanning bar, which put ~25px between the row's bottom and the
        // window's and would have needed the offset back. Then the bar was
        // deleted and the footer came back again. Every one of those four turns
        // changes this number and none of them changes this line, because a
        // `getBoundingClientRect` asks rather than assumes - and the symptom of
        // assuming wrong is a divider that sits a fixed distance from the
        // pointer and stays there for the rest of the gesture.
        const bottom = bottomPaneRef.current?.getBoundingClientRect().bottom
          ?? window.innerHeight;
        dragRef.current.bottomPaneHeight = Math.max(
          100,
          Math.min(bottom - e.clientY, bottom - 200),
        );
        applyLayoutVars();
        return;
      }
      if (isDraggingColumnRef.current) resizeSplit(e.clientX, e.clientY);
    };

    const endDrag = () => {
      const sideBarDrag = isDraggingSideBarRef.current;
      if (!isDraggingRef.current && !isDraggingColumnRef.current && !sideBarDrag) return;
      isDraggingRef.current = false;
      isDraggingColumnRef.current = false;
      isDraggingSideBarRef.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      // The one commit for the whole gesture, and it goes to exactly one store.
      // The side bar's width lives on its own key - one `storage` event per
      // thing that actually moved - so committing both here would wake every
      // other window with a layout change nothing asked for.
      if (sideBarDrag) patchSideBar({ width: dragRef.current.sideBarWidth });
      else patchLayout({ ...dragRef.current });
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
  }, [applyLayoutVars, patchLayout, patchSideBar, resizeSplit, resizeSideBar]);

  const beginDrag = useCallback((which: "height" | "split" | "side-bar") => {
    if (which === "height") isDraggingRef.current = true;
    else if (which === "split") isDraggingColumnRef.current = true;
    else isDraggingSideBarRef.current = true;
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

  /**
   * The keyboard's step, stored UNCLAMPED against the window.
   *
   * It used to commit `usableSideBarWidth(...)`, which is the other half of the
   * dock's rule read backwards: clamped on the way OUT, a width could never
   * grow back when the window did. Two arrow presses at a narrow window would
   * have permanently rewritten a 600px choice down to whatever fitted. The
   * floor and the ceiling still bound it - those are facts about the column
   * rather than about the window - and the render path clamps against the
   * window, which is where that belongs.
   */
  const nudgeSideBar = useCallback((deltaPx: number) => {
    patchSideBar({
      width: Math.max(
        MIN_SIDE_BAR_PX,
        Math.min(sideBarPrefs.width + deltaPx, MAX_SIDE_BAR_PX),
      ),
    });
  }, [patchSideBar, sideBarPrefs.width]);

  // Engines
  /**
   * The colouring chain, and the engine built from it.
   *
   * Rebuilt when the chain changes and at no other time: the engine holds a
   * per-packet match cache whose whole premise is that a packet's rule cannot
   * change, so editing the chain has to produce a NEW engine rather than
   * mutating this one.
   */
  // **The colouring chain is shipped, not chosen.** See `colorRules.ts`.
  const colorEngine = useMemo(() => new ColorRulesEngine(DEFAULT_COLOR_RULES), []);
  const packetGenerator = useMemo(() => new PacketGenerator(), []);
  /**
   * The colour of the row the selected packet was picked from.
   *
   * The two detail panes below the list, and the Frame Detail view, all label a
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
   * Statistics tables, and the Frame Detail view's own navigation. They each used
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

  /* **`showFrameInWindow` is deleted.** It was `goToFrame` for the detail
     window, identical but for the last line - one set the list's selection and
     the other set the window's own frame id. The window is a view reading the
     same selection now, so there is one jump path again, which is what
     `goToFrame`'s comment above already claimed there was. */



  // The Worker gates dissection on this: the socket stays open whether or not
  // capture is running, because the agent is detected before anyone presses
  // Start.
  useEffect(() => {
    pipeline.setCapturing(isCapturing);
  }, [isCapturing]);



  // Driven by the picker opening and closing. Sampling adapter counters is
  // cheap but not free, and nothing should be measured on the user's machine
  // while the menu that displays it is shut.
  /**
   * The agent's interface counters, on while something is displaying them.
   *
   * It was `handleInterfacePickerOpenChange` and was driven by Radix's
   * `onOpenChange`. With the menu gone, the panel that draws the charts owns
   * it from its own MOUNT - which is a stricter boundary than the menu's was,
   * because a menu can be left open behind a click and a panel cannot be left
   * mounted behind anything.
   *
   * `clearInterfaceRates()` on the way in stays: a panel reopened ten minutes
   * later must not draw a ten-minute-old sparkline as though it were now.
   */
  /**
   * The adapter panel's sampling, owned by the hook that owns the socket.
   *
   * It was three lines here - clear, subscribe, unsubscribe - and it had a
   * hole that only appeared once the surface became persistent: a reconnect
   * drops the subscription with the socket, and nothing re-sent it. The log
   * had solved that already, with a ref the `hello` handler reads, so this is
   * that pattern rather than a second one.
   *
   * The failure it closes is quieter than the log's, which is why it went
   * unnoticed: a dropped log subscription is a panel that stops filling, where
   * a dropped counter subscription leaves thirty stale samples on screen that
   * read as a genuinely idle adapter.
   */
  const handleInterfaceSampling = setInterfaceStatsSubscribed;

  // Reuses the existing "outdated" amber pill for a second, related case: an
  // agent old enough to predate `hello` entirely can't be caught by the
  // version comparison below (agentVersion just stays null forever), so
  // agentIncompatible - set by the hello-grace-period timer above - folds
  // into the same flag rather than needing its own UI treatment.
  const agentOutdated = (agentVersion !== null && isAgentMismatched(agentVersion, REQUIRED_AGENT_VERSION)) || agentIncompatible;

  /**
   * The last display-filter result, so a growing buffer only filters what is
   * new. Held in a ref rather than state because it is a memo of the render
   * below, not a value anything renders from directly.
   */
  const filterCacheRef = useRef<FilterCache | null>(null);

  // Display Filter Evaluation. The incremental part - and why it is worth
  // having - lives in services/incrementalFilter.ts.
  const filteredPackets = useMemo(() => {
    const { result, cache } = filterIncrementally(packets, appliedFilter, filterCacheRef.current, PATCH_LOG);
    // Writing a ref during render is only safe because this is idempotent: a
    // StrictMode double-invoke re-enters with cache.source === packets, finds
    // the prefix intact with nothing appended, and returns the very same array.
    // Keep that property if either side of this is ever changed.
    filterCacheRef.current = cache;
    return result;
  }, [packets, appliedFilter]);

  /**
   * Where the RAM window sits in the capture, and the filter run over the rest.
   *
   * Both live here rather than in `PacketList` because two things need them:
   * the list, which addresses rows through them, and the filter bar, which
   * says how far the scan has got and how much of the capture it covered. Two
   * hooks asking the store the same question could disagree for a frame.
   */
  const belowWindow = useWindowOrdinal(packets);
  /**
   * The capture's first ordinal still held. Zero unless the agent writes a
   * ring and has deleted files, whose frames then left the capture with them
   * (ADR 0052): the list, its counts and a filter's all start here.
   */
  const captureFloor = captureStorage.floorOrdinal;
  // The RAM window follows the floor as the list does: what the ring took is
  // not a frame the buffer keeps showing.
  const captureFloorId = captureStorage.floorId;
  useEffect(() => {
    if (captureFloorId > 0) dropBelow(captureFloorId);
  }, [captureFloorId, dropBelow]);
  // Gated on there being disk under the window at all. Every capture that fits
  // in memory - which is up to ~700k frames - is answered completely by
  // `filteredPackets` above, and a scan would be a pass over frames this
  // process is already holding.
  const captureFilter = useCaptureFilter(appliedFilter, belowWindow > captureFloor);
  const filterUncovered = uncoveredRows(captureFilter.state, belowWindow);

  /**
   * The two numbers the filter bar states, over the CAPTURE rather than the
   * buffer.
   *
   * They used to be `filteredPackets.length` and `packets.length`, which on a
   * capture larger than memory answer a question nobody asked - "of the frames
   * that happen to still be in RAM, how many match" - and answer it without
   * saying so. With the scan's bitmap in hand the honest numbers are cheap:
   * `rank` is a binary search.
   *
   * Unchanged for every capture that fits in memory, because `belowWindow` is
   * then zero and both terms collapse to what they were.
   */
  const captureRowCount = Math.max(0, belowWindow - captureFloor) + packets.length;
  const shownRowCount = (captureFilter.state.status === 'ready'
    ? matchesOnDisk(captureFilter.state.matches, belowWindow, captureFloor)
    : 0) + filteredPackets.length;

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
   * A surface fed from this does at least one full pass over the buffer when
   * the identity changes. Measured across the analytics column this throttle
   * was built for - five panels, since reduced to one live consumer - a
   * 21,903-packet buffer cost 16.6ms per flush: 166ms of every second, and
   * about 380ms/s at the 50,000 cap, to redraw summaries that no one can read
   * at 10Hz. Throttling the input is what makes that proportional to how fast
   * the information is actually consumed rather than to how fast packets
   * arrive. The map is the consumer now and the arithmetic is unchanged - it
   * redraws every arc when this identity moves.
   *
   * Deliberately NOT used for the packet list (it is the live view), the title
   * row's counter (`.length` is O(1), and it subscribes rather than being
   * passed), or the export modal and the stream pane, which reconstruct exact
   * data and must never see a stale snapshot.
   */
  // The throttled feed.
  //
  // `dashboardRefreshMs` of 0 means paused: the consumer keeps the last buffer
  // it was given, so every memo keyed on it stops recomputing. That is the
  // whole cost of the throttled surfaces, and pausing removes it without
  // removing them. The throttle still runs underneath at a slow rate rather
  // than being torn down, so resuming publishes immediately instead of waiting
  // out a fresh interval.
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

    // The unfiltered list is answered by arithmetic, because this runs on
    // every flush and must not touch the buffer at all in the common case.
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
      const inRange = packets.length > 0
        && selectedPacket.id >= packets[0].id
        && selectedPacket.id <= packets[packets.length - 1].id;
      if (inRange) return;
    }

    // **And where it goes instead is the nearest surviving frame, not the
    // newest one.** Reassigning to `filteredPackets[length - 1]` is invisible
    // while you follow a live capture and is the whole interaction going wrong
    // while you read history: type a filter at frame 12,000 of 700,000 and the
    // app answers by selecting the last frame in the capture. That is the same
    // argument the paragraph above makes about the window, applied to the
    // filter.
    //
    // It also stops being a reverse linear walk of the filtered array.
    // "Almost always near the tail" holds while you follow the tail, and is
    // false in exactly this case - a selection near the head walked the whole
    // array on every flush for as long as it stayed unmatched.
    const anchor = anchorSelection(filteredPackets, selectedPacket.id);
    if (anchor.kept || anchor.packet === null) return;
    setSelectedPacket(anchor.packet);
  }, [filteredPackets, packets, selectedPacket]);

  // The keyboard handler below reads the live list and selection through refs
  // so that it is registered once rather than re-registered on every flush -
  // which, with `filteredPackets` in its dependency list, it was: ten window
  // listener swaps a second for the whole life of a capture. It used to be
  // registered once per open/close of the detail MODAL, whose open flag was in
  // its dependency list; Frame Detail is a view and that gate is gone, so the
  // effect now depends on nothing that moves during a capture at all.
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

  /* `handleFollowStream` and the view-change handler below it sit HERE, above
     `useKeyboardNavigation`, rather than down with `leaveStream` where the rest
     of the stream state lives. `Ctrl+5` resolves through the same handler the
     rail button uses, and a `const` cannot be read before it is declared - so
     the alternative was the shortcut and the button meaning two different
     things, which is exactly what this handler exists to prevent. */

  /**
   * Opens a stream, from wherever it was asked for.
   *
   * Switching the view is part of it now rather than something the caller
   * remembers: a stream is followed from a packet row, the Frame Detail view or
   * a conversation table, and all three mean "show me this". The origin is
   * recorded here because this is the only place that knows what was selected
   * when the request was made.
   *
   * **The second argument is which of the two readings to open on, and it is a
   * parameter for a reason worth keeping.** "Follow stream" and "Show
   * conversation" ask different questions of the same frames - content against
   * shape - and the tempting shape for that is a second surface. It is one
   * surface with a tab, so the two cannot drift out of step.
   */
  const handleFollowStream = useCallback((
    target: StreamTarget, view: 'dialogue' | 'ladder' = 'dialogue',
  ) => {
    setStreamToFollow(target);
    setStreamView(view);
    setStreamOrigin(selectedPacketRef.current?.id ?? null);
    setView('stream');
  }, [setView]);

  /**
   * The store's stream digest (ADR 0055): one summary per TCP stream over the
   * whole capture, polled while a view that reads it is showing. The Follow
   * Stream pane reads its own stream's summary from it; the Conversations
   * table reads all of them.
   *
   * Looked up by the tracker's stream index and then checked against the
   * target's five-tuple, because an index is unique within one capture only:
   * `streamToFollow` outlives the capture it was chosen in, and a new capture
   * numbers its first connection 0 as well.
   */
  const streamDigest = useStreamDigest(view === 'stream' || view === 'statistics');
  const streamSummary = useMemo(() => {
    if (streamToFollow === null || streamToFollow.streamId === undefined) return null;
    const summary = streamDigest.summaries.get(streamToFollow.streamId);
    return summary !== undefined && summaryIsTarget(summary, streamToFollow) ? summary : null;
  }, [streamDigest.summaries, streamToFollow]);

  /**
   * The rail's Follow Stream button, which is a verb and was reading as a place.
   *
   * ## What was broken
   *
   * Every other entry in the rail's view group is a pure navigation: press it,
   * that surface fills the window. Follow Stream is not - it needs a stream -
   * and it was wired as if it were. `streamAvailable` was `streamToFollow !==
   * null`, which is "a stream is ALREADY open", and the click was a bare
   * `setView('stream')`, which shows whatever that happens to hold. Three
   * symptoms, all of them the same bug:
   *
   *  - selecting a frame on a TCP stream left the button **disabled**, because
   *    nothing had been followed yet;
   *  - following one from the Frame Detail pane enabled it, because that path
   *    sets `streamToFollow`;
   *  - and from then on it opened **that** stream for ever, because selecting a
   *    different frame never touched the state the button reads.
   *
   * ## What it does now
   *
   * The button follows the SELECTION, which is what its name says and what the
   * context menu on a packet row has always done. Availability is the selected
   * frame having a stream to follow, **or** a stream already being open - the
   * second half so the view stays reachable while reading a conversation whose
   * frames are not what is selected, and so the icon does not flicker
   * enabled/disabled as somebody arrows down the list past an ARP.
   *
   * The selection wins when both are true. Clicking with frame 900 selected
   * means "follow frame 900's stream", even if frame 12's is the one on screen.
   *
   * `targetForPacket` reads `frameProtocols`, the two ports and `streamId` -
   * all summary fields carried by a buffered frame - so this asks nothing of
   * the dissector and costs nothing per render.
   */
  const streamForSelection = selectedPacket !== null ? targetForPacket(selectedPacket) : null;

  /**
   * The rail's and the keyboard's one way of changing view.
   *
   * Both go through here rather than through `setView` directly, so `Ctrl+5`
   * and the rail button cannot come to mean different things - which is the
   * same reason `APP_VIEWS` order IS the numbering.
   */
  /**
   * "Stops in 14:58", recomputed on the schedule hook's own tick.
   *
   * That tick is what makes the countdown advance without any component here
   * owning a timer. It has two readers now - the rail button's tooltip and the
   * side bar header's detail - where it used to have one, and it was worth
   * moving precisely because the one it had was a tooltip.
   */
  const scheduleSummary = describeSchedule(
    schedule, scheduleNow, isCapturing, captureStartedAtRef.current,
  );
  const scheduleArmed = !isScheduleEmpty(schedule)
    && (isCapturing || scheduleProblem(schedule, scheduleNow) === null);

  const handleViewChange = useCallback((next: AppView) => {
    /**
     * **Landing on a view closes Settings**, because Settings is a sheet over
     * the workspace rather than a view in the list - it renders INSTEAD of the
     * view stack, so setting `view` underneath it changed the rail's active
     * marker and nothing on screen. Every way in went through here, so the one
     * way out was the back step: the rail's own icons looked broken.
     *
     * It belongs on the transition rather than on the pane, for the reason the
     * sheet exists: the view underneath is untouched while Settings is open,
     * so the only thing that can know a view is being CHOSEN is the code that
     * chooses it. `applyFilter` closes it for the same reason - it navigates
     * to Packets, and a navigation nobody can see is the identical bug.
     */
    const land = (v: AppView) => { setSheet(null); setView(v); };
    if (next !== 'stream') { land(next); return; }
    const target = selectedPacketRef.current !== null
      ? targetForPacket(selectedPacketRef.current) : null;
    // No stream on the selection: fall back to whatever is already open. The
    // rail disables the button when neither is true, so this is reachable only
    // by the shortcut. Nothing to land on means nothing happens at all -
    // including to Settings, because a shortcut that did nothing visible should
    // not have closed the surface you were reading.
    if (target === null) { if (streamToFollow !== null) land('stream'); return; }
    setSheet(null);
    handleFollowStream(target);
  }, [setView, streamToFollow, handleFollowStream]);

  /**
   * Escape in a non-Packets view returns to Packets.
   *
   * **Last in the chain, by construction.** Every inner consumer - the palette,
   * the filter presets dropdown, the discard prompt, the frame view's overlay,
   * the import refusal - is a layer on the window's Escape stack
   * (`lib/escapeStack.ts`), one capture-phase listener that gives the key to the
   * newest layer and stops it, so this bubble-phase listener only ever sees an
   * Escape that nothing else claimed. Registering it in the
   * capture phase instead would make it the FIRST to see the key and navigate
   * out from under an open popover.
   *
   * **Leaving a stream restores the frame it was followed from**, which is what
   * `leaveStream` used to do for the pane's own "Back to frame N" button. That
   * button is gone and the behaviour is not: it belongs to LEAVING a stream
   * rather than to one control, so it is here and in `goBack`, which are the
   * only two ways out. `goToFrame` rather than a bare `setSelectedPacket`,
   * because it refuses a frame that has left the buffer and says so - a real
   * case, since a long capture can drop the origin while the stream is read.
   */
  useEffect(() => {
    if (view === 'packets' && !sheetOpen) return;
    const onKey = (e: KeyboardEvent): void => {
      // A composing Escape cancels the IME's word; the stack declines it too.
      if (e.key !== 'Escape' || e.isComposing) return;
      // The sheet first, and it does not take the view with it: it is a surface
      // over whatever was underneath, so closing it returns you there rather
      // than to Packets. One Escape per surface, outermost first.
      if (sheetOpen) { setSheet(null); return; }
      if (view === 'stream' && streamOrigin !== null) goToFrame(streamOrigin);
      setView('packets');
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [view, setView, streamOrigin, goToFrame, sheetOpen]);

  // Window-level keyboard shortcuts - see hooks/useKeyboardNavigation.ts.
  useKeyboardNavigation({
    canCapture: permissions.canCapture,
    onViewShortcut: handleViewChange,
    // The title row's toggle, by key. See `toggleSideBar`.
    onToggleSideBar: toggleSideBar,
    onOpenPalette: openPalette,
    onFocusFilter: () => { filterInputRef.current?.focus(); filterInputRef.current?.select(); },
    filteredPacketsRef,
    selectedPacketRef,
    isCapturingRef,
    packetCountRef,
    selectedInterfacesRef,
    setSelectedPacket,
    // The same start and stop as the rail's button: a capture Space starts is
    // a capture with an id, a store and its own files like any other.
    // An offered previous capture is deleted by Start, and Space has nowhere
    // to ask - the same rule as a buffer with frames in it.
    startBlocked: () => startBlockedRef.current !== null || lastCaptureRef.current !== null,
    // The rail disables Start for this too; a key must not reach the start
    // that clears the session before the agent refuses it.
    ownedElsewhere: () => captureOwner !== null && captureOwner !== agentClientId,
    onStartCapture: () => { void handleStartCapture(); },
    onStopCapture: () => handlePauseCapture(),
  });

  // Actions
  //
  // Capture takes one adapter or several. What stays from the single-adapter
  // rule of 2026-08-26 is the part that was its point: nothing is pre-selected,
  // so a capture cannot begin without somebody having said where from.
  // **The set is fixed for the life of a capture** (ADR 0048): adapters are
  // chosen before Start and change only after Stop. The panel disables its rows
  // while any window captures; this is the same rule for any other way in. Both
  // agents refuse the change - `capture_running` to the owner, `capture_busy`
  // to anyone else - and a selection kept here after a refusal would name
  // adapters the running capture is not reading.
  const handleToggleInterface = (interfaceName: string) => {
    if (isCapturingRef.current || (captureOwner !== null && captureOwner !== agentClientId)) return;
    const next = toggleInterface(agentInterfaces, selectedInterfacesRef.current, interfaceName);
    setSelectedInterfaces(next);
    sendAgentCommand({ type: 'set_interfaces', interfaces: next });
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
    // Before anything touches the store: an export reading the previous
    // capture ends - its file removed - and says why, rather than reading on
    // into the new one (`cancelExportForChange`). Every Start goes through
    // here: the rail's button, the shortcut and the schedule.
    await cancelExportForChange('a new capture started');
    // The offered capture is about to be pruned; the rail's prompt asked.
    setLastCapture(null);
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
    // By label, which is what an export prints. Through the ref, because a
    // scheduled start calls this from a closure that may be renders old.
    // With the filter and snaplen the driver is about to apply, which is what
    // an export says about how the capture was narrowed.
    setCaptureSource({
      kind: 'live',
      adapters: selectedInterfacesRef.current.map(
        (name) => agentInterfaces.find((i) => i.name === name)?.label ?? name,
      ),
      ...recordOf(captureOptionsRef.current),
    });
    // Named by its id, which is what has the agent write the capture's own
    // pcapng into this capture's folder (ADR 0052).
    sendAgentCommand(startCaptureCommand(captureOptionsRef.current, captureIdRef.current));
    setIsCapturing(true);
  };

  const handlePauseCapture = () => stopCaptureAndSeal(true);

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
    resetByteRange();
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
    await cancelExportForChange('the capture was discarded');
    await clearSession();
    setSelectedPacket(null);
    resetByteRange();
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

  // `handleSelectProtocol` (`proto == tcp`) and `handleFilterHost`
  // (`ip.addr == "…"`) were here, for the two dashboard widgets that could hand
  // a filter back - Protocol breakdown and Top talkers, both deleted. Every
  // other route into the filter bar goes through `handleQuickFilter` above,
  // which Statistics uses for exactly this and which takes the whole expression
  // rather than building one.

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

  // `handleInspectFromDashboard` was here - a widget handing a frame back to
  // the list, through `dashboardContext`. Neither surviving surface does that:
  // the map selects a place rather than a packet, and the charts are aggregates
  // with no single frame to point at.


  /**
   * One step back up the view hierarchy, or nothing at a root.
   *
   * `backTargetFor` in `viewPrefs.ts` holds the shape - Follow Stream is one
   * conversation belonging to a frame, Frame Detail is one frame of the
   * capture, and Statistics and the Routing Map are neither, so they are roots
   * with no step to take.
   *
   * **This is not Escape.** Escape returns any non-Packets view to Packets in
   * one hop, which is the exit; this is one step, so leaving a stream lands on
   * the frame it was followed from rather than back in the list. That is also
   * why the origin restore lives here and not only in `leaveStream`: the frame
   * the stream came from is exactly what Frame Detail should be showing when
   * the step completes.
   */
  /**
   * Applies the display filter, and goes to look at what it selected.
   *
   * **The navigation is the rule that replaced "the filter row belongs to
   * Packets".** The field is in the title row now, visible from every view, and
   * the objection to that arrangement was always the same: a display filter
   * above Statistics or the Routing Map is a control with nothing in view to act
   * on. It acts on the CAPTURE rather than on what is in view, so the answer is
   * to go where the answer is rather than to hide the control.
   *
   * **Only a non-empty expression navigates.** Clearing selects the whole
   * capture, which is what every view already shows, so dragging somebody out of
   * Statistics to tell them that would be a jump with nothing at the end of it.
   */
  const applyFilter = useCallback((next?: string) => {
    const expression = next !== undefined ? next : filterText;
    setAppliedFilter(expression);
    // Applying navigates to Packets, so it closes Settings for the same reason
    // `handleViewChange` does: the filter field is in the title row and stays
    // reachable while the sheet is open, and a navigation the sheet covers is a
    // control that looks broken. Clearing does not navigate and so does not.
    if (expression.trim() !== '') { setSheet(null); setView('packets'); }
    // Only an expression that compiles is remembered: a recent list that
    // offers back a typo offers back the same error.
    if (expression.trim() !== '' && FilterEngine.validateFilter(expression).isValid) {
      recentFiltersStore.set(pushRecentFilter(recentFiltersStore.get(), expression));
    }
  }, [filterText, setView]);

  /**
   * What the registry's `when` predicates read (ADR 0057). Start follows
   * `captureKeyAction`'s rule, so the palette never offers a Start that Ctrl+E
   * would refuse.
   */
  const commandContext: CommandContext = useMemo(() => ({
    capturing: isCapturing,
    canStartCapture: captureKeyAction({
      capturing: isCapturing,
      adapterCount: selectedInterfaces.length,
      packetCount: packets.length,
      canCapture: permissions.canCapture,
      blocked: startBlockedReason !== null || lastCapture !== null,
      ownedElsewhere: captureOwner !== null && captureOwner !== agentClientId,
    }) === 'start',
    packetCount: packets.length,
    filterApplied: appliedFilter.trim() !== '',
    sideBarOpen,
  }), [isCapturing, selectedInterfaces.length, packets.length, permissions.canCapture,
    startBlockedReason, lastCapture, captureOwner, agentClientId, appliedFilter, sideBarOpen]);

  const presetExpressions = useMemo(
    () => allPresets(filterPresetLibrary).map((p) => p.filter).filter((f) => f.trim() !== ''),
    [filterPresetLibrary],
  );

  const closePalette = useCallback(() => setPalette(null), []);

  /**
   * The palette's commands, bound. The palette closes first, so a command that
   * opens a surface opens it with nothing on top. Every id here is a visible
   * control's handler, never a palette-only action.
   */
  const runCommand = (id: string): void => {
    setPalette(null);
    const view = APP_VIEWS.find((v) => `view.${v.id}` === id);
    if (view) { handleViewChange(view.id); return; }
    switch (id) {
      case 'capture.start': void handleStartCapture(); return;
      case 'capture.stop': handlePauseCapture(); return;
      case 'filter.focus': filterInputRef.current?.focus(); filterInputRef.current?.select(); return;
      case 'filter.clear': setFilterText(''); applyFilter(''); return;
      case 'sidebar.toggle': toggleSideBar(); return;
      case 'sidebar.interfaces': openSideBarPanel('interfaces'); return;
      case 'sidebar.schedule': openSideBarPanel('schedule'); return;
      case 'sidebar.transfer': openSideBarPanel('transfer'); return;
      case 'sidebar.network': openSideBarPanel('network'); return;
      case 'monitoring.open': setSheet('monitoring'); return;
      case 'settings.open': setSheet('settings'); return;
    }
  };

  /**
   * The back step, and Settings sits on top of the view hierarchy rather than
   * in it.
   *
   * Settings takes the workspace card without being a view, so the step out of
   * it is "back to what I was looking at" - the CURRENT view, unchanged
   * underneath - rather than a step up the `backTargetFor` chain. That is what
   * makes it a sheet: opening and closing it costs the view nothing.
   */
  const backTarget = backTargetFor(view);
  const backLabel = sheetOpen
    ? viewLabel(view)
    : backTarget === null ? null : viewLabel(backTarget);

  const goBack = useCallback(() => {
    if (sheetOpen) { setSheet(null); return; }
    if (backTarget === null) return;
    if (view === 'stream' && streamOrigin !== null) goToFrame(streamOrigin);
    setView(backTarget);
  }, [sheetOpen, backTarget, view, streamOrigin, goToFrame, setView]);

  /**
   * A stream that goes away takes its view with it.
   *
   * The buffer being cleared, or a capture being restarted, leaves `view` on
   * 'stream' with nothing to show - and the rail's icon is disabled in exactly
   * that state, so the view would be unreachable and unleavable at once.
   */
  useEffect(() => {
    if (streamToFollow === null && view === 'stream') setView('packets');
  }, [streamToFollow, view, setView]);

  /**
   * The capture directory an import is writing into, while it writes.
   *
   * Opened on the first batch rather than before the file is read: a file that
   * turns out not to be a capture, or that fails to parse, must not leave an
   * empty directory behind for the next startup to find and restore from.
   */
  const importCaptureIdRef = useRef<string | null>(null);
  /**
   * The import's decrypted answers (ADR 0049), held until the import's reset
   * has emptied the Worker's and then handed over. Memory only, and never to
   * the store.
   */
  const importDerivedRef = useRef<DerivedStore | null>(null);

  /**
   * Every frame an import produced, on its way to disk.
   *
   * This is what makes an import of a capture larger than memory possible at
   * all: the importer used to build `maxFrames` frames and say the rest had
   * been thrown away. Now the whole file goes to the store and `maxFrames` is
   * only what stays resident, so the list scrolls into the rest the same way
   * it scrolls into a live capture's history.
   */
  const handleImportBatch = useCallback((batch: Packet[], records: FrameRecordEntry[]) => {
    if (importCaptureIdRef.current === null) {
      // Before the store is re-opened. The panel shuts the import while an
      // export runs; this is the other door, and the export's reader refuses
      // to read on across the re-open either way (`guardedReader`).
      cancelExportJob('an import started');
      stopCaptureForImportRef.current();
      importCaptureIdRef.current = newCaptureId();
      // The offered capture is pruned when this one is stored, as Start's is.
      setLastCapture(null);
      // The Worker's budget, so an import keeps what a live capture would.
      importDerivedRef.current = new DerivedStore(derivedBudgetRef.current);
      captureStore.begin(importCaptureIdRef.current);
    }
    // Records first, so each is in the store before its frame: a record that
    // arrives after its frame's chunk has sealed is dropped (ADR 0049).
    captureStore.appendRecords(records);
    for (const { id, derived } of records) {
      if (derived) importDerivedRef.current?.set(id, derived);
    }
    captureStore.append(batch);
  }, []);

  const handleImportPackets = (imported: Packet[], info?: { filename: string; facts?: CaptureFileFacts }) => {
    stopCaptureForImportRef.current();
    setIsCapturing(false);
    setCaptureSource(info
      ? { kind: 'import', fileName: info.filename, ...(info.facts === undefined ? {} : { facts: info.facts }) }
      : { kind: 'session' });
    // The live capture's drop counters describe frames that are no longer in
    // the buffer. Left in place, every export of the imported file reported it
    // as a live capture that lost the previous capture's frames.
    clearCaptureStats();
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
    // An import that reached the store owns a capture directory now, so the
    // frames it wrote are persisted through the last of them - and the
    // previous capture's directory goes, the same rule Start follows.
    const storedImport = importCaptureIdRef.current;
    if (storedImport !== null) {
      captureStore.finish();
      captureIdRef.current = storedImport;
      captureStore.prune([storedImport]);
      importCaptureIdRef.current = null;
    }
    // `null` keeps `persistedThroughId` where it was, which is right when the
    // import went nowhere; when it went to disk, everything up to `lastId` is
    // there and a later flush must not write it a second time.
    adoptBuffer(imported, storedImport === null ? null : Math.floor(lastId));
    pipeline.reset(Math.floor(lastId) + 1);
    if (importDerivedRef.current !== null) {
      pipeline.keepDerived(importDerivedRef.current.entries());
      importDerivedRef.current = null;
    }
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

  // **`dashboardContext` was here and is gone with the dock.** One memoised
  // object carrying the throttled packet feed, two theme facts and a stable
  // callback, held together so `Dock`'s `React.memo` could actually hold. That
  // was the application's only memo boundary; `React.memo` now appears nowhere
  // in `src/` at all.
  //
  // There is no boundary to hold up any more: the map and the charts take their
  // props directly, from the two places that render them, and both of those are
  // unmounted when their view is not active. `dashboardPackets` survives and is
  // still the throttled feed - see `perf.dashboardRefreshMs` - because the map
  // redrawing its arcs ten times a second was never about the dock.

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
  const settingsOpen = sheet === 'settings';
  const totalBytes = useMemo(
    () => (settingsOpen ? dashboardPackets.reduce((sum, p) => sum + p.length, 0) : 0),
    [dashboardPackets, settingsOpen],
  );
  /**
   * What the window calls itself. Pure, and asserted without a window.
   *
   * The adapter leads when capturing: an analyst with four windows open is
   * looking for the one on the interface they care about, and "Inwire" four
   * times in the taskbar says nothing.
   */
  const captureAdapter = selectionLabel(agentInterfaces, selectedInterfaces);
  // The window's name, for the OS alone now: the taskbar, Alt-Tab and the
  // window list. The title row's centre shows the packet counter instead - see
  // `components/common/PacketCountsReadout.tsx` - so this string has exactly one
  // consumer again, which is what `windowTitleFor`'s own comment assumed.
  const windowTitle = windowTitleFor({ capturing: isCapturing, adapter: captureAdapter });
  useWindowTitle(windowTitle);

  // Published rather than passed: the title row's readout subscribes for
  // itself, so a number that changes on every 100ms flush never travels down
  // through props - and the row it sits in is on screen in every view, so
  // passing it would re-render the whole tree to move one number. See
  // `services/packetCounts.ts` for what putting it there would cost.
  useEffect(() => {
    publishPacketCounts({
      filtered: shownRowCount,
      total: captureRowCount,
      scan: captureFilter.state,
      uncovered: filterUncovered,
      onRescan: captureFilter.rescan,
    });
  }, [shownRowCount, captureRowCount, captureFilter.state, filterUncovered, captureFilter.rescan]);

  return (
    <div
      ref={layoutVarsRef}
      style={
        {
          // Both on the root rather than on the bottom pane - see `layoutVarsRef`
          // for why that placement outlived the bar it was chosen for. There was
          // a third, `--geo-pane-size`, and it is the reason this object exists:
          // it had never been in the React style at all, only in the imperative
          // drag path, so the map pane had no width until somebody dragged
          // something.
          "--bottom-pane-height": `${bottomPaneHeight}px`,
          "--details-pane-size": `${detailsPaneRatio * 100}%`,
          // Declared HERE as well as in `applyLayoutVars`, which is the whole
          // lesson of `--geo-pane-size` above: a layout property written only
          // by the drag path has no value until somebody drags something, and
          // the symptom is a column that renders at zero width on first paint.
          //
          // **Clamped on the way out, never on the way in.** The stored value
          // stays whatever was dragged; this is the point of use, so this is
          // where the window gets a say. Without the clamp here the reserve
          // held only while a pointer was down - and a window narrowed with a
          // wide panel open kept the panel and squeezed the workspace.
          "--side-bar-width": `${bandWidth === 0
            ? sideBarPrefs.width
            : usableSideBarWidth(sideBarPrefs.width, bandWidth - RAIL_PX)}px`,
        } as React.CSSProperties
      }
      className="h-screen w-screen flex flex-col font-sans overflow-hidden transition-colors bg-background text-foreground"
    >
      {/* The title row spans the WINDOW, and the rail hangs below it. That is
          what puts the app's mark at the true top-left corner, and what keeps
          the row and the rail one `bg-secondary` surface running into Windows'
          own rounded corner.

          **There is a 1px rule between them now, and this row does not draw
          it.** The band below does - `border-t` on the rail and on `<main>`,
          collinear, so one line crosses the whole window - which is what wraps
          the rail in an outline of its own without costing this row a pixel.
          A `border-b` here would come out of its own `h-8` under `border-box`
          and leave 31px for caption buttons that are 46x32 because Windows'
          are. Same argument for the status bar's missing `border-t`.

          It costs `TITLE_BAR_HEIGHT` (32px) of rail height, which is why
          `MIN_WINDOW_HEIGHT` is 680, and `STATUS_BAR_HEIGHT` (24px) costs the
          rail 24 more - so the rail gets 624 and its icons come to 494. The two
          strips are funded differently on purpose: the window minimum carries
          the row, the rail's own slack carries the bar. `scripts/session/view.ts`
          does that sum and is the only place it is worth trusting - the numbers
          were quoted here as 40 / 640 / 630 long after all three had moved. */}
      <TitleRow
        focused={windowFocused}
        maximized={windowMaximized}
        panesVisible={showPanes}
        onTogglePanes={togglePanes}
        sideBarOpen={sideBarOpen}
        onToggleSideBar={toggleSideBar}
        backLabel={backLabel}
        onBack={goBack}
        center={
          <FilterBar
            filterText={filterText}
            onFilterChange={setFilterText}
            onApplyFilter={applyFilter}
            filterPresetLibrary={filterPresetLibrary}
            onSaveCurrentFilter={handleSaveCurrentFilter}
            appliedFilter={appliedFilter}
            inputRef={filterInputRef}
          />
        }
      />

      {/* **The cluster band, and its ground is the shell backdrop.** The rail
          and <main> are two cards floating in here, inset by the 4px gutter
          this element's padding draws - left, right and bottom, and NOT top,
          because the cards meet the title row flush. What shows in that gutter
          is this `bg-secondary`, which is why it has to stay the chrome's
          colour: it is the surface the whole cluster sits on.

          That is VS Code's Modern UI arrangement, and the gutter is the half
          of it that makes the radius legal here. `spacing-size40` is 4px and
          `cornerRadius-large` is 8; both are carried below.

          It was `bg-card` while the chrome moved to `bg-secondary` without it,
          which put a wedge of the WRONG grey in the one curve the arrangement
          was about - a few dozen pixels, two plausible greys, and nothing in
          the suite that could see it. There is a great deal more of it on
          screen now. If the chrome's ground changes again, this changes with
          it. */}
      <div
        ref={bandRef}
        className="flex-1 flex min-h-0 overflow-hidden bg-secondary pl-1 pr-1 pb-1"
      >
        <ActivityRail
          isCapturing={isCapturing}
          onStartCapture={handleStartCapture}
          onStopCapture={handlePauseCapture}
          onClearPackets={handleClearPackets}
          bufferedPackets={packets.length}
          previousCapture={lastCaptureLabel}
          permissions={permissions}
          agentInterfaces={agentInterfaces}
          selectedInterfaces={selectedInterfaces}
          captureOwnedElsewhere={captureOwner !== null && captureOwner !== agentClientId}
          startBlockedReason={startBlockedReason}
          agentHealth={agentHealth}
          view={view}
          onViewChange={handleViewChange}
          streamAvailable={streamForSelection !== null || streamToFollow !== null}
          settingsOpen={settingsOpen}
          // Opens, and does not toggle. The rail's Settings button behaves as
          // a view's does: pressing the one already on screen keeps it there,
          // and leaving is choosing somewhere else - any view, Escape, or the
          // title row's back step. A toggle made it the one button that sent
          // you back to wherever you had been.
          onOpenSettings={() => setSheet('settings')}
          sideBarOpen={sideBarOpen}
          sideBarPanel={sideBar}
          onOpenSideBar={openSideBarPanel}
          schedule={schedule}
          scheduleSummary={scheduleSummary}
          scheduleArmed={scheduleArmed}
        />

        {/* The content pane, tucked into the corner the title row and the rail
            make. **All four corners are square**, and the top-left was the one
            exception: `rounded-tl-xl`, on the argument that the one corner
            where two chrome edges meet is not an edge of the window and may
            curve. That was deleted, and the rule it left is the one still in
            force: **no surface that meets the window draws a corner of its
            own**, because the only curve out there is Windows' own
            (`roundedCorners`, a default never set).

            This pane carries `rounded-r-lg` and does not break that rule - it
            no longer meets the window. The cluster band holds it 4px clear on
            the right and the bottom, and a card floating inside the chrome is
            not a surface at the window's edge. The rule is unchanged; what
            changed is that nothing here answers to it any more except the
            title row and the status bar, which still run edge to edge and are
            still square.

            **This pane is a card in its own right and the rail is another,
            with a gap between them.** They met flush for a revision, sharing
            one seam that the rail drew - which is VS Code's arrangement when a
            side bar sits against the activity bar. There is no side bar here,
            and `floatingPanels.css` covers that case too: with nothing to
            connect to, the rail "closes up as a standalone panel with every
            corner rounded". So each card now draws its own complete outline,
            and the question of who owns the seam does not arise.

            **`ml-1` is the gap and it belongs to this pane**, not to the rail.
            Also VS Code's convention - a left-hand rail gets its gap from the
            leading margin of the card beside it - and it is worth keeping
            rather than splitting: one margin means one number to change, where
            a margin on each side is two that have to agree.

            `rounded-lg` is 8px, `--vscode-cornerRadius-large`, and it is legal
            for the same reason the rail's is: the band's 4px gutter holds this
            pane off the window, so the shell's no-corner-against-the-window
            rule is not engaged. The gutter and the radius move together or not
            at all.

            At `--secondary` against `--background` the two grounds differ by
            13/255 in Night, so each card's edge half-reads on its own and the
            borders carry it in Day.

            `overflow-hidden` is load-bearing again, and for its ORIGINAL
            reason: the filter row paints its own `bg-background` straight into
            the top-right corner, so without the clip the curve is drawn and
            then filled back in by the child sitting in it. It was also keeping
            every child's scroller resolving against this box, which is the
            argument that held while all four corners were square.

            **This is a column, and it was a row for exactly one revision.** The
            dock ran the pane's full height with the filter row beside it, so
            that a widget summarising the whole capture did not sit under a row
            that narrows the list. Deleting the dock answered the same question
            by removing the thing that raised it, and the filter row now spans
            exactly what it acts on because there is nothing else in the row.

            The dock's width reserve went with it. `LIST_RESERVE` in
            `dockPrefs.ts` guaranteed the packet list a width while a column sat
            beside it; both the constant and the file are deleted. Something
            competes for that width again - the side bar - and the reserve came
            back as `MAIN_RESERVE_PX` in `sideBarPrefs.ts`, inheriting that
            constant's post-mortem rather than its number. */}

        {/* **The side bar, and the seam it makes with the rail.**

            VS Code's two arrangements, and which is in force is one boolean.
            Closed, the rail "closes up as a standalone panel with every corner
            rounded" (`.nosidebar` in `floatingPanels.css`) and `<main>` supplies
            the 4px gap as `ml-1`. Open, the rail and this column meet FLUSH and
            read as one surface: the column gives up its left border and its
            left corners, the rail draws the only seam, and the sash supplies
            the gap to `<main>` instead.

            The gap is one number either way, which is the point of the
            leading-margin convention - it belongs to the element on the right,
            or to the sash standing in that element's place, never to two
            margins that have to agree. */}
        {sideBar !== null && (
          <SideBar
            panel={sideBar}
            actions={sideBar === 'network' ? (
              <NetworkPanelActions
                agentConnected={agentStatus === 'connected'}
                onRefresh={() => sendAgentCommand({ type: 'refresh_adapters' })}
              />
            ) : undefined}
            detail={sideBar === 'interfaces' && agentInterfaces.length > 0
              ? agentInterfaces.length
              : sideBar === 'schedule' && !isScheduleEmpty(schedule)
                // The promotion this conversion is for: a live countdown that
                // was computed only to fill a 36px button's tooltip. Red when
                // the schedule will not act, as the plan box below it is.
                ? scheduleArmed ? scheduleSummary : <span className="text-destructive">{scheduleSummary}</span>
                : undefined}
          >
            {sideBar === 'interfaces' && (
              <CaptureInterfacePanel
                interfaces={agentInterfaces}
                adapters={adapters}
                selectedInterfaces={selectedInterfaces}
                onToggle={handleToggleInterface}
                interfaceRates={interfaceRates}
                agentHealth={agentHealth}
                isCapturing={isCapturing}
                captureOwnedElsewhere={
                  captureOwner !== null && captureOwner !== agentClientId
                }
                onOpenSettings={() => setSheet('settings')}
                onSamplingChange={handleInterfaceSampling}
                captureOptions={captureOptions}
                onCaptureOptionsChange={patchCaptureOptions}
                filterVerdict={captureFilterVerdict}
                stopNote={captureStopReason === null
                  ? null
                  : `The last capture stopped itself: ${stopReasonText(captureStopReason)}.`}
              />
            )}
            {sideBar === 'schedule' && (
              <CaptureSchedulePanel
                schedule={schedule}
                onScheduleChange={setSchedule}
                presets={schedulePresets}
                onPresetsChange={setSchedulePresets}
                bufferedPackets={packets.length}
                now={scheduleNow}
                isCapturing={isCapturing}
                startedAt={captureStartedAtRef.current}
              />
            )}
            {sideBar === 'network' && (
              <NetworkPane
                adapters={adapters}
                facts={networkFacts}
                captureInterfaces={selectedInterfaces}
                agentConnected={agentStatus === 'connected'}
                onOpenSpeedTest={() => setSheet('speedtest')}
                onOpenMonitoring={() => setSheet('monitoring')}
              />
            )}
            {sideBar === 'transfer' && (
              <TransferPanel
                // The full buffer, never `filteredPackets` or
                // `dashboardPackets`: what this writes is what was captured,
                // and the scope control inside it is the one place that
                // narrows it.
                packets={packets}
                appliedFilter={appliedFilter}
                permissions={permissions}
                captureStats={captureStats}
                // The whole capture, not the window: where the window sits on
                // disk, the scan that answers the filter below it, and the two
                // counts the title row already shows. Every one is a number or
                // a value that changes only when its subject does - `rescan`
                // is stable - so none of them adds a render or a computation
                // this component was not already doing.
                belowWindow={Math.max(0, belowWindow - captureFloor)}
                captureRowCount={captureRowCount}
                filteredRowCount={shownRowCount}
                filterScan={captureFilter.state}
                filterUncovered={filterUncovered}
                onRescan={captureFilter.rescan}
                agentInterfaces={agentInterfaces}
                captureSource={captureSource}
                onImportPackets={handleImportPackets}
                onImportBatch={handleImportBatch}
                captureId={captureStorage.captureId}
                capturedFileCount={keptFiles(captureFiles).length}
                capturing={isCapturing}
                importBlockedBy={reopening ? 'Not while the last capture is being reopened - an import would replace it.' : null}
              />
            )}
          </SideBar>
        )}

        {/* **The sash IS the gap**, which is what VS Code's is: a grid sash
            centred on the boundary between two cards. 4px wide, matching the
            `ml-1` it replaces, so opening the side bar moves `<main>`'s edge by
            exactly the column's width and not a pixel more.

            **It paints nothing at rest**, and that is a departure from the two
            dividers below. Those sit between two panes inside ONE card, where
            they are the border as well as the handle, so a resting grey bar is
            correct. Here two card borders already draw the edge across a 4px
            gutter, and a third line in the middle of it is clutter.

            The grab zone is widened with a pseudo-element rather than with
            width, because width here is the gap and the gap is load-bearing. */}
        {sideBar !== null && (
          <div
            role="separator"
            aria-orientation="vertical"
            aria-label="Side bar width"
            aria-valuenow={Math.round(sideBarPrefs.width)}
            aria-valuemin={MIN_SIDE_BAR_PX}
            aria-valuemax={Math.round(
              Math.max(MIN_SIDE_BAR_PX, window.innerWidth - RAIL_PX - MAIN_RESERVE_PX),
            )}
            tabIndex={0}
            title="Drag to resize - right-click, double-click or Enter to reset"
            onPointerDown={() => beginDrag('side-bar')}
            onDoubleClick={() => patchSideBar({ width: SIDE_BAR_DEFAULTS.width })}
            // Right-click restores the default on every draggable bar in this
            // app; `stopPropagation` keeps the packet list's own row menu out.
            onContextMenu={(e) => {
              e.preventDefault();
              e.stopPropagation();
              patchSideBar({ width: SIDE_BAR_DEFAULTS.width });
            }}
            onKeyDown={(e) => {
              const step = e.shiftKey ? 48 : 8;
              if (e.key === 'ArrowLeft') { e.preventDefault(); nudgeSideBar(-step); }
              else if (e.key === 'ArrowRight') { e.preventDefault(); nudgeSideBar(step); }
              else if (e.key === 'Home') { e.preventDefault(); nudgeSideBar(-9999); }
              else if (e.key === 'End') { e.preventDefault(); nudgeSideBar(9999); }
              else if (e.key === 'Enter') {
                e.preventDefault();
                patchSideBar({ width: SIDE_BAR_DEFAULTS.width });
              }
            }}
            className="w-1 shrink-0 z-10 cursor-col-resize relative
              after:absolute after:inset-y-0 after:-left-1 after:-right-1
              transition-colors hover:bg-handle-hover
              focus-visible:outline-none focus-visible:bg-handle-hover"
          />
        )}

        <main className={`${sideBarOpen ? '' : 'ml-1'} flex-1 flex flex-col min-w-0 overflow-hidden
          border border-border rounded-lg bg-background`}>
          {/* **The filter row was here and there is no filter row.**

              The rule it carried had been rewritten three times and the third
              was right about the wrong thing. It said the row is rendered by
              NAMING Packets rather than by excluding the views that do not want
              it - because a display filter above Statistics, the Routing Map,
              Follow Stream or Frame Detail is a control with nothing in view to
              act on, and an exclusion list silently hands the row to anything
              added later.

              **What that rule never questioned is why the filter had to be
              somewhere a view could hide it.** A display filter does not act on
              what is in view; it acts on the CAPTURE, and `captureScan` answers
              it over the whole thing on disk. The field belongs to the app, not
              to a pane - so it is in the title row, visible from everywhere, and
              the old problem is solved the other way round: **applying a filter
              goes to Packets**, because looking at what a filter selected is the
              point of applying one. A control that takes you to its subject is
              not a control with nothing to act on.

              That also deletes the 44px strip it lived in, the banner it carried
              - the status bar reports the agent now, and one fault wants one
              place - and `FilterRow.tsx` itself. The restore readout moved into
              the status bar's left group, which is where session state lives. */}

          {/* The views. One row still, because Statistics and Follow Stream are
              siblings of the packet list rather than children of it. */}
          {/* **Settings takes the workspace, and is not a view.**

              It was the last modal that was a place: `fixed inset-0`, a 70%
              scrim, a `max-w-5xl` panel and an X. Everything about that said
              "you are somewhere else for a moment", and Settings is not a
              moment - the dissector editor, the colour rules, the filter
              presets and the Update Center all live in it. Same argument that
              promoted Frame Detail: a modal is a detour, a pane is a place.

              **And it is deliberately not in `APP_VIEWS`.** That list answers
              one question - is this a way of looking at the capture? - and
              nothing in Settings changes when a packet arrives, which is the
              exact test that moved Network out of the view list and into a tab
              of this pane. Putting Settings in the rail's numbering would
              reverse that with no new argument. So it takes the card the way a
              sheet does: the view underneath is untouched and still
              `restoredView`-able, and leaving Settings puts it back.

              Rendered BEFORE the views and returning early, rather than beside
              them, so there is one surface in this card at a time by
              construction. */}
          {/* **Network was the second sheet and is a side bar PANEL now.**

              It took the whole workspace to describe the machine, which meant
              covering the capture to say what the capture is running on. It
              sits beside it instead, which is also what makes its "Observed
              (capture)" column live while frames arrive - the argument for the
              move, and one a sheet could not make.

              `sheet` is down to one member and stays a union all the same: it
              answers "what is IN the workspace card", and a second full-pane
              surface would join this list rather than sit beside it. */}
          {sheet === 'settings' ? (
            <SettingsPane
              agentHealth={agentHealth}
              onStartAgentService={startAgentService}
              agentError={agentError}
              heapNotice={heapNotice}
              agentStatus={agentStatus}
              agentVersion={agentVersion}
              agentOutdated={agentOutdated}
              agentNpcapAccess={agentNpcapAccess}
              agentInterfaces={agentInterfaces}
              droppedBuffer={droppedBuffer}
              linkChanges={linkChanges}
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
              filterPresetLibrary={filterPresetLibrary}
              onFilterPresetLibraryChange={handleFilterPresetLibraryChange}
            />
          ) : sheet === 'speedtest' ? (
            // The speed test (ADR 0054): opened from the Network panel, a sheet
            // by the same rules as Settings - the view underneath is untouched
            // and the back step, Escape or any view leaves it. Leaving does not
            // stop a test; the state is `services/speedTest/state.ts`'s.
            <SpeedTestSheet capturing={isCapturing} onShowOnMap={() => handleViewChange('geo')} />
          ) : sheet === 'monitoring' ? (
            // NetFlow v5 monitoring (ADRs 0058-0060): opened from the Network
            // panel or the palette, a sheet by the same rules. Leaving does not
            // stop collection; the client is `getMonitoringClient()`'s. The
            // capture pivot is the filter field's own path, so it lands on
            // Packets and closes the sheet as any applied filter does.
            <MonitoringSheet onFilterCapture={(expression) => { setFilterText(expression); applyFilter(expression); }} />
          ) : (
          <div className="flex-1 flex min-h-0 overflow-hidden">
            {/* Main Packet Inspection Core */}
            {/* Kept MOUNTED while another view is active, and hidden with
                `display: none`.

                Unmounting it would be cheaper per frame and is the wrong trade: the
                list is virtualised, so its scroll offset is a function of a row
                height and a window that would have to be measured and restored by
                hand, and the selection would have to be re-found in a buffer that
                has grown in the meantime. Coming back to Statistics and finding the
                packet list exactly where it was left is worth a subtree that keeps
                rendering while invisible.

                An inline style rather than Tailwind's `hidden`: that utility and
                `flex` are the same specificity, so which one wins depends on their
                order in the emitted stylesheet. This cannot be got wrong. */}
            <section
              style={view === 'packets' ? undefined : { display: 'none' }}
              className="flex-1 flex flex-col border-r border-border overflow-hidden min-w-0"
            >
              {/* Upper Pane: High-Density Packet Table */}
              <div
                // The tour highlights the pane rather than a row: it runs before
                // there are any rows. See components/tour/tourSteps.
                data-tour="list"
                className="flex-1 flex flex-col min-h-0 overflow-hidden"
              >
                <PacketList
                  previousCapture={lastCaptureLabel === null ? null
                    : { label: lastCaptureLabel.replace(/^the capture from /, ''), onReopen: () => { void reopenLastCapture(); } }}
                  capturing={isCapturing}
                  onChooseAdapter={() => showSideBar('interfaces')}
                  onClearFilter={() => { setFilterText(''); applyFilter(''); }}
                  names={nameMap}
                  resolveNames={nameResolution.network}
                  sourceProcess={sourceProcessFor}
                  packets={filteredPackets}
                  // Both arrays, because they mean different things to the row
                  // space: `packets` is what `belowWindow` was measured against
                  // and therefore indexes the capture, `filteredPackets` is what
                  // to show. Their identity is also how "no filter" is known -
                  // the same check the selection-visibility effect above uses.
                  allPackets={packets}
                  below={belowWindow}
                  floor={captureFloor}
                  filterScan={captureFilter.state}
                  themeKey={resolvedTheme}
                  selectedPacket={selectedPacket}
                  onSelectPacket={(pkt) => setSelectedPacket(pkt)}
                  // A double-click opens the Frame Detail view on that frame.
                  // It used to open a modal over this list; the row is selected
                  // first so the view has something to show and so the list is
                  // on the same frame when it is come back to.
                  onInspectPacket={(pkt) => { setSelectedPacket(pkt); setView('detail'); }}
                  onFollowStream={handleFollowStream}
                  onQuickFilter={handleQuickFilter}
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
                className="block h-1.5 w-full cursor-row-resize transition-colors shrink-0 z-10 bg-muted hover:bg-handle-hover"
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
                // The sizes are inherited from the root, which is where they are
                // set - see `layoutVarsRef`. This element is what a drag
                // measures, not what it writes.
                className={`h-[var(--bottom-pane-height)] border-t border-border flex ${stacked ? "flex-col" : "flex-row"} overflow-hidden transition-colors shrink-0 bg-card`}
              >
                {/* **The tree, then the dump**, and one divider between
                    them. There was a map ahead of the tree - the Routing Map
                    view's own drawing, at pane size - and it is gone: the map
                    is a VIEW and nothing else now, so it is mounted in exactly
                    one place at a time by construction rather than by a guard
                    on `view === 'packets'` that existed only to keep a second
                    WebGL context from being built behind a hidden section.

                    The divider resizes the pane on its LEFT and the hex dump
                    absorbs the difference - it is `flex-1`, the tree carries a
                    stored share. That is why the dump is last: it is the pane
                    with no minimum content width worth defending, since a dump
                    narrower than its own 16-byte row wraps into nonsense while
                    the tree truncates field names. */}

                {/* Protocol Layers Inspection Tree */}
                <div
                  // On the container, not inside the tree pane - that renders
                  // two different trees for "a packet" and "no packet", and the
                  // tour needs one anchor that exists in both states.
                  data-tour="detail"
                  className={`block min-w-0 overflow-hidden shrink-0 ${
                    stacked
                      ? "w-full h-[var(--details-pane-size)]"
                      : "w-[var(--details-pane-size)] h-full"
                  }`}
                >
                  <LinkedDetailsTree
                    packet={selectedPacketDetail}
                    onSelectFrame={goToFrame}
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
                  className={`block transition-colors shrink-0 z-10 bg-muted hover:bg-handle-hover ${
                    stacked ? "h-1.5 w-full cursor-row-resize" : "w-1.5 h-full cursor-col-resize"
                  }`}
                  title="Drag to resize - right-click, double-click or Enter to even out"
                  onPointerDown={() => beginDrag("split")}
                  onDoubleClick={() => patchLayout({
                    detailsPaneRatio: LAYOUT_DEFAULTS.detailsPaneRatio,
                  })}
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
                    else if (e.key === "Enter") {
                      e.preventDefault();
                      patchLayout({ detailsPaneRatio: LAYOUT_DEFAULTS.detailsPaneRatio });
                    }
                  }}
                />

                {/* Raw Hex & ASCII Dump View */}
                <div
                  className="block w-full flex-1 h-full min-w-0 overflow-hidden"
                >
                  <LinkedHexViewer
                    packet={selectedPacketDetail}
                    bytesState={selectedDetailState}
                    permissions={permissions}
                  />
                </div>

              </div>
              )}
            </section>

            {/* Frame Detail as a pane, where the packet list would be.

                Unmounted when it is not the active view, like Statistics and
                the map: it draws a field table over one frame's whole tree,
                and there is no scroll position worth keeping across a view
                change - the pane already scrolls itself back to the top of the
                fields whenever the frame changes.

                `selectedPacketDetail` rather than a frame of its own. The
                packet list's own panes are handed exactly this, from the one
                `usePacketDetail` above: the list is hidden rather than
                unmounted while this view is active, so a second hook on the
                same frame would be a second replay request for one tree.

                Unguarded, unlike Follow Stream: with nothing selected this pane
                renders its go-to-frame box, which is the view's way in rather
                than an empty state to be prevented. `scripts/session/view.ts`
                holds that to `restoredView` - a view with no extra condition
                here has to be one that survives a restart. */}
            {view === 'detail' && (
              <PacketDetailPane
                packets={packets}
                packet={selectedPacketDetail}
                detailState={selectedDetailState}
                filteredPackets={filteredPackets}
                onShowFrame={goToFrame}
                onFollowStream={handleFollowStream}
                colorEngine={colorEngine}
                permissions={permissions}
              />
            )}

            {/* Statistics as a pane, where the packet list would be.

                Unmounted when it is not the active view, unlike the packet list
                above: it holds no scroll position worth keeping and its tables are
                a full pass over the buffer, so leaving it mounted would aggregate
                50,000 packets twice a second for a surface nobody is looking at.
                The list is the exception, not the rule. */}
            {view === 'statistics' && (
              <StatisticsPane
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
                // The TCP level reads the store's digest, the whole capture
                // with each stream's outcome - the one table here that does
                // not count the buffer (ADR 0055).
                tcpDigest={streamDigest}
                onSelectFrame={goToFrame}
                droppedBuffer={droppedBuffer}
                // Every row here is a filter, so applying one means going to look
                // at the frames it selects. That is the cross-view navigation the
                // plan specifies, and it falls out of the pane's own model.
                onReturnToPackets={() => setView('packets')}
                // For the Graphs tab alone - the charts moved here from the
                // dock, and the timeline's D3 draw needs a theme key to redraw
                // on. Every other tab in the pane is a table and takes neither.
                isDark={isDark}
                themeKey={resolvedTheme}
              />
            )}

            {/* The map as a pane, where the packet list would be.

                Unmounted when it is not the active view, for the same reason
                Statistics is and one more: this is a MapLibre instance, so a
                hidden-but-mounted copy would be a WebGL context and a tile
                fetcher running for a surface nobody is looking at. This is the
                only place it is mounted - there was a second, pane-sized copy in
                the Packets view's bottom row, and "exactly one map is ever live"
                needed a guard to stay true where it is now a fact about the
                tree.

                `dashboardPackets` rather than `packets`: the throttled feed, the
                same one the dock's widgets took. The map redraws arcs on every
                change and the live buffer changes ten times a second. */}
            {view === 'geo' && (
              <div className="flex-1 min-w-0 overflow-hidden">
                {/* The fallback is one commit's worth of the window's own
                    ground, not a loading state. `warmGeoMap()` above has had
                    the chunk since shortly after launch, so this renders while
                    `React.lazy` resolves from its own cache. It is the ground
                    colour rather than a spinner for the reason
                    `electron/window.ts` fixes `backgroundColor`: the one frame
                    it does occupy must not be a flash of a different shade. */}
                <React.Suspense fallback={<div className="h-full w-full bg-background" />}>
                  <GeoMap
                    packets={dashboardPackets}
                    isDark={isDark}
                    themeKey={resolvedTheme}
                  />
                </React.Suspense>
              </div>
            )}

            {/* Follow Stream as a pane.

                Guarded on the target as well as the view: the two are kept in step
                by the effect above and by the rail's disabled icon, but a pane that
                rendered `target={null}` would be the empty Follow Stream the rail
                exists to prevent. */}
            {view === 'stream' && streamToFollow !== null && (
              <StreamFollowerPane
                target={streamToFollow}
                packets={packets}
                summary={streamSummary}
                captureId={streamDigest.captureId}
                colorEngine={colorEngine}
                packetTheme={packetTheme}
                initialTab={streamView}
                selectedId={selectedPacket?.id}
                // The pane stays open. Selecting a frame from in here is usually
                // one of several - reading down a conversation and checking each
                // against the tree - and leaving on the first would make that a
                // dozen round trips through the context menu.
                onSelectFrame={goToFrame}
              />
            )}


          </div>
          )}
        </main>
      </div>

      {/* **The application's bottom bar, second attempt.** The first spanned
          the window under the rail and the panes carrying the byte inspector,
          with its text pushed sideways to line up under the Hex View pane - and
          that indent was the whole argument against it: a full-width bar that
          has to be inset to look like it belongs somewhere narrower belongs
          there instead. It was deleted and the readout went back to
          `HexViewer`'s own footer.

          What was wrong was the ALIGNMENT, not the bar. A status bar does not
          line its items up with the panes above them - `Ln 56, Col 2` sits at
          the window's right edge in every editor that has one, not above the
          cursor - so the byte readout is an ordinary right-group item here with
          no inset at all. `StatusBar.tsx` carries the two rules that keep it
          that way.

          `--details-pane-size` stays on the ROOT element, and only the panes
          read it. That placement was chosen so the FIRST bar could resolve a
          percentage against the same base the panes are sized by. This one
          deliberately does not read it, and `scripts/session/status-bar.ts`
          fails if it ever starts - which turns a stale note into the marker for
          the rule. */}
      <StatusBar
        agentHealth={agentHealth}
        interfaces={agentInterfaces}
        selectedInterfaces={selectedInterfaces}
        isCapturing={isCapturing}
        captureStartedAt={captureStartedAtRef.current}
        captureStats={captureStats}
        droppedBuffer={droppedBuffer}
        bufferAutoPaused={bufferAutoPaused}
        nameResolution={nameResolution}
        restoreProgress={restoreProgress}
      />

      {/* **The geo map's expanded window was here.** A `WidgetOverlay`, fixed
          and rendered at the top level so the dock's own overflow could never
          clip it. The map is a view now - `view === 'geo'`, a pane like
          Statistics - so there is no modal to keep out of a scroll container and
          nothing that needs to escape one. */}

      {/* **The packet detail window was here.** A `fixed inset-0` backdrop with
          a 92vh panel in it, opened on `detailPacketId` and dismissed with
          Escape. It is a view now - `view === 'detail'`, in the row above with
          Statistics and the Routing Map - so there is no backdrop to escape
          from and no second frame id to keep in step with the selection. */}

      {/* **Export / Import was a modal here and is a side bar panel.** A 70%
          scrim over an app whose whole subject was on screen behind it, holding
          a sequence - what gets written, what travels with it, in which format -
          laid out as a three-column grid that scrambled that sequence's reading
          order. `ImportErrorDialog` is the one piece of it that stays a modal,
          and it lives inside the panel: a refusal that has to be acknowledged
          is a detour by every test this repo applies. */}




      {/* A jump that could not happen, said out loud.
          Bottom-centre and above the modals, because the click that triggers
          it can come from inside one - and the Frame Detail view's tree links
          and the Statistics tables both point at
          frames the buffer may since have trimmed. It never takes the pointer:
          the notice explains a refusal, it does not ask for anything. */}
      {navNotice !== null && (
        <div
          role="status"
          aria-live="polite"
          className="pointer-events-none fixed bottom-6 left-1/2 -translate-x-1/2 z-[100] max-w-md px-3.5 py-2 rounded-md border border-amber-500/40 bg-amber-500/95 dark:bg-amber-950/95 backdrop-blur-sm shadow-lg text-[11px] font-mono leading-snug text-amber-950 dark:text-amber-200 flex items-start gap-2"
        >
          <TriangleAlert className="w-4 h-4 shrink-0 mt-px" />
          <span>{navNotice}</span>
        </div>
      )}

      {/* Outside the AnimatePresence above: the tour is not one of the modals
          that swap in and out of it, and being listed there would make opening
          any modal unmount it part-way through a step. */}
      {!tour.completed && (
        <TourOverlay onDone={() => tourStore.set({ completed: true })} />
      )}

      {palette !== null && (
        <CommandPalette
          request={palette}
          ctx={commandContext}
          packets={packets}
          recentFilters={recentFilters}
          presetExpressions={presetExpressions}
          onRun={runCommand}
          onApplyFilter={(expression) => { setPalette(null); setFilterText(expression); applyFilter(expression); }}
          // Frame Detail reads the selection, so it stays; anywhere else lands
          // on the list, where a selected frame is visible.
          onGoToFrame={(id) => {
            setPalette(null);
            setSheet(null);
            setView(view === 'detail' ? 'detail' : 'packets');
            goToFrame(id);
          }}
          onClose={closePalette}
        />
      )}
    </div>
  );
}
