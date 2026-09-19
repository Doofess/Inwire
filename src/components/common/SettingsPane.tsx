import React, { useState } from 'react';
import type { AgentHealth } from '../../services/agentHealth';
import type { CaptureDropStats } from '../../services/agentProtocol';
import type { LinkChange } from '../../services/linkContext';
import {
  Settings,
  Palette,
  Activity,
  Funnel,
  Trash,
  Eraser,
  LayoutGrid,
  Accessibility,
  Key,
  Download,
  Code,
} from 'lucide-react';
import { DriverInfoPanel, DRIVER_ACTION_BUTTON_CLASS } from './DriverInfoPanel';
import { UpdateCenterPanel } from './UpdateCenterPanel';
import { AppearanceSettingsPanel } from './AppearanceSettingsPanel';
import { InterfaceSettingsPanel } from './InterfaceSettingsPanel';
import { AccessibilitySettingsPanel } from './AccessibilitySettingsPanel';
import { DisplayFiltersPanel } from './DisplayFiltersPanel';
import { ColorRulesPanel } from './ColorRulesPanel';
import { DecryptionSettingsPanel } from './DecryptionSettingsPanel';
import { CustomDissectorsPanel } from '../dissectors/CustomDissectorsPanel';
import type { CustomDissectorEngine } from '../../services/customDissectorEngine';
import type { AgentLogEntry } from '../../services/agentProtocol';
import type { ColorRule, FilterPresetLibrary, Capabilities } from '../../types/packet';
import type { PacketTheme } from '../../services/packetThemes';
import { formatBytes } from '../../lib/formatBytes';
import type { CaptureStorageState } from '../../services/capture/captureProtocol';

// Read from the constant capture actually stops at, not restated: this number
// only appears in explanatory copy, and copy that drifts from the behaviour it
// describes is worse than no copy.

/**
 * Capture folded into Driver Info rather than standing beside it.
 *
 * The Capture tab held one progress bar, two numbers and a Clear button - not
 * enough to be worth a click of its own, and the click cost more than the
 * content: the buffer is the far end of a pipeline whose near end (the driver,
 * the interface it listens on, what it is logging) was already in the next tab.
 * Reading "the driver is capturing" and "the buffer is 99% full" as two
 * separate visits made a single story into two.
 */
type SettingsSection = 'appearance' | 'interface' | 'accessibility' | 'filters' | 'colors'
  | 'dissectors' | 'decryption' | 'driver' | 'updates';

const SECTIONS: { id: SettingsSection; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'appearance', label: 'Appearance', icon: Palette },
  // Second, next to Appearance: the two are the "how it looks" pair, and
  // Appearance owns colour while this owns everything else about the UI.
  { id: 'interface', label: 'Interface', icon: LayoutGrid },
  // Third, closing the "how it looks and behaves" run before the tabs turn
  // to data and hardware. It is not a colour tab and not a layout tab: what
  // is in here is what somebody needs in order to use the app at all.
  { id: 'accessibility', label: 'Accessibility', icon: Accessibility },
  { id: 'filters', label: 'Display Filters', icon: Funnel },
  // Beside Display Filters, because a colouring rule IS a display filter with
  // a colour on it - the same expression, the same validator, the same
  // autocomplete. Splitting them across the panel would ask the reader to
  // learn the language twice.
  { id: 'colors', label: 'Colouring Rules', icon: Palette },
  // Beside Decryption, and before it, because the two are the pair that changes
  // what the dissector can READ rather than what is shown: one adds a protocol,
  // the other supplies the keys to see inside one. It was a full-screen modal
  // off the hamburger menu until that menu was deleted.
  { id: 'dissectors', label: 'Custom Dissectors', icon: Code },
  // After the two filter tabs and before the hardware one: a key log changes
  // what the dissector can read, which is the same kind of setting as a rule
  // that changes what is shown - and nothing to do with the driver.
  { id: 'decryption', label: 'Decryption', icon: Key },
  // **Network was here and is a sheet of its own now**, reached from the rail.
  // Its argument for being a tab still stands as far as it went - nothing in it
  // changes when a packet arrives, so it is not a view - but it was the wrong
  // half of the story: this panel is where the app is CONFIGURED, and Network
  // configures nothing. It is a report about the machine, and a report worth
  // one press is worth its own door. What is left here is the pair that does
  // belong: what the capture driver is doing, and which version of it you have.
  // **'Capture Health', not 'Driver Info'.** The panel was Status, Version,
  // Capture and Listening-on rows - four facts the status bar reports
  // permanently, one of them through a SECOND label table that could disagree
  // with the first. All four are deleted, and what is left is the app's only
  // full account of frames it lost: four drop stages, the buffer trim, and the
  // network transitions that explain a gap. The id stays `driver` because it is
  // a stored preference key, not a label.
  { id: 'driver', label: 'Capture Health', icon: Activity },
  // Last, directly after Capture Health, because the two answer halves of one
  // question. That tab says what the capture is losing; this says which version
  // of the driver you have and where a newer one comes from - and the banner
  // for "there is no driver" points from one to the other.
  { id: 'updates', label: 'Updates', icon: Download },
];

interface SettingsPaneProps {
  totalPacketsCount: number;
  totalBytes: number;
  packetBufferBytes: number;
  bufferResidentBytes: number;
  bufferAutoPaused: boolean;
  onClearPackets: () => void;
  /** What the capture store holds. The capture on disk IS this now. */
  captureStorage: CaptureStorageState;
  /** Deletes the stored capture. The only thing in the app that does. */
  onDiscardCapture: () => void;
  /** The display-filter presets, shared with the header's Presets dropdown. */
  filterPresetLibrary: FilterPresetLibrary;
  onFilterPresetLibraryChange: (library: FilterPresetLibrary) => void;
  /** The colouring chain, shared with the packet list's engine. */
  colorRules: ColorRule[];
  onColorRulesChange: (rules: ColorRule[]) => void;
  /** The active packet theme, so a rule previews in the colours it will use. */
  packetTheme: PacketTheme;
  permissions: Capabilities;
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  agentVersion: string | null;
  agentOutdated: boolean;
  /** The Npcap device object's DACL from `hello`, for the Update Center's row. */
  agentNpcapAccess?: string | null;
  captureStats?: CaptureDropStats | null;
  /** Frames pushed out of the browser's buffer because it filled. */
  droppedBuffer?: number;
  /** Network transitions observed this session. */
  linkChanges?: LinkChange[];
  agentInterfaces: { name: string; label: string }[];
  agentLog: AgentLogEntry[];
  agentLinkEnabled: boolean;
  /** Why the agent link is down, and whether the app can offer to fix it. */
  agentHealth: AgentHealth;
  onStartAgentService: () => void;
  agentError: string | null;
  /** What the renderer's heap guard has said, or null. */
  heapNotice?: string | null;
  onConnectAgent: () => void;
  onDisconnectAgent: () => void;
  onRestartAgent: () => void;
  onSubscribeAgentLog: () => void;
  onUnsubscribeAgentLog: () => void;
  onClearAgentLog: () => void;

  /* --- Custom Dissectors, which was a modal off the deleted menu ---------- */
  dissectorEngine: CustomDissectorEngine;
  onUpdateDissectors: () => void;

  /* --- Network was here, and is its own sheet off the rail now ------------ */
}

export const SettingsPane: React.FC<SettingsPaneProps> = ({
  totalPacketsCount,
  totalBytes,
  packetBufferBytes,
  bufferResidentBytes,
  bufferAutoPaused,
  onClearPackets,
  captureStorage,
  onDiscardCapture,
  filterPresetLibrary,
  onFilterPresetLibraryChange,
  colorRules,
  onColorRulesChange,
  packetTheme,
  permissions,
  agentStatus,
  agentVersion,
  agentOutdated,
  agentNpcapAccess,
  captureStats,
  droppedBuffer,
  linkChanges,
  agentInterfaces,
  agentLog,
  agentLinkEnabled,
  agentHealth,
  onStartAgentService,
  agentError,
  heapNotice,
  onConnectAgent,
  onDisconnectAgent,
  onRestartAgent,
  onSubscribeAgentLog,
  onUnsubscribeAgentLog,
  onClearAgentLog,
  dissectorEngine,
  onUpdateDissectors,
}) => {
  const [section, setSection] = useState<SettingsSection>('appearance');
  const bufferPercent = packetBufferBytes > 0
    ? Math.min(100, (bufferResidentBytes / packetBufferBytes) * 100)
    : 0;

  return (
    /* **A pane, not a modal, and this is the last one that was a place.**
     *
     * It was `fixed inset-0`, a 70% black scrim and a `max-w-5xl` panel at
     * `max-h-[90vh]`. Everything about that said "you are somewhere else for a
     * moment": the app dimmed behind it, the window's own chrome was covered,
     * and the way out was an X in a corner. Settings is not a moment - it is
     * where the dissector editor, the colour rules, the filter presets and the
     * Update Center live, and people work in it.
     *
     * The same argument promoted Frame Detail from a modal, and the ADR-shaped
     * version of it is in `App.tsx`: a modal is a detour, a pane is a place.
     *
     * **It is deliberately not a VIEW**, and that is the interesting half.
     * `APP_VIEWS` answers one question - is this a way of looking at the
     * capture? - and Settings is not: nothing in it changes when a packet
     * arrives, which is exactly the test that moved Network out of the view list
     * and into a tab of this pane. So it takes the workspace card without
     * joining the rail's numbering, the way a sheet does, and `AppView` is
     * untouched.
     *
     * No border, no radius, no shadow and no ground of its own: `<main>` is the
     * card and draws all four, so anything here would be a second card inside
     * the first. */
    <div className="h-full min-h-0 flex flex-col bg-background text-foreground">
      <>
        {/* No close button. Every other pane is left the same three ways - the
            back step in the title row, Escape, or the rail - and an X here
            would be a fourth door on one room, in the one pane that used to be
            a modal. The rail's Settings icon shows its active state while this
            is up, which is how the rail says "you are here" for every view. */}
        <div className="px-5 py-3.5 border-b border-border flex items-center">
          <div className="flex items-center gap-2.5">
            <Settings className="w-7 h-7 shrink-0 text-primary" />
            <div>
              <div className="font-bold text-base">Settings</div>
              <p className="text-xs text-muted-foreground">Appearance and application preferences</p>
            </div>
          </div>
        </div>

        {/* Body: sidebar + section */}
        <div className="flex min-h-0 flex-1">
          <nav className="w-44 shrink-0 border-r border-border p-2 flex flex-col gap-1">
            {SECTIONS.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setSection(id)}
                className={`flex items-center gap-2 px-2.5 py-2 rounded-md text-xs font-medium text-left transition-colors ${
                  section === id
                    ? 'bg-accent text-foreground'
                    : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground'
                }`}
              >
                <Icon className="w-3.5 h-3.5 shrink-0" />
                <span>{label}</span>
              </button>
            ))}
          </nav>

          <div className="flex-1 min-w-0 p-5 overflow-y-auto">
            {section === 'appearance' && <AppearanceSettingsPanel />}

            {section === 'interface' && <InterfaceSettingsPanel />}
            {section === 'accessibility' && <AccessibilitySettingsPanel />}

            {section === 'filters' && (
              <DisplayFiltersPanel
                library={filterPresetLibrary}
                onChange={onFilterPresetLibraryChange}
              />
            )}

            {section === 'colors' && (
              <ColorRulesPanel
                rules={colorRules}
                onChange={onColorRulesChange}
                theme={packetTheme}
                canEdit={permissions.canChangeColorRules}
              />
            )}

            {section === 'dissectors' && (
              <CustomDissectorsPanel
                dissectorEngine={dissectorEngine}
                onUpdateDissectors={onUpdateDissectors}
                permissions={permissions}
              />
            )}

            {section === 'decryption' && <DecryptionSettingsPanel />}

            {section === 'updates' && (
              <UpdateCenterPanel
                agentVersion={agentVersion}
                agentOutdated={agentOutdated}
                agentNpcapAccess={agentNpcapAccess}
                onShowDriverInfo={() => setSection('driver')}
              />
            )}

            {/* Mounted only while selected, so the log subscription starts
                and stops with the section rather than with the modal. */}
            {section === 'driver' && (
              <DriverInfoPanel
                agentStatus={agentStatus}
                captureStats={captureStats}
                droppedBuffer={droppedBuffer}
                linkChanges={linkChanges}
                agentInterfaces={agentInterfaces}
                agentLog={agentLog}
                agentLinkEnabled={agentLinkEnabled}
                agentError={agentError}
                heapNotice={heapNotice}
                onConnect={onConnectAgent}
                onDisconnect={onDisconnectAgent}
                onRestartAgent={onRestartAgent}
                agentHealth={agentHealth}
                onStartAgentService={onStartAgentService}
                onShowUpdates={() => setSection('updates')}
                onSubscribe={onSubscribeAgentLog}
                onUnsubscribe={onUnsubscribeAgentLog}
                onClearLog={onClearAgentLog}
                captureSection={
                  <div className="flex flex-col gap-4">
                    <div>
                      <div className="text-xs font-semibold text-foreground mb-2">Capture buffer</div>
                      <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                        <div
                          className={`h-full transition-all ${bufferPercent >= 99 ? 'bg-rose-500' : bufferPercent >= 75 ? 'bg-amber-500' : 'bg-primary'}`}
                          style={{ width: `${bufferPercent}%` }}
                        />
                      </div>
                      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs mt-3">
                        <dt className="text-muted-foreground">Used</dt>
                        <dd className="font-mono">
                          {totalPacketsCount.toLocaleString()} packets, {(bufferResidentBytes / 1024 / 1024).toFixed(0)} / {(packetBufferBytes / 1024 / 1024).toFixed(0)} MB
                          <span className="text-muted-foreground"> ({bufferPercent.toFixed(1)}%)</span>
                        </dd>
                        <dt className="text-muted-foreground">Captured</dt>
                        <dd className="font-mono">{formatBytes(totalBytes)}</dd>
                      </dl>
                    </div>

                    {bufferAutoPaused && (
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-600 dark:text-amber-400">
                        Capture stopped automatically: the disk holding the capture is
                        nearly full. Free some space, or discard this capture, and start again.
                      </div>
                    )}

                    {/* Two actions, because they are two different things and
                        one button used to do both. "Clear View" frees the
                        memory the list is holding; the capture stays on disk and
                        can still be exported or reopened. "Discard Capture" is
                        the one that destroys it - nothing else in the app does,
                        not closing the last window and not reopening it
                        (docs/decisions/0012-stored-captures-persist.md).

                        The same pill as the three driver actions above: they sit
                        in the same tab and do the same kind of thing, and two
                        shapes for one job read as two kinds of job. */}
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        onClick={onClearPackets}
                        disabled={totalPacketsCount === 0}
                        className={DRIVER_ACTION_BUTTON_CLASS}
                      >
                        <Eraser className="w-3.5 h-3.5" />
                        <span>Clear View</span>
                      </button>
                      <button
                        onClick={onDiscardCapture}
                        disabled={captureStorage.bytesOnDisk === 0 && totalPacketsCount === 0}
                        className={DRIVER_ACTION_BUTTON_CLASS}
                      >
                        <Trash className="w-3.5 h-3.5" />
                        <span>Discard Capture</span>
                      </button>
                    </div>

                    {/* Bytes that outlive the app should never be a surprise,
                        so the amount is stated next to the button that removes
                        it. There used to be a second figure here for the
                        IndexedDB session, written beside this one while the
                        capture store was a shadow; there is no second copy any
                        more, and no 512 MB budget quietly deleting the oldest
                        frames to stay under it.

                        The frame span is stated because it is load-bearing
                        rather than decorative: the buffer may only drop a
                        frame's bytes from memory once that frame is inside it,
                        so a reader wondering why memory is not coming down is
                        looking for this number. */}
                    {captureStorage.captureId !== null && captureStorage.bytesOnDisk > 0 ? (
                      <p className="text-[11px] text-muted-foreground">
                        <span className="font-medium text-foreground">
                          {(captureStorage.bytesOnDisk / 1_000_000).toFixed(1)} MB
                        </span>
                        {' stored on disk ('}
                        {captureStorage.framesWritten.toLocaleString()} frames
                        {captureStorage.stagedCount > 0
                          && `, ${captureStorage.stagedCount.toLocaleString()} waiting`}
                                                {'). This capture is kept until you discard it — closing Inwire '}
                        does not delete it.
                        {captureStorage.storedRange !== null && (
                          <>
                            {' Frames '}
                            {captureStorage.storedRange.first.toLocaleString()}
                            {'\u2013'}
                            {captureStorage.storedRange.last.toLocaleString()}
                            {' can have their bytes read back, so the buffer is free to stop'}
                            {' holding them.'}
                          </>
                        )}
                        {captureStorage.freeBytes !== null && (
                          <>
                            {' '}
                            {(captureStorage.freeBytes / 1_000_000_000).toFixed(1)} GB free
                            {' where they are kept.'}
                          </>
                        )}
                      </p>
                    ) : (
                      <p className="text-[11px] text-muted-foreground">
                        Nothing is stored on disk yet.
                      </p>
                    )}
                    {captureStorage.error !== null && (
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-600 dark:text-amber-400">
                        The capture store reported: {captureStorage.error}
                      </div>
                    )}
                    {/* Frames whose row was sealed before a patch could reach
                        it. Zero on both fixtures at the default horizon, so a
                        non-zero number here is the signal that the horizon is
                        too short - not something to leave unsaid. */}
                    {captureStorage.patchesMissed > 0 && (
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-600 dark:text-amber-400">
                        {captureStorage.patchesMissed.toLocaleString()} cross-reference
                        {captureStorage.patchesMissed === 1 ? '' : 's'} arrived after the row had
                        been written, so the stored copy is missing them.
                      </div>
                    )}

                  </div>
                }
              />
            )}
          </div>
        </div>

        {/* **The footer's Close button went with the X and the scrim.** A
            modal is dismissed, so it needs a dismissal; a pane is left, and
            this one is left the way every other pane is. Two buttons doing that
            in one surface was already one too many while it was a modal - the X
            above and this - and neither survives the move. */}
      </>
    </div>
  );
};
