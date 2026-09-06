import React, { useState } from 'react';
import type { CaptureDropStats } from '../../services/agentProtocol';
import type { LinkChange, LinkContext } from '../../services/linkContext';
import { motion } from 'motion/react';
import {
  TbSettings, TbX, TbPalette, TbActivity, TbFilter, TbTrash, TbEraser, TbLayoutBoard, TbAccessible, TbKey,
} from 'react-icons/tb';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';
import { DriverInfoPanel, DRIVER_ACTION_BUTTON_CLASS } from './DriverInfoPanel';
import { AppearanceSettingsPanel } from './AppearanceSettingsPanel';
import { InterfaceSettingsPanel } from './InterfaceSettingsPanel';
import { AccessibilitySettingsPanel } from './AccessibilitySettingsPanel';
import { DisplayFiltersPanel } from './DisplayFiltersPanel';
import { ColorRulesPanel } from './ColorRulesPanel';
import { DecryptionSettingsPanel } from './DecryptionSettingsPanel';
import type { AgentLogEntry } from '../../services/agentProtocol';
import type { ColorRule, FilterPresetLibrary, Capabilities } from '../../types/packet';
import type { PacketTheme } from '../../services/packetThemes';

// Mirrors AUTO_PAUSE_AT in App.tsx, purely for the explanatory copy below.
const AUTO_PAUSE_PERCENT = 99;

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
type SettingsSection = 'appearance' | 'interface' | 'accessibility' | 'filters' | 'colors' | 'decryption' | 'driver';

const SECTIONS: { id: SettingsSection; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'appearance', label: 'Appearance', icon: TbPalette },
  // Second, next to Appearance: the two are the "how it looks" pair, and
  // Appearance owns colour while this owns everything else about the UI.
  { id: 'interface', label: 'Interface', icon: TbLayoutBoard },
  // Third, closing the "how it looks and behaves" run before the tabs turn
  // to data and hardware. It is not a colour tab and not a layout tab: what
  // is in here is what somebody needs in order to use the app at all.
  { id: 'accessibility', label: 'Accessibility', icon: TbAccessible },
  { id: 'filters', label: 'Display Filters', icon: TbFilter },
  // Beside Display Filters, because a colouring rule IS a display filter with
  // a colour on it - the same expression, the same validator, the same
  // autocomplete. Splitting them across the panel would ask the reader to
  // learn the language twice.
  { id: 'colors', label: 'Colouring Rules', icon: TbPalette },
  // After the two filter tabs and before the hardware one: a key log changes
  // what the dissector can read, which is the same kind of setting as a rule
  // that changes what is shown - and nothing to do with the driver.
  { id: 'decryption', label: 'Decryption', icon: TbKey },
  { id: 'driver', label: 'Driver Info', icon: TbActivity },
];

interface SettingsModalProps {
  onClose: () => void;
  totalPacketsCount: number;
  totalBytes: number;
  packetBufferBytes: number;
  bufferResidentBytes: number;
  bufferAutoPaused: boolean;
  onClearPackets: () => void;
  /**
   * What is on disk, and what the disk is allowed to keep.
   *
   * `evictedForBudget` is the honest half: since the app stopped deleting
   * captures on close (docs/decisions/0012), the storage budget is the only
   * automatic deletion left, and it silently takes the *beginning* of a long
   * capture. An app that promises to keep a capture until asked has to say
   * when it could not.
   */
  storage: { storedBytes: number; storageBudgetBytes: number; evictedForBudget: number };
  /** Deletes the stored capture. The only thing in the app that does. */
  onDiscardCapture: () => void;
  /** The agent pairing block, rendered at the top of Driver Info. */
  pairingSection?: React.ReactNode;
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
  agentCaptureState: 'idle' | 'sniffing';
  captureStats?: CaptureDropStats | null;
  /** Frames pushed out of the browser's buffer because it filled. */
  droppedBuffer?: number;
  /** What the browser says about the link, or null where it says nothing. */
  linkContext?: LinkContext | null;
  /** Network transitions observed this session. */
  linkChanges?: LinkChange[];
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  agentLog: AgentLogEntry[];
  agentLinkEnabled: boolean;
  agentError: string | null;
  onConnectAgent: () => void;
  onDisconnectAgent: () => void;
  onRestartAgent: () => void;
  onSubscribeAgentLog: () => void;
  onUnsubscribeAgentLog: () => void;
  onClearAgentLog: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  onClose,
  totalPacketsCount,
  totalBytes,
  packetBufferBytes,
  bufferResidentBytes,
  bufferAutoPaused,
  onClearPackets,
  storage,
  onDiscardCapture,
  filterPresetLibrary,
  onFilterPresetLibraryChange,
  colorRules,
  onColorRulesChange,
  packetTheme,
  pairingSection,
  permissions,
  agentStatus,
  agentVersion,
  agentOutdated,
  agentCaptureState,
  captureStats,
  droppedBuffer,
  linkContext,
  linkChanges,
  agentInterfaces,
  selectedInterfaces,
  agentLog,
  agentLinkEnabled,
  agentError,
  onConnectAgent,
  onDisconnectAgent,
  onRestartAgent,
  onSubscribeAgentLog,
  onUnsubscribeAgentLog,
  onClearAgentLog,
}) => {
  const [section, setSection] = useState<SettingsSection>('appearance');
  const bufferPercent = packetBufferBytes > 0
    ? Math.min(100, (bufferResidentBytes / packetBufferBytes) * 100)
    : 0;

  return (
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
    >
      <motion.div
        {...modalPanelMotion}
        className="w-full max-w-3xl max-h-[90vh] rounded-xl border flex flex-col shadow-2xl transition-colors bg-card border-border text-card-foreground"
      >
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <TbSettings className="w-7 h-7 shrink-0 text-primary" />
            <div>
              <div className="font-bold text-base">Settings</div>
              <p className="text-xs text-muted-foreground">Appearance and application preferences</p>
            </div>
          </div>

          <button onClick={onClose} className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground">
            <TbX className="w-5 h-5" />
          </button>
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

            {section === 'decryption' && <DecryptionSettingsPanel />}

            {/* Mounted only while selected, so the log subscription starts
                and stops with the section rather than with the modal. */}
            {section === 'driver' && (
              <DriverInfoPanel
                agentStatus={agentStatus}
                agentVersion={agentVersion}
                agentOutdated={agentOutdated}
                agentCaptureState={agentCaptureState}
                captureStats={captureStats}
                droppedBuffer={droppedBuffer}
                linkContext={linkContext}
                linkChanges={linkChanges}
                agentInterfaces={agentInterfaces}
                selectedInterfaces={selectedInterfaces}
                agentLog={agentLog}
                agentLinkEnabled={agentLinkEnabled}
                agentError={agentError}
                onConnect={onConnectAgent}
                onDisconnect={onDisconnectAgent}
                onRestartAgent={onRestartAgent}
                onSubscribe={onSubscribeAgentLog}
                onUnsubscribe={onUnsubscribeAgentLog}
                onClearLog={onClearAgentLog}
                pairingSection={pairingSection}
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
                        <dd className="font-mono">{(totalBytes / 1024 / 1024).toFixed(2)} MB</dd>
                      </dl>
                    </div>

                    {bufferAutoPaused && (
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-600 dark:text-amber-400">
                        Capture stopped automatically: the buffer reached {(AUTO_PAUSE_PERCENT).toFixed(0)}% and
                        older packets would have started falling off the back. Clear the buffer to start again.
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
                        <TbEraser className="w-3.5 h-3.5" />
                        <span>Clear View</span>
                      </button>
                      <button
                        onClick={onDiscardCapture}
                        disabled={storage.storedBytes === 0 && totalPacketsCount === 0}
                        className={DRIVER_ACTION_BUTTON_CLASS}
                      >
                        <TbTrash className="w-3.5 h-3.5" />
                        <span>Discard Capture</span>
                      </button>
                    </div>

                    {/* Bytes that outlive the app should never be a surprise,
                        so the amount is stated next to the button that removes
                        it rather than left to be inferred. */}
                    <p className="text-[11px] text-muted-foreground">
                      {storage.storedBytes > 0 ? (
                        <>
                          <span className="font-medium text-foreground">
                            {(storage.storedBytes / 1_000_000).toFixed(1)} MB
                          </span>
                          {storage.storageBudgetBytes > 0 && (
                            <> of {(storage.storageBudgetBytes / 1_000_000).toFixed(0)} MB</>
                          )}
                          {' stored on disk. This capture is kept until you discard it — '}
                          closing Inwire no longer deletes it.
                        </>
                      ) : (
                        'Nothing is stored on disk yet.'
                      )}
                    </p>

                    {/* The one thing that still deletes without being asked.
                        It takes the OLDEST frames, so a long capture quietly
                        loses its beginning - which is the half a user is least
                        likely to notice missing and most likely to want. */}
                    {storage.evictedForBudget > 0 && (
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-600 dark:text-amber-400">
                        The oldest {storage.evictedForBudget.toLocaleString()} frame
                        {storage.evictedForBudget === 1 ? ' is' : 's are'} no longer stored on
                        disk: this capture reached the{' '}
                        {(storage.storageBudgetBytes / 1_000_000).toFixed(0)} MB storage limit.
                        {' '}They are still in the buffer and still export, but a reload will
                        start from the oldest frame that is still stored.
                      </div>
                    )}
                  </div>
                }
              />
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-border flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md bg-secondary hover:bg-accent text-foreground text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
};
