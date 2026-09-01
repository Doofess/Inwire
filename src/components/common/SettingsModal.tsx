import React, { useState } from 'react';
import { motion } from 'motion/react';
import { useTheme } from 'next-themes';
import { TbSettings, TbX, TbCheck, TbPalette, TbActivity, TbFilter, TbTrash, TbLayoutBoard } from 'react-icons/tb';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';
import { SYSTEM_THEME_OPTION, THEME_OPTIONS } from '../../lib/themeOptions';
import { followSystemThemeStore } from '../../services/themePrefs';
import { usePreferenceValue } from '../../services/preferenceStore';
import { DriverInfoPanel, DRIVER_ACTION_BUTTON_CLASS } from './DriverInfoPanel';
import { InterfaceSettingsPanel } from './InterfaceSettingsPanel';
import { DisplayFiltersPanel } from './DisplayFiltersPanel';
import type { AgentLogEntry } from '../../services/agentProtocol';
import type { FilterPresetLibrary } from '../../types/packet';

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
type SettingsSection = 'appearance' | 'interface' | 'filters' | 'driver';

const SECTIONS: { id: SettingsSection; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'appearance', label: 'Appearance', icon: TbPalette },
  // Second, next to Appearance: the two are the "how it looks" pair, and
  // Appearance owns colour while this owns everything else about the UI.
  { id: 'interface', label: 'Interface', icon: TbLayoutBoard },
  { id: 'filters', label: 'Display Filters', icon: TbFilter },
  { id: 'driver', label: 'Driver Info', icon: TbActivity },
];

interface SettingsModalProps {
  onClose: () => void;
  totalPacketsCount: number;
  totalBytes: number;
  packetBufferCap: number;
  bufferAutoPaused: boolean;
  onClearPackets: () => void;
  /** The display-filter presets, shared with the header's Presets dropdown. */
  filterPresetLibrary: FilterPresetLibrary;
  onFilterPresetLibraryChange: (library: FilterPresetLibrary) => void;
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  agentVersion: string | null;
  agentOutdated: boolean;
  agentCaptureState: 'idle' | 'sniffing';
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
  packetBufferCap,
  bufferAutoPaused,
  onClearPackets,
  filterPresetLibrary,
  onFilterPresetLibraryChange,
  agentStatus,
  agentVersion,
  agentOutdated,
  agentCaptureState,
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
  const { theme, setTheme } = useTheme();
  const [followsSystem, setFollowsSystem] = usePreferenceValue(followSystemThemeStore);
  const [section, setSection] = useState<SettingsSection>('appearance');
  const bufferPercent = packetBufferCap > 0
    ? Math.min(100, (totalPacketsCount / packetBufferCap) * 100)
    : 0;

  return (
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4"
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
            {section === 'appearance' && (
              <>
                <div className="text-xs font-semibold text-foreground">App theme</div>
                <div className="text-[11px] text-muted-foreground mb-2">
                  The window, panels and charts. System follows your OS setting,
                  choosing Day or Midnight.
                </div>
                {/* Five across: the four themes plus System, which is a mode
                    over them rather than a fifth palette - see
                    useSystemThemePreference. Picking a theme by name turns
                    following off, because choosing one IS saying "not whatever
                    the OS says". */}
                <div className="grid grid-cols-5 gap-2">
                  {[...THEME_OPTIONS, SYSTEM_THEME_OPTION].map(({ value, label, icon: Icon }) => {
                    const isSystem = value === SYSTEM_THEME_OPTION.value;
                    const isActive = isSystem ? followsSystem : !followsSystem && theme === value;
                    return (
                      <button
                        key={value}
                        onClick={() => {
                          setFollowsSystem(isSystem);
                          if (!isSystem) setTheme(value);
                        }}
                        className={`relative flex flex-col items-center gap-1.5 py-3 px-1 rounded-lg border text-[11px] font-medium transition-colors ${
                          isActive
                            ? 'border-primary bg-primary/10 text-primary'
                            : 'border-border bg-muted/40 text-muted-foreground hover:bg-accent hover:text-foreground'
                        }`}
                      >
                        {isActive && <TbCheck className="w-3.5 h-3.5 absolute top-1.5 right-1.5" />}
                        <Icon className="w-5 h-5" />
                        <span className="text-center leading-tight">{label}</span>
                      </button>
                    );
                  })}
                </div>

              </>
            )}

            {section === 'interface' && <InterfaceSettingsPanel />}

            {section === 'filters' && (
              <DisplayFiltersPanel
                library={filterPresetLibrary}
                onChange={onFilterPresetLibraryChange}
              />
            )}

            {/* Mounted only while selected, so the log subscription starts
                and stops with the section rather than with the modal. */}
            {section === 'driver' && (
              <DriverInfoPanel
                agentStatus={agentStatus}
                agentVersion={agentVersion}
                agentOutdated={agentOutdated}
                agentCaptureState={agentCaptureState}
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
                          {totalPacketsCount.toLocaleString()} / {packetBufferCap.toLocaleString()} packets
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

                    {/* The same pill as the three driver actions above it -
                        it sits in the same tab and does the same kind of thing,
                        and two shapes for one job read as two kinds of job. */}
                    <button
                      onClick={onClearPackets}
                      disabled={totalPacketsCount === 0}
                      className={`self-start ${DRIVER_ACTION_BUTTON_CLASS}`}
                    >
                      <TbTrash className="w-3.5 h-3.5" />
                      <span>Clear Buffer</span>
                    </button>
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
