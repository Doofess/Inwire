import React, { useState } from 'react';
import { motion } from 'motion/react';
import { useTheme } from 'next-themes';
import { TbSettings, TbX, TbCheck, TbPalette, TbActivity } from 'react-icons/tb';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';
import { THEME_OPTIONS } from '../../lib/themeOptions';
import { DriverInfoPanel } from './DriverInfoPanel';
import type { AgentLogEntry } from '../../services/agentProtocol';

type SettingsSection = 'appearance' | 'driver';

const SECTIONS: { id: SettingsSection; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'appearance', label: 'Appearance', icon: TbPalette },
  { id: 'driver', label: 'Driver Info', icon: TbActivity },
];

interface SettingsModalProps {
  onClose: () => void;
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  agentVersion: string | null;
  agentOutdated: boolean;
  agentCaptureState: 'idle' | 'sniffing';
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  agentLog: AgentLogEntry[];
  onSubscribeAgentLog: () => void;
  onUnsubscribeAgentLog: () => void;
  onClearAgentLog: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  onClose,
  agentStatus,
  agentVersion,
  agentOutdated,
  agentCaptureState,
  agentInterfaces,
  selectedInterfaces,
  agentLog,
  onSubscribeAgentLog,
  onUnsubscribeAgentLog,
  onClearAgentLog,
}) => {
  const { theme, setTheme } = useTheme();
  const [section, setSection] = useState<SettingsSection>('appearance');

  return (
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4"
    >
      <motion.div
        {...modalPanelMotion}
        className="w-full max-w-3xl rounded-xl border flex flex-col shadow-2xl transition-colors bg-card border-border text-card-foreground"
      >
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/20">
              <TbSettings className="w-5 h-5 text-foreground" />
            </div>
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
        <div className="flex min-h-0">
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

          <div className="flex-1 min-w-0 p-5">
            {section === 'appearance' && (
              <>
                <div className="text-xs font-semibold text-foreground mb-2">Appearance</div>
                <div className="grid grid-cols-3 gap-2">
                  {THEME_OPTIONS.map(({ value, label, icon: Icon }) => {
                    const isActive = theme === value;
                    return (
                      <button
                        key={value}
                        onClick={() => setTheme(value)}
                        className={`relative flex flex-col items-center gap-1.5 py-3 rounded-lg border text-xs font-medium transition-colors ${
                          isActive
                            ? 'border-cyan-500 bg-cyan-500/10 text-cyan-600 dark:text-cyan-300'
                            : 'border-border bg-muted/40 text-muted-foreground hover:bg-accent hover:text-foreground'
                        }`}
                      >
                        {isActive && <TbCheck className="w-3.5 h-3.5 absolute top-1.5 right-1.5" />}
                        <Icon className="w-5 h-5" />
                        <span>{label}</span>
                      </button>
                    );
                  })}
                </div>
              </>
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
                onSubscribe={onSubscribeAgentLog}
                onUnsubscribe={onUnsubscribeAgentLog}
                onClearLog={onClearAgentLog}
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
