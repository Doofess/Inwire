import React from 'react';
import {
  TbPlayerPlay,
  TbPlayerPause,
  TbSquare,
  TbNetwork,
} from 'react-icons/tb';
import { UserRole, UserRolePermissions } from '../../types/packet';
import { AppMenu } from './AppMenu';
import { CaptureInterfacePicker } from './CaptureInterfacePicker';
import { shortInterfaceLabel } from '../../services/captureInterfaces';
import type { AgentCommand } from '../../services/agentProtocol';

interface HeaderProps {
  isCapturing: boolean;
  /** Starts capturing on whatever adapter is currently selected. The Start
   *  button is disabled until one is, so this never begins a capture with
   *  no adapter named. */
  onStartCapture: () => void;
  onPauseCapture: () => void;
  onStopCapture: () => void;
  onSendAgentCommand: (command: AgentCommand) => void;
  onClearPackets: () => void;
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  onSelectInterface: (interfaceName: string) => void;
  permissions: UserRolePermissions;
  onOpenDissectorModal: () => void;
  onOpenStatsModal: () => void;
  onOpenExportModal: () => void;
  onOpenIspModal?: () => void;
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  agentCaptureState: 'idle' | 'sniffing';
  agentOutdated: boolean;
  onOpenSettingsModal: () => void;
  totalPacketsCount: number;
  filteredPacketsCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  isCapturing,
  onStartCapture,
  onPauseCapture,
  onStopCapture,
  onSendAgentCommand,
  onClearPackets,
  agentInterfaces,
  selectedInterfaces,
  onSelectInterface,
  permissions,
  onOpenDissectorModal,
  onOpenStatsModal,
  onOpenExportModal,
  onOpenIspModal,
  agentStatus,
  agentCaptureState,
  agentOutdated,
  onOpenSettingsModal,
  totalPacketsCount,
  filteredPacketsCount,
}) => {
  const selectedInterface = agentInterfaces.find((i) => i.name === selectedInterfaces[0]) ?? null;

  // The Interfaces button carries the whole adapter story in one control:
  // red when the agent reports nothing to capture from (driver missing,
  // service down, Npcap broken), amber when adapters exist but none is
  // chosen yet, green once one is. Colour and label are derived together
  // here so a state can never show one without the other.
  // Red means a settled answer, not "haven't heard yet". While the socket is
  // still opening the interface list is legitimately empty, and flashing
  // "No interfaces detected" during every page load would cry wolf on the
  // one state that should mean something is actually wrong.
  const adapterStateKnown = agentStatus !== 'connecting';
  const interfaceButton = agentInterfaces.length === 0
    ? adapterStateKnown
      ? {
          label: 'No interfaces detected',
          title: 'The agent reported no capture interfaces. Check that it is installed and running.',
          className: 'bg-rose-500 hover:bg-rose-600 text-white shadow-rose-500/20',
        }
      : {
          label: 'Interfaces',
          title: 'Waiting for the agent to report its capture interfaces...',
          className: 'bg-amber-500 hover:bg-amber-400 text-slate-950 shadow-amber-500/20',
        }
    : selectedInterface === null
      ? {
          label: 'Interfaces',
          title: 'Choose which adapter to capture from',
          className: 'bg-amber-500 hover:bg-amber-400 text-slate-950 shadow-amber-500/20',
        }
      : {
          label: shortInterfaceLabel(selectedInterface.label),
          title: selectedInterface.label,
          className: 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-emerald-500/20',
        };

  const interfaceButtonClass = `${interfaceButton.className} active:scale-95 text-xs px-3.5 sm:px-4 py-2 rounded font-bold uppercase tracking-wider flex items-center gap-1.5 shadow-md transition-all max-w-[14rem] cursor-pointer`;

  return (
    <header className="h-16 px-4 sm:px-6 border-b flex items-center justify-between gap-4 transition-colors z-40 shrink-0 select-none bg-card border-border text-card-foreground">
      {/* Left: App Menu, Branding & Capture Stream Controls */}
      <div className="flex items-center space-x-3 sm:space-x-4">
        {/* App Menu - Actions, Views, Filter Presets (Ctrl/Cmd+K). Leads the
            header the way GitHub's own hamburger leads its header, ahead of
            the logo rather than trailing every other control. */}
        <AppMenu
          isCapturing={isCapturing}
          onStartCapture={onStartCapture}
          onPauseCapture={onPauseCapture}
          onSendAgentCommand={onSendAgentCommand}
          onClearPackets={onClearPackets}
          selectedInterfaces={selectedInterfaces}
          onOpenDissectorModal={onOpenDissectorModal}
          onOpenStatsModal={onOpenStatsModal}
          onOpenExportModal={onOpenExportModal}
          onOpenIspModal={onOpenIspModal}
          onOpenSettingsModal={onOpenSettingsModal}
          permissions={permissions}
          totalPacketsCount={totalPacketsCount}
          agentOutdated={agentOutdated}
        />

        {/* Title */}
        <div className="hidden xl:flex flex-col">
          <div className="flex items-center gap-1.5">
            <span className="font-mono font-black text-sm tracking-tight text-cyan-400">NET VIEW</span>
          </div>
          <span className="text-[10px] text-muted-foreground font-mono">Packet Analyzer</span>
        </div>

        {/* Capture Buttons */}
        <div className="flex items-center space-x-2">
          {/* Sits ahead of Start Capture because it gates it: with no adapter
              chosen there is nothing to start. */}
          {agentInterfaces.length === 0 ? (
            <button disabled className={`${interfaceButtonClass} cursor-not-allowed`} title={interfaceButton.title}>
              <TbNetwork className="w-3.5 h-3.5 shrink-0" />
              <span className="truncate">{interfaceButton.label}</span>
            </button>
          ) : (
            <CaptureInterfacePicker
              interfaces={agentInterfaces}
              selectedInterface={selectedInterfaces[0] ?? null}
              onSelect={onSelectInterface}
              align="start"
            >
              <button className={interfaceButtonClass} title={interfaceButton.title}>
                <TbNetwork className="w-3.5 h-3.5 shrink-0" />
                <span className="truncate">{interfaceButton.label}</span>
              </button>
            </CaptureInterfacePicker>
          )}

          {isCapturing ? (
            <button
              onClick={() => {
                onPauseCapture();
                onSendAgentCommand({ type: 'stop_capture' });
              }}
              className="bg-rose-500 hover:bg-rose-600 active:scale-95 text-white text-xs px-3.5 sm:px-4 py-2 rounded font-bold uppercase tracking-wider flex items-center gap-1.5 shadow-md shadow-rose-500/20 transition-all cursor-pointer"
              title="Stop / Pause Capture Stream"
            >
              <TbPlayerPause className="w-3.5 h-3.5 fill-current" />
              <span>Stop Capture</span>
            </button>
          ) : (
            <button
              onClick={onStartCapture}
              disabled={!permissions.canCapture || !selectedInterface}
              className={`bg-cyan-500 hover:bg-cyan-400 active:scale-95 text-slate-950 text-xs px-3.5 sm:px-4 py-2 rounded font-bold uppercase tracking-wider flex items-center gap-1.5 shadow-md shadow-cyan-500/20 transition-all cursor-pointer ${
                !permissions.canCapture || !selectedInterface ? 'opacity-50 cursor-not-allowed' : ''
              }`}
              title={selectedInterface ? 'Start Live Packet Capture' : 'Choose an interface first'}
            >
              <TbPlayerPlay className="w-3.5 h-3.5 fill-current" />
              <span>Start Capture</span>
            </button>
          )}

          {isCapturing && (
            <button
              onClick={() => {
                onStopCapture();
                onSendAgentCommand({ type: 'stop_capture' });
              }}
              className="bg-secondary hover:bg-accent text-rose-500 dark:text-rose-400 hover:text-rose-600 dark:hover:text-rose-300 text-xs px-3 py-2 rounded font-bold border border-border flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Halt Capture"
            >
              <TbSquare className="w-3.5 h-3.5 fill-current" />
              <span className="hidden sm:inline">Halt</span>
            </button>
          )}

          <button
            onClick={onClearPackets}
            disabled={!permissions.canClearBuffer || totalPacketsCount === 0}
            className={`bg-cyan-500 hover:bg-cyan-400 active:scale-95 text-slate-950 text-xs px-3.5 sm:px-4 py-2 rounded font-bold uppercase tracking-wider shadow-md shadow-cyan-500/20 transition-all cursor-pointer ${
              !permissions.canClearBuffer || totalPacketsCount === 0 ? 'opacity-50 cursor-not-allowed' : ''
            }`}
            title="Clear Packet Buffer"
          >
            <span>Clear Cache</span>
          </button>

          {/* The agent's own `state` message is the only source of truth for
              whether it's actually sniffing - isCapturing is just local
              intent, which can go stale (a pre-auth click, a command sent
              while the socket was closed, another tab stopping capture).
              Matches the amber styling of the Agent Outdated pill rather
              than inventing a new visual language for "something's off". */}
          {isCapturing && agentCaptureState === 'idle' && (
            <span
              className="hidden sm:inline-flex items-center gap-1.5 text-[11px] px-2.5 py-1.5 rounded-full border font-mono bg-amber-500/10 border-amber-500/30 text-amber-600 dark:text-amber-400"
              title="Capture was requested but the agent reports it is idle - it may not be paired yet, or the command didn't reach it."
            >
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 dark:bg-amber-400" />
              <span>Agent Idle</span>
            </span>
          )}
        </div>
      </div>

      {/* Right: Buffer Status, Agent Status */}
      <div className="flex items-center space-x-2 sm:space-x-2.5">
        {/* Agent Connectivity Indicator - separate from the download button so
            the button stays a stable, always-clickable action and only this
            small pill reflects the (sometimes flickery) live connection state. */}
        <div
          className={`hidden sm:flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-full border font-mono ${
            agentStatus === 'connected' && agentOutdated
              ? 'bg-amber-500/10 border-amber-500/30 text-amber-600 dark:text-amber-400'
              : agentStatus === 'connected'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
              : agentStatus === 'connecting'
              ? 'bg-amber-500/10 border-amber-500/30 text-amber-600 dark:text-amber-400'
              : agentStatus === 'error'
              ? 'bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-400'
              : 'bg-secondary border-border text-muted-foreground'
          }`}
          title="NetView Agent connection status (ws://localhost:8999)"
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              agentStatus === 'connected' && agentOutdated
                ? 'bg-amber-500 dark:bg-amber-400'
                : agentStatus === 'connected'
                ? 'bg-emerald-500 dark:bg-emerald-400'
                : agentStatus === 'connecting'
                ? 'bg-amber-500 dark:bg-amber-400 animate-pulse'
                : agentStatus === 'error'
                ? 'bg-rose-500 dark:bg-rose-400'
                : 'bg-muted-foreground'
            }`}
          />
          <span>
            {agentStatus === 'connected' && agentOutdated
              ? 'Agent Outdated'
              : agentStatus === 'connected'
              ? 'Agent Connected'
              : agentStatus === 'connecting'
              ? 'Connecting...'
              : agentStatus === 'error'
              ? 'Connection Error'
              : 'Agent Disconnected'}
          </span>
        </div>
      </div>
    </header>
  );
};
