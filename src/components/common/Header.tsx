import React from 'react';
import {
  TbPlayerPlay,
  TbPlayerPause,
  TbSquare,
} from 'react-icons/tb';
import { UserRole, UserRolePermissions } from '../../types/packet';
import { AppMenu } from './AppMenu';
import { CaptureInterfacePicker } from './CaptureInterfacePicker';
import type { AgentCommand } from '../../services/agentProtocol';

interface HeaderProps {
  isCapturing: boolean;
  /** Starts without naming an adapter. Only used when no agent is connected
   *  and there is therefore nothing to choose between. */
  onStartCapture: () => void;
  /** The normal path: start capturing on exactly this adapter. */
  onStartCaptureOn: (interfaceName: string) => void;
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
  totalBytes: number;
  onApplyFilterPreset: (filter: string) => void;
}

// Matches the capture buffer cap enforced in App.tsx's WebSocket handler
// (oldest packets are dropped once the live buffer exceeds this size).
const PACKET_BUFFER_CAP = 4000;

export const Header: React.FC<HeaderProps> = ({
  isCapturing,
  onStartCapture,
  onStartCaptureOn,
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
  totalBytes,
  onApplyFilterPreset,
}) => {
  const bufferPercent = Math.min(100, (totalPacketsCount / PACKET_BUFFER_CAP) * 100);

  // The Start button renders two ways - wrapped in an interface picker, or
  // as a plain button when there is nothing to pick from - and both must look
  // identical, so the styling lives here rather than being duplicated twice
  // and drifting.
  const startCapture = {
    needsPicker: agentInterfaces.length > 0,
    className: `bg-cyan-500 hover:bg-cyan-400 active:scale-95 text-slate-950 text-xs px-3.5 sm:px-4 py-2 rounded font-bold uppercase tracking-wider flex items-center gap-1.5 shadow-md shadow-cyan-500/20 transition-all cursor-pointer ${
      !permissions.canCapture ? 'opacity-50 cursor-not-allowed' : ''
    }`,
  };

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
          onStartCaptureOn={onStartCaptureOn}
          onPauseCapture={onPauseCapture}
          onSendAgentCommand={onSendAgentCommand}
          onClearPackets={onClearPackets}
          agentInterfaces={agentInterfaces}
          selectedInterfaces={selectedInterfaces}
          onSelectInterface={onSelectInterface}
          onOpenDissectorModal={onOpenDissectorModal}
          onOpenStatsModal={onOpenStatsModal}
          onOpenExportModal={onOpenExportModal}
          onOpenIspModal={onOpenIspModal}
          onOpenSettingsModal={onOpenSettingsModal}
          onApplyFilterPreset={onApplyFilterPreset}
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
            // The picker only wraps the button when there is something to
            // pick from. With no agent connected the interface list is empty,
            // and a dropdown with no entries would leave Start unable to
            // start anything at all.
            startCapture.needsPicker ? (
              <CaptureInterfacePicker
                interfaces={agentInterfaces}
                selectedInterface={selectedInterfaces[0] ?? null}
                onSelect={onStartCaptureOn}
                align="start"
              >
                <button
                  disabled={!permissions.canCapture}
                  className={startCapture.className}
                  title="Choose an interface and start capturing"
                >
                  <TbPlayerPlay className="w-3.5 h-3.5 fill-current" />
                  <span>Start Capture</span>
                </button>
              </CaptureInterfacePicker>
            ) : (
              <button
                onClick={onStartCapture}
                disabled={!permissions.canCapture}
                className={startCapture.className}
                title="Start Live Packet Capture"
              >
                <TbPlayerPlay className="w-3.5 h-3.5 fill-current" />
                <span>Start Capture</span>
              </button>
            )
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
        {/* Capture Buffer Status - relocated from the old bottom status bar.
            Packet/filtered counts were dropped here since FilterBar already
            shows filtered/total right below the header; "DROPPED: 0" was a
            hardcoded placeholder with no real data behind it. */}
        <div
          className="hidden md:flex items-center gap-1.5 text-[11px] px-2.5 py-1.5 rounded-full border font-mono shrink-0 bg-secondary border-border text-muted-foreground"
          title={`Capture buffer: ${totalPacketsCount.toLocaleString()} / ${PACKET_BUFFER_CAP.toLocaleString()} packets`}
        >
          <span className="text-foreground font-semibold">Buffer {bufferPercent.toFixed(0)}%</span>
          <span className="text-border">·</span>
          <span>{(totalBytes / 1024).toFixed(1)} KB</span>
        </div>

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
