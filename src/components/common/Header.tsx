import React from 'react';
import {
  Play,
  Pause,
  Square,
} from 'lucide-react';
import { UserRole, UserRolePermissions } from '../../types/packet';
import { AppMenu } from './AppMenu';

interface HeaderProps {
  isCapturing: boolean;
  onStartCapture: () => void;
  onPauseCapture: () => void;
  onStopCapture: () => void;
  onClearPackets: () => void;
  permissions: UserRolePermissions;
  onOpenDissectorModal: () => void;
  onOpenStatsModal: () => void;
  onOpenExportModal: () => void;
  onOpenIspModal?: () => void;
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  onOpenColorRulesModal: () => void;
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
  onPauseCapture,
  onStopCapture,
  onClearPackets,
  permissions,
  onOpenDissectorModal,
  onOpenStatsModal,
  onOpenExportModal,
  onOpenIspModal,
  agentStatus,
  onOpenColorRulesModal,
  onOpenSettingsModal,
  totalPacketsCount,
  filteredPacketsCount,
  totalBytes,
  onApplyFilterPreset,
}) => {
  const bufferPercent = Math.min(100, (totalPacketsCount / PACKET_BUFFER_CAP) * 100);
  return (
    <header className="h-16 px-4 sm:px-6 border-b flex items-center justify-between gap-4 transition-colors z-40 shrink-0 select-none bg-card border-border text-card-foreground">
      {/* Left: Branding & Capture Stream Controls */}
      <div className="flex items-center space-x-3 sm:space-x-4">
        {/* Title */}
        <div className="hidden xl:flex flex-col">
          <div className="flex items-center gap-1.5">
            <span className="font-mono font-black text-sm tracking-tight text-cyan-400">NET VIEW</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 font-mono font-bold uppercase">
              PRO
            </span>
          </div>
          <span className="text-[10px] text-muted-foreground font-mono">Packet Analyzer</span>
        </div>

        {/* Capture Buttons */}
        <div className="flex items-center space-x-2">
          {isCapturing ? (
            <button
              onClick={onPauseCapture}
              className="bg-rose-500 hover:bg-rose-600 active:scale-95 text-white text-xs px-3.5 sm:px-4 py-2 rounded font-bold uppercase tracking-wider flex items-center gap-1.5 shadow-md shadow-rose-500/20 transition-all cursor-pointer"
              title="Stop / Pause Capture Stream"
            >
              <Pause className="w-3.5 h-3.5 fill-current" />
              <span>Stop Capture</span>
            </button>
          ) : (
            <button
              onClick={onStartCapture}
              disabled={!permissions.canCapture}
              className={`bg-cyan-500 hover:bg-cyan-400 active:scale-95 text-slate-950 text-xs px-3.5 sm:px-4 py-2 rounded font-bold uppercase tracking-wider flex items-center gap-1.5 shadow-md shadow-cyan-500/20 transition-all cursor-pointer ${
                !permissions.canCapture ? 'opacity-50 cursor-not-allowed' : ''
              }`}
              title="Start Live Packet Capture"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Start Capture</span>
            </button>
          )}

          {isCapturing && (
            <button
              onClick={onStopCapture}
              className="bg-secondary hover:bg-accent text-rose-500 dark:text-rose-400 hover:text-rose-600 dark:hover:text-rose-300 text-xs px-3 py-2 rounded font-bold border border-border flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Halt Capture"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
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
        </div>
      </div>

      {/* Right: Buffer Status, Agent Status, App Menu */}
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
            agentStatus === 'connected'
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
              agentStatus === 'connected'
                ? 'bg-emerald-500 dark:bg-emerald-400'
                : agentStatus === 'connecting'
                ? 'bg-amber-500 dark:bg-amber-400 animate-pulse'
                : agentStatus === 'error'
                ? 'bg-rose-500 dark:bg-rose-400'
                : 'bg-muted-foreground'
            }`}
          />
          <span>
            {agentStatus === 'connected'
              ? 'Agent Connected'
              : agentStatus === 'connecting'
              ? 'Connecting...'
              : agentStatus === 'error'
              ? 'Connection Error'
              : 'Agent Disconnected'}
          </span>
        </div>

        {/* App Menu - Actions, Views, Filter Presets (Ctrl/Cmd+K). Now the
            last thing in the header, flush against its right edge - the
            Download Driver button that used to sit here moved into the
            menu itself as an Actions item. */}
        <AppMenu
          isCapturing={isCapturing}
          onStartCapture={onStartCapture}
          onPauseCapture={onPauseCapture}
          onClearPackets={onClearPackets}
          onOpenDissectorModal={onOpenDissectorModal}
          onOpenStatsModal={onOpenStatsModal}
          onOpenExportModal={onOpenExportModal}
          onOpenColorRulesModal={onOpenColorRulesModal}
          onOpenIspModal={onOpenIspModal}
          onOpenSettingsModal={onOpenSettingsModal}
          onApplyFilterPreset={onApplyFilterPreset}
          permissions={permissions}
          totalPacketsCount={totalPacketsCount}
        />
      </div>
    </header>
  );
};
