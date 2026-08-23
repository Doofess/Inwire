import React from 'react';
import {
  Play,
  Pause,
  Square,
  Trash2,
  Download,
  Sun,
  Moon,
} from 'lucide-react';
import { UserRole, UserRolePermissions } from '../../types/packet';
import { getAgentDownloadForCurrentOS } from '../../services/platformDetect';

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
  isDark: boolean;
  onToggleTheme: () => void;
  totalPacketsCount: number;
  filteredPacketsCount: number;
}

function downloadAgentInstaller() {
  const { url, filename } = getAgentDownloadForCurrentOS();
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

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
  agentStatus,
  onOpenColorRulesModal,
  isDark,
  onToggleTheme,
  totalPacketsCount,
  filteredPacketsCount,
}) => {
  const agentDownload = getAgentDownloadForCurrentOS();
  return (
    <header
      className={`h-16 px-4 sm:px-6 border-b flex items-center justify-between transition-colors z-40 shrink-0 select-none ${
        isDark ? 'bg-slate-900 border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'
      }`}
    >
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
          <span className="text-[10px] text-slate-500 font-mono">Packet Analyzer</span>
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
              className="bg-slate-800 hover:bg-slate-700 text-rose-400 hover:text-rose-300 text-xs px-3 py-2 rounded font-bold border border-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Halt Capture"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              <span className="hidden sm:inline">Halt</span>
            </button>
          )}

          <button
            onClick={onClearPackets}
            disabled={!permissions.canClearBuffer || totalPacketsCount === 0}
            className={`p-2 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors ${
              !permissions.canClearBuffer || totalPacketsCount === 0 ? 'opacity-40 cursor-not-allowed' : ''
            }`}
            title="Clear Packet Buffer"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Right: Actions, Speed, Auth & Role Selector */}
      <div className="flex items-center space-x-2 sm:space-x-2.5">
        

        
        {/* Agent Connectivity Indicator - separate from the download button so
            the button stays a stable, always-clickable action and only this
            small pill reflects the (sometimes flickery) live connection state. */}
        <div
          className={`hidden sm:flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-full border font-mono ${
            agentStatus === 'connected'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : agentStatus === 'connecting'
              ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
              : agentStatus === 'error'
              ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
              : 'bg-slate-800/80 border-slate-700 text-slate-400'
          }`}
          title="NetView Agent connection status (ws://localhost:8999)"
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              agentStatus === 'connected'
                ? 'bg-emerald-400'
                : agentStatus === 'connecting'
                ? 'bg-amber-400 animate-pulse'
                : agentStatus === 'error'
                ? 'bg-rose-400'
                : 'bg-slate-500'
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

        {/* Download Driver Button - detects OS, downloads the matching one-click installer directly (no modal) */}
        <button
          onClick={downloadAgentInstaller}
          className="bg-slate-800 hover:bg-slate-700 text-slate-100 text-xs px-3 sm:px-4 py-2 rounded font-bold border border-slate-700 flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
          title={`Download the one-click NetView agent installer for ${agentDownload.label}`}
        >
          <Download className="w-3.5 h-3.5 text-emerald-400" />
          <span className="hidden sm:inline">Download Driver ({agentDownload.label})</span>
        </button>

        {/* Export PCAP Button */}
        <button
          onClick={onOpenExportModal}
          className="bg-slate-800 hover:bg-slate-700 text-slate-100 text-xs px-3 sm:px-4 py-2 rounded font-bold border border-slate-700 flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
          title="Import or Export PCAP / JSON"
        >
          <Download className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden sm:inline">Export PCAP</span>
        </button>

        {/* Theme Toggle */}
        <button
          onClick={onToggleTheme}
          className="p-2 rounded bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-slate-300 transition-colors cursor-pointer"
          title={isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
        >
          {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-400" />}
        </button>
      </div>
    </header>
  );
};
