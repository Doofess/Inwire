import React from 'react';
import { useTheme } from 'next-themes';
import {
  Play,
  Pause,
  Square,
  Trash2,
  Download,
  Sun,
  Moon,
  Monitor,
  Check,
} from 'lucide-react';
import { UserRole, UserRolePermissions } from '../../types/packet';
import { getAgentDownloadForCurrentOS } from '../../services/platformDetect';
import { Button } from '../ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';

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

const THEME_OPTIONS = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'system', label: 'System', icon: Monitor },
] as const;

function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const ActiveIcon = THEME_OPTIONS.find((o) => o.value === theme)?.icon ?? Monitor;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          title="Change theme"
          className="bg-secondary hover:bg-accent border-border text-foreground"
        >
          <ActiveIcon className="w-4 h-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {THEME_OPTIONS.map(({ value, label, icon: Icon }) => (
          <DropdownMenuItem key={value} onClick={() => setTheme(value)}>
            <Icon className="w-4 h-4" />
            <span>{label}</span>
            {theme === value && <Check className="w-3.5 h-3.5 ml-auto" />}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
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
  totalPacketsCount,
  filteredPacketsCount,
}) => {
  const agentDownload = getAgentDownloadForCurrentOS();
  return (
    <header className="h-16 px-4 sm:px-6 border-b flex items-center justify-between transition-colors z-40 shrink-0 select-none bg-card border-border text-card-foreground">
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
            className={`p-2 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors ${
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

        {/* Download Driver Button - detects OS, downloads the matching one-click installer directly (no modal) */}
        <Button
          variant="outline"
          onClick={downloadAgentInstaller}
          className="bg-secondary hover:bg-accent border-border text-foreground text-xs"
          title={`Download the one-click NetView agent installer for ${agentDownload.label}`}
        >
          <Download className="w-3.5 h-3.5 text-emerald-500 dark:text-emerald-400" />
          <span className="hidden sm:inline">Download Driver ({agentDownload.label})</span>
        </Button>

        {/* Export PCAP Button */}
        <Button
          variant="outline"
          onClick={onOpenExportModal}
          className="bg-secondary hover:bg-accent border-border text-foreground text-xs"
          title="Import or Export PCAP / JSON"
        >
          <Download className="w-3.5 h-3.5 text-cyan-500 dark:text-cyan-400" />
          <span className="hidden sm:inline">Export PCAP</span>
        </Button>

        {/* Theme Toggle - System / Light / Dark */}
        <ThemeToggle />
      </div>
    </header>
  );
};
