import React from 'react';
import { Play, Square, Trash2 } from 'lucide-react';
import { UserRolePermissions } from '../../types/packet';

interface FloatingToolbarProps {
  isCapturing: boolean;
  onStartCapture: () => void;
  onPauseCapture: () => void;
  onStopCapture: () => void;
  onClearPackets: () => void;
  permissions: UserRolePermissions;
  totalPacketsCount: number;
  isDark: boolean;
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
}

export const FloatingToolbar: React.FC<FloatingToolbarProps> = ({
  isCapturing, onStartCapture, onStopCapture, onClearPackets,
  permissions, totalPacketsCount, isDark, agentStatus
}) => {
  return (
    <div className={`absolute bottom-4 left-1/2 -translate-x-1/2 z-40 flex items-center gap-2 px-4 py-2 rounded-full shadow-2xl backdrop-blur-xl border ${isDark ? 'bg-zinc-900/80 border-zinc-700' : 'bg-white/80 border-slate-300'}`}>
      <div className="flex items-center gap-1">
        {!isCapturing ? (
          <button
            onClick={onStartCapture}
            disabled={!permissions.canCapture || (agentStatus !== 'connected' && agentStatus !== 'disconnected')}
            className={`w-9 h-9 rounded-full flex items-center justify-center transition-all ${
              !permissions.canCapture ? 'opacity-50 cursor-not-allowed bg-slate-500 text-slate-300' 
              : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-[0_0_15px_rgba(16,185,129,0.5)]'
            }`}
            title="Start Capture"
          >
            <Play className="w-4 h-4 fill-current ml-0.5" />
          </button>
        ) : (
          <button
            onClick={onStopCapture}
            className="w-9 h-9 rounded-full bg-rose-500 hover:bg-rose-400 text-slate-950 flex items-center justify-center transition-all shadow-[0_0_15px_rgba(244,63,94,0.5)]"
            title="Stop Capture"
          >
            <Square className="w-4 h-4 fill-current" />
          </button>
        )}

        <div className={`w-px h-6 mx-2 ${isDark ? 'bg-zinc-700' : 'bg-slate-300'}`}></div>

        <button
          onClick={onClearPackets}
          disabled={!permissions.canClearBuffer || totalPacketsCount === 0}
          className={`w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors ${
            !permissions.canClearBuffer || totalPacketsCount === 0 ? 'opacity-40 cursor-not-allowed' : ''
          }`}
          title="Clear Buffer"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
