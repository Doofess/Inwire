import React from 'react';
import { TbPlayerPlay, TbSquare, TbTrash } from 'react-icons/tb';
import { UserRolePermissions } from '../../types/packet';
import type { AgentCommand } from '../../services/agentProtocol';
import { CaptureInterfacePicker } from './CaptureInterfacePicker';

interface FloatingToolbarProps {
  isCapturing: boolean;
  /** Starts without naming an adapter - only for the no-agent case. */
  onStartCapture: () => void;
  /** The normal path: start capturing on exactly this adapter. */
  onStartCaptureOn: (interfaceName: string) => void;
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  onPauseCapture: () => void;
  onStopCapture: () => void;
  onSendAgentCommand: (command: AgentCommand) => void;
  onClearPackets: () => void;
  permissions: UserRolePermissions;
  totalPacketsCount: number;
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
}

/** Wraps the Start control in an interface picker, or leaves it alone when
 *  there is no agent and therefore no adapter to choose. Written as a helper
 *  so the button's own markup is declared exactly once. */
function startButton(
  needsPicker: boolean,
  button: React.ReactElement,
  interfaces: { name: string; label: string }[],
  selectedInterface: string | null,
  onSelect: (interfaceName: string) => void,
) {
  if (!needsPicker) return button;
  return (
    <CaptureInterfacePicker
      interfaces={interfaces}
      selectedInterface={selectedInterface}
      onSelect={onSelect}
      side="top"
    >
      {button}
    </CaptureInterfacePicker>
  );
}

export const FloatingToolbar: React.FC<FloatingToolbarProps> = ({
  isCapturing, onStartCapture, onStartCaptureOn, agentInterfaces, selectedInterfaces,
  onStopCapture, onSendAgentCommand, onClearPackets,
  permissions, totalPacketsCount, agentStatus
}) => {
  return (
    <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-40 flex items-center gap-2 px-4 py-2 rounded-full shadow-2xl backdrop-blur-xl border bg-card/80 border-border">
      <div className="flex items-center gap-1">
        {!isCapturing ? (
          startButton(
            agentInterfaces.length > 0,
            <button
              onClick={agentInterfaces.length > 0 ? undefined : onStartCapture}
              disabled={!permissions.canCapture || (agentStatus !== 'connected' && agentStatus !== 'disconnected')}
              className={`w-9 h-9 rounded-full flex items-center justify-center transition-all ${
                !permissions.canCapture ? 'opacity-50 cursor-not-allowed bg-muted text-muted-foreground'
                : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-[0_0_15px_rgba(16,185,129,0.5)]'
              }`}
              title={agentInterfaces.length > 0 ? 'Choose an interface and start capturing' : 'Start Capture'}
            >
              <TbPlayerPlay className="w-4 h-4 fill-current ml-0.5" />
            </button>,
            agentInterfaces,
            selectedInterfaces[0] ?? null,
            onStartCaptureOn,
          )
        ) : (
          <button
            onClick={() => {
              onStopCapture();
              onSendAgentCommand({ type: 'stop_capture' });
            }}
            className="w-9 h-9 rounded-full bg-rose-500 hover:bg-rose-400 text-slate-950 flex items-center justify-center transition-all shadow-[0_0_15px_rgba(244,63,94,0.5)]"
            title="Stop Capture"
          >
            <TbSquare className="w-4 h-4 fill-current" />
          </button>
        )}

        <div className="w-px h-6 mx-2 bg-border"></div>

        <button
          onClick={onClearPackets}
          disabled={!permissions.canClearBuffer || totalPacketsCount === 0}
          className={`w-8 h-8 rounded-full flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-accent transition-colors ${
            !permissions.canClearBuffer || totalPacketsCount === 0 ? 'opacity-40 cursor-not-allowed' : ''
          }`}
          title="Clear Buffer"
        >
          <TbTrash className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
