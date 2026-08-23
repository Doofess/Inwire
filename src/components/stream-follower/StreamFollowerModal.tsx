import React, { useState } from 'react';
import { Packet } from '../../types/packet';
import { MessageSquare, X, Copy, Check, Download, ArrowRightLeft, Shield } from 'lucide-react';

interface StreamFollowerModalProps {
  streamId: number | null;
  packets: Packet[];
  onClose: () => void;
  isDark: boolean;
}

export const StreamFollowerModal: React.FC<StreamFollowerModalProps> = ({
  streamId,
  packets,
  onClose,
  isDark,
}) => {
  const [viewFormat, setViewFormat] = useState<'ascii' | 'hex' | 'raw'>('ascii');
  const [copied, setCopied] = useState(false);

  if (streamId === null) return null;

  // Filter all packets belonging to this stream
  const streamPackets = packets.filter(p => p.streamId === streamId);

  // Client vs Server IPs
  const clientIp = streamPackets[0]?.source || 'Client';
  const serverIp = streamPackets[0]?.destination || 'Server';

  let totalClientBytes = 0;
  let totalServerBytes = 0;

  for (const p of streamPackets) {
    if (p.source === clientIp) totalClientBytes += p.length;
    else totalServerBytes += p.length;
  }

  const handleCopyStream = () => {
    const fullDialogue = streamPackets
      .map(p => {
        const prefix = p.source === clientIp ? `[CLIENT -> SERVER (${p.source})]` : `[SERVER -> CLIENT (${p.source})]`;
        return `${prefix}\n${p.streamPayload?.payloadText || p.asciiDump}\n`;
      })
      .join('\n');

    navigator.clipboard.writeText(fullDialogue);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleSaveStream = () => {
    const fullDialogue = streamPackets
      .map(p => {
        const prefix = p.source === clientIp ? `>>> [CLIENT -> SERVER] ${p.source}:${p.sourcePort}` : `<<< [SERVER -> CLIENT] ${p.source}:${p.sourcePort}`;
        return `${prefix}\n${p.streamPayload?.payloadText || p.asciiDump}\n`;
      })
      .join('\n');

    const blob = new Blob([fullDialogue], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tcp_stream_${streamId}_conversation.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div
        className={`w-full max-w-4xl max-h-[85vh] rounded-xl border flex flex-col shadow-2xl transition-colors ${
          isDark ? 'bg-zinc-950 border-zinc-700 text-zinc-100' : 'bg-white border-zinc-300 text-zinc-900'
        }`}
      >
        {/* Modal Header */}
        <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-sky-500/20 text-sky-400">
              <MessageSquare className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 font-bold text-sm">
                <span>Follow Stream #{streamId}</span>
                <span className={`text-xs px-2 py-0.5 rounded bg-zinc-800 ${isDark ? "text-zinc-300" : "text-slate-700"} font-mono`}>
                  {streamPackets.length} frames
                </span>
              </div>
              <p className={`text-xs ${isDark ? "text-zinc-400" : "text-slate-600"} font-mono`}>
                {clientIp} <span className={`${isDark ? "text-zinc-500" : "text-slate-600"}`}>⇄</span> {serverIp}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* View Format Switcher */}
            <div className={`flex rounded-md border ${isDark ? 'border-zinc-800 bg-zinc-900' : 'border-zinc-300 bg-zinc-100'} p-0.5 text-xs`}>
              <button
                onClick={() => setViewFormat('ascii')}
                className={`px-2 py-1 rounded font-medium transition-all ${
                  viewFormat === 'ascii'
                    ? 'bg-sky-600 text-white shadow-sm'
                    : isDark
                    ? 'text-zinc-400 hover:text-zinc-200'
                    : 'text-zinc-600 hover:text-zinc-900'
                }`}
              >
                ASCII / UTF-8
              </button>
              <button
                onClick={() => setViewFormat('hex')}
                className={`px-2 py-1 rounded font-medium transition-all ${
                  viewFormat === 'hex'
                    ? 'bg-sky-600 text-white shadow-sm'
                    : isDark
                    ? 'text-zinc-400 hover:text-zinc-200'
                    : 'text-zinc-600 hover:text-zinc-900'
                }`}
              >
                Hex Dump
              </button>
              <button
                onClick={() => setViewFormat('raw')}
                className={`px-2 py-1 rounded font-medium transition-all ${
                  viewFormat === 'raw'
                    ? 'bg-sky-600 text-white shadow-sm'
                    : isDark
                    ? 'text-zinc-400 hover:text-zinc-200'
                    : 'text-zinc-600 hover:text-zinc-900'
                }`}
              >
                Raw Byte
              </button>
            </div>

            <button
              onClick={handleCopyStream}
              className={`p-1.5 rounded-md border text-xs transition-colors flex items-center gap-1 ${
                isDark ? 'border-zinc-700 hover:bg-zinc-800 text-zinc-300' : 'border-zinc-300 hover:bg-zinc-100 text-zinc-700'
              }`}
              title="Copy conversation dialogue to clipboard"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>

            <button
              onClick={handleSaveStream}
              className={`p-1.5 rounded-md border text-xs transition-colors flex items-center gap-1 ${
                isDark ? 'border-zinc-700 hover:bg-zinc-800 text-zinc-300' : 'border-zinc-300 hover:bg-zinc-100 text-zinc-700'
              }`}
              title="Download stream text file"
            >
              <Download className="w-4 h-4 text-sky-400" />
            </button>

            <button
              onClick={onClose}
              className={`p-1.5 rounded-md hover:bg-zinc-800 ${isDark ? "text-zinc-400" : "text-slate-600"} hover:text-zinc-200`}
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Legend */}
        <div
          className={`px-4 py-2 border-b text-xs flex items-center justify-between ${
            isDark ? 'bg-zinc-900/50 border-zinc-800 text-zinc-300' : 'bg-zinc-50 border-zinc-200 text-zinc-700'
          }`}
        >
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full bg-rose-500" />
              <span className="font-semibold text-rose-400">Client Traffic ({totalClientBytes} bytes)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full bg-sky-400" />
              <span className="font-semibold text-sky-400">Server Traffic ({totalServerBytes} bytes)</span>
            </div>
          </div>
          <span className={`text-[11px] font-mono ${isDark ? "text-zinc-500" : "text-slate-600"}`}>Wireshark Stream Follower Engine</span>
        </div>

        {/* Stream Dialogue Viewport */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs custom-scrollbar">
          {streamPackets.length === 0 ? (
            <div className={`text-center py-12 ${isDark ? "text-zinc-500" : "text-slate-600"}`}>No stream payload data recorded for stream #{streamId}.</div>
          ) : (
            streamPackets.map(p => {
              const isClient = p.source === clientIp;
              const payload = p.streamPayload?.payloadText || p.asciiDump;

              return (
                <div
                  key={p.id}
                  className={`p-3 rounded-lg border leading-relaxed ${
                    isClient
                      ? isDark
                        ? 'bg-rose-950/20 border-rose-900/40 text-rose-300'
                        : 'bg-rose-50 border-rose-200 text-rose-900'
                      : isDark
                      ? 'bg-sky-950/20 border-sky-900/40 text-sky-300'
                      : 'bg-sky-50 border-sky-200 text-sky-900'
                  }`}
                >
                  <div className="flex items-center justify-between pb-1 mb-1 border-b border-current/20 text-[10px] opacity-75 font-sans">
                    <span className="font-semibold">
                      Frame #{p.id} • {isClient ? 'Client Request' : 'Server Response'} ({p.source}:{p.sourcePort} → {p.destination}:{p.destPort})
                    </span>
                    <span>{p.relativeTime.toFixed(4)}s ({p.length} bytes)</span>
                  </div>

                  <pre className="whitespace-pre-wrap font-mono text-xs break-all">
                    {viewFormat === 'hex' ? p.hexDump : payload}
                  </pre>
                </div>
              );
            })
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-4 py-2.5 border-t border-zinc-800 flex items-center justify-between text-xs">
          <span className={`${isDark ? "text-zinc-500" : "text-slate-600"} font-mono`}>
            Total {streamPackets.length} Packets ({totalClientBytes + totalServerBytes} bytes exchanged)
          </span>
          <button
            onClick={onClose}
            className={`px-4 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 ${isDark ? "text-zinc-200" : "text-slate-800"} font-medium transition-colors`}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
