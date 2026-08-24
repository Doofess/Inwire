import React, { useState } from 'react';
import { Packet } from '../../types/packet';
import { MessageSquare, X, Copy, Check, Download, ArrowRightLeft, Shield } from 'lucide-react';

interface StreamFollowerModalProps {
  streamId: number | null;
  packets: Packet[];
  onClose: () => void;
}

export const StreamFollowerModal: React.FC<StreamFollowerModalProps> = ({
  streamId,
  packets,
  onClose,
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
      <div className="w-full max-w-4xl max-h-[85vh] rounded-xl border flex flex-col shadow-2xl transition-colors bg-card border-border text-card-foreground">
        {/* Modal Header */}
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-sky-500/20 text-sky-400">
              <MessageSquare className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 font-bold text-sm">
                <span>Follow Stream #{streamId}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-secondary text-foreground/80 font-mono">
                  {streamPackets.length} frames
                </span>
              </div>
              <p className="text-xs text-muted-foreground font-mono">
                {clientIp} <span className="text-muted-foreground">⇄</span> {serverIp}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* View Format Switcher */}
            <div className="flex rounded-md border border-border bg-secondary p-0.5 text-xs">
              <button
                onClick={() => setViewFormat('ascii')}
                className={`px-2 py-1 rounded font-medium transition-all ${
                  viewFormat === 'ascii'
                    ? 'bg-sky-600 text-white shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                ASCII / UTF-8
              </button>
              <button
                onClick={() => setViewFormat('hex')}
                className={`px-2 py-1 rounded font-medium transition-all ${
                  viewFormat === 'hex'
                    ? 'bg-sky-600 text-white shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                Hex Dump
              </button>
              <button
                onClick={() => setViewFormat('raw')}
                className={`px-2 py-1 rounded font-medium transition-all ${
                  viewFormat === 'raw'
                    ? 'bg-sky-600 text-white shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                Raw Byte
              </button>
            </div>

            <button
              onClick={handleCopyStream}
              className="p-1.5 rounded-md border text-xs transition-colors flex items-center gap-1 border-border hover:bg-accent text-foreground/80"
              title="Copy conversation dialogue to clipboard"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>

            <button
              onClick={handleSaveStream}
              className="p-1.5 rounded-md border text-xs transition-colors flex items-center gap-1 border-border hover:bg-accent text-foreground/80"
              title="Download stream text file"
            >
              <Download className="w-4 h-4 text-sky-400" />
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Legend */}
        <div className="px-4 py-2 border-b text-xs flex items-center justify-between bg-secondary/50 border-border text-foreground/80">
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
          <span className="text-[11px] font-mono text-muted-foreground">Wireshark Stream Follower Engine</span>
        </div>

        {/* Stream Dialogue Viewport */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs custom-scrollbar">
          {streamPackets.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">No stream payload data recorded for stream #{streamId}.</div>
          ) : (
            streamPackets.map(p => {
              const isClient = p.source === clientIp;
              const payload = p.streamPayload?.payloadText || p.asciiDump;

              return (
                <div
                  key={p.id}
                  className={`p-3 rounded-lg border leading-relaxed ${
                    isClient
                      ? 'bg-rose-50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/40 text-rose-900 dark:text-rose-300'
                      : 'bg-sky-50 dark:bg-sky-950/20 border-sky-200 dark:border-sky-900/40 text-sky-900 dark:text-sky-300'
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
        <div className="px-4 py-2.5 border-t border-border flex items-center justify-between text-xs">
          <span className="text-muted-foreground font-mono">
            Total {streamPackets.length} Packets ({totalClientBytes + totalServerBytes} bytes exchanged)
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md bg-secondary hover:bg-accent text-foreground font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
