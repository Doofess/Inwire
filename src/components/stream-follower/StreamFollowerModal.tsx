import React, { useEffect, useState } from 'react';
import { Packet } from '../../types/packet';
import { TbMessage, TbX, TbCopy, TbCheck, TbDownload, TbAlertTriangle, TbLoader2 } from 'react-icons/tb';
import { packetHexDump, packetAsciiDump } from '../../services/pcapParser';
import { downloadBlob } from '../../lib/download';
import {
  clientEnd, isFromClient, streamPackets as framesOnStream,
  type StreamTarget,
} from '../../services/followStream';
import { portLabel } from '../../services/portServices';
import { useHydratedBytes } from '../../lib/useHydratedBytes';

/**
 * One conversation's payload, both directions, in order.
 *
 * Takes a five-tuple rather than the TCP stream index it used to: the tracker
 * numbers TCP conversations only, so a DNS exchange or a QUIC connection had
 * no id and this window could not be opened on one at all - which is most of
 * a modern capture. `services/followStream.ts` owns the selection and the
 * client/server decision so both are testable; this file renders them.
 */

/**
 * A stable empty list for the closed window.
 *
 * `useHydratedBytes` keys its effect on which frames it was handed, and a
 * fresh `[]` on every render would be a new set each time.
 */
const EMPTY_FRAMES: Packet[] = [];

interface StreamFollowerModalProps {
  target: StreamTarget | null;
  packets: Packet[];
  onClose: () => void;
}

export const StreamFollowerModal: React.FC<StreamFollowerModalProps> = ({
  target,
  packets,
  onClose,
}) => {
  const [viewFormat, setViewFormat] = useState<'ascii' | 'hex' | 'raw'>('ascii');
  const [copied, setCopied] = useState(false);

  /**
   * Escape closes this window, matching every other modal.
   *
   * It also has to be handled HERE rather than left to whatever is underneath:
   * this window can open on top of the packet detail window, which listens for
   * Escape on `window` in the capture phase. That window stands down while it
   * is covered, so without this the topmost thing on screen would be the one
   * key that dismisses nothing.
   *
   * Declared above the `streamId === null` early return so the hook order is
   * the same on every render.
   */
  useEffect(() => {
    if (target === null) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.preventDefault();
      e.stopPropagation();
      onClose();
    };
    window.addEventListener('keydown', onKeyDown, true);
    return () => window.removeEventListener('keydown', onKeyDown, true);
  }, [target, onClose]);

  // Hydrated, because every view below reads the frames' bytes and a buffer
  // large enough to have dropped them would otherwise render an empty stream
  // (docs/decisions/0013). A pass-through while the buffer still holds them,
  // which is every capture that fits in memory.
  //
  // Above the `target === null` early return, for the same reason the effect
  // above it is: this window is mounted with a null target and given one when
  // it opens, so a hook below the return would change the hook COUNT between
  // two renders of the same component - which React refuses outright. It is
  // the invariant the comment on that effect already names, and this hook was
  // added underneath it.
  const { packets: streamPackets, hydrating } = useHydratedBytes(
    target === null ? EMPTY_FRAMES : framesOnStream(packets, target),
  );

  if (target === null) return null;

  // Not "whoever sent the first frame": a capture that started mid-connection
  // has no SYN to go on, and a well-known port on one end says far more - and
  // when neither applies, `basis` says the answer is a guess so the window can
  // disclose it rather than colour the conversation on one.
  const client = clientEnd(streamPackets, target);
  const clientIp = client.address;
  const serverIp = client.address === target.addressA ? target.addressB : target.addressA;
  const serverPort = client.port === target.portA ? target.portB : target.portA;

  let totalClientBytes = 0;
  let totalServerBytes = 0;

  for (const p of streamPackets) {
    if (isFromClient(p, client)) totalClientBytes += p.length;
    else totalServerBytes += p.length;
  }

  /**
   * The payload as the chosen view shows it.
   *
   * `raw` was rendering the ASCII view - the two buttons produced identical
   * output, which is worse than not offering the choice. Wireshark's Raw is
   * the payload bytes as one unbroken hex string, which is what gets pasted
   * into a decoder; the hex dump with its offsets and ASCII column is a
   * different thing and already has its own button.
   */
  const renderPayload = (p: Packet): string => {
    if (viewFormat === 'hex') return packetHexDump(p);
    if (viewFormat === 'raw') {
      return Array.from(p.rawBytes, (b) => b.toString(16).padStart(2, '0')).join('');
    }
    return p.streamPayload?.payloadText || packetAsciiDump(p);
  };

  const handleCopyStream = () => {
    const fullDialogue = streamPackets
      .map(p => {
        const prefix = isFromClient(p, client) ? `[CLIENT -> SERVER (${p.source})]` : `[SERVER -> CLIENT (${p.source})]`;
        return `${prefix}\n${p.streamPayload?.payloadText || packetAsciiDump(p)}\n`;
      })
      .join('\n');

    navigator.clipboard.writeText(fullDialogue);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleSaveStream = () => {
    const fullDialogue = streamPackets
      .map(p => {
        const prefix = isFromClient(p, client) ? `>>> [CLIENT -> SERVER] ${p.source}:${p.sourcePort}` : `<<< [SERVER -> CLIENT] ${p.source}:${p.sourcePort}`;
        return `${prefix}\n${p.streamPayload?.payloadText || packetAsciiDump(p)}\n`;
      })
      .join('\n');

    const blob = new Blob([fullDialogue], { type: 'text/plain;charset=utf-8' });
    downloadBlob(blob, `${target.kind}_stream_${target.streamId ?? `${target.portA}-${target.portB}`}_conversation.txt`);
  };

  return (
    // z-[60] rather than the z-50 every other modal uses, because this is the
    // only one that opens ON TOP of another: the packet detail window has a
    // Follow Stream link. Relying on render order instead would work today and
    // break silently the first time someone reorders the JSX in App.tsx.
    <div className="fixed inset-0 z-[60] bg-black/70 flex items-center justify-center p-4">
      <div className="w-full max-w-4xl max-h-[85vh] rounded-xl border flex flex-col shadow-2xl transition-colors bg-card border-border text-card-foreground">
        {/* Modal Header */}
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TbMessage className="w-7 h-7 shrink-0 text-primary" />
            <div>
              <div className="flex items-center gap-2 font-bold text-sm">
                <span>
                  Follow {target.kind.toUpperCase()} Stream
                  {target.streamId !== undefined ? ` #${target.streamId}` : ''}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-secondary text-foreground/80 font-mono">
                  {streamPackets.length} frames
                </span>
              </div>
              <p className="text-xs text-muted-foreground font-mono">
                {clientIp} <span className="text-muted-foreground">⇄</span> {serverIp}
                :{portLabel(serverPort, target.kind, true)}
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
              {copied ? <TbCheck className="w-4 h-4 text-emerald-400" /> : <TbCopy className="w-4 h-4" />}
            </button>

            <button
              onClick={handleSaveStream}
              className="p-1.5 rounded-md border text-xs transition-colors flex items-center gap-1 border-border hover:bg-accent text-foreground/80"
              title="Download stream text file"
            >
              <TbDownload className="w-4 h-4 text-foreground" />
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground"
            >
              <TbX className="w-5 h-5" />
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
          <span className="text-[11px] font-mono text-muted-foreground">Stream Follower Engine</span>
        </div>

        {/* What this window is NOT sure about, said before the dialogue rather
            than after it. Both of these change how the conversation below
            should be read, and neither is visible in it. */}
        {client.basis === 'first-speaker' && (
          <div className="px-4 py-2 border-b border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-[11px] flex items-start gap-2">
            <TbAlertTriangle className="w-4 h-4 shrink-0 mt-px" />
            <span>
              The start of this conversation is not in the capture, and neither port
              is a well-known one — so <strong>client and server are assumed</strong> from
              whichever end was heard first. If the beginning was trimmed or capture
              began mid-connection, the two colours are the wrong way round.
            </span>
          </div>
        )}
        {hydrating && (
          <div className="px-4 py-2 border-b border-border bg-muted/40 text-muted-foreground text-[11px] flex items-center gap-2">
            <TbLoader2 className="w-4 h-4 shrink-0 animate-spin" />
            <span>Reading this stream’s bytes back from the stored capture…</span>
          </div>
        )}

        {/* Stream Dialogue Viewport */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs custom-scrollbar">
          {streamPackets.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">No frames on this stream are in the buffer.</div>
          ) : (
            streamPackets.map(p => {
              const isClient = isFromClient(p, client);

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
                    {renderPayload(p)}
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
