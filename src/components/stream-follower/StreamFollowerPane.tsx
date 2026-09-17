import React, { useState } from 'react';
import { Packet } from '../../types/packet';
import {
  MessageSquare,
  Copy,
  Check,
  Download,
  TriangleAlert,
  LoaderCircle,
} from 'lucide-react';
import { packetHexDump, packetAsciiDump } from '../../services/pcapParser';
import { saveGeneratedBlob } from '../../lib/saveFile';
import {
  clientEnd, isFromClient, streamPackets as framesOnStream,
  type StreamTarget,
} from '../../services/followStream';
import { portLabel } from '../../services/portServices';
import { useHydratedBytes } from '../../lib/useHydratedBytes';
import { Segmented } from '../ui/segmented';
import { LadderView } from '../ladder/LadderView';
import { copyText } from '../ui/CopyButton';

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

interface StreamFollowerPaneProps {
  target: StreamTarget | null;
  packets: Packet[];
  /**
   * Leaves for the packet list, and lands on the frame this was opened from.
   *
   * Unlike Statistics' version of this, it has a destination: a stream is always
   * entered from one packet - a row's context menu, the detail window, a
   * conversation table - and the thing you were looking at before is the thing
   * you want back. App records the origin and restores the selection.
   */
  onReturnToPackets: () => void;
  /** The frame the stream was opened from, named on the control that returns. */
  originFrame?: number | null;
  /**
   * The frame selected in the packet list, and how to change it.
   *
   * This window used to print `Frame #N` as plain text and have no way back to
   * the list at all - which meant finding a frame you had just read about
   * involved closing the window and scrolling. Optional, because the export
   * dialog opens a follower over a buffer it does not own.
   */
  selectedId?: number;
  onSelectFrame?: (id: number) => void;
  /**
   * Which view to open on.
   *
   * "Show conversation" and "Follow stream" are the same window opened with a
   * different question in mind - one asks about shape, the other about
   * content - so they are one component with two doors rather than two
   * components that would drift apart.
   */
  initialTab?: 'dialogue' | 'ladder';
}

export const StreamFollowerPane: React.FC<StreamFollowerPaneProps> = ({
  target,
  packets,
  onReturnToPackets,
  originFrame = null,
  selectedId,
  onSelectFrame,
  initialTab = 'dialogue',
}) => {
  // Which of the two ways of reading a conversation is showing. The dialogue
  // answers "what was said"; the ladder answers "in what shape" - a request
  // answered four seconds later, a side that went quiet, a retransmission
  // burst. Both are the same frames.
  const [tab, setTab] = useState<'dialogue' | 'ladder'>(initialTab);
  const [viewFormat, setViewFormat] = useState<'ascii' | 'hex' | 'raw'>('ascii');
  const [copied, setCopied] = useState(false);

  /*
   * Escape used to be handled here, in the capture phase with `stopPropagation`,
   * because this window opened ON TOP of the packet detail window and that
   * window stands down while covered - so without it the topmost thing on screen
   * was the one key that dismissed nothing.
   *
   * It is gone, and nothing replaced it. Both surfaces are VIEWS now - `stream`
   * and `detail` are sibling `AppView`s, so exactly one of them is mounted at a
   * time and neither can ever sit on top of the other. There is no covered pane
   * to stand down, which is the whole of what that listener existed to manage.
   *
   * App's view-level handler owns Escape in the bubble phase, explicitly last in
   * the chain, and returns any non-Packets view to Packets. A capture-phase
   * listener here would make this pane the FIRST to see the key and navigate out
   * from under whatever popover this pane itself has open - which is the rule
   * every inner consumer in the app keeps, not a fact about the detail view.
   */

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

  const handleCopyStream = async () => {
    const fullDialogue = streamPackets
      .map(p => {
        const prefix = isFromClient(p, client) ? `[CLIENT -> SERVER (${p.source})]` : `[SERVER -> CLIENT (${p.source})]`;
        return `${prefix}\n${p.streamPayload?.payloadText || packetAsciiDump(p)}\n`;
      })
      .join('\n');

    // Through `copyText` rather than `navigator.clipboard` directly: it carries
    // the execCommand fallback for contexts that refuse the async API, and it
    // reports failure - so the tick is not shown for a copy that did not happen.
    if (!(await copyText(fullDialogue))) return;
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
    // Fire and forget: the dialog IS the feedback, and the only other outcomes
    // are a cancel (which needs no comment) and a write error (which the
    // dialog's own failure already put in front of the person).
    void saveGeneratedBlob(
      blob,
      `${target.kind}_stream_${target.streamId ?? `${target.portA}-${target.portB}`}_conversation.txt`,
    );
  };

  return (
    /*
     * A pane. The `z-[60]` that put this above every other modal is gone with the
     * scrim, and so is the reason for it: it was the only modal that opened on top
     * of another, and it does not open on top of anything now.
     */
    <div className="flex-1 min-w-0 flex flex-col overflow-hidden bg-card text-card-foreground">
      <>
        {/* Pane header */}
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MessageSquare className="w-7 h-7 shrink-0 text-primary" />
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
            <Segmented<'dialogue' | 'ladder'>
              size="sm"
              ariaLabel="How to read this stream"
              value={tab}
              onValueChange={setTab}
              options={[
                { value: 'dialogue', label: 'Dialogue' },
                { value: 'ladder', label: 'Ladder' },
              ]}
            />
            {/* View Format Switcher. Only for the dialogue - a ladder has no
                payload to render as hex, and leaving a dead control on screen
                is worse than removing it. */}
            <div className={`flex rounded-md border border-border bg-secondary p-0.5 text-xs ${
              tab === 'ladder' ? 'hidden' : ''}`}>
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
              onClick={() => { void handleCopyStream(); }}
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
              <Download className="w-4 h-4 text-foreground" />
            </button>

            {/* The X stood here. The footer's control is the one that returns,
                and it names where it goes - two ways out of a pane, one of which
                is unlabelled, is one too many. */}
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
            <TriangleAlert className="w-4 h-4 shrink-0 mt-px" />
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
            <LoaderCircle className="w-4 h-4 shrink-0 animate-spin" />
            <span>Reading this stream’s bytes back from the stored capture…</span>
          </div>
        )}

        {tab === 'ladder' ? (
          <LadderView
            target={target}
            packets={packets}
            selectedId={selectedId}
            onSelectFrame={onSelectFrame}
          />
        ) : (
        /* Stream Dialogue Viewport */
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
                    p.id === selectedId ? 'ring-2 ring-primary/60 ' : ''}${
                    isClient
                      ? 'bg-rose-50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/40 text-rose-900 dark:text-rose-300'
                      : 'bg-sky-50 dark:bg-sky-950/20 border-sky-200 dark:border-sky-900/40 text-sky-900 dark:text-sky-300'
                  }`}
                >
                  <div className="flex items-center justify-between pb-1 mb-1 border-b border-current/20 text-[10px] opacity-75 font-sans">
                    {/* Clickable, at last. This printed as plain text, so the
                        only way to find a frame you had just read about was to
                        close the window and scroll for it. */}
                    <span className="font-semibold">
                      {onSelectFrame ? (
                        <button onClick={() => onSelectFrame(p.id)}
                          className="underline decoration-dotted underline-offset-2
                            hover:decoration-solid cursor-pointer"
                          title="Select this frame in the packet list">
                          Frame #{p.id}
                        </button>
                      ) : <>Frame #{p.id}</>}
                      {' • '}{isClient ? 'Client Request' : 'Server Response'} ({p.source}:{p.sourcePort} → {p.destination}:{p.destPort})
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
        )}

        {/* Modal Footer */}
        <div className="px-4 py-2.5 border-t border-border flex items-center justify-between text-xs">
          <span className="text-muted-foreground font-mono">
            Total {streamPackets.length} Packets ({totalClientBytes + totalServerBytes} bytes exchanged)
          </span>
          {/* Named, because it is navigation rather than dismissal: it goes back
              to the list and lands on the frame this stream was opened from. */}
          <button
            onClick={onReturnToPackets}
            className="px-4 py-1.5 rounded-md bg-secondary hover:bg-accent text-foreground font-medium transition-colors cursor-pointer"
          >
            {originFrame === null ? 'Back to packets' : `Back to frame ${originFrame.toLocaleString()}`}
          </button>
        </div>
      </>
    </div>
  );
};
