import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Packet } from '../../types/packet';
import {
  MessageSquare,
  Copy,
  Check,
  Download,
  TriangleAlert,
} from 'lucide-react';
import { saveGeneratedBlob } from '../../lib/saveFile';
import {
  clientEnd, isFromClient, streamPackets as framesOnStream,
  type StreamTarget,
} from '../../services/followStream';
import { portLabel } from '../../services/portServices';
import { virtualWindow } from '../../lib/virtualWindow';
import { Segmented } from '../ui/segmented';
import { LadderView } from '../ladder/LadderView';
import { copyText } from '../ui/CopyButton';

/**
 * One conversation's frames, both directions, in order.
 *
 * Takes a five-tuple rather than the TCP stream index it used to: the tracker
 * numbers TCP conversations only, so a DNS exchange or a QUIC connection had
 * no id and this window could not be opened on one at all - which is most of
 * a modern capture. `services/followStream.ts` owns the selection and the
 * client/server decision so both are testable; this file renders them.
 *
 * ## This shows frame headers, not payload, and that is a decision
 *
 * It used to render every frame on the stream as ASCII, a hex dump or one
 * unbroken hex string, chosen by three buttons. Three things made that
 * unusable on a real stream, and they compounded:
 *
 * - `framesOnStream` is a `.filter()` over the WHOLE packet buffer - up to a
 *   million frames - and it was called inline in the render body, so it ran on
 *   every render and returned a new array each time.
 * - The list was not virtualised. Every frame on the stream got a card.
 * - `renderPayload` was called inside that map, so each frame's full dump was
 *   rebuilt on every render. A 10,000-frame stream of 1,460-byte segments is
 *   ~14.6M transient strings per render, which is a multi-second freeze and a
 *   GC storm.
 *
 * **What was lost is real and is recorded rather than quietly dropped:** this
 * was the only place in the app that showed a reassembled conversation's
 * payload - the thing Follow Stream exists for in Wireshark, and the way you
 * read an HTTP exchange or notice a credential in the clear. The trade was put
 * explicitly and this is the answer that was chosen.
 *
 * **If it comes back, it comes back virtualised**: rendered for the ~30 rows
 * on screen and memoised per packet id, never rebuilt inside a map over the
 * whole stream. `virtualWindow` below is half of what that needs; the other
 * half was `lib/useHydratedBytes.ts`, which this file was the only consumer
 * of and which went with the payload rather than being left as a module
 * nothing imports. It is in git, and `scripts/session/side-bar.ts` records
 * the rule that outlived it - hydrate at press time, not on render.
 *
 * The Ladder tab is untouched. It answers the other half of the question -
 * the shape of a conversation rather than its content - and it reads no bytes.
 */

/**
 * A stable empty list for the closed window.
 *
 * This pane is mounted with a null target and given one when it opens, so the
 * memo below runs on every render of a closed window; a fresh `[]` each time
 * would change identity for everything downstream of it.
 */
const EMPTY_FRAMES: Packet[] = [];

/**
 * One dialogue row, in pixels.
 *
 * Applied as an inline `height` on the row rather than as a Tailwind class, so
 * the number the spacers are computed from and the number the row is drawn at
 * cannot drift apart - a row one pixel taller than the constant accumulates
 * into a list that scrolls past its own end.
 *
 * A uniform height is what lets `virtualWindow` do arithmetic instead of
 * measurement, and it is the structural reason the payload views this replaced
 * could not be virtualised as they stood: a frame's hex dump is as tall as the
 * frame is long, so every row would have had to be measured.
 */
const ROW_HEIGHT = 28;

/**
 * Rows drawn beyond each edge of the viewport.
 *
 * Twelve is `HexDumpView`'s number for a similar row height; it covers a fast
 * flick without drawing much that nobody sees.
 */
const OVERSCAN = 12;

interface StreamFollowerPaneProps {
  target: StreamTarget | null;
  packets: Packet[];
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
  selectedId,
  onSelectFrame,
  initialTab = 'dialogue',
}) => {
  // Which of the two ways of reading a conversation is showing. The dialogue
  // answers "what was said"; the ladder answers "in what shape" - a request
  // answered four seconds later, a side that went quiet, a retransmission
  // burst. Both are the same frames.
  const [tab, setTab] = useState<'dialogue' | 'ladder'>(initialTab);
  const [copied, setCopied] = useState(false);
  // Where the dialogue is scrolled to, for the virtual window below.
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(0);
  const scrollFrame = useRef<number | null>(null);

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

  // No byte hydration here any more, and its absence is the point: this view
  // reads `id`, `relativeTime`, the addresses and `length`, every one of which
  // is on the summary record. It used to read `rawBytes` off every frame on the
  // stream, so opening a stream whose frames the buffer had dropped meant a
  // round trip to the store and a spinner (docs/decisions/0013). Now it opens
  // on whatever is in the buffer, immediately, however long the stream is.

  /**
   * The frames on this stream.
   *
   * **Memoised, and that is the load-bearing part.** `framesOnStream` is a
   * filter over the whole buffer; called in the render body it ran on every
   * render - ten times a second during a capture - and handed back a new array
   * that changed identity for every memo below it. Keyed on the buffer and the
   * target, it runs when one of those actually changes.
   *
   * Above the `target === null` early return, because this pane is mounted with
   * a null target and given one when it opens - a hook below the return would
   * change the hook COUNT between two renders of the same component, which
   * React refuses outright.
   */
  const streamPackets = useMemo(
    () => (target === null ? EMPTY_FRAMES : framesOnStream(packets, target)),
    [packets, target],
  );

  /**
   * Scroll position, coalesced to one update per animation frame.
   *
   * The scroll event fires far faster than React can commit, and each one here
   * moves the virtual window. `{ passive: true }` is implicit on the React
   * handler; the rAF is what stops a fast flick queueing dozens of renders.
   */
  const onScroll = useCallback((event: React.UIEvent<HTMLDivElement>) => {
    const element = event.currentTarget;
    if (scrollFrame.current !== null) return;
    scrollFrame.current = requestAnimationFrame(() => {
      scrollFrame.current = null;
      setScrollTop(element.scrollTop);
      setViewportHeight(element.clientHeight);
    });
  }, []);

  /**
   * The scroller, measured on mount and on every resize.
   *
   * A `ResizeObserver` rather than measuring in the scroll handler, and it is
   * `PacketList.tsx:621`'s arrangement rather than a second answer to the same
   * question: a window resize changes this box without producing a scroll
   * event, so a height refreshed only on scroll goes stale exactly when the
   * pane gets taller and leaves blank space below the last row.
   */
  const viewportRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const element = viewportRef.current;
    if (element === null) return;
    const update = () => setViewportHeight(element.clientHeight);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(element);
    return () => observer.disconnect();
    // `tab` is the dep because the scroller only exists on the dialogue tab -
    // switching to the ladder unmounts it, and coming back mounts a new one.
  }, [tab]);

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
   * One frame as one line, and the same line the pane draws.
   *
   * Copy and save share it so what lands on the clipboard cannot drift from
   * what is on screen - they used to build their own dialogue strings, twice,
   * with two different prefix formats between them.
   *
   * Built only when a button is pressed. That is the whole difference from
   * what this replaced: the cost is O(stream) once, on an explicit action,
   * rather than O(stream) on every render.
   */
  const summaryLine = (p: Packet): string => {
    const arrow = isFromClient(p, client) ? '-->' : '<--';
    return [
      `#${p.id}`,
      `${p.relativeTime.toFixed(6)}s`,
      arrow,
      `${p.source}:${p.sourcePort}`,
      `${p.destination}:${p.destPort}`,
      `${p.length} B`,
    ].join('\t');
  };

  const streamText = (): string => {
    const header = `# Follow ${target.kind.toUpperCase()} stream`
      + `${target.streamId !== undefined ? ` #${target.streamId}` : ''}`
      + `  ${clientIp} <-> ${serverIp}:${serverPort}\n`
      + `# frame\ttime\tdir\tsource\tdestination\tlength\n`;
    return header + streamPackets.map(summaryLine).join('\n') + '\n';
  };

  const handleCopyStream = async () => {
    // Through `copyText` rather than `navigator.clipboard` directly: it carries
    // the execCommand fallback for contexts that refuse the async API, and it
    // reports failure - so the tick is not shown for a copy that did not happen.
    if (!(await copyText(streamText()))) return;
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleSaveStream = () => {
    const blob = new Blob([streamText()], { type: 'text/plain;charset=utf-8' });
    // Fire and forget: the dialog IS the feedback, and the only other outcomes
    // are a cancel (which needs no comment) and a write error (which the
    // dialog's own failure already put in front of the person).
    void saveGeneratedBlob(
      blob,
      `${target.kind}_stream_${target.streamId ?? `${target.portA}-${target.portB}`}_frames.txt`,
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
        {/* The "reading this stream's bytes back from the stored capture"
            banner stood here. Nothing replaced it because nothing waits any
            more: this view reads only what a summary record already carries,
            so a stream opens on whatever the buffer holds, immediately. */}

        {tab === 'ladder' ? (
          <LadderView
            target={target}
            packets={packets}
            selectedId={selectedId}
            onSelectFrame={onSelectFrame}
          />
        ) : (
        /*
         * The dialogue, virtualised.
         *
         * `virtualWindow` rather than the arithmetic inline, because that
         * arithmetic fails INVISIBLY: unclamped, a scroll offset the list can
         * no longer reach gives a `startIndex` past `endIndex`, so the slice is
         * empty and the only thing rendered is a top spacer the height of the
         * old list - which keeps `scrollHeight` large enough that the browser
         * never clamps the offset. A closed loop, and the reason that module
         * exists and is asserted. `HexDumpView` hand-rolls the same arithmetic
         * WITHOUT the clamp; it should be moved onto this too.
         */
        (() => {
          const view = virtualWindow(
            streamPackets.length, scrollTop, viewportHeight, ROW_HEIGHT, OVERSCAN,
          );
          return (
            <div
              ref={viewportRef}
              onScroll={onScroll}
              className="flex-1 overflow-y-auto font-mono text-xs custom-scrollbar"
            >
              {streamPackets.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  No frames on this stream are in the buffer.
                </div>
              ) : (
                <>
                  <div style={{ height: view.topSpacerHeight }} />
                  {streamPackets.slice(view.startIndex, view.endIndex).map((p) => {
                    const isClient = isFromClient(p, client);
                    return (
                      <div
                        key={p.id}
                        style={{ height: ROW_HEIGHT }}
                        className={`flex items-center gap-2 px-4 border-l-2 ${
                          p.id === selectedId ? 'bg-primary/10 ' : ''}${
                          isClient
                            ? 'border-rose-500 text-rose-700 dark:text-rose-300'
                            : 'border-sky-500 text-sky-700 dark:text-sky-300'
                        }`}
                      >
                        {/* Clickable, and it stays clickable. This printed as
                            plain text once, so the only way to find a frame you
                            had just read about was to close the window and
                            scroll for it. */}
                        <span className="w-20 shrink-0 font-semibold tabular-nums">
                          {onSelectFrame ? (
                            <button onClick={() => onSelectFrame(p.id)}
                              className="underline decoration-dotted underline-offset-2
                                hover:decoration-solid cursor-pointer"
                              title="Select this frame in the packet list">
                              #{p.id}
                            </button>
                          ) : <>#{p.id}</>}
                        </span>
                        <span className="w-24 shrink-0 tabular-nums text-muted-foreground">
                          {p.relativeTime.toFixed(4)}s
                        </span>
                        <span className="w-6 shrink-0 text-center" aria-hidden="true">
                          {isClient ? '→' : '←'}
                        </span>
                        <span className="flex-1 min-w-0 truncate">
                          {p.source}:{p.sourcePort}
                          <span className="text-muted-foreground"> to </span>
                          {p.destination}:{p.destPort}
                        </span>
                        <span className="w-20 shrink-0 text-right tabular-nums text-muted-foreground">
                          {p.length} B
                        </span>
                      </div>
                    );
                  })}
                  <div style={{ height: view.bottomSpacerHeight }} />
                </>
              )}
            </div>
          );
        })()
        )}

        {/* **The "Back to frame N" button was here and is in the chrome.**
            It was this pane's own way out, which made going back a thing you
            found in the footer of one view and nowhere else. The title row
            carries a back control for every view that has somewhere to go, so
            the step out of a stream is in the same place as the step out of
            Frame Detail - and it still lands on the frame the stream was opened
            from, because `App` restores that on the way. */}
        <div className="px-4 py-2.5 border-t border-border flex items-center text-xs">
          <span className="text-muted-foreground font-mono">
            Total {streamPackets.length} Packets ({totalClientBytes + totalServerBytes} bytes exchanged)
          </span>
        </div>
      </>
    </div>
  );
};
