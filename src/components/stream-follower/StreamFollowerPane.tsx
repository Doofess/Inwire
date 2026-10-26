import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Packet } from '../../types/packet';
import {
  MessageSquare,
  Copy,
  Check,
  Download,
  PanelRightOpen,
  TriangleAlert,
} from 'lucide-react';
import { saveGeneratedBlob } from '../../lib/saveFile';
import {
  clientEnd, endpointText, sideOf, streamPackets as framesOnStream,
  type ClientEnd, type StreamTarget,
} from '../../services/followStream';
import type { Endpoint } from '../../services/conversation/clientSide';
import type { StreamSummary } from '../../services/conversation/streamDigest';
import type { QuicPhaseStep, QuicSummary, UdpSummary } from '../../services/conversation/flowSummary';
import { keepFrames, loadStreamFrames, progressGate, recallFrames } from '../../services/conversation/streamFrames';
import { captureStore } from '../../services/capture/captureClient';
import type { ColorRulesEngine } from '../../services/colorRules';
import type { PacketTheme } from '../../services/packetThemes';
import { portLabel } from '../../services/portServices';
import { virtualWindow } from '../../lib/virtualWindow';
import { Segmented } from '../ui/segmented';
import { LadderView, type ScrollRequest } from '../ladder/LadderView';
import { TcpStateMap } from '../ladder/TcpStateMap';
import { copyText } from '../ui/CopyButton';
import { PhaseLine } from './PhaseLine';
import { dnsMarks } from '../../services/conversation/dnsMarks';
import type { TlsSummary } from '../../services/conversation/tlsSummary';
import type { DhcpSummary } from '../../services/conversation/dhcpSummary';

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

/**
 * How often a stream still being read is handed to the views, at most.
 *
 * `loadStreamFrames` reports after every page of 256 rows, and a stream of a
 * hundred thousand frames is four hundred pages. Each report the views see is
 * a copy of the frames so far and a fold of them, so they are taken at the
 * rate the packet list flushes at rather than at the rate the store answers.
 */
const PUBLISH_MS = 100;

const NONE_EXPANDED: ReadonlySet<number> = new Set();

/**
 * One stream's frames as read through the digest: the whole capture's, in
 * id order. `loading` is set until the last page has arrived.
 */
interface LoadedStream {
  /** `streamKey`: a TCP stream id and a UDP key are both small integers, so the kind rides in it. */
  key: string;
  frames: Packet[];
  /** `searched` (0..1): how far a sparse UDP or QUIC flow's search has got, when it reports one. */
  loading: { loaded: number; total: number; searched?: number } | null;
}

/** " · 40% searched" while a flow's search is under way, else nothing. */
function searchedSuffix(searched: number | undefined): string {
  return searched !== undefined && searched < 1 ? ` · ${Math.floor(searched * 100)}% searched` : '';
}

type AnySummary = StreamSummary | UdpSummary | QuicSummary | DhcpSummary;

/** What names a stream within one capture: its kind and the key the digest holds it under. */
const streamKey = (kind: StreamTarget['kind'], id: number): string => `${kind}:${id}`;
const summaryKey = (s: AnySummary): string => ('kind' in s ? streamKey(s.kind, s.key) : streamKey('tcp', s.streamId));

/**
 * A DHCP exchange's client is a hardware address and its side comes from the
 * message type, so the "client is a guess" notice has nothing to disclose.
 */
const DHCP_BASIS = 'well-known-port' as const;

/** The words for a QUIC phase. Inferred from what the frames carry, so the tooltip says so. */
const PHASE_LABEL: Record<QuicPhaseStep['phase'], string> = {
  initial: 'Initial', handshake: 'Handshake', '1-rtt': '1-RTT', closed: 'Closed',
};

interface StreamFollowerPaneProps {
  target: StreamTarget | null;
  packets: Packet[];
  /**
   * The digest's summary of the target's stream, UDP flow, QUIC connection or DHCP exchange
   * (ADR 0055), or null when there is none to have: a capture with no store, a
   * digest that has not answered yet, or a target the digest does not hold.
   * With one, the pane reads the stream's frames from the whole capture;
   * without, it shows what the buffer holds, as it always did.
   */
  summary: AnySummary | null;
  /** The digest's TLS phases for a TCP target, from the same poll as `summary`. */
  tls?: TlsSummary | null;
  /**
   * The capture the digest is answering for, or null when none has answered.
   * Everything this pane keeps per stream belongs to one capture, and a stream
   * index is unique within one capture only; a change here, to anything,
   * drops it all.
   */
  captureId: string | null;
  /** The digest's capture end, which decides when a DNS query stops waiting. */
  captureEnd?: number;
  /** The packet list's own colouring, so an arrow looks like its row. */
  colorEngine: ColorRulesEngine;
  packetTheme: PacketTheme;
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
  summary,
  tls,
  captureId,
  captureEnd = 0,
  colorEngine,
  packetTheme,
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
   * The stream's frames from the whole capture, read through the digest.
   *
   * Loaded once per stream, keyed on the summary's kind and key and not on the
   * summary itself: the digest polls once a second and hands back a new
   * summary each time the stream changes, and reloading on each would read a
   * live stream off disk every second. `summary.lastId` bounds the disk read,
   * so on a live capture the frames read end at that summary's `lastId` and
   * everything after comes from RAM - `tail` below - which is the right
   * answer, since the store and the buffer overlap at exactly that point.
   *
   * Pages are published to the views as they arrive, so the ladder is usable
   * from its first page; a cancelled read publishes nothing more. The frames
   * are kept by stream id, the last two streams and none over
   * `KEPT_FRAMES_MAX`, so switching tabs or going back to the stream just
   * left costs nothing and the pane's memory stays bounded.
   */
  const [stream, setStream] = useState<LoadedStream | null>(null);
  const cache = useRef(new Map<string, Packet[]>());

  // Bands the user opened, by their first frame's id. Held here rather than in
  // the ladder so a band stays open across the tabs; an id rather than an
  // index because a live stream grows under the fold, and the band somebody
  // opened must stay open across the next flush.
  const [expanded, setExpanded] = useState<ReadonlySet<number>>(NONE_EXPANDED);

  // The arrow under the pointer. The ladder reports it and draws it lit; the
  // state map, docked beside it, reads the same id to light the transition.
  const [hoverFrameId, setHoverFrameId] = useState<number | null>(null);

  // The frame a click on the state map asked the ladder to show. A fresh
  // object per click, so the same state clicked twice is two requests, and
  // never cleared: a frame still on its way from disk is brought in by the
  // page that brings it, which a request withdrawn after one render would miss.
  const [scrollTo, setScrollTo] = useState<ScrollRequest | null>(null);
  const pickState = useCallback((frameId: number) => setScrollTo({ frameId }), []);

  // Whether the state map is docked beside the ladder where the pane is
  // narrower than 1180px. Above that it is always docked and this is not
  // consulted; the classes below carry the width rule, not this state.
  const [mapOpen, setMapOpen] = useState(true);

  // A new capture drops everything kept per stream - the frames, the cache,
  // the opened bands, the hovered frame - because all of it is keyed by ids
  // that start again from one. Keyed on the capture the digest is answering
  // for rather than on the target being cleared, because an import under an
  // open view clears nothing. Declared before the load below so that, in a
  // commit where both run, the reset goes first and the load finds an empty
  // cache. Skipped on mount, when there is nothing to drop.
  const seenCapture = useRef(captureId);
  useEffect(() => {
    if (seenCapture.current === captureId) return;
    seenCapture.current = captureId;
    cache.current.clear();
    setStream(null);
    setExpanded(NONE_EXPANDED);
    setHoverFrameId(null);
    setScrollTo(null);
  }, [captureId]);

  const summaryId = summary === null ? undefined : summaryKey(summary);
  useEffect(() => {
    if (summary === null) return;
    const streamId = summaryKey(summary);
    const cached = recallFrames(cache.current, streamId);
    if (cached !== undefined) {
      setStream({ key: streamId, frames: cached, loading: null });
      return;
    }
    const total = summary.toServer.packets + summary.toClient.packets;
    const signal = { cancelled: false };
    // The gate answers for a page that resolves after this stream was left:
    // published, it would put the old frames under the new stream's summary.
    const publish = progressGate(signal, PUBLISH_MS);
    setStream({ key: streamId, frames: EMPTY_FRAMES, loading: { loaded: 0, total } });
    void loadStreamFrames(summary, packets, captureStore, (loaded, soFar, searched) => {
      if (!publish(performance.now())) return;
      // A copy: the array handed over is the one still being filled.
      setStream({ key: streamId, frames: soFar.slice(), loading: { loaded, total, searched } });
    }, signal).then((frames) => {
      if (signal.cancelled) return;
      keepFrames(cache.current, streamId, frames);
      setStream({ key: streamId, frames, loading: null });
    }).catch((error: unknown) => {
      // The read failed: the pane falls back to the buffer's frames, as it
      // would with no summary, rather than reading "Reading 0 of N" for good.
      // Not cached, so opening the stream again tries again.
      if (signal.cancelled) return;
      console.warn('[Inwire] Reading a stream from the capture failed; showing the buffer\'s frames.', error);
      setStream(null);
    });
    return () => { signal.cancelled = true; };
    // `summary` and `packets` are read as they were when the stream changed;
    // see above for why neither is a dependency. The capture id is one: a
    // load begun against a stale digest - the view re-enabled after a restart,
    // the new capture numbering a stream the same - must be cancelled when the
    // capture answering changes, or it would finish and cache the old
    // capture's frames under the new one's stream.
  }, [captureId, summaryId]);

  // What was loaded counts only for the stream on screen: the target can
  // change under a load, and the fallback below answers until the new one is
  // in. A target with no stream id (a UDP frame the digest has no key for)
  // never matches.
  const targetId = target === null || target.streamId === undefined ? undefined : streamKey(target.kind, target.streamId);
  const loaded = stream !== null && targetId !== undefined && stream.key === targetId ? stream : null;

  /**
   * The RAM frames past what was read: a live stream keeps growing after its
   * one read. Appended only once the read is complete - behind a partial read
   * they would leave a hole between the two that reads as frames the capture
   * lost - and kept by identity while nothing past the read has arrived, so a
   * flush of other streams' frames does not re-fold this one.
   */
  const tailRef = useRef<Packet[]>(EMPTY_FRAMES);
  const tail = useMemo(() => {
    if (loaded === null || loaded.loading !== null) return EMPTY_FRAMES;
    const last = loaded.frames.length > 0 ? loaded.frames[loaded.frames.length - 1].id : 0;
    const after = streamPackets.filter((p) => p.id > last);
    const previous = tailRef.current;
    const same = previous.length === after.length
      && (after.length === 0 || previous[after.length - 1] === after[after.length - 1]);
    if (same) return previous;
    tailRef.current = after;
    return after;
  }, [loaded, streamPackets]);

  /** Every frame the pane shows, both tabs alike. */
  const frames = useMemo(() => {
    if (loaded === null) return streamPackets;
    return tail.length === 0 ? loaded.frames : loaded.frames.concat(tail);
  }, [loaded, streamPackets, tail]);

  // Not "whoever sent the first frame": a capture that started mid-connection
  // has no SYN to go on, and a well-known port on one end says far more - and
  // when neither applies, `basis` says the answer is a guess so the window can
  // disclose it rather than colour the conversation on one. The digest decided
  // it from the stream's first frame in the whole capture, which is the better
  // witness; the buffer's first frame is the fallback.
  //
  // Both ends are memoised on their VALUES, not on the summary or the frames:
  // a new object per poll or per flush would re-fold the ladder and reset its
  // window every time one of those arrived.
  const chosen = target === null
    ? null
    : summary !== null
      ? { ...summary.client, basis: 'clientBasis' in summary ? summary.clientBasis : DHCP_BASIS }
      : target.kind === 'dhcp'
        ? { ...clientEnd(frames, target), basis: DHCP_BASIS }
        : clientEnd(frames, target);
  const clientAddress = chosen?.address ?? '';
  const clientPort = chosen?.port ?? 0;
  const clientBasis = chosen?.basis ?? 'first-speaker';
  const client = useMemo<ClientEnd>(
    () => ({ address: clientAddress, port: clientPort, basis: clientBasis }),
    [clientAddress, clientPort, clientBasis],
  );
  const serverAddress = summary?.server.address
    ?? (target === null ? '' : client.address === target.addressA ? target.addressB : target.addressA);
  const serverPort = summary?.server.port
    ?? (target === null ? 0 : client.port === target.portA ? target.portB : target.portA);
  const server = useMemo<Endpoint>(
    () => ({ address: serverAddress, port: serverPort }),
    [serverAddress, serverPort],
  );

  // DNS marks, only for a UDP flow whose digest summary has a tally. The capture's
  // end moves a waiting query to unanswered, so it is a dependency.
  const hasDnsTally = summary !== null && 'kind' in summary && summary.kind === 'udp' && summary.dns !== undefined;
  const notes = useMemo(
    () => (hasDnsTally ? dnsMarks(frames, captureEnd) : undefined),
    [hasDnsTally, frames, captureEnd],
  );

  const targetKind = target === null ? 'tcp' : target.kind;
  const totals = useMemo(() => {
    let toServer = 0;
    let toClient = 0;
    for (const p of frames) {
      if (sideOf(targetKind, p, client) === 'client') toServer += p.length;
      else toClient += p.length;
    }
    return { toServer, toClient };
  }, [frames, client, targetKind]);

  const toggleBand = useCallback((firstId: number) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (!next.delete(firstId)) next.add(firstId);
      return next;
    });
  }, []);
  const openBand = useCallback((firstId: number) => {
    setExpanded((current) => (current.has(firstId) ? current : new Set(current).add(firstId)));
  }, []);

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

  const loading = loaded?.loading ?? null;
  // The state map, the lane pills and the markers are TCP's: a UDP flow has no
  // states and a QUIC connection has phases, shown as the line above the ladder.
  const tcpSummary = summary !== null && !('kind' in summary) ? summary : null;
  const quicSummary = summary !== null && 'kind' in summary && summary.kind === 'quic' ? summary : null;
  const dhcpSummary = summary !== null && 'kind' in summary && summary.kind === 'dhcp' ? summary : null;
  // The noun in the title: a QUIC target is a connection, a DHCP one an exchange, the others streams.
  const noun = target.kind === 'quic' ? 'Connection' : target.kind === 'dhcp' ? 'Exchange' : 'Stream';
  // A DHCP exchange is named by its transaction id as the packet list shows it, in hex.
  const idLabel = target.streamId === undefined ? ''
    : target.kind === 'dhcp' ? ` 0x${(target.streamId >>> 0).toString(16).padStart(8, '0')}` : ` #${target.streamId}`;

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
    const arrow = sideOf(target.kind, p, client) === 'client' ? '-->' : '<--';
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
    const header = `# Follow ${target.kind.toUpperCase()} ${noun.toLowerCase()}`
      + idLabel
      + `  ${endpointText(client, target.kind, 'client')} <-> ${endpointText(server, target.kind)}\n`
      + `# frame\ttime\tdir\tsource\tdestination\tlength\n`;
    return header + frames.map(summaryLine).join('\n') + '\n';
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
      `${target.kind}_${noun.toLowerCase()}_${target.streamId ?? `${target.portA}-${target.portB}`}_frames.txt`,
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
                  Follow {target.kind.toUpperCase()} {noun}
                  {idLabel}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-secondary text-foreground/80">
                  {loading !== null
                    ? `reading ${loading.loaded.toLocaleString()} of ${loading.total.toLocaleString()}${searchedSuffix(loading.searched)}`
                    : `${frames.length.toLocaleString()} ${frames.length === 1 ? 'frame' : 'frames'}`}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                <span className="font-mono">
                  {client.address} <span className="text-muted-foreground">⇄</span> {server.address === ''
                    ? 'server not seen'
                    : <>{server.address}:{portLabel(server.port, target.kind === 'tcp' ? 'tcp' : 'udp', true)}</>}
                </span>
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

        {/* Legend - the dialogue's, whose rows are coloured by direction. The
            ladder colours nothing by direction (its chips are the colour
            rules', ADR 0055 §2), so a key to rose and sky over it would name
            two colours it does not use. */}
        {tab !== 'ladder' && (
          <div className="px-4 py-2 border-b text-xs flex items-center bg-secondary/50 border-border text-foreground/80">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-rose-500" />
                <span className="font-semibold text-rose-400">Client Traffic ({totals.toServer} bytes)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-sky-400" />
                <span className="font-semibold text-sky-400">Server Traffic ({totals.toClient} bytes)</span>
              </div>
            </div>
          </div>
        )}

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
          /*
           * The ladder and, docked beside it, the state map (ADR 0055 §1).
           * A container query rather than a media query decides the dock: the
           * pane's width is what matters, and with the side bar open a 1600px
           * window can hand this pane less than a 1024px one. At 1180px and
           * up the map is always there; below, it can be put away for the
           * ladder's sake, and a slim strip brings it back.
           */
          <>
          {/* A QUIC connection's phases, in the order they were first seen, each
              a button that brings its frame into the ladder through the same
              request the state map's states make. Inferred from the frames the
              capture holds, and the tooltip says so: a Closed is only a
              decrypted CONNECTION_CLOSE, never a guess. It wraps rather than
              scrolling, so at the 1024 minimum window nothing leaves the pane. */}
          {loaded !== null && quicSummary !== null && quicSummary.phases.length > 0 && (
            <PhaseLine
              label="QUIC phases"
              steps={quicSummary.phases.map((step) => ({
                key: `${step.phase}:${step.side}`, text: PHASE_LABEL[step.phase],
                side: step.side, frameId: step.frameId, time: step.time,
              }))}
              onPick={pickState}
            />
          )}
          {/* A DHCP exchange's messages, in the order each was first seen, as
              the same line: the message names are the option 53 type's own. */}
          {loaded !== null && dhcpSummary !== null && dhcpSummary.phases.length > 0 && (
            <PhaseLine
              label="DHCP phases"
              steps={dhcpSummary.phases.map((step) => ({
                key: `${step.message}:${step.side}`, text: step.message,
                side: step.side, frameId: step.frameId, time: step.time,
              }))}
              onPick={pickState}
            />
          )}
          {/* A TCP stream's TLS phases, between the state map's dock and the
              ladder: the same line, read from the digest's TLS summary. */}
          {loaded !== null && tcpSummary !== null && tls != null && tls.phases.length > 0 && (
            <PhaseLine
              label="TLS phases"
              steps={tls.phases.map((step) => ({
                key: `${step.phase}:${step.side}`,
                text: step.phase === 'alert' ? `alert: ${step.alertName ?? 'Unknown'}` : step.phase,
                side: step.side, frameId: step.frameId, time: step.time,
              }))}
              onPick={pickState}
            />
          )}
          <div className="flex-1 min-h-0 flex @container">
            <LadderView
              frames={frames}
              loading={loading}
              client={client}
              server={server}
              // The summary goes with the frames it describes, and only those:
              // over the buffer's frames its first id would read as a ring floor
              // and its steps would land on rows the buffer happens to hold.
              summary={loaded !== null ? tcpSummary : null}
              kind={target.kind}
              colorEngine={colorEngine}
              packetTheme={packetTheme}
              selectedId={selectedId}
              onSelectFrame={onSelectFrame}
              highlightFrameId={hoverFrameId}
              onHoverFrame={setHoverFrameId}
              scrollTo={scrollTo}
              expanded={expanded}
              onToggleBand={toggleBand}
              onOpenBand={openBand}
              notes={notes}
            />
            {loaded !== null && tcpSummary !== null && (
              <>
                <aside
                  className={`${mapOpen ? 'flex' : 'hidden @min-[1180px]:flex'} w-[19.5rem] shrink-0 min-h-0 flex-col
                    overflow-y-auto custom-scrollbar border-l border-border bg-card`}
                  aria-label="TCP state map"
                >
                  <TcpStateMap
                    summary={tcpSummary}
                    hoverFrameId={hoverFrameId}
                    onPickState={pickState}
                    onCollapse={() => setMapOpen(false)}
                  />
                </aside>
                {!mapOpen && (
                  <button
                    type="button"
                    onClick={() => setMapOpen(true)}
                    aria-label="Show the state map"
                    title="Show the state map"
                    className="@min-[1180px]:hidden w-7 shrink-0 flex items-start justify-center pt-2 border-l border-border
                      text-muted-foreground hover:text-foreground hover:bg-accent active:opacity-70"
                  >
                    <PanelRightOpen className="w-4 h-4" />
                  </button>
                )}
              </>
            )}
          </div>
          </>
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
            frames.length, scrollTop, viewportHeight, ROW_HEIGHT, OVERSCAN,
          );
          return (
            <div
              ref={viewportRef}
              onScroll={onScroll}
              className="flex-1 overflow-y-auto font-mono text-xs custom-scrollbar"
            >
              {frames.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  {loading !== null
                    ? `Reading ${loading.loaded.toLocaleString()} of ${loading.total.toLocaleString()} frames${searchedSuffix(loading.searched)}`
                    : summary !== null
                      ? 'No frames on this stream.'
                      : 'No frames on this stream are in the buffer.'}
                </div>
              ) : (
                <>
                  <div style={{ height: view.topSpacerHeight }} />
                  {frames.slice(view.startIndex, view.endIndex).map((p) => {
                    const isClient = sideOf(target.kind, p, client) === 'client';
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
          <span className="text-muted-foreground">
            {frames.length.toLocaleString()} {frames.length === 1 ? 'packet' : 'packets'} · {(totals.toServer + totals.toClient).toLocaleString()} {totals.toServer + totals.toClient === 1 ? 'byte' : 'bytes'} exchanged
          </span>
        </div>
      </>
    </div>
  );
};
