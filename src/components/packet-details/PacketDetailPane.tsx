import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { clearHoveredByte, publishHoveredByte } from '../../services/hoveredByte';
import type { PacketDetailState } from '../../lib/usePacketDetail';
import { targetForPacket, type StreamTarget } from '../../services/followStream';
import { Packet, Capabilities } from '../../types/packet';
import { ColorRulesEngine } from '../../services/colorRules';
import { loadPreference, useDebouncedPreference } from '../../services/preferences';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { useSplitRatio } from '../../lib/useSplitRatio';
import { useEscapeLayer } from '../../hooks/useEscapeLayer';
import { FrameFieldTable } from './FrameFieldTable';
import { FrameMetaRail } from './FrameMetaRail';
import { FrameNumberBox } from './FrameNumberBox';
import { LayerRail } from './LayerRail';
import { HexDumpView } from './HexDumpView';
import { hasBytes } from '../../services/packetBytes';
import { HexCopyMenu } from './HexViewer';
import { expertItemsFor } from '../../services/expertInfo';
import {
  buildFrameSummary,
  collectRelatedFrames,
  findPacketIndexById,
} from './packetDetailModel';
import { ChevronLeft, ChevronRight, ListTree } from 'lucide-react';
import { MICRO_LABEL, TITLE } from '../common/typography';

const DETAIL_LAYOUT_KEY = 'inwire.packetDetailLayout';

/**
 * Fields keep slightly more than half.
 *
 * Matches what the old fixed 560px dump column worked out to once the rail has
 * taken its 17rem, so a user who never touches the divider sees the proportion
 * they are used to.
 */
const DEFAULT_SPLIT = 0.57;

/**
 * The narrowest the field table may be dragged.
 *
 * Higher than a "stop it vanishing" floor would be, because the table stops
 * being readable long before it stops being visible. It is a three-column grid
 * - name, value, byte range - whose name column alone reaches 327px on the
 * Frame layer.
 *
 * Measured against real frames rather than guessed. At 500px the values wrap
 * four lines deep - `Globally u / nique addr / ess (facto / ry defaul / t)` -
 * which is present but useless, and a full interface description
 * ("Ethernet 2 (Intel(R) Ethernet Controller (3) I225-V #2)", ~363px of mono
 * at 11px) still cannot sit beside its name. 680px is where it can.
 */
const MIN_FIELDS_PX = 680;

/**
 * The narrowest the dump may be dragged, and the reason the two floors differ.
 *
 * Measured, not guessed: a 16-byte row is 524px of content - a 40px offset, a
 * 320px hex block and a 136px ASCII gutter - plus the dump's own 24px of
 * padding. Anything narrower clips the ASCII gutter off the right edge, which
 * is the half of a hex dump people actually read. 16 is the fewest bytes a row
 * ever carries, so this floor holds at every row width.
 */
const MIN_HEX_PX = 548;

/**
 * The drag handle's own width, which both panes have to be measured around.
 *
 * Without it the floors are quietly off by this much: the ratio splits the
 * container, but the handle is subtracted from the SECOND pane afterwards, so
 * a dump clamped to its 548px floor was drawn at 542px and clipped by exactly
 * the width of the divider.
 */
const HANDLE_PX = 6;

/**
 * Below this measured CANVAS width the fields and the dump stack into one
 * scrolling document; at or above it they sit side by side.
 *
 * Measured off the canvas rather than the window, which is the whole reason
 * this is no longer a media query: the rail's presence changes how much room
 * the body actually has by 17rem, and a window-width query cannot see that.
 */
const TWO_COLUMN_MIN_PX = MIN_FIELDS_PX + MIN_HEX_PX + HANDLE_PX;

/**
 * A consequence worth stating: this comes to 1234px of CANVAS, so a laptop-
 * width window showing the full rail stacks rather than splitting, and
 * collapsing the rail is the way back to two columns. That is the honest
 * answer rather than a limitation - the alternative is two columns that are
 * both too narrow to read, which is what the fixed 560px dump column used to
 * do at exactly this size.
 */

/** Full rail fits beside a usable canvas. */
const RAIL_FULL_QUERY = '(min-width: 1280px)';
/** Enough room for the icon strip; below this the rail leaves the row entirely. */
const RAIL_STRIP_QUERY = '(min-width: 1024px)';

interface DetailLayout {
  splitRatio: number;
  railCollapsed: boolean;
}

/**
 * A stored layout is untrusted input - hand-edited, or left by an older build -
 * so a bad one produces defaults rather than a modal with a divider off-screen.
 */
function normalizeDetailLayout(raw: unknown): DetailLayout | null {
  if (!raw || typeof raw !== 'object') return null;
  const value = raw as Record<string, unknown>;
  const ratio =
    typeof value.splitRatio === 'number' && Number.isFinite(value.splitRatio)
      ? Math.max(0.15, Math.min(value.splitRatio, 0.85))
      : DEFAULT_SPLIT;
  return { splitRatio: ratio, railCollapsed: value.railCollapsed === true };
}

/**
 * How many bytes a row of the dump carries at a given pane width.
 *
 * Snapped to three values rather than computed continuously: a row count that
 * changed with every pixel would reflow the whole dump while the divider is
 * being dragged, which reads as jitter rather than as resizing. Widths are the
 * point at which 24 and 32 bytes fit without the ASCII gutter clipping.
 */
function bytesPerRowFor(paneWidthPx: number): number {
  if (paneWidthPx >= 990) return 32;
  if (paneWidthPx >= 760) return 24;
  return 16;
}

/** Which shape the meta rail is in right now. */
type RailMode = 'full' | 'icons' | 'hidden';

interface PacketDetailPaneProps {
  /** The whole capture buffer. Frames are addressed by number against this. */
  packets: Packet[];
  /**
   * The frame being read, with its tree and bytes filled in, or null when the
   * selection is empty.
   *
   * Handed in rather than fetched here, which is the one substantive change the
   * move out of a modal forced. The modal was mounted only while it was open,
   * so its own `usePacketDetail` was the only one running; a pane sits beside a
   * packet list that is hidden rather than unmounted, and that list's own panes
   * are already asking for exactly this frame. Two hooks on one frame would be
   * two replay requests for one tree.
   */
  packet: Packet | null;
  /** Whether the tree and bytes are here, coming, or gone (`usePacketDetail`). */
  detailState: PacketDetailState;
  /** Frames the current display filter admits, for the filtered-out notice. */
  filteredPackets: Packet[];
  onShowFrame: (frameNumber: number) => void;
  onFollowStream: (target: StreamTarget) => void;
  colorEngine: ColorRulesEngine;
  permissions: Capabilities;
}

/**
 * The Frame Detail view: one packet, in full.
 *
 * Organised by HOW EACH PART IS USED rather than by what it is, which is the
 * distinction the previous layout missed. It stacked six full-width bands -
 * header, lookup errors, frame facts, chips, alerts, layer rail - above the
 * body, all at the same visual weight, so nothing told the eye where to start
 * and the body was whatever vertical space the bands happened to leave. Two of
 * those bands wrapped, so that leftover changed with the window width and with
 * how long the values happened to be.
 *
 * Three regions, each with a permanent home:
 *
 *   - THE META RAIL, at a fixed width down the left. Everything glanced at and
 *     never scrolled: the frame's timing, its own facts, what is wrong with it,
 *     and every way to leave it for another frame. Grouped, because eight flat
 *     items in a row have no hierarchy.
 *   - THE CANVAS, taking all the rest. Alerts across the top (capped, so a
 *     frame with several cannot starve the body), the layer band under them as
 *     a scale drawing of the frame, then FIELDS AND BYTES SIDE BY SIDE with a
 *     divider the user drags. Each has its own scroll. They stack into one
 *     document when the canvas is genuinely too narrow for two columns.
 *   - THE FOOTER, one bar under both, for the byte under the cursor and the
 *     position in the buffer.
 *
 * ## What changed when it stopped being a modal
 *
 * It was a `fixed inset-0` backdrop with a 92vh panel inside it, opened by a
 * double-click on a row and dismissed with Escape or an X. Four things follow
 * from it being a view instead, and each of them is a deletion:
 *
 *  - **No backdrop, no panel, no motion.** The pane fills the view slot the way
 *    Statistics and the Routing Map do. `modalBackdropMotion` and
 *    `modalPanelMotion` are gone with it.
 *  - **No close button, and no Escape of its own.** `App` already returns any
 *    non-Packets view to Packets on Escape, in the bubble phase, last in the
 *    chain. This still listens - but only for the one thing that is genuinely
 *    inside it, the summoned meta rail, which it claims with `stopPropagation`
 *    so the view does not also change underneath it. That is the layering rule
 *    every other popover in this app follows.
 *  - **No `obscured` prop.** Nothing opens on top of a pane.
 *  - **No frame of its own.** The selection is the app's, so leaving for the
 *    packet list and coming back lands on the same frame, and stepping with the
 *    arrows here moves the list's selection too. The modal kept a separate
 *    `detailPacketId`, which is why closing it used to drop you somewhere else.
 *
 * ## The empty state is the way in
 *
 * A view with a rail button has to be openable with nothing selected, and the
 * answer is the frame-number box - which already existed in the meta rail, as
 * one of several ways to leave a frame. Given nothing to show, the pane puts
 * that box in the middle of an empty canvas instead, which is the whole of
 * "go to packet": a frame number, and nothing else to type.
 *
 * Only HexDumpView, ByteInspector and AnomalyBanners are shared with the
 * workspace's bottom panes, because those are content rather than layout.
 */
/** This view's dump in the hovered-byte store; `HexViewer` is the other. */
const HOVER_SOURCE = 'frame-detail-hex' as const;

export const PacketDetailPane: React.FC<PacketDetailPaneProps> = ({
  packets,
  packet,
  detailState,
  filteredPackets,
  onShowFrame,
  onFollowStream,
  colorEngine,
  permissions,
}) => {
  /**
   * This pane's own byte highlight.
   *
   * Deliberately not shared with App's `activeByteRange`: hovering a field in
   * here should light up bytes in THIS dump and leave the packet list's bottom
   * panes - which are hidden rather than unmounted - showing whatever they were.
   */
  const [activeByteRange, setActiveByteRange] = useState<[number, number] | null>(null);
  /**
   * Owned here rather than inside the dump, so the byte breakdown can live in
   * a bar spanning the full width beneath both columns.
   */
  const [hoveredByteIndex, setHoveredByteIndex] = useState<number | null>(null);

  // This view's dump is the store's second publisher; the Packets view's
  // `HexViewer` is the first. Both can be mounted at once - the packets section
  // stays mounted behind `display: none` - so every clear names its source and
  // the store ignores one from a pane that does not currently own the value.
  const publishByte = useCallback((byteIdx: number | null) => {
    if (!packet || byteIdx === null || byteIdx >= packet.rawBytes.length) {
      clearHoveredByte(HOVER_SOURCE);
      return;
    }
    publishHoveredByte({
      source: HOVER_SOURCE,
      index: byteIdx,
      value: packet.rawBytes[byteIdx],
      frameId: packet.id,
    });
  }, [packet]);

  // The frame changing under a stationary pointer, and this view unmounting.
  useEffect(() => { clearHoveredByte(HOVER_SOURCE); }, [packet?.id]);
  useEffect(() => () => clearHoveredByte(HOVER_SOURCE), []);
  /**
   * The layer isolated in the rail, or null for the whole frame.
   *
   * Reset whenever the frame changes: layer 3 of one packet has nothing to do
   * with layer 3 of the next.
   */
  const [selectedLayer, setSelectedLayer] = useState<number | null>(null);

  const stored = useMemo(
    () =>
      loadPreference(DETAIL_LAYOUT_KEY, normalizeDetailLayout, {
        splitRatio: DEFAULT_SPLIT,
        railCollapsed: false,
      }),
    [],
  );

  /** The user's own choice to shut the rail, which outlives the window. */
  const [railCollapsed, setRailCollapsed] = useState(stored.railCollapsed);
  /** The rail summoned over the canvas while it is only an icon strip. */
  const [railOverlay, setRailOverlay] = useState(false);
  /** The facts disclosure, for windows too narrow to hold a rail at all. */
  const [narrowFactsOpen, setNarrowFactsOpen] = useState(false);

  /**
   * The fields' scroller - and, when the canvas is too narrow for two columns,
   * the scroller for the dump underneath them too. The dump virtualizes either
   * way; stacked it works out what is on screen from this element rather than
   * from a scrollbar of its own. See HexDumpView's scrollRef.
   */
  const bodyScrollRef = useRef<HTMLDivElement | null>(null);

  /**
   * The split container, measured for two things at once: whether there is room
   * for two columns, and how wide the dump's pane ends up - which is what sets
   * the bytes per row.
   */
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const [bodyEl, setBodyEl] = useState<HTMLDivElement | null>(null);
  const [bodyWidth, setBodyWidth] = useState(0);

  // Measured in the ref callback as well as by the observer, because the
  // callback runs during commit - before paint - and the observer's first
  // delivery does not. Without it the window opens stacked for one frame and
  // then snaps into two columns.
  const attachBody = useCallback((el: HTMLDivElement | null) => {
    bodyRef.current = el;
    setBodyEl(el);
    if (el) setBodyWidth(el.getBoundingClientRect().width);
  }, []);

  useEffect(() => {
    if (!bodyEl) return;
    const observer = new ResizeObserver(entries => {
      for (const entry of entries) setBodyWidth(entry.contentRect.width);
    });
    observer.observe(bodyEl);
    return () => observer.disconnect();
  }, [bodyEl]);

  const railFullFits = useMediaQuery(RAIL_FULL_QUERY);
  const railStripFits = useMediaQuery(RAIL_STRIP_QUERY);
  const railMode: RailMode = !railStripFits
    ? 'hidden'
    : railFullFits && !railCollapsed
      ? 'full'
      : 'icons';

  // Only the icon strip can summon the overlay, so leaving that mode puts it
  // away rather than leaving it armed to reappear when the mode comes back.
  useEffect(() => {
    if (railMode !== 'icons') setRailOverlay(false);
  }, [railMode]);

  const split = useSplitRatio(bodyRef, {
    initial: stored.splitRatio,
    minFirstPx: MIN_FIELDS_PX,
    // The handle sits inside the container but outside the ratio, and comes
    // out of the dump's side of it.
    minSecondPx: MIN_HEX_PX + HANDLE_PX,
  });

  useDebouncedPreference(
    DETAIL_LAYOUT_KEY,
    useMemo(
      () => ({ splitRatio: split.ratio, railCollapsed }),
      [split.ratio, railCollapsed],
    ),
  );

  const twoColumn = bodyWidth >= TWO_COLUMN_MIN_PX;
  // Not `split.ratio` directly: a ratio stored by a wider session, or one the
  // user has since shrunk the window under, would otherwise draw a pane
  // narrower than it can be dragged back to.
  const splitRatio = split.clampTo(bodyWidth);
  const hexPaneWidth = twoColumn ? bodyWidth * (1 - splitRatio) - HANDLE_PX : bodyWidth;
  const bytesPerRow = bytesPerRowFor(hexPaneWidth);

  // Lookup by id on demand. Nothing here scans the buffer, which matters
  // because `packets` changes identity on every 100ms flush during capture.
  // -1 for no selection and -1 for a frame the buffer has since dropped are the
  // same answer, and both mean the same thing to everything below: there is no
  // previous or next frame to step to.
  const packetId = packet?.id ?? null;
  const index = useMemo(
    () => (packetId === null ? -1 : findPacketIndexById(packets, packetId)),
    [packets, packetId],
  );

  const summary = useMemo(() => (packet ? buildFrameSummary(packet) : null), [packet]);
  const related = useMemo(() => (packet ? collectRelatedFrames(packet) : []), [packet]);
  const colorRuleName = useMemo(
    () => (packet ? colorEngine.getMatchedRuleName(packet) : undefined),
    [packet, colorEngine],
  );

  // Asks the same sorted-order question the buffer lookup does rather than
  // calling .some(), since the filtered set can also be large.
  const hiddenByFilter = useMemo(
    () => (packet ? findPacketIndexById(filteredPackets, packet.id) === -1 : false),
    [filteredPackets, packet],
  );

  /**
   * Everything that is about the frame being looked at rather than the window
   * itself: the byte highlight, the hovered byte, and the isolated layer.
   * Layer 3 of one packet has nothing to do with layer 3 of the next, so none
   * of it survives a frame change.
   */
  const resetFrameView = () => {
    setActiveByteRange(null);
    setHoveredByteIndex(null);
    setSelectedLayer(null);
  };

  // The layers the field table shows: all of them, or just the isolated one.
  const visibleLayers = useMemo(() => {
    const all = (packet?.layers ?? []).map((layer, index) => ({ layer, index }));
    return selectedLayer === null ? all : all.filter(l => l.index === selectedLayer);
  }, [packet, selectedLayer]);

  const goToIndex = (nextIndex: number) => {
    if (nextIndex < 0 || nextIndex >= packets.length) return;
    onShowFrame(packets[nextIndex].id);
    resetFrameView();
  };

  const showFrame = (frameNumber: number) => {
    onShowFrame(frameNumber);
    resetFrameView();
    // Navigating from the summoned rail is the end of what it was summoned for.
    setRailOverlay(false);
  };

  const hasPrev = index > 0;
  const hasNext = index !== -1 && index < packets.length - 1;

  /**
   * The rail's toggle means something different in each of its three shapes:
   * shut the column, re-open it, or - when there is no room for a column at
   * all - summon it over the canvas and put it away again.
   */
  const toggleRail = () => {
    if (railMode === 'full') {
      setRailCollapsed(true);
      return;
    }
    if (railOverlay) {
      setRailOverlay(false);
      return;
    }
    if (railFullFits) setRailCollapsed(false);
    else setRailOverlay(true);
  };

  /**
   * The arrows step frames, and Escape is claimed only for the summoned rail.
   *
   * ## Why Escape is still here at all
   *
   * It used to close this window. Nothing closes now - `App` sends any
   * non-Packets view back to Packets on Escape, in the BUBBLE phase, explicitly
   * last in the chain. So the only Escape this pane has any business taking is
   * the one belonging to the thing it has open over itself: the meta rail
   * summoned across the canvas on a window too narrow to keep it in flow.
   * Capture phase and `stopPropagation`, which is the same contract the filter
   * presets dropdown and the geo overlay keep - the innermost open thing gets
   * the key, and the view does not change out from under it.
   *
   * ## Why the arrows do not collide
   *
   * `useKeyboardNavigation` binds Up and Down, to move the packet list's
   * selection. This binds Left and Right. They step the SAME selection, because
   * the frame shown here is the app's selected frame - so the two handlers
   * agree rather than needing to be kept apart, which is what the modal's
   * `detailPacketId` gate existed to do.
   *
   * The handler reads its moving parts through a ref rather than taking them
   * as dependencies. `packets` changes identity on every 100ms flush during
   * capture, so a dependency on it would tear down and re-register this
   * listener ten times a second for the life of the view.
   */
  const navRef = useRef({ index, packets, onShowFrame });
  navRef.current = { index, packets, onShowFrame };

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const nav = navRef.current;
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
      if (typing) return;
      const step = e.key === 'ArrowLeft' ? -1 : e.key === 'ArrowRight' ? 1 : 0;
      if (step === 0) return;
      // -1 is "no frame on screen", and there is nothing to step from.
      if (nav.index === -1) return;
      e.preventDefault();
      const target = nav.index + step;
      if (target < 0 || target >= nav.packets.length) return;
      nav.onShowFrame(nav.packets[target].id);
      // The state setters are stable, so this stays out of the dependency list
      // and the listener is still registered exactly once.
      setActiveByteRange(null);
      setHoveredByteIndex(null);
      setSelectedLayer(null);
    };
    window.addEventListener('keydown', onKeyDown, true);
    return () => window.removeEventListener('keydown', onKeyDown, true);
  }, []);

  /**
   * A new frame starts at the top of its fields.
   *
   * Explicit, because it used to happen by accident: the dump reset the
   * scroller it virtualized against on every frame change, and while that was
   * the shared body scroller it took the fields back to the top too. Given a
   * column of its own the dump resets only its own scrollbar, which left the
   * fields parked wherever the previous frame had been read to - so frame 65
   * opened halfway down Ethernet.
   */
  useEffect(() => {
    if (bodyScrollRef.current) bodyScrollRef.current.scrollTop = 0;
  }, [packetId]);

  const frameBox = <FrameNumberBox packets={packets} onShowFrame={showFrame} />;

  /**
   * Everything the rail needs except the three things that differ between its
   * shapes - how wide it is, whether it is collapsed, and what its toggle does.
   * The rail appears in two places (beside the canvas, and as a full-width
   * disclosure on a window too narrow for a column) and this is what keeps
   * those from drifting apart.
   */
  const railContent = summary && {
    summary,
    colorRuleName,
    related,
    // The five-tuple, not just the TCP index: a UDP or QUIC frame has no
    // index and could not be followed at all before this.
    streamTarget: packet ? targetForPacket(packet) : null,
    hiddenByFilter,
    // The findings live in the rail's Analysis group. They had a bar of their
    // own across the canvas, a full-width strip for what is usually one line
    // - and the rail's Analysis group already answered "what is wrong with
    // this frame", with the TCP flags that raise most of them.
    expert: packet ? expertItemsFor(packet) : [],
    frameBox,
    onFollowStream,
    onShowFrame: showFrame,
  };

  // The overlay is a layer on the window's Escape stack, so a surface opened
  // over it closes first. Up only while it is drawn: `railOverlay` outlives
  // the strip when the pane widens, and a layer with nothing on screen would
  // eat the Escape that returns the view to Packets.
  const overlayShown = railMode === 'icons' && railOverlay && !!railContent;
  useEscapeLayer(overlayShown, () => setRailOverlay(false));

  /**
   * The dump and its heading, built once and placed in whichever position the
   * current layout calls for - its own column beside the fields, or the tail of
   * the fields' scroller.
   *
   * The scroller it virtualizes against differs between the two: in a column of
   * its own it owns the scrollbar (scrollRef omitted), stacked it must read the
   * shared document's scroll position instead. Getting that wrong renders no
   * rows at all rather than failing loudly, so the two are tied together here
   * rather than at the two call sites.
   */
  const dumpBlock = packet ? (
    <>
      <div
        className={`flex items-baseline justify-between gap-3 px-3 py-1.5 bg-card/95 backdrop-blur-sm border-l-2 border-primary ${
          twoColumn ? 'shrink-0 border-b border-b-border' : 'sticky top-0 z-20 mt-2'
        }`}
      >
        <span className="font-bold text-foreground text-xs">
          Raw bytes
          <span className="ml-2 font-normal text-muted-foreground text-[11px] font-mono">
            {hasBytes(packet)
              ? `${packet.rawBytes.length.toLocaleString()} captured`
              : detailState === 'unavailable' ? 'not stored' : 'reading…'}
          </span>
        </span>
        {hasBytes(packet) && <HexCopyMenu packet={packet} />}
      </div>

      {/* Three reasons there may be no dump, and they are different answers.
          Policy is a refusal, a read in flight resolves, and a frame the store
          can no longer supply never will - so none of them may render as the
          empty pane that means "this frame carried nothing". */}
      {!permissions.canViewPayloads ? (
        <div className="mx-3 my-3 p-2 rounded bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400 text-[11px]">
          Auditor / Guest role active: payload inspection is sanitized by policy.
        </div>
      ) : !hasBytes(packet) ? (
        <div className="mx-3 my-3 p-2 rounded bg-muted/40 border border-border text-muted-foreground text-[11px] leading-relaxed">
          {detailState === 'unavailable'
            ? 'This capture outgrew its storage limit, so the oldest frames’ bytes were dropped. Everything above is what is kept for this frame.'
            : 'Fetching this frame’s bytes from the stored capture…'}
        </div>
      ) : (
        <HexDumpView
          packet={packet}
          activeByteRange={activeByteRange}
          hoveredByteIndex={hoveredByteIndex}
          bytesPerRow={bytesPerRow}
          onHoverByte={byteIdx => {
            setHoveredByteIndex(byteIdx);
            setActiveByteRange(byteIdx === null ? null : [byteIdx, byteIdx]);
            publishByte(byteIdx);
          }}
          scrollRef={twoColumn ? undefined : bodyScrollRef}
          // HexDumpView adds its own overflow-y-auto whenever scrollRef is
          // omitted, so the column only has to give it the height to scroll in.
          className={twoColumn ? 'flex-1 min-h-0 px-3 py-2' : 'px-3 pb-4'}
        />
      )}
    </>
  ) : null;

  return (
    // The view slot, the same shape Statistics and the Routing Map fill. No
    // backdrop and no panel: `bg-card` against the workspace's `--background`
    // is the pane's only edge, and `<main>`'s own border draws the corner it
    // sits in - square, like every corner this app draws.
    <section className="flex-1 min-w-0 flex flex-col overflow-hidden bg-card text-card-foreground">
      {/* Identity and frame-to-frame navigation. Nothing else - the frame box
          lives in the meta rail, where it sits with the other ways of leaving
          this frame, and where it does not squeeze the title. There is no close
          button: Escape returns to Packets, which is what every other view
          does, and the rail is how you leave for a different one. */}
      <div className="h-9 shrink-0 px-4 border-b border-border flex items-center gap-4">
        <div className="flex items-center gap-2 min-w-0">
          <ListTree className="w-4 h-4 shrink-0 text-primary" />
          <span className={`${TITLE} shrink-0`}>
            Frame
          </span>
          <span className="text-xs font-mono font-bold text-primary shrink-0">
            {packet ? packet.id.toLocaleString() : '—'}
          </span>
          {packet && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/20 text-primary font-mono whitespace-nowrap shrink-0">
              {packet.protocolLabel ?? packet.protocol}
            </span>
          )}
          <span className="text-[11px] text-muted-foreground font-mono truncate min-w-0">
            {packet ? packet.info : 'No frame selected'}
          </span>
        </div>

        <div className="flex-1" />

        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={() => goToIndex(index - 1)}
            disabled={!hasPrev}
            className={`p-1 rounded transition-colors ${
              hasPrev ? 'hover:bg-accent text-foreground cursor-pointer' : 'opacity-30 cursor-not-allowed text-muted-foreground'
            }`}
            title="Previous frame (←)"
            aria-label="Previous frame"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <button
            onClick={() => goToIndex(index + 1)}
            disabled={!hasNext}
            className={`p-1 rounded transition-colors ${
              hasNext ? 'hover:bg-accent text-foreground cursor-pointer' : 'opacity-30 cursor-not-allowed text-muted-foreground'
            }`}
            title="Next frame (→)"
            aria-label="Next frame"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* **The empty state IS the go-to-packet feature.**

          A view with a rail button can be opened with nothing selected, so this
          is not an edge case to apologise for - it is the view's front door, and
          the only thing it asks for is a frame number. `FrameNumberBox` is the
          same control the meta rail carries, and it reports its three refusals -
          not a number, out of range, not in the buffer - inline under the input
          rather than as a band that pushes this whole block down and back up
          again while somebody is typing. */}
      {!packet || !summary ? (
        <div className="flex-1 flex items-center justify-center p-8">
          <div className="flex flex-col items-center gap-4 text-center">
            <ListTree className="w-8 h-8 text-muted-foreground/60" />
            <div className="flex flex-col items-center gap-1">
              <span className={MICRO_LABEL}>
                No frame selected
              </span>
              <span className="text-[11px] text-muted-foreground/70">
                Go to a frame by number, or pick a row in the packet list.
              </span>
            </div>
            {frameBox}
          </div>
        </div>
      ) : (
          <>
            {/* Too narrow for a rail of any kind. The facts fold into one line
                that opens into the same grouped list, rather than being
                dropped - they are the reason half of this window exists. */}
            {railMode === 'hidden' && (
              <>
                <button
                  onClick={() => setNarrowFactsOpen(open => !open)}
                  className="shrink-0 flex items-center gap-2 px-5 py-1.5 border-b border-border bg-secondary/30 text-[10px] font-mono text-muted-foreground hover:bg-accent/40 cursor-pointer"
                  aria-expanded={narrowFactsOpen}
                >
                  <ChevronRight
                    className={`w-3 h-3 shrink-0 transition-transform ${narrowFactsOpen ? 'rotate-90' : ''}`}
                  />
                  <span className="truncate">
                    {summary.localTime} · {summary.frameLength} B · {summary.interfaceName}
                  </span>
                </button>
                {narrowFactsOpen && railContent && (
                  <div className="shrink-0 max-h-[45%] overflow-y-auto custom-scrollbar border-b border-border">
                    <FrameMetaRail
                      {...railContent}
                      collapsed={false}
                      onToggleCollapse={() => setNarrowFactsOpen(false)}
                      className="w-full bg-secondary/30"
                    />
                  </div>
                )}
              </>
            )}

            <div className="flex-1 min-h-0 flex relative">
              {/* The in-flow rail: a column when there is room for one, an
                  icon strip when there is not. The strip STAYS in flow while
                  the overlay is up - taking it out would widen the canvas by
                  17rem underneath the thing covering it, and reflow the dump
                  behind the user's back. */}
              {railMode !== 'hidden' && railContent && (
                <FrameMetaRail
                  {...railContent}
                  collapsed={railMode === 'icons'}
                  onToggleCollapse={toggleRail}
                  className={
                    railMode === 'full'
                      ? 'w-[17rem] shrink-0 border-r border-border bg-secondary/30'
                      : 'w-12 shrink-0 border-r border-border bg-secondary/30'
                  }
                />
              )}

              {/* Summoned over the canvas, with a scrim that dismisses it the
                  way clicking off a menu does. Mounted only while it is up,
                  and only in the one mode that can summon it - a window
                  narrowed past the icon strip while the overlay was open left
                  it floating beside the disclosure line that replaces it. */}
              {railMode === 'icons' && railOverlay && railContent && (
                <>
                  <div
                    className="absolute inset-0 z-10 bg-black/20"
                    onClick={() => setRailOverlay(false)}
                    aria-hidden
                  />
                  <FrameMetaRail
                    {...railContent}
                    collapsed={false}
                    onToggleCollapse={toggleRail}
                    // `bg-card`, not the in-flow tint: floating over the field
                    // table, a 30% surface lets the table read through it.
                    className="absolute inset-y-0 left-12 z-20 w-[17rem] border-r border-border bg-card shadow-2xl"
                  />
                </>
              )}

              <div className="flex-1 min-w-0 flex flex-col">
                {/* The protocol stack as a band across the canvas: a scale
                    drawing of the frame, and the way any layer is isolated. */}
                <div className="border-b border-border bg-secondary/20 shrink-0">
                  <LayerRail
                    layers={packet.layers}
                    frameLength={Math.max(packet.rawBytes.length, packet.length)}
                    selectedIndex={selectedLayer}
                    onSelect={setSelectedLayer}
                    onHoverRange={setActiveByteRange}
                    activeByteRange={activeByteRange}
                  />
                </div>

                {/* Fields and bytes, side by side with a divider the user
                    drags, or stacked into one scroll when the canvas cannot
                    carry two columns. */}
                <div
                  ref={attachBody}
                  className={`flex-1 min-h-0 flex ${twoColumn ? 'flex-row' : 'flex-col'}`}
                >
                  <div
                    ref={bodyScrollRef}
                    // Sized by the divider in two columns, and the flexible
                    // half of the document when stacked - `flex-1` there is
                    // what gives it the height to scroll in at all.
                    className={`min-h-0 min-w-0 overflow-y-auto custom-scrollbar ${
                      twoColumn ? 'shrink-0' : 'flex-1'
                    }`}
                    style={twoColumn ? { width: `${splitRatio * 100}%` } : undefined}
                  >
                    <FrameFieldTable
                      packet={packet}
                      layers={visibleLayers}
                      activeByteRange={activeByteRange}
                      // The tree clears the bar's byte and never sets one.
                      // It has a RANGE, not a value, and the first bottom bar
                      // answering "this byte" for a tree hover is the bug this
                      // store exists to make unrepresentable.
                      onHoverByteRange={range => {
                        setActiveByteRange(range);
                        setHoveredByteIndex(null);
                        clearHoveredByte(HOVER_SOURCE);
                      }}
                      onSelectFrame={showFrame}
                      className="py-3"
                    />

                    {/* Stacked only. In two columns the dump lives in its own
                        column beside this scroller, not at the end of it. */}
                    {!twoColumn && dumpBlock}
                  </div>

                  {twoColumn && (
                    <>
                      {/* Doubles as the border between the panes. */}
                      <div
                        className="w-1.5 h-full shrink-0 cursor-col-resize bg-muted hover:bg-handle-hover transition-colors"
                        title="Drag to resize — double-click to reset"
                        onMouseDown={split.onHandleMouseDown}
                        onDoubleClick={split.reset}
                      />

                      {/* No overflow of its own: MIN_HEX_PX guarantees a
                          16-byte row fits, and setting overflow on one axis
                          would silently turn the other from `visible` into a
                          second vertical scrollbar beside the dump's own. */}
                      <div className="flex-1 min-w-0 flex flex-col min-h-0">
                        {dumpBlock}
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* **No footer.** This pane had one, and by the end all it carried
                was "Frame N of M" - a full-width strip for a position the
                header already implies and nobody read. Removed at the owner's
                request. The byte inspector that used to share it lives in the
                application status bar (`components/status/StatusBar.tsx`). */}
          </>
        )}
    </section>
  );
};
