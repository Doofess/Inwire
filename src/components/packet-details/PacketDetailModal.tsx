import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { usePacketDetail } from '../../lib/usePacketDetail';
import { motion } from 'motion/react';
import { targetForPacket, type StreamTarget } from '../../services/followStream';
import { Packet, Capabilities } from '../../types/packet';
import { ColorRulesEngine } from '../../services/colorRules';
import type { PacketTheme } from '../../services/packetThemes';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';
import { loadPreference, useDebouncedPreference } from '../../services/preferences';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { useSplitRatio } from '../../lib/useSplitRatio';
import { FrameFieldTable } from './FrameFieldTable';
import { FrameMetaRail } from './FrameMetaRail';
import { FrameNumberBox } from './FrameNumberBox';
import { LayerRail } from './LayerRail';
import { ByteInspector, HexDumpView } from './HexDumpView';
import { hasBytes } from '../../services/packetBytes';
import { HexCopyButtons } from './HexViewer';
import { ExpertFindings } from './ExpertFindings';
import { packetAccentStyle } from '../../lib/packetAccent';
import {
  buildFrameSummary,
  collectRelatedFrames,
  findPacketIndexById,
} from './packetDetailModel';
import {
  TbX,
  TbChevronLeft,
  TbChevronRight,
  TbBinaryTree,
} from 'react-icons/tb';

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

interface PacketDetailModalProps {
  /** The whole capture buffer. Frames are addressed by number against this. */
  packets: Packet[];
  /** The frame to show. */
  packetId: number;
  /** Frames the current display filter admits, for the filtered-out notice. */
  filteredPackets: Packet[];
  onClose: () => void;
  onShowFrame: (frameNumber: number) => void;
  onFollowStream: (target: StreamTarget) => void;
  colorEngine: ColorRulesEngine;
  /**
   * The packet palette in force, so this window can label a frame in the colour
   * the list painted its row. Resolved here rather than passed in as a colour
   * because the frame changes under this window's own navigation.
   */
  packetTheme: PacketTheme;
  permissions: Capabilities;
  /**
   * True when another window is open on top of this one.
   *
   * Escape and the arrow keys are registered on `window` in the capture phase,
   * so without this they keep firing underneath whatever is covering them -
   * pressing Escape to dismiss the stream window would close THIS window
   * instead and leave the stream floating over the packet list.
   */
  obscured?: boolean;
}

/**
 * A full-window view of one packet.
 *
 * Organised by HOW EACH PART IS USED rather than by what it is, which is the
 * distinction the previous layout missed. It stacked six full-width bands -
 * header, lookup errors, frame facts, chips, alerts, layer rail - above the
 * body, all at the same visual weight, so nothing told the eye where to start
 * and the body was whatever vertical space the bands happened to leave. Two of
 * those bands wrapped, so that leftover changed with the window width and with
 * how long the values happened to be.
 *
 * Three regions now, each with a permanent home:
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
 * Chrome is now constant-height at every window size - header and footer only -
 * so the window is the same shape every time it opens.
 *
 * Only HexDumpView, ByteInspector and AnomalyBanners are shared with the
 * workspace's bottom panes, because those are content rather than layout.
 */
export const PacketDetailModal: React.FC<PacketDetailModalProps> = ({
  packets,
  packetId,
  filteredPackets,
  onClose,
  onShowFrame,
  onFollowStream,
  colorEngine,
  packetTheme,
  permissions,
  obscured = false,
}) => {
  /**
   * This window's own byte highlight.
   *
   * Deliberately not shared with App's `activeByteRange`: hovering a field in
   * here should light up bytes in this window's dump and leave whatever the
   * main window was showing untouched underneath.
   */
  const [activeByteRange, setActiveByteRange] = useState<[number, number] | null>(null);
  /**
   * Owned here rather than inside the dump, so the byte breakdown can live in
   * a bar spanning the full width beneath both columns.
   */
  const [hoveredByteIndex, setHoveredByteIndex] = useState<number | null>(null);
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
  const index = useMemo(() => findPacketIndexById(packets, packetId), [packets, packetId]);
  // Frames in the buffer carry no protocol tree - it is fetched for the one
  // frame being looked at (docs/decisions/0007). Everything above the tree
  // renders from the frame itself and is there immediately.
  const { packet, state: detailState } = usePacketDetail(
    index === -1 ? null : packets[index], packets,
  );

  const summary = useMemo(() => (packet ? buildFrameSummary(packet) : null), [packet]);
  const related = useMemo(() => (packet ? collectRelatedFrames(packet) : []), [packet]);
  const colorRuleName = useMemo(
    () => (packet ? colorEngine.getMatchedRuleName(packet) : undefined),
    [packet, colorEngine],
  );

  /**
   * The colour the packet list painted this frame's row.
   *
   * Recomputed as the window navigates, so paging through frames with the arrow
   * keys retints the window where the protocol changes - which is the same
   * signal the list gives, restated in a window that has no rows.
   */
  const accentColor = useMemo(
    () => (packet ? colorEngine.getPacketAccent(packet, packetTheme) : null),
    [packet, colorEngine, packetTheme],
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
   * Escape closes and the arrows step, matching the other modals. Registered
   * in the capture phase so it wins over the app's own window handler
   * underneath; typing in the frame box is exempt, since the arrows belong to
   * the caret there.
   *
   * The handler reads its moving parts through a ref rather than taking them
   * as dependencies. `packets` changes identity on every 100ms flush during
   * capture, so a dependency on it would tear down and re-register this
   * listener ten times a second for the life of the window.
   */
  const navRef = useRef({ index, packets, onClose, onShowFrame, obscured, railOverlay });
  navRef.current = { index, packets, onClose, onShowFrame, obscured, railOverlay };

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const nav = navRef.current;
      // Something is open over this window; the keyboard is not ours.
      if (nav.obscured) return;
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
      if (e.key === 'Escape') {
        e.preventDefault();
        // The summoned rail is the innermost thing open, so it goes first -
        // the same courtesy the `obscured` prop does for the stream window.
        if (nav.railOverlay) {
          setRailOverlay(false);
          return;
        }
        nav.onClose();
        return;
      }
      if (typing) return;
      const step = e.key === 'ArrowLeft' ? -1 : e.key === 'ArrowRight' ? 1 : 0;
      if (step === 0) return;
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
    frameBox,
    onFollowStream,
    onShowFrame: showFrame,
  };

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
        {hasBytes(packet) && <HexCopyButtons packet={packet} />}
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
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
    >
      <motion.div
        {...modalPanelMotion}
        className="w-full max-w-[100rem] h-[92vh] rounded-xl border flex flex-col shadow-2xl transition-colors bg-card border-border text-card-foreground overflow-hidden"
        // Retints the whole window to this frame - the protocol chip, the
        // layer rail's bars, the field table's active row, the raw-bytes
        // rule, the selected byte, the divider. See packetAccent.ts.
        style={packetAccentStyle(accentColor)}
      >
        {/* Identity and frame-to-frame navigation. Nothing else - the frame
            box moved into the rail, where it sits with the other ways of
            leaving this frame, and where it no longer squeezes the title. */}
        <div className="px-5 py-3 border-b border-border flex items-center gap-4 shrink-0">
          <div className="flex items-center gap-2.5 min-w-0">
            <TbBinaryTree className="w-7 h-7 shrink-0 text-primary" />
            <div className="min-w-0">
              <div className="flex items-center gap-2 font-bold text-base">
                <span className="whitespace-nowrap">Frame {packet ? packet.id : '—'}</span>
                {packet && (
                  <span className="text-xs px-2 py-0.5 rounded bg-primary/20 text-primary font-mono whitespace-nowrap">
                    {packet.protocolLabel ?? packet.protocol}
                  </span>
                )}
              </div>
              <p className="text-xs text-muted-foreground font-mono truncate">
                {packet ? packet.info : 'No frame loaded'}
              </p>
            </div>
          </div>

          <div className="flex-1" />

          <div className="flex items-center gap-1 shrink-0">
            <button
              onClick={() => goToIndex(index - 1)}
              disabled={!hasPrev}
              className={`p-1.5 rounded-md transition-colors ${
                hasPrev ? 'hover:bg-accent text-foreground cursor-pointer' : 'opacity-30 cursor-not-allowed text-muted-foreground'
              }`}
              title="Previous frame (←)"
            >
              <TbChevronLeft className="w-5 h-5" />
            </button>
            <button
              onClick={() => goToIndex(index + 1)}
              disabled={!hasNext}
              className={`p-1.5 rounded-md transition-colors ${
                hasNext ? 'hover:bg-accent text-foreground cursor-pointer' : 'opacity-30 cursor-not-allowed text-muted-foreground'
              }`}
              title="Next frame (→)"
            >
              <TbChevronRight className="w-5 h-5" />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground cursor-pointer ml-1"
              title="Close (Esc)"
            >
              <TbX className="w-5 h-5" />
            </button>
          </div>
        </div>

        {!packet || !summary ? (
          <div className="flex-1 flex items-center justify-center text-muted-foreground font-mono text-xs">
            Frame {packetId} is no longer in the buffer.
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
                  <TbChevronRight
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
                {/* Alerts get the full canvas width - in a window showing one
                    packet, the thing saying something is wrong should not be in
                    a column. Capped, though: they used to be unbounded, and
                    three of them squeezed the fields and the dump to nothing. */}
                <div className="shrink-0 max-h-[9rem] overflow-y-auto custom-scrollbar empty:hidden">
                  <ExpertFindings packet={packet} className="px-5 py-3 border-b border-border" />
                </div>

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
                      onHoverByteRange={range => { setActiveByteRange(range); setHoveredByteIndex(null); }}
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
                        className="w-1.5 h-full shrink-0 cursor-col-resize bg-muted hover:bg-primary/50 transition-colors"
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

            {/* One status bar under the whole window. */}
            <div className="px-5 py-1.5 border-t border-border bg-secondary/50 text-[10px] font-mono text-muted-foreground flex items-center justify-between shrink-0">
              <ByteInspector packet={packet} hoveredByteIndex={hoveredByteIndex} />
              <span className="uppercase tracking-wider whitespace-nowrap">
                Frame {index + 1} of {packets.length.toLocaleString()}
              </span>
            </div>
          </>
        )}
      </motion.div>
    </motion.div>
  );
};
