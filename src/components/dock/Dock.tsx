import React, { useCallback, useEffect, useRef, useState } from 'react';
import { TbPin, TbPinFilled, TbX, TbGripVertical } from 'react-icons/tb';
import { RenderedWidget } from '../analytics/RenderedWidget';
import type { DashboardWidgetContext } from '../analytics/dashboardWidgets';
import {
  widgetTitle, type WidgetConfig, type WidgetInstance, type WidgetTypeId,
} from '../../services/dashboardPrefs';
import {
  clampDockWidth, dockOrder, maxDockWidth, DOCK_MIN_WIDTH, type DockItem,
} from '../../services/dockPrefs';

/**
 * The column between the rail and the main content.
 *
 * It is the old `DashboardAside` relocated and re-chromed, and the widgets
 * inside it are untouched: every item renders through `RenderedWidget`, exactly
 * as the right-hand column did, so per-widget config, the header `Segmented`
 * controls, the empty states and the geo map's expand window all still work
 * without knowing they moved.
 *
 * What is new is the item chrome - pin, close, a drag grip - and what is gone is
 * the morph. The old column collapsed into a 48px icon rail below 200px, one
 * gesture doing two jobs; there is a permanent rail now, so a narrow dock is just
 * a narrow dock.
 *
 * ## The grip, and the objection it answers
 *
 * `DashboardWidgetList` reorders the same widgets in Settings, and its header
 * says why it is there rather than here: "the dashboard column is scrolling live
 * data, and a drag gesture inside it would compete with that for the same
 * pointer." That objection is correct and is answered rather than overruled -
 * **only the grip is draggable**, not the item and not its body. A pointer over a
 * chart is still the chart's. The Settings list also stays, with its up/down
 * buttons, because native HTML5 drag exposes nothing to a keyboard.
 *
 * ## The title truncates at the default width, and that is accepted
 *
 * `WidgetCard`'s header holds the title, the type's `Segmented` control and the
 * expand button, and it was sized for a 352px card - the width the old right-hand
 * column gave it. At the dock's 260px default that leaves the title about 80px
 * and "TRAFFIC TIMELINE" becomes "TRAFFI...".
 *
 * Left alone deliberately, rather than by not having noticed. The widget is still
 * identifiable three other ways - its icon, this item's `aria-label`, and the
 * rail's own tooltip - and the alternatives all cost more than the truncation
 * does: moving the title into this header duplicates it, suppressing the card's
 * means changing a component every other caller shares, and widening the default
 * reverses a decision made with the 352 in view. A future session should not
 * "fix" this without reopening that.
 *
 * Native drag and drop rather than a library, which is what
 * `DisplayFiltersPanel` already does for the same shape of list - and every drag
 * fact is mirrored into a ref, for the reason that file states: two events
 * landing in the same task would read stale state and the drop would silently do
 * nothing.
 */

export interface DockProps {
  items: DockItem[];
  width: number;
  context: DashboardWidgetContext;
  /** The `inwire.dashboard` side: custom titles and per-widget config. */
  widgets: WidgetInstance[];
  onConfigChange: (type: WidgetTypeId, patch: WidgetConfig) => void;
  onReorder: (order: WidgetTypeId[]) => void;
  onTogglePinned: (type: WidgetTypeId) => void;
  onClose: (type: WidgetTypeId) => void;
  onWidthChange: (width: number) => void;
  /**
   * The geo map's expanded window, which only it has.
   *
   * Takes the element as well as the type so the overlay can scale from the card
   * it came out of, which is what the right-hand column did. `RenderedWidget`'s
   * own `onExpand` takes no arguments, so the element comes from a ref here
   * rather than from the widget.
   */
  onExpand?: (type: WidgetTypeId, from: HTMLElement | null) => void;
}

const DockImpl: React.FC<DockProps> = ({
  items, width, context, widgets, onConfigChange,
  onReorder, onTogglePinned, onClose, onWidthChange, onExpand,
}) => {
  const visible = dockOrder(items);
  const byType = new Map(widgets.map((w) => [w.type, w] as const));

  /**
   * The live window width, so the clamp can follow a resized window.
   *
   * Narrowing the window shrinks an open dock rather than squeezing the list
   * below its floor; the STORED width is left alone, so widening gives back the
   * width the user chose. That is the same courtesy the old column's morph paid,
   * which left `width` untouched when it collapsed.
   */
  const [windowWidth, setWindowWidth] = useState(() =>
    (typeof window === 'undefined' ? 1280 : window.innerWidth));
  useEffect(() => {
    const onResize = (): void => setWindowWidth(window.innerWidth);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);
  const effective = clampDockWidth(width, windowWidth);

  /* --- resize ------------------------------------------------------------ */

  const dockRef = useRef<HTMLDivElement | null>(null);
  const liveWidthRef = useRef(effective);
  const draggingRef = useRef(false);
  const leftEdgeRef = useRef(0);

  // The only place width reaches the DOM during a drag. Writing a CSS variable
  // imperatively is what keeps a pointer move from being a React render - the
  // old column's gesture did exactly this, and a chart re-rendering per move is
  // what it was avoiding.
  useEffect(() => {
    if (draggingRef.current) return;
    liveWidthRef.current = effective;
    dockRef.current?.style.setProperty('--dock-width', `${effective}px`);
  }, [effective]);

  const beginResize = useCallback((e: React.PointerEvent) => {
    const node = dockRef.current;
    if (node === null) return;
    leftEdgeRef.current = node.getBoundingClientRect().left;
    draggingRef.current = true;
    node.style.transitionProperty = 'none';
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  }, []);

  useEffect(() => {
    const onMove = (e: PointerEvent): void => {
      if (!draggingRef.current) return;
      const next = clampDockWidth(e.clientX - leftEdgeRef.current, window.innerWidth);
      liveWidthRef.current = next;
      dockRef.current?.style.setProperty('--dock-width', `${next}px`);
    };
    const onUp = (): void => {
      if (!draggingRef.current) return;
      draggingRef.current = false;
      if (dockRef.current) dockRef.current.style.transitionProperty = '';
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      // One commit for the whole gesture, not one per pointer move.
      onWidthChange(liveWidthRef.current);
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
    };
  }, [onWidthChange]);

  const nudgeWidth = (by: number): void => onWidthChange(
    clampDockWidth(liveWidthRef.current + by, window.innerWidth),
  );

  /* --- reorder ----------------------------------------------------------- */

  // State for the paint, refs for the logic. See the header.
  /** Per-item, so an expand can scale from the card it came out of. */
  const cardRefs = useRef(new Map<WidgetTypeId, HTMLElement>());

  const dragRef = useRef<WidgetTypeId | null>(null);
  const [dragging, setDragging] = useState<WidgetTypeId | null>(null);
  const dropRef = useRef<number | null>(null);
  const [dropAt, setDropAt] = useState<number | null>(null);

  const setDrag = (type: WidgetTypeId | null): void => { dragRef.current = type; setDragging(type); };
  const setDrop = (at: number | null): void => { dropRef.current = at; setDropAt(at); };

  /** Upper or lower half of the row decides before or after. */
  const dropIndexFor = (e: React.DragEvent, index: number): number => {
    const { top, height } = e.currentTarget.getBoundingClientRect();
    return e.clientY - top > height / 2 ? index + 1 : index;
  };

  const commitDrop = (): void => {
    const moved = dragRef.current;
    const at = dropRef.current;
    setDrag(null);
    setDrop(null);
    if (moved === null || at === null) return;
    const order = visible.map((i) => i.type);
    const from = order.indexOf(moved);
    if (from < 0) return;
    const without = order.filter((t) => t !== moved);
    // The insertion point was measured against the list WITH the dragged item
    // still in it, so an index past its old position is one too far once it is
    // removed. Getting this wrong moves the item one short, every time, in one
    // direction only - which reads as the drop being ignored.
    without.splice(at > from ? at - 1 : at, 0, moved);
    onReorder(without);
  };

  if (visible.length === 0) return null;

  return (
    <>
      <div
        ref={dockRef}
        style={{ width: `var(--dock-width, ${effective}px)` }}
        className="shrink-0 flex flex-col gap-2 overflow-y-auto custom-scrollbar p-2
          border-r border-border bg-background"
      >
        {visible.map((item, index) => {
          const instance = byType.get(item.type);
          if (instance === undefined) return null;
          const title = widgetTitle(instance);
          return (
            <section
              key={item.type}
              ref={(node) => {
                if (node) cardRefs.current.set(item.type, node);
                else cardRefs.current.delete(item.type);
              }}
              aria-label={title}
              onDragOver={(e) => {
                if (dragRef.current === null) return;
                e.preventDefault();
                setDrop(dropIndexFor(e, index));
              }}
              onDrop={(e) => { e.preventDefault(); commitDrop(); }}
              className={`shrink-0 rounded-lg transition-opacity ${
                dragging === item.type ? 'opacity-40' : ''
              } ${dropAt === index ? 'border-t-2 border-t-primary' : ''} ${
                dropAt === index + 1 ? 'border-b-2 border-b-primary' : ''
              }`}
            >
              <div className="flex items-center gap-1 px-1 pb-0.5">
                {/* The ONLY draggable element. The body below is a live chart
                    and the pointer over it belongs to the chart. */}
                <span
                  draggable
                  onDragStart={() => setDrag(item.type)}
                  onDragEnd={() => { setDrag(null); setDrop(null); }}
                  role="button"
                  tabIndex={-1}
                  aria-label={`Reorder ${title}`}
                  title="Drag to reorder - Settings has buttons for the same thing"
                  className="p-0.5 rounded cursor-grab active:cursor-grabbing
                    text-muted-foreground/60 hover:text-foreground"
                >
                  <TbGripVertical className="w-3.5 h-3.5" />
                </span>
                <span className="flex-1" />
                <button
                  type="button"
                  onClick={() => onTogglePinned(item.type)}
                  aria-pressed={item.pinned}
                  aria-label={item.pinned ? `Unpin ${title}` : `Pin ${title}`}
                  title={item.pinned
                    ? 'Unpin - it will move with the others'
                    : 'Pin to the top of the dock'}
                  className={`p-0.5 rounded transition-colors cursor-pointer ${
                    item.pinned
                      ? 'text-primary'
                      : 'text-muted-foreground/60 hover:text-foreground'
                  }`}
                >
                  {item.pinned
                    ? <TbPinFilled className="w-3.5 h-3.5" />
                    : <TbPin className="w-3.5 h-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => onClose(item.type)}
                  aria-label={`Close ${title}`}
                  title="Close - the rail's icon turns off with it"
                  className="p-0.5 rounded transition-colors cursor-pointer
                    text-muted-foreground/60 hover:text-foreground"
                >
                  <TbX className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Untouched. Exactly the call the right-hand column made. */}
              <RenderedWidget
                widget={instance}
                context={context}
                onConfigChange={onConfigChange}
                onExpand={onExpand === undefined
                  ? undefined
                  : () => onExpand(item.type, cardRefs.current.get(item.type) ?? null)}
              />
            </section>
          );
        })}
      </div>

      {/* House style for a splitter: 6px, `role="separator"`, full aria, and the
          arrow/Home/End keys - copied from the column this replaces. Right-click
          resets, and stops propagating because the packet list has a row context
          menu of its own. */}
      <div
        role="separator"
        aria-orientation="vertical"
        aria-label="Dock width"
        aria-valuenow={effective}
        aria-valuemin={DOCK_MIN_WIDTH}
        aria-valuemax={maxDockWidth(windowWidth)}
        tabIndex={0}
        title="Drag to resize - right-click to reset"
        onPointerDown={beginResize}
        onContextMenu={(e) => {
          e.preventDefault();
          e.stopPropagation();
          onWidthChange(clampDockWidth(DOCK_MIN_WIDTH, window.innerWidth));
        }}
        onKeyDown={(e) => {
          const step = e.shiftKey ? 64 : 16;
          if (e.key === 'ArrowLeft') { e.preventDefault(); nudgeWidth(-step); }
          else if (e.key === 'ArrowRight') { e.preventDefault(); nudgeWidth(step); }
          else if (e.key === 'Home') { e.preventDefault(); onWidthChange(DOCK_MIN_WIDTH); }
          else if (e.key === 'End') {
            e.preventDefault();
            onWidthChange(maxDockWidth(window.innerWidth));
          }
        }}
        className="w-1.5 shrink-0 cursor-col-resize transition-colors z-10
          bg-muted hover:bg-primary/50"
      />
    </>
  );
};

/**
 * The app's one memo boundary, inherited from the column this replaces.
 *
 * `App` re-renders about ten times a second during a capture - that is the 100ms
 * flush - and every widget in here does a full pass over the buffer when its
 * inputs change. `DashboardAside` was `React.memo`'d for exactly that reason and
 * was the only memo in the application; moving the column without moving the memo
 * would have quietly handed every one of those renders to the charts.
 *
 * It only works because every prop is stable: `context` is memoised in `App`,
 * `items` and `widgets` come from preference stores that return the same
 * reference until something changes, and all six callbacks are `useCallback`
 * there. An inline arrow in any one of them turns this back into a no-op, which
 * is the failure mode to watch for - it is invisible except as a profile.
 */
export const Dock = React.memo(DockImpl);
