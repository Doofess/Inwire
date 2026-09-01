import React, { useCallback, useLayoutEffect, useEffect, useMemo, useRef, useState } from 'react';
import { TbLayoutSidebarLeftCollapse } from 'react-icons/tb';
import {
  DASHBOARD_DEFAULTS,
  DASHBOARD_MAX_WIDTH,
  DASHBOARD_MORPH_WIDTH,
  DASHBOARD_RAIL_WIDTH,
  clampDashboardWidth,
  dashboardStore,
  type DashboardWidgetId,
} from '../../services/dashboardPrefs';
import { usePreferenceStore } from '../../services/preferenceStore';
import { usePreferenceSync } from '../../services/preferences';
import {
  DASHBOARD_WIDGETS,
  WIDGETS_BY_ID,
  type DashboardWidgetContext,
} from './dashboardWidgets';
import { WidgetOverlay } from './WidgetOverlay';

/**
 * The analytics column, and the icon rail it collapses to.
 *
 * Lifted out of App.tsx, which had its entire chrome inline at 1700-odd lines.
 * This owns three things App has no business knowing about: which widgets are
 * showing, in what order, and which one is open over the app.
 *
 * The rail follows the pattern already working in the packet detail window (see
 * FrameMetaRail): a 48px strip that STAYS IN FLOW while the overlay is up, so
 * the packet list does not reflow every time a widget is opened or closed.
 */

interface DashboardAsideProps {
  context: DashboardWidgetContext;
  /**
   * Whether the mobile Analytics tab is the one showing.
   *
   * This element is that tab below `lg` - see the `!flex !w-full` override on
   * its className. It is why `mode` cannot simply gate the whole thing: a
   * desktop setting of "hidden" would silently remove a tab on a phone, with no
   * control anywhere on a phone to bring it back.
   */
  isMobileTabActive: boolean;
}

/** How many anomalies are in the buffer, for the rail's badge. */
function useAnomalyCount(packets: DashboardWidgetContext['packets']): number {
  return useMemo(
    () => packets.reduce((n, p) => n + ((p.anomalies?.length ?? 0) > 0 || p.status === 'alert' ? 1 : 0), 0),
    [packets],
  );
}

const DashboardAsideImpl: React.FC<DashboardAsideProps> = ({ context, isMobileTabActive }) => {
  const [dashboard, patchDashboard] = usePreferenceStore(dashboardStore);
  usePreferenceSync(dashboardStore.key, dashboardStore.normalize, dashboardStore.accept);

  const { mode, width, order, disabled } = dashboard;
  const disabledSet = useMemo(() => new Set(disabled), [disabled]);
  const widgets = useMemo(
    () => order.map((id) => WIDGETS_BY_ID[id]).filter((w) => w && !disabledSet.has(w.id)),
    [order, disabledSet],
  );

  /**
   * Which widget the overlay is showing.
   *
   * Deliberately not persisted. "Which panel did I have open" is not a setting;
   * restoring a full-screen overlay on load would be the app opening a window
   * nobody asked for.
   */
  const [openId, setOpenId] = useState<DashboardWidgetId | null>(null);
  const railRefs = useRef(new Map<DashboardWidgetId, HTMLButtonElement>());
  const cardRefs = useRef(new Map<DashboardWidgetId, HTMLElement>());

  // The rail keeps a live alert signal even though the widgets are unmounted.
  //
  // Without this, minimizing turns a monitoring dashboard into five inert
  // glyphs: the alert panel is the one widget whose whole job is to tell you
  // something while you are NOT looking at it, and the icon rail is the mode
  // meant for leaving the app running. The count is one pass over the buffer -
  // trivial beside the map's per-packet address classification, which is what
  // minimizing actually saves.
  const anomalyCount = useAnomalyCount(context.packets);

  /**
   * Escape lives in WidgetOverlay, so a widget expanded from its own card gets
   * it too - which it never did while each widget hand-rolled its own panel.
   *
   * Focus restore is split, because the two doors differ in one way that
   * matters: the rail icon is still on screen while the panel is up, so the
   * overlay's own restore puts focus back on it. The CARD is not - it is
   * unmounted so the widget is never running twice - so by the time the panel
   * closes, the button that opened it no longer exists and the overlay has
   * nothing to hand focus back to. This finds the one that has just been
   * remounted in its place, and falls back to the card's own region.
   */
  const close = useCallback(() => {
    const id = openId;
    setOpenId(null);
    if (!id) return;
    requestAnimationFrame(() => {
      const card = cardRefs.current.get(id);
      if (!card) return;
      (card.querySelector<HTMLElement>('[data-widget-expand]') ?? card).focus();
    });
  }, [openId]);

  // ---------------------------------------------------------------------
  // Dragging the column, and the morph at the end of it
  // ---------------------------------------------------------------------

  const asideRef = useRef<HTMLElement | null>(null);
  const liveWidthRef = useRef(width);
  const draggingRef = useRef(false);
  const rightEdgeRef = useRef(0);
  /**
   * Rail or column WHILE a drag is in progress; null when it is not.
   *
   * The morph is not a separate control - it is what the width means. Dragging
   * past the point where the widgets no longer have room for their own headings
   * turns the column into the rail, and dragging back out turns it into a
   * column again, both without releasing. Only this crossing re-renders; every
   * other pointer move writes a CSS variable and skips React entirely, which is
   * the same trick the pane dividers use in App.
   */
  const [dragRail, setDragRail] = useState<boolean | null>(null);

  const railMode = (dragRail ?? mode === 'icons') && !isMobileTabActive;

  /**
   * The one place the width reaches the DOM.
   *
   * Written imperatively rather than through a `style` prop because a drag
   * would otherwise be a render per pointer move - and this component's subtree
   * is five analytics widgets. Applied after every render as well as during the
   * drag, so the committed value takes over the moment the gesture ends and
   * there is never a frame showing the old one.
   */
  useLayoutEffect(() => {
    const px = draggingRef.current
      ? liveWidthRef.current
      : railMode
        ? DASHBOARD_RAIL_WIDTH
        : width;
    asideRef.current?.style.setProperty('--dashboard-width', `${px}px`);
  });

  const endDrag = useCallback(() => {
    if (!draggingRef.current) return;
    draggingRef.current = false;
    setDragRail(null);
    // Restored before the commit below re-renders, so releasing inside the rail
    // slides the last few pixels to 48 rather than snapping.
    asideRef.current?.style.removeProperty('transition-property');
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
    // The one commit for the whole gesture. Released inside the rail, the
    // stored width is left ALONE rather than written as 48 - expanding again
    // should give back the column that was there, not a default one.
    if (liveWidthRef.current < DASHBOARD_MORPH_WIDTH) patchDashboard({ mode: 'icons' });
    else patchDashboard({ mode: 'full', width: clampDashboardWidth(liveWidthRef.current) });
  }, [patchDashboard]);

  useEffect(() => {
    const onMove = (e: PointerEvent) => {
      if (!draggingRef.current) return;
      const px = Math.max(
        DASHBOARD_RAIL_WIDTH,
        Math.min(rightEdgeRef.current - e.clientX, DASHBOARD_MAX_WIDTH),
      );
      liveWidthRef.current = px;
      asideRef.current?.style.setProperty('--dashboard-width', `${px}px`);
      const rail = px < DASHBOARD_MORPH_WIDTH;
      setDragRail((prev) => (prev === rail ? prev : rail));
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', endDrag);
    // A drag that ends outside the window, or is taken over by the browser,
    // would otherwise leave the body stuck with a resize cursor.
    window.addEventListener('pointercancel', endDrag);
    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', endDrag);
      window.removeEventListener('pointercancel', endDrag);
    };
  }, [endDrag]);

  const beginDrag = useCallback(() => {
    const rect = asideRef.current?.getBoundingClientRect();
    if (!rect) return;
    // Measured off the column's own right edge rather than the window's, so a
    // scrollbar or anything else living out there cannot offset the drag.
    rightEdgeRef.current = rect.right;
    liveWidthRef.current = rect.width;
    draggingRef.current = true;
    // Set on the element rather than through a class, because a class needs a
    // React commit to land and the first few pointer moves arrive before that -
    // long enough for the column to rubber-band away from the hand grabbing it.
    // A transition during a drag is wrong in principle too: it puts the column
    // permanently a fraction of a second behind the pointer driving it.
    if (asideRef.current) asideRef.current.style.transitionProperty = 'none';
    document.body.style.cursor = 'col-resize';
    // Otherwise the drag selects packet rows as it passes over them.
    document.body.style.userSelect = 'none';
  }, []);

  /**
   * The same resize, from the keyboard.
   *
   * A separator that can only be moved by dragging a 6px target with a mouse is
   * not a control everyone has - and this one does not merely resize, it is the
   * only in-place way to reach the rail at all now that the button is gone.
   */
  const nudgeWidth = useCallback(
    (delta: number) => {
      if (railMode) {
        if (delta > 0) patchDashboard({ mode: 'full', width: clampDashboardWidth(width) });
        return;
      }
      const next = width + delta;
      if (next < DASHBOARD_MORPH_WIDTH) patchDashboard({ mode: 'icons' });
      else patchDashboard({ width: clampDashboardWidth(next) });
    },
    [patchDashboard, railMode, width],
  );

  if (mode === 'hidden' && !isMobileTabActive) return null;

  /**
   * The expanded window - one, for both doors into it.
   *
   * The rail's icons and the expand button on a card now set the same state and
   * render the same element with the same props. It used to be two: the widgets
   * drew a fixed panel of their own for the card, and this file drew a
   * different one, with a title bar of its own stacked above the widget's, for
   * the rail. Same widget, same intent, two windows that had already drifted
   * apart in size, chrome and close control.
   *
   * `gutter` is the only thing that still differs, and it is not decoration:
   * the rail sits above the scrim so a second icon SWAPS the widget instead of
   * forcing close-then-reopen, and a panel drawn over it would take that back.
   * In the full column there is no rail to leave room for.
   */
  const overlay = openId && (
    <WidgetOverlay
      label={WIDGETS_BY_ID[openId].label}
      onClose={close}
      gutter={railMode}
      panelRole={railMode ? 'tabpanel' : 'dialog'}
    >
      {WIDGETS_BY_ID[openId].render(context, { variant: 'full' })}
    </WidgetOverlay>
  );

  // ---------------------------------------------------------------------
  // The rail's contents
  // ---------------------------------------------------------------------
  const rail = (
    <div
      role="tablist"
      aria-orientation="vertical"
      aria-label="Analytics widgets"
      className="flex flex-col items-center gap-1"
    >
      <button
        type="button"
        onClick={() => patchDashboard({ mode: 'full' })}
        aria-label="Expand analytics dashboard"
        title="Expand analytics dashboard"
        className="p-2 rounded-md text-muted-foreground hover:bg-accent hover:text-foreground transition-colors cursor-pointer"
      >
        <TbLayoutSidebarLeftCollapse className="w-4 h-4" />
      </button>

      {widgets.map((widget) => {
        const Icon = widget.icon;
        const isOpen = openId === widget.id;
        return (
          <button
            key={widget.id}
            type="button"
            ref={(node) => {
              if (node) railRefs.current.set(widget.id, node);
              else railRefs.current.delete(widget.id);
            }}
            role="tab"
            aria-selected={isOpen}
            // The accessible name comes from the registry, not from a
            // tooltip: Radix tooltips wire aria-describedby, so an
            // icon-only button with only a tooltip has no name at all.
            aria-label={widget.label}
            title={widget.label}
            onClick={() => setOpenId(isOpen ? null : widget.id)}
            onKeyDown={(e) => {
              // Up and down move along the rail and swap the open widget
              // with them, which is the same thing clicking does.
              if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
              e.preventDefault();
              const i = widgets.findIndex((w) => w.id === widget.id);
              const next = widgets[(i + (e.key === 'ArrowDown' ? 1 : -1) + widgets.length) % widgets.length];
              railRefs.current.get(next.id)?.focus();
              if (openId) setOpenId(next.id);
            }}
            className={`relative p-2 rounded-md transition-colors cursor-pointer ${
              isOpen
                ? 'bg-primary text-primary-foreground'
                : 'text-muted-foreground hover:bg-accent hover:text-foreground'
            }`}
          >
            <Icon className="w-4 h-4" />
            {/* The live signal that survives the widgets being unmounted. */}
            {widget.id === 'alerts' && anomalyCount > 0 && (
              <span
                aria-label={`${anomalyCount} anomalies`}
                className="absolute top-0.5 right-0.5 min-w-3 h-3 px-0.5 rounded-full bg-danger text-[8px] leading-3 font-bold text-white text-center"
              >
                {anomalyCount > 99 ? '99+' : anomalyCount}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );

  // ---------------------------------------------------------------------
  // The column's contents
  // ---------------------------------------------------------------------
  const column = widgets.map((widget) => (
    <section
      key={widget.id}
      // A heading per widget, so the whole dashboard is navigable by
      // heading - which is the fastest way anybody using a screen reader
      // will move around it. The alert panel has no header of its own, so
      // this is the only name it has ever had.
      aria-label={widget.label}
      // Focusable only as a target, never in tab order: it is where focus
      // lands if the widget's expand button has gone away.
      tabIndex={-1}
      ref={(node) => {
        if (node) cardRefs.current.set(widget.id, node);
        else cardRefs.current.delete(widget.id);
      }}
      className={widget.cardClassName || undefined}
    >
      {/* The card is not drawn while its own widget fills the overlay.
          Not tidiness: GeoMap is a MapLibre instance bound to a DOM node,
          and rendering the card behind the panel would run two of them
          against one shared session. The column is under a full-screen
          scrim while this is true, so the gap it leaves is not visible -
          and the widget is remounted, at its stored camera and place list,
          the moment the panel closes. */}
      {widget.id !== openId &&
        widget.render(context, {
          variant: 'card',
          onExpand: () => setOpenId(widget.id),
        })}
    </section>
  ));

  return (
    <>
      {/* The handle, and the only thing that sets the dashboard's size.
          `lg` and up only: below that the full column is hidden anyway, so a
          handle there would offer to drag the dashboard into a width at which
          it disappears. The rail's own button is the way back at those sizes. */}
      {!isMobileTabActive && (
        <div
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize analytics dashboard"
          aria-valuenow={railMode ? DASHBOARD_RAIL_WIDTH : width}
          aria-valuemin={DASHBOARD_RAIL_WIDTH}
          aria-valuemax={DASHBOARD_MAX_WIDTH}
          tabIndex={0}
          title="Drag to resize - right-click to reset. Narrow enough collapses it to icons"
          className="hidden lg:block w-1.5 shrink-0 cursor-col-resize transition-colors z-10 bg-muted hover:bg-primary/50"
          onPointerDown={beginDrag}
          // The same right-click reset every draggable bar has. It restores the
          // MODE as well as the width, because dragging into the rail is the
          // easiest of these gestures to trigger by accident and "put it back"
          // plainly means the column, not a 48px column nobody asked for.
          onContextMenu={(e) => {
            e.preventDefault();
            e.stopPropagation();
            patchDashboard({ mode: 'full', width: DASHBOARD_DEFAULTS.width });
          }}
          onKeyDown={(e) => {
            // Left widens, because left is the direction the separator moves
            // to make the column bigger.
            const step = e.shiftKey ? 64 : 16;
            if (e.key === 'ArrowLeft') { e.preventDefault(); nudgeWidth(step); }
            else if (e.key === 'ArrowRight') { e.preventDefault(); nudgeWidth(-step); }
            else if (e.key === 'Home') { e.preventDefault(); patchDashboard({ mode: 'icons' }); }
            else if (e.key === 'End') { e.preventDefault(); patchDashboard({ mode: 'full', width: DASHBOARD_MAX_WIDTH }); }
            else if (e.key === 'Enter') {
              e.preventDefault();
              patchDashboard(railMode ? { mode: 'full' } : { mode: 'icons' });
            }
          }}
        />
      )}

      <aside
        ref={asideRef}
        // The width lives in a custom property rather than a utility class,
        // because it is dragged: see the layout effect above.
        className={`nv-morph w-[var(--dashboard-width)] shrink-0 flex-col border-l border-border bg-background ${
          railMode
            ? 'hidden md:flex items-center py-2 overflow-hidden z-[45] relative'
            : 'hidden lg:flex p-4 space-y-4 overflow-y-auto custom-scrollbar'
        } transition-[width,background-color,border-color] duration-200 ease-out ${
          isMobileTabActive ? '!flex !w-full !border-l-0' : ''
        }`}
      >
        {railMode ? rail : column}
      </aside>

      {/* Outside the column, which scrolls: a fixed panel is not clipped by an
          overflow ancestor today, but it is one `transform` away from being so,
          and that is not a failure anybody would connect back to this line. */}
      {overlay}
    </>
  );
};

/**
 * Memoized, and the app has no other memo boundary anywhere.
 *
 * App re-renders on every packet flush - about ten times a second while
 * capturing - and every child's function body runs with it. The widgets avoided
 * the WORK because their memos key on the throttled feed, but the render pass
 * itself was paid at the full rate regardless. With this boundary and a
 * memoized context, the dashboard renders at its own rate instead: a fivefold
 * cut on the expanded case, which is the one most people are in.
 */
export const DashboardAside = React.memo(DashboardAsideImpl);
