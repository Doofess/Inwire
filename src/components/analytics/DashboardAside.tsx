import React, { useCallback, useLayoutEffect, useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence } from 'motion/react';
import { TbLayoutSidebarLeftCollapse } from 'react-icons/tb';
import {
  DASHBOARD_DEFAULTS,
  DASHBOARD_MAX_WIDTH,
  DASHBOARD_MORPH_WIDTH,
  DASHBOARD_RAIL_WIDTH,
  WIDGET_CARD_WIDTH,
  clampDashboardWidth,
  dashboardStore,
  widgetTitle,
  type WidgetConfig,
  type WidgetInstance,
  type WidgetTypeId,
} from '../../services/dashboardPrefs';
import { usePreferenceStore } from '../../services/preferenceStore';
import { usePreferenceSync } from '../../services/preferences';
import { WIDGET_RENDERERS, type DashboardWidgetContext } from './dashboardWidgets';
import { RenderedWidget } from './RenderedWidget';
import { WidgetOverlay } from './WidgetOverlay';
import { Popover, PopoverContent, PopoverTrigger, PopoverArrow } from '../ui/popover';
import { useIncrementalAggregate } from '../../lib/useIncrementalAggregate';

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
 *
 * **Only the map has an expanded window.** Every other widget is read at card
 * size, and the rail pops one out beside its own icon rather than opening
 * anything in the middle of the screen - see the bubbles below. That is why
 * `openType` is only ever 'geo' rather than a widget of any kind: it is
 * not a general mechanism with one user, it is the map's window.
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

/**
 * How many anomalies are in the buffer, for the rail's light.
 *
 * A running count rather than a `reduce` over the whole buffer: a packet's
 * anomalies are decided when it is dissected and never change, so re-reading
 * 43,000 of them twice a second to produce a number on a badge was the
 * cheapest of the dashboard's full-buffer passes and still entirely wasted.
 */
function useAnomalyCount(packets: DashboardWidgetContext['packets']): number {
  return useIncrementalAggregate(
    packets,
    () => ({ count: 0 }),
    (acc, p) => {
      if ((p.anomalies?.length ?? 0) > 0 || p.status === 'alert') acc.count += 1;
    },
    (acc) => acc.count,
  );
}

/** A hairline between two kinds of thing in the rail. */
const RailDivider: React.FC<{ className?: string }> = ({ className }) => (
  <span aria-hidden className={`w-5 h-px bg-border my-1 shrink-0 ${className ?? ''}`} />
);

const DashboardAsideImpl: React.FC<DashboardAsideProps> = ({ context, isMobileTabActive }) => {
  const [dashboard, patchDashboard] = usePreferenceStore(dashboardStore);
  usePreferenceSync(dashboardStore.key, dashboardStore.normalize, dashboardStore.accept);

  const { mode, width, widgets: allWidgets } = dashboard;
  const widgets = useMemo(() => allWidgets.filter((w) => w.enabled), [allWidgets]);

  /**
   * The map's window, and where it grew from.
   *
   * Deliberately not persisted. "Which panel did I have open" is not a setting;
   * restoring a full-screen overlay on load would be the app opening a window
   * nobody asked for.
   *
   * `origin` is the point the panel scales out of - see WidgetOverlay. It is
   * captured from whichever control was clicked rather than passed down from
   * one, because the two doors into the map are in different subtrees.
   */
  const [openType, setOpenType] = useState<WidgetTypeId | null>(null);
  const [origin, setOrigin] = useState<{ x: number; y: number } | undefined>();
  const railRefs = useRef(new Map<WidgetTypeId, HTMLButtonElement>());
  const cardRefs = useRef(new Map<WidgetTypeId, HTMLElement>());

  const openFrom = useCallback((type: WidgetTypeId, el: Element | null) => {
    const rect = el?.getBoundingClientRect();
    setOrigin(rect ? { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 } : undefined);
    setOpenType(type);
  }, []);

  // The rail keeps a live alert signal even though the widgets are unmounted.
  //
  // Without this, minimizing turns a monitoring dashboard into a column of
  // inert glyphs: the alert panel is the one widget whose whole job is to tell
  // you something while you are NOT looking at it, and the icon rail is the
  // mode meant for leaving the app running. The count is one pass over the
  // buffer - trivial beside the map's per-packet address classification, which
  // is what minimizing actually saves.
  const anomalyCount = useAnomalyCount(context.packets);

  /**
   * Escape lives in WidgetOverlay, so the map gets it however it was opened.
   *
   * Focus restore is split, because the two doors differ in one way that
   * matters: the rail icon is still on screen while the panel is up, so the
   * overlay's own restore puts focus back on it. The CARD is not - it is
   * unmounted so the map is never running twice - so by the time the panel
   * closes, the button that opened it no longer exists and the overlay has
   * nothing to hand focus back to. This finds the one that has just been
   * remounted in its place, and falls back to the card's own region.
   */
  const close = useCallback(() => {
    const type = openType;
    setOpenType(null);
    if (!type) return;
    requestAnimationFrame(() => {
      const card = cardRefs.current.get(type);
      if (!card) return;
      (card.querySelector<HTMLElement>('[data-widget-expand]') ?? card).focus();
    });
  }, [openType]);

  /** Writes one widget's settings. The card's header control and the list in
   *  Settings both land here, so a card toggle IS the stored setting. */
  const patchConfig = useCallback(
    (type: WidgetTypeId, patch: WidgetConfig) => {
      patchDashboard({
        widgets: allWidgets.map((w) =>
          w.type === type ? { ...w, config: { ...w.config, ...patch } } : w,
        ),
      });
    },
    [allWidgets, patchDashboard],
  );

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
   * is the whole dashboard. Applied after every render as well as during the
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

  // ---------------------------------------------------------------------
  // One widget, in the one card
  // ---------------------------------------------------------------------

  /**
   * A widget, framed - the same call the popout bubble makes. See
   * RenderedWidget.
   */
  const renderWidget = useCallback(
    (widget: WidgetInstance, onExpand?: () => void) => (
      <RenderedWidget
        widget={widget}
        context={context}
        onConfigChange={patchConfig}
        onExpand={onExpand}
      />
    ),
    [context, patchConfig],
  );

  if (mode === 'hidden' && !isMobileTabActive) return null;

  /**
   * The map's window - the only expanded widget left.
   *
   * Everything else lost its expanded form when the dashboard became something
   * you build: a widget that is a ranked list of five rows has nothing to say
   * at 1600x1000 that it does not say at 352px, and the two windows it used to
   * be openable into had already drifted apart in size, chrome and close
   * control. The map is different because its subject genuinely is bigger than
   * a card.
   *
   * `gutter` leaves the rail uncovered when the rail is what opened it, so the
   * rail stays reachable above the scrim.
   */
  const openWidget = openType ? widgets.find((w) => w.type === openType) : undefined;
  const overlay = openWidget && (
    <WidgetOverlay
      key={openWidget.type}
      label={widgetTitle(openWidget)}
      icon={WIDGET_RENDERERS[openWidget.type].icon}
      onClose={close}
      gutter={railMode}
      origin={origin}
    >
      {WIDGET_RENDERERS[openWidget.type].render(context, openWidget.config, { variant: 'full' })}
    </WidgetOverlay>
  );

  // ---------------------------------------------------------------------
  // The rail
  // ---------------------------------------------------------------------

  // Alerts is not a widget button in the rail, so it is taken out of the strip
  // and pinned to the bottom as a light. Any number of alert widgets in the
  // column is one light here - it is a signal, not a count of widgets.
  const railWidgets = widgets.filter((w) => w.type !== 'alerts');
  const hasAlertWidget = widgets.some((w) => w.type === 'alerts');

  const focusRail = (from: WidgetTypeId, delta: number) => {
    const i = railWidgets.findIndex((w) => w.type === from);
    if (i < 0 || railWidgets.length === 0) return;
    const next = railWidgets[(i + delta + railWidgets.length) % railWidgets.length];
    railRefs.current.get(next.type)?.focus();
  };

  const railButtonClass = (active: boolean) =>
    // A 32px target inside a 48px strip. The icons used to be their own hit
    // area - a 16px glyph with nothing around it - which is below every pointer
    // target guideline there is and felt like it on a trackpad.
    `relative w-8 h-8 flex items-center justify-center rounded-md transition-colors cursor-pointer shrink-0 ${
      active
        ? 'bg-primary text-primary-foreground'
        : 'text-muted-foreground hover:bg-accent hover:text-foreground'
    }`;

  const rail = (
    <div
      role="toolbar"
      aria-orientation="vertical"
      aria-label="Analytics widgets"
      className="flex flex-col items-center gap-0.5 h-full w-full"
    >
      {/* Not a widget, and it must not look like one: it changes the shape of
          the dashboard rather than opening anything. Hence the divider under
          it - without one it was the sixth identical glyph in a row of six. */}
      <button
        type="button"
        onClick={() => patchDashboard({ mode: 'full' })}
        aria-label="Expand analytics dashboard"
        title="Expand analytics dashboard"
        className={railButtonClass(false)}
      >
        <TbLayoutSidebarLeftCollapse className="w-4 h-4" />
      </button>
      <RailDivider />

      {railWidgets.map((widget) => {
        const renderer = WIDGET_RENDERERS[widget.type];
        const Icon = renderer.icon;
        const title = widgetTitle(widget);
        const onKeyDown = (e: React.KeyboardEvent) => {
          if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
          e.preventDefault();
          focusRail(widget.type, e.key === 'ArrowDown' ? 1 : -1);
        };
        const setRef = (node: HTMLButtonElement | null) => {
          if (node) railRefs.current.set(widget.type, node);
          else railRefs.current.delete(widget.type);
        };

        // The map keeps its window, so its icon opens that rather than a
        // bubble - a globe in a 352px popover would be a smaller map than the
        // card it came from, which is the opposite of what expanding means.
        if (widget.type === 'geo') {
          const isOpen = openType === widget.type;
          return (
            <button
              key={widget.type}
              ref={setRef}
              type="button"
              aria-label={title}
              aria-expanded={isOpen}
              title={title}
              onKeyDown={onKeyDown}
              onClick={(e) => (isOpen ? close() : openFrom(widget.type, e.currentTarget))}
              className={railButtonClass(isOpen)}
            >
              <Icon className="w-4 h-4" />
            </button>
          );
        }

        return (
          <Popover key={widget.type}>
            <PopoverTrigger asChild>
              <button
                ref={setRef}
                type="button"
                aria-label={title}
                title={title}
                onKeyDown={onKeyDown}
                className={railButtonClass(false)}
              >
                <Icon className="w-4 h-4" />
              </button>
            </PopoverTrigger>
            {/* Beside the icon, pointing at it, at the width this widget has
                in a column nobody has resized. The point of the bubble is that
                it IS the widget rather than a shrunken preview - so it is the
                same card, from the same call, at the same size. */}
            <PopoverContent
              side="left"
              align="start"
              alignOffset={-8}
              style={{ width: WIDGET_CARD_WIDTH }}
              // Transparent, because the card inside brings its own frame - the
              // popover would otherwise draw a second border and a second
              // radius around it. `drop-shadow` rather than `shadow`: a box
              // shadow here would be cast by this transparent rectangle and
              // show square corners behind the card's rounded ones, while a
              // drop-shadow follows the painted shape.
              className="p-0 border-0 bg-transparent shadow-none drop-shadow-2xl"
              aria-label={title}
            >
              {renderWidget(widget)}
              {/* The tail. `fill-card`, not `fill-popover`, because what it is
                  attached to is the widget's card. */}
              <PopoverArrow className="fill-card" />
            </PopoverContent>
          </Popover>
        );
      })}

      {hasAlertWidget && (
        <>
          {/* Pinned to the bottom, behind a divider, and NOT a button.
              It stopped being one when alerts lost its expanded window, and a
              control that looks like its neighbours and does nothing when
              clicked is worse than no control - so it does not take focus, has
              no hover state and shows no pointer cursor. */}
          <RailDivider className="mt-auto" />
          <div
            role="status"
            aria-live="polite"
            title={
              anomalyCount > 0
                ? `${anomalyCount} ${anomalyCount === 1 ? 'alert' : 'alerts'} captured`
                : 'No alerts'
            }
            className={`relative w-8 h-8 flex items-center justify-center shrink-0 mb-0.5 ${
              anomalyCount > 0 ? 'text-danger' : 'text-muted-foreground/40'
            }`}
          >
            <WIDGET_RENDERERS.alerts.icon className="w-4 h-4" />
            {anomalyCount > 0 && (
              <>
                <span className="sr-only">
                  {anomalyCount} {anomalyCount === 1 ? 'alert' : 'alerts'} captured
                </span>
                {/* A light, not a badge. The count it replaced was three
                    digits of 8px type on a 16px glyph, which at rail width was
                    a smudge; the number is in the tooltip and the accessible
                    name instead, where it is actually readable.

                    Two elements because `animate-ping` scales the thing it is
                    on to nothing at the end of each cycle - so the ring pings
                    and a solid dot underneath stays put. The blanket
                    reduced-motion rule in index.css stills the ring and leaves
                    the dot, which is exactly the right fallback. */}
                <span
                  aria-hidden
                  className="absolute top-1 right-1 w-2 h-2 rounded-full bg-danger opacity-75 animate-ping"
                />
                <span
                  aria-hidden
                  className="absolute top-1 right-1 w-2 h-2 rounded-full bg-danger ring-2 ring-background"
                />
              </>
            )}
          </div>
        </>
      )}
    </div>
  );

  // ---------------------------------------------------------------------
  // The column
  // ---------------------------------------------------------------------

  const column =
    widgets.length === 0 ? (
      // Still reachable, though not by deleting anything - widgets cannot be
      // deleted. This is every one of them switched off at once.
      <div className="flex-1 flex flex-col items-center justify-center text-center gap-2 px-6">
        <p className="text-xs text-muted-foreground">Every widget is switched off.</p>
        <p className="text-[11px] text-muted-foreground/70 leading-snug">
          Turn one back on in Settings, under Interface.
        </p>
      </div>
    ) : (
      widgets.map((widget) => (
        <section
          key={widget.type}
          // A heading per widget, so the whole dashboard is navigable by
          // heading - which is the fastest way anybody using a screen reader
          // will move around it.
          aria-label={widgetTitle(widget)}
          // Focusable only as a target, never in tab order: it is where focus
          // lands if the widget's expand button has gone away.
          tabIndex={-1}
          ref={(node) => {
            if (node) cardRefs.current.set(widget.type, node);
            else cardRefs.current.delete(widget.type);
          }}
          className="shrink-0"
        >
          {/* The card is not drawn while its own widget fills the overlay.
              Not tidiness: GeoMap is a MapLibre instance bound to a DOM node,
              and rendering the card behind the panel would run two of them
              against one shared session. The column is under a full-screen
              scrim while this is true, so the gap it leaves is not visible -
              and the widget is remounted, at its stored camera and place list,
              the moment the panel closes. */}
          {widget.type !== openType &&
            renderWidget(
              widget,
              widget.type === 'geo'
                ? () => {
                    const card = cardRefs.current.get(widget.type);
                    openFrom(widget.type, card?.querySelector('[data-widget-expand]') ?? card);
                  }
                : undefined,
            )}
        </section>
      ))
    );

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
          and that is not a failure anybody would connect back to this line.

          Wrapped in AnimatePresence, which it never was - so its exit variants
          were declared and had never once played. It faded in and vanished. */}
      <AnimatePresence>{overlay}</AnimatePresence>
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
