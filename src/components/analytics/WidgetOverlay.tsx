import React, { useEffect, useLayoutEffect, useRef } from 'react';
import { TbX } from 'react-icons/tb';
import { motion } from 'motion/react';
import { modalBackdropMotion, popoutPanelMotion } from '../../lib/modalMotion';
import { prefersReducedMotion } from '../../lib/motion';

/**
 * The window the geo map opens into, from either of the two controls that open
 * it.
 *
 * It used to be the window ANY widget opened into, and before that there were
 * two of them: the card's expand button put GeoMap into a panel it drew itself,
 * while the rail put the same widget inside a shell the dashboard drew, with
 * its own title bar above the widget's, at a different size, with a different
 * close control. Same widget, same intent, two answers.
 *
 * Now only the map has an expanded form at all. Every other widget is read at
 * card size - in the column, or in the popout bubble its rail icon gives it -
 * because a ranked list of five rows has nothing to say at 1600x1000 that it
 * does not say at 352px. The map is different: its subject is genuinely bigger
 * than a card.
 *
 * It owns the things a hand-rolled panel keeps forgetting: Escape, and putting
 * focus back where it came from. The card path had neither.
 *
 * **It is capped, and not only for taste.** `inset-10` alone means the window
 * is the viewport, which on a 3440px ultrawide is a 2242x1102 panel - and for
 * the geo map that is a 2.5 megapixel canvas redrawn every frame while the
 * globe only ever fills a circle as wide as the panel is TALL. The rest is
 * backdrop being rendered at full cost.
 *
 * Measured on that display, MapLibre's cost is almost exactly linear in canvas
 * area - 2.47 MP took 4.7 ms a frame, 1.11 MP took 2.0 - so the ceiling below
 * is worth roughly a third of the map's per-frame work on a wide screen, and
 * more on a display where `devicePixelRatio` is above 1, since the canvas is
 * scaled by it in both axes.
 *
 * 1600x1000 rather than something larger because of what the extra pixels buy:
 * for the globe, nothing at all past the point where its diameter is bounded by
 * the height. `m-auto` against all four insets is what centres it once a cap
 * binds - and the expanded map now spends the width that buys on a side panel
 * rather than on empty black. See GeoMap.
 */
interface WidgetOverlayProps {
  /** Accessible name for the panel - the widget's own name. */
  label: string;
  onClose: () => void;
  /**
   * Leave the icon rail uncovered.
   *
   * Only true when the rail is what opened this. The rail sits above the scrim
   * so it stays usable while the map is open, and a panel drawn over it would
   * take that back. It is the one thing the two doors cannot share, because in
   * the full column there is no rail to leave room for.
   */
  gutter?: boolean;
  /** The widget's own icon, for the title bar. */
  icon?: React.ComponentType<{ className?: string }>;
  /**
   * The point on screen this window grows out of, in viewport coordinates.
   *
   * A window that fades in at the centre of the screen says nothing about where
   * it came from, which on a dashboard with several ways to open the same thing
   * is the one question the animation could have answered. Given a trigger's
   * position, the panel scales out of it the way the Interfaces menu grows out
   * of its button.
   *
   * Optional, and absent simply means "from your own centre" - so a caller that
   * has no trigger to point at is not obliged to invent one.
   */
  origin?: { x: number; y: number };
  children: React.ReactNode;
}

export const WidgetOverlay: React.FC<WidgetOverlayProps> = ({
  label,
  onClose,
  gutter,
  icon: Icon,
  origin,
  children,
}) => {
  // Captured on mount rather than passed in, so both doors get focus restored
  // without either having to hold a ref to the control that opened it.
  const openerRef = useRef<HTMLElement | null>(
    typeof document === 'undefined' ? null : (document.activeElement as HTMLElement | null),
  );

  useEffect(() => {
    const opener = openerRef.current;
    return () => {
      // Dropping focus to <body> strands a keyboard user at the top of the
      // document, which is a long way from the icon they just closed.
      if (opener?.isConnected) requestAnimationFrame(() => opener.focus());
    };
  }, []);

  /**
   * Points the panel's scale at the control that opened it.
   *
   * Written to the element in a layout effect rather than passed to `motion`,
   * and both halves of that matter. `motion` animates `transform`; the ORIGIN
   * of that transform is a separate CSS property, so an inline value and an
   * animated scale do not fight - the panel simply scales about a different
   * point. And it has to be a layout effect because the first animated frame is
   * painted on mount: set in a passive effect, the panel would grow from its
   * own centre for one frame and then jump.
   *
   * The value is a measurement, not a constant. The panel is centred by
   * `m-auto` against four insets and capped, so where it lands is known only
   * once it has been laid out - hence reading its own rect and expressing the
   * trigger point relative to it.
   */
  const panelRef = useRef<HTMLDivElement | null>(null);
  useLayoutEffect(() => {
    const panel = panelRef.current;
    // Under reduced motion the panel fades without scaling, and an origin for
    // a scale that never happens is just a property nobody reads.
    if (!panel || !origin || prefersReducedMotion()) return;
    const rect = panel.getBoundingClientRect();
    if (rect.width === 0) return;
    panel.style.transformOrigin = `${origin.x - rect.left}px ${origin.y - rect.top}px`;
  }, [origin]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      // Capture phase and stopped, matching the modals: while this is up it is
      // the topmost thing on screen, and Escape belongs to it.
      e.stopPropagation();
      onClose();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onClose]);

  return (
    <>
      {/* No backdrop-filter on this scrim, and none on any of the app's other
          full-viewport scrims either. It looked free and it is - on a GPU.
          Chrome falls back to a SOFTWARE compositor when GPU acceleration is
          off (remote desktop, VMs, a blocklisted or crashed driver), and then
          a full-viewport blur is re-rasterised on the CPU every frame the
          region under it is damaged, which the map does continuously while it
          is dragged. Measured on that path, expanded map, 1598x969, ABAB:

              blur on    15.0 / 13.6 fps   p95 82-113 ms
              blur off   39.9 / 39.4 fps   p95 40-42 ms

          Two and a half times the frame rate from one class. The hardware
          compositor measured 144 fps both ways, which is how it shipped - the
          dim is 70% black and the blur behind it was never really visible. */}
      <motion.div
        {...modalBackdropMotion}
        onClick={onClose}
        className="fixed inset-0 z-30 bg-black/70"
      />
      <motion.div
        ref={panelRef}
        {...popoutPanelMotion}
        role="dialog"
        aria-label={label}
        tabIndex={0}
        className={`fixed inset-4 md:inset-10 m-auto max-w-[1600px] max-h-[1000px] ${
          gutter ? 'mr-16' : ''
        } z-40 rounded-xl border bg-card border-border text-card-foreground shadow-2xl flex flex-col overflow-hidden`}
      >
        {/* A real title bar, which this deliberately did NOT have before.
            The reasoning then was sound and its premise has since gone: four of
            the five widgets drew a heading of their own, so a shell heading
            above them was a second one, and the close control floated over the
            content instead. Widgets draw no chrome at all now - WidgetCard does
            - so what was left here was a window with no name and an X hovering
            in the corner of a map. It is also the same bar every other modal in
            the app has, which is the point. */}
        <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-border shrink-0">
          <h2 className="text-xs font-bold text-muted-foreground uppercase tracking-widest flex items-center gap-1.5 min-w-0">
            {Icon && <Icon className="w-3.5 h-3.5 shrink-0 text-foreground" />}
            <span className="truncate">{label}</span>
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label={`Close ${label}`}
            title="Close"
            className="p-1.5 -mr-1.5 rounded-md text-muted-foreground hover:bg-accent hover:text-foreground transition-colors cursor-pointer shrink-0"
          >
            <TbX className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 min-h-0 overflow-y-auto custom-scrollbar">{children}</div>
      </motion.div>
    </>
  );
};
