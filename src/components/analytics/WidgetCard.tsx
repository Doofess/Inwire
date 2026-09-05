import React from 'react';
import { TbMaximize } from 'react-icons/tb';

/**
 * The frame every dashboard widget is drawn in, wherever it is drawn.
 *
 * Before this, each widget drew its own card, and no two drew the same one.
 * Measured across the five that shipped: heading sizes of 11px and 12px, body
 * padding of 0, 14px and 16px, one header divider out of five, the expand
 * control in three different places, and the same two-way toggle drawn bare in
 * the timeline and inside a bordered box in Top Talkers - two cards that sit
 * one above the other in the same column.
 *
 * With a fixed set of five that was untidy. With a dashboard the user BUILDS it
 * stops being cosmetic: someone who adds three widgets gets three header
 * treatments, and the rail's popout bubble inherits whichever card it happens
 * to wrap. So the chrome is drawn once, here, and a widget renders only its
 * body.
 *
 * Three things this owns that the widgets kept forgetting:
 *
 * **A height.** Protocol Breakdown collapsed to a 40px header stub when it had
 * nothing to show, so the whole column jumped as the first packets arrived.
 * `className` carries a shape from the registry - the way the map already
 * carried `aspect-[11/8]` - and it applies whether or not there is data.
 *
 * **An empty state.** The timeline drew a blank 180px void with two orphaned
 * axis labels beneath it. It matters most before a capture has started, which
 * is the first thing anybody sees of the dashboard.
 *
 * **The expand control.** One button, one place, one icon - and only the map
 * passes `onExpand` now, since it is the only widget with a window of its own.
 */

interface WidgetCardProps {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  /** The widget's own controls, right-aligned in the header. */
  controls?: React.ReactNode;
  /**
   * Opens this widget's expanded window.
   *
   * Only the geo map has one. Everything else is either read at card size or
   * popped out of the rail at card size, which is the same card.
   */
  onExpand?: () => void;
  /**
   * The body reaches the frame's edge, and the header grows a divider.
   *
   * For a widget that paints to its own bounds - the map - where body padding
   * would show as a card-coloured margin around a canvas and the header would
   * otherwise float on top of the paint with nothing separating them.
   */
  bleed?: boolean;
  /** Draws the empty state instead of `children`. */
  isEmpty?: boolean;
  /** One line, in the widget's own words. Shown under the icon when empty. */
  emptyMessage?: string;
  /** The shape the card holds whether or not it has data. From the registry. */
  className?: string;
  /** A computed height, for the widgets whose shape depends on their settings. */
  style?: React.CSSProperties;
  children: React.ReactNode;
}

export const WidgetCard: React.FC<WidgetCardProps> = ({
  icon: Icon,
  title,
  controls,
  onExpand,
  bleed,
  isEmpty,
  emptyMessage,
  className,
  style,
  children,
}) => (
  <div
    style={style}
    className={`rounded-lg border border-border bg-card text-card-foreground shadow-sm flex flex-col overflow-hidden transition-colors select-none ${
      className ?? ''
    }`}
  >
    <div
      className={`flex items-center justify-between gap-3 px-3.5 shrink-0 ${
        // A divider only when the body bleeds. Everywhere else the padding
        // already separates the heading from the content, and a rule there is
        // a second horizontal line inside a card that is itself outlined.
        bleed ? 'py-2.5 border-b border-border' : 'pt-3 pb-2'
      }`}
    >
      <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-widest flex items-center gap-1.5 min-w-0">
        <Icon className="w-3.5 h-3.5 shrink-0 text-foreground" />
        <span className="truncate">{title}</span>
      </h3>

      <div className="flex items-center gap-1.5 shrink-0">
        {controls}
        {onExpand && (
          <button
            type="button"
            onClick={onExpand}
            // Where focus returns when the window this opens is closed. The
            // card is unmounted while that window is up, so the button that
            // opened it no longer exists by the time it closes.
            data-widget-expand=""
            aria-label={`Expand ${title}`}
            title={`Expand ${title}`}
            className="p-1 -mr-1 rounded text-muted-foreground hover:bg-accent hover:text-foreground transition-colors cursor-pointer"
          >
            <TbMaximize className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>

    <div className={`flex-1 min-h-0 ${bleed ? '' : 'px-3.5 pb-3.5'}`}>
      {isEmpty ? (
        <div className="h-full w-full flex flex-col items-center justify-center gap-2 text-center px-4">
          <Icon className="w-6 h-6 text-muted-foreground/40" aria-hidden />
          <p className="text-[11px] text-muted-foreground/80 leading-snug max-w-[28ch]">
            {emptyMessage}
          </p>
        </div>
      ) : (
        children
      )}
    </div>
  </div>
);
