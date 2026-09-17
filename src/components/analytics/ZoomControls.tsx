import React from 'react';
import { Plus, Minus, RotateCw } from 'lucide-react';

interface ZoomControlsProps {
  /** Omit a handler to leave that button out. */
  onZoomIn?: () => void;
  onZoomOut?: () => void;
  /** Return to the default view. Only shown when there is something to undo. */
  onReset?: () => void;
  /**
   * Rendered above the zoom buttons, in the same column.
   *
   * A slot rather than a second absolutely-positioned stack beside this one:
   * two independent `absolute right-2 bottom-2` containers would have to agree
   * on each other's height to avoid overlapping, and would drift the moment
   * either gained a button. One flex column cannot disagree with itself.
   *
   * The map passes its projection switcher here. The timeline chart passes
   * nothing and renders exactly as before.
   */
  leading?: React.ReactNode;
}

/**
 * The floating zoom buttons used by the analytics panels that can be expanded.
 *
 * Shared rather than copied, because the two panels that need them had drifted
 * into different answers to the same question: the map used MapLibre's built-in
 * control - a joined pill whose glyphs were `background-image` data URIs that
 * the dark themes recoloured with `filter: invert(1)` - while the timeline had
 * its own small bordered squares. Same control, two appearances, neither
 * matching the app's other floating chrome.
 *
 * What this settles for both:
 *
 *   - **Inline SVG glyphs**, so they are resolution-independent by
 *     construction: the browser rasterises the path at the device's real pixel
 *     ratio, and the stroke takes `currentColor` from the theme rather than a
 *     filter approximating it.
 *   - **Separated circles.** These are independent actions that happen to be
 *     related, not one segmented control, and at this size a circle reads as a
 *     button over a chart or a map far better than a rounded square whose
 *     corners compete with the content behind it.
 *   - **The same shell as the map's location counter**, so every floating
 *     control in the app is recognisably the same kind of object.
 */
export const ZoomControls: React.FC<ZoomControlsProps> = ({ onZoomIn, onZoomOut, onReset, leading }) => {
  const buttonClass =
    'flex h-9 w-9 items-center justify-center rounded-full border border-border '
    + 'bg-card/80 text-foreground shadow-sm backdrop-blur-sm transition-colors '
    + 'hover:bg-accent active:scale-95 cursor-pointer';

  // Bottom right, which is where every map anyone has used puts zoom - and,
  // more to the point, out from under the panel's close button. These only
  // render in the expanded view, and there they sat directly beneath that X:
  // three round controls in one vertical run, one of which closed the window,
  // and the X the odd one out because it is the PANEL's control rather than
  // the map's. The location counter owns the bottom left, so this corner was
  // free.
  return (
    <div className="absolute right-2 bottom-2 z-10 flex flex-col gap-2 pointer-events-auto">
      {leading}
      {onZoomIn && (
        <button type="button" onClick={onZoomIn} aria-label="Zoom in" title="Zoom in" className={buttonClass}>
          <Plus className="h-4 w-4" />
        </button>
      )}
      {onZoomOut && (
        <button type="button" onClick={onZoomOut} aria-label="Zoom out" title="Zoom out" className={buttonClass}>
          <Minus className="h-4 w-4" />
        </button>
      )}
      {onReset && (
        <button type="button" onClick={onReset} aria-label="Reset zoom" title="Reset zoom" className={buttonClass}>
          <RotateCw className="h-4 w-4" />
        </button>
      )}
    </div>
  );
};
