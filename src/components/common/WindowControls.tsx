import React from 'react';
import { windowControl } from '../../lib/windowChrome';

/**
 * Minimize, maximize/restore and close, drawn by the app.
 *
 * The window is frameless, so these are not decoration - they are the only way
 * out of it short of Alt+F4. Three rules follow from that, and each is a way
 * this can fail silently rather than visibly:
 *
 *  - **`.app-no-drag` on the container.** The title row is a drag region, and a
 *    button inside one without this moves the window instead of being pressed.
 *    The symptom is a close button that does nothing at all.
 *  - **Windows' own metrics, not ours.** 46x32 with a 10px glyph is what
 *    Windows draws, and matching it is not deference: the target size and the
 *    spacing are what fifteen years of muscle memory aims at, and a 32x32
 *    button in the same corner is one people miss. The glyphs are square-edged
 *    SVG strokes for the same reason - a rounded, thickened set reads as a web
 *    page's idea of a window.
 *  - **Close keeps its red.** `#c42b1c` is Windows' own hover fill, and it is
 *    the one colour in the app that is deliberately not a theme token: it is
 *    learned rather than designed, it has to mean the same thing on a light
 *    ground and a dark one, and a close button that hovered to the accent
 *    colour would be the accent colour's least useful appearance.
 *
 * ## Why the glyphs are paths and not an icon font
 *
 * `lucide-react` has no window-control set, and the nearest shapes (`Minus`,
 * `Square`, `X`) are drawn on a 24px grid with a 2px stroke - at 10px they
 * come out heavy and slightly off-centre against each other. These are three
 * one-line paths on a 10px grid, which is the whole of what a caption button is.
 */

/** Windows' own: 46x32, and the reserve in `TitleRow` is three of them. */
const BUTTON = 'w-[46px] h-8 shrink-0 inline-flex items-center justify-center '
  + 'transition-colors cursor-pointer app-no-drag '
  + 'focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-ring';

const Glyph: React.FC<{ d: string; fill?: boolean }> = ({ d, fill }) => (
  <svg
    aria-hidden
    width="10"
    height="10"
    viewBox="0 0 10 10"
    // `shapeRendering: crispEdges` because every stroke here is axis-aligned at
    // integer coordinates: antialiasing a 1px horizontal line at 10px makes the
    // minimise glyph a grey smear rather than a line.
    shapeRendering="crispEdges"
    fill={fill === true ? 'currentColor' : 'none'}
    stroke={fill === true ? 'none' : 'currentColor'}
    strokeWidth="1"
  >
    <path d={d} />
  </svg>
);

export interface WindowControlsProps {
  /** From `useWindowChrome`. Decides the maximize glyph and its label. */
  maximized: boolean;
}

export const WindowControls: React.FC<WindowControlsProps> = ({ maximized }) => (
  <div className="flex items-stretch shrink-0 app-no-drag">
    <button
      onClick={() => windowControl('minimize')}
      aria-label="Minimize"
      title="Minimize"
      className={`${BUTTON} text-foreground/80 hover:bg-accent hover:text-foreground`}
    >
      <Glyph d="M0 5.5 H10" />
    </button>

    <button
      onClick={() => windowControl('toggle-maximize')}
      // The label is the ACTION, not the state: a screen reader reading
      // "maximized" on a button would be announcing where you are, and this is
      // a control for going somewhere else.
      aria-label={maximized ? 'Restore down' : 'Maximize'}
      title={maximized ? 'Restore down' : 'Maximize'}
      className={`${BUTTON} text-foreground/80 hover:bg-accent hover:text-foreground`}
    >
      {maximized
        // Two offset rectangles, Windows' restore glyph - the back one drawn
        // with its lower-left corner open so the two do not read as a grid.
        ? <Glyph d="M2.5 2.5 H9.5 V9.5 H2.5 Z M0.5 7.5 V0.5 H7.5 V2.5" />
        : <Glyph d="M0.5 0.5 H9.5 V9.5 H0.5 Z" />}
    </button>

    <button
      onClick={() => windowControl('close')}
      aria-label="Close"
      title="Close"
      // The only hardcoded colour in the app's chrome, and deliberately so -
      // see the header. White on it in both light and dark, because #c42b1c is
      // dark enough for white at every theme.
      className={`${BUTTON} text-foreground/80 hover:bg-[#c42b1c] hover:text-white`}
    >
      <Glyph d="M0.5 0.5 L9.5 9.5 M9.5 0.5 L0.5 9.5" />
    </button>
  </div>
);
