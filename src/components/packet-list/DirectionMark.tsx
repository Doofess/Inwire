import React from 'react';
import { Direction } from '../../services/direction';

/**
 * The four direction marks the packet list draws, as one drawn set.
 *
 * ## Why these are not characters any more
 *
 * They were `↑ ↓ ↔ ·`, in the list's own `font-mono`, and three of the four
 * were fine. The fourth was not, for a reason that is a fact about the font
 * rather than a matter of taste: **`↔` (U+2194) is in no JetBrains Mono
 * subset.** Fontsource ships six `@font-face` ranges and the latin one names
 * `U+2191` and `U+2193` explicitly - the two vertical arrows - and stops there.
 * So the transit glyph alone fell out of the app's typeface and was drawn by
 * whatever Windows substituted, at that font's weight, width and baseline,
 * next to three neighbours from a different one. That is what "smudged" was:
 * a fallback glyph squeezed into one monospace advance, with a shaft and two
 * heads to fit where the vertical arrows had the whole line height to work in.
 *
 * Widening it as text is not available. A monospace glyph's ink width is the
 * typeface's decision, `scaleX` distorts the strokes it widens, and no
 * horizontal arrow exists in the subsets this app loads to swap it for. Drawn,
 * the transit mark gets the full box across - 11.2 units where the vertical
 * arrows get 10 down - and all four carry one stroke width, one box and one
 * baseline, which is the only form in which "aligns with the rest" is a
 * property rather than a coincidence.
 *
 * It is also independent of the typeface, which the characters were not: an
 * arrow drawn as a path does not care which glyphs the mono face carries, and
 * arrow coverage varies by font.
 *
 * ## Why no colour
 *
 * Unchanged, and it is the older decision: the row's fill is already the
 * colouring rule's answer, and a second colour scheme running down the same row
 * would compete with it for the same meaning.
 */

/** 16-unit box, so the numbers below read as sixteenths of the rendered size. */
const MARKS: Record<Direction, React.ReactNode> = {
  // A dot, not an arrow: nothing identified the capturing host, and a fourth
  // arrow direction would be a fourth answer rather than the absence of one.
  [Direction.Unknown]: <circle cx="8" cy="8" r="1.6" fill="currentColor" stroke="none" />,
  [Direction.Out]: <path d="M8 13.4V3.4M4.5 6.9 8 3.4l3.5 3.5" />,
  [Direction.In]: <path d="M8 2.6v10M4.5 9.1 8 12.6l3.5-3.5" />,
  // Wider than the vertical pair is deliberate and is the whole fix: a
  // horizontal arrow spends its length on two heads and keeps only what is
  // left for the shaft, so matching their 10 units would read as shorter.
  [Direction.Transit]: <path d="M2.8 8h10.4M6 4.8 2.8 8 6 11.2M10 4.8 13.2 8 10 11.2" />,
};

export const DirectionMark: React.FC<{ direction: Direction }> = ({ direction }) => (
  <svg
    viewBox="0 0 16 16"
    className="w-3 h-3 inline-block align-middle"
    fill="none"
    stroke="currentColor"
    // 1.75 of 16 is 1.31px at the 12px the mark renders at, which is where a
    // JetBrains Mono stem sits at this list's text sizes. Thinner reads as a
    // hairline against the digits in the columns either side.
    strokeWidth={1.75}
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    {MARKS[direction]}
  </svg>
);
