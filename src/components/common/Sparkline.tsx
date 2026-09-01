import React from 'react';

interface SparklineProps {
  /** Oldest sample first. Fewer than two points renders a flat baseline. */
  values: number[];
  /**
   * Rendered CSS width in px. The drawing itself uses a fixed internal
   * coordinate space (see VIEW_WIDTH), so this can be animated between values
   * without recomputing any geometry - the curve simply stretches.
   */
  width?: number;
  height?: number;
  className?: string;
  /**
   * Shared vertical scale. When several sparklines are compared side by side -
   * as in the interface picker - scaling each to its own maximum makes a
   * near-idle adapter look as busy as a saturated one. Pass the maximum across
   * the whole set to make the heights comparable; omit it to auto-scale.
   */
  max?: number;
  /**
   * How many sample slots the full width represents. Fixes the horizontal
   * scale: with a capacity of 30 each sample is always 1/29th of the width,
   * whether the series holds three points or thirty. Pass the same value the
   * caller trims its history to.
   */
  capacity?: number;
}

// The internal coordinate space. Fixed and independent of the rendered width
// so that growing a sparkline is a pure CSS width transition: with a viewBox
// that changed size too, every growth step would need the points recomputed
// and the animation would have to be driven in JS.
const VIEW_WIDTH = 100;

/**
 * A small inline traffic chart, in the spirit of the sparklines Wireshark
 * draws beside each interface on its welcome screen.
 *
 * Deliberately plain SVG rather than the D3 the analytics panels use: this
 * renders once per adapter per sampling tick inside an open menu, and pulling
 * in a chart library's scales and axes for a 64x16 line would cost more than
 * the whole feature.
 */
export const Sparkline: React.FC<SparklineProps> = ({
  values,
  width = 68,
  height = 16,
  className = '',
  max,
  capacity = 30,
}) => {
  const baseline = height - 1;
  // A single point has no line to draw, and an all-zero series must render as
  // a flat line at the bottom rather than dividing by a zero range.
  const peak = Math.max(max ?? 0, ...values, 0);
  const usable = peak > 0 ? peak : 1;

  // Each sample occupies a FIXED slice of the width, and the newest sits at the
  // right edge, so the trace fills in from the right as history accumulates.
  //
  // Spreading whatever samples exist across the full width instead - x =
  // i/(n-1) - means the first few samples after opening the menu get magnified
  // across the entire chart, so a brand-new sparkline opens absurdly zoomed in
  // and then appears to zoom *out* as it fills. It also makes the horizontal
  // scale differ between adapters that happen to hold different sample counts,
  // which is not a scale at all.
  const slots = Math.max(capacity, 2);
  const step = VIEW_WIDTH / (slots - 1);

  const drawn = values.slice(-slots);
  const points = drawn.length >= 2
    ? drawn.map((value, i) => {
        const x = VIEW_WIDTH - (drawn.length - 1 - i) * step;
        // 1px of headroom top and bottom so a peak is not clipped by the
        // viewBox and a zero does not sit on the very edge.
        const y = baseline - (Math.min(value, usable) / usable) * (height - 2);
        return `${x.toFixed(2)},${y.toFixed(2)}`;
      })
    : [];
  // Where the trace starts, so the filled area is anchored under the line
  // rather than stretched back to x=0 across empty space.
  const firstX = (VIEW_WIDTH - (drawn.length - 1) * step).toFixed(2);

  return (
    <svg
      height={height}
      viewBox={`0 0 ${VIEW_WIDTH} ${height}`}
      // Width as a style rather than an attribute so it transitions. The
      // stroke is vector-effect'd below because preserveAspectRatio="none"
      // would otherwise thicken the line as the box widens.
      style={{ width: `${width}px` }}
      // Slow on purpose. The width is driven by a traffic level that can jump
      // between one 500ms sample and the next, and a snappy transition turns
      // that into a chart that visibly flinches on every tick.
      className={`transition-[width] duration-1000 ease-out ${className}`}
      preserveAspectRatio="none"
      aria-hidden
    >
      {points.length > 0 ? (
        <>
          {/* Filled area under the line, which is what makes a low-rate
              adapter legible at 16px tall - the line alone is one pixel. */}
          <polygon
            points={`${firstX},${baseline} ${points.join(' ')} ${VIEW_WIDTH},${baseline}`}
            className="fill-current opacity-20"
          />
          <polyline
            points={points.join(' ')}
            className="stroke-current"
            fill="none"
            strokeWidth={1}
            strokeLinejoin="round"
            // Without this, the non-uniform scale imposed by
            // preserveAspectRatio="none" stretches the stroke too, so a wide
            // sparkline would draw a noticeably fatter line than a narrow one.
            vectorEffect="non-scaling-stroke"
          />
        </>
      ) : (
        <line
          x1={0}
          y1={baseline}
          x2={VIEW_WIDTH}
          y2={baseline}
          className="stroke-current opacity-30"
          strokeWidth={1}
          vectorEffect="non-scaling-stroke"
        />
      )}
    </svg>
  );
};
