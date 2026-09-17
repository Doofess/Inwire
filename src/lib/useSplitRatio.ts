import { RefObject, useCallback, useEffect, useRef, useState } from 'react';

interface SplitOptions {
  /** Where the divider sits before the user touches it, as a 0-1 fraction. */
  initial: number;
  /**
   * The narrowest each pane may be, in pixels - given separately because the
   * two sides rarely deserve the same floor. A field table can be read at
   * almost any width; a hex dump has an exact one below which its ASCII
   * gutter, the half people actually read, stops fitting.
   */
  minFirstPx: number;
  minSecondPx: number;
}

export interface Split {
  /** Fraction of the container width given to the FIRST pane. */
  ratio: number;
  /**
   * `ratio` clamped so both floors hold at the given container width.
   *
   * Dragging is not the only thing that can put the divider somewhere it does
   * not fit: a ratio restored from a previous, wider session, or a window the
   * user simply made smaller, both arrive here already out of range. Render
   * against this rather than `ratio` so the panes are never drawn narrower
   * than they can be dragged.
   */
  clampTo: (containerWidthPx: number) => number;
  /** Put this on the drag handle. */
  onHandleMouseDown: () => void;
  /** Put this on the handle too - the conventional "even it out" gesture. */
  reset: () => void;
}

/**
 * A draggable vertical divider between two panes.
 *
 * Lifted from the workspace splitter in App.tsx, which had these three things
 * right and is worth copying rather than re-deriving:
 *
 *   1. The position is measured against the CONTAINER's bounding rect, not the
 *      window, so the ratio stays correct no matter what sits to the left or
 *      right of it - which is the whole difference between this working inside
 *      a pane inset from the window's edges and only working full-bleed.
 *   2. The listeners live on `window`, not the handle, so a fast drag that
 *      outruns the cursor does not drop the gesture.
 *   3. `body`'s cursor and `user-select` are set for the duration, so the
 *      cursor does not flicker between panes and the drag does not select text
 *      across the whole document.
 *
 * The listeners are registered once and read the moving parts through a ref:
 * this runs inside a window whose `packets` prop changes identity on every
 * 100ms flush during capture, and a dependency on anything re-rendered would
 * tear down and re-register these ten times a second.
 */
export function useSplitRatio(
  containerRef: RefObject<HTMLElement | null>,
  { initial, minFirstPx, minSecondPx }: SplitOptions,
): Split {
  const [ratio, setRatio] = useState(initial);
  const draggingRef = useRef(false);
  const optionsRef = useRef({ containerRef, minFirstPx, minSecondPx });
  optionsRef.current = { containerRef, minFirstPx, minSecondPx };

  const clampTo = useCallback(
    (width: number) => {
      if (width <= 0) return ratio;
      const lo = minFirstPx / width;
      const hi = 1 - minSecondPx / width;
      // Too narrow to honour both floors. Nothing sensible to clamp to, so
      // leave the ratio alone rather than pick a side to violate.
      if (lo > hi) return ratio;
      return Math.max(lo, Math.min(ratio, hi));
    },
    [ratio, minFirstPx, minSecondPx],
  );

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!draggingRef.current) return;
      const { containerRef: ref, minFirstPx: minFirst, minSecondPx: minSecond } = optionsRef.current;
      const el = ref.current;
      if (!el) return;

      const { left, width } = el.getBoundingClientRect();
      const lo = minFirst / width;
      const hi = 1 - minSecond / width;
      if (lo > hi) return;

      const next = (e.clientX - left) / width;
      setRatio(Math.max(lo, Math.min(next, hi)));
    };

    const onMouseUp = () => {
      if (!draggingRef.current) return;
      draggingRef.current = false;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
    return () => {
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      // A drag interrupted by unmount - closing the window mid-gesture - must
      // not leave the whole document stuck with a resize cursor.
      onMouseUp();
    };
  }, []);

  const onHandleMouseDown = useCallback(() => {
    draggingRef.current = true;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, []);

  const reset = useCallback(() => setRatio(initial), [initial]);

  return { ratio, clampTo, onHandleMouseDown, reset };
}
