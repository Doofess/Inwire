import { useEffect, useState, type RefObject } from 'react';

export interface ElementSize {
  width: number;
  height: number;
}

/**
 * The measured size of an element, for drawing code that cannot use CSS.
 *
 * The charts here are drawn into an SVG at explicit pixel dimensions, so a
 * container that changes size - the dashboard column being dragged, the pane
 * divider moving, the window resizing - leaves the drawing at whatever size it
 * was built at. `clientWidth` read once inside a draw effect only happens to be
 * right because something else usually triggers a redraw soon after; a chart
 * that is not being fed new data simply stays wrong.
 *
 * Throttled rather than reported per frame. A resize gesture fires this 60 to
 * 120 times a second, and each report tears down and rebuilds a whole D3 scene.
 * A trailing throttle redraws about ten times a second during the drag - which
 * looks continuous - and always lands on the final size, because the trailing
 * edge fires after the last change rather than before it.
 */
export function useElementSize(
  ref: RefObject<Element | null>,
  throttleMs = 100,
): ElementSize {
  const [size, setSize] = useState<ElementSize>({ width: 0, height: 0 });

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    let timer: number | null = null;
    let latest: ElementSize = { width: 0, height: 0 };

    const flush = () => {
      timer = null;
      // Rounded: sub-pixel jitter from a percentage-sized parent would
      // otherwise redraw the scene forever without ever looking different.
      setSize((prev) =>
        prev.width === latest.width && prev.height === latest.height ? prev : latest,
      );
    };

    const observer = new ResizeObserver((entries) => {
      const box = entries[0]?.contentRect;
      if (!box) return;
      latest = { width: Math.round(box.width), height: Math.round(box.height) };
      if (timer === null) timer = window.setTimeout(flush, throttleMs);
    });

    observer.observe(el);
    // The observer fires once on observe, but only asynchronously, so take the
    // first measurement here: a chart that draws before that callback lands
    // would otherwise fall back to its hardcoded default size for one frame.
    const rect = el.getBoundingClientRect();
    latest = { width: Math.round(rect.width), height: Math.round(rect.height) };
    setSize(latest);

    return () => {
      observer.disconnect();
      if (timer !== null) window.clearTimeout(timer);
    };
  }, [ref, throttleMs]);

  return size;
}
