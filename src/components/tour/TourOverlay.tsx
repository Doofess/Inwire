import React, { useCallback, useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { Button } from '../ui/button';
import { Popover, PopoverAnchor, PopoverArrow, PopoverContent } from '../ui/popover';
import { TOUR_STEPS } from './tourSteps';

/**
 * The first-run walkthrough: a spotlight on one element at a time, with a card
 * beside it.
 *
 * **The spotlight is a box-shadow, not a mask.** One absolutely-positioned
 * element sits over the target's rect with `box-shadow: 0 0 0 9999px <scrim>`,
 * so the shadow darkens the entire rest of the viewport and the element's own
 * box stays clear. The alternatives - an SVG mask, or four divs walling off the
 * target - both need the geometry restated every time the target moves, and the
 * four-div version leaves hairlines at the corners on fractional device pixel
 * ratios. This is one rect and one property.
 *
 * **The card is a Radix Popover anchored to that same rect.** Placement beside
 * an arbitrary element is the part of this that is genuinely fiddly - flipping
 * when there is no room on the preferred side, keeping the arrow pointed
 * through that flip, staying inside the viewport - and `ui/popover.tsx` already
 * has all of it, along with the app's shared open/close animation. The anchor
 * is a zero-size div positioned at the rect, which is how you point Radix at
 * something that is not its own trigger.
 *
 * **The spotlight does not block clicks on the target.** `pointer-events: none`
 * on the ring: the tour describes the app rather than driving it, and someone
 * who wants to press Start Capture while it is highlighted should be able to.
 *
 * Motion comes from `motion/react`, so it inherits the `MotionConfig` in
 * `main.tsx` and honours the Motion setting for free. A tour that animates past
 * someone who asked for no animation is a poor advertisement for the tab it is
 * launched from.
 */

/** How far the ring stands off the element it is highlighting. */
const PADDING = 6;

interface Rect {
  top: number;
  left: number;
  width: number;
  height: number;
}

function rectOf(anchor: string): Rect | null {
  const el = document.querySelector(`[data-tour="${anchor}"]`);
  if (!el) return null;
  const r = el.getBoundingClientRect();
  // A target inside a collapsed pane measures zero and would put the spotlight
  // in the corner over nothing.
  if (r.width === 0 || r.height === 0) return null;
  return {
    top: r.top - PADDING,
    left: r.left - PADDING,
    width: r.width + PADDING * 2,
    height: r.height + PADDING * 2,
  };
}

export const TourOverlay: React.FC<{
  /** Finishing and skipping both call this. See services/tourPrefs. */
  onDone: () => void;
}> = ({ onDone }) => {
  const steps = TOUR_STEPS;

  const [index, setIndex] = useState(0);
  const [rect, setRect] = useState<Rect | null>(null);

  const step = steps[index];

  // Re-measured on every frame the layout could have moved under: scrolling a
  // pane, resizing the window, and the panes' own resize handles - which is why
  // this is a ResizeObserver on <body> rather than a window resize listener.
  useEffect(() => {
    if (!step) return;
    const measure = () => setRect(rectOf(step.anchor));
    measure();

    const observer = new ResizeObserver(measure);
    observer.observe(document.body);
    // Capture phase, so a scroll inside any pane is seen and not just the
    // document's own.
    window.addEventListener('scroll', measure, true);
    window.addEventListener('resize', measure);
    return () => {
      observer.disconnect();
      window.removeEventListener('scroll', measure, true);
      window.removeEventListener('resize', measure);
    };
  }, [step]);

  const next = useCallback(() => {
    setIndex((i) => {
      if (i + 1 < steps.length) return i + 1;
      onDone();
      return i;
    });
  }, [steps.length, onDone]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onDone();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onDone]);

  // A step whose target is not on screen is skipped rather than shown against a
  // spotlight over nothing - the pane may be collapsed, or the window too
  // narrow for that control.
  useEffect(() => {
    if (step && rect === null) {
      const timer = setTimeout(() => {
        if (rectOf(step.anchor) === null) next();
      }, 400);
      return () => clearTimeout(timer);
    }
  }, [step, rect, next]);

  if (!step || !rect) return null;

  const last = index === steps.length - 1;

  return (
    <>
      <motion.div
        // aria-hidden: the card below carries the whole message, and a scrim
        // that announced itself would be read before it.
        aria-hidden
        className="fixed z-[60] rounded-lg pointer-events-none ring-2 ring-primary"
        style={{
          top: rect.top,
          left: rect.left,
          width: rect.width,
          height: rect.height,
          boxShadow: '0 0 0 9999px rgb(0 0 0 / 0.62)',
        }}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.18 }}
      />

      <Popover open>
        <PopoverAnchor asChild>
          <div
            className="fixed pointer-events-none"
            style={{ top: rect.top, left: rect.left, width: rect.width, height: rect.height }}
          />
        </PopoverAnchor>
        <PopoverContent
          side={step.side}
          className="z-[61] w-80 p-4"
          // The tour is not modal and must not steal focus from the control it
          // is describing - someone should be able to press the highlighted
          // button while reading about it.
          onOpenAutoFocus={(e) => e.preventDefault()}
        >
          <PopoverArrow />
          <div className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
            Step {index + 1} of {steps.length}
          </div>
          <h3 className="mt-1 text-sm font-semibold text-foreground">{step.title}</h3>
          <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{step.body}</p>
          <div className="mt-3.5 flex items-center justify-between gap-3">
            <Button variant="ghost" size="xs" onClick={onDone}>
              Skip
            </Button>
            <div className="flex items-center gap-2">
              {index > 0 && (
                <Button variant="outline" size="xs" onClick={() => setIndex((i) => i - 1)}>
                  Back
                </Button>
              )}
              <Button size="xs" onClick={next}>
                {last ? 'Done' : 'Next'}
              </Button>
            </div>
          </div>
        </PopoverContent>
      </Popover>
    </>
  );
};
