/**
 * Telling a double right-click from a right-drag, on a surface where the right
 * button already rotates (the Routing Map's globe).
 *
 * A press is a CLICK only if it comes back up quickly and where it went down,
 * so a short drag never counts as one; two clicks close together in time and
 * place are the double. Pure, so `scripts/session/double-right-click.ts` can
 * hold the thresholds - the effect that uses it in `GeoMap.tsx` is not
 * reachable from a script.
 */

/** Released within this long and this far of where it went down. */
export const RIGHT_CLICK_MAX_MS = 350;
export const RIGHT_CLICK_MAX_PX = 4;
/** The second click within this long and this far of the first. */
export const DOUBLE_RIGHT_CLICK_MS = 450;
export const DOUBLE_RIGHT_CLICK_PX = 8;

export interface PointAt { x: number; y: number; at: number }

export type RightRelease = 'drag' | 'click' | 'double';

/**
 * Feed it every right-button press and release. `release` answers what the
 * press it ends was, and remembers a click so the next one can be its double.
 */
export function createDoubleRightClick(): {
  press: (p: PointAt) => void;
  release: (p: PointAt) => RightRelease;
} {
  let down: PointAt | null = null;
  let lastClick: PointAt | null = null;
  return {
    press(p) { down = p; },
    release(p) {
      const pressed = down;
      down = null;
      const isClick = pressed !== null
        && p.at - pressed.at <= RIGHT_CLICK_MAX_MS
        && Math.hypot(p.x - pressed.x, p.y - pressed.y) <= RIGHT_CLICK_MAX_PX;
      if (!isClick) { lastClick = null; return 'drag'; }
      if (lastClick !== null
        && p.at - lastClick.at <= DOUBLE_RIGHT_CLICK_MS
        && Math.hypot(p.x - lastClick.x, p.y - lastClick.y) <= DOUBLE_RIGHT_CLICK_PX) {
        // Spent: a third click starts a new pair rather than firing again.
        lastClick = null;
        return 'double';
      }
      lastClick = p;
      return 'click';
    },
  };
}
