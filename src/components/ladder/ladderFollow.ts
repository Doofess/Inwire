/**
 * When the ladder moves its own window, and when it scrolls to a frame
 * (ADR 0055; final review I4 and I5). Pure, so a script can hold the decisions
 * `LadderView` makes in effects a test cannot reach.
 */
import { revealScroll } from './ladderLayout';

/**
 * What asks the ladder to choose its time window again.
 *
 * - `stream`: a different stream (or client end). Always, and the user's
 *   earlier zoom belongs to the one that went.
 * - `page`: the same stream's frames grew by a page, or the read finished. The
 *   first choice was made from one page, so it is made again while nobody has
 *   touched the window - but a page arrives every ~100 ms, and choosing again
 *   after a zoom, a pan, a minimap drag or a click on the state map would undo
 *   what the user just did.
 */
export type WindowTrigger = 'stream' | 'page';

export function rechoosesWindow(trigger: WindowTrigger, userActed: boolean): boolean {
  return trigger === 'stream' || !userActed;
}

/**
 * One pass of the reveal: the frame just brought into the time window, scrolled
 * into the ladder's box once the layout has placed its row.
 *
 * `placed` is the row's extent in the box's own coordinates, or null while it
 * is not drawn (the window set above lands on a later render, or the frame is
 * past the cap on rows) - the request then stays pending. Placed, it is
 * answered once, whether or not the box had to move.
 */
export function revealStep(
  pending: number | null, placed: { top: number; bottom: number } | null,
  scrollTop: number, viewport: number,
): { pending: number | null; scrollTop: number } {
  if (pending === null || placed === null) return { pending, scrollTop };
  return { pending: null, scrollTop: revealScroll(scrollTop, viewport, placed.top, placed.bottom) };
}
