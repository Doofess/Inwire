import { useCallback } from 'react';

/**
 * Arrow keys move focus within one container, and must not leave it.
 *
 * Lifted out of `ActivityRail`, where it was written for that strip and had
 * been the only implementation. The side bar's panels need the identical thing
 * - they are columns of plain buttons, which is what the rail is - and writing
 * it a second time is how the two would come to disagree about Home, about
 * wrapping, or about the `stopPropagation` below.
 *
 * ## `stopPropagation` is the load-bearing half
 *
 * `useKeyboardNavigation` listens on `window` for ArrowUp/ArrowDown and moves
 * the packet SELECTION, guarded only against `[role="grid"]`. Without this, an
 * arrow press inside any of these containers would move focus here AND step the
 * selected packet - one key doing two things, in two places, with only one of
 * them visible to whoever is looking at the rail. The old dashboard rail called
 * `preventDefault` alone and carried that bug for its whole life.
 *
 * That is also why this is a shared hook rather than a copied twenty lines: a
 * panel of bare buttons that forgets the `stopPropagation` does not fail, it
 * quietly steps the capture underneath.
 *
 * ## Why it queries the DOM rather than holding refs
 *
 * The containers this serves all have a variable number of buttons - the rail
 * disables Follow Stream when there is no stream, the adapter list is however
 * many adapters the agent reports - and several of them are `disabled` at any
 * moment. `button:not([disabled])` asks the DOM what is focusable right now,
 * which is the one source that cannot go stale between renders.
 */
export type RovingOrientation = 'vertical' | 'horizontal';

const KEYS: Record<RovingOrientation, { next: string; prev: string }> = {
  vertical: { next: 'ArrowDown', prev: 'ArrowUp' },
  horizontal: { next: 'ArrowRight', prev: 'ArrowLeft' },
};

export function useRovingFocus(
  orientation: RovingOrientation = 'vertical',
): (e: React.KeyboardEvent<HTMLElement>) => void {
  return useCallback((e: React.KeyboardEvent<HTMLElement>): void => {
    const { next: nextKey, prev: prevKey } = KEYS[orientation];
    if (e.key !== prevKey && e.key !== nextKey && e.key !== 'Home' && e.key !== 'End') {
      return;
    }
    // **A field keeps its own arrows, and its own Home and End.**
    //
    // The rail had no inputs, so the first version of this did not have to ask.
    // A panel does: the schedule's custom duration, and its start/stop Hour
    // and Minute. Home in a text field is "start of line" and Up in a number
    // field is "increment" - both of which this would have taken, moving FOCUS
    // out of the field somebody was typing in.
    //
    // Answered here rather than by a `stopPropagation` on each input, because
    // the per-input form is a thing every future field has to remember, and
    // forgetting it is silent: the caret does not move and the focus ring
    // lands somewhere else.
    const target = e.target as HTMLElement;
    if (target.closest('input, textarea, select, [contenteditable="true"]') !== null) {
      return;
    }
    const buttons = [...e.currentTarget.querySelectorAll<HTMLButtonElement>(
      'button:not([disabled])',
    )];
    if (buttons.length === 0) return;
    const at = buttons.indexOf(document.activeElement as HTMLButtonElement);
    e.preventDefault();
    e.stopPropagation();
    const step = e.key === nextKey ? 1 : -1;
    const to = e.key === 'Home'
      ? 0
      : e.key === 'End'
        ? buttons.length - 1
        : at < 0
          ? 0
          : (at + step + buttons.length) % buttons.length;
    buttons[to]?.focus();
  }, [orientation]);
}
