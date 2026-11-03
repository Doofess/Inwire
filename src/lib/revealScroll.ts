/**
 * The scroll that shows a box from `top` to `bottom`, moving as little as it
 * can - or not at all when the box is already in view.
 *
 * All four numbers are in the scroller's content coordinates. A box taller
 * than the viewport shows its top, which is where a ladder row's chip and a
 * side-bar section's title are.
 *
 * Shared by Follow Stream's ladder (`ladderFollow.ts`), whose nudged rows can
 * sit below a box that holds the right time window, and the Export / Import
 * panel, whose last section is below the fold at the minimum window.
 */
export function revealScroll(scrollTop: number, viewport: number, top: number, bottom: number): number {
  if (top < scrollTop || bottom - top > viewport) return top;
  if (bottom > scrollTop + viewport) return bottom - viewport;
  return scrollTop;
}

/**
 * Scrolls `el`'s nearest scrolling ancestor, and only that one, until `el` is
 * in view.
 *
 * Not `scrollIntoView`: that also moves every `overflow-hidden` ancestor up to
 * the document, and in this shell that shifts `<main>` and the whole card
 * cluster out from under the title row. The jump is instant, so there is no
 * motion for the reduced-motion setting to suppress.
 */
export function revealInScroller(el: HTMLElement): void {
  let scroller = el.parentElement;
  while (scroller !== null) {
    const { overflowY } = getComputedStyle(scroller);
    if ((overflowY === 'auto' || overflowY === 'scroll') && scroller.scrollHeight > scroller.clientHeight) break;
    scroller = scroller.parentElement;
  }
  if (scroller === null) return;
  const top = el.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scroller.scrollTop;
  scroller.scrollTop = revealScroll(scroller.scrollTop, scroller.clientHeight, top, top + el.offsetHeight);
}
