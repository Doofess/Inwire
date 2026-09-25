/**
 * Export pages re-emitted in timestamp order, with a page of lookahead.
 *
 * pcap and pcapng readers expect a file in time order, and today's writers
 * sort the buffer before writing it. A whole-capture export cannot sort the
 * whole capture - it never holds it - but it does not need to: frames arrive
 * in capture order, which is arrival order, and out of time order only by the
 * small skew between adapters in a multi-adapter capture or a driver
 * reordering a burst. So a frame is held back until the next page shows
 * nothing earlier can still come, and then released.
 *
 * The rule: when a page arrives, everything already pending with `tsUs` at or
 * below that page's earliest frame is released. What is released can only be
 * overtaken by a frame more than a page out of place, which is a skew this
 * does not claim to repair - the result is then as ordered as the input
 * allowed, never reordered wrongly within what it holds.
 *
 * Ties keep their arrival order, so frames with one timestamp come out in
 * the order they were captured, exactly as a stable sort of the whole would
 * put them.
 *
 * An empty page releases nothing. It says nothing about what can still come -
 * its earliest frame would be +Infinity, and read as a floor that would
 * release everything held, including frames the next page could undercut.
 *
 * ## What it holds
 *
 * The frames not yet released: those newer than the latest page's earliest
 * frame. For input in time order that is at most one page. For input out of
 * order it is bounded by the skew - how far back in time a late frame reaches
 * - times the capture rate: a two-second skew at 50,000 frames a second holds
 * 100,000 frames. A skew wider than a page is what this does not repair, so
 * that product is also the most it is ever worth holding.
 */
import type { Packet } from '../../types/packet';
import type { ExportPage } from './exportFrames';

export async function* orderByTime(
  pages: AsyncIterable<ExportPage>,
): AsyncGenerator<ExportPage> {
  let pending: Packet[] = [];
  let last: ExportPage | null = null;
  /** The page whose counters last went out. */
  let lastYielded: ExportPage | null = null;

  for await (const page of pages) {
    if (page.packets.length === 0) {
      last = page;
      continue;
    }
    let floor = Number.POSITIVE_INFINITY;
    for (const p of page.packets) if (p.tsUs < floor) floor = p.tsUs;

    // `pending` is sorted, so what may go is a prefix of it. Released before
    // this page joins, so a tie between a pending frame and a new one goes
    // out in arrival order.
    let release = 0;
    while (release < pending.length && pending[release].tsUs <= floor) release++;
    const out = pending.slice(0, release);
    // `Array.prototype.sort` is stable, and the concatenation is in arrival
    // order, so equal timestamps keep it.
    pending = pending.slice(release).concat(page.packets).sort((a, b) => a.tsUs - b.tsUs);

    // The counters are the newest page's. They run a page ahead of what has
    // been released, which for a progress bar is invisible.
    last = page;
    if (out.length > 0) {
      lastYielded = page;
      yield { ...page, packets: out };
    }
  }

  if (last !== null && pending.length > 0) yield { ...last, packets: pending };
  // The final counters still go out when nothing is left to release with
  // them - an empty last page is how `exportFrames` reports a torn tail that
  // no frame followed.
  else if (last !== null && last !== lastYielded) yield { ...last, packets: [] };
}
