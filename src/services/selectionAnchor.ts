import type { Packet } from '../types/packet';

/**
 * Where a selection goes when the list underneath it changes.
 *
 * ## The behaviour this replaces
 *
 * `App.tsx` reassigned the selection to `filteredPackets[length - 1]` - the
 * NEWEST match - whenever the selected frame stopped being in the list. For a
 * live capture following the tail that is invisible. For somebody reading
 * history it is the whole interaction going wrong: type a filter while looking
 * at frame 12,000 of 700,000 and the app answers by selecting the last frame in
 * the capture and scrolling there. The filter is right and the reader has lost
 * their place.
 *
 * `App.tsx`'s own comment records fixing half of this already - "this effect
 * used to drag the selection back to the newest frame the moment they did" -
 * for frames that left the RAM window. The other half is the filter.
 *
 * So the answer is the **nearest surviving frame in time**: the first match at
 * or after where the reader was, and the last one before if there is nothing
 * after. Frame ids are assigned in arrival order, so "nearest in id" and
 * "nearest in time" are the same question.
 *
 * ## And it is a binary search, which the scan it replaces was not
 *
 * The old test was a reverse linear walk, justified by "the selection is almost
 * always near the tail". That is true while you are following a live capture
 * and false in exactly the case above - a selection near the head of a 700,000
 * frame buffer walked the entire array, on every flush, ten times a second,
 * for as long as it stayed unmatched.
 *
 * Ids are monotonically increasing in both `packets` and any filtered view of
 * it, because a filter preserves order. That is the whole precondition.
 *
 * ## Why this is a module and not ten lines in the effect
 *
 * A `useEffect` in `App.tsx` is unreachable from the assertion suite - the rule
 * the root `CLAUDE.md` states after a `queue.shift()` inside a `find` predicate
 * took the renderer down. Arithmetic worth testing gets lifted somewhere a
 * script can import it; `scripts/session/selection-anchor.ts` is the script.
 */
export interface SelectionAnchor {
  /** The frame to select, or `null` when there is nothing to select. */
  packet: Packet | null;
  /**
   * True when the frame asked for is still in the list.
   *
   * Separate from `packet` because "it is still there" and "here is where to go
   * instead" are different instructions to the caller: the first must not
   * trigger a state update at all, and a caller that only compared identities
   * would set state to the value it already held ten times a second.
   */
  kept: boolean;
}

const ABSENT: SelectionAnchor = { packet: null, kept: false };

/**
 * Finds `id` in an id-ordered list, or the nearest frame to it.
 *
 * Forward before backward: a reader who filters is usually looking for the
 * next thing that matches, and a list whose matches all lie ahead should open
 * at the first of them rather than at the frame behind the reader.
 */
export function anchorSelection(list: readonly Packet[], id: number): SelectionAnchor {
  if (list.length === 0) return ABSENT;

  let lo = 0;
  let hi = list.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const at = list[mid].id;
    if (at === id) return { packet: list[mid], kept: true };
    if (at < id) lo = mid + 1;
    else hi = mid - 1;
  }

  // `lo` is the insertion point: every id before it is smaller, every id from
  // it on is larger. So `lo` is the first frame after the selection and
  // `lo - 1` is the last one before, and exactly one of them exists at each
  // end of the list.
  if (lo < list.length) return { packet: list[lo], kept: false };
  return { packet: list[list.length - 1], kept: false };
}
