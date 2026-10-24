/**
 * Packet marks: the set, walking it, and its file (ADR 0067).
 *
 * A mark is a fact about a capture, not about a frame: the user sets and clears
 * it after the frame was stored, so it cannot live in a row. It is a set of
 * frame ids - `Packet.id`, the number `frame.number` reads, which is stable
 * across a reopen because numbering resumes past the highest stored id - kept
 * beside the capture by the store and never written into the pcapng.
 *
 * Pure: no Electron, no `node:*`. The store holds the file (`captureHost.ts`),
 * the filter reads the set through its context (`filter/fields.ts`).
 */

export type Marks = ReadonlySet<number>;

/** A new set with `id` marked, or unmarked if it was. The argument is never changed. */
export function toggleMark(marks: Marks, id: number): Marks {
  const next = new Set(marks);
  if (!next.delete(id)) next.add(id);
  return next;
}

/**
 * The next id to jump to: from `from` (exclusive) in direction `dir`, wrapping
 * once as Wireshark does, the first that is `eligible`; null when none is.
 *
 * `sortedIds` is ascending. `from` need not be in it (the selected row is
 * usually not marked), and null starts before the first / after the last.
 * `eligible` is how the caller leaves out a mark the ring has expired or the
 * current filter hides, without this knowing why. The walk covers every entry
 * once, `from` itself last, so a lone eligible mark at `from` answers itself.
 */
export function nextMarked(
  sortedIds: readonly number[],
  from: number | null,
  dir: 1 | -1,
  eligible: (id: number) => boolean,
): number | null {
  const n = sortedIds.length;
  if (n === 0) return null;
  // The first position to try: the lowest index above `from`, or the highest below.
  let start: number;
  if (from === null) {
    start = dir === 1 ? 0 : n - 1;
  } else {
    let lo = 0;
    let hi = n;
    // Lowest index whose id is > from (dir 1) or >= from (dir -1, minus one below).
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (dir === 1 ? sortedIds[mid] <= from : sortedIds[mid] < from) lo = mid + 1;
      else hi = mid;
    }
    start = dir === 1 ? lo : lo - 1;
  }
  for (let step = 0; step < n; step++) {
    const at = (((start + step * dir) % n) + n) % n;
    if (eligible(sortedIds[at])) return sortedIds[at];
  }
  return null;
}

/** The marks file's version. A reader that finds another treats the file as torn. */
const VERSION = 1;
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder('utf-8', { fatal: true });

/**
 * The bytes of `marks.iwmrk`: JSON `{"v":1,"ids":[...]}`, ids ascending.
 *
 * JSON because the set is small (a person marked these by hand), a truncated
 * JSON document never parses, and a file a person can read when asked for it.
 */
export function encodeMarks(ids: Marks): Uint8Array {
  const sorted = [...ids].sort((a, b) => a - b);
  return ENCODER.encode(JSON.stringify({ v: VERSION, ids: sorted }));
}

/**
 * The ids in a marks file, ascending, or null when it is torn, empty, another
 * version or not ours. Null means "no marks": the capture still opens.
 */
export function decodeMarks(bytes: Uint8Array): number[] | null {
  if (bytes.length === 0) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(DECODER.decode(bytes));
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) return null;
  const { v, ids } = parsed as { v?: unknown; ids?: unknown };
  if (v !== VERSION || !Array.isArray(ids)) return null;
  const out: number[] = [];
  for (const id of ids) {
    if (typeof id !== 'number' || !Number.isSafeInteger(id) || id < 0) return null;
    out.push(id);
  }
  return [...new Set(out)].sort((a, b) => a - b);
}
