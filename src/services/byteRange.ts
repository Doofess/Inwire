import { useSyncExternalStore } from 'react';

/**
 * The byte range highlighted across the packets view's two bottom panes.
 *
 * ## Why this is a store and not `useState` in `App`
 *
 * It was App state, and it is the cross-highlight between two SIBLING panes -
 * hover a field in the tree and its bytes light up in the dump; hover a byte in
 * the dump and its field lights up in the tree. Sibling state lives in the
 * common parent, and the common parent is `App`, so every pointer move over a
 * byte set state at the top of the application and re-rendered the entire tree
 * below it: the packet list, the status bar, both panes.
 *
 * That is invisible on a 54-byte frame and not invisible on a 64KB one. The
 * dump virtualizes by pixels, so a full-height column of a large frame mounts
 * something like 79 rows, and a row is one `<span>` per byte twice - hex and
 * ASCII. Moving the pointer across the dump rebuilt all of it, plus everything
 * else App renders, once per byte.
 *
 * **The same regression has shipped here once before**, with the packet counter
 * threaded down through props while App re-rendered ten times a second during a
 * capture (`b0ce1fc`). `services/packetCounts.ts` was the answer then and this
 * is the same answer: the panes that care subscribe, and App is not on the path
 * at all.
 *
 * ## Why it is not `hoveredByte.ts`
 *
 * Those two stores look alike and are opposites, which is worth stating plainly
 * because merging them would undo a deliberate design.
 *
 * `hoveredByte` carries a byte's VALUE, specifically so that only code holding
 * the bytes can publish one - which makes a hex dump the only possible
 * publisher and a protocol tree structurally unable to be one. That store
 * exists to keep the tree OUT.
 *
 * This one carries a RANGE, and the tree is a first-class publisher of it: a
 * field is a range, and lighting up its bytes is the whole point. The two
 * stores answer different questions about the same pointer.
 *
 * ## Ownership
 *
 * Both panes are mounted at once, so a `clear` from the pane the pointer is
 * LEAVING must not blank a range the other one just published. Clearing names
 * its source and is a no-op unless that source owns the current range - the
 * same rule, for the same reason, as `hoveredByte.ts`.
 *
 * `resetByteRange` is the deliberate exception: Clear and Discard throw the
 * selection away, and there is then no frame for any range to describe.
 *
 * ## Scope
 *
 * The packets view only. `PacketDetailPane` keeps its own `useState` and does
 * not subscribe, which is a decision its own comment already records: it is one
 * pane owning both halves of its cross-highlight, so its state has a real
 * common parent and needs no store. It is also already off App's render path,
 * which is what this store buys the packets view.
 */

export type ByteRangeSource = 'packets-tree' | 'packets-hex';

export interface ActiveByteRange {
  /** Which pane put this range here, or `null` when nothing is highlighted. */
  source: ByteRangeSource | null;
  range: [number, number] | null;
}

const EMPTY: ActiveByteRange = { source: null, range: null };

let current: ActiveByteRange = EMPTY;
const listeners = new Set<() => void>();

/**
 * Field by field, because the panes rebuild this object on every pointer move
 * inside a single byte cell - `onMouseEnter` fires per element, and a range is
 * a fresh array every time. An identity compare would wake both subscribers on
 * every move that changed nothing.
 */
function same(a: ActiveByteRange, b: ActiveByteRange): boolean {
  return a.source === b.source
    && a.range?.[0] === b.range?.[0]
    && a.range?.[1] === b.range?.[1];
}

function set(next: ActiveByteRange): void {
  if (same(current, next)) return;
  current = next;
  for (const listener of listeners) listener();
}

/** Takes ownership of the highlight, whoever held it before. */
export function publishByteRange(source: ByteRangeSource, range: [number, number]): void {
  set({ source, range });
}

/** Releases the highlight, but only if this source is the one holding it. */
export function clearByteRange(source: ByteRangeSource): void {
  if (current.source !== source) return;
  set(EMPTY);
}

/** Unconditional. For Clear and Discard, where the frame itself is going. */
export function resetByteRange(): void {
  set(EMPTY);
}

export function subscribeByteRange(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export function readByteRange(): ActiveByteRange {
  return current;
}

/**
 * The range itself, which is all either pane needs - neither draws anything
 * different depending on which of them published it.
 */
export function useActiveByteRange(): [number, number] | null {
  return useSyncExternalStore(subscribeByteRange, readByteRange, readByteRange).range;
}
