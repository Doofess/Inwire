import { useSyncExternalStore } from 'react';

/**
 * The byte under the pointer, for the status bar to read.
 *
 * ## Why this module exists at all
 *
 * The application's first bottom bar carried the byte inspector and could not
 * reach `HexViewer`'s local hover state, so it was handed a byte derived in
 * `App` from `activeByteRange` - which is **also** what the protocol tree
 * publishes for a one-byte field. The bar therefore answered "this byte" for a
 * hover in a pane that was not the dump. That conflation is the second of the
 * two reasons the bar was deleted (the first was the indent; see
 * `components/status/StatusBar.tsx`).
 *
 * ## The one design decision, which is that it carries the VALUE
 *
 * A store carrying an index would leave the bar holding a number it could not
 * render, because the bar lives outside both panes and has no frame. `App`
 * would then have to thread the selected frame into it - a second source of
 * truth for the thing that went wrong the first time, and a prop that changes
 * on every selection.
 *
 * Carrying the byte itself means **the only code that can put a byte in the bar
 * is code that already had the bytes in hand**. That is a hex dump, and it is
 * never a tree: `PacketDetailsTree` publishes a byte RANGE, has no value to
 * offer and no call into this module. The conflation is not avoided here, it is
 * unrepresentable.
 *
 * ## Two dumps, not one
 *
 * The Packets view's `HexViewer` and the Frame Detail view's own dump are both
 * legitimate publishers, and the Packets view stays **mounted behind
 * `display: none`** while Frame Detail is up. So a clear has to name its
 * source: the pane that is leaving must not be able to blank a byte the other
 * pane just published. `clearHoveredByte` is a no-op unless the caller owns the
 * current value, which is the whole reason `publish` requires a source and
 * `clear` takes one rather than there being a single `set(x | null)`.
 */
export type ByteHoverSource = 'packets-hex' | 'frame-detail-hex';

export interface HoveredByte {
  /** Which dump published it. Null when nothing is hovered. */
  source: ByteHoverSource | null;
  /** Index into that frame's bytes. */
  index: number | null;
  /** The byte itself, read out of `rawBytes` by the publisher. */
  value: number | null;
  /** The frame it came from, so the readout can name it. */
  frameId: number | null;
}

export const NO_HOVERED_BYTE: HoveredByte =
  { source: null, index: null, value: null, frameId: null };

let current: HoveredByte = NO_HOVERED_BYTE;
const listeners = new Set<() => void>();

function notify(): void {
  for (const listener of listeners) listener();
}

/**
 * Publishes a hovered byte. The source is required, so "publish" can never
 * accidentally mean "clear" - clearing is the other function, and it is
 * ownership-checked.
 *
 * Compared field by field before notifying, for the reason
 * `publishPacketCounts` gives: a dump rebuilds this object on every pointer
 * move within the same cell, and the identity always differs.
 */
export function publishHoveredByte(
  next: HoveredByte & { source: ByteHoverSource },
): void {
  if (
    next.source === current.source
    && next.index === current.index
    && next.value === current.value
    && next.frameId === current.frameId
  ) {
    return;
  }
  current = next;
  notify();
}

/**
 * Clears the hover, but only if this source is the one that set it.
 *
 * The ownership check is what makes the `display: none` case safe. Both dumps
 * can be mounted at once, so an unmount cleanup or a frame change in the hidden
 * one would otherwise blank a byte the visible one is showing.
 */
export function clearHoveredByte(source: ByteHoverSource): void {
  if (current.source !== source) return;
  current = NO_HOVERED_BYTE;
  notify();
}

/**
 * Subscribes to changes. Exported rather than private because the assertion
 * script drives this store under plain `tsx` with no React, and a store whose
 * only reader is a hook is a store no script can test - which is how the
 * derivation this module replaces went unchecked for as long as it did.
 */
export function subscribeHoveredByte(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/** The current value, for a reader that is not a React component. */
export function readHoveredByte(): HoveredByte {
  return current;
}

export function useHoveredByte(): HoveredByte {
  return useSyncExternalStore(subscribeHoveredByte, readHoveredByte, () => NO_HOVERED_BYTE);
}

/** The five ways one byte is worth reading, already formatted. */
export interface ByteReadout {
  offset: string;
  dec: string;
  hex: string;
  bits: string;
  ascii: string;
}

/**
 * Formats one byte for display.
 *
 * Pure, and in the service rather than the component, for the reason
 * `filterPercentage` is: an assertion script can reach a service and cannot
 * reach a component's render.
 *
 * **Both hex numbers are zero-padded**, which the inline formatting this
 * replaces did for the value and not for the offset - so byte 10 of a frame
 * read `@0xA` beside `0x0A`. The ASCII column is the printable range only:
 * 32 to 126, and a full stop for everything else, because a control character
 * rendered raw moves the cursor or eats the line.
 */
export function describeByte(index: number, value: number): ByteReadout {
  const printable = value >= 32 && value <= 126;
  return {
    offset: `0x${index.toString(16).toUpperCase().padStart(4, '0')}`,
    dec: String(value),
    hex: `0x${value.toString(16).toUpperCase().padStart(2, '0')}`,
    bits: value.toString(2).padStart(8, '0'),
    ascii: printable ? String.fromCharCode(value) : '.',
  };
}
