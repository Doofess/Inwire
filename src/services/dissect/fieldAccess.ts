/**
 * Reading a frame's fields, wherever they are stored.
 *
 * `Packet.fields` is a flat bag of Wireshark-abbreviated values, and it is the
 * largest thing a resident frame carries - 1,431 B of a 1,876 B record, 76% of
 * everything left after the lists were pooled (`scripts/perf/record-cost.ts`).
 * The reason is not the values: 24.7 entries a frame each cost a full
 * dictionary-mode property slot, about 58 B, and a third of them are booleans
 * with two possible values.
 *
 * The fix is to move the keys most frames carry into typed columns
 * (`fieldBlock.ts`, `docs/decisions/0017`), which means a value can be in one of
 * two places. **This module is the only code that knows that.** Everything else
 * - the filter engine, the colour chain, Apply as Column, Statistics, the
 * pcapng writer, name resolution - asks here and is unaffected by the split.
 *
 * The bag remains the contract. A frame that never joined a buffer - one
 * imported from a CSV, or replayed to build a detail tree - carries its whole
 * bag and no columns, and reads exactly as it always has.
 */
import { DENSE_FIELDS } from './denseFields';
import type { Packet } from '../../types/packet';

const DENSE_ABBREVS = new Set(DENSE_FIELDS.map((k) => k.abbrev));

/**
 * One field's value, or `undefined` when the frame does not carry it.
 *
 * `undefined` is a real answer and is not the same as a falsy one: a filter
 * naming a field the frame lacks must not match it under any operator, and zero
 * is a legitimate value for half the fields worth storing - `tcp.flags.syn == 0`
 * is a filter people write. That rules out encoding absence as a sentinel.
 *
 * Columns first, bag second. The two can never hold the same key - the declared
 * dense set and the keys written after dissection are asserted disjoint in
 * `scripts/dissect/dense-fields.ts` - so the order is a matter of speed rather
 * than of precedence.
 */
export function fieldValue(packet: Packet, abbrev: string): string | number | undefined {
  const block = packet.cols;
  if (block !== undefined && packet.row !== undefined) {
    const value = block.read(packet.row, abbrev);
    if (value !== undefined) return value;
  }
  return packet.fields?.[abbrev];
}

/**
 * A reader for one field, specialised to where that field lives.
 *
 * `fieldValue` has to try both halves, because it is handed a name at call
 * time. The filter engine is not in that position: `filter/compile.ts` resolves
 * every field reader once, when an expression is compiled, and then runs it
 * over the whole buffer - so which half to look in can be settled there instead
 * of on every frame.
 *
 * It is the **sparse** fields this saves, and they are 90 of the 123 keys.
 * Without it each one probes the block first - a map lookup and a bitmap test -
 * gets `undefined`, and falls back to the bag, once per frame per pass.
 */
export function fieldReader(abbrev: string): (packet: Packet) => string | number | undefined {
  if (!DENSE_ABBREVS.has(abbrev)) return (packet) => packet.fields?.[abbrev];
  return (packet) => {
    const block = packet.cols;
    // Still falls back to the bag: a frame that never joined a buffer - one
    // imported from a CSV, or replayed to build a detail tree - has no block
    // and carries every field in the bag, as it always did.
    if (block !== undefined && packet.row !== undefined) {
      const value = block.read(packet.row, abbrev);
      if (value !== undefined) return value;
    }
    return packet.fields?.[abbrev];
  };
}

/**
 * Every field this frame carries.
 *
 * For the readers that walk rather than ask - name resolution goes through the
 * bag looking for whatever it recognises. Materialises an array, so it belongs
 * in a per-frame pass and not in the filter's hot path, which asks for named
 * fields it has already resolved.
 */
export function fieldEntries(packet: Packet): [string, string | number][] {
  const out: [string, string | number][] = Object.entries(packet.fields ?? {});
  const block = packet.cols;
  if (block !== undefined && packet.row !== undefined) {
    assertLiveBlock(block);
    for (const key of DENSE_FIELDS) {
      const value = block.read(packet.row, key.abbrev);
      if (value !== undefined) out.push([key.abbrev, value]);
    }
  }
  return out;
}

/**
 * A `FieldBlock` that lost its methods, which means it crossed a boundary.
 *
 * A structured clone carries the Maps and the typed arrays and drops the
 * prototype, so a cloned block is data with no `read` on it. That happened for
 * real: every frame the capture store was sent arrived this way, `encodeChunk`
 * threw `block.read is not a function`, the throw was caught and reported as a
 * non-fatal failure, and the capture stored raw bytes and **no rows at all**
 * for the life of the process.
 *
 * Named here rather than left as a `TypeError`, because the useful thing to
 * say is not "read is not a function" - it is which rule was broken and where
 * the fix lives.
 */
function assertLiveBlock(block: Packet['cols'] & object): void {
  if (typeof (block as { read?: unknown }).read === 'function') return;
  throw new TypeError(
    'this Packet\'s field block has no methods, so it has been through a '
    + 'structured clone. Anything sending frames across a process or worker '
    + 'boundary must flatten them first - see services/capture/storePacket.ts',
  );
}
