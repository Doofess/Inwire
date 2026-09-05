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
import type { Packet } from '../../types/packet';

/**
 * One field's value, or `undefined` when the frame does not carry it.
 *
 * `undefined` is a real answer and is not the same as a falsy one: a filter
 * naming a field the frame lacks must not match it under any operator, and zero
 * is a legitimate value for half the fields worth storing - `tcp.flags.syn == 0`
 * is a filter people write. That rules out encoding absence as a sentinel.
 */
export function fieldValue(packet: Packet, abbrev: string): string | number | undefined {
  return packet.fields?.[abbrev];
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
  return Object.entries(packet.fields ?? {});
}
