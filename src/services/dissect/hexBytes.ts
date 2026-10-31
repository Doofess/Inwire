/**
 * Hex for the byte ranges the reference renders as `FT_BYTES`.
 *
 * ## Why this is one module and not four loops
 *
 * It was four: `quic.ts`'s `hexOfRange`, `icmp.ts`'s `hexColons`,
 * `mediaType.ts`'s `dataLayer`, and `ber.ts`'s `berHex`. Each wrote the same
 * `bytes[i].toString(16).padStart(2, '0')` into an accumulating string, and
 * three of the four disagreed about clamping - `hexOfRange` clamped both ends
 * because "these offsets are derived from length fields an adversary writes",
 * `hexColons` clamped only the top, and `berHex` clamped neither.
 *
 * They are also, together, **the only O(payload) string work left on the
 * ingest path**: ADR 0042 profiled the whole dissector and `hexOfRange` was the
 * largest pure-leaf cost in this repository's own code, at 57-75 ms of a
 * ~1,260 ms pass across runs. `dataLayer` and the ICMP pair are the same shape
 * on smaller inputs.
 *
 * ## The table, and why it is `':' + hex` rather than `hex`
 *
 * `toString(16)` allocates and `padStart` allocates again, twice per byte, for
 * one of 256 answers. `HEX` removes both.
 *
 * `SEPARATED` then removes the second concatenation per byte. Writing
 * `out += ':' + HEX[b]` makes a temporary for every byte; writing
 * `out += SEPARATED[b]` does not, and that single change is most of the win.
 * Measured over 2,000 passes of a 1,460-byte payload, three rounds:
 *
 * | | |
 * |---|---|
 * | `toString(16).padStart(2, '0')`, colon appended separately | 45.6-48.7 ms |
 * | `HEX[b]` table, colon appended separately | 17.8-20.0 ms |
 * | `parts[] .join(':')` | 27.3 ms |
 * | `SEPARATED[b]` | 8.5-10.9 ms |
 * | **char codes into a scratch buffer, decoded once** | **4.7-6.6 ms** |
 *
 * The `join` row is there because it is the obvious answer and it is the second
 * worst: an array of 1,460 one-element-per-byte strings costs more than the
 * rope V8 builds out of `+=`. The last row is what a long range does now (see
 * `FLAT_FROM`), measured later and on another day than the rows above it, so
 * compare it with the `SEPARATED` row it was timed beside: 7.1-10.2 ms.
 *
 * ## What is deliberately NOT here
 *
 * `addressFormat.ts` keeps its own loop. Its inputs are 6 and 16 bytes, the
 * profile puts `formatMac` at 7-13 ms with the table having nothing to remove
 * at that length, and it is on a different path from the payload dumps this
 * exists for. A shared helper reaching every hex loop in the tree would be
 * tidier and would say the wrong thing about where the cost is.
 */

/** `00`..`ff`. One answer per byte, built once. */
const HEX: readonly string[] = Array.from(
  { length: 256 }, (_, i) => i.toString(16).padStart(2, '0'),
);

/** `:00`..`:ff`. The separator carried with the byte - see the header. */
const SEPARATED: readonly string[] = HEX.map((hex) => `:${hex}`);

/**
 * Past this many bytes the string is written as character codes and decoded
 * once, so it is born flat.
 *
 * The `+=` rope above is cheap to build and expensive to KEEP: V8 holds one
 * rope node per byte until something reads the string through, and a tree
 * only stores it. A QUIC tree's
 * `quic.remaining_payload` measured 29.5 kB as a rope and 2.8 kB flat, and a
 * coordinator holding tens of thousands of such trees ran the renderer out of
 * heap (ADR 0053, phase 5). `scripts/dissect/hex-bytes.ts` holds what a kept
 * string costs. Below the line a rope is a handful of nodes, and short
 * strings are what most fields are.
 */
const FLAT_FROM = 8;

/** The two ASCII codes of each byte's hex, at `2b` and `2b + 1`. */
const HEX_CODES = new Uint8Array(512);
for (let b = 0; b < 256; b++) {
  HEX_CODES[2 * b] = HEX[b].charCodeAt(0);
  HEX_CODES[2 * b + 1] = HEX[b].charCodeAt(1);
}
const COLON = 0x3a;
// A TextDecoder reads "latin1" as windows-1252. Every code written here is
// ASCII, where the two agree.
const LATIN1 = new TextDecoder('latin1');
let scratch = new Uint8Array(4096);

function flatHex(bytes: Uint8Array, start: number, stop: number, colons: boolean): string {
  const step = colons ? 3 : 2;
  const length = (stop - start) * step - (colons ? 1 : 0);
  if (scratch.length < length) scratch = new Uint8Array(Math.max(length, scratch.length * 2));
  let at = 0;
  for (let i = start; i < stop; i++) {
    if (colons && i > start) scratch[at++] = COLON;
    const code = 2 * bytes[i];
    scratch[at++] = HEX_CODES[code];
    scratch[at++] = HEX_CODES[code + 1];
  }
  return LATIN1.decode(scratch.subarray(0, length));
}

/**
 * Lowercase hex over `[from, to)`, colon-separated - the reference's `show`
 * for an `FT_BYTES` field.
 *
 * Colons rather than a run, because `show` is what `tree-coverage.ts` compares
 * and its `showname` runs the same bytes together; reading the human-facing
 * line produces a mismatch on every frame.
 *
 * **Both ends are clamped**, which is the strictest of the four callers this
 * replaced rather than the average of them. The offsets reaching here are
 * derived from length fields on the wire, which an adversary writes.
 *
 * The table makes that clamp matter *more* than it did, which is the one way
 * this change could have gone wrong quietly. An unclamped `bytes[-1]` is
 * `undefined`; under the old per-byte `toString(16)` that threw a `TypeError`
 * out of the middle of dissection, and under `HEX[undefined]` it is `undefined`
 * concatenated as the literal text "undefined" into a hex dump. A throw is
 * loud. `scripts/dissect/hex-bytes.ts` asserts the clamp for that reason, and
 * was checked by removing it.
 */
export function hexColons(bytes: Uint8Array, from: number, to: number): string {
  const start = Math.max(0, Math.min(from, bytes.length));
  const stop = Math.max(start, Math.min(to, bytes.length));
  if (stop === start) return '';
  if (stop - start > FLAT_FROM) return flatHex(bytes, start, stop, true);
  let out = HEX[bytes[start]];
  for (let i = start + 1; i < stop; i++) out += SEPARATED[bytes[i]];
  return out;
}

/**
 * The same range with no separator, for the fields the reference runs together.
 *
 * BER is the caller: a `SubjectPublicKeyInfo`'s modulus is compared as one
 * string, not as a colon-separated one.
 */
export function hexRun(bytes: Uint8Array, from: number, to: number): string {
  const start = Math.max(0, Math.min(from, bytes.length));
  const stop = Math.max(start, Math.min(to, bytes.length));
  if (stop - start > FLAT_FROM) return flatHex(bytes, start, stop, false);
  let out = '';
  for (let i = start; i < stop; i++) out += HEX[bytes[i]];
  return out;
}
