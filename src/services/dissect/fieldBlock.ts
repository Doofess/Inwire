/**
 * A run of frames' dense field values, stored as columns rather than as
 * properties on each frame.
 *
 * `Packet.fields` is 1,431 B a frame, 76% of a resident record. The reason is
 * not the values: 24.7 entries a frame are spread over 123 keys, each costing a
 * full dictionary-mode property slot of about 58 B, and a third of them are
 * booleans with two possible values. But **33 keys hold 85.4% of the entries**,
 * and the commonest are near-universal and tiny - `eth.ig` on every frame with
 * two distinct values, `tcp.flags.syn` on 22,063 with two
 * (`scripts/perf/fields-split-cost.ts`, `docs/decisions/0017`).
 *
 * A column costs the width of the value plus one presence bit: 81 B a frame for
 * all 33 against roughly 1,900 B as properties.
 *
 * **Blocks are referenced by their frames and freed by the collector.** A frame
 * holds its block and its row in it; when the buffer trims its oldest frames,
 * the block they shared becomes unreachable and goes. Nothing rebases, nothing
 * is keyed by position in the buffer, and this file does not need to know a
 * buffer exists - which is what makes it safe against trimming, filtering,
 * sorting and everything else done to the array of frames.
 */

export type ColumnWidth = 'u8' | 'u16' | 'u32' | 'f64' | 'str';

export interface DenseKey {
  abbrev: string;
  /** Where the column starts; it widens from here as values demand. */
  width: ColumnWidth;
}

type NumericArray = Uint8Array | Uint16Array | Uint32Array | Float64Array;

interface Column {
  width: ColumnWidth;
  /** `width`'s place in `ORDER`, so a widening test is a comparison of two numbers. */
  rank: number;
  /** This key's presence bit: the byte within a row's stride, and the bit in it. */
  presenceByte: number;
  presenceMask: number;
  /** The values, or - for a `str` column - indices into `table`. */
  values: NumericArray;
  /** Distinct strings, for a `str` column only. */
  table?: string[];
  /** The reverse of `table`, so writing is a lookup rather than a scan. */
  index?: Map<string, number>;
}

/** The order widths grow in. A column only ever moves right along this. */
const ORDER: ColumnWidth[] = ['u8', 'u16', 'u32', 'f64'];

function allocate(width: ColumnWidth, rows: number): NumericArray {
  switch (width) {
    case 'u8': return new Uint8Array(rows);
    case 'u16': return new Uint16Array(rows);
    case 'u32': return new Uint32Array(rows);
    default: return new Float64Array(rows);
  }
}

/** The narrowest width that holds `value` exactly, as its place in `ORDER`. */
function rankFor(value: number): number {
  if (!Number.isInteger(value) || value < 0) return 3;
  if (value <= 0xff) return 0;
  if (value <= 0xffff) return 1;
  if (value <= 0xffffffff) return 2;
  return 3;
}

export class FieldBlock {
  private readonly columns = new Map<string, Column>();
  /** One bit per declared key per row; see the constructor. */
  private readonly presence: Uint8Array;
  private readonly presenceStride: number;
  private rows = 0;

  constructor(keys: readonly DenseKey[], readonly capacity: number) {
    // One bitmap for every key rather than one array per key: 33 keys is 5
    // bytes a row packed against 33 unpacked. Presence cannot be folded into
    // the value, because zero is a legitimate value and absence is not one -
    // `tcp.flags.syn == 0` is a filter people write, and a field the frame does
    // not carry must not match it.
    this.presenceStride = Math.ceil(keys.length / 8);
    this.presence = new Uint8Array(this.presenceStride * capacity);

    keys.forEach((key, i) => {
      const column: Column = {
        width: key.width,
        rank: ORDER.indexOf(key.width),
        presenceByte: i >> 3,
        presenceMask: 1 << (i & 7),
        // A string column holds indices into its own table, so it is 2 B a row
        // rather than the 8 a reference costs.
        values: key.width === 'str' ? new Uint16Array(capacity) : allocate(key.width, capacity),
      };
      if (key.width === 'str') { column.table = []; column.index = new Map(); }
      this.columns.set(key.abbrev, column);
    });
  }

  get full(): boolean { return this.rows >= this.capacity; }

  /** The next free row, or -1 when the block is full. */
  claimRow(): number {
    if (this.rows >= this.capacity) return -1;
    return this.rows++;
  }

  /** Whether this block has a column for `abbrev` at all. */
  has(abbrev: string): boolean { return this.columns.has(abbrev); }

  write(row: number, abbrev: string, value: string | number): void {
    this.tryWrite(row, abbrev, value);
  }

  /**
   * `write`, answering whether this block has a column for `abbrev` - one
   * lookup where `has` then `write` took two, and `absorb` asks it of every
   * field of every frame that joins the buffer: 7% of the renderer's main
   * thread at 60,000 frames a second, measured, with `write` inlined into it.
   */
  tryWrite(row: number, abbrev: string, value: string | number): boolean {
    const column = this.columns.get(abbrev);
    if (column === undefined) return false;

    if (column.width === 'str') {
      const text = String(value);
      let at = column.index!.get(text);
      if (at === undefined) {
        at = column.table!.length;
        // A table larger than its index can address would silently alias two
        // different strings, so the index widens instead. In practice a block
        // sees a few dozen distinct values in a string column.
        if (at > 0xffff && column.values instanceof Uint16Array) {
          const wider = new Uint32Array(this.capacity);
          wider.set(column.values);
          column.values = wider;
        }
        column.table!.push(text);
        column.index!.set(text, at);
      }
      column.values[row] = at;
    } else {
      const needed = rankFor(value as number);
      if (needed > column.rank) this.widen(column, ORDER[needed]);
      column.values[row] = value as number;
    }

    this.presence[row * this.presenceStride + column.presenceByte] |= column.presenceMask;
    return true;
  }

  read(row: number, abbrev: string): string | number | undefined {
    const column = this.columns.get(abbrev);
    if (column === undefined) return undefined;
    if ((this.presence[row * this.presenceStride + column.presenceByte] & column.presenceMask) === 0) {
      return undefined;
    }
    const raw = column.values[row];
    return column.width === 'str' ? column.table![raw] : raw;
  }

  /**
   * Grows a column to hold a value its current width cannot.
   *
   * The starting widths are each field's own size in its protocol, which no
   * valid frame exceeds - but several dense fields are computed rather than
   * read off the wire, and no protocol bounds those. Truncating instead would
   * report a plausible wrong number, which is the worst thing this file could
   * produce: 65,536 written to a `u16` column reads back as 0.
   */
  private widen(column: Column, to: ColumnWidth): void {
    const grown = allocate(to, this.capacity);
    // The cast only collapses the union of the four concrete array types, which
    // TypeScript will not do on its own; every one of them is an ArrayLike.
    grown.set(column.values as unknown as ArrayLike<number>);
    column.values = grown;
    column.width = to;
    column.rank = ORDER.indexOf(to);
  }

  /** Bytes held, for the measurement scripts. Excludes the string tables. */
  get byteLength(): number {
    let total = this.presence.byteLength;
    for (const column of this.columns.values()) total += column.values.byteLength;
    return total;
  }
}
