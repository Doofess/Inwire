/**
 * A compact, self-describing encoding for the plain values a tracker answers
 * with: numbers, strings, booleans, bytes, and arrays and objects of those.
 *
 * Written for frame records (`frameRecord.ts`), where every frame carries a
 * few dozen of these and the store deflates a chunk of them together. So the
 * aim is few bytes before deflate and fast code on the arrival path, not
 * generality:
 *
 * - integers are zigzag varints - a stream index or a relative sequence
 *   number is one to five bytes, not eight;
 * - a non-integer is a float64, byte for byte, so an RTT read back is the RTT
 *   that was written, not one that round-trips through decimal;
 * - `undefined` is its own tag, distinct from `null` and from a missing key,
 *   because the dissectors test `=== undefined` and the answer must survive
 *   that test unchanged;
 * - object keys are written in full. The store deflates a chunk at a time, and
 *   4,096 frames asking the same few questions is exactly what deflate's
 *   window is for - interning them here would be a second, worse deflate.
 *
 * Not JSON: `undefined`, `Uint8Array`, `-0` and exact float64 do not survive
 * it, and every one of those reaches a tree. Not `v8.serialize`: the store is
 * a Node process but the Worker and the renderer are not.
 */

const T_UNDEFINED = 0;
const T_NULL = 1;
const T_FALSE = 2;
const T_TRUE = 3;
const T_INT = 4; // zigzag varint, |n| < 2^52
const T_FLOAT = 5; // float64 little-endian
const T_STRING = 6; // varint length + UTF-8
const T_BYTES = 7; // varint length + bytes
const T_ARRAY = 8; // varint count + values
const T_OBJECT = 9; // varint count + (string key, value) pairs

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** A growable byte buffer, reused across frames by its owner. */
export class ValueWriter {
  private buf = new Uint8Array(256);
  private view = new DataView(this.buf.buffer);
  length = 0;

  reset(): void {
    this.length = 0;
  }

  /** The bytes written since the last reset, copied out. */
  bytes(): Uint8Array {
    return this.buf.slice(0, this.length);
  }

  private room(n: number): void {
    if (this.length + n <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.length + n) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buf.subarray(0, this.length));
    this.buf = next;
    this.view = new DataView(next.buffer);
  }

  byte(b: number): void {
    this.room(1);
    this.buf[this.length++] = b;
  }

  /** An unsigned integer below 2^53, seven bits at a time. */
  varint(n: number): void {
    this.room(8);
    while (n >= 0x80) {
      this.buf[this.length++] = (n % 0x80) | 0x80;
      n = Math.floor(n / 0x80);
    }
    this.buf[this.length++] = n;
  }

  value(v: unknown): void {
    switch (typeof v) {
      case 'undefined': this.byte(T_UNDEFINED); return;
      case 'boolean': this.byte(v ? T_TRUE : T_FALSE); return;
      case 'number':
        // Below 2^52 because zigzag doubles it; an epoch-microsecond timestamp
        // (~1.8e15) still fits, and anything larger is exact as a float64.
        if (Number.isInteger(v) && Math.abs(v) < 2 ** 52 && !Object.is(v, -0)) {
          this.byte(T_INT);
          this.varint(v >= 0 ? v * 2 : -v * 2 - 1);
        } else {
          this.byte(T_FLOAT);
          this.room(8);
          this.view.setFloat64(this.length, v, true);
          this.length += 8;
        }
        return;
      case 'string': {
        const utf8 = encoder.encode(v);
        this.byte(T_STRING);
        this.varint(utf8.length);
        this.room(utf8.length);
        this.buf.set(utf8, this.length);
        this.length += utf8.length;
        return;
      }
      case 'object':
        if (v === null) { this.byte(T_NULL); return; }
        if (v instanceof Uint8Array) {
          this.byte(T_BYTES);
          this.varint(v.length);
          this.room(v.length);
          this.buf.set(v, this.length);
          this.length += v.length;
          return;
        }
        if (Array.isArray(v)) {
          this.byte(T_ARRAY);
          this.varint(v.length);
          for (const item of v) this.value(item);
          return;
        }
        {
          const keys = Object.keys(v as object);
          this.byte(T_OBJECT);
          this.varint(keys.length);
          for (const key of keys) {
            const utf8 = encoder.encode(key);
            this.varint(utf8.length);
            this.room(utf8.length);
            this.buf.set(utf8, this.length);
            this.length += utf8.length;
            this.value((v as Record<string, unknown>)[key]);
          }
        }
        return;
      default:
        // A function, a symbol or a bigint in an answer is a tracker handing a
        // dissector something that cannot be recorded, and that has to be
        // found by the gate rather than written as garbage.
        throw new Error(`valueCodec: cannot record a ${typeof v}`);
    }
  }
}

/** Reads what a `ValueWriter` wrote, in order. */
export class ValueReader {
  private at: number;
  private readonly view: DataView;

  constructor(private readonly buf: Uint8Array, start = 0, private readonly end = buf.length) {
    this.at = start;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  get done(): boolean {
    return this.at >= this.end;
  }

  byte(): number {
    if (this.at >= this.end) throw new RangeError('valueCodec: read past the end');
    return this.buf[this.at++];
  }

  varint(): number {
    let n = 0;
    let scale = 1;
    for (;;) {
      const b = this.byte();
      n += (b & 0x7f) * scale;
      if (b < 0x80) return n;
      scale *= 0x80;
    }
  }

  private utf8(): string {
    const length = this.varint();
    if (this.at + length > this.end) throw new RangeError('valueCodec: string past the end');
    const s = decoder.decode(this.buf.subarray(this.at, this.at + length));
    this.at += length;
    return s;
  }

  value(): unknown {
    const tag = this.byte();
    switch (tag) {
      case T_UNDEFINED: return undefined;
      case T_NULL: return null;
      case T_FALSE: return false;
      case T_TRUE: return true;
      case T_INT: {
        const z = this.varint();
        return z % 2 === 0 ? z / 2 : -(z + 1) / 2;
      }
      case T_FLOAT: {
        if (this.at + 8 > this.end) throw new RangeError('valueCodec: float past the end');
        const f = this.view.getFloat64(this.at, true);
        this.at += 8;
        return f;
      }
      case T_STRING: return this.utf8();
      case T_BYTES: {
        const length = this.varint();
        if (this.at + length > this.end) throw new RangeError('valueCodec: bytes past the end');
        const bytes = this.buf.slice(this.at, this.at + length);
        this.at += length;
        return bytes;
      }
      case T_ARRAY: {
        const n = this.varint();
        const out: unknown[] = new Array(n);
        for (let i = 0; i < n; i++) out[i] = this.value();
        return out;
      }
      case T_OBJECT: {
        const n = this.varint();
        const out: Record<string, unknown> = {};
        for (let i = 0; i < n; i++) {
          const key = this.utf8();
          out[key] = this.value();
        }
        return out;
      }
      default:
        throw new RangeError(`valueCodec: unknown tag ${tag}`);
    }
  }
}
