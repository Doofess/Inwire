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
const T_MAP = 10; // varint count + (value key, value) pairs, in insertion order
const T_INSTANCE = 11; // varint class index + an object's own fields
const T_DATE = 12; // float64 milliseconds - the clock a certificate is judged by

/**
 * Classes whose instances a record may hold, by position.
 *
 * A snapshot of tracker state can contain an instance - an HTTP/2 connection
 * carries its `HpackTable` - and a plain-object copy of one has the fields but
 * none of the methods, so the dissector handed it on revisit would call a
 * method that is not there. A registered class is written as its index plus
 * its own fields and comes back with its prototype. An instance of any class
 * NOT registered throws on write: that is state nobody has decided how to
 * record, and the gate is where that should be found.
 *
 * Only classes whose whole state is in own, enumerable fields qualify -
 * TypeScript `private` fields are, `#private` ones are not.
 */
const RECORD_CLASSES: { prototype: object; name: string }[] = [];

export function registerRecordClass(ctor: { prototype: object; name: string }): void {
  if (!RECORD_CLASSES.includes(ctor)) RECORD_CLASSES.push(ctor);
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** A growable byte buffer, reused across frames by its owner. */
/** Encoded object keys (`ValueWriter.key`). Bounded, in case a key is ever data. */
const KEY_BYTES = new Map<string, Uint8Array>();
const MAX_CACHED_KEYS = 4096;

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

  /**
   * A string's UTF-8 length and bytes. ASCII - every object key, and nearly
   * every string a tracker answers with - is written a byte at a time; only a
   * string with anything past 0x7f goes through `TextEncoder`.
   *
   * Measured, not assumed: `TextEncoder.encode` was the recorder's largest cost
   * on the arrival path, 7.4% of the whole pass plus the collector's share of
   * the thousands of small arrays it allocated a second.
   */
  private utf8(s: string): void {
    const n = s.length;
    let ascii = true;
    for (let i = 0; i < n; i++) {
      if (s.charCodeAt(i) > 0x7f) { ascii = false; break; }
    }
    if (!ascii) {
      const utf8 = encoder.encode(s);
      this.varint(utf8.length);
      this.room(utf8.length);
      this.buf.set(utf8, this.length);
      this.length += utf8.length;
      return;
    }
    this.varint(n);
    this.room(n);
    for (let i = 0; i < n; i++) this.buf[this.length++] = s.charCodeAt(i);
  }

  private fields(v: Record<string, unknown>): void {
    const keys = Object.keys(v);
    this.varint(keys.length);
    for (const key of keys) {
      this.key(key);
      this.value(v[key]);
    }
  }

  /**
   * Writes `{ ...v, ...set }` without the keys in `omit` - the same bytes that
   * object would encode to - without building it. A snapshot of a live tracker
   * object is one of those on nearly every TLS frame, and building each only to
   * encode it and drop it was a large part of what recording cost the
   * collector.
   *
   * Spread's own order, which the bytes depend on: `v`'s keys in order, a key
   * `set` also names taking `set`'s value in place, then `set`'s other keys -
   * including one `omit` removed from `v` - at the end. Always a plain object,
   * as a spread is.
   */
  objectWith(v: object, omit: readonly string[], set: Readonly<Record<string, unknown>>): void {
    const source = v as Record<string, unknown>;
    const own = Object.keys(source);
    const replaced = Object.keys(set);
    let count = 0;
    for (const key of own) if (!omit.includes(key)) count++;
    const appended = replaced.filter((key) => omit.includes(key) || !own.includes(key));
    this.byte(T_OBJECT);
    this.varint(count + appended.length);
    for (const key of own) {
      if (omit.includes(key)) continue;
      this.key(key);
      this.value(Object.prototype.hasOwnProperty.call(set, key) ? set[key] : source[key]);
    }
    for (const key of appended) {
      this.key(key);
      this.value(set[key]);
    }
  }

  /**
   * An object key, exactly as `utf8` writes it, from a cache. Keys are a few
   * dozen property names written millions of times, so their bytes are worked
   * out once; the output is the same bytes either way.
   */
  private key(key: string): void {
    let bytes = KEY_BYTES.get(key);
    if (bytes === undefined) {
      const saved = this.length;
      this.utf8(key);
      bytes = this.buf.slice(saved, this.length);
      this.length = saved;
      if (KEY_BYTES.size < MAX_CACHED_KEYS) KEY_BYTES.set(key, bytes);
    }
    this.room(bytes.length);
    this.buf.set(bytes, this.length);
    this.length += bytes.length;
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
      case 'string':
        this.byte(T_STRING);
        this.utf8(v);
        return;
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
        if (v instanceof Date) {
          this.byte(T_DATE);
          this.room(8);
          this.view.setFloat64(this.length, v.getTime(), true);
          this.length += 8;
          return;
        }
        if (v instanceof Map) {
          this.byte(T_MAP);
          this.varint(v.size);
          for (const [key, item] of v) {
            this.value(key);
            this.value(item);
          }
          return;
        }
        {
          const proto = Object.getPrototypeOf(v);
          if (proto !== Object.prototype && proto !== null) {
            const index = RECORD_CLASSES.findIndex((c) => c.prototype === proto);
            if (index < 0) {
              throw new Error(`valueCodec: cannot record an instance of ${proto?.constructor?.name ?? 'an unknown class'}`);
            }
            this.byte(T_INSTANCE);
            this.varint(index);
          } else {
            this.byte(T_OBJECT);
          }
          this.fields(v as Record<string, unknown>);
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

  /** Bytes not yet read. */
  get remaining(): number {
    return this.end - this.at;
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

  private fields(out: Record<string, unknown>): Record<string, unknown> {
    const n = this.varint();
    for (let i = 0; i < n; i++) {
      const key = this.utf8();
      out[key] = this.value();
    }
    return out;
  }

  private float64(): number {
    if (this.at + 8 > this.end) throw new RangeError('valueCodec: float past the end');
    const f = this.view.getFloat64(this.at, true);
    this.at += 8;
    return f;
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
      case T_FLOAT:
        return this.float64();
      case T_DATE:
        return new Date(this.float64());
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
      case T_OBJECT:
        return this.fields({});
      case T_MAP: {
        const n = this.varint();
        const out = new Map<unknown, unknown>();
        for (let i = 0; i < n; i++) {
          const key = this.value();
          out.set(key, this.value());
        }
        return out;
      }
      case T_INSTANCE: {
        const cls = RECORD_CLASSES[this.varint()];
        if (cls === undefined) throw new RangeError('valueCodec: unknown class');
        return this.fields(Object.create(cls.prototype) as Record<string, unknown>);
      }
      default:
        throw new RangeError(`valueCodec: unknown tag ${tag}`);
    }
  }
}
