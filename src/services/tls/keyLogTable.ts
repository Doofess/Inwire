/**
 * The key log packed into one buffer (ADR 0073).
 *
 * A `Map<string, Map<string, Uint8Array>>` costs ~540 bytes a line, and the
 * page, the pipeline Worker and every shard each held a whole one. This is the
 * same data in about 80: one `SharedArrayBuffer` (or, where the context is not
 * cross-origin isolated, an `ArrayBuffer` copy of one) that the page writes and
 * every Worker reads in place.
 *
 * ## Layout
 *
 * Everything lives in one buffer, and a reader builds every view from the
 * buffer and its header alone. All integers are little-endian `Int32`.
 *
 *   header   32 ints (128 bytes): magic, version, the four capacities, the four
 *            region offsets, the total, GENERATION, the four counters.
 *   slots    `slotCap` ints, open addressing, linear probing. 0 is empty,
 *            otherwise connection index + 1. `slotCap` is a power of two and
 *            at least 2x `connCap`, so the load never passes 0.5.
 *   conns    36 bytes each: the 32-byte client random, then an int, the head
 *            record + 1 (0 is none).
 *   records  16 bytes each, four ints: connection, label id | length << 8,
 *            secret offset in the arena, next record + 1 (0 is none). A
 *            connection's records are a linked list in insertion order, so
 *            `secretsFor` replaying them lets a later record for a label win,
 *            as `Map.set` did.
 *   arena    the secret bytes, appended.
 *
 * The hash reads bytes 16..31 of the client random, never 0..3: TLS 1.2 clients
 * put `gmt_unix_time` there.
 *
 * ## Publication
 *
 * One writer, any number of readers, no locks. The writer appends in an order
 * a reader can rely on: secret bytes, then the record's fields, then the link
 * (`Atomics.store` into the previous record's `next`, or, for a new connection,
 * the random and head and then the slot), then the counters, then one
 * `Atomics.add` on GENERATION per `add` that changed something. A reader loads
 * slots, heads and `next` with `Atomics.load`, so whatever it reaches through a
 * link was written before the link was.
 *
 * ## Growth
 *
 * When a region would overflow, the writer allocates a new buffer in which only
 * the overflowing regions are doubled, copies into it, and never writes the old
 * one again. A reader on the old buffer keeps answering from it, whole and
 * stale, until it adopts the new one. Where the new buffer would pass
 * `MAX_BUFFER_BYTES`, or allocation throws, the line is dropped and counted.
 */
import { MAX_KEYLOG_SECRETS } from './keyLogLimits';

/** The labels a line may carry. Anything else is counted and ignored. */
export const LABEL_NAMES = [
  'CLIENT_RANDOM',
  'CLIENT_EARLY_TRAFFIC_SECRET',
  'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
  'SERVER_HANDSHAKE_TRAFFIC_SECRET',
  'CLIENT_TRAFFIC_SECRET_0',
  'SERVER_TRAFFIC_SECRET_0',
  'EXPORTER_SECRET',
  'EARLY_EXPORTER_SECRET',
] as const;

const LABEL_IDS = new Map<string, number>(LABEL_NAMES.map((name, i) => [name, i]));
const LABEL_BYTES = LABEL_NAMES.map((name) => Uint8Array.from(name, (c) => c.charCodeAt(0)));

const MAGIC = 0x4b4c5431; // 'KLT1'
const VERSION = 1;
const H = {
  MAGIC: 0, VERSION: 1, SLOT_CAP: 2, CONN_CAP: 3, REC_CAP: 4, ARENA_CAP: 5,
  SLOTS_OFF: 6, CONNS_OFF: 7, RECS_OFF: 8, ARENA_OFF: 9, TOTAL: 10,
  GENERATION: 11, CONNS: 12, RECS: 13, ARENA_USED: 14, IGNORED: 15, DROPPED: 16,
} as const;
const HEADER_INTS = 32;
const HEADER_BYTES = HEADER_INTS * 4;
const CONN_BYTES = 36;
const REC_BYTES = 16;
const RANDOM_BYTES = 32;
const MAX_SECRET_BYTES = 255;

const INITIAL_CONNS = 256;
const INITIAL_RECS = 1024;
const INITIAL_ARENA = 32_768;
/** Int32 offsets and typed-array lengths stay well inside what V8 allocates. */
const MAX_BUFFER_BYTES = 2_000_000_000;

export interface KeyLogTableStats { connections: number; secrets: number; ignored: number; dropped: number }

export interface KeyLogTableOptions {
  shared: boolean;
  maxSecrets?: number;
  /** The generation the new table starts at; a clear carries the old one over, plus one. */
  generation?: number;
}

const HEX_VALUE = new Int8Array(128).fill(-1);
for (let i = 0; i < 10; i++) HEX_VALUE[48 + i] = i;
for (let i = 0; i < 6; i++) { HEX_VALUE[97 + i] = 10 + i; HEX_VALUE[65 + i] = 10 + i; }
const HEX_DIGITS = Uint8Array.from('0123456789abcdef', (c) => c.charCodeAt(0));

/** Decodes `count` bytes of strict hex from `text` into `out`; false when any digit is not hex. */
function decodeHex(text: string, out: Uint8Array, count: number): boolean {
  for (let i = 0; i < count; i++) {
    const hi = text.charCodeAt(i * 2);
    const lo = text.charCodeAt(i * 2 + 1);
    const h = hi < 128 ? HEX_VALUE[hi] : -1;
    const l = lo < 128 ? HEX_VALUE[lo] : -1;
    if (h < 0 || l < 0) return false;
    out[i] = (h << 4) | l;
  }
  return true;
}

/** FNV-1a over bytes 16..31 of the random at `base`, avalanched. */
function hashRandom(bytes: Uint8Array, base: number): number {
  let h = 0x811c9dc5;
  for (let i = base + 16; i < base + 32; i++) h = Math.imul(h ^ bytes[i], 0x01000193);
  h ^= h >>> 15;
  h = Math.imul(h, 0x2c1b3c6d);
  h ^= h >>> 12;
  return h >>> 0;
}

interface Layout {
  slotCap: number; connCap: number; recCap: number; arenaCap: number;
  slotsOff: number; connsOff: number; recsOff: number; arenaOff: number; total: number;
}

function layoutFor(connCap: number, recCap: number, arenaCap: number): Layout {
  let slotCap = 2;
  while (slotCap < connCap * 2) slotCap *= 2;
  const slotsOff = HEADER_BYTES;
  const connsOff = slotsOff + slotCap * 4;
  const recsOff = connsOff + connCap * CONN_BYTES;
  const arenaOff = recsOff + recCap * REC_BYTES;
  const total = Math.ceil((arenaOff + arenaCap) / 4) * 4;
  return { slotCap, connCap, recCap, arenaCap, slotsOff, connsOff, recsOff, arenaOff, total };
}

function allocate(total: number, shared: boolean): ArrayBuffer | SharedArrayBuffer {
  return shared ? new SharedArrayBuffer(total) : new ArrayBuffer(total);
}

export class KeyLogTable {
  public buffer!: ArrayBuffer | SharedArrayBuffer;
  public readonly readOnly: boolean;
  private readonly shared: boolean;
  private readonly maxSecrets: number;

  private i32!: Int32Array;
  private u8!: Uint8Array;
  private slotsI = 0;
  private slotMask = 0;
  private connsB = 0;
  private recsI = 0;
  private arenaB = 0;
  private connCap = 0;
  private recCap = 0;
  private arenaCap = 0;

  private readonly rnd = new Uint8Array(RANDOM_BYTES);
  private readonly sec = new Uint8Array(MAX_SECRET_BYTES);

  private constructor(readOnly: boolean, shared: boolean, maxSecrets: number) {
    this.readOnly = readOnly;
    this.shared = shared;
    this.maxSecrets = maxSecrets;
  }

  /** A new, empty, writable table. */
  public static create(options: KeyLogTableOptions): KeyLogTable {
    const table = new KeyLogTable(false, options.shared, options.maxSecrets ?? MAX_KEYLOG_SECRETS);
    const l = layoutFor(INITIAL_CONNS, INITIAL_RECS, INITIAL_ARENA);
    const buffer = allocate(l.total, options.shared);
    const hdr = new Int32Array(buffer, 0, HEADER_INTS);
    hdr[H.MAGIC] = MAGIC;
    hdr[H.VERSION] = VERSION;
    table.writeLayout(hdr, l);
    hdr[H.GENERATION] = options.generation ?? 0;
    table.bind(buffer);
    return table;
  }

  /** A read-only view of a buffer a writer made. Never writes it. */
  public static open(buffer: ArrayBuffer | SharedArrayBuffer): KeyLogTable {
    if (buffer.byteLength < HEADER_BYTES) throw new Error('not a key log table: too short');
    const hdr = new Int32Array(buffer, 0, HEADER_INTS);
    if (hdr[H.MAGIC] !== MAGIC || hdr[H.VERSION] !== VERSION) throw new Error('not a key log table');
    if (hdr[H.TOTAL] > buffer.byteLength) throw new Error('key log table is truncated');
    const table = new KeyLogTable(true, false, 0);
    table.bind(buffer);
    return table;
  }

  private writeLayout(hdr: Int32Array, l: Layout): void {
    hdr[H.SLOT_CAP] = l.slotCap;
    hdr[H.CONN_CAP] = l.connCap;
    hdr[H.REC_CAP] = l.recCap;
    hdr[H.ARENA_CAP] = l.arenaCap;
    hdr[H.SLOTS_OFF] = l.slotsOff;
    hdr[H.CONNS_OFF] = l.connsOff;
    hdr[H.RECS_OFF] = l.recsOff;
    hdr[H.ARENA_OFF] = l.arenaOff;
    hdr[H.TOTAL] = l.total;
  }

  private bind(buffer: ArrayBuffer | SharedArrayBuffer): void {
    this.buffer = buffer;
    const i32 = new Int32Array(buffer, 0, buffer.byteLength >> 2);
    this.i32 = i32;
    this.u8 = new Uint8Array(buffer);
    this.slotsI = i32[H.SLOTS_OFF] >> 2;
    this.slotMask = i32[H.SLOT_CAP] - 1;
    this.connsB = i32[H.CONNS_OFF];
    this.recsI = i32[H.RECS_OFF] >> 2;
    this.arenaB = i32[H.ARENA_OFF];
    this.connCap = i32[H.CONN_CAP];
    this.recCap = i32[H.REC_CAP];
    this.arenaCap = i32[H.ARENA_CAP];
  }

  public get generation(): number {
    return Atomics.load(this.i32, H.GENERATION);
  }

  public get isEmpty(): boolean {
    return Atomics.load(this.i32, H.CONNS) === 0;
  }

  public stats(): KeyLogTableStats {
    const i32 = this.i32;
    return {
      connections: Atomics.load(i32, H.CONNS),
      secrets: Atomics.load(i32, H.RECS),
      ignored: Atomics.load(i32, H.IGNORED),
      dropped: Atomics.load(i32, H.DROPPED),
    };
  }

  /** A private copy of the buffer, for a context that cannot share memory. */
  public copy(): ArrayBuffer {
    const out = new Uint8Array(this.u8.byteLength);
    out.set(this.u8);
    return out.buffer;
  }

  /**
   * The slot for the random at `src[so..so+32]`: the one holding it, or the
   * empty one where it would go. Terminates because the load is at most 0.5.
   */
  private findSlot(src: Uint8Array, so: number): number {
    const i32 = this.i32;
    const u8 = this.u8;
    let h = hashRandom(src, so) & this.slotMask;
    for (;;) {
      const idx = this.slotsI + h;
      const s = Atomics.load(i32, idx);
      if (s === 0) return idx;
      const co = this.connsB + (s - 1) * CONN_BYTES;
      let i = 0;
      while (i < RANDOM_BYTES && u8[co + i] === src[so + i]) i++;
      if (i === RANDOM_BYTES) return idx;
      h = (h + 1) & this.slotMask;
    }
  }

  /** The secrets for one connection: fresh copies, never views of the buffer. */
  public lookup(clientRandom: Uint8Array): Map<string, Uint8Array> | undefined {
    if (clientRandom.length !== RANDOM_BYTES) return undefined;
    const i32 = this.i32;
    const s = Atomics.load(i32, this.findSlot(clientRandom, 0));
    if (s === 0) return undefined;
    let r = Atomics.load(i32, (this.connsB + (s - 1) * CONN_BYTES + RANDOM_BYTES) >> 2);
    if (r === 0) return undefined;
    const out = new Map<string, Uint8Array>();
    while (r !== 0) {
      const ri = this.recsI + (r - 1) * 4;
      const labelLen = i32[ri + 1];
      const start = this.arenaB + i32[ri + 2];
      out.set(LABEL_NAMES[labelLen & 0xff], this.u8.slice(start, start + (labelLen >>> 8)));
      r = Atomics.load(i32, ri + 3);
    }
    return out;
  }

  /** The records as `LABEL <random hex> <secret hex>\n`, lowercase, in insertion order. */
  public serialise(): Uint8Array {
    const i32 = this.i32;
    const u8 = this.u8;
    const count = Atomics.load(i32, H.RECS);
    let total = 0;
    for (let r = 0; r < count; r++) {
      const labelLen = i32[this.recsI + r * 4 + 1];
      total += LABEL_BYTES[labelLen & 0xff].length + 1 + 64 + 1 + (labelLen >>> 8) * 2 + 1;
    }
    const out = new Uint8Array(total);
    let o = 0;
    const hex = (from: number, n: number) => {
      for (let i = 0; i < n; i++) {
        const b = u8[from + i];
        out[o++] = HEX_DIGITS[b >> 4];
        out[o++] = HEX_DIGITS[b & 15];
      }
    };
    for (let r = 0; r < count; r++) {
      const ri = this.recsI + r * 4;
      const labelLen = i32[ri + 1];
      const label = LABEL_BYTES[labelLen & 0xff];
      out.set(label, o);
      o += label.length;
      out[o++] = 0x20;
      hex(this.connsB + i32[ri] * CONN_BYTES, RANDOM_BYTES);
      out[o++] = 0x20;
      hex(this.arenaB + i32[ri + 2], labelLen >>> 8);
      out[o++] = 0x0a;
    }
    return out;
  }

  /**
   * Adds a key log's text. `changed`: a secret was learned, so GENERATION moved.
   * The rules per line are the store's from before the table: trim, skip blank
   * and `#`, three whitespace-separated parts, a known label, a 64-hex random,
   * and a secret of 1..255 bytes of hex; a line identical to the one held for
   * its label is skipped without counting; one past `maxSecrets` is dropped.
   */
  public addText(text: string): { changed: boolean } {
    if (this.readOnly) throw new Error('key log is read-only in this context');
    let changed = false;
    let ignored = 0;
    let dropped = 0;

    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (line.length === 0 || line.startsWith('#')) continue;

      const parts = line.split(/\s+/);
      const labelId = parts.length === 3 ? LABEL_IDS.get(parts[0]) : undefined;
      if (labelId === undefined) { ignored++; continue; }
      const randomHex = parts[1];
      const secretHex = parts[2];
      if (randomHex.length !== 64 || !decodeHex(randomHex, this.rnd, RANDOM_BYTES)) { ignored++; continue; }
      const n = secretHex.length / 2;
      if (n < 1 || n > MAX_SECRET_BYTES || !Number.isInteger(n) || !decodeHex(secretHex, this.sec, n)) {
        ignored++;
        continue;
      }

      let slot = this.findSlot(this.rnd, 0);
      let conn = Atomics.load(this.i32, slot) - 1;
      let tail = 0;
      let held = 0;
      if (conn >= 0) {
        let r = this.i32[(this.connsB + conn * CONN_BYTES + RANDOM_BYTES) >> 2];
        while (r !== 0) {
          tail = r;
          const ri = this.recsI + (r - 1) * 4;
          if ((this.i32[ri + 1] & 0xff) === labelId) held = r;
          r = this.i32[ri + 3];
        }
      }
      if (held !== 0) {
        const ri = this.recsI + (held - 1) * 4;
        const heldLen = this.i32[ri + 1] >>> 8;
        if (heldLen === n) {
          const at = this.arenaB + this.i32[ri + 2];
          let i = 0;
          while (i < n && this.u8[at + i] === this.sec[i]) i++;
          if (i === n) continue;
        }
      }

      const recs = this.i32[H.RECS];
      if (recs >= this.maxSecrets) { dropped++; continue; }
      const conns = this.i32[H.CONNS];
      const used = this.i32[H.ARENA_USED];
      const isNew = conn < 0;
      if (recs + 1 > this.recCap || used + n > this.arenaCap || (isNew && conns + 1 > this.connCap)) {
        // The lines this add already wrote stay in the buffer being retired,
        // where a reader can see them: its generation has to say so before it
        // is left. The new buffer copies the bumped value and gains one more.
        if (changed) Atomics.add(this.i32, H.GENERATION, 1);
        if (!this.grow(isNew ? 1 : 0, 1, n)) { dropped++; continue; }
        slot = this.findSlot(this.rnd, 0);
      }

      // 1. The secret bytes. 2. The record's fields. 3. The link. 4. The counters.
      const i32 = this.i32;
      this.u8.set(this.sec.subarray(0, n), this.arenaB + used);
      if (isNew) conn = conns;
      const ri = this.recsI + recs * 4;
      i32[ri] = conn;
      i32[ri + 1] = labelId | (n << 8);
      i32[ri + 2] = used;
      i32[ri + 3] = 0;
      if (isNew) {
        const co = this.connsB + conn * CONN_BYTES;
        this.u8.set(this.rnd, co);
        Atomics.store(i32, (co + RANDOM_BYTES) >> 2, recs + 1);
        Atomics.store(i32, slot, conn + 1);
        Atomics.store(i32, H.CONNS, conns + 1);
      } else {
        Atomics.store(i32, this.recsI + (tail - 1) * 4 + 3, recs + 1);
      }
      Atomics.store(i32, H.ARENA_USED, used + n);
      Atomics.store(i32, H.RECS, recs + 1);
      changed = true;
    }

    if (ignored > 0) Atomics.store(this.i32, H.IGNORED, this.i32[H.IGNORED] + ignored);
    if (dropped > 0) Atomics.store(this.i32, H.DROPPED, this.i32[H.DROPPED] + dropped);
    if (changed) Atomics.add(this.i32, H.GENERATION, 1);
    return { changed };
  }

  /**
   * Moves to a bigger buffer, doubling only what overflows. The old buffer is
   * left exactly as it was and is not written again. False when the result
   * would be too big or the allocation fails.
   */
  private grow(needConns: number, needRecs: number, needArena: number): boolean {
    const old = this.i32;
    const conns = old[H.CONNS];
    const recs = old[H.RECS];
    const used = old[H.ARENA_USED];
    let cc = this.connCap;
    let rc = this.recCap;
    let ac = this.arenaCap;
    while (conns + needConns > cc) cc *= 2;
    while (recs + needRecs > rc) rc *= 2;
    while (used + needArena > ac) ac *= 2;
    const l = layoutFor(cc, rc, ac);
    if (l.total > MAX_BUFFER_BYTES) return false;
    let buffer: ArrayBuffer | SharedArrayBuffer;
    try { buffer = allocate(l.total, this.shared); } catch { return false; }

    const nu8 = new Uint8Array(buffer);
    const oldSlotCap = old[H.SLOT_CAP];
    nu8.set(this.u8.subarray(0, HEADER_BYTES), 0);
    this.writeLayout(new Int32Array(buffer, 0, HEADER_INTS), l);
    nu8.set(this.u8.subarray(this.connsB, this.connsB + conns * CONN_BYTES), l.connsOff);
    nu8.set(this.u8.subarray(this.recsI * 4, this.recsI * 4 + recs * REC_BYTES), l.recsOff);
    nu8.set(this.u8.subarray(this.arenaB, this.arenaB + used), l.arenaOff);
    const rehash = l.slotCap !== oldSlotCap;
    if (!rehash) nu8.set(this.u8.subarray(this.slotsI * 4, this.slotsI * 4 + oldSlotCap * 4), l.slotsOff);
    this.bind(buffer);
    if (rehash) {
      for (let c = 0; c < conns; c++) this.i32[this.findSlot(this.u8, this.connsB + c * CONN_BYTES)] = c + 1;
    }
    return true;
  }
}
