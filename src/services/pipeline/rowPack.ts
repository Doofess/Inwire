/**
 * A shard's finished rows as one buffer, forwarded rather than re-cloned
 * (ADR 0053 phase 6).
 *
 * With shards, every TCP row crossed three boundaries as an object graph:
 * shard to coordinator, then coordinator to the window and to the store.
 * Profiled at 60,000 frames a second, the coordinator spent ~47% of its time
 * deserializing the shards' answers and serializing each row twice more. Now a
 * shard encodes a batch's rows with the store's own chunk codec, undeflated
 * (`chunkCodec.ts`: interned strings, fixed slots, lossless for a row), and the
 * coordinator sends that buffer on as it came - once per receiver, the first
 * time a flush uses one of its rows. `scripts/perf/row-codec.ts` measured the
 * choice: per row, 1.49 us to decode against structured clone's 2.03, and
 * 0.25 to forward against 2.67 to serialize again.
 *
 * **A flush names rows, not packs.** Shards interleave frame by frame and a
 * flush is cut by size and time, so a pack's rows are spread over the merged
 * order and usually over two flushes. A flush carries an order list - which
 * row of which pack, or which of the coordinator's own objects, comes next -
 * and each receiver keeps a pack (`PackReader`) until its last row is read.
 * The merge's own writes to a shard's row ride beside it as an overlay
 * (`rowOverlay.ts`), because the pack is the shard's and is not re-encoded.
 */
import type { Packet } from '../../types/packet';
import { applyPrefixes, decodeChunk, encodeChunk } from '../capture/chunkCodec';
import type { PackedRowIn, RowIn } from '../capture/captureWriter';
import { applyOverlay, type RowOverlay } from './rowOverlay';

export interface RowPack {
  /** Unique among the packs one coordinator epoch sees. */
  key: number;
  prefix: Uint8Array;
  summary: Uint8Array;
  count: number;
}

/**
 * Packs rows as a shard has them when it is done: `layers` empty (the tree
 * stays in the shard's cache) and `rawBytes` empty (the bytes travel beside
 * the pack). At most `CHUNK_FRAMES` rows, as `encodeChunk` requires.
 */
export function packRows(key: number, rows: readonly Packet[], capLengths: readonly number[]): RowPack {
  const { prefix, summary } = encodeChunk(rows, capLengths);
  return { key, prefix, summary, count: rows.length };
}

export function unpackRows(pack: RowPack): Packet[] {
  const rows = decodeChunk(pack.summary);
  // The timestamp, length, status and stream are in the fixed-width prefix.
  applyPrefixes(rows, pack.prefix);
  return rows;
}

/** One flush's rows, as they cross to a receiver. */
export interface PackedRows {
  /** Packs this receiver has not been sent before. */
  packs: RowPack[];
  /** Rows the coordinator dissected itself, or built: sent as they are. */
  objects: Packet[];
  /** Two slots per row, in order: `[packKey, index]`, or `[-1, index into objects]`. */
  order: Int32Array;
  /** `[position in this flush, overlay]` for packed rows the merge wrote to. */
  overlays: [number, RowOverlay][];
  /** One per packed row, in order of appearance: its `rawBytes`, or null for none. */
  bytes: (Uint8Array | null)[];
  /** A new capture: drop every pack held before reading this flush's. */
  packsReset?: true;
}

/** Builds one flush for one receiver, row by row in merged order. Used once. */
export class PackedFlush {
  private readonly objects: Packet[] = [];
  private readonly order: number[] = [];
  private readonly used = new Map<number, RowPack>();
  private readonly overlays: [number, RowOverlay][] = [];
  private readonly bytes: (Uint8Array | null)[] = [];

  object(packet: Packet): void {
    this.order.push(-1, this.objects.length);
    this.objects.push(packet);
  }

  packed(pack: RowPack, index: number, bytes: Uint8Array | null, overlay: RowOverlay | null): void {
    if (overlay !== null) this.overlays.push([this.order.length / 2, overlay]);
    this.order.push(pack.key, index);
    this.used.set(pack.key, pack);
    this.bytes.push(bytes);
  }

  get length(): number {
    return this.order.length / 2;
  }

  /** The flush; a pack goes in only if its key is not in `sent`, which it is added to. */
  seal(sent: Set<number>): PackedRows {
    const packs: RowPack[] = [];
    for (const [key, pack] of this.used) {
      if (sent.has(key)) continue;
      sent.add(key);
      packs.push(pack);
    }
    return {
      packs, objects: this.objects, order: Int32Array.from(this.order), overlays: this.overlays, bytes: this.bytes,
    };
  }
}

/**
 * One receiver's send state, kept by the Worker: which packs it has been sent,
 * and whether it must be told to forget the last capture's. Starts pending,
 * because a new Worker's first flush may follow a receiver that held packs from
 * the Worker before it. Lifted out of the Worker so a reset is testable.
 */
export class PackSender {
  private readonly sent = new Set<number>();
  private pending = true;

  /** A new capture, or a coordinator reset: send every pack again, and say so. */
  reset(): void {
    this.sent.clear();
    this.pending = true;
  }

  seal(flush: PackedFlush): PackedRows {
    const rows = flush.seal(this.sent);
    if (this.pending) {
      rows.packsReset = true;
      this.pending = false;
    }
    return rows;
  }
}

interface Held {
  pack: RowPack;
  rows: Packet[];
  left: number;
}

/** A receiver's end: the packs it has been sent, until their last row is read. */
export class PackReader {
  private readonly packs = new Map<number, Held>();

  /** Every row of the flush, in order, with its bytes and overlay applied. */
  read(flush: PackedRows): Packet[] {
    return this.take(flush, null);
  }

  /**
   * The flush twice over, from one pass: `rows` exactly as `read` returns them
   * (decoded, bytes set, overlays applied: what the digest folds), and `slots`,
   * the same rows in the same order as the store's writer is handed them. A
   * packed row's slot keeps the pack, the position, the flush's overlay for it
   * (or null) and its id, and carries `rawBytes` only when the flush brought
   * some; an object row is the object itself. The writer holds the pack beyond
   * this reader's `left` count, which is the reader's own bookkeeping.
   */
  readSlots(flush: PackedRows): { rows: Packet[]; slots: RowIn[] } {
    const slots: RowIn[] = new Array(flush.order.length / 2);
    const rows = this.take(flush, slots);
    return { rows, slots };
  }

  /** `read`'s body; with `slots` it also fills them, so the two cannot disagree. */
  private take(flush: PackedRows, slots: RowIn[] | null): Packet[] {
    if (flush.packsReset) this.packs.clear();
    for (const pack of flush.packs) this.packs.set(pack.key, { pack, rows: unpackRows(pack), left: pack.count });
    const { order, objects, bytes } = flush;
    const out: Packet[] = new Array(order.length / 2);
    let packed = 0;
    for (let i = 0, at = 0; at < order.length; i++, at += 2) {
      const key = order[at];
      const index = order[at + 1];
      if (key < 0) {
        out[i] = objects[index];
        if (slots !== null) slots[i] = objects[index];
        continue;
      }
      const held = this.packs.get(key);
      // A protocol error, and said so: a missing pack must not render as a blank row.
      if (held === undefined) throw new Error(`packed rows: no pack ${key} for row ${index}`);
      const row = held.rows[index];
      const frameBytes = bytes[packed++];
      if (frameBytes !== null) row.rawBytes = frameBytes;
      if (slots !== null) {
        const slot: PackedRowIn = { pack: held.pack, index, overlay: null, id: row.id };
        if (frameBytes !== null) slot.rawBytes = frameBytes;
        slots[i] = slot;
      }
      if (--held.left === 0) this.packs.delete(key);
      out[i] = row;
    }
    for (const [position, overlay] of flush.overlays) {
      applyOverlay(out[position], overlay);
      const slot = slots?.[position];
      if (slot !== undefined && 'pack' in slot) slot.overlay = overlay;
    }
    return out;
  }

  reset(): void {
    this.packs.clear();
  }

  /** Packs held: zero once every row sent has been read. */
  get held(): number {
    return this.packs.size;
  }
}
