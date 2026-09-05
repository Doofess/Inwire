/**
 * Puts live frames into capture order before anything order-dependent sees
 * them.
 *
 * The agent captures each adapter on its own thread, and the threads race to
 * the socket: a frame from adapter B that was captured before a frame from
 * adapter A routinely arrives after it. The `inwire` fixture - exported from
 * this app - has eleven such inversions. That is not a display nit: the TCP
 * tracker, the ICMP pairing, the TLS record cursor and the QUIC key
 * derivation all run once, in the order frames are handed to them, so a
 * frame dissected out of order is dissected wrong and stays wrong.
 *
 * So frames wait here, briefly, and leave sorted by their capture time and
 * then by the agent's sequence number. The hold is short - `holdMs` of
 * arrival time, not capture time - because it is only covering thread skew,
 * which is milliseconds; a hold long enough to cover a genuinely late frame
 * would make the list feel a beat behind the wire for no gain. A frame that
 * arrives later than that still goes out, just not ahead of what already
 * left; nothing here can un-emit.
 *
 * Deliberately free of React and the DOM (docs/decisions/0003): this moves into
 * the pipeline Worker in Phase 11 unchanged.
 */

export interface Orderable {
  /** Capture time, epoch microseconds. */
  tsUs: number;
  /** The agent's per-capture sequence number; ties on `tsUs` resolve by it. */
  seq: number;
  /** When this frame reached the browser, in `performance.now()` milliseconds. */
  arrivedAt: number;
}

function compare(a: Orderable, b: Orderable): number {
  return a.tsUs - b.tsUs || a.seq - b.seq;
}

export class OrderingWindow<T extends Orderable> {
  private held: T[] = [];
  private lastReleased: Orderable | null = null;
  /** Frames released behind one that already left - late by more than the hold. */
  public lateCount = 0;

  constructor(public readonly holdMs: number) {}

  get size(): number {
    return this.held.length;
  }

  push(frame: T): void {
    this.held.push(frame);
  }

  /**
   * Everything that has waited at least `holdMs` as of `now`, in capture
   * order. Younger frames stay for the next call.
   */
  drain(now: number): T[] {
    if (this.held.length === 0) return [];
    const cutoff = now - this.holdMs;
    const ready: T[] = [];
    const keep: T[] = [];
    for (const frame of this.held) (frame.arrivedAt <= cutoff ? ready : keep).push(frame);
    this.held = keep;
    return this.release(ready);
  }

  /** Everything, now, in capture order - for stop and for a cleared buffer. */
  flush(): T[] {
    const all = this.held;
    this.held = [];
    return this.release(all);
  }

  clear(): void {
    this.held = [];
    this.lastReleased = null;
    this.lateCount = 0;
  }

  private release(frames: T[]): T[] {
    if (frames.length === 0) return frames;
    // Array.prototype.sort is stable, so equal keys keep arrival order.
    frames.sort(compare);
    if (this.lastReleased !== null) {
      for (const frame of frames) {
        if (compare(frame, this.lastReleased) < 0) this.lateCount++;
        else break; // sorted, so the first in-order frame ends the late run
      }
    }
    this.lastReleased = frames[frames.length - 1];
    return frames;
  }
}
