/**
 * Decrypted answers, by frame, in memory only (ADR 0049).
 *
 * A frame record never holds plaintext: the owner's rule is that decrypted
 * content stays in memory. So the answers a record refuses - HTTP/3 frames out
 * of a 1-RTT QUIC packet, a decrypting TLS connection's HTTP state - are kept
 * here instead, encoded, beside the on-disk record, and a revisit reads them
 * from here. Without them the revisit misses and the frame is replayed.
 *
 * Bounded by bytes, oldest first out, because what it holds is as large as the
 * traffic that was decrypted. Emptied when the key log is cleared - the same
 * moment the tree cache is, for the same reason - and on a reset, when the
 * frames it describes are no longer the capture.
 */

/** The least it is ever given, and what it holds until told otherwise. */
export const DERIVED_BUDGET_BYTES = 64 * 1024 * 1024;

/** The share of the packet buffer's budget it gets. */
export const DERIVED_BUFFER_SHARE = 1 / 4;

/**
 * How much decrypted content to keep, from the packet buffer's budget.
 *
 * Tied to that budget rather than fixed, because it is the one memory figure
 * a person already chose - or that `'auto'` sized to the machine (ADR 0036) -
 * for how much of a capture stays in reach. At 64 MB flat it covered about nine
 * minutes of decrypted browsing (the key-log fixture's 8.2 MB in 75 seconds),
 * and every decrypted frame older than that was replayed. A quarter of a
 * 2,096 MB buffer is 524 MB: about 80 minutes of the same. Never less than
 * the old figure, and never past the buffer's own quarter: this is plaintext,
 * and holding more of it than the frames it belongs to is not a trade worth
 * making.
 */
export function derivedBudgetFor(bufferBytes: number): number {
  return Math.max(DERIVED_BUDGET_BYTES, Math.floor(bufferBytes * DERIVED_BUFFER_SHARE));
}

export class DerivedStore {
  /** Insertion order is age: the first key is the oldest. */
  private readonly byFrame = new Map<number, Uint8Array>();
  private held = 0;

  constructor(private budget = DERIVED_BUDGET_BYTES) {}

  /** A new budget, applied at once: shrinking lets the oldest go now. */
  resize(budget: number): void {
    this.budget = budget;
    this.evictToFit();
  }

  private evictToFit(): void {
    while (this.held > this.budget) {
      const oldest = this.byFrame.entries().next();
      if (oldest.done) break;
      this.byFrame.delete(oldest.value[0]);
      this.held -= oldest.value[1].length;
    }
  }

  set(id: number, derived: Uint8Array): void {
    const previous = this.byFrame.get(id);
    if (previous !== undefined) {
      this.held -= previous.length;
      this.byFrame.delete(id);
    }
    // One frame larger than the whole budget is not kept at all, rather than
    // emptying everything else to make room for it.
    if (derived.length > this.budget) return;
    this.byFrame.set(id, derived);
    this.held += derived.length;
    this.evictToFit();
  }

  /** A frame's decrypted answers, or null when it had none or they have gone. */
  get(id: number): Uint8Array | null {
    return this.byFrame.get(id) ?? null;
  }

  clear(): void {
    this.byFrame.clear();
    this.held = 0;
  }

  /** Everything held, oldest first - for handing an import's answers to the Worker. */
  entries(): [number, Uint8Array][] {
    return [...this.byFrame];
  }

  get bytes(): number {
    return this.held;
  }

  get size(): number {
    return this.byFrame.size;
  }
}
