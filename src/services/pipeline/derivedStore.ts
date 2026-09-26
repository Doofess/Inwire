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

/** The default budget: enough for the decrypted tail of a long capture. */
export const DERIVED_BUDGET_BYTES = 64 * 1024 * 1024;

export class DerivedStore {
  /** Insertion order is age: the first key is the oldest. */
  private readonly byFrame = new Map<number, Uint8Array>();
  private held = 0;

  constructor(private readonly budget = DERIVED_BUDGET_BYTES) {}

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
    while (this.held > this.budget) {
      const oldest = this.byFrame.entries().next();
      if (oldest.done) break;
      this.byFrame.delete(oldest.value[0]);
      this.held -= oldest.value[1].length;
    }
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
