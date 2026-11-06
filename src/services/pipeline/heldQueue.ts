/**
 * The coordinator's frames not yet routed, each with the in-flight cost taken
 * when it was dispatched (`coordinator.ts`, `held`).
 *
 * The cost is kept rather than read again from `frame.bytes` when the frame is
 * routed: a frame waiting behind a barrier can have had its buffer transferred
 * away by then, and `heldCost` would never return to zero. Item and cost were
 * two arrays the coordinator kept in step by hand, compaction included; here
 * they move together. Two parallel arrays rather than an object per item: this
 * runs once a frame on the coordinator Worker, the pipeline's throughput limit.
 */

/** Taken items after which the arrays are cut down to what is still held. */
const COMPACT_AFTER = 4096;

export class HeldQueue<T> {
  private items: T[] = [];
  private costs: number[] = [];
  private from = 0;
  /** The cost of the item the last `shift` returned. */
  shiftedCost = 0;

  get size(): number {
    return this.items.length - this.from;
  }

  push(item: T, cost: number): void {
    this.items.push(item);
    this.costs.push(cost);
  }

  /** The front item, its cost in `shiftedCost`; undefined when empty. */
  shift(): T | undefined {
    if (this.from === this.items.length) return undefined;
    const item = this.items[this.from];
    this.shiftedCost = this.costs[this.from];
    this.from++;
    if (this.from === this.items.length) this.clear();
    else if (this.from > COMPACT_AFTER) {
      this.items = this.items.slice(this.from);
      this.costs = this.costs.slice(this.from);
      this.from = 0;
    }
    return item;
  }

  /** The item `offset` places behind the front, left where it is. */
  peek(offset: number): T | undefined {
    const at = this.from + offset;
    return at < this.items.length ? this.items[at] : undefined;
  }

  clear(): void {
    this.items = [];
    this.costs = [];
    this.from = 0;
  }
}
