/**
 * A map by frame id that keeps its newest `capacity` entries.
 *
 * What the tree caches were, as a `Map` dropping `keys().next()` on every
 * insert past the cap - and that is quadratic in a way nothing on screen
 * shows: V8's ordered hash table leaves a hole for each delete until it next
 * rebuilds, and `keys().next()` walks the holes from the front, so a full
 * cache scans up to its whole capacity of them per frame. The order of
 * insertion is kept here in a ring instead, and the map is only ever looked
 * up by key (`scripts/perf/parallel-threads.ts` measured the Map's cost).
 */
export class FifoMap<V> {
  private readonly map = new Map<number, V>();
  private readonly order: Float64Array;
  private next = 0;

  constructor(private readonly capacity: number) {
    this.order = new Float64Array(capacity).fill(-1);
  }

  set(id: number, value: V): void {
    if (!this.map.has(id)) {
      const gone = this.order[this.next];
      if (gone >= 0) this.map.delete(gone);
      this.order[this.next] = id;
      this.next = (this.next + 1) % this.capacity;
    }
    this.map.set(id, value);
  }

  get(id: number): V | undefined {
    return this.map.get(id);
  }

  has(id: number): boolean {
    return this.map.has(id);
  }

  get size(): number {
    return this.map.size;
  }

  clear(): void {
    this.map.clear();
    this.order.fill(-1);
    this.next = 0;
  }
}
