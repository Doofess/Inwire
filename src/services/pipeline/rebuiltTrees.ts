import type { ProtocolLayer } from '../../types/packet';

/**
 * The Worker's few trees rebuilt from their records, for a frame looked at
 * twice (ADR 0049). Arrival's cache is separate.
 *
 * A later frame can still write a link into one (`tcp.reassembled_in`, a
 * response's frame) - and since shards keep no tree (ADR 0072), that is the
 * normal case for a recent TCP or QUIC frame. A kept tree a link lands on is
 * dropped, and so is a rebuild that was waiting on the store when it landed,
 * so the next click rebuilds from a store that has the link.
 * `scripts/pipeline/rebuilt-trees.ts`.
 */
export class RebuiltTrees {
  private readonly trees = new Map<number, ProtocolLayer[]>();
  /** Rebuilds under way, and whether a link has landed on each since it began. */
  private readonly building = new Map<number, boolean>();

  constructor(private readonly limit: number) {}

  get(id: number): ProtocolLayer[] | undefined {
    return this.trees.get(id);
  }

  /** A rebuild of `id` asks the store for its kit. */
  begin(id: number): void {
    if (!this.building.has(id)) this.building.set(id, false);
  }

  /** A rebuild ends, with its tree or with null; the tree is kept unless a link landed meanwhile. */
  keep(id: number, layers: ProtocolLayer[] | null): void {
    const stale = this.building.get(id) === true;
    this.building.delete(id);
    if (layers === null || stale) return;
    this.trees.delete(id);
    this.trees.set(id, layers);
    while (this.trees.size > this.limit) {
      const oldest = this.trees.keys().next();
      if (oldest.done) break;
      this.trees.delete(oldest.value);
    }
  }

  /** A later frame wrote a link into `id`. */
  patched(id: number): void {
    this.trees.delete(id);
    if (this.building.has(id)) this.building.set(id, true);
  }

  /**
   * A key log or capture went away: no kept tree stands, nor one still being
   * rebuilt from what was there before - it could hold plaintext.
   */
  clear(): void {
    this.trees.clear();
    for (const id of this.building.keys()) this.building.set(id, true);
  }
}
