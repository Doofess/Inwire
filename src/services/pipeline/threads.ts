/**
 * How many TCP shards a live capture is dissected on (ADR 0053 phase 3).
 *
 * The setting is **Dissection threads: auto / 1**. One is the single Worker,
 * exactly as it was. Auto leaves two cores for everything else this machine
 * runs while a capture does - the renderer, main and the capture store, each a
 * process of its own, and the agent - and stops at a ceiling past which a
 * shard only adds a heap: the coordinator merges every frame on one core, and
 * that is where the next limit is (`scripts/perf/ui-burst-drive.ts`).
 */
export type DissectionThreads = 'auto' | 1;

/** No more shards than this, however many cores. */
export const MAX_SHARDS = 6;

/** The shards `auto` means on a machine with this many cores; 0 is the single Worker. */
export function autoShards(cores: number): number {
  const shards = Math.min(MAX_SHARDS, Math.floor(cores) - 2);
  // One shard beside the coordinator is a second core for TCP and a hop for
  // every segment; below two it is not worth the hop.
  return shards >= 2 ? shards : 0;
}

/** The shards a setting asks for: 0 for the single Worker. */
export function shardsFor(setting: DissectionThreads, cores: number): number {
  return setting === 1 ? 0 : autoShards(cores);
}
