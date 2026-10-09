/**
 * How many threads dissect a live capture's TCP (ADR 0053 phase 3).
 *
 * The setting is **Multi Threaded Capture**: Auto, or a count. 1 is the single
 * Worker, exactly as it was. A count above 1 is that many shard Workers, beside
 * the coordinator that numbers and merges every frame. Auto leaves two cores
 * for everything else this machine runs while a capture does - the renderer,
 * main and the capture store, each a process of its own, and the agent - and
 * stops at a ceiling past which a shard only adds a heap: the coordinator
 * merges every frame on one core, and that is where the next limit is
 * (`scripts/perf/ui-burst-drive.ts`). A count chosen by hand may go past that
 * ceiling, up to one fewer than the machine's cores.
 */

/** The counts the setting offers, before `threadChoices` drops what this machine cannot run. */
export const THREAD_CHOICES = [1, 2, 4, 6, 8, 12, 16] as const;
export type ThreadCount = (typeof THREAD_CHOICES)[number];
export type DissectionThreads = 'auto' | ThreadCount;

/** No more shards than this for Auto, however many cores. */
export const MAX_SHARDS = 6;

/** The shards `auto` means on a machine with this many cores; 0 is the single Worker. */
export function autoShards(cores: number): number {
  const shards = Math.min(MAX_SHARDS, Math.floor(cores) - 2);
  // One shard beside the coordinator is a second core for TCP and a hop for
  // every segment; below two it is not worth the hop.
  return shards >= 2 ? shards : 0;
}

/**
 * The shards a setting asks for: 0 for the single Worker.
 *
 * A count is held below the machine's cores, so a setting carried to a smaller
 * machine runs as many as that machine has room for rather than more threads
 * than cores - and never fewer than two, for the reason `autoShards` gives.
 */
export function shardsFor(setting: DissectionThreads, cores: number): number {
  if (setting === 'auto') return autoShards(cores);
  if (setting === 1) return 0;
  return Math.max(2, Math.min(setting, Math.floor(cores) - 1));
}

/** The counts worth offering on a machine with this many cores: 1, and whatever leaves a core for the coordinator. */
export function threadChoices(cores: number): ThreadCount[] {
  return THREAD_CHOICES.filter((n) => n === 1 || n <= Math.floor(cores) - 1);
}

/** A stored value read back: Auto, an offered count, or null for anything else. */
export function readThreads(value: unknown): DissectionThreads | null {
  if (value === 'auto') return 'auto';
  return (THREAD_CHOICES as readonly unknown[]).includes(value) ? value as ThreadCount : null;
}
