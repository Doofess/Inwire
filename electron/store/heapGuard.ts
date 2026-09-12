/**
 * The capture store's memory ceiling, enforced by us because V8 will not.
 *
 * ## The flag that does nothing
 *
 * `host.ts` forks the store with `execArgv: ['--max-old-space-size=2048']`,
 * and the comment beside it says a runaway store then kills itself rather than
 * the machine. **It does not.** Measured against the running app: the flag
 * arrives - `process.execArgv` in the store reads back
 * `["--max-old-space-size=2048"]` - and `v8.getHeapStatistics().heap_size_limit`
 * is **4192 MB**, V8's own 64-bit default. `v8.setFlagsFromString` at the top
 * of the entry point does not move it either, because V8 reads the limit when
 * it creates the isolate and the isolate already exists.
 *
 * The remaining lever is `--js-flags` on the Electron command line, which is
 * process-wide: it would put the same ceiling on main and on the renderer,
 * which is not what anyone wants. And `NODE_OPTIONS` is the wrong direction
 * entirely - `enableNodeOptionsEnvironmentVariable` is a fuse this app intends
 * to turn **off** before signing.
 *
 * ## So: a watchdog, which is better than the flag was
 *
 * A blown V8 heap aborts. It prints `MarkCompactCollector: young object
 * promotion failed` to a stderr a packaged GUI app pipes into a log nobody is
 * reading, the process dies, and the app says "the capture store stopped
 * (exit 134)". That is a worse experience than the ceiling was meant to buy.
 *
 * Sampling the heap and standing down deliberately says *why*, once at 80% so
 * the capture can be stopped while it is still whole and again at the ceiling.
 * The renderer already handles a store that exits - `child.on('exit')` over
 * its own channel - so the ending is a handled state either way; the
 * difference is whether anyone can tell what happened.
 *
 * ## Where the number comes from
 *
 * 2 GB is what the inert flag asked for, kept so the intent does not change
 * with the mechanism. The store's job is a staging ring, a chunk being
 * deflated, and 32 cached chunk directories - single-digit megabytes in
 * steady state. Anything approaching 2 GB means something is being retained
 * that should not be, and the honest response to that is to stop rather than
 * to keep going more slowly.
 *
 * Imports nothing from Electron, so `scripts/capture/heap-guard.ts` drives it.
 */

/** What the inert `--max-old-space-size=2048` asked for. */
export const HEAP_CEILING_BYTES = 2 * 1024 * 1024 * 1024;

/** Where the warning goes out, as a share of the ceiling. */
export const HEAP_WARN_RATIO = 0.8;

/** How often the heap is sampled. Cheap - `getHeapStatistics` is not a GC. */
export const HEAP_SAMPLE_MS = 2_000;

export type HeapVerdict =
  | { level: 'ok' }
  /** Said once. A second warning per sample would be 30 messages a minute. */
  | { level: 'warn'; message: string }
  | { level: 'stop'; message: string };

const OK: HeapVerdict = { level: 'ok' };

function mb(bytes: number): string {
  return `${Math.round(bytes / 1024 / 1024).toLocaleString()} MB`;
}

/**
 * Whether the store should say something, or stop.
 *
 * @param used     `heap_used_size` this sample.
 * @param limit    V8's own limit, which is the real wall and may be *lower*
 *                 than the ceiling on a 32-bit build or under a container
 *                 memory cap. Standing down at our number when V8's is
 *                 smaller would let V8 abort first, which is the whole thing
 *                 being avoided - so the effective ceiling is the lower of
 *                 the two, with room to unwind.
 * @param warned   Whether the warning has already gone out.
 * @param ceiling  Overridable so the assertions do not have to allocate 2 GB.
 */
export function judgeHeap(
  used: number, limit: number, warned: boolean, ceiling = HEAP_CEILING_BYTES,
): HeapVerdict {
  // 90% of V8's limit, because the last tenth is where the collector spends
  // its time and a process that gets there is already unusable.
  const wall = Math.min(ceiling, Math.floor(limit * 0.9));
  if (used >= wall) {
    return {
      level: 'stop',
      message: `the capture store used ${mb(used)} of memory, past its ${mb(wall)} ceiling, `
        + 'and stopped. The capture on disk is intact up to the last sealed chunk.',
    };
  }
  if (!warned && used >= wall * HEAP_WARN_RATIO) {
    return {
      level: 'warn',
      message: `the capture store is using ${mb(used)} of its ${mb(wall)} ceiling. `
        + 'Stop the capture to keep it whole.',
    };
  }
  return OK;
}
