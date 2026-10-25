/**
 * The renderer's memory ceiling, which until now did not exist at all.
 *
 * ## Why this is the thing that was blocking a bigger buffer
 *
 * The packet buffer was capped at 1 GB, defaulting to 512 MB, and the obvious
 * question - *why not as much RAM as the machine has?* - has an answer that is
 * not about RAM. The buffer lives in the renderer's JavaScript heap, V8 fixes
 * that heap's limit when it creates the isolate (4,192 MB by default on
 * 64-bit), and past it V8 does not slow down, it **aborts**.
 *
 * `electron/store/heapGuard.ts` is the same argument already made and already
 * measured, one process over: the capture store carried
 * `--max-old-space-size=2048` for months, the flag arrived, and
 * `heap_size_limit` stayed at 4192 MB regardless. What stands in its place
 * there is a watchdog. The store got one because it was seen to die at
 * 4,060 MB. **The renderer never got one**, and it is the process holding the
 * buffer, the dissected trees, React's tree and a virtualized hex dump.
 *
 * So the cap was doing the guard's job badly: a number low enough that nobody
 * reached the wall. Raising it safely means measuring the heap and standing
 * down on purpose, which is what this does.
 *
 * ## What a deliberate stop buys over an abort
 *
 * A V8 abort takes the window with it. There is no dialog, no log line the user
 * can reach, and the capture's last frames are wherever the writer got to. The
 * app reads as having crashed, because it has.
 *
 * Standing down stops the capture and says why, with the capture on disk
 * intact - and on this app that is a genuinely mild outcome rather than a
 * consolation, because the buffer is a *window* onto a capture that is entirely
 * on disk (ADR 0025). Frames leaving it are still in the list and still
 * readable. What is lost by stopping is the frames that had not arrived yet.
 *
 * Imports nothing - no Electron, no `node:*`, no React - so
 * `scripts/session/renderer-heap-guard.ts` drives it under plain `tsx`, and
 * `scripts/capture/node-safe.ts` stays satisfied.
 */

/** Where the warning goes out, as a share of the wall. */
export const HEAP_WARN_RATIO = 0.8;

/**
 * How often the heap is sampled.
 *
 * Matches the store's guard. `performance.memory` is a read of counters V8
 * already maintains, not a collection, so this costs nothing measurable - but
 * it runs for the life of the window, which is the reason not to make it
 * faster rather than a reason to worry about it.
 */
export const HEAP_SAMPLE_MS = 2_000;

/**
 * How much of V8's limit is usable before the collector is the whole workload.
 *
 * The store's guard uses the same 0.9 and for the same measured reason: the
 * last tenth is where mark-compact spends its time, and a process that gets
 * there is unusable before it is dead.
 */
export const HEAP_USABLE_RATIO = 0.9;

/**
 * A fall between two samples at least this large is a full collection.
 *
 * A scavenge frees the young generation, tens of megabytes, about 1-2% of a
 * heap near its wall. Near the limit a full collection may free under a tenth,
 * because V8's peaks have little room above the live size there, so the line
 * sits between the two.
 */
export const HEAP_COLLECTED_DROP = 0.05;

/**
 * Samples past the wall, with no collection among them, that stop a capture.
 *
 * The fallback for a heap that never shows a trough. 30 s: after a capture
 * stopped at 60,000 frames a second, its garbage sat at 4.1 GB for 14 s before
 * a collection ran (issue #15).
 */
export const HEAP_UNCOLLECTED_SAMPLES = 15;

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
 * Whether the renderer should say something, or stop capturing.
 *
 * @param used    Bytes of JS heap judged live: what `HeapJudge` makes of the
 *                samples, never one raw sample, which counts garbage too.
 * @param limit   V8's own limit for this isolate, or 0/null when the browser
 *                will not say. **An unknown limit is not a licence to keep
 *                going and not a reason to stop**: it returns `ok`, because a
 *                guard that stopped captures on a machine it could not measure
 *                would be worse than the absence it replaced. The buffer budget
 *                makes the same choice from the same fact.
 * @param warned  Whether the warning has already gone out.
 */
export function judgeRendererHeap(
  used: number, limit: number | null, warned: boolean,
): HeapVerdict {
  if (!limit || limit <= 0 || !Number.isFinite(used) || used <= 0) return OK;

  const wall = Math.floor(limit * HEAP_USABLE_RATIO);
  if (used >= wall) {
    return {
      level: 'stop',
      message: `Inwire used ${mb(used)} of memory, past its ${mb(wall)} ceiling, and stopped `
        + 'the capture. Everything captured so far is on disk and still readable. '
        + 'A smaller packet buffer in Settings > Interface will let a capture run longer.',
    };
  }
  if (!warned && used >= wall * HEAP_WARN_RATIO) {
    return {
      level: 'warn',
      message: `Inwire is using ${mb(used)} of its ${mb(wall)} memory ceiling. `
        + 'The capture will stop itself if it reaches the ceiling; '
        + 'the frames already captured are on disk either way.',
    };
  }
  return OK;
}

/**
 * What the browser will tell us about this heap, or nulls.
 *
 * `performance.memory` is **non-standard and Chromium-only**, which is exactly
 * why it is isolated here behind a shape the assertions can construct: the app
 * runs in Chromium and nothing else, but a module that reads it inline is a
 * module that cannot be tested off one.
 *
 * It is also gated on cross-origin isolation in some Chromium configurations,
 * and this app IS cross-origin isolated (`ISOLATION_HEADERS` in `main.ts`), so
 * it is expected to be there - expected, not assumed. Absent reads as unknown,
 * and `judgeRendererHeap` treats unknown as "say nothing".
 */
export interface HeapReading {
  used: number | null;
  limit: number | null;
}

interface ChromiumMemory {
  usedJSHeapSize?: number;
  jsHeapSizeLimit?: number;
}

export function readHeap(): HeapReading {
  const memory = (performance as Performance & { memory?: ChromiumMemory }).memory;
  if (!memory) return { used: null, limit: null };
  return {
    used: typeof memory.usedJSHeapSize === 'number' ? memory.usedJSHeapSize : null,
    limit: typeof memory.jsHeapSizeLimit === 'number' ? memory.jsHeapSizeLimit : null,
  };
}

/**
 * Turns a run of samples into a verdict on the heap's live size.
 *
 * `usedJSHeapSize` counts garbage until a full collection runs, and V8 lets the
 * heap grow to several times its live size before one. At 60,000 frames a
 * second a live set of 1.1-1.9 GB read as a sawtooth up to 4.1 GB, and a guard
 * on one sample stopped the capture with nothing near the wall (issue #15). So
 * this judges a **trough**: a sample that fell by `HEAP_COLLECTED_DROP` or more
 * from the one before, which is what a collection left plus at most one sample
 * interval of allocation. A live set that really climbs shows it in its troughs.
 * A heap past the wall that shows no collection for `HEAP_UNCOLLECTED_SAMPLES`
 * is judged as it reads.
 */
export class HeapJudge {
  private previous = 0;
  private trough: number | null = null;
  private uncollected = 0;
  private warned = false;

  judge(used: number, limit: number | null): HeapVerdict {
    if (!limit || limit <= 0 || !Number.isFinite(used) || used <= 0) return OK;
    const wall = Math.floor(limit * HEAP_USABLE_RATIO);
    const collected = this.previous > 0 && used <= this.previous * (1 - HEAP_COLLECTED_DROP);
    this.previous = used;
    if (collected) {
      this.trough = used;
      this.uncollected = 0;
    } else if (used >= wall) {
      this.uncollected += 1;
    } else {
      this.uncollected = 0;
    }
    const live = Math.max(this.trough ?? 0, this.uncollected >= HEAP_UNCOLLECTED_SAMPLES ? used : 0);
    const verdict = judgeRendererHeap(live, limit, this.warned);
    if (verdict.level === 'warn') this.warned = true;
    return verdict;
  }
}

export interface HeapGuardHost {
  /** Called once when the heap crosses the warning line. */
  onWarn(message: string): void;
  /** Called once when it reaches the wall. Must stop the capture. */
  onStop(message: string): void;
}

/**
 * Samples the heap until the returned function is called.
 *
 * The warning latches, and **the stop latches too** - `onStop` fires once per
 * guard rather than once per sample. Without that, a heap that stays at the
 * wall (which it will, briefly, since stopping a capture does not collect
 * anything synchronously) would call it thirty times a minute, and `onStop`
 * puts a message on screen.
 */
export function startRendererHeapGuard(host: HeapGuardHost): () => void {
  const judge = new HeapJudge();
  let stopped = false;

  const timer = setInterval(() => {
    if (stopped) return;
    const { used, limit } = readHeap();
    if (used === null) return;
    const verdict = judge.judge(used, limit);
    if (verdict.level === 'warn') {
      host.onWarn(verdict.message);
    } else if (verdict.level === 'stop') {
      stopped = true;
      host.onStop(verdict.message);
    }
  }, HEAP_SAMPLE_MS);

  return () => clearInterval(timer);
}
