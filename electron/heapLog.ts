/**
 * What main says about the page's memory: a crash code it can name, and the
 * heap timeline `npm run start:app` asks for.
 *
 * Kept free of Electron so `scripts/electron/heap-log.ts` holds both under
 * plain tsx. `main.ts` is the adapter: it reads the numbers and prints the line.
 *
 * ## Why a timeline
 *
 * The renderer died twice (2026-10-24 and 2026-10-30) with `crashed (exit code
 * -36861)` and nothing else. A forced V8 out-of-memory in a test launch exits
 * with exactly that reason and code, so both were the page's JavaScript heap
 * reaching its 4,192 MB limit. Chromium's own log says no more than that: its
 * stack capture at the limit fails ("Near V8 cage limit"), because the heap
 * limit is the pointer-compression cage. What it cannot say is whether the
 * heap crept up or jumped, and when; a line every ten seconds can.
 */

/** Set by `electron/start.cjs`; a packaged app never logs the heap. */
export const HEAP_LOG_ENV = 'INWIRE_HEAP_LOG';

export const HEAP_LOG_INTERVAL_MS = 10_000;

export function heapLogEnabled(value: string | undefined): boolean {
  return value === '1';
}

/**
 * The exit code a forced V8 out-of-memory gave on Windows, Electron 44.3.0
 * (`performance.memory` at 3,949 of 4,192 MB, reason `crashed`, not `oom`).
 * Re-measure after an Electron upgrade: the number is Chromium's, not ours.
 */
export const RENDERER_OOM_EXIT_CODE = -36861;

/** What a crash's exit code means, when it is one we have measured. */
export function crashCodeMeaning(exitCode: number, platform: string): string | null {
  return platform === 'win32' && exitCode === RENDERER_OOM_EXIT_CODE ? 'out of JavaScript heap' : null;
}

/** The `[renderer] gone` line, with the code's meaning when it has one. */
export function crashLine(reason: string, exitCode: number, platform: string): string {
  const meaning = crashCodeMeaning(exitCode, platform);
  return `[renderer] gone: ${reason} (exit code ${exitCode}${meaning ? `: ${meaning}` : ''})`;
}

/** One timeline sample. Either reading may be missing: a busy page answers late. */
export interface HeapSample {
  at: Date;
  /** `performance.memory.usedJSHeapSize` and `jsHeapSizeLimit`, bytes. */
  jsUsed: number | null;
  jsLimit: number | null;
  /** The renderer process's private bytes, from `app.getAppMetrics()` (KB there, bytes here). */
  privateBytes: number | null;
}

const mb = (bytes: number | null): string =>
  bytes === null ? '?' : Math.round(bytes / 1_048_576).toLocaleString('en-US');

export function heapLine(sample: HeapSample): string {
  const time = sample.at.toTimeString().slice(0, 8);
  return `[heap] ${time} page js ${mb(sample.jsUsed)} / ${mb(sample.jsLimit)} MB, renderer private ${mb(sample.privateBytes)} MB`;
}
