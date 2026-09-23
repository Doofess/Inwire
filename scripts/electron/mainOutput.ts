/**
 * Main's stdout, split into what the capture store said and everything else.
 *
 * Shared by `disk-drive.ts` and `import-drive.ts`, which both assert the store
 * stayed quiet. It is deliberately not an assertion script itself: `check.ts`
 * only treats a file as one if it contains `process.exit`, which is the same
 * reason `stubAgent.ts` sits beside it without being run.
 *
 * ## Why this is not a `split('\n')` in each driver
 *
 * Both drivers used to collect **every** line main printed and assert the list
 * was empty, under a name about the store. On any machine with the agent
 * service installed that failed twice a run on `[agent-pipe] auto start:
 * started` - the supervisor reporting normal operation - so the first fix was
 * to keep only lines carrying `[capture-store:`, the prefix
 * `electron/store/host.ts` puts on both of the child's streams.
 *
 * **That fix opened a silent pass, which is the one thing this check must
 * never do.** Two reasons, both about how the bytes actually arrive:
 *
 * - **`data` events are chunks, not lines.** Node emits whatever the pipe
 *   delivered, so a marker can straddle a boundary: one chunk ending
 *   `...[capture-` and the next beginning `store:err] ...` yields two
 *   fragments, *neither* containing the marker. Both would be filed as
 *   unasserted output, the store's complaint would never reach the list, and
 *   the assertion would pass. Before the fix any output at all failed the
 *   check, so this could not happen - the fix is what made it possible.
 *
 *   A partial line is therefore held back until its newline arrives, and
 *   `flush()` classifies whatever is left.
 *
 * - **The prefix is per CHUNK, not per line.** `host.ts` writes
 *   `` console.log(`[capture-store:${stream}] ${text}`) `` where `text` is a
 *   whole `data.toString().trimEnd()`, so only the first line of a multi-line
 *   store message is marked. `CaptureHost` deliberately logs stack traces to
 *   stderr, so the marked line would be the message and every frame beneath it
 *   would be filed as unrelated - the assertion still trips, and the reason it
 *   tripped ends up somewhere else.
 *
 *   So a line that does not begin a new prefixed record continues the previous
 *   one. That is a heuristic and is named as one: it reads `[` at the start of
 *   a line as "a new record", which is true of `[capture-store:` and of
 *   `[agent-pipe]`, and not of a stack frame.
 *
 * The silent-pass half is the same shape as the mistake ADR 0041 records -
 * a measurement wrapped in `.catch(() => {})` that published a different
 * number. Narrowing what a check looks at is the same act as catching what it
 * would have thrown.
 */

/** A new record starts at a bracketed prefix; anything else continues one. */
const STARTS_A_RECORD = /^\[/;
const STORE_MARKER = '[capture-store:';

export interface MainOutput {
  /** Lines the capture store printed. Both drivers assert this is empty. */
  readonly store: string[];
  /** Everything else main printed. Reported, never asserted. */
  readonly other: string[];
  /**
   * Classifies whatever is still buffered.
   *
   * Must be called before reading either list: a process that ends without a
   * trailing newline leaves its last line held back, and that line is exactly
   * as likely to be the one that mattered.
   */
  flush(): void;
  /**
   * Prints the unasserted lines that have arrived since the last call.
   *
   * Since the last call, because `disk-drive.ts` asserts the store twice - once
   * after the capture and once after the filter and the disk reads - and a
   * report that only ran at the first of them threw away everything from the
   * most store-intensive half of the run. The commit that introduced this
   * split said the rest was "printed rather than asserted: still visible", and
   * in one of the two files it was not.
   */
  report(): void;
}

export function watchMainOutput(stdout: NodeJS.ReadableStream | null | undefined): MainOutput {
  const store: string[] = [];
  const other: string[] = [];
  let tail = '';
  let inStore = false;
  let reported = 0;

  const classify = (line: string): void => {
    if (!line.trim()) return;
    if (line.includes(STORE_MARKER)) {
      inStore = true;
      store.push(line);
      return;
    }
    if (STARTS_A_RECORD.test(line)) {
      inStore = false;
      other.push(line);
      return;
    }
    (inStore ? store : other).push(line);
  };

  stdout?.on('data', (data: Buffer | string) => {
    tail += String(data);
    const lines = tail.split(/\r?\n/);
    // The last element is either a partial line or an empty string after a
    // trailing newline. Either way it is not ready to classify.
    tail = lines.pop() ?? '';
    for (const line of lines) classify(line);
  });

  const flush = (): void => {
    if (!tail) return;
    const held = tail;
    tail = '';
    classify(held);
  };

  return {
    store,
    other,
    flush,
    report(): void {
      flush();
      const fresh = other.slice(reported);
      reported = other.length;
      if (fresh.length === 0) return;
      console.log(`      ${fresh.length} other line(s) from main, reported not asserted:`);
      for (const line of fresh.slice(0, 5)) console.log(`        ${line.slice(0, 120)}`);
      if (fresh.length > 5) console.log(`        ... and ${fresh.length - 5} more`);
    },
  };
}
