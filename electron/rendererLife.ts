/**
 * Whether main may talk to a page, and what to do when the page dies.
 *
 * Kept free of Electron so `scripts/electron/renderer-life.ts` can hold both
 * decisions under plain tsx. A crashed renderer keeps its BrowserWindow and its
 * webContents, and nothing reloads it, so a window that is not destroyed is not
 * a window that can be sent to.
 */

/** The two facts a send depends on; `Electron.WebContents` has both. */
export interface SendTarget {
  isDestroyed(): boolean;
  isCrashed(): boolean;
}

/**
 * Every main-to-page send asks this first. A send to a crashed page does not
 * throw; Electron logs "Render frame was disposed before WebFrameMain could be
 * accessed" for each one. The order is deliberate: `isCrashed` on a destroyed
 * webContents throws, so it is never asked.
 */
export function canSend(contents: SendTarget): boolean {
  return !contents.isDestroyed() && !contents.isCrashed();
}

/** The `render-process-gone` details this module reads. */
export interface CrashDetails {
  reason: string;
  exitCode: number;
}

/**
 * What main does when a page is gone: nothing for a clean exit, which is not a
 * crash; the crash screen, a page loaded into the same window; or the OS's box.
 *
 * The box is only for the crash screen dying itself. Loading the crash screen
 * over a crash screen that keeps dying would loop for ever, and a page that
 * cannot stay up is the one case where the OS's task dialog (light whatever the
 * theme, but alive) beats a window that blinks. The dead page's own URL is the
 * evidence, so no flag has to be remembered across the reload; its query is
 * ignored, because the screen carries the reason there.
 */
export function crashResponse(
  details: CrashDetails,
  deadUrl: string,
): 'none' | 'screen' | 'native' {
  if (details.reason === 'clean-exit') return 'none';
  let pathname = '';
  try {
    pathname = new URL(deadUrl).pathname;
  } catch {
    // Not a URL: the page was never the crash screen.
  }
  return pathname.endsWith('/crash.html') ? 'native' : 'screen';
}

/**
 * A background launch shows no OS box (a modal one would sit in front of the
 * owner and hang the test), so a test names the answer in
 * `INWIRE_CRASH_ANSWER`. Anything else is no answer.
 */
export function readCrashAnswer(value: string | undefined): 'reload' | 'quit' | null {
  return value === 'reload' || value === 'quit' ? value : null;
}
