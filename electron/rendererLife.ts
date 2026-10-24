/**
 * Whether main may talk to a page, and what to ask when the page dies.
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

export interface CrashPrompt {
  message: string;
  detail: string;
}

/** Reload is first, and it is also what Esc and the default pick. */
export const CRASH_BUTTONS = ['Reload', 'Quit'] as const;

const CRASH_FOLLOW_UP =
  'Reload brings the window back. Quit closes Inwire, and still asks first if a capture is unsaved.';

/**
 * The box shown after a crash, or null when the process simply exited cleanly,
 * which is not a crash. The reason is put in plain words because Electron's
 * own strings ("integrity-failure") mean nothing to the person reading.
 */
export function crashPrompt(details: CrashDetails): CrashPrompt | null {
  if (details.reason === 'clean-exit') return null;
  let first: string;
  switch (details.reason) {
    case 'crashed': first = `The page crashed (exit code ${details.exitCode}).`; break;
    case 'oom': first = 'The page ran out of memory.'; break;
    case 'killed': first = 'The page was ended by another program or by Windows.'; break;
    case 'launch-failed': first = 'The page could not start.'; break;
    case 'integrity-failure': first = "Windows refused to run the page's code."; break;
    default: first = `The page exited unexpectedly (exit code ${details.exitCode}).`;
  }
  return { message: "Inwire's window stopped working", detail: `${first} ${CRASH_FOLLOW_UP}` };
}

/**
 * A background launch shows no box (a modal one would sit in front of the
 * owner and hang the test), so a test names the answer in
 * `INWIRE_CRASH_ANSWER`. Anything else is no answer.
 */
export function readCrashAnswer(value: string | undefined): 'reload' | 'quit' | null {
  return value === 'reload' || value === 'quit' ? value : null;
}
