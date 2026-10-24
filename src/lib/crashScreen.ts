/**
 * The crash screen's vocabulary, shared by main, the crash page and the tests.
 *
 * In `src/lib/` because all of them can import it and it imports nothing, the
 * way `quitConfirm.ts` is. When the renderer dies the app has no page to draw
 * its own dialogs on, so main loads a small second page (`crash.html`) into the
 * same window, and that page and main's OS-box fallback must say the same words
 * from one copy.
 *
 * **The exit code is not in any wording.** It means nothing to the person
 * reading and is a number they would copy into a search box; main logs it
 * (`[renderer] gone: <reason> (exit code N)`) and that is its only home.
 */

export const CRASH_SCREEN_TEXT = {
  title: "Inwire's window stopped working",
  followUp:
    'Reload brings the window back. Frames already written to the capture store are kept '
    + 'either way, and Inwire offers them when it opens again.',
  buttons: { reload: 'Reload', quit: 'Quit' },
} as const;

/**
 * Electron's `render-process-gone` reason in plain words, because
 * "integrity-failure" means nothing to the person reading. Anything not named,
 * including a reason a later Electron adds, gets the plain sentence.
 */
export function crashReasonSentence(reason: string): string {
  switch (reason) {
    case 'crashed': return 'The page crashed.';
    case 'oom': return 'The page ran out of memory.';
    case 'killed': return 'The page was ended by another program or by Windows.';
    case 'launch-failed': return 'The page could not start.';
    case 'integrity-failure': return "Windows refused to run the page's code.";
    default: return 'The page exited unexpectedly.';
  }
}

/** The detail line of the OS's box, the fallback when the crash screen cannot load. */
export function crashNativeDetail(reason: string): string {
  return `${crashReasonSentence(reason)} ${CRASH_SCREEN_TEXT.followUp}`;
}

/** Where the crash page is served from, under the app's origin or the dev server's. */
export const CRASH_SCREEN_PATH = '/crash.html';

/** The query that carries Electron's reason to the crash page. */
export function crashScreenSearch(reason: string): string {
  return `?reason=${encodeURIComponent(reason)}`;
}

/**
 * The reason off the crash page's own query, or `unknown`, which reads as the
 * plain sentence. Never throws: a malformed escape is a page that still opens.
 */
export function readCrashReason(search: string): string {
  try {
    return new URLSearchParams(search).get('reason') ?? 'unknown';
  } catch {
    return 'unknown';
  }
}
