/**
 * The one way a script starts the app.
 *
 * Every test launch goes through here so that it runs in the BACKGROUND: the
 * person who owns this machine works on it while the suite runs, and a window
 * that pops up and takes focus on every `npm run check` is a window in front
 * of their work. `INWIRE_BACKGROUND_WINDOW=1` makes `electron/main.ts` never
 * show the window; it still paints, so DOM waits and screenshots work.
 *
 * `{ visible: true }` is the explicit opt-out for a check that needs a real
 * foreground window. `scripts/electron/background-launch.ts` fails any script
 * that calls Playwright's launch directly instead.
 */
import type { _electron } from 'playwright';

export type LaunchOptions = Parameters<typeof _electron.launch>[0] & { visible?: boolean };

export async function launchApp(options: LaunchOptions = {}): ReturnType<typeof _electron.launch> {
  // Imported here so a script that skips cleanly without playwright still can.
  const { _electron } = await import('playwright');
  const { visible, ...rest } = options;
  if (visible) return _electron.launch(rest);
  return _electron.launch({
    ...rest,
    env: { ...(rest.env ?? process.env) as Record<string, string>, INWIRE_BACKGROUND_WINDOW: '1' },
  });
}
