import { useEffect, useSyncExternalStore } from 'react';

/**
 * The renderer's half of the window's own title bar.
 *
 * Three things cross to main, and each is here because only one side knows it:
 *
 *  - the **resolved theme**, so main can colour the native window buttons. Main
 *    owns the hex (`electron/titleBarColors.ts`); this sends a name.
 *  - the **title**, because only this side knows the adapter's name and whether
 *    frames are arriving.
 *  - **maximized and focused**, which travel the other way: they are facts the
 *    OS tells main, and a window drawing its own chrome has to draw what the
 *    frame used to.
 *
 * Every call is guarded on `window.inwire?.`, which is not defensive styling -
 * `src/types/desktop.d.ts` declares the whole bridge optional because the
 * assertion scripts import `src/` under plain Node with no preload at all. A
 * title row that threw without it would take 137 scripts down with it.
 */

export interface WindowChromeState {
  /** Maximized, so the layout can stop avoiding the frame's rounded corners. */
  maximized: boolean;
  /** Focused, so the chrome can dim. Main mirrors this into the overlay. */
  focused: boolean;
}

/**
 * Assumed focused and restored until main says otherwise.
 *
 * Both defaults are the common case and, more to the point, the harmless one:
 * a restored window that is briefly painted as restored is correct, and a
 * focused window painted as focused does not flash. The inverse defaults would
 * dim every launch for one frame.
 */
const INITIAL: WindowChromeState = { maximized: false, focused: true };

let current: WindowChromeState = INITIAL;
const listeners = new Set<() => void>();

function readState(value: unknown): WindowChromeState | null {
  if (typeof value !== 'object' || value === null) return null;
  const state = value as Record<string, unknown>;
  // Field by field, the house rule for anything crossing a process boundary:
  // the sender is in another TypeScript program and this side says what it
  // accepts. A half-readable message keeps the half it could read.
  return {
    maximized: typeof state.maximized === 'boolean' ? state.maximized : current.maximized,
    focused: typeof state.focused === 'boolean' ? state.focused : current.focused,
  };
}

/**
 * Subscribed once, at module scope, rather than from the hook.
 *
 * The hook may mount in more than one place - the title row needs `focused`,
 * the layout needs `maximized` - and a per-mount subscription would register a
 * listener per consumer for a value that is global to the window. This is the
 * same shape `preferenceStore.ts` uses for the same reason.
 */
let subscribed = false;
function subscribe(listener: () => void): () => void {
  if (!subscribed) {
    subscribed = true;
    window.inwire?.onWindowState?.((value) => {
      const next = readState(value);
      if (next === null) return;
      if (next.maximized === current.maximized && next.focused === current.focused) return;
      current = next;
      for (const fn of listeners) fn();
    });
  }
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/** Whether the window is maximized and focused. Safe with no bridge. */
export function useWindowChrome(): WindowChromeState {
  return useSyncExternalStore(subscribe, () => current, () => INITIAL);
}

/**
 * Tells main which theme to paint the native buttons for.
 *
 * Takes `resolvedTheme`, never `theme`: the picker's fifth entry, System, is a
 * rule for choosing between two themes rather than a theme, and has no palette.
 * Skips the undefined tick next-themes has before its mount effect runs - main
 * already opened the window in the cached pair, so saying nothing is better
 * than saying the wrong thing and correcting it.
 */
export function useTitleBarTheme(resolvedTheme: string | undefined): void {
  useEffect(() => {
    if (resolvedTheme === undefined) return;
    window.inwire?.setTitleBarTheme?.(resolvedTheme);
  }, [resolvedTheme]);
}

/**
 * Sets the window title.
 *
 * Effect rather than a render-time call, because `setTitle` is a side effect on
 * another process and React may render this twice for every one time it commits.
 */
export function useWindowTitle(title: string): void {
  useEffect(() => {
    window.inwire?.setWindowTitle?.(title);
  }, [title]);
}

/**
 * What the window calls itself, given what the capture is doing.
 *
 * A function so `scripts/session/` can assert the wording without a window.
 * The adapter leads when there is one: an analyst with several windows open is
 * looking for the one on the interface they care about, and "Inwire" four times
 * in the taskbar tells them nothing.
 */
export function windowTitleFor(
  { capturing, adapter, packets }: { capturing: boolean; adapter: string | null; packets: number },
): string {
  if (capturing && adapter !== null) return `${adapter} - capturing - Inwire`;
  if (capturing) return 'Capturing - Inwire';
  // A buffer with frames in it but no capture running is a finished capture
  // somebody may still be reading, which is worth distinguishing from an empty
  // window - it is also the state `guardClose` refuses to quit out of silently.
  if (packets > 0) return `${packets.toLocaleString()} packets - Inwire`;
  return 'Inwire';
}
