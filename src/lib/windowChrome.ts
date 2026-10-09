import { useEffect, useSyncExternalStore } from 'react';

/**
 * The renderer's half of the window's own title bar.
 *
 * Three things cross to main, and each is here because only one side knows it:
 *
 *  - the **resolved theme**, so main knows what ground to open the NEXT window
 *    on. Main owns the hex (`electron/windowColors.ts`); this sends a name.
 *    Nothing here colours a
 *    window button - those are ours, in CSS, and follow the cascade.
 *  - the **title**, because only this side knows the adapter's name and whether
 *    frames are arriving.
 *  - **maximized and focused**, which travel the other way: they are facts the
 *    OS tells main, and a window drawing its own chrome has to draw what the
 *    frame used to.
 *
 * Every call is guarded on `window.inwire?.`, which is not defensive styling -
 * `src/types/desktop.d.ts` declares the whole bridge optional because the
 * assertion scripts import `src/` under plain Node with no preload at all. A
 * title row that threw without it would take the whole suite down with it.
 */

export interface WindowChromeState {
  /** Maximized, so the layout can stop avoiding the frame's rounded corners. */
  maximized: boolean;
  /**
   * Focused, so the chrome can dim.
   *
   * The dim is `opacity` on the title row, in CSS - main mirrors nothing, and
   * there is no overlay to mirror into. That was the deleted
   * `mixHex`/`setTitleBarOverlay` apparatus, which pre-composited a colour in
   * main and pushed it over IPC.
   */
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
 * Tells main which theme this window resolved to.
 *
 * Nothing on screen depends on the answer - the window's controls are CSS and
 * follow the cascade. Main caches it so the *next* window is constructed with
 * the right `backgroundColor`, which is the one colour decision that happens
 * before a renderer exists to make it.
 *
 * Takes `resolvedTheme`, never `theme`: the picker's third entry, System, is a
 * rule for choosing between the two themes rather than a theme, and has no
 * palette.
 * Skips the undefined tick next-themes has before its mount effect runs - main
 * already opened the window on the cached ground, so saying nothing is better
 * than saying the wrong thing and correcting it.
 */
export function useWindowTheme(resolvedTheme: string | undefined): void {
  useEffect(() => {
    if (resolvedTheme === undefined) return;
    window.inwire?.setWindowTheme?.(resolvedTheme);
  }, [resolvedTheme]);
}

/**
 * The three window buttons' one action, as a stable callback.
 *
 * Here rather than inline in the component so the bridge is reached in exactly
 * one place in the renderer, the same way every other `window.inwire` call in
 * this file is.
 */
export function windowControl(action: 'minimize' | 'toggle-maximize' | 'close'): void {
  window.inwire?.windowControl?.(action);
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
  { capturing, adapter }: { capturing: boolean; adapter: string | null },
): string {
  if (capturing && adapter !== null) return `${adapter} - capturing - Inwire`;
  if (capturing) return 'Capturing - Inwire';
  // **No packet count IN THIS STRING**, which is no longer the same thing as no
  // packet count in the title row.
  //
  // It used to read "2,224 packets - Inwire" once a capture stopped, and that
  // was wrong in two ways at once: a number that changes is the most
  // distracting thing that can go in the one strip a person cannot look away
  // from, and the count was already on screen in the filter bar, against the
  // filter that produced it - so a second copy with no filter attached answered
  // a different question in the same words.
  //
  // The second half has since stopped being true. The filter bar's badge is
  // gone and so is the dock widget that replaced it, so the counter is now the
  // title row's centre and the only copy there is - see
  // `components/common/PacketCountsReadout.tsx`. The first half still stands,
  // and is the accepted cost of putting it there.
  //
  // What this string is for is the part that never wanted a count: the OS.
  // `useWindowTitle` sends it to main, and it names the window in the taskbar,
  // in Alt-Tab and in the window list - places a figure that ticks ten times a
  // second has no business being.
  return 'Inwire';
}
