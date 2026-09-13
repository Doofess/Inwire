/**
 * Where the window was last time.
 *
 * ## Why this cannot be a preference
 *
 * Every other setting in this app lives in `localStorage` and stays there -
 * `main.tsx` reads three of them **synchronously at module scope, before
 * `createRoot`**, precisely because a React effect runs after the first paint
 * and the user would see a flash. That argument is why preferences are not
 * being moved to files.
 *
 * Window bounds are the exception, and for the mirror-image reason: the main
 * process has to size and position the window *before a renderer exists at
 * all*, so it cannot ask `localStorage` anything. A small JSON file beside the
 * app's other state is the only place this can live.
 *
 * **The window's own ground colour is here for exactly that reason and no
 * other.** `backgroundColor` is fixed when the window is constructed, long
 * before a renderer could report a theme, so the alternative is opening every
 * window in one theme's colour and correcting it a beat later. That was a
 * survivable flaw while a native caption sat above the page; on a frameless
 * window the ground IS the app's surface, so it is a full-window flash. The
 * theme itself still lives in `localStorage` like every other preference; this
 * is a cache of what it resolved to last time, written by the renderer and read
 * by main, and it is never the source of truth.
 *
 * Failure is always silent and always falls back to the default. A window that
 * opens in the wrong place is a smaller problem than an app that will not open.
 */
import { app, screen, type BrowserWindow } from 'electron';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { TITLE_BAR_HEIGHT } from './window';
import {
  DEFAULT_WINDOW_THEME, isHexColor, resolveWindowBackground,
} from './windowColors';

export interface WindowBounds {
  width: number;
  height: number;
  x?: number;
  y?: number;
}

export interface WindowState {
  bounds: WindowBounds;
  maximized: boolean;
  /** The resolved theme's `--background`, for the very first paint. */
  background: string;
}

const DEFAULT_STATE: WindowState = {
  bounds: { width: 1600, height: 950 },
  maximized: false,
  background: resolveWindowBackground(DEFAULT_WINDOW_THEME),
};

/**
 * The last ground the renderer reported, held for the next `save()`.
 *
 * Module state rather than a field on the tracker because the two halves are
 * written by different things at different times: bounds change on a drag, the
 * colour changes on a theme switch, and both end up in one file. One window at
 * a time is guaranteed by `requestSingleInstanceLock` in `main.ts`.
 */
let lastBackground: string = DEFAULT_STATE.background;

/**
 * Records the theme's ground colour, for the *next* launch.
 *
 * Repaints nothing. `backgroundColor` is only read when a window is
 * constructed, so this cannot affect the window that is open - it exists so the
 * window that opens tomorrow opens in the colour the user was last looking at
 * rather than flashing the default and correcting itself.
 */
export function rememberBackground(background: string): void {
  lastBackground = background;
}

function statePath(): string {
  return path.join(app.getPath('userData'), 'window-state.json');
}

/**
 * Reads the saved bounds, discarding any that no longer land on a screen.
 *
 * The case this exists for is ordinary: the app was last used with a second
 * monitor attached. Restoring those coordinates puts the window somewhere the
 * user cannot see it and cannot drag it back from, which reads as "the app
 * launched and did nothing".
 */
export function loadWindowState(): WindowState {
  let stored: Partial<WindowState> | null = null;
  try {
    stored = JSON.parse(readFileSync(statePath(), 'utf8')) as Partial<WindowState>;
  } catch {
    return DEFAULT_STATE;
  }

  const bounds = stored?.bounds;
  if (
    typeof bounds?.width !== 'number' || typeof bounds?.height !== 'number'
    || bounds.width < 1 || bounds.height < 1
  ) {
    return DEFAULT_STATE;
  }

  const state: WindowState = {
    bounds: { width: bounds.width, height: bounds.height },
    maximized: stored?.maximized === true,
    // Validated as a hex string rather than trusted: this goes straight to
    // Electron's `backgroundColor`, which rejects a malformed value at
    // construction - a profile that stops the app opening at all, which is the
    // one outcome this file exists to avoid.
    background: isHexColor(stored?.background) ? stored.background : DEFAULT_STATE.background,
  };
  lastBackground = state.background;

  if (typeof bounds.x === 'number' && typeof bounds.y === 'number' && onSomeScreen(bounds)) {
    state.bounds.x = bounds.x;
    state.bounds.y = bounds.y;
  }
  return state;
}

function onSomeScreen(bounds: WindowBounds): boolean {
  if (bounds.x === undefined || bounds.y === undefined) return false;
  // A window counts as reachable if its title bar is inside a display, which
  // is what the user needs in order to drag it anywhere else. The title bar is
  // now the app's own, so the height comes from the constant rather than from a
  // guess at what Windows draws.
  return screen.getAllDisplays().some(({ workArea }) =>
    bounds.x! >= workArea.x - bounds.width + 120
    && bounds.x! <= workArea.x + workArea.width - 120
    && bounds.y! >= workArea.y
    && bounds.y! <= workArea.y + workArea.height - TITLE_BAR_HEIGHT);
}

/**
 * Saves on move, resize and close.
 *
 * Debounced, because a drag fires continuously and this writes a file. The
 * bounds recorded are the **restored** ones: saving a maximized window's bounds
 * would mean unmaximizing it later put it at full-screen size with a title bar,
 * which is not a state the user ever chose.
 */
export function trackWindowState(window: BrowserWindow): void {
  let timer: NodeJS.Timeout | undefined;

  const save = (): void => {
    if (window.isDestroyed()) return;
    const state: WindowState = {
      bounds: window.getNormalBounds(),
      maximized: window.isMaximized(),
      background: lastBackground,
    };
    try {
      mkdirSync(path.dirname(statePath()), { recursive: true });
      writeFileSync(statePath(), JSON.stringify(state), 'utf8');
    } catch {
      // A read-only or full profile directory. The window still works.
    }
  };

  const schedule = (): void => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(save, 400);
  };

  window.on('resize', schedule);
  window.on('move', schedule);
  window.on('maximize', schedule);
  window.on('unmaximize', schedule);
  // Synchronously on close: the debounce would not fire in time.
  window.on('close', () => {
    if (timer) clearTimeout(timer);
    save();
  });
}
