/**
 * The window's security posture, stated once so it can be asserted.
 *
 * `scripts/electron/shell.ts` reads this file and checks every field by name. That is a ratchet in the same spirit as `noUnusedLocals` and
 * `scripts/dissect/registry.ts`: these are not settings, they are decisions,
 * and the cost of one of them quietly flipping is not a failing build - it is
 * an app that still works and is no longer safe.
 *
 * The one that matters most is `nodeIntegrationInWorker`. It is **renderer-wide**,
 * so enabling it would hand `node:fs` and `child_process` not to the storage
 * code that wants them but to `pipeline.worker.ts`, whose entire job is parsing
 * bytes an attacker put on the wire. That is the same argument that keeps the
 * dissector off an administrator account, one layer in - and it is why the
 * capture store runs in a `utilityProcess` instead.
 */

/** The scheme, host and origin the packaged app is served from. */
export { APP_SCHEME, APP_HOST, APP_ORIGIN } from './appPaths';

/**
 * Privileges the `app://` scheme is registered with, before `app.whenReady()`.
 *
 * Every flag here has a silent failure behind it, which is why they are named
 * individually rather than spread from a preset:
 *
 *  - **`standard`** - without it the page's origin is *opaque*, and reading
 *    `globalThis.localStorage` **throws**. `services/preferences.ts` catches
 *    that and returns `null`, so the app runs on defaults with no error
 *    anywhere: every preference, theme, colour rule and filter preset resets on
 *    every launch. It is also what makes root-absolute paths resolve, so
 *    `index.html` needs no edit and Vite's `base` stays `/`.
 *  - **`secure`** - without a secure context `crypto.getRandomValues` is
 *    unavailable and `services/anonymise.ts` falls back to `Math.random()` for
 *    the Crypto-PAn key. The export still works; it is just no longer the
 *    promise the feature makes ("the key is random per export, so two exports
 *    cannot be correlated").
 *  - **`supportFetchAPI` / `corsEnabled`** - the renderer makes four
 *    cross-origin requests (geojs, cloudflare-dns, ipapi, openfreemap tiles),
 *    which will now carry `Origin: app://inwire`.
 *  - **`codeCache`** - the renderer bundle is measured in megabytes; without it
 *    every cold start re-parses all of it.
 *  - **`allowServiceWorkers: false`** - the service worker is being deleted.
 *    An origin that cannot register one cannot inherit a stale one either.
 */
export const SCHEME_PRIVILEGES = {
  standard: true,
  secure: true,
  supportFetchAPI: true,
  corsEnabled: true,
  codeCache: true,
  allowServiceWorkers: false,
} as const;

/**
 * `webPreferences`, in full.
 *
 * `sandbox: true` is what forces the preload to be CommonJS, which is why the
 * Electron sources compile to `dist-electron/` with a `package.json` declaring
 * `"type": "commonjs"` - the repository root declares `"type": "module"` and a
 * sandboxed preload cannot be an ES module.
 */
export const WEB_PREFERENCES = {
  contextIsolation: true,
  nodeIntegration: false,
  nodeIntegrationInWorker: false,
  nodeIntegrationInSubFrames: false,
  sandbox: true,
  webSecurity: true,
  allowRunningInsecureContent: false,
  experimentalFeatures: false,
  /**
   * Chromium downloads a hunspell dictionary from Google the first time a text
   * input takes focus. In a packet analyzer - run by people watching their own
   * traffic - an unexplained request to `redirector.gvt1.com` appearing in the
   * user's own capture is a support ticket and a trust problem.
   */
  spellcheck: false,
  /**
   * The renderer must keep running while the window is hidden or occluded: a
   * capture is still arriving, `useCaptureSchedule` is still counting toward a
   * stop time hours away, and `redirect.ts` is still slicing a derive pass.
   *
   * This alone is not enough - it covers hidden and occluded, not *minimized*
   * - so `main.ts` also passes `--disable-renderer-backgrounding`,
   * `--disable-background-timer-throttling` and
   * `--disable-backgrounding-occluded-windows`.
   */
  backgroundThrottling: false,
} as const;

/**
 * The narrowest window the layout is designed for.
 *
 * This began as the guard against the app's phone layout - `App.tsx` and
 * `PacketList.tsx` used to branch on `window.innerWidth < 768` and keep a
 * `mobileTab`, which a dragged-narrow desktop window could reach. Those
 * branches are gone and `mobileTab` no longer exists, so the number now earns
 * its place on its own: a packet list below about a thousand pixels is a list
 * with no Info column worth reading.
 *
 * **It deliberately stays 1024 now that the window also carries a 56px activity
 * rail and a dock.** Raising it to 1280, which would give the dock more room,
 * breaks half-screen snapping on a 1920px display - Windows gives a 960px
 * window there, and analyser on one half with a terminal on the other is a
 * workflow this tool exists to support. The dock absorbs the pressure instead,
 * by reserving 640px for the list; see the width rule in `src/services/`.
 */
export const MIN_WINDOW_WIDTH = 1024;
export const MIN_WINDOW_HEIGHT = 640;

/**
 * The window is frameless, and draws its own controls.
 *
 * **This reverses an earlier decision, and the entry it replaces was wrong on
 * the facts.** The window used to be `titleBarStyle: 'hidden'` with
 * `titleBarOverlay`, and the comment here said `frame: false` would hand back
 * "Windows' own resize borders, snap layouts on a maximise-button hover, the
 * system menu on Alt+Space and the shadow that tells a focused window from an
 * unfocused one". Two of those four are simply not true, and Electron's own
 * typings say so:
 *
 *   `thickFrame` - "Use `WS_THICKFRAME` style for frameless windows on Windows,
 *   which adds the standard window frame. Setting it to `false` will remove
 *   window shadow and window animations, and disable window resizing via
 *   dragging the window edges. **Default is `true`.**"
 *
 *   `roundedCorners` - "Whether a frameless window should have rounded corners.
 *   **Default is `true`.**"
 *
 * So a frameless window on defaults keeps edge resizing, the drop shadow, the
 * minimise/restore animations and Windows 11's corner radius. **Do not set
 * `thickFrame: false`** - that is the option that would cost all of it, and it
 * is the one this file deliberately never names.
 *
 * What is genuinely lost, and accepted:
 *
 *  - **Snap Layouts**, the flyout on a maximise-button hover. It needs
 *    `WM_NCHITTEST` to answer `HTMAXBUTTON` for our own button's rectangle, and
 *    Electron exposes no hook for that. **Win+Arrow snapping is unaffected** -
 *    it is a window-manager keybinding, not a caption feature.
 *  - **Alt+Space**, the system menu. There is no native caption to raise it
 *    from. The application menu is untouched; `autoHideMenuBar` still shows it
 *    on Alt, which is what supplies Ctrl+C/V/A/Z to every input in the app.
 *
 * Both are recorded in `docs/verification.md` as accepted losses rather than as
 * things to re-check every release.
 */
export const WINDOW_IS_FRAMELESS = true;

/**
 * The height of the app's own title row.
 *
 * 40 is what the reference class settled on - Windows Terminal puts its tabs in
 * a 40px caption, Figma's desktop shell is about the same, VS Code runs 35 and
 * feels cramped for anything but a menu.
 */
export const TITLE_BAR_HEIGHT = 40;

/**
 * One window control's hit target, and how many there are.
 *
 * 46x32 is what Windows itself uses, and matching it is not deference - it is
 * that the target size and spacing are what fifteen years of muscle memory
 * actually aims at. The glyphs inside are 10px, also Windows'.
 *
 * The reserve this produces is a **constant now, and that is the one thing
 * frameless made simpler.** Under `titleBarOverlay` the reserved width had to
 * be read from `env(titlebar-area-width)`, because Windows drew the buttons at
 * ~138px at 100% scaling and ~207px at 150% - a hardcoded value put the app's
 * own content under the close button on any machine that was not at 100%. The
 * buttons are ours now, so they are 138 CSS pixels wide at every scale factor,
 * and `.titlebar-reserve` is gone with the `env()` it needed.
 */
export const WINDOW_CONTROL_WIDTH = 46;
export const WINDOW_CONTROL_HEIGHT = 32;
export const WINDOW_CONTROL_COUNT = 3;

/**
 * The ground the window paints before the renderer has drawn anything.
 *
 * Only the fallback now: `windowState.ts` caches the resolved theme's own
 * ground and `main.ts` opens the window in that, because a frameless window IS
 * the app's surface and opening it in the wrong theme is a full-window flash
 * rather than a dark rectangle behind a native caption. This is what a profile
 * with nothing stored gets. Paired with `show: false` and `ready-to-show`.
 */
export const WINDOW_BACKGROUND = '#09090b';

/** Chromium switches that must be set before `app.whenReady()`. */
export const COMMAND_LINE_SWITCHES: readonly string[] = [
  'disable-renderer-backgrounding',
  'disable-background-timer-throttling',
  'disable-backgrounding-occluded-windows',
];
