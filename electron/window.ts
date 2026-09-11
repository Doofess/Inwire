/**
 * The window's security posture, stated once so it can be asserted.
 *
 * `scripts/electron/window-options.ts` reads this file and checks every field
 * by name. That is a ratchet in the same spirit as `noUnusedLocals` and
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
 * A window narrower than this enters the app's phone layout.
 *
 * `App.tsx` and `PacketList.tsx` branch on `window.innerWidth < 768` and keep a
 * `mobileTab`, which a browser could reach and a desktop window can too, just
 * by being dragged narrow. Until those branches are removed this is what stops
 * it, and it is worth having afterwards regardless: a packet list below about
 * a thousand pixels is a list with no Info column worth reading.
 */
export const MIN_WINDOW_WIDTH = 1024;
export const MIN_WINDOW_HEIGHT = 640;

/**
 * The ground the window paints before the renderer has drawn anything.
 *
 * `index.html` carries `class="bg-zinc-950"`, so a default white window flashes
 * for as long as a multi-megabyte bundle takes to parse. Paired with
 * `show: false` and `ready-to-show` in `main.ts`.
 */
export const WINDOW_BACKGROUND = '#09090b';

/** Chromium switches that must be set before `app.whenReady()`. */
export const COMMAND_LINE_SWITCHES: readonly string[] = [
  'disable-renderer-backgrounding',
  'disable-background-timer-throttling',
  'disable-backgrounding-occluded-windows',
];
