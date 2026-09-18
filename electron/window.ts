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
 * rail.** Raising it to 1280 breaks half-screen snapping on a 1920px display -
 * Windows gives a 960px window there, and analyser on one half with a terminal
 * on the other is a workflow this tool exists to support. So the rail's 56px
 * comes out of the list's width rather than out of the minimum.
 *
 * The dock used to be the other half of that argument: it reserved 640px for
 * the list, which is what made 1280 tempting and what the snapping rule
 * refused. The dock is deleted and its reserve with it, so only the snapping
 * rule is left - which was always the load-bearing one.
 */
export const MIN_WINDOW_WIDTH = 1024;
/**
 * 680, not 640, and the difference is the title row.
 *
 * The title row spans the full window width now, so the rail starts below it
 * rather than beside it - which is what puts the app's mark at the true
 * top-left corner and lets the rail and the row read as one surface. Taking
 * that height out of the rail instead would push Settings off the bottom edge
 * at the minimum, because the bottom group is pinned with `mt-auto` and an
 * overflow there does not scroll.
 *
 * So the minimum carries the row: 680 - `TITLE_BAR_HEIGHT` (32, declared just
 * below) leaves 648 below it.
 *
 * **The status bar is funded differently, and the difference is deliberate.**
 * `STATUS_BAR_HEIGHT` (24) comes out of that 648 rather than out of this
 * minimum, so the rail's budget is 624 and its 494 of icons keep 130 of slack.
 * The row could not be paid for that way because the rail had no slack to spare
 * when it arrived; the bar can, because six deleted icons left 154. Raising the
 * minimum to 704 instead would have cost every 1366x768 laptop 24px of window
 * for a strip that fits without it. `scripts/session/view.ts` does both
 * subtractions rather than assuming them, and the width is untouched for the
 * half-screen-snapping reason above.
 *
 * Those numbers were 40 / 640 / 630 here for a while, which disagreed with the
 * `TITLE_BAR_HEIGHT` fifteen lines down and with the rail itself. Six deleted
 * icons and a 32px row are what moved them.
 */
export const MIN_WINDOW_HEIGHT = 680;

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
 * **32, and that is the floor rather than a further step.** It was 40, then 36.
 * The reference class spans that range - Windows Terminal puts its tabs in a
 * 40px caption, VS Code runs 35 - and 40 was chosen when this row carried a
 * centred window title and nothing else. It carries a lockup and the packet
 * counter now, both set at 11-12px, so the row was taller than its contents.
 *
 * It cannot go below 32 without redrawing the window buttons, which are 46x32
 * (`WindowControls`) because **32 is Windows' own caption-button metric** rather
 * than a choice this app made. At 32 they fill the row exactly, edge to edge.
 *
 * The 36 in between was chosen to keep 2px of air above and below them, on the
 * argument that it stopped the close button's hit area touching the screen edge
 * when maximised. That was the wrong way round: a maximised window whose close
 * button reaches the very top-left... corner is Fitts's law working, and it is
 * precisely what Windows does with its own caption. The 2px was costing the
 * thing it was meant to protect.
 *
 * `MIN_WINDOW_HEIGHT` has not moved through any of it, and did not move for the
 * status bar either - see the arithmetic in `scripts/session/view.ts`.
 */
export const TITLE_BAR_HEIGHT = 32;

/**
 * The height of the app's own status bar, at the window's bottom edge.
 *
 * **24, which is shorter than the title row on purpose.** The title row is
 * chrome you act on - it drags the window and it holds the caption buttons,
 * whose 32px is Windows' own metric. The status bar is chrome you read. VS Code
 * runs its own at 22; 24 is a step up from that for this app's denser figures,
 * and it is a multiple of the 4px rhythm every other measurement here follows.
 *
 * Unlike the title row, this comes out of the rail's slack rather than out of
 * `MIN_WINDOW_HEIGHT` - the reasoning is on that constant above. The rail is
 * left with 624 against its 494, and `scripts/session/view.ts` fails if that
 * stops being true.
 */
export const STATUS_BAR_HEIGHT = 24;

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

// There is deliberately no `WINDOW_BACKGROUND` here any more, and re-adding one
// would be a second answer to a question that already has one. It was
// `'#09090b'`, a near-black picked to match `index.html`'s own class, and by the
// end nothing imported it: the fallback ground is
// `resolveWindowBackground(DEFAULT_WINDOW_THEME)` in `windowColors.ts`, which
// reads Night's own `--background` out of `PALETTE_BY_THEME` - `#161616`, not
// `#09090b`. A literal here had drifted from the palette by a shade nobody would
// notice until the window flashed it. `windowState.ts` caches what the renderer
// last resolved; `windowColors.ts` is what a profile with nothing stored gets.

/** Chromium switches that must be set before `app.whenReady()`. */
export const COMMAND_LINE_SWITCHES: readonly string[] = [
  'disable-renderer-backgrounding',
  'disable-background-timer-throttling',
  'disable-backgrounding-occluded-windows',
];
