/**
 * The Electron main process: the app's actual entry point.
 *
 * ## What belongs here
 *
 * OS-owned things, and nothing else. The window, the menu, the `app://`
 * handler, the single-instance lock, native dialogs, and later the named pipe
 * to the capture agent and the `utilityProcess` that owns the capture files.
 * Every decision worth testing lives beside this file as a pure module
 * (`appPaths.ts`, `window.ts`, `csp.ts`) so `scripts/electron/*` can drive it
 * under plain Node - the same rule `capture.worker.ts` states for itself.
 *
 * ## Two things that are load-bearing and look like boilerplate
 *
 * `app.setName('Inwire')` must come before anything reads `userData`, or a dev
 * run lands in `…\Electron` and a packaged run in `…\Inwire`: two profiles, two
 * localStorages, two single-instance locks, and a capture directory that
 * changes depending on how the app was started.
 *
 * And `userData` is moved out of **Roaming**. Electron's default is
 * `%APPDATA%`, which on a domain-joined machine replicates to a file server at
 * logoff - and the capture store is about to start writing multi-gigabyte
 * files into it.
 */
import {
  app, BrowserWindow, dialog, ipcMain, Menu, protocol, session, shell,
} from 'electron';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { APP_HOST, APP_ORIGIN, APP_SCHEME, decideServe } from './appPaths';
import {
  AGENT_PORT_REQUEST, KEYLOG_ATTACH_CHANNEL, KEYLOG_CHOOSE_CHANNEL,
  KEYLOG_FOLLOW_SUGGESTED_CHANNEL, KEYLOG_FORGET_CHANNEL,
  SAVE_FILE_CHANNEL, STORE_INGEST_PORT_REQUEST, STORE_PORT_REQUEST,
  WINDOW_CONTROL_CHANNEL,
  UNSAVED_CAPTURE_CHANNEL, UPDATE_APPLY_CHANNEL, UPDATE_CHECK_CHANNEL, UPDATE_STATE_CHANNEL,
  SPEEDTEST_CANCEL_CHANNEL, SPEEDTEST_START_CHANNEL,
  UPDATE_STATE_REQUEST, WINDOW_STATE_CHANNEL, WINDOW_THEME_CHANNEL, WINDOW_TITLE_CHANNEL,
  QUIT_CONFIRM_CHANNEL, QUIT_CONFIRM_REPLY_CHANNEL,
} from './channels';
import { QuitConfirm } from './quitConfirm';
import { QUIT_CONFIRM_TEXT, readQuitConfirmReply } from '../src/lib/quitConfirm';
import { saveGeneratedFile, type SaveFileRequest } from './saveFile';
import { registerSaveStream } from './saveStream';
import { registerSaveCaptured } from './saveCaptured';
import { KeyLogFollower } from './keyLogFollower';
import { AgentPipeLink } from './agentPipe';
import { isComponentId } from './updateCenter/components';
import { UpdateCenter } from './updateCenter/host';
import { SpeedTestHost } from './speedTest/host';
import { captureDirectory, CaptureStoreHost } from './store/host';
import { developmentCsp, productionCsp } from './csp';
import { buildMenu } from './menu';
import { loadWindowState, rememberBackground, trackWindowState } from './windowState';
import { resolveWindowBackground } from './windowColors';
import {
  COMMAND_LINE_SWITCHES,
  MIN_WINDOW_HEIGHT,
  MIN_WINDOW_WIDTH,
  SCHEME_PRIVILEGES,
  WEB_PREFERENCES,
} from './window';

/**
 * `INWIRE_BACKGROUND_WINDOW=1` parks the window off-screen and shows it without
 * activation, so a test launch neither takes focus from the person working on
 * this machine nor appears in front of them. Set by
 * `scripts/electron/launchApp.ts` for every script that starts the app.
 */
const BACKGROUND_WINDOW = process.env.INWIRE_BACKGROUND_WINDOW === '1';
const BACKGROUND_PARK = -20000;
/**
 * Where the renderer comes from in development.
 *
 * Set by `npm run dev`. When it is absent the app serves itself from `app://`,
 * which is what `npm run start:app` does **without packaging** - and that
 * script exists because otherwise the protocol handler, the MIME table, the
 * 404 rule and the CSP would only ever be exercised in a packaged build.
 */
const DEV_SERVER_URL = process.env.INWIRE_DEV_SERVER ?? '';

/**
 * Cross-origin isolation, on every `app://` response.
 *
 * Together these make `crossOriginIsolated` true, which gates
 * `SharedArrayBuffer` and `Atomics.wait` between the renderer and its own
 * Workers - so the pipeline Worker can eventually share the frame index with
 * the UI rather than posting copies of it.
 *
 * **Every** response, not just the document, and that is the whole lesson
 * here: a dedicated worker's script must carry the header itself even when it
 * is same-origin. Set only on the document, this blocks
 * `pipeline.worker-*.js` with `coep-frame-resource-needs-coep-header` - which
 * is no dissection at all, and maplibre's worker with it, which is the tiles
 * silently never arriving.
 *
 * The outbound hosts are unaffected. `require-corp` is satisfied either by a
 * CORP header or by a successful CORS check, and every one of geojs,
 * openfreemap, cloudflare-dns and ipapi is reached by a CORS `fetch`.
 * Verified against the running app: 200 from geojs and from openfreemap with
 * isolation on.
 */
const ISOLATION_HEADERS = {
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
} as const;

/** The built renderer, beside the compiled main process. */
const RENDERER_ROOT = path.join(__dirname, '..', 'dist');

app.setName('Inwire');
app.setAppUserModelId('com.inwire.app');
// Before anything touches userData. Local, not Roaming - see the header.
//
// `INWIRE_USER_DATA` overrides it, and that is not a debugging nicety: this
// profile holds the stored capture, and startup PRUNES it - so anything that
// launches the app writes into a real person's captures and deletes what was
// there. `scripts/electron/smoke.ts` runs on every `npm run check` and would
// otherwise destroy a developer's work every time.
//
// Chromium's own `--user-data-dir` cannot do this job: the `setPath` below
// overrides it unconditionally, which is exactly what makes the Local-not-
// Roaming decision reliable. So the escape hatch has to be here.
app.setPath('userData', process.env.INWIRE_USER_DATA
  || path.join(app.getPath('appData'), '..', 'Local', 'Inwire'));

for (const flag of COMMAND_LINE_SWITCHES) app.commandLine.appendSwitch(flag);
// A parked window must keep painting through a locked or Remote Desktop
// session, where Windows would otherwise report it occluded and Chromium
// throttle it. (`disable-backgrounding-occluded-windows` is in the list above.)
if (BACKGROUND_WINDOW) app.commandLine.appendSwitch('disable-features', 'CalculateNativeWinOcclusion');

protocol.registerSchemesAsPrivileged([
  { scheme: APP_SCHEME, privileges: { ...SCHEME_PRIVILEGES } },
]);

/**
 * One instance, and it is not politeness.
 *
 * From the moment the capture store writes real files, two instances means two
 * writers on one set of four files with no handle exclusivity to stop them -
 * OPFS's `readwrite-unsafe` semantics were the browser's version of that guard,
 * and a filesystem has none.
 */
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    const [existing] = BrowserWindow.getAllWindows();
    if (!existing) return;
    if (existing.isMinimized()) existing.restore();
    existing.focus();
  });

  void app.whenReady().then(start);
}

/**
 * Whether the renderer is holding frames that quitting would discard.
 *
 * Pushed from the renderer whenever it changes. Main asks nothing at quit
 * time: the answer has to be available synchronously inside a `close` handler,
 * and the renderer may be mid-flush.
 */
let unsavedCapture = false;
/** Set once the reader has said yes, so the guard does not ask twice. */
let quitConfirmed = false;
/** The capture store, forked on the renderer's first request for its port. */
const store = new CaptureStoreHost(captureDirectory());
/**
 * The link to the capture agent.
 *
 * Here rather than in the pipeline Worker because it is a named pipe, and
 * neither a renderer nor a Web Worker can open one. That inverts the old
 * constraint exactly: while the transport was a WebSocket the socket *had* to
 * be in the renderer, because `is_origin_allowed` refused a connection with no
 * `Origin` and only a renderer sends one.
 *
 * `INWIRE_AGENT_PIPE` overrides the pipe name, and that is not a debugging
 * nicety either. `scripts/electron/smoke.ts` has to serve a stub agent, and on
 * a development machine the real service already holds the production name -
 * so without an override the smoke test's only honest option is to SKIP, which
 * is exactly what it did. It follows the four existing `INWIRE_*` variables and
 * is read once here rather than baked into a build.
 */
const agent = new AgentPipeLink(process.env.INWIRE_AGENT_PIPE || undefined, captureDirectory());

/**
 * Everything that updates, in one place.
 *
 * In main because it fetches, writes a file and raises a UAC prompt, none of
 * which a sandboxed renderer can do - and deliberately so, since the file it
 * writes is the file that gets run elevated.
 */
const updates = new UpdateCenter({
  onChange: (snapshot) => {
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed()) window.webContents.send(UPDATE_STATE_CHANNEL, snapshot);
    }
  },
  // A new driver means new adapters, and the picker is showing the list from
  // before it existed. See `AgentPipeLink.recycle` for why this is a
  // reconnect and not `refresh_adapters`.
  onDriverInstalled: () => agent.recycle(),
});

async function start(): Promise<void> {
  // Built here rather than at module scope because `userData` can be moved by
  // `INWIRE_USER_DATA` before this runs, and the settings file lives there.
  const keyLogs = new KeyLogFollower(path.join(app.getPath('userData'), 'keylog.json'));
  // **None of these four reads an argument.** The renderer names no path; it
  // can only ask main to follow a file main already knows - one picked in
  // main's own dialog, or main's own `SSLKEYLOGFILE`. See `keyLogFollower.ts`.
  // `scripts/electron/keylog-follow.ts` holds these handlers to that.
  ipcMain.handle(KEYLOG_ATTACH_CHANNEL, (event) => keyLogs.attach(event.sender));
  ipcMain.handle(KEYLOG_CHOOSE_CHANNEL, (event) =>
    keyLogs.choose(BrowserWindow.fromWebContents(event.sender)));
  ipcMain.handle(KEYLOG_FOLLOW_SUGGESTED_CHANNEL, () => keyLogs.followSuggested());
  ipcMain.handle(KEYLOG_FORGET_CHANNEL, () => keyLogs.forget());
  app.on('will-quit', () => keyLogs.stop());

  ipcMain.on(UNSAVED_CAPTURE_CHANNEL, (_event, hasFrames: unknown) => {
    unsavedCapture = hasFrames === true;
  });
  // The renderer reports its resolved theme; main owns the hex. Nothing is
  // repainted - `backgroundColor` is read once, when a window is constructed -
  // so this only records what the NEXT launch should open on.
  ipcMain.on(WINDOW_THEME_CHANNEL, (_event, theme: unknown) => {
    const name = typeof theme === 'string' ? theme : undefined;
    rememberBackground(resolveWindowBackground(name));
  });

  // The three buttons the app draws for itself, now that the window is
  // frameless. `close()` and never `destroy()`: the quit guard hangs off the
  // `close` event, and a button that skipped it would discard a capture on one
  // click with no confirm.
  ipcMain.on(WINDOW_CONTROL_CHANNEL, (event, action: unknown) => {
    const window = BrowserWindow.fromWebContents(event.sender);
    if (window === null || window.isDestroyed()) return;
    if (action === 'minimize') window.minimize();
    else if (action === 'close') window.close();
    else if (action === 'toggle-maximize') {
      if (window.isMaximized()) window.unmaximize();
      else window.maximize();
    }
    // Anything else is ignored. The renderer is typed to the union, so an
    // unknown verb means the bridge was reached by something that is not this
    // app's own code.
  });
  // A title, not a format string: what the window should say is a product
  // decision and it is made in the renderer, which is the only place that
  // knows the adapter's name and whether frames are arriving.
  ipcMain.on(WINDOW_TITLE_CHANNEL, (event, title: unknown) => {
    const window = BrowserWindow.fromWebContents(event.sender);
    if (window === null || window.isDestroyed()) return;
    // Guarded rather than trusted: `setTitle` takes whatever it is given, and a
    // window titled `undefined` is the kind of defect nobody files.
    if (typeof title === 'string' && title.trim() !== '') window.setTitle(title);
  });
  ipcMain.handle(STORE_PORT_REQUEST, async (event) => {
    store.watch(event.sender);
    await store.connect(event.sender);
  });
  // The second channel, one-way, for frames on their way to disk. The renderer
  // only ferries it; its destination is the pipeline Worker. ADR 0038.
  ipcMain.handle(STORE_INGEST_PORT_REQUEST, async (event) => {
    await store.connectIngest(event.sender);
  });
  ipcMain.handle(AGENT_PORT_REQUEST, (event) => {
    agent.attach(event.sender);
  });
  ipcMain.handle(SAVE_FILE_CHANNEL, (event, request: SaveFileRequest) =>
    saveGeneratedFile(event, request));
  registerSaveStream(ipcMain);
  registerSaveCaptured(ipcMain, captureDirectory());
  ipcMain.handle(UPDATE_STATE_REQUEST, () => updates.snapshot());
  ipcMain.handle(UPDATE_CHECK_CHANNEL, () => updates.check());
  ipcMain.handle(UPDATE_APPLY_CHANNEL, (_event, id: unknown) => {
    // The only message here that ends in an elevated process. A renderer
    // string stops being a renderer string on this line.
    if (!isComponentId(id)) return undefined;
    return updates.apply(id);
  });
  // The speed test (ADR 0054): one click, one test, nothing the renderer says
  // reaches the engine but "start" and "cancel".
  const speedTest = new SpeedTestHost();
  ipcMain.handle(SPEEDTEST_START_CHANNEL, () => speedTest.start());
  ipcMain.handle(SPEEDTEST_CANCEL_CHANNEL, () => speedTest.cancel());
  app.on('will-quit', () => speedTest.dispose());
  // The store seals whatever is open when it goes; killing it here rather than
  // leaving it to be orphaned is what keeps a clean quit from looking like a
  // crash to the next launch's recovery pass.
  app.on('will-quit', () => {
    store.stop();
    // The pipe holds a handle the agent counts as a live client, and a client
    // going away is what stops a capture nobody is watching. Dropping it here
    // rather than leaving it to process teardown is what makes a clean quit
    // stop the sniffer promptly instead of on the agent's own timeout.
    agent.detach();
  });
  registerAppProtocol();
  hardenSession(session.defaultSession);
  Menu.setApplicationMenu(buildMenu({ packaged: app.isPackaged }));
  // Before the window, and deliberately not awaited. The agent is demand-start
  // (ADR 0035), so something has to ask for it, and asking here is what makes
  // the link land while the window is still painting rather than after a
  // renderer has mounted, found the pipe shut, diagnosed it and offered a
  // button. A slow SCM must delay the agent, never the window.
  agent.ensureRunning();
  const firstWindow = await createWindow();

  // **After the window, not before it.** `updates.detect()` spawns `reg` once
  // or twice and sometimes `powershell.exe`, and it used to run at
  // `whenReady()` - unawaited, but still competing with `loadURL` for a cold
  // disk and whatever Defender does to a freshly installed binary. Nobody reads
  // an Update Center row until Settings is opened, so the rows have until then.
  //
  // The agent's spawns stay where they are, above: they are on the critical
  // path to a working capture and `agentPipe.ts` argues that case.
  firstWindow.once('ready-to-show', () => {
    void updates.detect();
    // The store forks on the renderer's first port request, which it makes
    // after 4 MB of bundle has parsed and `App` has mounted - so the fork, a
    // process spawn plus a 239 kB CJS parse, sat between "the app is on screen"
    // and "a capture can start". Asking here overlaps it with the parse.
    // `ensure()` memoises on `this.spawned`, so this is idempotent and the
    // renderer's own request still works exactly as it did.
    store.warm();
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) void createWindow();
  });
}

/**
 * Serves the built renderer, and **404s rather than falling back**.
 *
 * `server.ts`'s `app.get('*')` fallback caused two silent failures that
 * `vite.config.ts` documents at length - an installer that downloaded as HTML,
 * and a map worker that parsed HTML as a module and died before registering a
 * handler. Every Electron custom-scheme example reproduces that fallback. This
 * app has no router, so `decideServe` gives the shell only to extension-less
 * paths and refuses everything else it cannot find.
 */
function registerAppProtocol(): void {
  protocol.handle(APP_SCHEME, async (request) => {
    const url = new URL(request.url);
    if (url.host !== APP_HOST) {
      return new Response(null, { status: 404 });
    }

    const decision = decideServe(url.pathname);
    if (decision.kind === 'refuse') {
      return new Response(decision.reason, { status: 400 });
    }

    const relative = decision.kind === 'shell' ? 'index.html' : decision.relative;
    const mime = decision.kind === 'shell' ? 'text/html; charset=utf-8' : decision.mime;
    const absolute = path.join(RENDERER_ROOT, relative);

    // `readFile` rather than `net.fetch(pathToFileURL(...))`: `fs` reads
    // through an asar archive and `file://` does not.
    try {
      const body = await readFile(absolute);
      return new Response(body, { headers: { 'content-type': mime, ...ISOLATION_HEADERS } });
    } catch {
      return new Response(null, { status: 404 });
    }
  });
}

/**
 * Everything a renderer is allowed to do to the outside world.
 *
 * The defaults are wrong for this app in three ways, and all three are grants
 * rather than denials: Electron grants every permission request by default,
 * opens a real window for every `target="_blank"`, and lets a page navigate
 * itself anywhere.
 *
 * The navigation rules matter more here than in most apps.
 * `GeoMap.tsx` renders a link whose hostname came from **reverse DNS of
 * captured traffic** - a string an attacker on the wire chooses. In a browser
 * that opens a tab; unhandled in Electron it opens a window carrying this
 * app's own privileges, and `shell.openExternal` on an unvalidated string is a
 * documented path to running a local program.
 */
function hardenSession(target: Electron.Session): void {
  target.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  target.setPermissionCheckHandler(() => false);

  const csp = DEV_SERVER_URL ? developmentCsp(DEV_SERVER_URL) : productionCsp();
  /**
   * Only the app's own responses, which are the only ones a CSP governs.
   *
   * Registered with no filter, this fired for **every response in the
   * session** - so every openfreemap basemap tile, hundreds of them on a
   * single pan of the globe, plus every DoH answer and every geo-IP lookup,
   * was serialised into the main process's JavaScript and back out again to
   * attach a header that means nothing on a tile. Main is the process holding
   * the pipe to a privileged service; it has no business on the map's paint
   * path.
   *
   * The dev server is in the list because `DEV_SERVER_URL` is where the
   * document comes from under `npm run dev`, and a policy that stopped being
   * applied there would only be noticed in production.
   *
   * `scripts/electron/shell.ts` asserts the policy's CONTENT rather than where
   * it is applied, so it is unaffected - which is worth saying, because a gate
   * that had pinned the registration shape would have made this look unsafe.
   */
  const governed = [`${APP_ORIGIN}/*`, ...(DEV_SERVER_URL ? [`${DEV_SERVER_URL}/*`] : [])];
  target.webRequest.onHeadersReceived({ urls: governed }, (details, callback) => {
    // The isolation headers are NOT set here. `onHeadersReceived` does not
    // fire for `protocol.handle` responses, so setting them here reached the
    // document (which Chromium synthesises differently) and not the worker
    // scripts - and a worker script under COEP must carry the header itself,
    // same-origin or not. Measured: `pipeline.worker` and maplibre's worker
    // both failed with `coep-frame-resource-needs-coep-header`, which for the
    // pipeline worker means no dissection at all. They live on the Response in
    // `registerAppProtocol` instead.
    callback({
      responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': [csp] },
    });
  });

  app.on('web-contents-created', (_event, contents) => {
    contents.setWindowOpenHandler(({ url }) => {
      openExternally(url);
      return { action: 'deny' };
    });
    contents.on('will-navigate', (event, url) => {
      if (url.startsWith(APP_ORIGIN) || (DEV_SERVER_URL && url.startsWith(DEV_SERVER_URL))) return;
      event.preventDefault();
      openExternally(url);
    });
  });
}

/** Hands a link to the system browser, and only if it is plainly a web link. */
function openExternally(raw: string): void {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return;
  void shell.openExternal(parsed.toString());
}

/** Tells the renderer what only main is told: maximized, and focused. */
function sendWindowState(window: BrowserWindow): void {
  if (window.isDestroyed()) return;
  window.webContents.send(WINDOW_STATE_CHANNEL, {
    maximized: window.isMaximized(),
    focused: window.isFocused(),
  });
}

async function createWindow(): Promise<BrowserWindow> {
  const state = loadWindowState();
  const window = new BrowserWindow({
    ...state.bounds,
    minWidth: MIN_WINDOW_WIDTH,
    minHeight: MIN_WINDOW_HEIGHT,
    // Off disk, so the very first frame is already the user's theme rather than
    // a near-black rectangle that turns white on Day. `windowState.ts` explains
    // why that cache exists at all; a profile with nothing stored gets
    // `resolveWindowBackground(DEFAULT_WINDOW_THEME)` - Night's own ground, read
    // out of the palette by `windowColors.ts` rather than restated as a literal.
    backgroundColor: state.background,
    // Shown on `ready-to-show`, so a multi-megabyte bundle parses behind a
    // window painted in the app's own ground rather than a white rectangle.
    show: false,
    // Frameless, and the app draws its own controls. `thickFrame` and
    // `roundedCorners` are deliberately NOT set - their defaults are what keep
    // edge resizing, the drop shadow, the window animations and Windows 11's
    // corner radius. See `window.ts` for what this costs and what it does not.
    frame: false,
    // The WINDOW's icon, which is a different thing from the executable's.
    // Packaged, the taskbar and Alt-Tab take the icon compiled into the exe by
    // `electron-builder.yml`; unpackaged - `npm run dev`, `npm run start:app` -
    // there is no exe of ours to take one from, so without this the app runs
    // under Electron's default. Same file either way.
    icon: path.join(__dirname, '..', 'electron', 'resources', 'icon.ico'),
    // Still true with no frame, and still load-bearing: the menu is
    // what supplies Ctrl+C/V/A/Z to every input in the app (`menu.ts`), and
    // Alt reveals it. Hiding the caption strip does not hide the menu bar.
    autoHideMenuBar: true,
    title: 'Inwire',
    webPreferences: {
      ...WEB_PREFERENCES,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  // Neither in a background launch: `maximize()` shows an unshown window, and
  // the parked bounds must not be saved over the person's real placement.
  if (state.maximized && !BACKGROUND_WINDOW) window.maximize();
  if (!BACKGROUND_WINDOW) trackWindowState(window);
  guardClose(window);

  // Both facts the renderer cannot observe. Sent on change and once the page
  // exists, because a window restored maximized has already fired `maximize`
  // by the time anything is listening.
  // Written out rather than looped: Electron types `on` as one overload per
  // event name, so a loop over a union of them does not type-check.
  const announce = (): void => sendWindowState(window);
  window.on('maximize', announce);
  window.on('unmaximize', announce);
  window.on('enter-full-screen', announce);
  window.on('leave-full-screen', announce);
  // Focus is now just another announcement: the controls dim in CSS, because
  // they are the app's own elements rather than glyphs Windows draws from an
  // opaque colour it was handed.
  window.on('focus', announce);
  window.on('blur', announce);
  window.webContents.once('did-finish-load', () => sendWindowState(window));

  if (BACKGROUND_WINDOW) {
    // A test launch: shown without activation and parked outside every
    // display, so nobody sees it or loses focus to it, and out of the taskbar.
    // It is *shown* because a hidden window gets no animation frames from
    // Chromium - measured, 2 in a second - which stalls every rAF-driven wait.
    window.setSkipTaskbar(true);
    window.once('ready-to-show', () => {
      window.setBounds({ ...window.getBounds(), x: BACKGROUND_PARK, y: BACKGROUND_PARK });
      window.showInactive();
    });
  } else {
    window.once('ready-to-show', () => window.show());
  }

  if (DEV_SERVER_URL) await window.loadURL(DEV_SERVER_URL);
  else await window.loadURL(`${APP_ORIGIN}/index.html`);

  return window;
}

/**
 * Asks before throwing a capture away.
 *
 * On the window's `close` rather than on `app.before-quit`, and that is not
 * arbitrary: `before-quit` fires for a menu Exit but *not* for the close
 * button, and by the time it runs during a quit the window may already be
 * gone, leaving the dialog nothing to attach to. Guarding `close` covers the
 * X, Alt+F4 and Exit alike - a prevented `close` also cancels an `app.quit()`
 * in progress.
 *
 * The wording is ours, which is the improvement over what this replaces. A
 * `beforeunload` could not supply its own text - the old comment said so - and
 * in Electron it would not have shown a dialog at all.
 *
 * **The renderer draws the confirm, and the OS's box is only the fallback.**
 * `showMessageBox` on Windows is a Win32 task dialog, and Windows paints it
 * light whatever `nativeTheme.themeSource` says - this used to set
 * `themeSource` around the box in the belief that it followed, and the box
 * stayed white over a window in Night. The renderer's dialog takes the app's
 * own tokens like every other surface. When the renderer does not acknowledge
 * within a second - hung, crashed, not loaded - the OS's box asks instead, in
 * the OS's own theme, because a confirm in the wrong colours beats a close
 * button that does nothing. `quitConfirm.ts` is the decision, and says why a
 * second close re-asks rather than being ignored.
 *
 * **Nothing overrides `nativeTheme.themeSource` here, and nothing should.**
 * It never reached the task dialog, and a standing override would pin
 * `prefers-color-scheme` in the renderer, which `useSystemThemePreference`
 * reads - so under System the app would be following itself and never see an
 * OS theme change. `scripts/electron/window-chrome.ts` holds main to that.
 */
function guardClose(window: BrowserWindow): void {
  // Taken now: in `closed`, `window.webContents` is already being torn down.
  const contents = window.webContents;
  const confirm = new QuitConfirm({
    send: (request) => {
      if (window.isDestroyed() || contents.isDestroyed() || contents.isCrashed()) return false;
      contents.send(QUIT_CONFIRM_CHANNEL, request);
      return true;
    },
    showNative: async () => {
      if (window.isDestroyed()) return false;
      const { response } = await dialog.showMessageBox(window, {
        type: 'warning',
        buttons: [QUIT_CONFIRM_TEXT.quit, QUIT_CONFIRM_TEXT.keep],
        defaultId: 1,
        cancelId: 1,
        noLink: true,
        title: QUIT_CONFIRM_TEXT.title,
        message: QUIT_CONFIRM_TEXT.message,
        detail: QUIT_CONFIRM_TEXT.detail,
      });
      return response === 0;
    },
    quit: () => {
      quitConfirmed = true;
      if (!window.isDestroyed()) window.close();
    },
    setTimer: (fn, ms) => setTimeout(fn, ms),
    clearTimer: (handle) => { clearTimeout(handle as ReturnType<typeof setTimeout> | undefined); },
  });

  // Only this window's page may answer this window's confirm.
  const onReply = (event: Electron.IpcMainEvent, value: unknown): void => {
    if (event.sender !== contents) return;
    const reply = readQuitConfirmReply(value);
    if (reply !== null) confirm.replied(reply);
  };
  ipcMain.on(QUIT_CONFIRM_REPLY_CHANNEL, onReply);
  window.once('closed', () => ipcMain.removeListener(QUIT_CONFIRM_REPLY_CHANNEL, onReply));
  contents.on('render-process-gone', () => confirm.rendererGone());
  // A reload takes the page's dialog with it; see `rendererReset`.
  contents.on('did-start-navigation', (details) => {
    if (details.isMainFrame && !details.isSameDocument) confirm.rendererReset();
  });

  window.on('close', (event) => {
    if (quitConfirmed || !unsavedCapture) return;
    event.preventDefault();
    confirm.requested();
  });
}

/**
 * Quitting closes the app on Windows and Linux, and on macOS too.
 *
 * The usual macOS convention - stay alive with no windows - is wrong for a
 * program that owns a running capture and a set of open file handles. A
 * dockless process still writing to a capture directory is worse than the
 * convention is good.
 */
app.on('window-all-closed', () => app.quit());
