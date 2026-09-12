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
import { app, BrowserWindow, dialog, ipcMain, Menu, net, protocol, session, shell } from 'electron';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { APP_HOST, APP_ORIGIN, APP_SCHEME, decideServe } from './appPaths';
import {
  AGENT_PORT_REQUEST, SAVE_FILE_CHANNEL, STORE_PORT_REQUEST, UNSAVED_CAPTURE_CHANNEL,
} from './channels';
import { saveGeneratedFile, type SaveFileRequest } from './saveFile';
import { AgentPipeLink } from './agentPipe';
import { captureDirectory, CaptureStoreHost } from './store/host';
import { developmentCsp, productionCsp } from './csp';
import { buildMenu } from './menu';
import { loadWindowState, trackWindowState } from './windowState';
import {
  COMMAND_LINE_SWITCHES,
  MIN_WINDOW_HEIGHT,
  MIN_WINDOW_WIDTH,
  SCHEME_PRIVILEGES,
  WEB_PREFERENCES,
  WINDOW_BACKGROUND,
} from './window';

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
app.setPath('userData', path.join(app.getPath('appData'), '..', 'Local', 'Inwire'));

for (const flag of COMMAND_LINE_SWITCHES) app.commandLine.appendSwitch(flag);

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
 */
const agent = new AgentPipeLink();

async function start(): Promise<void> {
  ipcMain.on(UNSAVED_CAPTURE_CHANNEL, (_event, hasFrames: unknown) => {
    unsavedCapture = hasFrames === true;
  });
  ipcMain.handle(STORE_PORT_REQUEST, async (event) => {
    store.watch(event.sender);
    await store.connect(event.sender);
  });
  ipcMain.handle(AGENT_PORT_REQUEST, (event) => {
    agent.attach(event.sender);
  });
  ipcMain.handle(SAVE_FILE_CHANNEL, (event, request: SaveFileRequest) =>
    saveGeneratedFile(event, request));
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
  await createWindow();

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
  // Referenced so the import is not dropped; `net` is the documented escape
  // hatch if a future asset has to be streamed rather than buffered.
  void net;
  void pathToFileURL;
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
  target.webRequest.onHeadersReceived((details, callback) => {
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

async function createWindow(): Promise<BrowserWindow> {
  const state = loadWindowState();
  const window = new BrowserWindow({
    ...state.bounds,
    minWidth: MIN_WINDOW_WIDTH,
    minHeight: MIN_WINDOW_HEIGHT,
    backgroundColor: WINDOW_BACKGROUND,
    // Shown on `ready-to-show`, so a multi-megabyte bundle parses behind a
    // window painted in the app's own ground rather than a white rectangle.
    show: false,
    autoHideMenuBar: true,
    title: 'Inwire',
    webPreferences: {
      ...WEB_PREFERENCES,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  if (state.maximized) window.maximize();
  trackWindowState(window);
  guardClose(window);

  window.once('ready-to-show', () => window.show());

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
 */
function guardClose(window: BrowserWindow): void {
  window.on('close', (event) => {
    if (quitConfirmed || !unsavedCapture) return;
    event.preventDefault();
    void (async () => {
      const { response } = await dialog.showMessageBox(window, {
        type: 'warning',
        buttons: ['Quit', 'Keep capturing'],
        defaultId: 1,
        cancelId: 1,
        noLink: true,
        title: 'Quit Inwire?',
        message: 'Quit while a capture is in the buffer?',
        detail:
          'Frames already written to the capture store are kept and will be '
          + 'restored next time. Anything still in memory is discarded.',
      });
      if (response !== 0) return;
      quitConfirmed = true;
      window.close();
    })();
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
