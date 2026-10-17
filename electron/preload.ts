/**
 * The only thing the renderer can see of the main process.
 *
 * Deliberately almost empty in this phase. The surface grows with the features
 * that need it - a `MessagePort` to the capture store, native save and open
 * dialogs, agent service state - and each one arrives with the phase that uses
 * it rather than being laid out in advance for a caller that does not exist.
 *
 * ## Two constraints that shape every line here
 *
 * This file is **CommonJS**, because `sandbox: true` forbids an ES-module
 * preload and the repository root declares `"type": "module"`. That is why the
 * Electron sources compile to `dist-electron/` with their own `package.json`
 * saying `"type": "commonjs"`.
 *
 * And a `MessagePort` **cannot cross `contextBridge`** - it is not a
 * structured-cloneable value the bridge's proxy layer supports. When the
 * capture store's port arrives it will be handed over with
 * `window.postMessage(msg, '*', [port])` from here into the main world, which
 * is the documented way out of the isolated world, rather than through an
 * exposed function that would silently fail.
 */
import { contextBridge, ipcRenderer } from 'electron';
import {
  AGENT_PORT_CHANNEL, AGENT_PORT_REQUEST, SAVE_FILE_CHANNEL,
  SAVE_STREAM_CLOSE_CHANNEL, SAVE_STREAM_OPEN_CHANNEL, SAVE_STREAM_WRITE_CHANNEL, SAVE_CAPTURED_CHANNEL,
  KEYLOG_ATTACH_CHANNEL, KEYLOG_CHOOSE_CHANNEL, KEYLOG_FOLLOW_SUGGESTED_CHANNEL,
  KEYLOG_FORGET_CHANNEL, KEYLOG_STATUS_CHANNEL, KEYLOG_TEXT_CHANNEL,
  MONITORING_CONFIG_GET_CHANNEL, MONITORING_CONFIG_SAVE_CHANNEL, MONITORING_EXIT_CHANNEL,
  MONITORING_PORT_CHANNEL, MONITORING_PORT_REQUEST, MONITORING_START_CHANNEL,
  MONITORING_STATUS_CHANNEL, MONITORING_STOP_CHANNEL,
  STORE_EXIT_CHANNEL, STORE_INGEST_PORT_CHANNEL, STORE_INGEST_PORT_REQUEST,
  STORE_PORT_CHANNEL, STORE_PORT_REQUEST, WINDOW_CONTROL_CHANNEL,
  UNSAVED_CAPTURE_CHANNEL, UPDATE_APPLY_CHANNEL, UPDATE_CHECK_CHANNEL, UPDATE_STATE_CHANNEL,
  SPEEDTEST_CANCEL_CHANNEL, SPEEDTEST_EVENT_CHANNEL, SPEEDTEST_START_CHANNEL,
  UPDATE_STATE_REQUEST, WINDOW_STATE_CHANNEL, WINDOW_THEME_CHANNEL, WINDOW_TITLE_CHANNEL,
  QUIT_CONFIRM_CHANNEL, QUIT_CONFIRM_REPLY_CHANNEL,
  type WindowControl,
} from './channels';
import type { QuitConfirmAnswer } from '../src/lib/quitConfirm';

/**
 * The one line of DOM in the Electron half of this app.
 *
 * `tsconfig.electron.json` has no DOM lib on purpose - it is what makes a
 * reference to `window` in the main process a build failure rather than a
 * runtime one. The preload is the single legitimate exception, because it runs
 * beside a page, and declaring exactly the one call it needs keeps the
 * exception visible instead of reopening the whole DOM to `main.ts`.
 */
declare const window: {
  postMessage(message: unknown, targetOrigin: string, transfer?: unknown[]): void;
};

/**
 * What the renderer is told about its host.
 *
 * `platform` rather than a user-agent sniff: `services/platformDetect.ts`
 * inferred the OS from `navigator` in order to pick an agent installer to
 * download, and both the inference and the download are going away. What
 * remains is the handful of places that legitimately want to know which OS
 * this is, and the main process simply knows.
 */
/** `process.platform` is a build target; this is what a person calls it. */
const OS_NAMES: Record<string, string> = {
  win32: 'Windows',
  darwin: 'macOS',
  linux: 'Linux',
};

/**
 * One of Electron's kilobyte readings, as bytes, or null.
 *
 * Wrapped because this file has exactly one job it must never fail at: reaching
 * `exposeInMainWorld`. A `process` shim that does not carry one of these
 * methods on some future Electron would otherwise throw at module scope and
 * take the entire bridge down - which is the `node:os` failure again, in a
 * different disguise and just as silent.
 */
function readKilobytes(read: () => number): number | null {
  try {
    const kb = read();
    return typeof kb === 'number' && kb > 0 ? kb * 1024 : null;
  } catch {
    return null;
  }
}

const api = {
  isDesktop: true,
  platform: process.platform,
  /**
   * The OS, for `shb_os` in a pcapng export.
   *
   * Built from `process`, not from `node:os`. **A sandboxed preload cannot
   * require an arbitrary Node module** - it gets `electron` and a small
   * polyfill set, and importing `node:os` here does not throw a useful error:
   * the preload fails to load, `contextBridge.exposeInMainWorld` never runs,
   * and `window.inwire` is simply undefined. The app then has no store, no
   * agent and no save dialog, and nothing in the console says why.
   *
   * `process.getSystemVersion()` is in Electron's sandboxed `process` shim and
   * gives the build - 10.0.26200 - which with the platform name is what a
   * reader opening the file wants under "Operating System". It replaced
   * `navigator.userAgent`, which named a Chrome build.
   */
  osDescription: `${OS_NAMES[process.platform] ?? process.platform} ${process.getSystemVersion()}`,
  /**
   * How much RAM the machine has, and how much heap V8 will give this
   * renderer. Both in **bytes**; Electron reports kilobytes.
   *
   * This is what lets the packet buffer size itself to the machine instead of
   * being a fixed 512 MB chosen for no machine in particular
   * (`services/bufferBudget.ts`).
   *
   * **`process.getSystemMemoryInfo()`, not `node:os`.** `os.totalmem()` is the
   * obvious call and it is the documented trap: a sandboxed preload cannot
   * require an arbitrary Node module, and the failure is not an exception
   * anybody sees - the preload dies while loading, `exposeInMainWorld` never
   * runs, and `window.inwire` is simply undefined, taking the store, the agent
   * and the save dialog with it. Electron's own `process` shim answers both
   * questions synchronously and is already what `osDescription` above uses.
   *
   * **`null` when it cannot be read, and never 0.** The budget multiplies these
   * by a fraction, so a zero would compute a buffer of nothing and a capture
   * that trims every frame it takes. An absent reading means "fall back to the
   * fixed default" - the same `provesAbsent` rule the service diagnosis keeps.
   */
  systemMemoryBytes: readKilobytes(() => process.getSystemMemoryInfo().total),
  heapLimitBytes: readKilobytes(() => process.getHeapStatistics().heapSizeLimit),
  versions: {
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node,
  },
  /**
   * Whether the buffer holds frames that quitting would discard.
   *
   * A one-way notification rather than a question asked at quit time: the
   * renderer already knows, and main must be able to decide without waiting on
   * a thread that may be busy dissecting.
   */
  setUnsavedCapture(hasFrames: boolean): void {
    ipcRenderer.send(UNSAVED_CAPTURE_CHANNEL, hasFrames === true);
  },

  /**
   * Asks main for the capture store's port, and returns nothing.
   *
   * It cannot return the port. `contextBridge` serialises everything it
   * passes through a proxy layer that does not support a `MessagePort`, and a
   * function that tried would fail rather than transfer. The documented way
   * out of the isolated world is `window.postMessage` with a transfer list,
   * which is what the listener below does - so the renderer asks here and
   * receives on `window`.
   */
  requestCaptureStorePort(): void {
    void ipcRenderer.invoke(STORE_PORT_REQUEST);
  },

  /**
   * Asks for the store's SECOND port, the one frames travel on.
   *
   * Same route and same reason as the agent's: the renderer receives it on
   * `window` and transfers it straight into the pipeline Worker, so the main
   * thread carries it exactly once and never sees a frame. ADR 0038.
   */
  requestCaptureIngestPort(): void {
    void ipcRenderer.invoke(STORE_INGEST_PORT_REQUEST);
  },

  onCaptureStoreExit(listener: (reason: string) => void): void {
    ipcRenderer.on(STORE_EXIT_CHANNEL, (_event, reason: string) => listener(reason));
  },

  /**
   * Asks main to open a link to the capture agent. Returns nothing, same rule.
   *
   * The agent is a named pipe now, and neither a renderer nor a Web Worker can
   * open one - `net.connect` is Node. So the handle lives in main and what
   * comes back is a port, which travels the same way the store's does and for
   * the same reason.
   */
  requestAgentPort(): void {
    void ipcRenderer.invoke(AGENT_PORT_REQUEST);
  },

  /**
   * Shows a save dialog and writes the bytes where the person says.
   *
   * Unlike the two port requests above this one CAN return its answer: a path
   * and a success flag are ordinary cloneable values, and the caller needs
   * both - an export that cannot say where the file went is barely better than
   * the download it replaced.
   */
  saveFile(request: {
    suggestedName: string;
    extensions?: string[];
    description?: string;
    bytes: Uint8Array;
  }): Promise<unknown> {
    return ipcRenderer.invoke(SAVE_FILE_CHANNEL, request);
  },

  /**
   * The same save in pieces, for a file too large to hand over whole.
   *
   * Open shows the dialog and answers with a token; the bytes then go to a
   * `.partial` beside the chosen path and take its name only on a committed
   * close. `src/lib/saveSink.ts` is the only caller and narrows the answers.
   */
  openSaveStream(request: {
    suggestedName: string;
    extensions?: string[];
    description?: string;
  }): Promise<unknown> {
    return ipcRenderer.invoke(SAVE_STREAM_OPEN_CHANNEL, request);
  },
  writeSaveStream(token: string, bytes: Uint8Array): Promise<unknown> {
    return ipcRenderer.invoke(SAVE_STREAM_WRITE_CHANNEL, token, bytes);
  },
  closeSaveStream(token: string, commit: boolean): Promise<unknown> {
    return ipcRenderer.invoke(SAVE_STREAM_CLOSE_CHANNEL, token, commit === true);
  },

  /**
   * Copies a capture's own pcapng files - the agent's, as captured - where
   * the person picks. A capture id, never a path (ADR 0052).
   */
  saveCaptured(captureId: string): Promise<unknown> {
    return ipcRenderer.invoke(SAVE_CAPTURED_CHANNEL, String(captureId));
  },

  /** The Update Center's state right now, for a panel that has just mounted. */
  getUpdateState(): Promise<unknown> {
    return ipcRenderer.invoke(UPDATE_STATE_REQUEST);
  },

  /**
   * Asks the feed. Resolves when the check is over, however it ended.
   *
   * It does not reject and does not report failure: an unreachable feed is the
   * ordinary case on an offline machine, and the answer arrives through
   * `onUpdateState` like every other change.
   */
  checkForUpdates(): Promise<unknown> {
    return ipcRenderer.invoke(UPDATE_CHECK_CHANNEL);
  },

  /** Downloads, verifies and installs one component. Raises a UAC prompt. */
  applyUpdate(id: string): Promise<unknown> {
    return ipcRenderer.invoke(UPDATE_APPLY_CHANNEL, id);
  },

  /**
   * The internet speed test (ADR 0054). Takes nothing: what is dialled is
   * main's to decide. Progress arrives through `onSpeedTestEvent`.
   */
  startSpeedTest(): Promise<unknown> {
    return ipcRenderer.invoke(SPEEDTEST_START_CHANNEL);
  },
  cancelSpeedTest(): Promise<unknown> {
    return ipcRenderer.invoke(SPEEDTEST_CANCEL_CHANNEL);
  },
  /** Subscribes to the running test's events, and returns the unsubscribe. */
  onSpeedTestEvent(listener: (event: unknown) => void): () => void {
    const handler = (_event: unknown, event: unknown): void => listener(event);
    ipcRenderer.on(SPEEDTEST_EVENT_CHANNEL, handler);
    return () => { ipcRenderer.removeListener(SPEEDTEST_EVENT_CHANNEL, handler); };
  },

  /**
   * NetFlow monitoring (ADRs 0058, 0059). The port arrives on
   * `inwire:monitoring-port` and goes straight into the monitoring Worker;
   * asking for it opens the history without listening. Start is the only
   * thing that binds the socket, and every value back is `unknown` until
   * `src/services/monitoring/control.ts` has read it.
   */
  requestMonitoringPort(): Promise<unknown> {
    return ipcRenderer.invoke(MONITORING_PORT_REQUEST);
  },
  getMonitoringConfig(): Promise<unknown> {
    return ipcRenderer.invoke(MONITORING_CONFIG_GET_CHANNEL);
  },
  saveMonitoringConfig(config: unknown): Promise<unknown> {
    return ipcRenderer.invoke(MONITORING_CONFIG_SAVE_CHANNEL, config);
  },
  startMonitoring(config: unknown): Promise<unknown> {
    return ipcRenderer.invoke(MONITORING_START_CHANNEL, config);
  },
  stopMonitoring(): Promise<unknown> {
    return ipcRenderer.invoke(MONITORING_STOP_CHANNEL);
  },
  /** The utility exited; returns the unsubscribe. */
  onMonitoringRuntimeExit(listener: (exit: unknown) => void): () => void {
    const handler = (_event: unknown, exit: unknown): void => listener(exit);
    ipcRenderer.on(MONITORING_EXIT_CHANNEL, handler);
    return () => { ipcRenderer.removeListener(MONITORING_EXIT_CHANNEL, handler); };
  },
  /** Intake's status whenever it changes; returns the unsubscribe. */
  onMonitoringStatus(listener: (status: unknown) => void): () => void {
    const handler = (_event: unknown, status: unknown): void => listener(status);
    ipcRenderer.on(MONITORING_STATUS_CHANNEL, handler);
    return () => { ipcRenderer.removeListener(MONITORING_STATUS_CHANNEL, handler); };
  },

  /**
   * The followed TLS key log (`electron/keyLogFollower.ts`).
   *
   * **No method here takes a path**, and that is deliberate rather than an
   * omission: the page can pick from what main already knows and nothing
   * else. Text arrives through `onKeyLogText`, from the top on every attach.
   */
  attachKeyLog(): Promise<unknown> {
    return ipcRenderer.invoke(KEYLOG_ATTACH_CHANNEL);
  },
  chooseKeyLog(): Promise<unknown> {
    return ipcRenderer.invoke(KEYLOG_CHOOSE_CHANNEL);
  },
  followSuggestedKeyLog(): Promise<unknown> {
    return ipcRenderer.invoke(KEYLOG_FOLLOW_SUGGESTED_CHANNEL);
  },
  forgetKeyLog(): Promise<unknown> {
    return ipcRenderer.invoke(KEYLOG_FORGET_CHANNEL);
  },
  /** Returns the unsubscribe, for `onUpdateState`'s reason. */
  onKeyLogText(listener: (text: string) => void): () => void {
    const handler = (_event: unknown, text: unknown): void => {
      if (typeof text === 'string') listener(text);
    };
    ipcRenderer.on(KEYLOG_TEXT_CHANNEL, handler);
    return () => { ipcRenderer.removeListener(KEYLOG_TEXT_CHANNEL, handler); };
  },
  onKeyLogStatus(listener: (status: unknown) => void): () => void {
    const handler = (_event: unknown, status: unknown): void => listener(status);
    ipcRenderer.on(KEYLOG_STATUS_CHANNEL, handler);
    return () => { ipcRenderer.removeListener(KEYLOG_STATUS_CHANNEL, handler); };
  },

  /**
   * Subscribes to state changes, and **returns the unsubscribe**.
   *
   * `onCaptureStoreExit` above returns nothing, which is fine for a listener
   * registered once for the life of the window. This one is registered by a
   * Settings panel that mounts and unmounts every time somebody opens the
   * modal, so without a disposer the listeners accumulate and every state
   * change runs a render for each visit made this session.
   */
  onUpdateState(listener: (state: unknown) => void): () => void {
    const handler = (_event: unknown, state: unknown): void => listener(state);
    ipcRenderer.on(UPDATE_STATE_CHANNEL, handler);
    return () => { ipcRenderer.removeListener(UPDATE_STATE_CHANNEL, handler); };
  },

  /**
   * Reports the resolved theme, so main can cache the ground the NEXT window
   * opens on.
   *
   * A theme name and not a colour: `windowColors.ts` owns the hex, and says why
   * a value computed in the renderer is always a frame behind the cascade that
   * produced it. `resolvedTheme`, never `theme` - the picker carries System
   * beside the two real themes, and System is a rule rather than a palette.
   */
  setWindowTheme(theme: string): void {
    ipcRenderer.send(WINDOW_THEME_CHANNEL, theme);
  },

  /**
   * The three window buttons, which the app draws itself.
   *
   * Typed to the union rather than `string`: the bridge is the boundary where a
   * typo stops being a compile error, and `'maximize'` instead of
   * `'toggle-maximize'` would be a button that silently did nothing.
   */
  windowControl(action: WindowControl): void {
    ipcRenderer.send(WINDOW_CONTROL_CHANNEL, action);
  },

  /** Sets the window title. The renderer decides what it says. */
  setWindowTitle(title: string): void {
    ipcRenderer.send(WINDOW_TITLE_CHANNEL, title);
  },

  /**
   * Subscribes to maximized/focused, and **returns the unsubscribe**.
   *
   * Same disposer form as `onUpdateState` even though the title row mounts once
   * for the life of the window: a listener that cannot be removed is a rule this
   * file keeps uniformly, because the exception is what gets copied.
   */
  onWindowState(listener: (state: unknown) => void): () => void {
    const handler = (_event: unknown, state: unknown): void => listener(state);
    ipcRenderer.on(WINDOW_STATE_CHANNEL, handler);
    return () => { ipcRenderer.removeListener(WINDOW_STATE_CHANNEL, handler); };
  },

  /**
   * Subscribes to main's "Quit Inwire?" requests, and returns the unsubscribe.
   *
   * The payload is `unknown` and narrowed on the page's side by
   * `readQuitConfirmRequest`, like every other value from main.
   */
  onQuitConfirm(listener: (request: unknown) => void): () => void {
    const handler = (_event: unknown, request: unknown): void => listener(request);
    ipcRenderer.on(QUIT_CONFIRM_CHANNEL, handler);
    return () => { ipcRenderer.removeListener(QUIT_CONFIRM_CHANNEL, handler); };
  },

  /**
   * Answers one confirm. `shown` first, as soon as it is on screen - main falls
   * back to the OS's box if that does not arrive within a second
   * (`electron/quitConfirm.ts`) - and then `quit` or `keep`.
   */
  answerQuitConfirm(id: number, answer: QuitConfirmAnswer): void {
    ipcRenderer.send(QUIT_CONFIRM_REPLY_CHANNEL, { id, answer });
  },
} as const;

// Main sends the port here; this forwards it into the page. `'*'` as the
// target origin because the page's own origin is what it is - the message
// never leaves this window, and the listener checks `event.source === window`.
ipcRenderer.on(STORE_PORT_CHANNEL, (event) => {
  window.postMessage({ channel: STORE_PORT_CHANNEL }, '*', event.ports);
});

ipcRenderer.on(STORE_INGEST_PORT_CHANNEL, (event) => {
  window.postMessage({ channel: STORE_INGEST_PORT_CHANNEL }, '*', event.ports);
});

// The agent's port takes the identical route. It does not stop in the page,
// though: `pipelineClient` transfers it straight into the pipeline Worker, so
// the renderer's main thread carries it once and never sees a frame.
ipcRenderer.on(AGENT_PORT_CHANNEL, (event) => {
  window.postMessage({ channel: AGENT_PORT_CHANNEL }, '*', event.ports);
});

// The monitoring runtime's port, the same route again: the page hands it to the
// monitoring Worker and reads nothing from it.
ipcRenderer.on(MONITORING_PORT_CHANNEL, (event) => {
  window.postMessage({ channel: MONITORING_PORT_CHANNEL }, '*', event.ports);
});

contextBridge.exposeInMainWorld('inwire', api);
