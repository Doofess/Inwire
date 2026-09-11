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
  STORE_EXIT_CHANNEL, STORE_PORT_CHANNEL, STORE_PORT_REQUEST, UNSAVED_CAPTURE_CHANNEL,
} from './channels';

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
const api = {
  isDesktop: true,
  platform: process.platform,
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
} as const;

// Main sends the port here; this forwards it into the page. `'*'` as the
// target origin because the page's own origin is what it is - the message
// never leaves this window, and the listener checks `event.source === window`.
ipcRenderer.on(STORE_PORT_CHANNEL, (event) => {
  window.postMessage({ channel: STORE_PORT_CHANNEL }, '*', event.ports);
});

// The agent's port takes the identical route. It does not stop in the page,
// though: `pipelineClient` transfers it straight into the pipeline Worker, so
// the renderer's main thread carries it once and never sees a frame.
ipcRenderer.on(AGENT_PORT_CHANNEL, (event) => {
  window.postMessage({ channel: AGENT_PORT_CHANNEL }, '*', event.ports);
});

export type InwireBridge = typeof api;

contextBridge.exposeInMainWorld('inwire', api);
