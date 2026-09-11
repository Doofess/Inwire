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
import { UNSAVED_CAPTURE_CHANNEL } from './channels';

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
} as const;

export type InwireBridge = typeof api;

contextBridge.exposeInMainWorld('inwire', api);
