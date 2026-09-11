/**
 * What the preload exposes on `window`.
 *
 * Declared here rather than imported from `electron/preload.ts` deliberately:
 * the renderer's TypeScript program (`tsconfig.json`) and the main process's
 * (`tsconfig.electron.json`) are separate on purpose - the second has no DOM
 * lib, so that a reference to `window` in the main process is a build failure.
 * Importing a type across that line would drag one program's globals into the
 * other and undo the split.
 *
 * Every member is optional. The renderer must keep working when the bridge is
 * absent, because it is absent in every one of the 119 assertion scripts, which
 * import `src/` modules directly under plain Node.
 */
export {};

declare global {
  interface Window {
    inwire?: {
      readonly isDesktop: true;
      readonly platform: string;
      readonly versions: {
        readonly electron: string;
        readonly chrome: string;
        readonly node: string;
      };
      /**
       * Tells the main process whether quitting would lose anything.
       *
       * The confirmation lives there because `beforeunload` in Electron
       * refuses to close the window and shows no dialog at all - see the call
       * site in `App.tsx`.
       */
      setUnsavedCapture?(hasFrames: boolean): void;
      /**
       * Asks for the capture store's port. Returns nothing on purpose.
       *
       * A `MessagePort` cannot cross `contextBridge` - the bridge's proxy
       * layer does not support one, and a function that tried to return one
       * would fail rather than transfer. The preload hands it into the page
       * with `window.postMessage(msg, '*', [port])` instead, so the caller
       * asks here and listens on `window` for `CAPTURE_PORT_MESSAGE`.
       */
      requestCaptureStorePort?(): void;
      /**
       * Called if the store process dies.
       *
       * A `MessagePort` has no error event and no reliable close event, so a
       * dead store is a channel that simply goes quiet - and every pending
       * read would hang for the life of the window. Main watches the process
       * and reports over its own channel.
       */
      onCaptureStoreExit?(listener: (reason: string) => void): void;
      /**
       * Asks for a port to the capture agent. Returns nothing, same reason.
       *
       * The agent is reached over a named pipe, which neither a renderer nor a
       * Web Worker can open - `net.connect` is Node. Main holds the handle and
       * hands over a port, which `pipelineClient` transfers straight into the
       * pipeline Worker so that the main thread carries it once and then plays
       * no part in the frame path (docs/decisions/0007).
       */
      requestAgentPort?(): void;
    };
  }
}
