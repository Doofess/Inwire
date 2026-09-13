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
      /** The OS as a person would name it, e.g. "Windows 11 Pro (10.0.26200)". */
      readonly osDescription?: string;
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
      /**
       * Shows a save dialog and writes the bytes where the person chooses.
       *
       * Returns the outcome, unlike the port requests: a path is an ordinary
       * cloneable value and the caller needs it, because an export that cannot
       * say where the file went is barely better than the download it
       * replaced. `src/lib/saveFile.ts` narrows the result.
       */
      saveFile?(request: {
        suggestedName: string;
        extensions?: string[];
        description?: string;
        bytes: Uint8Array;
      }): Promise<unknown>;
      /**
       * The Update Center's state, for a panel that has just mounted.
       *
       * `unknown` like `saveFile`, and narrowed by
       * `src/services/updateCenter.ts` - the same division the agent's
       * messages already use, where the sender's types are in another program
       * and the receiver is the one that says what it will accept.
       */
      getUpdateState?(): Promise<unknown>;
      /**
       * Asks the update feed.
       *
       * Never rejects and reports no failure. An unreachable feed is the
       * ordinary case on an offline machine, and whatever it learned arrives
       * through `onUpdateState` like every other change.
       */
      checkForUpdates?(): Promise<unknown>;
      /**
       * Downloads, verifies and installs one component. Raises a UAC prompt.
       *
       * Main checks the id against its own list before acting on it, because
       * this is the one message from the renderer that ends in an elevated
       * process.
       */
      applyUpdate?(id: string): Promise<unknown>;
      /**
       * Subscribes to state changes, and returns the unsubscribe.
       *
       * Unlike `onCaptureStoreExit`, which returns nothing because it is
       * registered once for the life of the window. This one is registered by
       * a Settings panel that mounts and unmounts on every visit.
       */
      onUpdateState?(listener: (state: unknown) => void): () => void;
      /**
       * Reports the resolved theme, so main can colour the native buttons.
       *
       * Windows draws the minimise/maximise/close glyphs itself, inside the
       * area `titleBarOverlay` reserves, and it is told the two colours to use.
       * A theme *name* crosses rather than a colour: `electron/titleBarColors.ts`
       * owns the hex and explains why resolving it in the renderer is always one
       * frame behind the cascade.
       *
       * Pass `resolvedTheme`, never `theme` - the picker's fifth entry, System,
       * is a rule for choosing between two themes and has no palette of its own.
       */
      setTitleBarTheme?(theme: string): void;
      /**
       * Sets the window title.
       *
       * The renderer decides the wording, because it is the only side that
       * knows the adapter's name and whether frames are arriving. Main refuses
       * an empty string rather than titling the window after a bug.
       */
      setWindowTitle?(title: string): void;
      /**
       * Subscribes to maximized/focused, and returns the unsubscribe.
       *
       * Both are facts only the main process is told, and a window wearing its
       * own title bar has to draw what the OS used to: a restored window must
       * not paint into the frame's rounded corners, and an unfocused window's
       * chrome dims. Neither has a CSS media query.
       *
       * The payload is `unknown` like every other message from main, and
       * narrowed on this side.
       */
      onWindowState?(listener: (state: unknown) => void): () => void;
    };
  }
}
