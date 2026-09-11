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
    };
  }
}
