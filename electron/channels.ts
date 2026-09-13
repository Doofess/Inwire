/**
 * The names on the wire between the renderer and the main process.
 *
 * In their own module so both ends import the same string. A channel name
 * typed twice is a message that is sent and never received, with nothing to
 * catch it - the same reasoning that put the capture store's message union in
 * `services/capture/captureProtocol.ts`.
 */

/** Renderer -> main: does the buffer hold frames that quitting would lose? */
export const UNSAVED_CAPTURE_CHANNEL = 'inwire:unsaved-capture';

/** Main -> renderer: carries the `MessagePort` to the capture store. */
export const STORE_PORT_CHANNEL = 'inwire:capture-port';

/** Renderer -> main: please send me that port. */
export const STORE_PORT_REQUEST = 'inwire:capture-port-request';

/** Main -> renderer: the store process is gone, and why. */
export const STORE_EXIT_CHANNEL = 'inwire:capture-store-exit';

/**
 * Main -> renderer: carries the `MessagePort` to the capture agent.
 *
 * The renderer only ferries it. The port's real destination is the pipeline
 * Worker, so that the renderer's main thread never sees a captured frame -
 * which is the property ADR 0007 bought and the move of the socket into main
 * must not hand back.
 */
export const AGENT_PORT_CHANNEL = 'inwire:agent-port';

/** Renderer -> main: please open a link to the agent and send me its port. */
export const AGENT_PORT_REQUEST = 'inwire:agent-port-request';

/**
 * Renderer -> main: show a save dialog and write these bytes.
 *
 * One round trip rather than "give me a path" followed by a write, because
 * the renderer cannot write and a path it was handed but could not use would
 * be a filesystem location leaked into a page for no purpose.
 */
export const SAVE_FILE_CHANNEL = 'inwire:save-file';

/**
 * Main -> renderer: the Update Center's whole state, whenever it changes.
 *
 * A snapshot rather than a delta, for the same reason the agent's
 * `adapter_config` is one: there are five rows, the whole thing is smaller
 * than a delta's bookkeeping, and a renderer that missed one message would
 * otherwise be wrong until the next install.
 */
export const UPDATE_STATE_CHANNEL = 'inwire:update-state';

/** Renderer -> main: what is the state now? Answers directly, unlike the ports. */
export const UPDATE_STATE_REQUEST = 'inwire:update-state-request';

/** Renderer -> main: ask the feed. Quiet on failure; see `updateCenter/host.ts`. */
export const UPDATE_CHECK_CHANNEL = 'inwire:update-check';

/**
 * Renderer -> main: download, verify and install one component.
 *
 * The only message in the application that ends in a UAC prompt, so the id it
 * carries is checked against `isComponentId` before anything acts on it.
 */
export const UPDATE_APPLY_CHANNEL = 'inwire:update-apply';

/**
 * Renderer -> main: the theme the title row is currently painted in.
 *
 * Carries the **resolved theme name**, not a colour. Main owns the hex, in
 * `windowColors.ts`, for the reason that module explains: a table resolves
 * before the first paint, and a colour computed in the renderer is always at
 * least one frame behind the cascade that produced it.
 *
 * Nothing on screen changes when this arrives - the window's controls are CSS
 * now, and follow the cascade like everything else. It is written to
 * `window-state.json` so the *next* launch opens on the right ground instead of
 * flashing the default and correcting itself.
 *
 * Sent on every theme change, and once at startup - the startup send is not
 * redundant, because the value main opened the window with came off disk and
 * the renderer is the only thing that knows whether it was still right.
 */
export const WINDOW_THEME_CHANNEL = 'inwire:window-theme';

/**
 * Main -> renderer: whether the window is maximized and whether it has focus.
 *
 * Both are facts only the main process is told. The renderer needs them because
 * a window wearing its own title bar has to draw what the OS used to: a
 * restored window gets the frame's rounded corners and so must not paint into
 * them, and an unfocused window's chrome dims. Neither has a CSS media query.
 */
export const WINDOW_STATE_CHANNEL = 'inwire:window-state';

/** Renderer -> main: what the window's title should say, from capture state. */
export const WINDOW_TITLE_CHANNEL = 'inwire:window-title';

/**
 * Renderer -> main: minimize, toggle maximize, or close.
 *
 * The window is frameless, so these three are the app's own buttons rather than
 * Windows'. One channel with a verb rather than three channels, because they
 * are one control group and a renderer that could reach two of them can reach
 * the third.
 *
 * **`close` means `window.close()`, never `destroy()`.** The quit guard hangs
 * off the `close` event, so a button that destroyed the window would skip the
 * "you have unsaved frames" confirm entirely - which is the one thing standing
 * between a click and a discarded capture.
 */
export const WINDOW_CONTROL_CHANNEL = 'inwire:window-control';

/** The verbs `WINDOW_CONTROL_CHANNEL` accepts. Anything else is ignored. */
export const WINDOW_CONTROLS = ['minimize', 'toggle-maximize', 'close'] as const;
export type WindowControl = (typeof WINDOW_CONTROLS)[number];
