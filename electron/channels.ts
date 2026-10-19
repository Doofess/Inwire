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

/**
 * Main -> renderer: a SECOND `MessagePort` to the capture store, for frames.
 *
 * The renderer only ferries it, exactly as it ferries the agent's port. Its
 * real destination is the pipeline Worker, which is the only place that holds
 * a captured frame's bytes and an id for it at the same moment - so the
 * renderer's main thread still never sees a frame, and ADR 0007 is intact.
 *
 * Why a second port rather than reusing the first: the first is the app's, and
 * it carries requests that expect replies. This one is one-way and carries
 * frames at capture rate. Sharing would put a 256 kB batch in front of the
 * read the hex viewer is waiting on. ADR 0038.
 */
export const STORE_INGEST_PORT_CHANNEL = 'inwire:capture-ingest-port';

/** Renderer -> main: please send me the ingest port too. */
export const STORE_INGEST_PORT_REQUEST = 'inwire:capture-ingest-port-request';

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
 * Renderer -> main: the same save, in pieces - open shows the dialog and
 * answers with a token, write appends, close commits or aborts.
 *
 * For a file larger than the renderer should hold at once. The bytes go to
 * `<path>.partial` and only take the chosen name on commit; see
 * `electron/saveSession.ts`.
 */
export const SAVE_STREAM_OPEN_CHANNEL = 'inwire:save-stream-open';

/**
 * Renderer -> main: "save as captured" - copy a capture's own pcapng files,
 * the ones the agent wrote as it captured (ADR 0052), where the person picks.
 * The renderer sends a capture id and nothing else; see
 * `electron/capturedFiles.ts`.
 */
export const SAVE_CAPTURED_CHANNEL = 'inwire:save-captured';
export const SAVE_STREAM_WRITE_CHANNEL = 'inwire:save-stream-write';
export const SAVE_STREAM_CLOSE_CHANNEL = 'inwire:save-stream-close';

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
 * Renderer -> main: run an internet speed test (ADR 0054). Carries nothing -
 * the renderer never names a host, a size or a URL; the engine is pinned to
 * `MAIN_OUTBOUND_HOSTS.speedTest`. Answers once the test has started.
 */
export const SPEEDTEST_START_CHANNEL = 'inwire:speedtest-start';

/** Renderer -> main: cancel the test running, if any. */
export const SPEEDTEST_CANCEL_CHANNEL = 'inwire:speedtest-cancel';

/**
 * Main -> renderer: the engine's events (`src/services/speedTest/protocol.ts`),
 * relayed unread from its utilityProcess, ending with `done`, `failed` or
 * `cancelled`.
 */
export const SPEEDTEST_EVENT_CHANNEL = 'inwire:speedtest-event';

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

/**
 * Renderer -> main: I am ready for key log text; send it from the top.
 *
 * `electron/keyLogFollower.ts`. Answers with the follower's status. None of
 * the five key log channels carries a path from the renderer - see that
 * file's header for why that is the security half of the feature.
 */
export const KEYLOG_ATTACH_CHANNEL = 'inwire:keylog-attach';

/** Renderer -> main: show the open dialog and follow what is picked. */
export const KEYLOG_CHOOSE_CHANNEL = 'inwire:keylog-choose';

/** Renderer -> main: follow the file main's own `SSLKEYLOGFILE` names. */
export const KEYLOG_FOLLOW_SUGGESTED_CHANNEL = 'inwire:keylog-follow-suggested';

/** Renderer -> main: stop following and forget the path. */
export const KEYLOG_FORGET_CHANNEL = 'inwire:keylog-forget';

/** Main -> renderer: complete key log lines, as text, as they are appended. */
export const KEYLOG_TEXT_CHANNEL = 'inwire:keylog-text';

/** Main -> renderer: the follower's status whenever it changes. */
export const KEYLOG_STATUS_CHANNEL = 'inwire:keylog-status';

/**
 * Main -> renderer: show the quit confirm, or withdraw it
 * (`QuitConfirmRequest` in `src/lib/quitConfirm.ts`).
 *
 * The renderer draws it rather than the OS, because the OS's box on Windows is
 * a task dialog Windows paints light whatever theme the app is in. Main still
 * owns the decision and the fallback - see `electron/quitConfirm.ts`.
 */
export const QUIT_CONFIRM_CHANNEL = 'inwire:quit-confirm';

/** Renderer -> main: `shown`, `quit` or `keep`, for one confirm by id. */
export const QUIT_CONFIRM_REPLY_CHANNEL = 'inwire:quit-confirm-reply';

/**
 * Renderer -> main: open the monitoring dataset and hand this page a runtime
 * port (ADR 0059). Answered on `MONITORING_PORT_CHANNEL`. Opening never binds
 * the socket; only Start does.
 */
export const MONITORING_PORT_REQUEST = 'inwire:monitoring-port-request';

/** Main -> renderer: the monitoring Worker's end of the runtime port, as `ports[0]`. */
export const MONITORING_PORT_CHANNEL = 'inwire:monitoring-port';

/** Renderer -> main (invoke): start the listener with a `SourceConfig`; answers a `StartResult`. */
export const MONITORING_START_CHANNEL = 'inwire:monitoring-start';

/** Renderer -> main (invoke): stop the listener; answers a `StopResult`. */
export const MONITORING_STOP_CHANNEL = 'inwire:monitoring-stop';

/** Renderer -> main (invoke): the saved source, or why it could not be read. */
export const MONITORING_CONFIG_GET_CHANNEL = 'inwire:monitoring-config-get';

/** Renderer -> main (invoke): save a source; refused, never silently, when it does not validate. */
export const MONITORING_CONFIG_SAVE_CHANNEL = 'inwire:monitoring-config-save';

/** Main -> renderer: the utility's `IntakeStatus` whenever it changes. */
export const MONITORING_STATUS_CHANNEL = 'inwire:monitoring-status';

/** Main -> renderer: the monitoring utility exited; every pending request has already failed (`RuntimeExit`). */
export const MONITORING_EXIT_CHANNEL = 'inwire:monitoring-runtime-exit';

/**
 * Renderer -> main (invoke): choose where the monitoring dataset lives (ADR 0061). The argument is
 * `'pick'` (main shows the folder dialog) or `'default'`; the renderer never sends a path. Answers a
 * `LocationReply`.
 */
export const MONITORING_LOCATION_CHOOSE_CHANNEL = 'inwire:monitoring-location-choose';

/** Renderer -> main (invoke): discard the whole dataset or its sealed prefix, while stopped; answers a `DiscardResult`. */
export const MONITORING_DISCARD_CHANNEL = 'inwire:monitoring-discard';

/** Renderer -> main (invoke): save a retention policy, while stopped; answers a `RetentionSaveReply`. */
export const MONITORING_RETENTION_SAVE_CHANNEL = 'inwire:monitoring-retention-save';
