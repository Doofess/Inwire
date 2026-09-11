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
