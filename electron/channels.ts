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
