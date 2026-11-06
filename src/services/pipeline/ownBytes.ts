/**
 * A frame's bytes as a buffer of their own, for a message that clones them.
 *
 * A live frame's bytes are a view into the agent's batch (`receiveBatch`), and
 * a structured clone of a view copies its whole buffer: a row posted with its
 * bytes would send its batch - hundreds of frames - to carry one. A view that
 * is already its whole buffer is returned as it is; any other is copied to a
 * buffer sized exactly to it.
 */
export function ownBytes(view: Uint8Array): Uint8Array {
  return view.byteOffset === 0 && view.byteLength === view.buffer.byteLength ? view : view.slice();
}
