/**
 * The quit confirm's vocabulary, shared by main, the preload and the renderer.
 *
 * In `src/lib/` because all three can import it and it imports nothing: main's
 * decision (`electron/quitConfirm.ts`) and its native fallback, and the
 * renderer's `QuitConfirmDialog`, say the same words from this one copy. Two
 * copies of the wording would drift, and the reader would meet a different
 * question depending on whether the renderer happened to be answering.
 */

/** What the confirm says, in the app's own dialog and in the OS's fallback. */
export const QUIT_CONFIRM_TEXT = {
  title: 'Quit Inwire?',
  message: 'Quit while a capture is in the buffer?',
  detail:
    'Frames already written to the capture store are kept and will be '
    + 'restored next time. Anything still in memory is discarded.',
  quit: 'Quit',
  keep: 'Keep capturing',
} as const;

/**
 * Main -> renderer: show the confirm numbered `id`, or take it down.
 *
 * `open: false` is a withdrawal. Main sends it when it gives up waiting and
 * shows the OS's box instead, so that a renderer which was only slow does not
 * later put up a second confirm whose answer nobody is listening for.
 */
export interface QuitConfirmRequest {
  id: number;
  open: boolean;
}

/**
 * Renderer -> main: what became of confirm `id`.
 *
 * `shown` is the renderer saying it is alive and the question is on screen;
 * it is what stops main's fallback timer, so the reader is given as long as
 * they like to decide. `quit` and `keep` are the decision.
 */
export type QuitConfirmAnswer = 'shown' | 'quit' | 'keep';

export interface QuitConfirmReply {
  id: number;
  answer: QuitConfirmAnswer;
}

/**
 * A request off the wire, or null.
 *
 * Field by field, the house rule for anything crossing a process boundary:
 * the sender is in another TypeScript program and this side says what it
 * accepts.
 */
export function readQuitConfirmRequest(value: unknown): QuitConfirmRequest | null {
  if (typeof value !== 'object' || value === null) return null;
  const { id, open } = value as Record<string, unknown>;
  if (!Number.isSafeInteger(id) || typeof open !== 'boolean') return null;
  return { id: id as number, open };
}

/** A reply off the wire, or null. Main reads replies with this. */
export function readQuitConfirmReply(value: unknown): QuitConfirmReply | null {
  if (typeof value !== 'object' || value === null) return null;
  const { id, answer } = value as Record<string, unknown>;
  if (!Number.isSafeInteger(id)) return null;
  if (answer !== 'shown' && answer !== 'quit' && answer !== 'keep') return null;
  return { id: id as number, answer };
}
