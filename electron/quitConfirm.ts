/**
 * Who asks "Quit Inwire?", and what happens when they do not answer.
 *
 * The confirm is the renderer's own dialog, because only the renderer can draw
 * it in the app's theme: Electron's `showMessageBox` on Windows is a Win32 task
 * dialog, which Windows draws light whatever `nativeTheme` says, so the app in
 * Night threw a white box over a dark window on the way out.
 *
 * But a renderer is the one thing that may not be there to ask - hung on a
 * burst, crashed, or not loaded yet - and the confirm is the only thing between
 * a click and a discarded capture. So the renderer has `RENDERER_ACK_MS` to say
 * it has the question on screen, and if it does not, the OS's box asks instead.
 * The two failure modes this exists to make impossible are a close that does
 * nothing (a hung renderer swallowing the request, the window unclosable) and a
 * close that quits without asking.
 *
 * Beside `main.ts` rather than in it, and importing no Electron, so that
 * `scripts/electron/quit-confirm.ts` can drive every one of those cases under
 * plain `tsx` with a fake clock - the same split as `pipeTransport.ts` beside
 * `agentPipe.ts`.
 */
import type { QuitConfirmReply, QuitConfirmRequest } from '../src/lib/quitConfirm';

/**
 * How long the renderer has to say the confirm is up.
 *
 * Only the acknowledgement is timed, never the decision: once the renderer has
 * said `shown`, the reader can take as long as they like. A second is far past
 * what a live renderer needs to put a dialog up, and short enough that a hung
 * one does not read as a close button that is broken.
 */
export const RENDERER_ACK_MS = 1000;

export interface QuitConfirmHost {
  /**
   * Posts a request to the window's renderer. Returns false when there is no
   * renderer to post to - destroyed or crashed - so the fallback can be shown
   * at once rather than a second later.
   */
  send(request: QuitConfirmRequest): boolean;
  /** The OS's own box. Resolves true for Quit; rejects or false for anything else. */
  showNative(): Promise<boolean>;
  /** The reader said Quit. */
  quit(): void;
  setTimer(fn: () => void, ms: number): unknown;
  clearTimer(handle: unknown): void;
}

type State =
  | { kind: 'idle' }
  /** The renderer was asked; `timer` is armed until it says `shown`. */
  | { kind: 'renderer'; id: number; timer: unknown }
  | { kind: 'native' };

export class QuitConfirm {
  private state: State = { kind: 'idle' };
  private nextId = 1;

  constructor(private readonly host: QuitConfirmHost) {}

  /** Whether a confirm, of either kind, is up or being put up. */
  get pending(): boolean {
    return this.state.kind !== 'idle';
  }

  /**
   * The window was asked to close with a capture in the buffer.
   *
   * **A second request never stacks a second confirm.** While the OS's box is
   * up it is ignored - the box is modal and already asking. While the
   * renderer's is up the SAME confirm is asked for again and the clock is
   * re-armed, and that is the whole point of not simply ignoring it: a renderer
   * that acknowledged and then hung would otherwise hold the only question
   * open with nothing able to answer it, and Alt+F4 would do nothing for ever.
   * A live renderer answers `shown` again for a dialog it already has; a hung
   * one runs out the clock and the OS asks.
   */
  requested(): void {
    if (this.state.kind === 'native') return;
    if (this.state.kind === 'renderer') {
      this.host.clearTimer(this.state.timer);
      this.ask(this.state.id);
      return;
    }
    this.ask(this.nextId++);
  }

  /** A reply from the renderer. Anything not about the current confirm is ignored. */
  replied(reply: QuitConfirmReply): void {
    const state = this.state;
    if (state.kind !== 'renderer' || state.id !== reply.id) return;
    this.host.clearTimer(state.timer);
    if (reply.answer === 'shown') {
      // Disarmed rather than cleared: the confirm is still up, so a second
      // close must still find it pending.
      this.state = { kind: 'renderer', id: state.id, timer: undefined };
      return;
    }
    this.state = { kind: 'idle' };
    if (reply.answer === 'quit') this.host.quit();
  }

  /**
   * The renderer crashed or was killed. If it was holding the question, the OS
   * asks now - it is not coming back to answer.
   */
  rendererGone(): void {
    if (this.state.kind === 'renderer') this.fallBack();
  }

  private ask(id: number): void {
    if (!this.host.send({ id, open: true })) {
      this.state = { kind: 'renderer', id, timer: undefined };
      this.fallBack();
      return;
    }
    const timer = this.host.setTimer(() => {
      if (this.state.kind === 'renderer' && this.state.id === id) this.fallBack();
    }, RENDERER_ACK_MS);
    this.state = { kind: 'renderer', id, timer };
  }

  private fallBack(): void {
    if (this.state.kind !== 'renderer') return;
    const { id, timer } = this.state;
    this.host.clearTimer(timer);
    this.state = { kind: 'native' };
    // Withdrawn first, so a renderer that was only slow cannot put its own
    // confirm up behind the OS's and leave a question on screen that nothing
    // is listening to the answer of. Best effort: if there is no renderer,
    // there is nothing to withdraw.
    this.host.send({ id, open: false });
    void this.host.showNative().then(
      (quit) => {
        this.state = { kind: 'idle' };
        if (quit) this.host.quit();
      },
      // A box that could not be shown - the window went away under it - is a
      // Keep, never a Quit. The next close asks again.
      () => { this.state = { kind: 'idle' }; },
    );
  }
}
