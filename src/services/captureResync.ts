/**
 * Putting a reconnected agent back where this window was - without the
 * agent's answer to the first half undoing the second.
 *
 * A pipe that breaks mid-capture ends the capture on the agent's side: the
 * owner left, so it stopped (agent.py:1170-1175, and the Rust agent's
 * `control.rs`). The app keeps showing "capturing", and on the next `hello` it
 * puts things back: `set_interfaces` with the remembered selection, then
 * `start_capture`.
 *
 * **Both agents answer the first of those with a `state` - and it says idle**,
 * because it is sent before the second arrives (agent.py:1385: every command
 * that changes what the agent is doing is answered with the resulting state,
 * to every client). The state handler read that idle as the agent's verdict on
 * the capture this window believes in and called `onCaptureStopped()` - so the
 * start that followed began a capture the UI had just declared stopped. After
 * any pipe break mid-capture, the agent captured while the window said it was
 * not.
 *
 * So the resync remembers that one answer is its own. The `state` that
 * answers our `set_interfaces` is consumed rather than obeyed; the reply to
 * `start_capture` - a `sniffing`, or an idle when every adapter failed -
 * decides, exactly as it would outside a resync. A refused `set_interfaces`
 * answers with an `error` and no `state`, so an error ends the wait too, or the
 * start's own idle would be swallowed in its place.
 *
 * Pure, so `scripts/session/capture-resync.ts` can drive both agents' reply
 * sequences through it without React.
 */
import type { AgentCommand } from './agentProtocol';

export interface Resync {
  /**
   * A `set_interfaces` sent to resume a capture, whose own `state` answer has
   * not arrived yet.
   */
  awaitingSelectionReply: boolean;
}

export const NO_RESYNC: Resync = { awaitingSelectionReply: false };

export interface ResyncInput {
  /** Another window owns the running capture - asking would be refused. */
  ownedElsewhere: boolean;
  /** The adapters this window has selected. */
  selected: readonly string[];
  /** Whether this window believes a capture is running. */
  capturing: boolean;
}

/**
 * What the `hello` handler sends to put a fresh connection back where this
 * window was, and what to expect back.
 *
 * Not when another window owns the capture: the resync is what used to hijack
 * it, and both commands would be refused now - asking at all would put a
 * `capture_busy` in front of a user who has done nothing.
 */
export function planResync(input: ResyncInput): { commands: AgentCommand[]; resync: Resync } {
  if (input.ownedElsewhere) return { commands: [], resync: NO_RESYNC };
  const commands: AgentCommand[] = [];
  if (input.selected.length > 0) {
    commands.push({ type: 'set_interfaces', interfaces: [...input.selected] });
  }
  if (input.capturing) commands.push({ type: 'start_capture' });
  return {
    commands,
    // Only a resumed capture has anything to lose to the selection's answer.
    resync: { awaitingSelectionReply: input.selected.length > 0 && input.capturing },
  };
}

/** The parts of an agent message the decision reads. */
export interface AgentReply {
  type: string;
  state?: 'idle' | 'sniffing';
}

/**
 * Reads one agent message against the resync in progress: whether it means the
 * capture this window believes in has stopped, and the resync state after it.
 */
export function readReply(
  resync: Resync,
  message: AgentReply,
  capturing: boolean,
): { stopped: boolean; resync: Resync } {
  if (message.type === 'state') {
    if (resync.awaitingSelectionReply) {
      // Our own `set_interfaces`, answered. Whatever it says, it is not the
      // start's answer - that comes next.
      return { stopped: false, resync: NO_RESYNC };
    }
    // The agent is the authority on whether capture is running: idle while
    // this window believes otherwise means every adapter failed, or the
    // capture was stopped from elsewhere.
    return { stopped: message.state === 'idle' && capturing, resync };
  }
  if (message.type === 'error' && resync.awaitingSelectionReply) {
    // The selection was refused, so no `state` is coming for it.
    return { stopped: false, resync: NO_RESYNC };
  }
  return { stopped: false, resync };
}
