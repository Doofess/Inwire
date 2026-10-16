/**
 * Whether a key may start or stop a capture - Space and Ctrl+E both ask this.
 *
 * Stopping is always allowed: being unable to stop a running capture from the
 * keyboard would be a far worse trade than being unable to start one. Starting
 * is refused in every case where the rail button would have to ASK something,
 * because a key has nowhere to ask it:
 *
 *  - no adapter chosen - the first capture of a session needs the picker;
 *  - frames in the buffer - a stopped capture cannot be resumed, so starting
 *    again clears it, which is the rail's confirm prompt and never a keystroke;
 *  - no agent, or Start blocked by a filter or ring settings the agent refused -
 *    the rail says why, and a key cannot;
 *  - a capture another client of the agent owns - the rail disables Start, and
 *    a start would clear this session before the agent refused it.
 */

export interface CaptureKeyState {
  capturing: boolean;
  adapterCount: number;
  packetCount: number;
  canCapture: boolean;
  blocked: boolean;
  /** Another client of the agent owns the running capture. */
  ownedElsewhere: boolean;
}

export function captureKeyAction(s: CaptureKeyState): 'start' | 'stop' | null {
  if (s.capturing) return 'stop';
  if (s.adapterCount === 0 || s.packetCount > 0 || !s.canCapture || s.blocked || s.ownedElsewhere) return null;
  return 'start';
}
