/**
 * Whether Start may run, and whether it must ask before it does.
 *
 * Two surfaces start a capture: the rail's button and the welcome on an empty
 * Packets view. Both discard something when they do - the frames in the buffer,
 * or a previous capture that is still on disk and that nobody can see in the
 * list - and the rule is that Start asks first. The decision lived in the rail;
 * a second copy beside the welcome's button is how the two would come to
 * disagree about when a capture may be deleted unasked, so both read this.
 *
 * Pure, with no React, so a plain-tsx script can import it.
 */
export interface StartGateInput {
  isCapturing: boolean;
  /** `permissions.canCapture`. */
  canCapture: boolean;
  /** `permissions.canClearBuffer`. */
  canClearBuffer: boolean;
  /** An adapter is chosen. */
  hasSelection: boolean;
  /** Another window owns the capture. */
  ownedElsewhere: boolean;
  /** App's own reason Start must wait, or null. */
  blockedReason: string | null;
  bufferedPackets: number;
  /** The label of the capture still on disk, or null. */
  previousCapture: string | null;
}

export interface StartGate {
  /** Why Start cannot run now, as text to show, or null. */
  blocked: string | null;
  /** What Start would discard and so must ask about first, or null. */
  discards: 'previous' | 'buffer' | null;
}

export function startGate(input: StartGateInput): StartGate {
  const {
    isCapturing, canCapture, canClearBuffer, hasSelection, ownedElsewhere,
    blockedReason, bufferedPackets, previousCapture,
  } = input;

  // A stopped capture cannot be resumed, so starting again means discarding: a
  // buffer appended to across two runs has a gap in the middle that nothing in
  // the file records. A previous capture offered on disk is discarded by Start
  // just the same, and only when the buffer is empty - frames in the buffer
  // are the capture being replaced, and the one on disk is that capture's.
  const discards: StartGate['discards'] = isCapturing ? null
    : bufferedPackets > 0 ? 'buffer'
      : previousCapture != null ? 'previous'
        : null;

  // The rail's tooltip text for each case, kept as it was. A missing permission
  // has never had words of its own: the rail said "Choose an interface first".
  let blocked: string | null = null;
  if (ownedElsewhere) {
    blocked = 'Another Inwire window is capturing. Stop it there, or close that window.';
  } else if (blockedReason !== null) {
    blocked = blockedReason;
  } else if (!canCapture || !hasSelection) {
    blocked = 'Choose an interface first';
  } else if (discards !== null && !canClearBuffer) {
    blocked = 'Not allowed to clear the current capture.';
  }
  return { blocked, discards };
}

/**
 * What one press of Start does, given the gate: nothing while it is blocked,
 * ask first when it would discard something, otherwise start.
 *
 * Its own function so the rule a button follows can be run from a script: the
 * welcome's button calling `onStart` straight would type-check and delete the
 * previous capture unasked.
 */
export function startPress(gate: StartGate): 'none' | 'confirm' | 'start' {
  if (gate.blocked !== null) return 'none';
  return gate.discards !== null ? 'confirm' : 'start';
}

/**
 * The stored capture worth offering for reopening, or null.
 *
 * One that ever received a frame and has a directory: anything else reopens
 * nothing. Read at launch and after Clear View, which empties the list and
 * keeps the capture on disk - and an empty list with no offer is a Start that
 * deletes the capture without asking, because `startGate` has nothing to ask
 * about.
 */
export function offeredCapture<M extends { captureId?: string | null; lastPacketMs: number | null }>(
  meta: M | null,
): M | null {
  return meta?.captureId && meta.lastPacketMs != null ? meta : null;
}
