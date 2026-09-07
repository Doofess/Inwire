import { useEffect, type RefObject } from 'react';

import type { Packet } from '../types/packet';
import type { AgentCommand } from '../services/agentProtocol';

/**
 * The keyboard shortcuts that belong to the window rather than to a control.
 *
 * Space starts and stops capture; the arrows step the selection. Both are
 * global listeners, which is what makes them worth isolating: a global handler
 * competes with every focused control on the page, and the rules for when it
 * must stand down are the whole substance of this hook. They were 92 lines in
 * the middle of `App.tsx`.
 *
 * Everything it reads comes through a **ref**, deliberately. A `keydown`
 * listener re-registered on every change of the buffer or the selection would
 * be re-registered on every flush - 10 times a second during a capture - so
 * the effect depends only on the two things that change what the handler MEANS
 * (whether the detail window is open, and whether the user may capture) and
 * reads everything else live.
 */
export interface KeyboardNavigationOptions {
  /** Non-null while the packet detail window is open, which owns the keyboard. */
  detailPacketId: number | null;
  canCapture: boolean;
  filteredPacketsRef: RefObject<Packet[]>;
  selectedPacketRef: RefObject<Packet | null>;
  isCapturingRef: RefObject<boolean>;
  /** How many frames are in the buffer - Space must not discard a full one. */
  packetCountRef: RefObject<number>;
  /** Space can only resume on an adapter already chosen; it cannot ask. */
  selectedInterfacesRef: RefObject<string[]>;
  setIsCapturing: (capturing: boolean) => void;
  setSelectedPacket: (packet: Packet) => void;
  sendAgentCommand: (command: AgentCommand) => void;
}

export function useKeyboardNavigation({
  detailPacketId,
  canCapture,
  filteredPacketsRef,
  selectedPacketRef,
  isCapturingRef,
  packetCountRef,
  selectedInterfacesRef,
  setIsCapturing,
  setSelectedPacket,
  sendAgentCommand,
}: KeyboardNavigationOptions): void {
  useEffect(() => {
    // The packet detail window owns the keyboard while it is open: its own
    // arrows step frames, and Space must not reach the capture toggle
    // underneath it and start or stop a live capture nobody asked to change.
    if (detailPacketId !== null) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      const filteredPackets = filteredPacketsRef.current;
      const selectedPacket = selectedPacketRef.current;
      // Don't trigger if user is typing in an input
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement
      ) {
        return;
      }

      if (e.code === "Space") {
        e.preventDefault();
        // Mirror the Header start/stop buttons: flip local state and tell the
        // agent, rather than just flipping local state (which used to be
        // enough when the old agent sniffed unconditionally from launch).
        const wasCapturing = isCapturingRef.current;
        // Starting needs an adapter, and a keyboard handler has nowhere to
        // pop a picker. So space resumes on whatever was already chosen and
        // otherwise does nothing - the first capture of a session has to be
        // started from a control that can ask. Stopping is always allowed:
        // being unable to stop a running capture from the keyboard would be
        // a far worse trade than being unable to start one.
        if (!wasCapturing && selectedInterfacesRef.current.length === 0) return;
        // Nor does it start one that would DISCARD a buffer. A stopped capture
        // cannot be resumed, so starting again clears what is there - and that
        // is a question, asked by the header button's prompt. A keyboard
        // shortcut has nowhere to ask it and must not answer it silently:
        // Space would otherwise be one keystroke, with no undo, between a
        // finished capture and an empty list. Stopping stays unconditional.
        if (!wasCapturing && packetCountRef.current > 0) return;
        const next = canCapture ? !wasCapturing : false;
        setIsCapturing(next);
        if (next !== wasCapturing) {
          sendAgentCommand(next ? { type: "start_capture" } : { type: "stop_capture" });
        }
        return;
      }

      // Arrow keys only: the packet list handles its own, and handles them
      // better - it moves by index into the sorted buffer (so it can reach a
      // row the virtualizer has not rendered), scrolls the new row into view,
      // and decides whether to keep following the live tail. Without this
      // guard both handlers run and every press moves the selection two rows.
      //
      // Scoped to the arrows rather than bailing outright, because Space must
      // still start and stop capture while the list has focus - which is where
      // focus usually is.
      const insidePacketList =
        e.target instanceof Element && e.target.closest('[role="grid"]') !== null;

      if (e.code === "ArrowDown") {
        if (insidePacketList) return;
        e.preventDefault();
        if (filteredPackets.length === 0) return;
        if (!selectedPacket) {
          setSelectedPacket(filteredPackets[0]);
        } else {
          const idx = filteredPackets.findIndex(
            (p) => p.id === selectedPacket.id,
          );
          if (idx >= 0 && idx < filteredPackets.length - 1) {
            setSelectedPacket(filteredPackets[idx + 1]);
          }
        }
      } else if (e.code === "ArrowUp") {
        if (insidePacketList) return;
        e.preventDefault();
        if (filteredPackets.length === 0) return;
        if (!selectedPacket) {
          setSelectedPacket(filteredPackets[filteredPackets.length - 1]);
        } else {
          const idx = filteredPackets.findIndex(
            (p) => p.id === selectedPacket.id,
          );
          if (idx > 0) {
            setSelectedPacket(filteredPackets[idx - 1]);
          }
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canCapture, detailPacketId]);
}
