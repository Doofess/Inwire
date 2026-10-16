import { useEffect, useRef, type RefObject } from 'react';

import type { Packet } from '../types/packet';
import { APP_VIEWS, type AppView } from '../services/viewPrefs';
import { matchChord } from '../lib/commands';
import { captureKeyAction } from '../lib/captureKey';

/**
 * The chords that act even while a text field has focus (ADR 0057).
 *
 * Focus usually sits in the display filter, so the palette, the filter's own
 * key, Go to packet and the capture toggle must work from there - a palette
 * key that stood down for every input would be a key that almost never works.
 * The view digits and Ctrl+B are NOT here: a digit with a modifier typed into
 * a field is the field's, and has been since the digits were bound.
 */
export const CHORDS_BEFORE_INPUT_GUARD: readonly string[] = [
  'palette.open', 'palette.commands', 'filter.focus', 'packet.goto', 'capture.start', 'capture.stop',
];

export function chordBeforeInputGuard(id: string): boolean {
  return CHORDS_BEFORE_INPUT_GUARD.includes(id);
}

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
 * (whether the user may capture, and the view-switch callback) and reads
 * everything else live. There used to be a third - whether the detail MODAL was
 * open - and the gate it fed is gone with the modal; see the note inside.
 */
export interface KeyboardNavigationOptions {
  canCapture: boolean;
  /** Switches the rail's active view, for Ctrl+1..5. */
  onViewShortcut: (view: AppView) => void;
  /**
   * `Ctrl+B` - open the side bar on the last panel, or close it.
   *
   * VS Code's key for the same surface, and the same job: this is the keyboard
   * reaching the door the rail buttons are, not a second door. The side bar is
   * deliberately outside the Escape chain - it is a persisted place rather than
   * a detour - so without this it has no keyboard at all.
   */
  onToggleSideBar: () => void;
  /** Ctrl+K, Ctrl+Shift+P and Ctrl+G - the palette, opened on a prefix. */
  onOpenPalette: (prefix: '' | '>' | ':') => void;
  /** Ctrl+/ - Wireshark's key for the display filter. */
  onFocusFilter: () => void;
  filteredPacketsRef: RefObject<Packet[]>;
  selectedPacketRef: RefObject<Packet | null>;
  isCapturingRef: RefObject<boolean>;
  /** How many frames are in the buffer - Space must not discard a full one. */
  packetCountRef: RefObject<number>;
  /** Space can only resume on an adapter already chosen; it cannot ask. */
  selectedInterfacesRef: RefObject<string[]>;
  setSelectedPacket: (packet: Packet) => void;
  /**
   * Whether Start must wait - a filter the agent refused, or ring settings it
   * would. Space then starts nothing: the rail says why, and a key cannot.
   */
  startBlocked: () => boolean;
  /**
   * The rail's own start and stop. **Space used to send its own
   * `start_capture`**, which started a capture with no id and no store of its
   * own - and so, once the agent wrote each capture's files (ADR 0052), with
   * nowhere to write them. One start, one stop, whatever pressed them.
   */
  onStartCapture: () => void;
  onStopCapture: () => void;
}

export function useKeyboardNavigation({
  canCapture,
  onViewShortcut,
  onToggleSideBar,
  onOpenPalette,
  onFocusFilter,
  filteredPacketsRef,
  selectedPacketRef,
  isCapturingRef,
  packetCountRef,
  selectedInterfacesRef,
  setSelectedPacket,
  startBlocked,
  onStartCapture,
  onStopCapture,
}: KeyboardNavigationOptions): void {
  // Through a ref, for the reason `toggleSideBarRef` gives below.
  const captureRef = useRef({ startBlocked, onStartCapture, onStopCapture });
  captureRef.current = { startBlocked, onStartCapture, onStopCapture };
  /**
   * `Ctrl+B`'s handler, held the way everything that changes is held here.
   *
   * It reads which panel was last open, so it cannot be a stable
   * `useCallback` the way `onViewShortcut` is - and a fresh identity in the
   * dep array below would re-register the window listener on every render,
   * which during a capture is ten times a second. That is the exact property
   * this file's opening comment exists to protect.
   */
  const toggleSideBarRef = useRef(onToggleSideBar);
  toggleSideBarRef.current = onToggleSideBar;
  // The palette and the filter field, held the same way and for the same reason.
  const commandRef = useRef({ onOpenPalette, onFocusFilter });
  commandRef.current = { onOpenPalette, onFocusFilter };

  useEffect(() => {
    /* **There is no detail-window gate any more.** This used to bail out
       entirely while `detailPacketId` was set, because a modal was covering the
       window: its own arrows stepped frames and Space must not have reached the
       capture toggle underneath it. Frame Detail is a view, so there is nothing
       underneath and nothing to shield - and the two handlers no longer
       overlap. This binds Up and Down, the pane binds Left and Right, and both
       move the same selection. */

    /** Space and Ctrl+E ask the same question, in `captureKeyAction`. */
    const toggleCapture = (): void => {
      const action = captureKeyAction({
        capturing: isCapturingRef.current,
        adapterCount: selectedInterfacesRef.current.length,
        packetCount: packetCountRef.current,
        canCapture,
        blocked: captureRef.current.startBlocked(),
      });
      if (action === 'stop') captureRef.current.onStopCapture();
      else if (action === 'start') captureRef.current.onStartCapture();
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      const filteredPackets = filteredPacketsRef.current;
      const selectedPacket = selectedPacketRef.current;

      /**
       * Every keyed command in `commands.ts` is dispatched here by id, and
       * `scripts/commands/registry.ts` fails on one with no `case`. Two
       * switches, because the line between them is the input guard: these
       * act from inside a text field, the second set does not.
       */
      const command = matchChord(e);
      if (command && chordBeforeInputGuard(command.id)) {
        switch (command.id) {
          case 'palette.open': e.preventDefault(); commandRef.current.onOpenPalette(''); return;
          case 'palette.commands': e.preventDefault(); commandRef.current.onOpenPalette('>'); return;
          case 'packet.goto': e.preventDefault(); commandRef.current.onOpenPalette(':'); return;
          case 'filter.focus': e.preventDefault(); commandRef.current.onFocusFilter(); return;
          // One chord for both: the toggle decides which, by the same rule as Space.
          case 'capture.start':
          case 'capture.stop': e.preventDefault(); toggleCapture(); return;
        }
      }

      // Don't trigger if user is typing in an input
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement
      ) {
        return;
      }

      /**
       * Ctrl+1..5 switch views. Taken before the input guard above? No - after,
       * deliberately: a digit typed into the filter box is a filter, and these
       * carry a modifier precisely so they do not collide with typing anywhere
       * else. Digits were entirely unbound before this.
       *
       * `APP_VIEWS` order IS the numbering, so the rail's tooltips and this
       * cannot disagree about which key opens what.
       */
      // The view commands are generated from APP_VIEWS, so they share one
      // case by prefix rather than five ids that could drift from it.
      const route = command === undefined ? undefined
        : command.id.startsWith('view.') ? 'view' : command.id;
      switch (route) {
        case 'view': {
          const view = APP_VIEWS.find((v) => `view.${v.id}` === command?.id);
          if (view === undefined) break;
          e.preventDefault();
          onViewShortcut(view.id);
          return;
        }
        // The side bar, on VS Code's own key for it.
        case 'sidebar.toggle':
          e.preventDefault();
          toggleSideBarRef.current();
          return;
      }

      /**
       * Space toggles capture, and it is scoped **positively**.
       *
       * It used to be scoped by exclusion - everything except an input or a
       * textarea - which was correct only while nothing else in the window was
       * focusable. The activity rail is a dozen buttons, and Space on a focused
       * button is how a button is pressed: under the old rule, tabbing to Start
       * and pressing Space both activated it and ran this handler's
       * `preventDefault`, so the button's own activation was suppressed and the
       * capture toggled anyway - the same outcome by the wrong route, and the
       * wrong outcome entirely on the other twelve.
       *
       * So it now fires only where there is nothing else Space could mean: the
       * body itself, or inside the packet list. Every control added to this
       * window from here on is safe by default rather than by being remembered.
       */
      const target = e.target;
      const spaceIsOurs = target === document.body
        || (target instanceof Element && target.closest('[role="grid"]') !== null);

      if (e.code === "Space" && spaceIsOurs) {
        e.preventDefault();
        // The rail's own start and stop, under the rule `captureKeyAction`
        // states: stopping always, starting only where nothing must be asked.
        toggleCapture();
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
    // `onViewShortcut` joins the deps rather than going through a ref: it is
    // a stable `useCallback` in App, so this re-registers once, not per flush.
    //
    // **`onToggleSideBar` does NOT, and the difference is the whole rule this
    // file opens with.** It arrives as an inline arrow - it has to read which
    // panel was last open, which changes - so a fresh identity every render
    // would tear this listener down and rebuild it ten times a second during a
    // capture. It goes through the ref above, where everything that changes
    // already goes.
  }, [canCapture, onViewShortcut]);
}
