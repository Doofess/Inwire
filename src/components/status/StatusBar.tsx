import React from 'react';
import { ByteReadout } from './ByteReadout';
import { OutboundStatus } from './OutboundStatus';
import { SessionStatus, type SessionStatusProps } from './SessionStatus';
import { PacketCountsReadout } from '../common/PacketCountsReadout';

/**
 * The application's status bar: the chrome's bottom edge.
 *
 * ## The two rules
 *
 * This bar existed once and was deleted. Both rules below are the shape of what
 * went wrong, and a future session should read them before adding an item.
 *
 * **1. No item is aligned to anything above it.** The first bar carried the
 * byte inspector, whose subject is the hex dump - a pane that starts a
 * pane-width in from the window's left edge - so its text was pushed sideways
 * with a CSS length built from `--details-pane-size`, and the bar became two
 * blocks so a percentage would resolve against `<main>`'s content box rather
 * than the window. The verdict written into `HexViewer` at the time still
 * stands: a full-width bar that has to be pushed sideways to look like it
 * belongs somewhere narrower is a bar in the wrong place.
 *
 * What was wrong was the alignment, not the bar. A status bar groups its items
 * left and right by PRIORITY and never by correspondence with the thing above
 * them - `Ln 56, Col 2` sits at the window's right edge in every editor that
 * has one, and nobody expects it over the cursor. So the byte readout is an
 * ordinary right-group item here, with no inset at all, and there is no length
 * in this file built from any pane's size. `scripts/session/status-bar.ts`
 * fails if one appears.
 *
 * **2. An item renders only state the app owns, published by exactly one
 * place.** The first bar could not read `HexViewer`'s local hover, so it was
 * fed from `activeByteRange` derived up in `App` - which the protocol tree ALSO
 * publishes. The bar therefore answered "this byte" for a hover in a pane that
 * was not the dump. The replacement is `services/hoveredByte.ts`, a store
 * carrying the byte's VALUE rather than its index - so the only code that can
 * publish one is code that already had the bytes in hand, which is a dump and
 * never a tree. There are exactly two publishers, one per dump, and the script
 * names both: a tree has a range and nothing to offer, so the conflation is
 * unrepresentable rather than merely avoided.
 *
 * ## Why it is not a drag region
 *
 * The title row moves the window and this does not, which is what every other
 * desktop app does and is also the safe answer: a control that forgets
 * `app-no-drag` inside a drag region has one symptom, a click that does
 * nothing. The rail is entirely no-drag for the same reason, and so is this -
 * by never opting in rather than by opting out per item.
 *
 * ## Height
 *
 * `h-6`, 24px, against the title row's 32. The row is chrome you act on - it
 * drags the window and holds caption buttons at Windows' own 32px metric - and
 * this is chrome you read. It comes out of the rail's slack rather than out of
 * `MIN_WINDOW_HEIGHT`; the arithmetic is on `STATUS_BAR_HEIGHT` in
 * `electron/window.ts` and is checked by `scripts/session/view.ts`.
 *
 * ## The ground
 *
 * `bg-secondary`, the same ground as the title row and the rail - the three
 * strips are one surface and the shell's colour scheme is unchanged by the
 * outline described next.
 *
 * **This bar draws no `border-t`, and there is an edge above it anyway.** The
 * cluster sits on this strip - the rail and `<main>` are two cards, each
 * closing its own bottom edge, held 4px clear by the band's `pb-1`. So the
 * line above is the cards' outline, 4px up, with the chrome's own ground in
 * the gap.
 *
 * A `border-t` here is therefore not a second opinion about the design: it is
 * a second line 4px under the first, and a 23px bar into the bargain, because
 * `border-box` takes the border out of the height rather than adding to it.
 * `TitleRow` declines its `border-b` for the sharper version of the same -
 * 1px off an `h-8` row clips 32px caption buttons.
 * `scripts/session/status-bar.ts` fails on either.
 *
 * ## What may be threaded through it
 *
 * **Session state and handlers, and nothing derived from the packet buffer.**
 * The two items that change at capture rate - the packet counter and the byte
 * readout - subscribe to their own stores and take no props at all, which is
 * what keeps this bar off `App`'s ten-times-a-second render path. An item that
 * would need the buffer is an item that belongs in a pane.
 */
export interface StatusBarProps extends SessionStatusProps {
  /** The two switches that let this app make requests of its own. */
  nameResolution: { geoIp: boolean; reverseDns: boolean };
}

export const StatusBar: React.FC<StatusBarProps> = ({ nameResolution, ...session }) => (
  <footer
    className="h-6 shrink-0 flex items-center justify-between
      bg-secondary text-secondary-foreground
      text-[11px] font-mono select-none overflow-hidden"
    aria-label="Status"
  >
    {/* Left: is this thing working? Session state, in the order it fails in -
        the link before the capture, because a capture cannot run without one. */}
    <div className="min-w-0 flex items-center">
      <SessionStatus {...session} />
    </div>

    {/* Right: what am I looking at? Context for the frame in hand.

        **This group does not truncate, and that inverts the obvious rule.**
        The left group is labels, which survive an ellipsis - "Ethernet Cont…"
        is still an adapter you recognise. This group is NUMBERS, and "178,2…"
        is a wrong number rather than a shortened one. So the left group is
        `min-w-0` and gives up width first; this one is `shrink-0` and the items
        inside it hide whole rather than clipping.

        Ordered with the most changeable furthest from the edge: the byte
        readout comes and goes with the pointer, so it sits inboard where its
        arrival does not shove the numbers sideways. */}
    <div className="shrink-0 flex items-center justify-end">
      <ByteReadout />
      {/* The outbound indicator sits between the two, which is a swap: it was
          furthest right, on the argument that it is the most stable thing in
          the bar and so the best anchor for the corner. The counter has the
          corner now, and the trade is real either way - a right-aligned group
          shifts left as its widest member grows, so whichever item is NOT at
          the edge is the one that moves when the counts gain a digit. Putting
          the numbers at the corner is what makes them findable without reading
          the bar, which is what a counter is for. */}
      <OutboundStatus
        geoIp={nameResolution.geoIp}
        reverseDns={nameResolution.reverseDns}
      />
      <PacketCountsReadout />
    </div>
  </footer>
);
