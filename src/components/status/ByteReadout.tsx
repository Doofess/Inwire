import React from 'react';
import { StatusItem } from './StatusItem';
import { describeByte, useHoveredByte } from '../../services/hoveredByte';

/**
 * The byte under the pointer, at the right end of the status bar.
 *
 * ## It subscribes for itself, and takes no props
 *
 * `App` re-renders about ten times a second during a capture, and a pointer
 * crossing a hex dump publishes far faster than that. Both rates reach this one
 * span and neither reaches the bar around it, which is the whole reason the
 * hovered byte is a store rather than a prop. `PacketCountsReadout` is the
 * pattern and its header makes the same argument at length.
 *
 * ## It renders nothing when nothing is hovered
 *
 * The footer this replaces said "Hover any byte to inspect raw bitwise &
 * numerical representation" when idle, and that sentence does not survive the
 * move. Inside the pane that owns the bytes it taught you what the pane does.
 * In a window-wide bar it would be a permanent sentence about a pane that may
 * not be on screen at all - which is the same category error that put the first
 * bottom bar in the wrong place.
 *
 * ## The labels moved into the tooltip
 *
 * `OFFSET: / DEC: / HEX: / BITS: / ASCII:` is about 400px at this size, which
 * is most of the right group's budget at the 1024px minimum window, and the
 * five values are self-describing to anyone reading a hex dump: an offset with
 * an `@`, a bare decimal, an `0x`, a `0b`, and a quoted character. The labelled
 * form is one hover away in the `title` and costs no width.
 *
 * The three colours are kept from the footer, because they are load-bearing
 * rather than decorative: at a glance they are what separates four numbers that
 * are all the same byte.
 */
export const ByteReadout: React.FC = () => {
  const hovered = useHoveredByte();

  if (hovered.index === null || hovered.value === null) return null;

  const byte = describeByte(hovered.index, hovered.value);
  const ascii = byte.ascii === '.' && hovered.value !== 0x2e ? 'N/A' : `'${byte.ascii}'`;

  return (
    <StatusItem
      className="gap-2 tabular-nums"
      title={
        `Frame ${hovered.frameId} - offset ${hovered.index} (${byte.offset}), `
        + `decimal ${byte.dec}, hex ${byte.hex}, bits 0b${byte.bits}, ASCII ${ascii}`
      }
    >
      {/* **Five figures separated by emphasis, not by hue.**

          The bits were `text-emerald-400` and the ASCII `text-amber-400` -
          raw Tailwind shades, which is what `scripts/themes/status.ts` guards
          against and caught here. Two things were wrong with them. They are
          fixed shades, so they do not move between Day and Night the way every
          token in this bar does; and green and amber are the app's success and
          warning colours, spent on a readout where nothing has succeeded or
          gone wrong.

          What separates them instead is weight: the offset and the hex are the
          two you look for, so they take `--foreground` and `--primary`, and
          the rest sit at the item's muted default. That is the same vocabulary
          `StatusItem`'s three tones use, rather than a sixth colour system
          living in one cell. */}
      <span>@<b className="text-foreground">{byte.offset}</b></span>
      <span className="text-primary">{byte.hex}</span>
      <span>{byte.dec}</span>
      {/* The bits are the widest of the five and the least often read at a
          glance, so they are the first thing to go when the window is narrow. */}
      <span className="hidden lg:inline">0b{byte.bits}</span>
      <span className="text-foreground">{ascii}</span>
    </StatusItem>
  );
};
