"use client"

import * as React from "react"
import { Popover as PopoverPrimitive } from "radix-ui"

import { cn } from "@/src/lib/utils"

/**
 * A panel anchored to the control that opened it.
 *
 * The CSS for this has been in `index.css` since before the component was: the
 * rules at the top of that file already target `[data-slot='popover-content']`
 * with the same `nv-menu-in` / `nv-menu-out` keyframes and the same
 * `transform-origin: var(--radix-popover-content-transform-origin)` that give
 * the Interfaces menu its "grows out of its button" motion. So this is a
 * wrapper over Radix and nothing else - the styling is shared with every other
 * anchored surface in the app by construction, which is the point.
 *
 * The dashboard's collapsed rail is what needed it. A rail icon pops its widget
 * out beside itself rather than opening a window in the middle of the screen,
 * and Radix supplies the parts that are tedious and easy to get subtly wrong:
 * flipping when there is no room on the preferred side, an arrow that stays
 * pointed at the trigger through that flip, Escape, outside-click, and putting
 * focus back on the trigger when it closes.
 *
 * Not `ui/dialog.tsx`'s sibling: a popover is not modal, and the rail's
 * bubbles must not be. This is a monitoring dashboard, and a panel that traps
 * focus while packets arrive behind it is the wrong shape for it.
 */

function Popover({ ...props }: React.ComponentProps<typeof PopoverPrimitive.Root>) {
  return <PopoverPrimitive.Root data-slot="popover" {...props} />
}

function PopoverTrigger({ ...props }: React.ComponentProps<typeof PopoverPrimitive.Trigger>) {
  return <PopoverPrimitive.Trigger data-slot="popover-trigger" {...props} />
}

function PopoverAnchor({ ...props }: React.ComponentProps<typeof PopoverPrimitive.Anchor>) {
  return <PopoverPrimitive.Anchor data-slot="popover-anchor" {...props} />
}

function PopoverContent({
  className,
  align = "center",
  sideOffset = 8,
  collisionPadding = 8,
  ...props
}: React.ComponentProps<typeof PopoverPrimitive.Content>) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        data-slot="popover-content"
        align={align}
        sideOffset={sideOffset}
        collisionPadding={collisionPadding}
        className={cn(
          // Above the rail, which sits at z-45 so it stays reachable while a
          // widget is open over the app.
          "z-50 max-h-(--radix-popover-content-available-height)",
          "rounded-lg border border-border bg-popover text-popover-foreground shadow-xl outline-none",
          className
        )}
        {...props}
      />
    </PopoverPrimitive.Portal>
  )
}

/**
 * The tail, pointing back at the trigger.
 *
 * `bg-popover` on the arrow and a border-coloured shadow rather than a stroke:
 * an SVG arrow with a border draws a line across the panel edge it is attached
 * to, which reads as a notch rather than as a tail.
 */
function PopoverArrow({
  className,
  width = 12,
  height = 6,
  ...props
}: React.ComponentProps<typeof PopoverPrimitive.Arrow>) {
  return (
    <PopoverPrimitive.Arrow
      data-slot="popover-arrow"
      width={width}
      height={height}
      className={cn("fill-popover", className)}
      {...props}
    />
  )
}

export { Popover, PopoverTrigger, PopoverAnchor, PopoverContent, PopoverArrow }
