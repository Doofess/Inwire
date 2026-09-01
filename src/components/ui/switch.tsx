"use client"

import * as React from "react"
import { Switch as SwitchPrimitive } from "radix-ui"

import { cn } from "@/src/lib/utils"

/**
 * An on/off control.
 *
 * The app had no switch, checkbox or radio of any kind before this - every
 * binary choice was a bordered card with a check badge, which works for a grid
 * of theme swatches and not for a settings list of a dozen rows.
 *
 * Radix rather than a styled div, so the thing announces as a switch, responds
 * to Space and Enter, and carries its own `aria-checked` - none of which a
 * `<div onClick>` does.
 *
 * State is carried by the THUMB'S POSITION first and the fill second. That is
 * not decoration: this app ships a deliberately monochrome theme, where the
 * distance between `--primary` and the unchecked track is lightness alone, and
 * a control that says "on" only by turning a colour is a control that says
 * nothing there. Position works in every theme, including one with no colour to
 * spend.
 */
function Switch({
  className,
  ...props
}: React.ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      className={cn(
        "peer inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-transparent",
        "transition-colors outline-none",
        "bg-muted-foreground/35 data-[state=checked]:bg-primary",
        // A border on the unchecked track as well, so the control still reads
        // as a control against a muted panel background.
        "border-border data-[state=checked]:border-primary",
        "disabled:cursor-not-allowed disabled:opacity-50",
        "cursor-pointer",
        className
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className={cn(
          "pointer-events-none block size-4 rounded-full bg-background shadow-sm ring-0",
          "transition-transform data-[state=unchecked]:translate-x-0.5 data-[state=checked]:translate-x-[18px]"
        )}
      />
    </SwitchPrimitive.Root>
  )
}

export { Switch }
