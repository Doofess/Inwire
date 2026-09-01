"use client"

import * as React from "react"
import { RadioGroup as RadioGroupPrimitive } from "radix-ui"

import { cn } from "@/src/lib/utils"

/**
 * A choice between two or more alternatives, drawn as a segmented control.
 *
 * Built on Radix `RadioGroup`, not `ToggleGroup`. They look identical and are
 * not the same thing: a toggle group is semantically a toolbar of independent
 * toggles that happens to enforce one active member, so it announces the wrong
 * thing, and `type="single"` will deselect back to an empty value unless the
 * caller catches it - which for a setting like density means a control with
 * nothing chosen and a fallback branch to write. A radio group announces "2 of
 * 3", moves with the arrow keys, and cannot hold an empty value.
 *
 * The selected segment is marked by a FILL AND A BORDER, never by text colour
 * alone. In the monochrome theme, and in Solarized Dark where `--primary` and
 * `--muted-foreground` sit close together, a recoloured label at 11px is not a
 * legible difference.
 */

interface SegmentedOption<T extends string> {
  value: T;
  label: string;
  /** Optional supporting line, shown under the group rather than in the chip. */
  hint?: string;
}

interface SegmentedProps<T extends string> {
  value: T;
  onValueChange: (value: T) => void;
  options: readonly SegmentedOption<T>[];
  /** Names the group for assistive tech. Required - it has no visible label. */
  ariaLabel: string;
  className?: string;
  disabled?: boolean;
}

function Segmented<T extends string>({
  value,
  onValueChange,
  options,
  ariaLabel,
  className,
  disabled,
}: SegmentedProps<T>) {
  return (
    <RadioGroupPrimitive.Root
      data-slot="segmented"
      value={value}
      onValueChange={(next) => onValueChange(next as T)}
      aria-label={ariaLabel}
      disabled={disabled}
      // Horizontal so the arrow keys match the visual axis.
      orientation="horizontal"
      className={cn(
        "inline-flex items-center gap-0.5 rounded-md border border-border bg-muted/40 p-0.5",
        disabled && "opacity-50",
        className
      )}
    >
      {options.map((option) => (
        <RadioGroupPrimitive.Item
          key={option.value}
          value={option.value}
          title={option.hint}
          className={cn(
            "rounded px-2.5 py-1 text-[11px] font-medium whitespace-nowrap outline-none",
            "transition-colors cursor-pointer",
            "text-muted-foreground hover:text-foreground",
            // Fill + border + foreground, all three. See the note above.
            "data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground",
            "data-[state=checked]:border-primary",
            "disabled:cursor-not-allowed"
          )}
        >
          {option.label}
        </RadioGroupPrimitive.Item>
      ))}
    </RadioGroupPrimitive.Root>
  )
}

export { Segmented }
export type { SegmentedOption }
