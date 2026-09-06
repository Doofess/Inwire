"use client"

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
  /**
   * `sm` for a control that sits in a widget's header rather than in a
   * settings row.
   *
   * A size rather than a second component, because the alternative is what the
   * dashboard had: two hand-rolled pill pairs, one bare and one in a bordered
   * box, drawn at different sizes in two widgets that sit one above the other
   * in the same column. The chip padding shrinks; the fill-and-border marking
   * of the selected segment does not, because that is the part that has to
   * stay legible.
   */
  size?: 'sm' | 'md';
  className?: string;
  disabled?: boolean;
}

function Segmented<T extends string>({
  value,
  onValueChange,
  options,
  ariaLabel,
  size = 'md',
  className,
  disabled,
}: SegmentedProps<T>) {
  // The hint for whichever segment is selected, shown under the group.
  //
  // It was a `title` and nothing else, which is a tooltip: not reachable by
  // touch, not reliably reachable by keyboard, and gone again the moment the
  // pointer moves. That is an acceptable home for a nicety and the wrong one
  // for the line that explains what a choice is FOR - which is exactly what
  // the typeface picker needs it to be. The `title` stays as well, since a
  // hover on an unselected segment is how you compare the options.
  //
  // Nothing renders when no option carries a hint, so the three groups that
  // predate this are untouched.
  const activeHint = options.find((o) => o.value === value)?.hint;

  const group = (
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
            "rounded font-medium whitespace-nowrap outline-none",
            size === 'sm' ? "px-1.5 py-0.5 text-[10px]" : "px-2.5 py-1 text-[11px]",
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
  );

  if (!activeHint) return group;

  // Right-aligned under the control, because that is where the control is in a
  // SettingRow - a left-aligned line would hang off the end of nothing.
  return (
    <div className="flex flex-col items-end gap-1">
      {group}
      <p className="text-[10px] leading-snug text-muted-foreground text-right max-w-56">
        {activeHint}
      </p>
    </div>
  );
}

export { Segmented }
export type { SegmentedOption }
