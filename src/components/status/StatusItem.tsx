import React from 'react';

/**
 * One cell of the status bar.
 *
 * Every item in the bar goes through here, so the bar's texture - height,
 * padding, and the muted default - is decided once rather than copied into six
 * components that drift. `ActivityRail` learned the
 * same lesson with `railButton`.
 *
 * **Every item is a `<span>`, and none of them is pressable.** They were
 * buttons: each one opened the Settings tab that fixes what it was reporting -
 * the link into Driver Info, the adapter and the outbound indicator into
 * Interface. That is gone on request, and the bar is a readout.
 *
 * What it buys is worth writing down, because the argument for the buttons was
 * a good one and somebody will make it again. Six items meant six tab stops
 * ahead of the workspace for a keyboard user, and six things that look
 * pressable in a strip where the one genuinely pressable control - the packet
 * counter's `+N UNSEARCHED` rescan - is NOT a `StatusItem` and does not go
 * through here. A bar where most things react to a click and one of them does
 * something is worse at advertising that one than a bar where nothing does.
 *
 * So there is no `onClick` and this renders one element. Adding the prop back
 * is not a small change: it is the decision above, and it would need the
 * focus-ring and hover styling that went with it.
 *
 * **There is no hover treatment left**, and that is the point rather than an
 * omission: nothing here responds to a pointer because nothing here does
 * anything. The wash it used was `foreground/10` rather than a named token,
 * because the bar sits on `--secondary` and every ground one step off it in
 * this palette is either the rail's active fill or a content surface's - worth
 * keeping in the note in case a pressable thing ever lands in this strip.
 */
export type StatusTone = 'normal' | 'attention' | 'accent';

/**
 * **A tone colours the TEXT, and the warning hue is deliberately not here.**
 *
 * `--warning` on the chrome"s `--secondary` measures 4.06:1 in Day, under the
 * 4.5 floor `scripts/themes/registry.ts` holds text to - so an item that needs
 * to raise a hand puts the hue on its GLYPH and takes `attention` for its text,
 * which is full-strength rather than muted. That is the rail"s own answer to
 * the identical problem: it found `--primary` on a tint of itself peaks at 3.97
 * in Day and moved the colour off the text rather than lowering the floor.
 *
 * Shape plus colour, never colour alone - which is also why every attention
 * state in this bar carries a glyph that differs in outline, not just in hue.
 */
const TONE: Record<StatusTone, string> = {
  normal: 'text-muted-foreground',
  attention: 'text-secondary-foreground',
  accent: 'text-primary',
};

export interface StatusItemProps {
  children: React.ReactNode;
  /** The native tooltip. Say what the item means, not what it says. */
  title?: string;
  tone?: StatusTone;
  /** For the one or two items that have to give up width first. */
  className?: string;
  /** The accessible name, when the visible text is an abbreviation or a glyph. */
  label?: string;
}

/** The one shape every item in the bar takes. */
const CELL = 'h-6 px-2 shrink-0 flex items-center gap-1.5 whitespace-nowrap';

export const StatusItem: React.FC<StatusItemProps> = ({
  children, title, tone = 'normal', className = '', label,
}) => (
  <span className={`${CELL} ${TONE[tone]} ${className}`} title={title} aria-label={label}>
    {children}
  </span>
);
