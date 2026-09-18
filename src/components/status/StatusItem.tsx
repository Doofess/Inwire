import React from 'react';

/**
 * One cell of the status bar.
 *
 * Every item in the bar goes through here, so the bar's texture - height,
 * padding, hover, focus, the disabled-looking muted default - is decided once
 * rather than copied into six components that drift. `ActivityRail` learned the
 * same lesson with `railButton`.
 *
 * **It renders a `<button>` only when it has somewhere to go.** A status item
 * that is purely a readout is a `<span>`: giving it a button's role and a
 * focus stop would put six tab stops in the way of the keyboard user for six
 * things that cannot be pressed. The ones that DO go somewhere are real
 * buttons, because "clicking the link indicator opens Driver Info" has to be
 * reachable without a mouse.
 *
 * The hover is `foreground/10` rather than a named token on purpose: the bar
 * sits on `--secondary`, and every ground one step off it in this palette is
 * either the rail's active fill or a content surface's. A translucent wash of
 * the text colour is the one treatment that reads correctly on both themes
 * without claiming to be either of those things.
 */
export type StatusTone = 'normal' | 'attention' | 'accent';

const TONE: Record<StatusTone, string> = {
  normal: 'text-muted-foreground',
  attention: 'text-warning',
  accent: 'text-primary',
};

export interface StatusItemProps {
  children: React.ReactNode;
  /** Where this item goes when pressed. Omit for a pure readout. */
  onClick?: () => void;
  /** The native tooltip. Say what the item means, not what it says. */
  title?: string;
  tone?: StatusTone;
  /** For the one or two items that have to give up width first. */
  className?: string;
  /** The accessible name, when the visible text is an abbreviation or a glyph. */
  label?: string;
}

/** Shared by both branches, so the two can never drift apart. */
const CELL = 'h-6 px-2 shrink-0 flex items-center gap-1.5 whitespace-nowrap';

export const StatusItem: React.FC<StatusItemProps> = ({
  children, onClick, title, tone = 'normal', className = '', label,
}) => {
  const classes = `${CELL} ${TONE[tone]} ${className}`;

  if (!onClick) {
    return (
      <span className={classes} title={title} aria-label={label}>
        {children}
      </span>
    );
  }

  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-label={label}
      className={`${classes} hover:bg-foreground/10 focus-visible:outline-none
        focus-visible:ring-1 focus-visible:ring-ring focus-visible:ring-inset
        transition-colors`}
    >
      {children}
    </button>
  );
};
