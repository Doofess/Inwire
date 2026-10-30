import React from 'react';
import type { LucideIcon } from 'lucide-react';

/**
 * What a pane says when it has nothing to show - the packet list, the protocol
 * tree and the hex dump, one shape for all three.
 *
 * **In the app's sans face, not the mono one.** Each pane sets `font-mono` for
 * the data it draws, and the empty states used to inherit it: an uppercase
 * label in a code font, which read as a placeholder nobody had come back to.
 * An empty state is the app talking, so it is set the way the rest of the
 * chrome is - `font-sans`, sentence case, the title a step above the line
 * under it.
 *
 * **It says what to do next, and offers it when it can.** A hint names the
 * keys; `actions` holds buttons for the step the text describes, so the reader
 * does not have to find the control the sentence is talking about.
 */
export function EmptyState({
  icon: Icon, title, children, actions, hint, busy = false,
}: {
  icon: LucideIcon;
  title: string;
  /** One or two short sentences under the title. */
  children?: React.ReactNode;
  /** Buttons - `EmptyStateButton` - for the next step. */
  actions?: React.ReactNode;
  /** A quieter last line, usually naming keys with `Kbd`. */
  hint?: React.ReactNode;
  /** A slow pulse on the icon, for a pane that is waiting on something that is coming. */
  busy?: boolean;
}) {
  return (
    <div className="flex flex-col items-center text-center font-sans max-w-[24rem] mx-auto px-4">
      <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-secondary">
        <Icon className={`h-5 w-5 text-muted-foreground ${busy ? 'animate-pulse' : ''}`} aria-hidden />
      </div>
      <p className="text-[13px] font-semibold text-foreground">{title}</p>
      {children && <div className="mt-1 text-xs leading-relaxed text-muted-foreground">{children}</div>}
      {actions && <div className="mt-3 flex flex-wrap items-center justify-center gap-2">{actions}</div>}
      {/* A fixed line, so a hint with keys in it stands as tall as one without:
          two panes side by side then put their titles on the same row. */}
      {hint && <div className="mt-3 flex min-h-5 items-center text-[11px] text-muted-foreground"><span>{hint}</span></div>}
    </div>
  );
}

/** A button in an empty state: `primary` for the step the text recommends, plain for the rest. */
export function EmptyStateButton({
  icon: Icon, children, onClick, primary = false, disabled = false, title,
}: {
  icon?: LucideIcon;
  children: React.ReactNode;
  onClick: () => void;
  primary?: boolean;
  /** Shut, with `title` saying why. */
  disabled?: boolean;
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring
        ${primary
          ? 'bg-primary text-primary-foreground hover:bg-primary/90'
          : 'border border-border bg-secondary text-foreground hover:bg-accent'}`}
    >
      {Icon && <Icon className="h-3.5 w-3.5" aria-hidden />}
      {children}
    </button>
  );
}

/** A key, as a hint names it. */
export function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="mx-0.5 inline-block min-w-[1.25rem] rounded border border-border bg-secondary px-1 py-px
      text-center text-[10px] leading-4 text-foreground">
      {children}
    </kbd>
  );
}
