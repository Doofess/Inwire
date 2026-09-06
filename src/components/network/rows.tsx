import React from 'react';
import { CopyButton } from '../ui/CopyButton';

/**
 * The shared vocabulary of the Network panel.
 *
 * Every section is a list of facts, and each fact needs the same four things:
 * a name, a value, somewhere to say where the value came from, and a way to
 * get it out of the app. Doing that four times in seven sections is how the
 * seven sections end up looking like seven different panels.
 *
 * Two rules are enforced here rather than left to each section.
 *
 * **A null renders as an em dash, never as a guess and never as a zero.** The
 * whole panel is a comparison between what the machine is configured with and
 * what the capture actually shows, so a fabricated value on either side does
 * not read as a bug - it reads as a discrepancy, which is exactly the thing
 * somebody would open this panel to find. "Not known" has to be visibly
 * distinct from "known to be nothing".
 *
 * **Masking is done on the value, not around it.** A "hide sensitive" that
 * each section implemented for itself would be a switch that is only as good
 * as the least careful section - and the point of it is screen-sharing, where
 * the failure is not noticing.
 */

/** Replaces the middle of a value, keeping enough to tell two of them apart. */
export function mask(value: string): string {
  if (value.length <= 4) return '••••';
  // Keeps the first and last two characters: enough to see that two rows are
  // different addresses without saying which addresses they are. A MAC keeps
  // nothing of its OUI, deliberately - the vendor half is exactly what
  // identifies the device.
  return `${value.slice(0, 2)}••••${value.slice(-2)}`;
}

interface ValueProps {
  value: string | number | null | undefined;
  /** Masks the value when the panel is hiding sensitive things. */
  sensitive?: boolean;
  hidden?: boolean;
  mono?: boolean;
}

export const Value: React.FC<ValueProps> = ({ value, sensitive, hidden, mono = true }) => {
  if (value === null || value === undefined || value === '') {
    return <span className="text-muted-foreground/60" title="Not known">—</span>;
  }
  const text = String(value);
  const shown = sensitive && hidden ? mask(text) : text;
  return <span className={mono ? 'font-mono break-all' : 'break-words'}>{shown}</span>;
};

interface RowProps {
  label: string;
  value?: string | number | null;
  /** Which provider answered - shown on hover, so a value can be traced back. */
  source?: string | null;
  sensitive?: boolean;
  hidden?: boolean;
  /** Highlights the row: a configured/observed disagreement worth noticing. */
  warn?: boolean;
  children?: React.ReactNode;
}

export const Row: React.FC<RowProps> = ({
  label, value, source, sensitive, hidden, warn, children,
}) => {
  const text = value === null || value === undefined ? '' : String(value);
  return (
    <div className={`flex items-start gap-3 px-3 py-2 text-xs ${
      warn ? 'bg-amber-500/10 border-l-2 border-amber-500' : ''}`}>
      <div className="w-40 shrink-0 text-muted-foreground" title={source ? `From ${source}` : undefined}>
        {label}
        {source && <span className="ml-1 opacity-40">·</span>}
      </div>
      <div className="flex-1 min-w-0 text-foreground">
        {children ?? <Value value={value} sensitive={sensitive} hidden={hidden} />}
      </div>
      {/* Only when there is something to copy, and never the masked form - a
          copy button that put bullets on the clipboard would be a trap. */}
      {text !== '' && !children && (
        <CopyButton value={text} label={label.toLowerCase()} />
      )}
    </div>
  );
};


export const Section: React.FC<{ title: string; note?: string; children: React.ReactNode }> = ({
  title, note, children,
}) => (
  <div className="rounded-lg border border-border overflow-hidden">
    <div className="px-3 py-2 bg-secondary border-b border-border">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
        {title}
      </div>
      {note && <div className="text-[11px] text-muted-foreground/70 mt-0.5">{note}</div>}
    </div>
    <div className="divide-y divide-border">{children}</div>
  </div>
);

/**
 * A section with nothing in it yet, saying which of the two reasons applies.
 *
 * "The agent is not connected" and "the capture did not show this" are
 * completely different statements, and a panel that rendered one blank area
 * for both would leave the reader unable to tell a missing agent from a quiet
 * network.
 */
export const Empty: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="px-3 py-4 text-xs text-muted-foreground text-center">{children}</div>
);

/**
 * Two columns: what the OS is configured with, and what the capture showed.
 *
 * The panel's whole argument. Either side may be unknown, and the two being
 * different is the finding rather than an error.
 */
export const Compare: React.FC<{
  label: string;
  configured: React.ReactNode;
  observed: React.ReactNode;
  warn?: boolean;
  note?: string;
}> = ({ label, configured, observed, warn, note }) => (
  <div className={`px-3 py-2 text-xs ${warn ? 'bg-amber-500/10 border-l-2 border-amber-500' : ''}`}>
    <div className="flex items-start gap-3">
      <div className="w-40 shrink-0 text-muted-foreground">{label}</div>
      <div className="flex-1 min-w-0">{configured}</div>
      <div className="flex-1 min-w-0">{observed}</div>
    </div>
    {note && <div className="ml-40 pl-3 mt-1 text-[11px] text-amber-600 dark:text-amber-400">{note}</div>}
  </div>
);

export const CompareHeader: React.FC = () => (
  <div className="flex items-start gap-3 px-3 py-1.5 text-[10px] uppercase tracking-wider
    text-muted-foreground/70 bg-muted/30">
    <div className="w-40 shrink-0" />
    <div className="flex-1">Configured (OS)</div>
    <div className="flex-1">Observed (capture)</div>
  </div>
);
