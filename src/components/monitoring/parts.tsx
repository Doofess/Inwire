import React from 'react';
import type { Tone } from './monitoringCopy';

/** The small pieces the monitoring sheet's parts share. Tokens only. */

const DOT: Record<Tone, string> = {
  neutral: 'bg-muted-foreground/60',
  progress: 'bg-primary motion-safe:animate-pulse',
  good: 'bg-success',
  warn: 'bg-warning',
  bad: 'bg-danger',
};

/** A state's colour, always beside the words that carry it: never the only sign. */
export function ToneDot({ tone, className = '' }: { tone: Tone; className?: string }) {
  return <span aria-hidden className={`inline-block h-2 w-2 shrink-0 rounded-full ${DOT[tone]} ${className}`} />;
}

export const BUTTON_PRIMARY = `inline-flex h-8 items-center justify-center gap-1.5 rounded-md bg-primary px-3.5 text-xs font-semibold
  text-primary-foreground transition-colors hover:bg-primary/90 cursor-pointer disabled:cursor-not-allowed disabled:opacity-50
  focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background`;

export const BUTTON_SECONDARY = `inline-flex h-8 items-center justify-center gap-1.5 rounded-md border border-border bg-secondary px-3 text-xs
  font-semibold text-foreground transition-colors hover:bg-accent cursor-pointer disabled:cursor-not-allowed disabled:opacity-50
  focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background`;

/** The field's surface without a width, for a control sized by its row rather than filling it. */
export const INPUT_SURFACE = `h-8 rounded-md border border-input bg-background px-2.5 font-mono text-xs text-foreground
  placeholder:text-muted-foreground/70 disabled:opacity-60
  focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring aria-[invalid=true]:border-danger`;

export const INPUT = `${INPUT_SURFACE} w-full`;

/** A titled block of the sheet. The heading is a real heading, so a screen reader can walk them. */
export function Block({ title, aside, children, labelId }: {
  title: string; aside?: React.ReactNode; children: React.ReactNode; labelId?: string;
}) {
  return (
    <section aria-labelledby={labelId} className="min-w-0">
      <div className="mb-2.5 flex min-h-6 items-center justify-between gap-3">
        <h2 id={labelId} className="text-[13px] font-semibold text-foreground">{title}</h2>
        {aside}
      </div>
      {children}
    </section>
  );
}

/** A note set apart from the facts around it: a hint, a warning or a failure, by `tone`. */
export function Note({ tone = 'neutral', icon, title, children, role }: {
  tone?: 'neutral' | 'warn' | 'bad'; icon?: React.ReactNode; title?: string; children: React.ReactNode;
  role?: 'alert' | 'note';
}) {
  const edge = tone === 'bad' ? 'border-l-danger' : tone === 'warn' ? 'border-l-warning' : 'border-l-primary/60';
  const glyph = tone === 'bad' ? 'text-danger' : tone === 'warn' ? 'text-warning' : 'text-primary';
  return (
    <div role={role} className={`flex gap-2.5 rounded-md border border-border border-l-[3px] ${edge} bg-card px-3 py-2.5`}>
      {icon && <span className={`mt-px shrink-0 ${glyph}`} aria-hidden>{icon}</span>}
      <div className="min-w-0 space-y-1 text-xs leading-relaxed text-foreground">
        {title && <p className="font-semibold">{title}</p>}
        {children}
      </div>
    </div>
  );
}

/** A label and a value, for the status rows' facts. */
export function Fact({ label, children, title }: { label: string; children: React.ReactNode; title?: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 text-xs" title={title}>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="tabular-nums text-foreground">{children}</dd>
    </div>
  );
}
