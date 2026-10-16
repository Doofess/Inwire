import type { BloatGrade } from '../../services/speedTest/method';

/** A term with a one-line explanation, on hover and on keyboard focus alike. */
export function Hint({ term, explain }: { term: string; explain: string }) {
  return (
    <span tabIndex={0} aria-label={`${term}: ${explain}`}
      className="group relative cursor-help underline decoration-dotted underline-offset-2 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring rounded-sm">
      {term}
      <span role="tooltip"
        className="pointer-events-none absolute bottom-full left-0 z-20 mb-1.5 hidden w-64 rounded-md border border-border bg-popover px-2.5 py-1.5
          text-[11px] font-normal leading-snug text-popover-foreground shadow-lg no-underline group-hover:block group-focus:block">
        {explain}
      </span>
    </span>
  );
}

/** The grade's colour comes from the status tokens, never from the two speed colours. */
export const GRADE_TONE: Record<BloatGrade, string> = {
  'A+': 'bg-success/15 text-success border-success/40',
  A: 'bg-success/15 text-success border-success/40',
  B: 'bg-warning/15 text-warning border-warning/40',
  C: 'bg-warning/15 text-warning border-warning/40',
  D: 'bg-danger/15 text-danger border-danger/40',
  F: 'bg-danger/15 text-danger border-danger/40',
};

export const GRADE_WORD: Record<BloatGrade, string> = {
  'A+': 'barely moves', A: 'small rise', B: 'some rise', C: 'noticeable', D: 'large', F: 'severe',
};

/** Milliseconds as a figure: a decimal under ten, where one matters. */
export function fmtMsValue(ms: number): string {
  return ms < 10 ? ms.toFixed(1) : Math.round(ms).toString();
}
