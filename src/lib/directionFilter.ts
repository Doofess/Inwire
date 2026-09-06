/**
 * Composing a Sent/Received choice with whatever filter is already typed.
 *
 * The segmented control in the filter bar is not a second, hidden filter. It
 * writes into the same expression the user can see and edit, so there is never
 * a state where the field says one thing and the list shows another - which is
 * the failure mode of every "quick filter" that keeps its own state beside a
 * text box.
 *
 * That makes this a string transformation rather than a piece of UI state, and
 * it has two properties worth holding to:
 *
 *   - **The rest of the expression is parenthesised.** `frame.direction == out
 *     && dns || tcp` parses as `(direction && dns) || tcp`, which would show
 *     inbound TCP under a "Sent" button. Anything typed is wrapped before it
 *     is joined.
 *   - **The clause is written in one canonical form, as a prefix.** That is
 *     what lets it be recognised and removed again exactly, without parsing
 *     the expression. A user who hand-edits it into some other shape gets
 *     `all` back from the reader, and their expression is then treated as
 *     ordinary text to wrap - which is wrong in no way that matters and is far
 *     better than silently rewriting something they wrote.
 */

export type DirectionMode = 'all' | 'out' | 'in';

const CLAUSE: Record<Exclude<DirectionMode, 'all'>, string> = {
  out: 'frame.direction == out',
  in: 'frame.direction == in',
};

/**
 * Which way the control should be pointing, given the expression.
 *
 * Read from the text rather than remembered, so hand-editing the field moves
 * the control and the two can never disagree.
 */
export function directionModeOf(filter: string): DirectionMode {
  const text = filter.trim();
  for (const mode of ['out', 'in'] as const) {
    const clause = CLAUSE[mode];
    if (text === clause) return mode;
    if (text.startsWith(`${clause} && (`) && text.endsWith(')')) return mode;
  }
  return 'all';
}

/** The expression with any direction clause this module wrote taken back off. */
export function withoutDirection(filter: string): string {
  const text = filter.trim();
  for (const mode of ['out', 'in'] as const) {
    const clause = CLAUSE[mode];
    if (text === clause) return '';
    const prefix = `${clause} && (`;
    if (text.startsWith(prefix) && text.endsWith(')')) {
      return text.slice(prefix.length, -1);
    }
  }
  return text;
}

/**
 * The expression with the chosen direction applied.
 *
 * Idempotent, and switching between Sent and Received replaces rather than
 * accumulates - both because the clause is always stripped first.
 */
export function withDirection(filter: string, mode: DirectionMode): string {
  const rest = withoutDirection(filter);
  if (mode === 'all') return rest;
  if (rest === '') return CLAUSE[mode];
  return `${CLAUSE[mode]} && (${rest})`;
}
