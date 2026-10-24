/**
 * The two heading levels, and the only two.
 *
 * A pane, a sheet or a panel is named by a **TITLE**: sentence case, semibold,
 * the foreground colour. A group of controls or figures inside it is named by
 * a **MICRO_LABEL**: uppercase and tracked at 10px, muted. Both are the sans
 * face. Uppercase in the mono face was a third level that did the micro-label's
 * job in another typeface, and the 2026-10-24 audit counted sixteen of them;
 * `scripts/themes/typography.ts` fails on any class string that brings it back.
 *
 * The mono face is for data - addresses, bytes, hex, filter expressions, field
 * names, paths - never for the chrome around it. Counts in chrome stay sans:
 * `body` sets `tnum`, so the figures already line up.
 */

export const TITLE = 'text-xs font-semibold text-foreground';

export const MICRO_LABEL = 'text-[10px] font-bold uppercase tracking-widest text-muted-foreground';
