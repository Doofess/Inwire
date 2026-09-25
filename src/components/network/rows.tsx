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

/**
 * The two constants a restacked row is built from.
 *
 * `LABEL` is the line above a value rather than the column beside it, so it is
 * sized like a heading rather than like a cell. `WARN_BLOCK` is the treatment
 * that says "these two disagree, and the disagreement is the finding" - it was
 * `bg-amber-500/10 border-l-2 border-amber-500`, raw Tailwind shades of exactly
 * the kind `scripts/themes/status.ts` was pointed at `ByteReadout` to catch.
 * Fixed shades do not move between Day and Night the way every other colour in
 * this panel does, and amber is the app's warning hue, which it has a token
 * for.
 */
const LABEL = 'text-[10px] font-semibold uppercase tracking-wider text-muted-foreground';
const WARN_BLOCK = 'bg-warning/10 border-l-2 border-warning';

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
    <div className={`px-3 py-2 text-xs ${warn ? WARN_BLOCK : ''}`}>
      {/* **Label above value, not beside it.** It was a `w-40` column, which
          left ~90px for the value in a 288px column - and this panel's values
          are IPv6 addresses with prefix lengths, MACs with vendor lines and
          multi-entry DNS lists. A truncated address is a wrong address, so the
          value takes the whole width and the label takes a line of its own.

          The copy button rides the LABEL line rather than the value's, which
          is what stops it stealing width from the thing it copies. */}
      <div className="flex items-center gap-1">
        <span className={LABEL} title={source ? `From ${source}` : undefined}>
          {label}
        </span>
        {/* Only when there is something to copy, and never the masked form - a
            copy button that put bullets on the clipboard would be a trap. */}
        {text !== '' && !children && (
          <CopyButton value={text} label={label.toLowerCase()} className="ml-auto" />
        )}
      </div>
      <div className="mt-0.5 text-foreground">
        {children ?? <Value value={value} sensitive={sensitive} hidden={hidden} />}
      </div>
    </div>
  );
};


/**
 * A titled block of facts, with a heading that STICKS.
 *
 * Seven of these stack in one scroller now - there was a `w-40` nav showing one
 * at a time, and it went with the two-column sheet - so the heading has to
 * survive its own section being scrolled through, or a reader three rows into
 * IPv6 has no way of knowing which section they are in.
 *
 * **`overflow-hidden` went for that.** It clipped the children to the card's
 * radius, and it also made this element a scroll container, which pins a
 * `sticky` child to a box exactly its own height - stickiness that does
 * nothing. The radius moves onto the heading instead. What is lost is the clip
 * on the last row's ground when that row carries a warning wash; what is
 * gained is knowing where you are.
 *
 * **The body is the lighter surface and the heading the darker one, in both
 * themes.** Day always had it that way (`--card` #fff under `--secondary`
 * #eef1f5); Night had it reversed - the body showed the column's `--card`
 * #1a1a1a through it, under a `--secondary` #232323 heading - and the owner
 * asked for it the other way round. So Night alone swaps, with `dark:`
 * variants: the body takes `--muted` (#232323; `--muted` rather than the
 * identical `--secondary`, because `--secondary` is the chrome's colour and
 * a section body is content) and the heading `--card` (#1a1a1a) - the
 * column's own ground, so the heading reads as the column showing through
 * above a raised body. `--background` (#161616) was tried first and sat
 * DARKER than the column around it, which read as a slot cut into the card
 * rather than as its title. Day is untouched on purpose: swapping it too would
 * darken the body again and drop `--warning` on it to 4.06:1. The note lost its
 * `/70` in the same pass - it measured 3.71:1 on the new body.
 */
export const Section: React.FC<{ title: string; note?: React.ReactNode; children: React.ReactNode }> = ({
  title, note, children,
}) => (
  <div className="rounded-lg border border-border dark:bg-muted">
    <div className="sticky top-0 z-10 rounded-t-lg px-3 py-2 bg-secondary dark:bg-card border-b border-border">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
        {title}
      </div>
      {note && <div className="text-[11px] text-muted-foreground mt-0.5">{note}</div>}
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
 * What the OS is configured with and what the capture showed, stacked.
 *
 * The panel's whole argument: either side may be unknown, and the two being
 * different is the finding rather than an error.
 *
 * ## The words moved onto the values, because position can no longer carry them
 *
 * This was two `flex-1` columns under a `CompareHeader` that wrote "Configured
 * (OS)" and "Observed (capture)" ONCE per section - so every pair below
 * inherited its meaning from which side of the row it sat on. In a 288px column
 * there are no sides. **`CompareHeader` is deleted and each value carries its
 * own tag**, every time, which is what keeps the pane readable when a section
 * is scrolled so its heading is off screen - a thing the two-column form never
 * had to survive.
 *
 * `OS` and `SEEN` rather than the full phrases, with those phrases in the
 * `title`. A 48px gutter is what a tag can have beside a value that may be an
 * IPv6 address; "Configured (OS)" needs 90 and would put the address back in
 * the ~90px box this restack exists to escape.
 *
 * ## The warned side is marked, which the two-column form did not need to do
 *
 * Side by side, "which of these two is the surprising one" was answered by
 * position - the right-hand column was the capture. Stacked, it is not, so on
 * a finding the OBSERVED tag takes the warning hue. The block treatment and the
 * `note` sentence are unchanged and they are what actually carry the argument;
 * this is the half that the geometry cost.
 */
const TAG = 'w-12 shrink-0 text-[10px] uppercase tracking-wider pt-px';

export const Compare: React.FC<{
  label: string;
  configured: React.ReactNode;
  observed: React.ReactNode;
  warn?: boolean;
  note?: string;
}> = ({ label, configured, observed, warn, note }) => (
  <div className={`px-3 py-2 text-xs ${warn ? WARN_BLOCK : ''}`}>
    <div className={LABEL}>{label}</div>
    <div className="mt-0.5 space-y-1">
      <div className="flex items-start gap-2">
        <span className={`${TAG} text-muted-foreground/70`} title="Configured on this machine">
          OS
        </span>
        <div className="flex-1 min-w-0">{configured}</div>
      </div>
      <div className="flex items-start gap-2">
        <span
          className={`${TAG} ${warn ? 'text-warning font-semibold' : 'text-muted-foreground/70'}`}
          title="Observed in this capture"
        >
          SEEN
        </span>
        <div className="flex-1 min-w-0">{observed}</div>
      </div>
    </div>
    {/* No indent any more: it was `ml-40 pl-3`, hanging the sentence under a
        label column that no longer exists. */}
    {note && <div className="mt-1 text-[11px] text-warning-muted">{note}</div>}
  </div>
);
