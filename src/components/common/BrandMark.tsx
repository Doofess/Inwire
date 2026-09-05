import React from 'react';
import { MARK_SIZE, brandMarkPaths } from '../../lib/brandMark';

/**
 * The app's mark: two nested chevrons, each a band folded once.
 *
 * Monochrome and painted in `currentColor`, so it takes the colour of whatever
 * it sits in - which is how one drawing serves four themes with no per-theme
 * work at all. The header sets that colour once on the lockup, so the mark and
 * the wordmark beside it cannot end up different colours.
 *
 * Deliberately NOT drawn in the house icon style. Everything else in this app
 * is `react-icons/tb` - a 24 viewBox, `fill="none"`, `stroke-width="2"`, round
 * caps - and the pull to match it is strong and wrong. A brand mark that looks
 * like one more toolbar glyph has failed at being a brand mark. This is a
 * filled form, at its own weight, and it sits beside that set rather than in
 * it.
 *
 * The geometry lives in `lib/brandMark.ts` because the favicon, the PNGs and
 * the Windows `.ico` are all generated from the same call - see
 * `scripts/brand/render-icons.ts`.
 */
export const BrandMark: React.FC<{ className?: string; title?: string }> = ({
  className,
  title,
}) => (
  <svg
    viewBox={`0 0 ${MARK_SIZE} ${MARK_SIZE}`}
    className={className}
    // The wordmark beside it already names the app, so by default this is
    // decorative and should not be announced twice.
    role={title ? 'img' : undefined}
    aria-hidden={title ? undefined : true}
    aria-label={title}
    fill="currentColor"
  >
    {brandMarkPaths().map((run) => (
      <path key={run.d} d={run.d} fillOpacity={run.opacity} />
    ))}
  </svg>
);
