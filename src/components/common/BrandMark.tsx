import React from 'react';
import { MARK_SIZE, brandMarkPaths, tierForSize, type MarkTier } from '../../lib/brandMark';

/**
 * The app's mark: one ribbon spiralling around a sphere.
 *
 * **It carries its own colours, and that reverses an old rule.** The mark was
 * monochrome `currentColor` for exactly as long as it was two flat chevrons, and
 * the argument then was good - one drawing served every theme with no per-theme
 * work. The drawing is a shaded form now, so its colours ARE the drawing, and
 * inheriting one would flatten it to a silhouette. What survives of the old rule
 * is the part that mattered: the colours still live in one place, and it is not
 * here. See `lib/brandMark.ts` for why a single ramp still serves both themes.
 *
 * **The tier is not optional in practice.** The drawing sheds turns as the box
 * shrinks, and picking the wrong one is not a subtle error: the full tier at
 * 16px is a smudge. `size` is the honest way to ask for it - callers know how
 * big they are rendering it, not which of three internal drawings they want.
 *
 * Deliberately NOT in the house icon style. Everything else in this app is
 * `lucide-react` - a 24 viewBox, `fill="none"`, `stroke-width="2"`, round caps
 * - and the pull to match it is strong and wrong. A brand mark that looks like
 * one more toolbar glyph has failed at being a brand mark.
 *
 * The geometry lives in `lib/brandMark.ts` because the icon, the PNGs and the
 * Windows `.ico` are all generated from the same call - see
 * `scripts/brand/render-icons.ts`.
 */
export const BrandMark: React.FC<{
  className?: string;
  title?: string;
  /** Rendered size in CSS pixels, which is what picks the drawing. */
  size?: number;
  /** Escape hatch for a caller that genuinely knows better. */
  tier?: MarkTier;
}> = ({ className, title, size = 16, tier }) => (
  <svg
    viewBox={`0 0 ${MARK_SIZE} ${MARK_SIZE}`}
    className={className}
    // The wordmark beside it already names the app, so by default this is
    // decorative and should not be announced twice.
    role={title ? 'img' : undefined}
    aria-hidden={title ? undefined : true}
    aria-label={title}
  >
    {brandMarkPaths(tier ?? tierForSize(size)).map((p, i) => (
      // The runs are ordered back to front and overlap by design, so the index
      // IS the identity here - two segments can share a `d` and must both draw.
      // eslint-disable-next-line react/no-array-index-key
      <path key={i} d={p.d} fill={p.fill} />
    ))}
  </svg>
);
