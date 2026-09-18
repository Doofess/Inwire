/**
 * The app's mark: a head-on RJ45 connector.
 *
 * Body, latch, cavity, contacts. **Flat-facet shading** - depth comes from one
 * solid tone per face, with no gradients, no highlights and no drop shadow.
 * That is the same constraint the drawing this replaced worked under, and it is
 * kept for the same reason: a gradient at 16px is mush, and every artefact
 * below is rasterised from this one source down to 16.
 *
 * ## What this module is
 *
 * It is the mark's geometry and nothing else, and every icon the app ships is
 * generated from it - `public/icon.svg`, the two PNGs, and both `.ico` files -
 * by `scripts/brand/render-icons.ts`. `scripts/brand/icon.ts` then asserts that
 * the committed files still match what this would produce, so a change here
 * that is not re-rendered fails the suite rather than shipping a stale icon.
 *
 * **It used to generate rather than declare.** The previous mark was one ribbon
 * spiralling round a sphere, computed - a spiral spec, a projection, a taper
 * function, and about 140 flat fills emitted per tier. This one is drawn art,
 * so the module holds the art. What survives is the module's JOB, which was
 * never the arithmetic: one source, every output generated from it, and the
 * colours living here rather than in the component.
 *
 * ## Two tiers, and the rule is a hard edge rather than a taste
 *
 * **`primary` at 48px and up, `small` below it.** The primary mark has eight
 * contacts; below about 48px eight contacts stop resolving and read as a single
 * blue band, which is worse than fewer contacts because it says something
 * untrue about the object. The small mark has four, drops the cavity's bevelled
 * walls, and opens up the spacing.
 *
 * The previous mark had three tiers for a related reason - it shed turns of the
 * spiral as the box shrank - so the mechanism is unchanged and only the count
 * moved. `tierForSize` is still the honest way to ask: a caller knows how big
 * it is drawing, not which internal drawing it wants.
 *
 * ## The colours are derived, not picked
 *
 * Every tone is one of the app's own two brand colours shifted in LIGHTNESS
 * only, so hue and saturation stay the app's: the steel faces come from
 * `--secondary`, the contacts from `--primary` (`#0b6bcb`). `#c42b1c` is
 * deliberately absent - it is the close button's colour and stays the alarm.
 *
 * **Do not recolour a face by hand.** The ramp is what makes the facets read as
 * one object lit from one side; a tone nudged on its own flattens the corner it
 * belongs to. Change `MARK_BODY` or `MARK_ACCENT` and regenerate the ramp.
 */

/** The viewBox both tiers are drawn in. Square, so no size can distort it. */
export const MARK_SIZE = 256;

/** The two colours every face is derived from. */
export const MARK_BODY = '#1e2632';
export const MARK_ACCENT = '#0b6bcb';

export type MarkTier = 'primary' | 'small';

/**
 * Which drawing a given rendered size gets.
 *
 * 48 is where eight contacts stop resolving. Below it the primary mark's
 * contact block reads as one blue bar - see the 16px magnification in the
 * mark's own contact sheet, which is what set this number.
 */
export const tierForSize = (px: number): MarkTier => (px >= 48 ? 'primary' : 'small');

export interface MarkPath {
  d: string;
  fill: string;
}

/**
 * A rounded rectangle as path data.
 *
 * The art is authored with `<rect rx>` for the body and the contacts, and this
 * flattens those to paths so the mark is ONE kind of shape everywhere. That
 * matters downstream rather than here: `BrandMark` maps over a single list,
 * `brandMarkSvg` emits one element type, and `markBounds` has one thing to
 * measure. A second shape kind would have to be handled in all three.
 */
function roundedRect(x: number, y: number, w: number, h: number, r: number): string {
  const rx = Math.min(r, w / 2, h / 2);
  return [
    `M${x + rx} ${y}`,
    `H${x + w - rx}`,
    `A${rx} ${rx} 0 0 1 ${x + w} ${y + rx}`,
    `V${y + h - rx}`,
    `A${rx} ${rx} 0 0 1 ${x + w - rx} ${y + h}`,
    `H${x + rx}`,
    `A${rx} ${rx} 0 0 1 ${x} ${y + h - rx}`,
    `V${y + rx}`,
    `A${rx} ${rx} 0 0 1 ${x + rx} ${y}`,
    'Z',
  ].join(' ');
}

/** Eight contacts, evenly spaced, as one row. */
function contacts(
  count: number, x0: number, step: number, y: number,
  w: number, h: number, r: number, fill: string,
): MarkPath[] {
  return Array.from({ length: count }, (_, i) => ({
    d: roundedRect(x0 + i * step, y, w, h, r),
    fill,
  }));
}

/**
 * The full mark. 48px and up.
 *
 * Ordered back to front, because the faces overlap and the painter's order IS
 * the depth: the latch is behind the body, the cavity is cut into the body's
 * front face, and the contacts sit inside the cavity.
 */
const PRIMARY: MarkPath[] = [
  // The latch, behind the body. Its front face first, then the lit top edge.
  { d: 'M94 104 L102 46 C103 38 109 33 117 33 L139 33 C147 33 153 38 154 46 L162 104 Z', fill: '#212936' },
  { d: 'M102 46 C103 38 109 33 117 33 L139 33 C147 33 153 38 154 46 L146 48 C145 42 143 40 138 40 L118 40 C113 40 111 42 110 48 Z', fill: '#5E779C' },

  // The body, and the one lit face on it - the top, catching the same light as
  // the latch's crown.
  { d: roundedRect(34, 90, 188, 126, 18), fill: '#151B23' },
  { d: 'M52 90 H204 A18 18 0 0 1 221 102 H35 A18 18 0 0 1 52 90 Z', fill: '#60799F' },

  // The cavity's four bevelled walls. Four tones off one ramp, darkest at the
  // top where least light reaches and lightest at the bottom sill.
  { d: 'M44 108 H212 L204 114 H52 Z', fill: '#0A0C10' },
  { d: 'M212 108 V186 L204 172 V114 Z', fill: '#171D26' },
  { d: 'M44 108 V186 L52 172 V114 Z', fill: '#212936' },
  { d: 'M44 186 H212 L204 172 H52 Z', fill: '#303D50' },

  // The cavity floor, then the contacts standing in it.
  { d: roundedRect(52, 114, 152, 58, 0), fill: '#090B0E' },
  ...contacts(8, 56, 19, 118, 11, 48, 5.5, '#479EF5'),
  // The contacts' tips, where they meet the floor and fall out of the light.
  ...contacts(8, 56, 19, 157, 11, 9, 4.5, '#06386A'),
];

/**
 * The simplified mark. Below 48px.
 *
 * Four contacts rather than eight, no cavity bevels, and a slightly larger body
 * - at 16px the bevels are sub-pixel and the extra contacts merge, so drawing
 * them spends detail on mush. What is left is the silhouette that identifies
 * the object: a latch above a dark rectangle with blue bars in it.
 */
const SMALL: MarkPath[] = [
  { d: 'M92 104 L100 44 C101 36 108 30 116 30 L140 30 C148 30 155 36 156 44 L164 104 Z', fill: '#2E3A4C' },
  { d: 'M100 44 C101 36 108 30 116 30 L140 30 C148 30 155 36 156 44 L147 46 C146 40 144 38 139 38 L117 38 C112 38 110 40 109 46 Z', fill: '#5E779C' },
  { d: roundedRect(28, 92, 200, 132, 20), fill: '#191F29' },
  { d: 'M48 92 H208 A20 20 0 0 1 227 105 H29 A20 20 0 0 1 48 92 Z', fill: '#60799F' },
  { d: roundedRect(40, 112, 176, 76, 8), fill: '#0A0C10' },
  ...contacts(4, 50, 38, 120, 24, 52, 12, '#258CF3'),
];

const TIERS: Record<MarkTier, MarkPath[]> = { primary: PRIMARY, small: SMALL };

export function brandMarkPaths(tier: MarkTier): MarkPath[] {
  return TIERS[tier];
}

/**
 * The drawing's extent inside the viewBox.
 *
 * Read off every coordinate pair in the path data, which is **approximate on
 * the two curved faces**: a cubic's control points can lie outside the curve,
 * so a box measured this way is never tighter than the truth. That is the safe
 * direction for what reads it - `scripts/brand/icon.ts` asserts the mark stays
 * INSIDE the box and fills most of it, and an over-estimate can only fail those
 * checks, never pass one it should not.
 */
export function markBounds(tier: MarkTier) {
  let minX = Infinity; let minY = Infinity;
  let maxX = -Infinity; let maxY = -Infinity;

  for (const { d } of brandMarkPaths(tier)) {
    // Every command in this file is absolute and its operands are plain
    // numbers, so the pairs fall out in order. The arc flags are 0/1 and land
    // harmlessly inside the box they are already inside.
    const nums = (d.match(/-?\d+(?:\.\d+)?/g) ?? []).map(Number);
    for (let i = 0; i + 1 < nums.length; i += 2) {
      minX = Math.min(minX, nums[i]);
      maxX = Math.max(maxX, nums[i]);
      minY = Math.min(minY, nums[i + 1]);
      maxY = Math.max(maxY, nums[i + 1]);
    }
  }

  return { minX, minY, maxX, maxY };
}

/**
 * The mark as a standalone SVG document.
 *
 * `background` is for the rasters only: Windows composites them against
 * surfaces nobody can predict, and a mark on an unknown ground is a mark nobody
 * can see. It is a plain square - no rounded corners, no gradient - because the
 * OS applies its own mask.
 */
export function brandMarkSvg(tier: MarkTier, options: { background?: string } = {}): string {
  const ground = options.background
    ? `<rect width="${MARK_SIZE}" height="${MARK_SIZE}" fill="${options.background}"/>`
    : '';
  const shapes = brandMarkPaths(tier)
    .map((p) => `<path d="${p.d}" fill="${p.fill}"/>`)
    .join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${MARK_SIZE} ${MARK_SIZE}" `
    + `width="${MARK_SIZE}" height="${MARK_SIZE}">${ground}${shapes}</svg>`;
}
