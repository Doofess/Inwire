/**
 * The app's mark: a stack of five isometric plates.
 *
 * Flat fills, one per plate, no gradients and no strokes. That constraint has
 * outlived three drawings now and is kept for the same reason each time: every
 * artefact below is rasterised from this one source down to 16px, and a
 * gradient at 16px is mush.
 *
 * ## What this module is
 *
 * It is the mark's geometry and nothing else, and every icon the app ships is
 * generated from it - `public/icon.svg`, the two PNGs, and both `.ico` files -
 * by `scripts/brand/render-icons.ts`. `scripts/brand/icon.ts` then asserts that
 * the committed files still match what this would produce, so a change here
 * that is not re-rendered fails the suite rather than shipping a stale icon.
 *
 * That job has survived every redraw, and it is the reason the art is ported
 * into this file rather than committed as the artist's `.ico`: a binary dropped
 * in beside the pipeline is exactly the drift the regenerate-and-compare check
 * exists to catch.
 *
 * ## The box is 100, and the numbers are the author's
 *
 * `MARK_SIZE` was 256 while the mark was drawn at that size. This one is
 * authored in a 100 box - `logo/inwire-layers.svg` and `logo/README.md` - so
 * the box follows the art. The point is that the coordinates below can be read
 * straight against the source SVG with no arithmetic in between; scaling them
 * by 2.56 to keep an old constant would have made every number a decimal and
 * every comparison a calculation.
 *
 * The drawing spans x 10..90 and y 12..88, so it carries about 10% optical
 * margin of its own. Do not add more - the raster targets are tight boxes and
 * the OS adds its own padding in most of the places this appears.
 *
 * ## Two tiers, and the boundary is measured rather than chosen
 *
 * **`primary` at 32px and up, `small` below it.** Five plates need five
 * distinguishable bands; the gap is 9 in a 100 box, which is 2.9px at 32 and
 * 1.4px at 16 - and at 1.4px the five plates render as one blue lump, which
 * says something untrue about the object rather than merely losing detail.
 * `small` takes every other plate, so it is three bands at 2.9px in a 16px
 * icon: the same band width that works at 32, which is why the two tiers look
 * like one mark at their own sizes.
 *
 * Taking every OTHER plate is what keeps them one mark. The three it keeps are
 * both ends of the ramp and its middle, over the same 12..88 span, so the small
 * tier is the large one with the in-between steps dropped rather than a second
 * drawing that happens to look similar.
 *
 * ## The colours are one ramp, and the ramp is `--primary`
 *
 * Every plate is `#0b6bcb` - the app's own accent - moved in LIGHTNESS only.
 * Hue stays 210 and saturation stays 0.90 across all five, which is what makes
 * a stack of flat shapes read as one object rather than as five coloured
 * tiles. `scripts/brand/icon.ts` measures that rather than trusting it: it
 * converts every fill and holds its hue and saturation to `MARK_ACCENT`'s own.
 *
 * **Do not recolour a plate by hand.** Move it along L, or move `MARK_ACCENT`
 * and rebuild the ramp. A plate nudged off the hue is the one failure here that
 * looks fine in isolation and wrong in the stack.
 *
 * `#c42b1c` is deliberately absent - it is the close button's red and stays the
 * alarm, and an icon that shares a hue with "this went wrong" spends it.
 */

/** The viewBox both tiers are drawn in. Square, so no size can distort it. */
export const MARK_SIZE = 100;

/** `--primary`. Every plate is this colour at a different lightness. */
export const MARK_ACCENT = '#0b6bcb';

export type MarkTier = 'primary' | 'small';

/**
 * Which drawing a given rendered size gets.
 *
 * 32 is where five plates stop resolving: below it the 9-unit gap is under two
 * device pixels and the stack reads as a single blue shape. The title row's own
 * 16px mark is therefore the small tier, and so is anything in a tray.
 */
export const tierForSize = (px: number): MarkTier => (px >= 32 ? 'primary' : 'small');

export interface MarkPath {
  d: string;
  fill: string;
}

/**
 * The ramp, darkest first - which is also back-to-front.
 *
 * L = 0.22, 0.34, 0.46, 0.58, 0.70 off `MARK_ACCENT`'s hue and saturation. The
 * order is load-bearing twice over: the plates overlap, so painter's order IS
 * the depth, and the lightest plate has to be painted last or the stack reads
 * as lit from underneath.
 */
const RAMP = ['#06386A', '#0957A4', '#0C75DF', '#3494F4', '#6EB2F7'] as const;

/**
 * One plate, from the y of its top vertex.
 *
 * A rhombus on the 2:1 isometric diagonal - 80 wide, 40 tall, centred on x 50.
 * Every command is absolute, because `markBounds` reads the coordinate pairs
 * straight out of the path data and a relative command there would be measured
 * as a position.
 */
const plate = (top: number, fill: string): MarkPath => ({
  d: `M50 ${top} L90 ${top + 20} L50 ${top + 40} L10 ${top + 20} Z`,
  fill,
});

/** The gap between one plate's top vertex and the next. */
const GAP = 9;

/** The top vertex of the bottom-most plate. Its foot lands on y 88. */
const FLOOR = 48;

/** Five plates. 32px and up. */
const PRIMARY: MarkPath[] = RAMP.map((fill, i) => plate(FLOOR - i * GAP, fill));

/**
 * Three plates. Below 32px.
 *
 * Every other plate of the tier above: same span, same ends of the ramp, twice
 * the gap. Nothing here is a separate drawing - change `PRIMARY` and this
 * follows, which is what stops the two tiers drifting into different marks.
 */
const SMALL: MarkPath[] = PRIMARY.filter((_, i) => i % 2 === 0);

const TIERS: Record<MarkTier, MarkPath[]> = { primary: PRIMARY, small: SMALL };

export function brandMarkPaths(tier: MarkTier): MarkPath[] {
  return TIERS[tier];
}

/**
 * The drawing's extent inside the viewBox.
 *
 * Read off every coordinate pair in the path data, which is exact here: the
 * mark is straight lines with absolute commands, so there are no control points
 * to overestimate from. `scripts/brand/icon.ts` asserts the mark stays INSIDE
 * the box and fills most of it.
 */
export function markBounds(tier: MarkTier) {
  let minX = Infinity; let minY = Infinity;
  let maxX = -Infinity; let maxY = -Infinity;

  for (const { d } of brandMarkPaths(tier)) {
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
 * **There is no `background` option and that is the point.** Every raster this
 * produces is RGBA with transparent corners AND transparent gaps between the
 * plates, so the mark sits on the taskbar, in Explorer and in Alt-Tab as a
 * shape rather than as a tile. The previous mark painted an opaque square
 * behind itself, on the argument that Windows composites against surfaces
 * nobody can predict - which is true, and is an argument for a mark that reads
 * on any ground rather than for shipping a black square. This one is saturated
 * blue with no thin strokes, so it does.
 */
export function brandMarkSvg(tier: MarkTier): string {
  const shapes = brandMarkPaths(tier)
    .map((p) => `<path d="${p.d}" fill="${p.fill}"/>`)
    .join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${MARK_SIZE} ${MARK_SIZE}" `
    + `width="${MARK_SIZE}" height="${MARK_SIZE}">${shapes}</svg>`;
}
