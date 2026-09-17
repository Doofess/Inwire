/**
 * The Inwire mark: one ribbon, spiralling pole to pole around a sphere.
 *
 * **The ribbon lies ON the surface.** Its two edges are points on the sphere
 * either side of the curve, along the surface direction perpendicular to travel
 * - so the band wraps the ball like tape rather than hovering beside it, and it
 * narrows wherever the surface turns away. That narrowing is the whole reason
 * the form reads as round, and it falls out of the projection rather than being
 * drawn in. This is the same construction `components/analytics/arcLayer.ts`
 * uses to put arcs on the Routing Map's globe: the mark and the thing it names
 * are built the same way.
 *
 * **Near hides far, by painter's order.** The segments are drawn back to front
 * at full opacity, so a turn in front covers the turn behind it exactly as a
 * solid ribbon would, and what shows through the gaps is the band's far side
 * seen from inside - which is where the dark half of the drawing comes from.
 * Nothing is hidden by hand and nothing is cut.
 *
 * **Tone is shading, not depth.** They were the same thing until the drawing was
 * compared against a real one: depth alone puts the brightest part of the band
 * dead centre, where the surface is nearest, which is a highlight in the middle
 * of a ball and reads as a bullseye. A light direction runs the gradient
 * diagonally across the form instead. Depth still orders the painting; it
 * stopped colouring it.
 *
 * **The gradient is many flat fills.** `scripts/brand/icon.ts` refuses a
 * `<linearGradient>` and still does. The band is cut into short segments along
 * its length, each a flat fill at its own shading value; a hundred and forty of
 * them across a 256px drawing is a step well under a perceptible level. It reads
 * as a gradient, and every run stays a plain filled path - which is what keeps
 * the bounds exact and the coverage measurable.
 *
 * **There is no monochrome rendering, and that is a reversal.** The mark was a
 * flat glyph in `currentColor` for exactly as long as it was two chevrons, and
 * the old `icon.ts` asserted the component held no colour literal at all. It
 * does not any more. What survives of that rule is the part worth keeping: the
 * colours live HERE, with the geometry, and `BrandMark.tsx` still holds none.
 *
 * No React and no DOM, so the assertion scripts can import it under plain `tsx`
 * - the same constraint `services/interfacePrefs.ts` documents for the same
 * reason.
 */

export type Point = readonly [number, number];
export type V3 = readonly [number, number, number];

/** The drawing grid. Square, and halves cleanly to a 16px icon. */
export const MARK_SIZE = 32;
const MID = MARK_SIZE / 2;
const R2 = (n: number) => Math.round(n * 100) / 100;

/**
 * The mark's two colours, and the reason there is only one pair of them.
 *
 * One ramp serves every ground, which was checked rather than assumed. The worry
 * was Night: a far colour dark enough to read as shadow on white should
 * disappear into a `#1a1a1a` card. It does not - and the obvious fix, lightening
 * the far end for the dark theme, measurably FLATTENS the form, because the
 * sense of depth IS the distance between the two ends of the ramp.
 *
 * So the pair is fixed, and the property `currentColor` was protecting - one
 * drawing, no per-theme work - survives the move to colour intact.
 */
export const MARK_FAR = '#123a6b';
export const MARK_NEAR = '#2fc3e8';

// --- vectors ----------------------------------------------------------------

const add = (a: V3, b: V3): V3 => [a[0] + b[0], a[1] + b[1], a[2] + b[2]];
const sub = (a: V3, b: V3): V3 => [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
const mul = (a: V3, k: number): V3 => [a[0] * k, a[1] * k, a[2] * k];
const cross = (a: V3, b: V3): V3 =>
  [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
const norm = (a: V3): V3 => {
  const L = Math.hypot(a[0], a[1], a[2]) || 1;
  return [a[0] / L, a[1] / L, a[2] / L];
};
/** Rodrigues: v rotated about the unit axis a by theta. */
const rotateAbout = (v: V3, a: V3, theta: number): V3 => {
  const c = Math.cos(theta);
  const s = Math.sin(theta);
  const d = a[0] * v[0] + a[1] * v[1] + a[2] * v[2];
  return add(add(mul(v, c), mul(cross(a, v), s)), mul(a, d * (1 - c)));
};

// --- the band ---------------------------------------------------------------

export interface SpiralSpec {
  readonly radius: number;
  /** How many times the band goes round between the poles. */
  readonly turns: number;
  /** Ribbon width at its widest, in grid units. */
  readonly width: number;
  /** Tilt of the sphere's axis away from vertical, and the azimuth of that tilt. */
  readonly tilt: number;
  readonly lean: number;
  /** How much of the length each tip tapers over, as a fraction of it. */
  readonly taper: number;
  /** Segments along the band. More is a smoother gradient and more paths. */
  readonly segments: number;
  /** The darkest the shading goes. The lit side is always 1. */
  readonly toneFloor: number;
  /** Where the light comes from. See the note on tone at the top of the file. */
  readonly light: V3;
}

export interface MarkRun {
  /** A closed polygon. Absolute coordinates only, so bounds can be read off it. */
  readonly pts: readonly Point[];
  /** Where this sits between the unlit side and the lit one, 0 to 1. */
  readonly tone: number;
  /** Mean depth. Draw order only - it does not reach the paint. */
  readonly z: number;
}

const project = (v: V3): Point => [MID + v[0], MID - v[1]];

/** Ends that come to a point, easing rather than ramping into it. */
function taperAt(u: number, span: number): number {
  const k = Math.min(u, 1 - u) / span;
  if (k >= 1) return 1;
  return k * k * (3 - 2 * k);
}

export function spiralRuns(spec: SpiralSpec): MarkRun[] {
  const { radius, turns, width, tilt, lean, taper, segments, toneFloor } = spec;
  const light = norm(spec.light);
  const axis = norm([
    Math.sin(tilt) * Math.cos(lean), Math.cos(tilt), Math.sin(tilt) * Math.sin(lean),
  ]);
  // The sphere is built upright and then tipped, so `turns` stays readable as a
  // fact about the band rather than about the camera.
  const upright: V3 = [0, 1, 0];
  const spinAxis = norm(cross(upright, axis));
  const spinAngle = Math.acos(Math.max(-1, Math.min(1, axis[1])));
  const tip = (v: V3): V3 => (spinAngle < 1e-6 ? v : rotateAbout(v, spinAxis, spinAngle));

  const SAMPLES = segments * 6;
  const at = (u: number): V3 => {
    const lat = Math.PI / 2 - Math.PI * u;
    const lon = 2 * Math.PI * turns * u;
    return tip([Math.cos(lat) * Math.cos(lon), Math.sin(lat), Math.cos(lat) * Math.sin(lon)]);
  };

  // Both edges, as points on the sphere either side of the curve.
  const edges: { a: V3; b: V3; c: V3 }[] = [];
  for (let i = 0; i <= SAMPLES; i++) {
    const u = i / SAMPLES;
    const p = at(u);
    const tangent = norm(sub(at(Math.min(1, u + 1e-3)), at(Math.max(0, u - 1e-3))));
    const across = norm(cross(p, tangent));
    const half = (width * taperAt(u, taper)) / 2 / radius;
    edges.push({
      c: mul(p, radius),
      a: mul(norm(add(p, mul(across, half))), radius),
      b: mul(norm(sub(p, mul(across, half))), radius),
    });
  }

  const runs: MarkRun[] = [];
  const per = Math.max(1, Math.floor(SAMPLES / segments));
  for (let s = 0; s < SAMPLES; s += per) {
    const slice = edges.slice(s, Math.min(SAMPLES, s + per) + 1);
    if (slice.length < 2) continue;
    const z = slice.reduce((acc, q) => acc + q.c[2], 0) / slice.length;
    // Shading from the surface direction against the light. The band lies ON the
    // sphere, so its own outward normal IS the direction from the centre.
    const lit = slice.reduce((acc, q) => {
      const n = norm(q.c);
      return acc + (n[0] * light[0] + n[1] * light[1] + n[2] * light[2]);
    }, 0) / slice.length;
    runs.push({
      pts: [...slice.map((q) => project(q.a)), ...slice.map((q) => project(q.b)).reverse()],
      tone: toneFloor + (1 - toneFloor) * ((lit + 1) / 2),
      z,
    });
  }
  return runs.sort((a, b) => a.z - b.z);
}

// --- the three tiers --------------------------------------------------------

/**
 * How much drawing a given size can hold.
 *
 * One design language shedding detail as the box shrinks. Three specs rather
 * than one scaled drawing because of the 16px cell: three and a half turns is a
 * smudge there, and 16px is what Windows puts in the taskbar, Alt-Tab and the
 * window's own title row - the size a person actually looks at all day.
 *
 * A tier changes how many times the band goes round and how wide it is, never
 * the construction, so the three are visibly one object at three densities.
 */
export type MarkTier = 'full' | 'compact' | 'micro';

const FULL: SpiralSpec = {
  radius: 13.4,
  turns: 3.5,
  width: 4.6,
  tilt: 0.44,
  lean: 0.9,
  taper: 0.1,
  // 140 steps rather than 64. The band covers three and a half turns, so 64
  // leaves about eighteen per turn - and the light changes fast enough across a
  // turn that eighteen reads as facets rather than as a gradient.
  segments: 140,
  toneFloor: 0.1,
  light: [0.5, 0.52, 0.69],
};

const COMPACT: SpiralSpec = { ...FULL, turns: 2.6, width: 5.2, segments: 72, toneFloor: 0.16 };

/**
 * 16px.
 *
 * **Both halves of the band, not just the near one.** Culling everything behind
 * the sphere is the obvious way to keep the gaps open at this size, and it was
 * tried: it leaves two detached arcs that read as a mouth, and it costs the
 * width, because the band's widest points sit exactly on the silhouette that
 * culling removes. Two turns of the whole band keeps the swirl, the silhouette
 * and the legal bounds together.
 */
const MICRO: SpiralSpec = {
  ...FULL, radius: 13.8, turns: 2.1, width: 6.2, segments: 30, toneFloor: 0.46, taper: 0.16,
};

export const MARK_TIERS: Record<MarkTier, SpiralSpec> = { full: FULL, compact: COMPACT, micro: MICRO };

/** Which drawing a given rendered size gets. */
export const tierForSize = (px: number): MarkTier =>
  (px >= 64 ? 'full' : px >= 24 ? 'compact' : 'micro');

// --- paths and paint --------------------------------------------------------

const hex = (n: number) => Math.round(Math.max(0, Math.min(255, n))).toString(16).padStart(2, '0');
const channel = (s: string, i: number) => parseInt(s.slice(1 + i * 2, 3 + i * 2), 16);
/** The ramp, as a colour. `tone` 0 is the far end and 1 the lit one. */
export const markColor = (tone: number): string =>
  `#${[0, 1, 2].map((i) =>
    hex(channel(MARK_FAR, i) + (channel(MARK_NEAR, i) - channel(MARK_FAR, i)) * tone)).join('')}`;

export const markPath = (run: MarkRun): string =>
  `M${run.pts.map(([x, y]) => `${R2(x)} ${R2(y)}`).join('L')}Z`;

export interface MarkPath {
  readonly d: string;
  readonly fill: string;
}

/** What a renderer needs and nothing else: a path and the colour to fill it. */
export function brandMarkPaths(tier: MarkTier): MarkPath[] {
  return spiralRuns(MARK_TIERS[tier]).map((run) => ({ d: markPath(run), fill: markColor(run.tone) }));
}

/**
 * The box the drawn mark actually occupies, per tier.
 *
 * Computed from the generated geometry rather than declared beside it: the
 * band's extent depends on the taper, the turn count and the tilt all at once,
 * so stating it in advance would mean restating that arithmetic somewhere it
 * could drift from this.
 */
export function markBounds(tier: MarkTier) {
  const runs = spiralRuns(MARK_TIERS[tier]);
  const xs = runs.flatMap((r) => r.pts.map((p) => p[0]));
  const ys = runs.flatMap((r) => r.pts.map((p) => p[1]));
  return {
    minX: R2(Math.min(...xs)), maxX: R2(Math.max(...xs)),
    minY: R2(Math.min(...ys)), maxY: R2(Math.max(...ys)),
  };
}

/**
 * The mark as a standalone SVG document.
 *
 * Used for `public/icon.svg` and as the source the rasteriser draws from, so
 * every committed artefact is the same drawing.
 */
export function brandMarkSvg(tier: MarkTier, options: { background?: string } = {}): string {
  const body = brandMarkPaths(tier)
    .map((p) => `<path d="${p.d}" fill="${p.fill}"/>`).join('');
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${MARK_SIZE} ${MARK_SIZE}"`
    + ` width="${MARK_SIZE}" height="${MARK_SIZE}">`
    + (options.background
      ? `<rect width="${MARK_SIZE}" height="${MARK_SIZE}" fill="${options.background}"/>`
      : '')
    + body
    + '</svg>'
  );
}
