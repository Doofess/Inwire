/**
 * The small amount of colour arithmetic the app does for itself.
 *
 * Tailwind handles the chrome, but anything that hands a colour to a canvas, to
 * D3 or to MapLibre has to compute it: a `bg-primary/20` chip is a utility, and
 * the same tint on a map layer is a hex string somebody has to produce. This
 * exists so the packet palette and the basemap tint do that the same way rather
 * than each carrying their own copy of it.
 */

export type Rgb = [number, number, number];

export function toRgb(hex: string): Rgb {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

export function toHex([r, g, b]: Rgb): string {
  return `#${[r, g, b]
    .map((c) => Math.max(0, Math.min(255, Math.round(c))).toString(16).padStart(2, '0'))
    .join('')}`;
}

/** `amount` of `color` over `ground`, 0 giving the ground and 1 the colour. */
export function mixHex(color: string, ground: string, amount: number): string {
  const [cr, cg, cb] = toRgb(color);
  const [gr, gg, gb] = toRgb(ground);
  return toHex([
    gr + (cr - gr) * amount,
    gg + (cg - gg) * amount,
    gb + (cb - gb) * amount,
  ]);
}

/** WCAG 2.1 relative luminance. */
export function relativeLuminance(hex: string): number {
  const [r, g, b] = toRgb(hex).map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG contrast ratio between two colours, 1:1 to 21:1. */
export function contrastRatio(a: string, b: string): number {
  const [x, y] = [relativeLuminance(a), relativeLuminance(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

/** Whether a colour is dark enough to be treated as a dark ground. */
export function isDarkColor(hex: string): boolean {
  return relativeLuminance(hex) < 0.2;
}

export type Lab = [number, number, number];

export function labToHex([L, a, b]: Lab): string {
  const fy = (L + 16) / 116;
  const fx = fy + a / 500;
  const fz = fy - b / 200;
  const inv = (t: number) => (t ** 3 > 0.008856 ? t ** 3 : (t - 16 / 116) / 7.787);
  const x = inv(fx) * 0.95047;
  const y = inv(fy);
  const z = inv(fz) * 1.08883;

  const lin = [
    x * 3.2406 + y * -1.5372 + z * -0.4986,
    x * -0.9689 + y * 1.8758 + z * 0.0415,
    x * 0.0557 + y * -0.204 + z * 1.057,
  ];
  return toHex(
    lin.map((c) => {
      const s = c <= 0.0031308 ? 12.92 * c : 1.055 * Math.max(0, c) ** (1 / 2.4) - 0.055;
      return s * 255;
    }) as Rgb,
  );
}

export function toLabColor(hex: string): Lab {
  return toLab(hex);
}

function toLab(hex: string): Lab {
  const [r, g, b] = toRgb(hex).map((c) => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  const x = (r * 0.4124 + g * 0.3576 + b * 0.1805) / 0.95047;
  const y = r * 0.2126 + g * 0.7152 + b * 0.0722;
  const z = (r * 0.0193 + g * 0.1192 + b * 0.9505) / 1.08883;
  const f = (t: number) => (t > 0.008856 ? Math.cbrt(t) : 7.787 * t + 16 / 116);
  const [fx, fy, fz] = [f(x), f(y), f(z)];
  return [116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)];
}

/**
 * Perceptual distance between two colours (CIE76).
 *
 * Contrast ratio answers "can I read text on this", which is a different
 * question from "can I tell these two rows apart" - two fills can have near
 * identical luminance and be obviously different colours, or differ in
 * luminance and still read as the same wash. Row fills need the second
 * question, so they are measured in Lab.
 *
 * Rough scale: ~2.3 is the just-noticeable difference, ~10 is comfortably
 * distinct at a glance in a dense table.
 */
export function deltaE76(a: string, b: string): number {
  const [l1, a1, b1] = toLab(a);
  const [l2, a2, b2] = toLab(b);
  return Math.hypot(l1 - l2, a1 - a2, b1 - b2);
}

/**
 * A hue moved along L until it is readable on a given ground.
 *
 * Only the lightness axis moves; a and b are left alone, so the result still
 * reads as the same colour as whatever it describes. That is the whole point
 * wherever this is used - a packet accent has to look like the row it names, a
 * status colour has to look like the fill it belongs to.
 *
 * Direction is away from the ground: on a dark surface the colour lightens, on
 * a light one it deepens. Most hues need no adjustment at all; the ones that do
 * are palette entries chosen to sit ON their own theme's ground rather than
 * against it - Dracula's yellow on a dark card, Gruvbox's faded yellow on a
 * near-white one.
 */
export function legibleOn(hue: string, ground: string, minRatio = 4.5): string {
  if (contrastRatio(hue, ground) >= minRatio) return hue;

  const [L, a, b] = toLab(hue);
  const away = isDarkColor(ground) ? 1 : -1;
  for (let step = 3; step <= 100; step += 3) {
    const candidate = labToHex([Math.max(0, Math.min(100, L + away * step)), a, b]);
    if (contrastRatio(candidate, ground) >= minRatio) return candidate;
  }
  // Unreachable for any real palette, but a colour nobody can read is a worse
  // failure than one that is off-palette.
  return away < 0 ? '#000000' : '#ffffff';
}

/** How far a colour is from grey. 0 is neutral. */
export function chroma(hex: string): number {
  const [, a, b] = toLab(hex);
  return Math.hypot(a, b);
}
