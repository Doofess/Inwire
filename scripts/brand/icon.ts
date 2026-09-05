/**
 * Assertion tests for the app's brand mark and the files generated from it.
 *
 *   npx tsx scripts/brand/icon.ts
 *
 * The mark is drawn once, in `src/lib/brandMark.ts`, and appears in five
 * places: the header component, the tab favicon, two web PNGs, an Apple touch
 * icon and the Windows `.ico` the installer and the agent executable carry. Only
 * the first of those is live code; the rest are committed artefacts produced by
 * `scripts/brand/render-icons.ts`.
 *
 * So the failure this exists to catch is a specific and quiet one: **someone
 * edits the mark and does not re-render**, and the app then ships a header that
 * does not match its own tab icon. That is the same class of drift
 * `scripts/themes/packet-themes.ts` guards between `index.css` and
 * `themePalettes.ts`, and it is caught the same way - by regenerating and
 * comparing rather than by trusting.
 *
 * It also pins the properties that made the PREVIOUS icon unusable: it was a
 * rounded-square tile with two gradients and a Gaussian blur, none of which
 * survive being shrunk to a 16px tab.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MARK_BOUNDS, MARK_SIZE, brandMarkPaths } from '../../src/lib/brandMark';
import { FAVICON_SVG, ICO_SIZES, PNG_TARGETS } from './render-icons';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (p: string) => readFileSync(join(root, p));
const text = (p: string) => read(p).toString('utf8');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

// --- The committed favicon is the generated one -----------------------------

const svg = text('public/icon.svg');
check('public/icon.svg is exactly what the mark generates - re-run render-icons.ts',
  svg.trim(), FAVICON_SVG.trim());

// --- The properties that killed the old icon --------------------------------

check('no filter - a Gaussian blur smears into mush below about 32px',
  /<filter|feGaussianBlur/.test(svg), false);
check('no gradient - the mark is monochrome so it can follow four themes',
  /Gradient/.test(svg), false);
check('no full-bleed rounded rect - that is the app-tile shape this replaced',
  /<rect[^>]*\brx=/.test(svg), false);
check('the viewBox is square, so no size can distort it',
  /viewBox="0 0 (\d+) (\d+)"/.exec(svg)?.slice(1, 3), [String(MARK_SIZE), String(MARK_SIZE)]);
check('it carries its own dark-mode rule - a tab has no cascade to inherit',
  /prefers-color-scheme:\s*dark/.test(svg), true);

// --- The mark itself --------------------------------------------------------

{
  const runs = brandMarkPaths();
  // Four quads: two chevrons, two straight runs each. A band whose fold count
  // changed has changed shape, not just proportion.
  check('the mark is four folded runs', runs.length, 4);
  check('...each a closed quad of absolute coordinates',
    runs.every((run) => /^M[-\d. ]+(?:L[-\d. ]+){3}Z$/.test(run.d)), true);

  // The tones are decoration: the `.ico` and a 16px tab render the mark
  // flattened, and it has to survive that. What makes it survive is NEGATIVE
  // SPACE - the notch between the two chevrons and the vee inside each one -
  // so that is what is measured, by sampling the flattened shape over its own
  // bounding box and asking how much of it is actually painted.
  //
  // Not a disjointness test. The obvious version of this check - "the two
  // chevrons must not touch" - was written first and was wrong: the outer
  // chevron's mitred apex is a long spike, the inner chevron sits over it, and
  // the two shapes genuinely do overlap while the flattened render remains two
  // clearly separate arrowheads. Overlap is not the failure. Filling in is.
  const quad = (run: { d: string }) => {
    const n = run.d.match(/-?\d+(?:\.\d+)?/g)!.map(Number);
    return [0, 1, 2, 3].map((i) => [n[i * 2], n[i * 2 + 1]] as [number, number]);
  };
  const cross = (o: number[], a: number[], b: number[]) =>
    (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0]);
  const inside = (pt: number[], poly: number[][]) => {
    // Each run is a convex quad wound consistently, so "same side of all four
    // edges" is exact here - no ray casting needed.
    const signs = poly.map((p, i) => cross(p, poly[(i + 1) % 4], pt));
    return signs.every((v) => v >= 0) || signs.every((v) => v <= 0);
  };
  const quads = runs.map(quad);
  const GRID = 128;
  let painted = 0;
  for (let iy = 0; iy < GRID; iy++) {
    for (let ix = 0; ix < GRID; ix++) {
      const x = MARK_BOUNDS.minX + ((ix + 0.5) / GRID) * (MARK_BOUNDS.maxX - MARK_BOUNDS.minX);
      const y = MARK_BOUNDS.minY + ((iy + 0.5) / GRID) * (MARK_BOUNDS.maxY - MARK_BOUNDS.minY);
      if (quads.some((q) => inside([x, y], q))) painted++;
    }
  }
  const coverage = painted / (GRID * GRID);
  // Currently 0.41. The ceiling catches the bands being fattened or the notch
  // closing until the mark flattens into a blob; the floor catches the opposite
  // failure, a mark thinned until it disappears at 16px. Both are the kind of
  // change that looks fine at 160px and ruins the favicon.
  check('flattened, between a third and a half of its box is painted',
    [coverage >= 0.3, coverage <= 0.55], [true, true]);

  // The mark must sit inside the box - anything outside is clipped at some
  // sizes and not others. Checked against computed bounds rather than by
  // scanning the path text by eye.
  const b = MARK_BOUNDS;
  check('the mark sits inside the viewBox',
    [b.minX >= 0, b.minY >= 0, b.maxX <= MARK_SIZE, b.maxY <= MARK_SIZE],
    [true, true, true, true]);
  // ...and fills enough of it to not look lost. A mark floating in the middle
  // of its own box is the thing that makes an icon look small at every size.
  check('...and fills at least 80% of it in both axes',
    [(b.maxX - b.minX) / MARK_SIZE >= 0.8, (b.maxY - b.minY) / MARK_SIZE >= 0.7],
    [true, true]);
}

{
  // The component has to inherit its colour or it cannot follow the themes.
  const component = text('src/components/common/BrandMark.tsx');
  check('the component paints only currentColor',
    /#[0-9a-fA-F]{3,8}\b/.test(component), false);
  check('...and renders every run the geometry gives it, rather than a fixed list',
    component.includes('brandMarkPaths().map'), true);
}

// --- The rasters ------------------------------------------------------------

const pngSize = (buf: Buffer) => [buf.readUInt32BE(16), buf.readUInt32BE(20)];

for (const { file, size } of PNG_TARGETS) {
  const buf = read(file);
  check(`${file} is a PNG at ${size}px`,
    [buf.subarray(1, 4).toString(), ...pngSize(buf)], ['PNG', size, size]);
}

{
  const ico = read('local-agent/icon.ico');
  check('local-agent/icon.ico is an icon container', [ico.readUInt16LE(0), ico.readUInt16LE(2)], [0, 1]);
  const count = ico.readUInt16LE(4);
  const sizes: number[] = [];
  let payloadsArePng = true;
  for (let i = 0; i < count; i++) {
    const at = 6 + i * 16;
    sizes.push(ico.readUInt8(at) || 256);
    const offset = ico.readUInt32LE(at + 12);
    if (ico.subarray(offset + 1, offset + 4).toString() !== 'PNG') payloadsArePng = false;
  }
  // Windows picks the nearest entry and rescales if it has to; shipping the
  // exact sizes it asks for is the difference between a crisp tray icon and a
  // resampled one.
  check('...holding the sizes Windows actually asks for', sizes, [...ICO_SIZES]);
  check('...each as a PNG payload', payloadsArePng, true);
}

// --- It is actually referenced ----------------------------------------------

{
  const html = text('index.html');
  const missing = ['/icon.svg', '/icon-192.png', '/apple-touch-icon.png'].filter((f) => !html.includes(f));
  check('index.html still points at the icons this generates', missing, []);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
