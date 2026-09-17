/**
 * Assertion tests for the app's brand mark and the files generated from it.
 *
 *   npx tsx scripts/brand/icon.ts
 *
 * The mark is drawn once, in `src/lib/brandMark.ts`, and appears in six places:
 * `BrandMark.tsx` in the title row, the tab icon, two web PNGs, and the Windows
 * `.ico` **twice** - once for the agent executable and the Inno wizard, once for
 * the app executable. Only the first of those is live code; the rest are
 * committed artefacts produced by `scripts/brand/render-icons.ts`.
 *
 * (It said "the header component". There is no header - `Header.tsx` went with
 * the 64px accent bar - and the mark's home is the title row's top-left corner.
 * The check at the bottom of this file already reads `BrandMark.tsx` by path,
 * so only the sentence was behind.)
 *
 * So the failure this exists to catch is a specific and quiet one: **someone
 * edits the mark and does not re-render**, and the app then ships a header that
 * does not match its own icon. That is the same class of drift
 * `scripts/themes/packet-themes.ts` guards between `index.css` and
 * `themePalettes.ts`, and it is caught the same way - by regenerating and
 * comparing rather than by trusting.
 *
 * **Two rules from the previous mark are gone and both are worth naming.**
 *
 * The first was that the component paints only `currentColor`, which was how one
 * flat glyph served every theme. The mark is a shaded form now; inheriting one
 * colour would flatten it to a silhouette. What replaces that rule is narrower
 * and still worth having: the colours live in the geometry module and the
 * component holds none.
 *
 * The second was that the drawing is measured once. It is tiered now - three
 * densities for three size ranges - so coverage and bounds are checked **per
 * tier**. That is the entire point of tiering: the ceiling is what `full` has to
 * stay under and the floor is what `micro` has to clear, and a single
 * measurement would let one of them hide behind the other.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MARK_SIZE, MARK_TIERS, brandMarkPaths, markBounds, spiralRuns,
  type MarkTier,
} from '../../src/lib/brandMark';
import { FAVICON_SVG, ICO_SIZES, ICO_TARGETS, PNG_TARGETS } from './render-icons';

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

// --- The committed icon is the generated one --------------------------------

const svg = text('public/icon.svg');
check('public/icon.svg is exactly what the mark generates - re-run render-icons.ts',
  svg.trim(), FAVICON_SVG.trim());

// --- The properties that killed the icon before this one --------------------

check('no filter - a Gaussian blur smears into mush below about 32px',
  /<filter|feGaussianBlur/.test(svg), false);
// The shading is many flat fills along the band, which is why this still holds:
// a gradient element would be one more thing to survive a rasteriser, and the
// bounds and coverage below could not be read off the path data any more.
check('no gradient element - the shading is flat fills, one per segment',
  /Gradient/.test(svg), false);
check('no full-bleed rounded rect - that is the app-tile shape this replaced',
  /<rect[^>]*\brx=/.test(svg), false);
check('the viewBox is square, so no size can distort it',
  /viewBox="0 0 (\d+) (\d+)"/.exec(svg)?.slice(1, 3), [String(MARK_SIZE), String(MARK_SIZE)]);

// --- The mark itself, once per tier -----------------------------------------

const TIERS: MarkTier[] = ['full', 'compact', 'micro'];

/**
 * How much of its own bounding box the mark paints, flattened.
 *
 * Flattening is a GEOMETRIC operation here, not a colour one - the union of
 * every run, whatever each is filled with. That is what makes the measure
 * survive the mark going from one colour to two.
 */
function coverageOf(tier: MarkTier): number {
  const runs = spiralRuns(MARK_TIERS[tier]);
  const b = markBounds(tier);
  const inside = (pts: readonly (readonly [number, number])[], px: number, py: number) => {
    let hit = false;
    for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
      const [xi, yi] = pts[i];
      const [xj, yj] = pts[j];
      if ((yi > py) !== (yj > py) && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi) hit = !hit;
    }
    return hit;
  };
  const GRID = 120;
  let painted = 0;
  for (let iy = 0; iy < GRID; iy++) {
    for (let ix = 0; ix < GRID; ix++) {
      const x = b.minX + ((ix + 0.5) / GRID) * (b.maxX - b.minX);
      const y = b.minY + ((iy + 0.5) / GRID) * (b.maxY - b.minY);
      if (runs.some((r) => inside(r.pts, x, y))) painted++;
    }
  }
  return painted / (GRID * GRID);
}

for (const tier of TIERS) {
  const b = markBounds(tier);
  const cover = coverageOf(tier);
  // The ceiling catches the band being fattened or the turns closing until the
  // mark flattens into a disc; the floor catches the opposite failure, a mark
  // thinned until it disappears at 16px. Both are the kind of change that looks
  // fine at 256 and ruins the taskbar.
  check(`${tier}: flattened, between a third and a half of its box is painted`,
    [cover >= 0.3, cover <= 0.55], [true, true]);
  // Anything outside the box is clipped at some sizes and not others.
  check(`${tier}: the mark sits inside the viewBox`,
    [b.minX >= 0, b.minY >= 0, b.maxX <= MARK_SIZE, b.maxY <= MARK_SIZE],
    [true, true, true, true]);
  // ...and fills enough of it to not look lost. A mark floating in the middle of
  // its own box is the thing that makes an icon look small at every size.
  check(`${tier}: ...and fills at least 80% of it across and 70% down`,
    [(b.maxX - b.minX) / MARK_SIZE >= 0.8, (b.maxY - b.minY) / MARK_SIZE >= 0.7],
    [true, true]);
  // Every run is `M x y L x y ... Z`, absolute throughout, so the bounds above
  // are read off real coordinates rather than approximated from a curve.
  check(`${tier}: every run is a closed polygon of absolute coordinates`,
    brandMarkPaths(tier).every((p) => /^M[-\d. ]+(?:L[-\d. ]+)+Z$/.test(p.d)), true);
}

{
  // The tiers are three densities of ONE construction, not three drawings. The
  // turn count is what separates them, and it only ever goes down.
  const turns = TIERS.map((t) => MARK_TIERS[t].turns);
  check('the tiers shed turns as the box shrinks',
    turns.every((n, i) => i === 0 || n < turns[i - 1]), true);
  /**
   * Banding, measured as banding rather than guessed at as a segment count.
   *
   * The first version of this check counted tone steps per turn, and it was the
   * wrong quantity twice over: a turn near the pole is a fraction of the arc of
   * one at the equator, and a step is only visible if the drawing is big enough
   * to resolve it. What matters is the largest jump between adjacent tone
   * values, and it only matters at a size that can show it.
   *
   * So the limit is held against `full` alone - the only tier drawn above 64px.
   * `compact` tops out at 48 and `micro` at 16, where the whole band is a couple
   * of dozen pixels and a tone step cannot be resolved at all; holding them to a
   * gradient's smoothness would be buying paths nobody can see.
   */
  const tones = spiralRuns(MARK_TIERS.full).map((r) => r.tone).sort((a, b) => a - b);
  const widest = tones.reduce((m, t, i) => (i ? Math.max(m, t - tones[i - 1]) : m), 0);
  check('...and full leaves no visible band - the widest tone step is under 0.045',
    widest <= 0.045, true);
}

{
  const component = text('src/components/common/BrandMark.tsx');
  // This replaces "the component paints only currentColor". The mark carries
  // colour now; what must not happen is a SECOND place that decides what those
  // colours are.
  check('the component holds no colour of its own',
    /#[0-9a-fA-F]{3,8}\b/.test(component), false);
  check('...and renders every run the geometry gives it, rather than a fixed list',
    component.includes('brandMarkPaths('), true);
}

// --- The rasters ------------------------------------------------------------

const pngSize = (buf: Buffer) => [buf.readUInt32BE(16), buf.readUInt32BE(20)];

for (const { file, size } of PNG_TARGETS) {
  const buf = read(file);
  check(`${file} is a PNG at ${size}px`,
    [buf.subarray(1, 4).toString(), ...pngSize(buf)], ['PNG', size, size]);
}

for (const target of ICO_TARGETS) {
  const ico = read(target);
  check(`${target} is an icon container`, [ico.readUInt16LE(0), ico.readUInt16LE(2)], [0, 1]);
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
  check(`${target}: holds the sizes Windows actually asks for`, sizes, [...ICO_SIZES]);
  check(`${target}: ...each as a PNG payload`, payloadsArePng, true);
}

check('the two .ico files are the same bytes - they are one drawing',
  read(ICO_TARGETS[0]).equals(read(ICO_TARGETS[1])), true);

// --- It is actually referenced ----------------------------------------------

{
  const html = text('index.html');
  const missing = ['/icon.svg', '/icon-192.png', '/apple-touch-icon.png'].filter((f) => !html.includes(f));
  check('index.html still points at the icons this generates', missing, []);
}

{
  // The one that had nothing behind it at all. `win.icon` was absent and
  // `directories.buildResources` points at a folder that did not exist, so
  // `Inwire.exe` shipped with Electron's default icon - which no script could
  // see, because there was nothing to compare.
  const builder = text('electron-builder.yml');
  const named = /^\s*icon:\s*(\S+)\s*$/m.exec(builder)?.[1];
  check('electron-builder names an icon for the Windows executable',
    named, 'electron/resources/icon.ico');
  check('...and the file it names is one this script checked',
    ICO_TARGETS.includes(named as (typeof ICO_TARGETS)[number]), true);
  // The window's own icon, which is what `npm run start:app` and dev show -
  // the packaged exe takes its icon from the resource above instead.
  const main = text('electron/main.ts');
  check('the BrowserWindow is given an icon too', /icon:\s*/.test(main), true);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
