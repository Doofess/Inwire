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
 * **Two rules from the mark before last survive, and one measurement did not.**
 *
 * The component paints no colour of its own. That began as "only
 * `currentColor`", which was how one flat glyph served every theme; the mark has
 * been a shaded form through two redraws now, and inheriting a single colour
 * would flatten either of them to a silhouette. What the rule became is
 * narrower and still worth having: the colours live in the geometry module, and
 * the component holds none.
 *
 * The drawing is measured **per tier** rather than once, which is the entire
 * point of tiering - a single measurement lets one tier hide behind the other.
 *
 * What went is the coverage test. It flattened every run of the old spiral into
 * a union of polygons and counted painted cells on a 120x120 grid, which worked
 * because that mark was **generated**: every run came back as an array of
 * points. This one is drawn art with curves and arcs in it, so there are no
 * polygons to flatten and a point-in-path test would mean writing a renderer.
 * What replaces it measures the thing that actually goes wrong with a drawn
 * mark - the tiers drifting apart, or a face picking up a colour from outside
 * the ramp - and the bounds checks, which never needed the polygons, are kept
 * verbatim.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MARK_SIZE, brandMarkPaths, markBounds, tierForSize,
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

const TIERS: MarkTier[] = ['primary', 'small'];

for (const tier of TIERS) {
  const b = markBounds(tier);
  const paths = brandMarkPaths(tier);

  // Anything outside the box is clipped at some sizes and not others.
  check(`${tier}: the mark sits inside the viewBox`,
    [b.minX >= 0, b.minY >= 0, b.maxX <= MARK_SIZE, b.maxY <= MARK_SIZE],
    [true, true, true, true]);

  // ...and fills enough of it to not look lost. A mark floating in the middle
  // of its own box is the thing that makes an icon look small at every size.
  check(`${tier}: ...and fills at least 75% of it across and 70% down`,
    [(b.maxX - b.minX) / MARK_SIZE >= 0.75, (b.maxY - b.minY) / MARK_SIZE >= 0.7],
    [true, true]);

  // `markBounds` reads coordinate pairs straight out of the path data, which is
  // only sound while every command is ABSOLUTE. One relative command - a lower
  // case `l`, `h`, `c` - and the numbers after it are offsets being measured as
  // positions, which does not throw and does not look wrong until some size
  // clips.
  check(`${tier}: every command is absolute`,
    paths.every((p) => !/[a-z]/.test(p.d.replace(/[^A-Za-z]/g, ''))), true);

  // A fill that is not a literal hex is a fill that came from somewhere else -
  // a gradient, a pattern, `currentColor`. All three are the thing the flat
  // facet shading exists to avoid, and a `url(#…)` would also not survive the
  // rasteriser's data: URL.
  check(`${tier}: every face is one literal flat colour`,
    paths.every((p) => /^#[0-9a-fA-F]{6}$/.test(p.fill)), true);

  // The close button's red is the app's alarm colour and is the one hue the
  // mark may never borrow - an icon that shares a hue with "this went wrong"
  // spends it.
  check(`${tier}: the alarm red is not in the mark`,
    paths.some((p) => p.fill.toLowerCase() === '#c42b1c'), false);
}

{
  // **The tiers are two densities of one object, and the small one sheds.**
  // That is the invariant tiering exists for: the small mark drops the cavity's
  // four bevelled walls and half the contacts, because below 48px those are
  // sub-pixel and eight contacts merge into a single blue bar - which says
  // something untrue about the object rather than merely losing detail.
  const [primary, small] = TIERS.map((t) => brandMarkPaths(t).length);
  check('the small tier is the simpler drawing', small < primary, true);

  /**
   * The contact count, read as the most repeated fill rather than by counting
   * rectangles.
   *
   * The contacts are the only row of identical faces in either drawing, so the
   * fill that repeats most IS that row - which means this counts the thing that
   * matters without the script needing to know which hex the contacts are, and
   * so without a second copy of the ramp living here.
   */
  const contactCount = (tier: MarkTier) => {
    const byFill = new Map<string, number>();
    for (const p of brandMarkPaths(tier)) byFill.set(p.fill, (byFill.get(p.fill) ?? 0) + 1);
    return Math.max(...byFill.values());
  };
  check('the primary mark has all eight contacts', contactCount('primary'), 8);
  check('...and the small one has four', contactCount('small'), 4);

  // The boundary itself, which is the number every raster target is picked by.
  // 48 is where eight contacts stop resolving; one off it in either direction
  // is a size rendered with the wrong drawing.
  check('48 is the edge between the two drawings',
    [tierForSize(47), tierForSize(48), tierForSize(16), tierForSize(256)],
    ['small', 'primary', 'small', 'primary']);
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
