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
import { inflateSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MARK_ACCENT, MARK_SIZE, brandMarkPaths, markBounds, tierForSize,
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

/**
 * A hex fill as hue, saturation and lightness.
 *
 * Here rather than in `brandMark.ts` because it is the measuring instrument,
 * not the art: the module states the ramp by writing five hexes down, and this
 * is what holds those hexes to the rule the module claims for them. A converter
 * living beside the colours would let a wrong colour and a wrong check ship
 * together.
 */
function hsl(hex: string): { h: number; s: number; l: number } {
  const n = parseInt(hex.slice(1), 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => v / 255);
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  const d = max - min;
  if (d === 0) return { h: 0, s: 0, l };
  const s = d / (l > 0.5 ? 2 - max - min : max + min);
  const h = max === r ? ((g - b) / d + (g < b ? 6 : 0))
    : max === g ? (b - r) / d + 2
      : (r - g) / d + 4;
  return { h: h * 60, s, l };
}

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
  // fills exist to avoid, and a `url(#...)` would also not survive the
  // rasteriser's data: URL.
  check(`${tier}: every plate is one literal flat colour`,
    paths.every((p) => /^#[0-9a-fA-F]{6}$/.test(p.fill)), true);

  // The close button's red is the app's alarm colour and is the one hue the
  // mark may never borrow - an icon that shares a hue with "this went wrong"
  // spends it.
  check(`${tier}: the alarm red is not in the mark`,
    paths.some((p) => p.fill.toLowerCase() === '#c42b1c'), false);

  // **Every plate is `--primary` at a different lightness**, which is the rule
  // that makes a stack of flat shapes read as one object. Measured against
  // `MARK_ACCENT` rather than against a hue written down here, so the ramp has
  // one definition: move the accent and the mark has to follow it.
  const ref = hsl(MARK_ACCENT);
  const offRamp = paths
    .map((p) => ({ fill: p.fill, ...hsl(p.fill) }))
    .filter((c) => Math.abs(c.h - ref.h) > 1 || Math.abs(c.s - ref.s) > 0.02)
    .map((c) => c.fill);
  check(`${tier}: every plate shares --primary's hue and saturation`, offRamp, []);

  // Painter's order IS the depth here: the plates overlap, and the light has to
  // come from above. Reversing this does not throw and does not clip - it
  // renders a stack lit from underneath, which reads as wrong without saying
  // why.
  const lightness = paths.map((p) => hsl(p.fill).l);
  check(`${tier}: ...and they are painted back to front, darkest first`,
    lightness.every((l, i2) => i2 === 0 || l > lightness[i2 - 1]), true);

  // The plates are evenly spaced. An uneven stack is the one defect that looks
  // like a rendering artefact rather than like a mistake in the source.
  const tops = paths.map((p) => Number(/^M50 (\d+)/.exec(p.d)?.[1]));
  const gaps = tops.slice(1).map((t, i2) => tops[i2] - t);
  check(`${tier}: the gap between plates is uniform`, new Set(gaps).size, 1);
}

{
  // **The tiers are two densities of one object, and the small one sheds.**
  // That is the invariant tiering exists for: the small mark takes every OTHER
  // plate, because below 32px the 9-unit gap is under two device pixels and
  // five plates merge into a single blue lump - which says something untrue
  // about the object rather than merely losing detail.
  const [primary, small] = TIERS.map((t) => brandMarkPaths(t).length);
  check('five plates, and three in the small tier', [primary, small], [5, 3]);

  // **Same span, and the ends of the ramp are the same two colours.** This is
  // what makes the small tier a CUT of the large one rather than a second
  // drawing that happens to look similar - and it is the thing that silently
  // stops being true if somebody edits one tier's list by hand.
  const ends = (t: MarkTier) => {
    const paths = brandMarkPaths(t);
    return [paths[0].fill, paths[paths.length - 1].fill];
  };
  check('the small tier keeps both ends of the ramp', ends('small'), ends('primary'));
  const span = (t: MarkTier) => {
    const b = markBounds(t);
    return [b.minX, b.minY, b.maxX, b.maxY];
  };
  check('...and fills exactly the same box', span('small'), span('primary'));

  // The boundary itself, which is the number every raster target is picked by.
  // 32 is where five plates stop resolving; one off it in either direction is a
  // size rendered with the wrong drawing. 16 is the title row's mark and the
  // favicon, 32 is the taskbar, 256 is Explorer at "extra large".
  check('32 is the edge between the two drawings',
    [tierForSize(31), tierForSize(32), tierForSize(16), tierForSize(256)],
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

/** IHDR's colour type byte. 6 is truecolour WITH alpha. */
const pngColourType = (buf: Buffer) => buf.readUInt8(25);

/**
 * The alpha of the top-left pixel, decoded.
 *
 * Only pixel (0,0) is read, and that is what makes this ten lines instead of a
 * PNG decoder: on the FIRST pixel of the FIRST row every one of the five filter
 * types reduces to the identity. Sub has no left neighbour, Up and Paeth have
 * no row above, and Average has neither - so the filtered byte IS the sample,
 * whichever filter the encoder picked. Anywhere else in the image this would be
 * wrong.
 */
function cornerAlpha(buf: Buffer): number {
  const idat: Buffer[] = [];
  let at = 8;
  while (at < buf.length) {
    const len = buf.readUInt32BE(at);
    const kind = buf.subarray(at + 4, at + 8).toString('ascii');
    if (kind === 'IDAT') idat.push(buf.subarray(at + 8, at + 8 + len));
    at += 12 + len;
  }
  // [filter type][R][G][B][A] ...
  return inflateSync(Buffer.concat(idat)).readUInt8(4);
}

for (const { file, size } of PNG_TARGETS) {
  const buf = read(file);
  check(`${file} is a PNG at ${size}px`,
    [buf.subarray(1, 4).toString(), ...pngSize(buf)], ['PNG', size, size]);
  check(`${file}: ...with an alpha channel, and nothing behind the mark`,
    [pngColourType(buf), cornerAlpha(buf)], [6, 0]);
}

for (const target of ICO_TARGETS) {
  const ico = read(target);
  check(`${target} is an icon container`, [ico.readUInt16LE(0), ico.readUInt16LE(2)], [0, 1]);
  const count = ico.readUInt16LE(4);
  const sizes: number[] = [];
  let payloadsArePng = true;
  const payloads: Buffer[] = [];
  for (let i = 0; i < count; i++) {
    const at = 6 + i * 16;
    sizes.push(ico.readUInt8(at) || 256);
    const offset = ico.readUInt32LE(at + 12);
    if (ico.subarray(offset + 1, offset + 4).toString() !== 'PNG') payloadsArePng = false;
    payloads.push(ico.subarray(offset, offset + ico.readUInt32LE(at + 8)));
  }
  // Windows picks the nearest entry and rescales if it has to; shipping the
  // exact sizes it asks for is the difference between a crisp tray icon and a
  // resampled one.
  check(`${target}: holds the sizes Windows actually asks for`, sizes, [...ICO_SIZES]);
  check(`${target}: ...each as a PNG payload`, payloadsArePng, true);

  // **No square behind the icon**, which is the thing Windows shows off most:
  // the taskbar, Alt-Tab and Explorer all composite this against grounds that
  // change with the theme and the wallpaper, and an opaque tile is visible as a
  // tile in every one of them. The mark is transparent in its corners AND in
  // the gaps between its plates. The previous mark painted `#0c0a09` behind
  // itself; this asserts that decision cannot come back unnoticed.
  check(`${target}: ...and every entry is transparent behind the mark`,
    payloads.map(cornerAlpha), payloads.map(() => 0));
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
