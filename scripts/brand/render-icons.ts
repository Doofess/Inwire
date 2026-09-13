/**
 * Writes every icon the app ships, from the one geometry module.
 *
 *   npx tsx scripts/brand/render-icons.ts
 *
 * Not run by `npm run check` - it writes files. `scripts/brand/icon.ts` is the
 * assertion that the committed files still match what this would produce, so a
 * change to the mark that is not re-rendered fails the suite rather than
 * shipping a stale tab icon.
 *
 * Rasterising needs a renderer, and the repo has none - no `sharp`, no canvas
 * binding, and adding one for six PNGs is a native dependency in everybody's
 * install for a file that changes about once a year. So the PNGs come out of
 * headless Chrome, which is already a dev dependency of this workflow, and the
 * `.ico` is packed here: an ICO is a 6-byte header, a 16-byte directory entry
 * per image, and the PNG payloads verbatim - Vista and later accept PNG inside
 * ICO, and 16/32/48/256 is the set Windows actually asks for.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brandMarkSvg } from '../../src/lib/brandMark';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/**
 * The favicon's two colours.
 *
 * A tab sits on browser chrome the app does not control and cannot read, so the
 * SVG carries its own `prefers-color-scheme` rule. Near-black and near-white
 * rather than pure, so it does not vibrate against the chrome it sits on.
 */
export const FAVICON_LIGHT = '#0c0a09';
export const FAVICON_DARK = '#f6f7f9';

/**
 * The ground under the raster icons.
 *
 * They keep an opaque background because Windows and iOS composite them against
 * surfaces neither we nor they can predict, and a transparent mark on an
 * unknown ground is a mark nobody can see. This is NOT the app tile coming
 * back: the file is a plain square, no rounded corners and no gradient, and iOS
 * applies its own mask to it.
 */
export const RASTER_BG = '#0c0a09';
export const RASTER_FG = '#f6f7f9';

export const FAVICON_SVG = brandMarkSvg({
  color: FAVICON_LIGHT,
  darkColor: FAVICON_DARK,
});

/** The sizes each artefact needs, and what it is for. */
export const PNG_TARGETS = [
  { file: 'public/icon-192.png', size: 192 },
  { file: 'public/apple-touch-icon.png', size: 180 },
] as const;

/** What Windows asks for. 256 is the one Explorer uses at "extra large". */
export const ICO_SIZES = [16, 32, 48, 256] as const;

/** Packs already-encoded PNGs into a single .ico. */
export function packIco(images: { size: number; png: Buffer }[]): Buffer {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // 1 = icon
  header.writeUInt16LE(images.length, 4);

  const entries = Buffer.alloc(16 * images.length);
  let offset = header.length + entries.length;
  images.forEach((img, i) => {
    const at = i * 16;
    // 256 is stored as 0 - the field is one byte, so 256 does not fit.
    entries.writeUInt8(img.size >= 256 ? 0 : img.size, at);
    entries.writeUInt8(img.size >= 256 ? 0 : img.size, at + 1);
    entries.writeUInt8(0, at + 2); // palette size, 0 for truecolour
    entries.writeUInt8(0, at + 3); // reserved
    entries.writeUInt16LE(1, at + 4); // colour planes
    entries.writeUInt16LE(32, at + 6); // bits per pixel
    entries.writeUInt32LE(img.png.length, at + 8);
    entries.writeUInt32LE(offset, at + 12);
    offset += img.png.length;
  });

  return Buffer.concat([header, entries, ...images.map((i) => i.png)]);
}

/** A page that draws the mark to a canvas at each size and hands back base64. */
export function rasterPage(sizes: number[]): string {
  const svg = brandMarkSvg({ color: RASTER_FG, background: RASTER_BG, flat: true });
  return `<!doctype html><meta charset="utf-8"><body><script>
    window.__render = async () => {
      const svg = ${JSON.stringify(svg)};
      const url = 'data:image/svg+xml;base64,' + btoa(svg);
      const img = new Image();
      await new Promise((ok, no) => { img.onload = ok; img.onerror = no; img.src = url; });
      const out = {};
      for (const size of ${JSON.stringify(sizes)}) {
        const c = document.createElement('canvas');
        c.width = c.height = size;
        const g = c.getContext('2d');
        g.imageSmoothingEnabled = true;
        g.imageSmoothingQuality = 'high';
        g.drawImage(img, 0, 0, size, size);
        out[size] = c.toDataURL('image/png').split(',')[1];
      }
      return out;
    };
  </script></body>`;
}

/** Writes the SVG. The rasters are written by `write-rasters.ts`, which needs
 *  a browser and so cannot run from here. */
if (process.argv[1] && process.argv[1].endsWith('render-icons.ts')) {
  mkdirSync(join(root, 'public'), { recursive: true });
  writeFileSync(join(root, 'public', 'icon.svg'), FAVICON_SVG + '\n');
  console.log('wrote public/icon.svg');
  const sizes = [...new Set([...ICO_SIZES, ...PNG_TARGETS.map((t) => t.size)])].sort((a, b) => a - b);
  writeFileSync(join(root, 'scripts', 'brand', '.raster.html'), rasterPage(sizes));
  console.log('wrote scripts/brand/.raster.html (open it to rasterise)');
}
