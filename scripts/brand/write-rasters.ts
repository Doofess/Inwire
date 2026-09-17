/**
 * Turns the browser's rasterisation into the committed PNG and ICO files.
 *
 *   npx tsx scripts/brand/write-rasters.ts <captured.json>
 *
 * The JSON is `{ "16": "<base64 png>", ... }`, produced by loading
 * `scripts/brand/.raster.html` in a browser and calling `window.__render()`.
 * Split from `render-icons.ts` only because that half needs a browser and this
 * half needs a filesystem.
 */
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ICO_SIZES, ICO_TARGETS, PNG_TARGETS, packIco } from './render-icons';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const raw = JSON.parse(readFileSync(process.argv[2], 'utf8')) as Record<string, unknown>;
// The MCP bridge wraps a returned value; accept either shape rather than
// depending on which.
const shots = (raw.result ?? raw.value ?? raw) as Record<string, string>;

const png = (size: number): Buffer => {
  const b64 = shots[String(size)];
  if (!b64) throw new Error(`no raster captured for ${size}px`);
  return Buffer.from(b64, 'base64');
};

for (const { file, size } of PNG_TARGETS) {
  const buf = png(size);
  writeFileSync(join(root, file), buf);
  console.log(`${file}  ${size}px  ${buf.length} bytes`);
}

// One buffer, written to every destination. `icon.ts` asserts they match, and
// this is the reason they can: they are never built twice.
const ico = packIco(ICO_SIZES.map((size) => ({ size, png: png(size) })));
for (const target of ICO_TARGETS) {
  mkdirSync(dirname(join(root, target)), { recursive: true });
  writeFileSync(join(root, target), ico);
  console.log(`${target}  ${ICO_SIZES.join('/')}  ${ico.length} bytes`);
}
