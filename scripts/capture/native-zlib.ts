/**
 * The store compresses with node's zlib and the rest of the app reads with
 * `fflate` - and every capture written before the switch was compressed by
 * `fflate`. Both are raw DEFLATE, so either reads the other; this holds that,
 * on a chunk the real codec produced, at both levels in use.
 *
 *   npx tsx scripts/capture/native-zlib.ts
 */
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { deflateSync, inflateSync } from 'fflate';

let failures = 0;
function check(name: string, ok: boolean): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
}
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

// Shaped like a summary chunk: repeated strings and small numbers, which is
// what the store deflates, plus a stretch of noise.
const text = new TextEncoder().encode(Array.from({ length: 4096 }, (_, i) =>
  `TLSv1.3|Application Data|10.0.0.${i % 7}|52.92.${i % 13}.250|${51900 + (i % 9)}|443|${i * 1460}`).join('\n'));
const noise = Uint8Array.from({ length: 65536 }, (_, i) => (i * 2654435761) >>> 24);
for (const [label, data] of [['a summary-shaped chunk', text], ['noise', noise]] as const) {
  const native = new Uint8Array(deflateRawSync(data, { level: 1 }));
  check(`${label}: the store's deflate reads back with fflate`, same(inflateSync(native), data));
  const old = deflateSync(data, { level: 6 });
  check(`${label}: a capture written by fflate reads back with the store's inflate`, same(new Uint8Array(inflateRawSync(old)), data));
}

console.log(failures === 0 ? '\nAll native-zlib checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
