/**
 * The minimap's colour index against the sums it replaces.
 *
 *   npx tsx scripts/session/minimap-bands.ts
 *
 * Every check is a range summed two ways - through `MinimapBands` and by
 * walking the frames - over a buffer that grows, is trimmed from the front
 * (far enough to make the index compact), is replaced, and meets a frame
 * nobody has coloured.
 */
import { MinimapBands, BLOCK, REBUILD_DECIDE, type ColourOf } from '../../src/lib/minimapBands';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

let nextId = 1;
const frame = (): Packet => ({ id: nextId++ } as unknown as Packet);
/** A colour per frame id, all four channels varying. */
const colourFor = (id: number) => (((id * 37) & 0xff) << 24 | ((id * 11) & 0xff) << 16 | ((id * 5) & 0xff) << 8 | (id & 0xff)) >>> 0;
const undecided = new Set<number>();
let decidedOnTheWay = 0;
const colourOf: ColourOf = (p, decide) => {
  if (undecided.has(p.id)) {
    if (!decide) return undefined;
    undecided.delete(p.id);
    decidedOnTheWay++;
  }
  return colourFor(p.id);
};
function brute(packets: Packet[], from: number, to: number): number[] {
  const s = [0, 0, 0, 0];
  for (let i = from; i < to; i++) {
    const c = colourFor(packets[i].id);
    s[0] += c >>> 24; s[1] += (c >>> 16) & 0xff; s[2] += (c >>> 8) & 0xff; s[3] += c & 0xff;
  }
  return s;
}
const into = new Float64Array(4);
/** Every range of a few shapes - inside a block, across one, across many, the whole. */
function agrees(bands: MinimapBands, packets: Packet[]): string | null {
  const n = packets.length;
  const ranges: [number, number][] = [[0, n], [0, 1], [n - 1, n], [3, 5], [BLOCK - 2, BLOCK + 3], [1, n - 1],
    [Math.floor(n / 3), Math.floor((2 * n) / 3)], [BLOCK, 3 * BLOCK], [7, 7]];
  for (const [a, b] of ranges) {
    if (a < 0 || b > n || a > b) continue;
    bands.sum(a, b, into);
    const want = brute(packets, a, b);
    if ([0, 1, 2, 3].some((c) => into[c] !== want[c])) return `[${a}, ${b}): got ${[...into]} want ${want}`;
  }
  return null;
}

const bands = new MinimapBands();
let buffer: Packet[] = [];
let ok = true;
let first: string | null = null;
// Growth past the first allocation, by flush-sized steps.
for (let step = 0; step < 40; step++) {
  buffer = buffer.concat(Array.from({ length: 97 }, frame));
  if (!bands.sync(buffer, colourOf)) { ok = false; first = `refused at step ${step}`; break; }
  const wrong = agrees(bands, buffer);
  if (wrong !== null) { ok = false; first = `step ${step}: ${wrong}`; break; }
}
check('growing flush by flush, every range sums as the frames do', ok, first ?? '');
check('...and it indexed every frame', bands.length === buffer.length, `${bands.length} vs ${buffer.length}`);

// Trims, heavy enough that the dropped prefix outgrows the kept part.
ok = true; first = null;
for (let step = 0; step < 30; step++) {
  buffer = buffer.slice(150).concat(Array.from({ length: 120 }, frame));
  if (!bands.sync(buffer, colourOf)) { ok = false; first = `refused at trim ${step}`; break; }
  const wrong = agrees(bands, buffer);
  if (wrong !== null) { ok = false; first = `trim ${step}: ${wrong}`; break; }
}
check('trimmed from the front and compacted, every range still sums right', ok, first ?? '');

// A frame appended undecided is decided as it is indexed: there are few.
const fresh = Array.from({ length: 5 }, frame);
for (const p of fresh) undecided.add(p.id);
buffer = buffer.concat(fresh);
check('an appended undecided frame is decided as it is indexed', bands.sync(buffer, colourOf) && decidedOnTheWay === 5);
check('...and sums right', agrees(bands, buffer) === null);

// A rebuild decides a few undecided frames itself - a live capture always
// brings some - and refuses past its budget, which is what a rule edit leaves.
const replaced = Array.from({ length: 300 }, frame);
undecided.add(replaced[150].id);
const before = decidedOnTheWay;
check('a rebuild decides a few undecided frames itself', bands.sync(replaced, colourOf) && decidedOnTheWay === before + 1);
check('...and sums right', agrees(bands, replaced) === null);
const edited = Array.from({ length: REBUILD_DECIDE + 10 }, frame);
for (const p of edited) undecided.add(p.id);
const beforeEdit = decidedOnTheWay;
check('a rebuild over more undecided frames than its budget refuses', bands.sync(edited, colourOf) === false);
check('...having decided no more than its budget', decidedOnTheWay - beforeEdit <= REBUILD_DECIDE);
for (const p of edited) undecided.delete(p.id);
check('once they are decided, the rebuild succeeds', bands.sync(replaced, colourOf) && agrees(bands, replaced) === null);

// Same ids, different head: not an extension.
const twin = replaced.map((p) => ({ ...p }));
check('a same-length replacement is rebuilt, not extended', bands.sync(twin, colourOf) && agrees(bands, twin) === null && bands.length === 300);

console.log(failures === 0 ? '\nAll minimap-bands checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
