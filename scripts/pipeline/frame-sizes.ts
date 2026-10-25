/**
 * `FrameSizes` against the true offsets (#17): frames passed out of order by
 * two adapters' skew, with gaps that never fill, and the place a read of the
 * file learns at each gap. Every point it gives must be exactly where that
 * frame is; a point is allowed to be early (the end of a placed run), never
 * wrong.
 */
import { FrameSizes, RUNS_MAX } from '../../src/services/pipeline/frameSizes';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n        ${detail}`}`);
  if (!ok) failures++;
}

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Trial {
  firstSeq: number;
  frames: number;
  gaps: number;
  skew: boolean;
  firstMissing: boolean;
}

function trial(seed: number, t: Trial): string | null {
  const random = rng(seed);
  const lens: number[] = [];
  for (let i = 0; i < t.frames; i++) lens.push(32 + 4 * Math.floor(random() * 380));
  const offset: number[] = [0];
  for (let i = 0; i < t.frames; i++) offset.push(offset[i] + lens[i]);
  // Frames that never pass: a few short gaps, and maybe the file's first.
  const missing = new Set<number>();
  for (let g = 0; g < t.gaps; g++) {
    const at = 1 + Math.floor(random() * (t.frames - 20));
    const width = 1 + Math.floor(random() * 6);
    for (let k = 0; k < width; k++) missing.add(at + k);
  }
  if (t.firstMissing) missing.add(0);
  const order: number[] = [];
  for (let i = 0; i < t.frames; i++) if (!missing.has(i)) order.push(i);
  if (t.skew) {
    for (let k = 0; k < t.frames / 8; k++) {
      const i = Math.floor(random() * (order.length - 3));
      const j = i + 1 + Math.floor(random() * 3);
      [order[i], order[j]] = [order[j], order[i]];
    }
  }
  const sizes = new FrameSizes(1, t.firstSeq);
  const seqOf = (i: number) => t.firstSeq + i;
  const checkPoint = (anchor: number, when: string): string | null => {
    const point = sizes.point(seqOf(anchor));
    if (point === null) return null;
    const i = point.seq - t.firstSeq;
    if (i < 0 || i > anchor || point.rel !== offset[i]) {
      return `${when}: point ${JSON.stringify(point)} for anchor ${anchor}, frame ${i} is at ${offset[i]}`;
    }
    return null;
  };
  for (let k = 0; k < order.length; k++) {
    sizes.add(seqOf(order[k]), lens[order[k]]);
    if (k % 50 === 25) {
      // Reads of the file place runs while frames still pass, so a late
      // frame can join a run that is placed already, from in front.
      const top = seqOf(Math.max(...order.slice(0, k + 1)));
      for (let s = sizes.unplacedFrom(t.firstSeq, top); s !== null; s = sizes.unplacedFrom(s + 1, top)) {
        sizes.learn(s, offset[s - t.firstSeq]);
      }
    }
    if (k % 97 === 0) {
      const wrong = checkPoint(Math.max(...order.slice(0, k + 1)), `after ${k + 1} passed`);
      if (wrong) return wrong;
    }
  }
  const anchor = Math.max(...order);
  const wrong = checkPoint(anchor, 'all passed');
  if (wrong) return wrong;
  // A read counting from where the sizes say, learning each gap's end, gets
  // to the anchor's own place.
  let at = sizes.point(seqOf(anchor))?.seq ?? t.firstSeq;
  for (let guard = 0; guard < 1000; guard++) {
    const point = sizes.point(seqOf(anchor));
    if (point !== null && point.seq === seqOf(anchor)) {
      return point.rel === offset[anchor] ? null : `anchor placed at ${point.rel}, is at ${offset[anchor]}`;
    }
    const gapEnd = sizes.unplacedFrom(at, seqOf(anchor));
    if (gapEnd === null) return `no point for the anchor and no gap to cross from ${at}`;
    sizes.learn(gapEnd, offset[gapEnd - t.firstSeq]);
    const wrongAfter = checkPoint(anchor, `after learning ${gapEnd}`);
    if (wrongAfter) return wrongAfter;
    at = gapEnd;
  }
  return 'did not reach the anchor';
}

{
  let first: string | null = null;
  let runs = 0;
  for (let seed = 1; seed <= 300 && first === null; seed++) {
    for (const t of [
      { firstSeq: 0, frames: 2000, gaps: 0, skew: true, firstMissing: false },
      { firstSeq: 51_000, frames: 2000, gaps: 6, skew: false, firstMissing: false },
      { firstSeq: 51_000, frames: 2000, gaps: 6, skew: true, firstMissing: false },
      { firstSeq: 7, frames: 3000, gaps: 12, skew: true, firstMissing: true },
    ]) {
      runs++;
      const wrong = trial(seed, t);
      if (wrong !== null) { first = `seed ${seed} ${JSON.stringify(t)}: ${wrong}`; break; }
    }
  }
  check(`every point is exactly where its frame is, through skew and gaps, learned across to the anchor (${runs} trials)`,
    first === null, first ?? '');
}

{
  // In order with no gap: the anchor's own place, at once.
  const sizes = new FrameSizes(1, 100);
  for (let s = 100; s < 110; s++) sizes.add(s, 64);
  const p = sizes.point(109);
  check('in order: the anchor itself', p !== null && p.seq === 109 && p.rel === 9 * 64, JSON.stringify(p));
}

{
  // A run after a gap, never learned: the point is the gap's start, and the
  // gap is where a read learns.
  const sizes = new FrameSizes(1, 0);
  for (let s = 0; s < 10; s++) sizes.add(s, 40);
  for (let s = 15; s < 30; s++) sizes.add(s, 40);
  const p = sizes.point(29);
  check('after a gap: the end of the placed run, and the gap to cross', p !== null && p.seq === 10 && p.rel === 400
    && sizes.unplacedFrom(10, 29) === 15, `${JSON.stringify(p)} ${sizes.unplacedFrom(10, 29)}`);
}

{
  // The first frame of the file never passed: nothing is placed until a read
  // from the start learns where the first run begins.
  const sizes = new FrameSizes(1, 0);
  for (let s = 3; s < 10; s++) sizes.add(s, 40);
  check('the file\'s first frames missing: no point, the gap from the start', sizes.point(9) === null
    && sizes.unplacedFrom(0, 9) === 3);
}

{
  // More gaps than runs are kept: the oldest go, points stay exact. Every
  // frame is in the file, 36 bytes each, so frame s is at s * 36.
  const sizes = new FrameSizes(1, 0);
  for (let s = 0; s < (RUNS_MAX + 10) * 3; s++) if (s % 3 !== 2) sizes.add(s, 36);
  const last = (RUNS_MAX + 10) * 3 - 2;
  const p = sizes.point(last);
  check('runs past the bound: the point is still a frame\'s true place', p !== null && p.rel === p.seq * 36,
    JSON.stringify(p));
}

if (failures > 0) {
  console.log(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('\nAll frame-size checks passed.');
