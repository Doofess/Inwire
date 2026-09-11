/**
 * The filter result as a bitmap with rank/select.
 *
 *   npx tsx scripts/capture/match-set.ts
 *
 * `FilterEngine.filterPackets` returns `Packet[]`, which is right while the
 * whole capture is in RAM and structurally impossible once it is not: a filter
 * over 47M frames can match 47M frames, and even a list of ordinals would be
 * 188 MB for something as ordinary as `tcp`. A bitmap is one bit per frame
 * whatever matches.
 *
 * The load-bearing property is **rank/select**, because the packet list is
 * virtualised and asks for "filtered rows 12,000 to 12,050" - which means "the
 * 12,000th set bit". Getting that wrong does not throw; it draws the wrong
 * frame, with the right frame number beside it, and nobody notices.
 *
 * So the central check here is differential: `ordinalAt(k)` and `rank(n)` are
 * compared against a naive walk over the same bits, across densities from empty
 * to full and at every chunk boundary. A test that only checked a handful of
 * hand-picked positions would pass on an implementation that was off by one in
 * exactly the place a real capture lands.
 */
import { MatchSet, MATCH_SET_BITS_PER_CHUNK } from '../../src/services/capture/matchSet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkThrows(name: string, fn: () => unknown): void {
  let threw = false;
  try { fn(); } catch { threw = true; }
  check(name, threw, true);
}

const CHUNK = MATCH_SET_BITS_PER_CHUNK;

/** The answer, computed the slow obvious way, to compare the fast way against. */
function naive(matching: number[]): {
  ordinalAt: (k: number) => number; rank: (n: number) => number;
} {
  const sorted = matching.slice().sort((a, b) => a - b);
  return {
    ordinalAt: (k) => (k >= 0 && k < sorted.length ? sorted[k] : -1),
    rank: (n) => sorted.filter((o) => o < n).length,
  };
}

console.log('--- the basics ---\n');

{
  const set = new MatchSet(100);
  check('nothing matches to begin with', set.count(), 0);
  set.set(0); set.set(50); set.set(99);
  check('count before sealing still works', set.count(), 3);
  checkThrows('...but ordinalAt does not, because the prefix sums are not built',
    () => set.ordinalAt(0));
  set.seal();
  check('the three matches, in order',
    [set.ordinalAt(0), set.ordinalAt(1), set.ordinalAt(2)], [0, 50, 99]);
  check('one past the last match is not a row', set.ordinalAt(3), -1);
  check('a negative row is not a row', set.ordinalAt(-1), -1);
  check('has() agrees with what was set',
    [set.has(0), set.has(1), set.has(50), set.has(99)], [true, false, true, true]);
  check('has() outside the capture is false, not an error',
    [set.has(-1), set.has(100)], [false, false]);
  checkThrows('setting after sealing is refused', () => set.set(1));
  checkThrows('setting outside the capture is refused', () => new MatchSet(10).set(10));
}

{
  const empty = new MatchSet(0).seal();
  check('an empty capture has no matches and no rows',
    [empty.count(), empty.ordinalAt(0), empty.chunkCount], [0, -1, 0]);
  const none = new MatchSet(5000).seal();
  check('a filter that matches nothing', [none.count(), none.ordinalAt(0)], [0, -1]);
}

console.log('\n--- chunk boundaries, where an off-by-one hides ---\n');

{
  // Three chunks and a short fourth: the last frame of each chunk, the first of
  // the next, and the very last frame of a capture that does not fill a chunk.
  const frames = CHUNK * 3 + 7;
  const marks = [
    0, 1,
    CHUNK - 1, CHUNK, CHUNK + 1,
    CHUNK * 2 - 1, CHUNK * 2,
    CHUNK * 3 - 1, CHUNK * 3,
    frames - 1,
  ];
  const set = new MatchSet(frames);
  for (const m of marks) set.set(m);
  set.seal();
  check('every boundary frame is found at the right row',
    marks.map((_, k) => set.ordinalAt(k)), marks);
  check('the count is the number of marks', set.count(), marks.length);
  check('rank at each mark counts the ones before it',
    marks.map((m) => set.rank(m)), marks.map((_, i) => i));
  check('rank one past a mark counts it', set.rank(marks[3] + 1), 4);
  check('rank at zero is zero, and past the end is the total',
    [set.rank(0), set.rank(frames), set.rank(frames + 1000)],
    [0, marks.length, marks.length]);
}

{
  // A frame count that is not a whole number of words, so the tail-clearing
  // matters. A matcher handed a full word of padding could set bits past the
  // end of the capture; count() must not believe them.
  const frames = CHUNK * 2 + 13;
  const set = new MatchSet(frames);
  const bits = new Uint32Array(CHUNK / 32).fill(0xffffffff);
  set.setChunk(2, bits);
  set.seal();
  check('padding bits past the end of the capture do not count', set.count(), 13);
  check('...and the last real frame is the last row',
    set.ordinalAt(12), frames - 1);
  check('...with nothing after it', set.ordinalAt(13), -1);
}

console.log('\n--- against a naive walk, at every density ---\n');

for (const [label, density] of [
  ['every frame', 1], ['half', 0.5], ['one in a hundred', 0.01],
  ['one in ten thousand', 0.0001], ['none', 0],
] as [string, number][]) {
  const frames = CHUNK * 5 + 331;
  const set = new MatchSet(frames);
  const matching: number[] = [];
  // A fixed sequence rather than Math.random, so a failure is reproducible.
  let seed = 0x2f6e2b1;
  const next = () => {
    seed ^= seed << 13; seed >>>= 0;
    seed ^= seed >>> 17;
    seed ^= seed << 5; seed >>>= 0;
    return seed / 0x100000000;
  };
  for (let i = 0; i < frames; i++) {
    if (density === 1 || (density > 0 && next() < density)) { set.set(i); matching.push(i); }
  }
  set.seal();
  const slow = naive(matching);

  check(`${label}: the count agrees`, set.count(), matching.length);

  let ordinalMismatch = -1;
  for (let k = 0; k < matching.length; k++) {
    if (set.ordinalAt(k) !== slow.ordinalAt(k)) { ordinalMismatch = k; break; }
  }
  check(`${label}: every row resolves to the same frame as a naive walk`, ordinalMismatch, -1);

  let rankMismatch = -1;
  for (let n = 0; n <= frames; n += 7) {
    if (set.rank(n) !== slow.rank(n)) { rankMismatch = n; break; }
  }
  check(`${label}: rank agrees with a naive count`, rankMismatch, -1);

  // The round trip that the list actually does: take a row, get its frame, ask
  // which row that frame is. It must come back to where it started.
  let roundTripBad = -1;
  for (let k = 0; k < matching.length; k += Math.max(1, Math.floor(matching.length / 200))) {
    if (set.rank(set.ordinalAt(k)) !== k) { roundTripBad = k; break; }
  }
  check(`${label}: rank(ordinalAt(k)) === k`, roundTripBad, -1);
}

console.log('\n--- persisting a result ---\n');

{
  const frames = CHUNK * 2 + 100;
  const set = new MatchSet(frames);
  for (let i = 0; i < frames; i += 3) set.set(i);
  set.seal();

  const bytes = set.toBytes();
  const back = MatchSet.fromBytes(frames, bytes);
  check('a saved bitmap comes back with the same count', back.count(), set.count());
  let bad = -1;
  for (let k = 0; k < set.count(); k++) {
    if (back.ordinalAt(k) !== set.ordinalAt(k)) { bad = k; break; }
  }
  check('...and the same rows', bad, -1);
  // 47M frames is 5.9 MB whatever the filter matched, which is the whole point.
  check('the bitmap is one bit per frame, rounded to whole chunks',
    bytes.length, Math.ceil(frames / CHUNK) * (CHUNK / 8));
  checkThrows('a bitmap of the wrong size for the capture is refused',
    () => MatchSet.fromBytes(frames + CHUNK, bytes));
}

{
  const set = new MatchSet(CHUNK);
  checkThrows('a chunk of the wrong width is refused',
    () => set.setChunk(0, new Uint32Array(4)));
  checkThrows('a chunk index past the end is refused',
    () => set.setChunk(1, new Uint32Array(CHUNK / 32)));
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All match set checks passed.');
process.exit(0);
