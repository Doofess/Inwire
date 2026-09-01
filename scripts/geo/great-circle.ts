/**
 * Assertion tests for the great-circle path builder.
 *
 *   npx tsx scripts/geo/great-circle.ts
 *
 * The map draws connections as straight two-point lines today, which is wrong
 * twice over: on a Mercator projection the shortest path between two places is
 * a curve, not a chord, and a two-point line across the Pacific is drawn the
 * long way round the whole map.
 *
 * The dateline case is the one worth testing hardest. The map is created with
 * `renderWorldCopies: false` and maxBounds of ±179.9 - both load-bearing, since
 * a full 360° span crashes maplibre-gl outright - so a path whose longitudes
 * run 170 → -170 is not drawn as a short hop across the Pacific but as a stripe
 * back across Asia, Europe and the Atlantic.
 */
import { greatCirclePath, splitAtAntimeridian } from '../../src/lib/greatCircle';

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
function checkTrue(name: string, condition: boolean) {
  check(name, condition, true);
}
function near(a: number, b: number, tol: number) {
  return Math.abs(a - b) <= tol;
}

const TLV: [number, number] = [34.7818, 32.0853];   // Tel Aviv
const NYC: [number, number] = [-74.006, 40.7128];   // New York
const TYO: [number, number] = [139.6917, 35.6895];  // Tokyo
const SFO: [number, number] = [-122.4194, 37.7749]; // San Francisco

// --- Endpoints and shape -----------------------------------------------------

const path = greatCirclePath(TLV, NYC, 48);
check('the path has the requested number of points', path.length, 48);
checkTrue('it starts at the origin', near(path[0][0], TLV[0], 1e-6) && near(path[0][1], TLV[1], 1e-6));
checkTrue('it ends at the destination',
  near(path[path.length - 1][0], NYC[0], 1e-6) && near(path[path.length - 1][1], NYC[1], 1e-6));

// A great circle between two northern-hemisphere cities bows POLEWARD - that
// is the whole visual point, and a straight interpolation would not.
const straightMidLat = (TLV[1] + NYC[1]) / 2;
const actualMid = path[Math.floor(path.length / 2)];
checkTrue(
  `the midpoint bows north of the straight line (${actualMid[1].toFixed(1)} > ${straightMidLat.toFixed(1)})`,
  actualMid[1] > straightMidLat + 1,
);

// Every point must be a real coordinate; NaN here renders nothing at all and
// fails silently, which is the worst way for this to break.
const bad = path.filter(([lng, lat]) =>
  !Number.isFinite(lng) || !Number.isFinite(lat) || Math.abs(lat) > 90 || Math.abs(lng) > 180);
check('every point is a valid coordinate', bad, []);

// --- Degenerate input --------------------------------------------------------

const samePoint = greatCirclePath(TLV, TLV, 16);
check('identical endpoints still yield a path', samePoint.length, 16);
check('every point of a zero-length path is the point itself',
  samePoint.filter(([lng, lat]) => !near(lng, TLV[0], 1e-6) || !near(lat, TLV[1], 1e-6)), []);

checkTrue('a two-step path is just the endpoints', greatCirclePath(TLV, NYC, 2).length === 2);

// --- The antimeridian --------------------------------------------------------

const pacific = greatCirclePath(TYO, SFO, 48);
const pacificParts = splitAtAntimeridian(pacific);
check('a Pacific crossing splits into two segments', pacificParts.length, 2);
checkTrue('both segments carry points',
  pacificParts.every((seg) => seg.length >= 2));
check('no segment spans more than 180 degrees of longitude',
  pacificParts
    .map((seg) => Math.max(...seg.map((p) => p[0])) - Math.min(...seg.map((p) => p[0])))
    .filter((span) => span > 180),
  []);

// Splitting must not invent or lose points beyond the two inserted at the seam.
const totalPoints = pacificParts.reduce((n, seg) => n + seg.length, 0);
checkTrue(`the split adds exactly the two seam points (${totalPoints} vs ${pacific.length})`,
  totalPoints === pacific.length + 2);

const atlantic = greatCirclePath(TLV, NYC, 48);
check('a path that does not cross the dateline stays whole',
  splitAtAntimeridian(atlantic).length, 1);
check('an unsplit path is returned unchanged',
  splitAtAntimeridian(atlantic)[0].length, atlantic.length);

// --- Curvature ----------------------------------------------------------------

/**
 * The map draws a flattened arc rather than the true great circle, because a
 * dozen full arcs out of one city overlap into a fan that reads as the
 * projection rather than as the traffic. The blend has to stay honest at both
 * ends and monotone in between.
 */
{
  // How far a path bows away from the straight line between its endpoints,
  // measured at the midpoint - which is where a great circle deviates most.
  const bow = (curvature: number) => {
    const path = greatCirclePath(TLV, NYC, 49, curvature);
    const mid = path[(path.length - 1) / 2];
    const chordLat = (TLV[1] + NYC[1]) / 2;
    const chordLng = (TLV[0] + NYC[0]) / 2;
    return Math.hypot(mid[0] - chordLng, mid[1] - chordLat);
  };

  const full = bow(1);
  const half = bow(0.5);
  const none = bow(0);

  checkTrue(`a full great circle bows away from the chord (${full.toFixed(2)} deg)`, full > 1);
  checkTrue(`curvature 0 draws the straight line (${none.toFixed(4)} deg)`, none < 1e-9);
  checkTrue(`curvature 0.5 halves the bow (${half.toFixed(2)} vs ${full.toFixed(2)})`,
    Math.abs(half - full / 2) < 1e-6);

  // Monotone: every step toward 0 must flatten the arc, never bulge it.
  const bows = [0, 0.25, 0.5, 0.75, 1].map(bow);
  check('flattening is monotone', bows.filter((v, i) => i > 0 && v <= bows[i - 1]), []);

  // Endpoints stay exact whatever the blend - a route that misses its own
  // marker is visible at zoom, and this is the step most likely to break it.
  const drifted = [0, 0.3, 0.5, 1].filter((c) => {
    const path = greatCirclePath(TLV, NYC, 48, c);
    return path[0][0] !== TLV[0] || path[0][1] !== TLV[1]
      || path[path.length - 1][0] !== NYC[0] || path[path.length - 1][1] !== NYC[1];
  });
  check('endpoints stay exact at every curvature', drifted, []);
}

// A flattened path crossing the dateline is the case the unwrapping exists for:
// blending a longitude of 179 with one of -179 in the naive way lands the point
// in the middle of Africa, and the resulting path is a stripe across the map.
{
  const flattened = greatCirclePath(TYO, SFO, 48, 0.5);
  check('a flattened path still only crosses the dateline once',
    flattened.filter((p, i) => i > 0 && Math.abs(p[0] - flattened[i - 1][0]) > 180).length, 1);

  const parts = splitAtAntimeridian(flattened);
  check('and still splits into exactly two segments', parts.length, 2);
  check('with no segment spanning more than half the globe',
    parts
      .map((seg) => Math.max(...seg.map((p) => p[0])) - Math.min(...seg.map((p) => p[0])))
      .filter((span) => span > 180),
    []);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
