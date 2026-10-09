/** `[longitude, latitude]`, the order GeoJSON and MapLibre both use. */
export type LngLat = [number, number];

/**
 * `[longitude, latitude, altitude]`, altitude as a fraction of the globe's
 * radius.
 *
 * A fraction rather than metres because that is the unit the globe shader
 * works in - a point at altitude h sits at `normalize(surface) * (1 + h)` -
 * and because the number then means the same thing regardless of projection.
 * The Mercator path scales it into world units at draw time.
 */
export type LngLatAlt = [number, number, number];

/**
 * The earth's mean radius, in metres (IUGG R1).
 *
 * One number, three former homes: `arcLayer` called it `GLOBE_RADIUS_METRES`,
 * `pinLayer` called it `EARTH_RADIUS_M`, and the globe vertex shader had it
 * typed out a third time as a GLSL literal. The shader interpolates this now,
 * so an edit here cannot leave the geometry and the shader disagreeing about
 * how big the world is.
 *
 * It is the scale MapLibre's globe projection works in: the unit sphere is one
 * earth radius, so an altitude in metres becomes a fraction by dividing by it.
 */
export const EARTH_RADIUS_METRES = 6371008.8;

const RAD = Math.PI / 180;
const DEG = 180 / Math.PI;

/**
 * The shortest path between two points on the globe, as a polyline.
 *
 * The map drew connections as two-point `LineString`s, which is wrong on a
 * Mercator projection in the ordinary case and badly wrong in the long one: the
 * shortest route from Tel Aviv to New York passes well north of the straight
 * line between them, and drawing the chord instead makes every intercontinental
 * connection look like it went the wrong way. Sampling the great circle is what
 * turns a connection into something that reads as a flight path.
 *
 * Spherical linear interpolation on the unit vectors rather than interpolating
 * latitude and longitude directly - the naive version is what produces the
 * chord this exists to replace, and it degenerates completely near the poles.
 *
 * `curvature` blends between the two: 1 draws the true great circle, 0 draws
 * the straight line, and anything between flattens the arc without losing the
 * sense of one. A full great circle is geographically correct and, on a busy
 * map, too much of a good thing - a dozen routes out of one city fan into wide
 * overlapping loops that say more about Mercator than about the traffic.
 * Endpoints are exact at every value, so a flattened arc still meets its own
 * markers.
 */
export function greatCirclePath(
  from: LngLat,
  to: LngLat,
  steps = 48,
  curvature = 1,
): LngLat[] {
  const count = Math.max(2, Math.floor(steps));
  const blend = Math.max(0, Math.min(1, curvature));

  const [lng1, lat1] = [from[0] * RAD, from[1] * RAD];
  const [lng2, lat2] = [to[0] * RAD, to[1] * RAD];

  const v1 = [
    Math.cos(lat1) * Math.cos(lng1),
    Math.cos(lat1) * Math.sin(lng1),
    Math.sin(lat1),
  ];
  const v2 = [
    Math.cos(lat2) * Math.cos(lng2),
    Math.cos(lat2) * Math.sin(lng2),
    Math.sin(lat2),
  ];

  const dot = Math.min(1, Math.max(-1, v1[0] * v2[0] + v1[1] * v2[1] + v1[2] * v2[2]));
  const omega = Math.acos(dot);
  const sinOmega = Math.sin(omega);

  const points: LngLat[] = [];
  for (let i = 0; i < count; i++) {
    const t = i / (count - 1);

    // Coincident or near-coincident endpoints: the interpolation is 0/0, and
    // there is no arc to draw anyway. Common in practice, since two hosts in
    // one datacentre resolve to the same coordinates.
    if (sinOmega < 1e-9) {
      points.push([from[0], from[1]]);
      continue;
    }

    const a = Math.sin((1 - t) * omega) / sinOmega;
    const b = Math.sin(t * omega) / sinOmega;
    const x = a * v1[0] + b * v2[0];
    const y = a * v1[1] + b * v2[1];
    const z = a * v1[2] + b * v2[2];

    points.push([
      Math.atan2(y, x) * DEG,
      Math.atan2(z, Math.hypot(x, y)) * DEG,
    ]);
  }

  if (blend < 1) flattenTowardChord(points, from, to, blend);

  // Exact endpoints. Floating point leaves them a fraction off otherwise, and a
  // connection that does not quite touch its own marker is visible at zoom.
  points[0] = [from[0], from[1]];
  points[points.length - 1] = [to[0], to[1]];
  return points;
}

/**
 * Pulls each point of a great circle toward the straight line between the
 * endpoints, in place.
 *
 * Done on UNWRAPPED longitudes, which is the whole difficulty. A path crossing
 * the antimeridian has longitudes that jump 179 -> -179, and blending a value
 * on one side of the seam with one on the other lands halfway around the world.
 * So the arc's longitudes are first made continuous by carrying the +/-360
 * forward, the chord is expressed in the same continuous space using the
 * shortest signed difference between the endpoints, the two are mixed, and the
 * result is wrapped back into [-180, 180] for `splitAtAntimeridian` to cut.
 */
function flattenTowardChord(points: LngLat[], from: LngLat, to: LngLat, blend: number): void {
  const last = points.length - 1;
  if (last < 1) return;

  // Shortest signed longitude difference, so the chord takes the same way round
  // the globe the arc does.
  const delta = ((to[0] - from[0] + 540) % 360) - 180;

  let unwrapped = points[0][0];
  let previous = points[0][0];

  for (let i = 0; i <= last; i++) {
    const t = i / last;

    if (i > 0) {
      let step = points[i][0] - previous;
      if (step > 180) step -= 360;
      else if (step < -180) step += 360;
      unwrapped += step;
      previous = points[i][0];
    }

    const chordLng = from[0] + delta * t;
    const chordLat = from[1] + (to[1] - from[1]) * t;

    const lng = unwrapped * blend + chordLng * (1 - blend);
    const lat = points[i][1] * blend + chordLat * (1 - blend);

    points[i] = [((lng + 180) % 360 + 360) % 360 - 180, lat];
  }
}

/**
 * The highest an arc rises, as a fraction of the globe's radius.
 *
 * 0.18 is about 1,150 km at Earth scale, which is meaningless as geography and
 * exactly right as drawing: high enough that a route reads as leaving the
 * surface and arcing over it, low enough that a dozen of them do not turn into
 * a tangle floating clear of the planet they belong to.
 */
const ARC_MAX_ALTITUDE = 0.18;

/**
 * The shortest an arc rises, for two points barely apart.
 *
 * Without a floor, a route between two hosts in the same city is drawn flat on
 * the surface while its neighbours arc overhead, and it stops looking like the
 * same kind of object. A small constant lift keeps every route a route.
 */
const ARC_MIN_ALTITUDE = 0.012;

/**
 * The tallest an arc may be for its length: a quarter of the ground it spans.
 *
 * `ARC_MIN_ALTITUDE` is 76 km at Earth scale, and on its own it made every short
 * hop a loop - two places 50 km apart got an arc half again taller than it was
 * long, a narrow hoop standing on the map, which reads as wrong the moment you
 * zoom in (the owner's report). The cap is a shape, not a distance: an arc is
 * never more than this fraction as tall as it is long, so a short route is a
 * low curve of the same proportions as a long one, still lifted off the
 * surface. It binds below roughly 1,200 km; past that the linear rise above is
 * already flatter than this.
 */
const ARC_MAX_ASPECT = 0.25;

/**
 * A great circle with an altitude profile: an arc, not a path painted on.
 *
 * Altitude is `sin(pi * t)`, which is 0 at both endpoints and peaks at the
 * midpoint. Endpoints touching down exactly is what lets the arc meet its own
 * markers; a profile that merely got close would leave every route floating
 * above the pin it belongs to.
 *
 * The peak scales with the angular separation of the endpoints, so a
 * Tel Aviv - New York route rises visibly higher than a local hop. That is not
 * decoration: with a fixed peak, distance is carried only by the length of the
 * line, which foreshortens to nothing when the route points away from the
 * camera. Height survives rotation.
 */
export function greatCircleArc(
  from: LngLat,
  to: LngLat,
  steps = 48,
  curvature = 1,
): LngLatAlt[] {
  const path = greatCirclePath(from, to, steps, curvature);

  // Angular separation, normalised to 0..1 over a half turn - antipodal points
  // are pi apart, and nothing on a sphere is further.
  const [lng1, lat1] = [from[0] * RAD, from[1] * RAD];
  const [lng2, lat2] = [to[0] * RAD, to[1] * RAD];
  const dot =
    Math.cos(lat1) * Math.cos(lng1) * Math.cos(lat2) * Math.cos(lng2) +
    Math.cos(lat1) * Math.sin(lng1) * Math.cos(lat2) * Math.sin(lng2) +
    Math.sin(lat1) * Math.sin(lat2);
  const omega = Math.acos(Math.min(1, Math.max(-1, dot)));
  // `omega` is also the route's length in globe radii, the unit the altitude
  // is in, which is what lets the aspect cap compare the two directly.
  const peak = Math.min(
    ARC_MIN_ALTITUDE + (ARC_MAX_ALTITUDE - ARC_MIN_ALTITUDE) * (omega / Math.PI),
    ARC_MAX_ASPECT * omega,
  );

  const last = path.length - 1;
  const arc = path.map((point, i) => {
    const t = last === 0 ? 0 : i / last;
    return [point[0], point[1], peak * Math.sin(Math.PI * t)] as LngLatAlt;
  });

  // Endpoints pinned to the surface exactly, for the same reason
  // greatCirclePath pins their longitude and latitude: sin(PI) is 1.2e-16
  // rather than 0, and "touches down at both ends" should be a guarantee the
  // caller can rely on rather than a value that is merely very small.
  if (arc.length > 0) {
    arc[0][2] = 0;
    arc[arc.length - 1][2] = 0;
  }
  return arc;
}

/**
 * Cuts a path where it crosses the antimeridian.
 *
 * Necessary because of two deliberate choices in the map's construction: it
 * disables `renderWorldCopies` and clamps `maxBounds` to ±179.9, the latter
 * because a full 360° span crashes maplibre-gl 6.5.0 outright inside
 * `Transform._calcMatrices`. With no world copies to wrap into, a path whose
 * longitude jumps 179 → -179 is not drawn as the one-degree hop it really is;
 * it is drawn as a stripe all the way back across the map.
 *
 * The seam points are interpolated rather than snapped, so both halves still
 * meet the edge at the right latitude.
 */
export function splitAtAntimeridian<T extends LngLat | LngLatAlt>(path: T[]): T[][] {
  if (path.length < 2) return [path];

  const segments: T[][] = [];
  let current: T[] = [path[0]];

  for (let i = 1; i < path.length; i++) {
    const previous = path[i - 1];
    const point = path[i];
    const [prevLng] = previous;
    const [lng] = point;
    const delta = lng - prevLng;

    if (Math.abs(delta) > 180) {
      // Which edge this half runs into: eastbound over +180, westbound over -180.
      const goingEast = delta < 0;
      const exitLng = goingEast ? 180 : -180;
      const entryLng = -exitLng;

      // Fraction of the step at which the seam is reached, measured on the
      // unwrapped longitude so the latitude lands correctly.
      const unwrapped = goingEast ? lng + 360 : lng - 360;
      const t = (exitLng - prevLng) / (unwrapped - prevLng);

      // Every component after longitude is interpolated the same way, which is
      // what lets an arc keep its altitude across the cut. Interpolating lat
      // and leaving alt to be re-derived per segment would put a step in the
      // profile exactly at the seam - the one place a route is already two
      // separate pieces of geometry and can least afford to look like it.
      const seam = (lngAt: number): T => {
        const out = [lngAt] as unknown as number[];
        for (let c = 1; c < previous.length; c++) {
          out[c] = previous[c] + (point[c] - previous[c]) * t;
        }
        return out as T;
      };

      current.push(seam(exitLng));
      segments.push(current);
      current = [seam(entryLng), point];
      continue;
    }

    current.push(point);
  }

  segments.push(current);
  return segments;
}
