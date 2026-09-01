/** `[longitude, latitude]`, the order GeoJSON and MapLibre both use. */
export type LngLat = [number, number];

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
export function splitAtAntimeridian(path: LngLat[]): LngLat[][] {
  if (path.length < 2) return [path];

  const segments: LngLat[][] = [];
  let current: LngLat[] = [path[0]];

  for (let i = 1; i < path.length; i++) {
    const [prevLng, prevLat] = path[i - 1];
    const [lng, lat] = path[i];
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
      const seamLat = prevLat + (lat - prevLat) * t;

      current.push([exitLng, seamLat]);
      segments.push(current);
      current = [[entryLng, seamLat], [lng, lat]];
      continue;
    }

    current.push([lng, lat]);
  }

  segments.push(current);
  return segments;
}
