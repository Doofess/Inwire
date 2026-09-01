import { createPreferenceStore } from './preferenceStore';

/**
 * How the geo map projects the world.
 *
 *   'mercator' - the flat plane, now free to rotate and tilt.
 *   'globe'    - the sphere.
 *
 * A preference rather than session state, which is the distinction from
 * `geoSession`'s camera: where the map was last POINTING is about one sitting
 * and should not follow you into next week, but which projection you think in
 * is a standing choice.
 *
 * Defaults to globe. It is the more legible of the two for what this map
 * actually shows - traffic leaving one place for others around the world -
 * because a sphere has no edge for a route to be cut in half by, and no
 * Mercator distortion making a northern hop look like a continental crossing.
 * Flat remains one click away for anyone who wants the whole world at once.
 */
export type MapProjectionMode = 'mercator' | 'globe';

export const mapProjectionStore = createPreferenceStore<MapProjectionMode>(
  'netview.mapProjection',
  (raw) => (raw === 'globe' || raw === 'mercator' ? raw : null),
  'globe',
);
