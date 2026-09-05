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
  'inwire.mapProjection',
  (raw) => (raw === 'globe' || raw === 'mercator' ? raw : null),
  'globe',
);

/**
 * Which of the two basemap skins the geo map paints itself in.
 *
 *   'colorful' - the fixed storybook globe: sage land, slate sea, a lit slab.
 *   'muted'    - the app's own tokens: land is `--background`, sea a neutral
 *                step off it, the coastline the accent.
 *
 * The muted skin came first and was replaced rather than kept, on the argument
 * recorded in `mapTheme.ts`: land against sea is a categorical distinction, not
 * a surface hierarchy, and building it out of a chrome ramp costs a contrast
 * search to keep the two halves of the world apart. That argument is about
 * which should be the DEFAULT, and it still wins. It was never an argument that
 * nobody should be able to choose the other - a dashboard whose map is the same
 * greys as the panel around it is a legitimate thing to want, and it is the
 * only skin that changes with the theme.
 *
 * So: colourful by default, muted one click away.
 */
export type MapSkin = 'colorful' | 'muted';

export const mapSkinStore = createPreferenceStore<MapSkin>(
  'inwire.mapSkin',
  (raw) => (raw === 'colorful' || raw === 'muted' ? raw : null),
  'colorful',
);

/**
 * Whether a connection arc takes the colour of its dominant protocol.
 *
 * On, each arc is painted by `protocolColor` - so a QUIC route on the map is
 * the same hue as the QUIC slice in the protocol donut, which is the whole
 * point of `themePalettes`' nine shared hues.
 *
 * Off, every arc is the theme's `--primary`. That is not a lesser option: nine
 * hues over a map answer "what protocol is this route", and a single accent
 * answers "where is my traffic going" without spending any attention on the
 * first question. On a busy capture the second is often the question being
 * asked, and colour that encodes something you are not reading is noise.
 *
 * Only the arcs. Markers are already the accent, and the donut and the timeline
 * keep their own colouring - this is not a global "colour by protocol" switch.
 */
export const arcProtocolColorStore = createPreferenceStore<boolean>(
  'inwire.mapArcProtocolColors',
  (raw) => (typeof raw === 'boolean' ? raw : null),
  true,
);
