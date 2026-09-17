import { createPreferenceStore } from './preferenceStore';

/*
 * **`mapProjectionStore` was here and the flat map went with it.**
 *
 * It offered 'mercator' or 'globe', defaulted to globe, and put a switcher in
 * the map's zoom stack. The argument for keeping both was "flat remains one
 * click away for anyone who wants the whole world at once"; the globe gives
 * that at its own minimum zoom, so the click bought a projection that is worse
 * at the one thing this map does. A sphere has no edge for a route to be cut in
 * half by, and no Mercator distortion making a northern hop look like a
 * continental crossing.
 *
 * The cost of having had both is worth recording, because it was not the
 * switcher: `applyProjectionMode` in `GeoMap.tsx` spent half its body undoing
 * the other half - clearing `maxBounds` entering globe and restoring them
 * leaving it, swapping the zoom anchor between centre and pointer, and carrying
 * two minimum zooms.
 *
 * `inwire.mapProjection` is left in `localStorage` rather than cleared, which is
 * the ordinary answer rather than an exception to one: `RETIRED_PREFERENCE_KEYS`
 * in `preferences.ts` is a delete path and takes only the keys whose stored
 * VALUE would mislead. A projection for a projection switcher that no longer
 * exists is not one of those - nothing reads it, it costs a few bytes, and
 * every entry added to that list is another chance to delete the wrong one.
 *
 * **Mercator arithmetic is not gone and must not be deleted**: `arcLayer.ts` and
 * `pinLayer.ts` work in Web Mercator coordinates because that is the space
 * MapLibre's shaders use, and the globe crossfades into a flat projection at
 * high zoom on its own. Those are the library's internals.
 */

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
