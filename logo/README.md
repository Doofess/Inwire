# InWire — layered stack mark

Five isometric plates, gap 9, lightest on top. Nothing but blue: every layer is a lightness step off `--primary`, same hue, same saturation.

## Colours

| Layer | Hex | L |
|---|---|---|
| 1 (top) | `#6EB2F7` | 0.70 |
| 2 | `#3494F4` | 0.58 |
| 3 | `#0C75DF` | 0.46 |
| 4 | `#0957A4` | 0.34 |
| 5 (bottom) | `#06386A` | 0.22 |

Derived from `--primary` `#0B6BCB` (hue 210°, sat 0.90). To reshade, move L only.

## Background

There is none. The SVG contains five `<path>` elements and nothing else — no background rect, no padding shape, no plate. Every PNG is RGBA with the corners at alpha 0, and the gaps between the plates are transparent too, not filled. Verified: corner pixel `srgba(0,0,0,0)`, alpha range 0–1 across all sizes.

The mark sits in a 100×100 box spanning x 10–90, y 12–88, so it carries about 10% optical margin already. Don't add more.

## Files

These are the author's originals. **Nothing builds from them.**

| File | Use |
|---|---|
| `inwire-layers.svg` | The source drawing, and the thing `src/lib/brandMark.ts` was ported from. |
| `inwire-layers-256.png` | The README's mark. |
| `inwire-layers-512.png`, `inwire-layers-1024.png` | Raster copies for anywhere a vector will not do. |
| `inwire.ico`, `inwire.icns` | The hand-made icons, kept as a record. Neither is what ships. |

## What actually ships, and why it is not from here

The geometry lives **twice on purpose**: here as the drawing, and in
`src/lib/brandMark.ts` as the thing the app renders. Every shipped artefact is
generated from the TypeScript by `scripts/brand/render-icons.ts`, and
`scripts/brand/icon.ts` regenerates and compares on every `npm run check` — so
a plate that moves in one place fails the build rather than drifting.

| Generated file | Who reads it |
|---|---|
| `electron/resources/icon.ico` | `Inwire.exe`, named in `electron-builder.yml`, and `BrowserWindow` |
| `local-agent/icon.ico` | the agent executable and the Inno wizard's `SetupIconFile` |
| `public/icon.svg` | the renderer's favicon |

The two `.ico` files are asserted **byte-identical**. Dropping a hand-made
binary in beside that pipeline is exactly the drift the comparison exists to
catch, which is why `inwire.ico` here is a record and not an input.

## One caveat, and it has since been answered

At 16 px the five plates collapse into a blue lump — the gap is 9 in a 100 box,
so 1.4 px at 16, and five distinct bands can't survive that. 32 px holds fine.

`brandMark.ts` fixes it by taking **every other plate** below 32 px: three
plates, same span, same two ends of the ramp, twice the gap. Taking alternate
plates rather than redrawing is what keeps the two tiers one mark, and both
fill the identical box.
