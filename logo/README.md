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

| File | Use |
|---|---|
| `inwire-layers.svg` | Source. Scales to anything. |
| `inwire.ico` | Windows / Electron, 16–256. |
| `inwire.icns` | macOS / Electron, 32–1024. |
| `png/` | 16, 20, 24, 32, 48, 64, 128, 256, 512, 1024 — all transparent. |

## Electron

```json
"build": {
  "win":   { "icon": "build/inwire.ico" },
  "mac":   { "icon": "build/inwire.icns" },
  "linux": { "icon": "build/png/inwire-layers-512.png" }
}
```

## One caveat

At 16 px the five plates collapse into a blue lump — five distinct bands can't survive in 16 rows of pixels. 32 px holds fine. If the tray icon bothers you, a three-layer cut of the same mark for 16/20 px fixes it.
