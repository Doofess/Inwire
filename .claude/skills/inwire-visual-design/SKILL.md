---
name: inwire-visual-design
description: Inwire's typography, theming and brand-mark rules - the system faces and why there is no webfont and no typeface picker, the two themes and the token contract, and the five-plate brand mark every icon is generated from. Use when changing fonts, colours, theme tokens, the CSS in src/index.css, or anything under logo/ and electron/resources/.
---

# Visual design: typography, theming, the brand mark

Moved out of the root `CLAUDE.md` so it loads when you are doing visual work
rather than in every session. Run `npm run check` after any colour edit —
`scripts/themes/` enforces token completeness, contrast and CSS-vs-palette drift,
and `scripts/accessibility/fonts.ts` and `scripts/brand/icon.ts` hold the rest.
## Typography

**The faces the host OS ships** — on Windows, Segoe UI Variable on `--font-sans`
and Cascadia Mono on `--font-mono`, declared once in `src/index.css` and nowhere
else, with **no webfont imported at all**. The system face is hand-hinted for
the 12px most of the UI is set in, and it is the face every other window on the
desktop wears. The stacks lead with the named Windows faces and fall through to
`system-ui` and `ui-monospace` — SF Pro and Menlo on a Mac, fontconfig's answer
on Linux — which is the same decision in that OS's own words; the port's
typography task is to look at what those resolve to, not to pick faces.

**Cascadia Mono, not Cascadia Code** — Code ligates `->` and `==`, and an Info
column is a place where the bytes must be drawn as written. Windows ships no
Cascadia Mono Italic, so the mono italic in the protocol tree is a sheared
roman; accepted. **There is no typeface picker**, because a setting that moved
the sans and not the mono put the seam back for exactly the readers who reached
for it; `docs/history.md` records what that cost.

Three facts were **measured against Chromium's DirectWrite path** rather than
assumed, and `index.css` records them on the tokens:

- **`"Segoe UI Variable"` does not resolve.** DirectWrite exposes three
  optical-size families with five named weights each and no axis, so **Small**
  leads, being the cut for 12px and under.
- **Weight 500 snaps up to Semibold** in both faces, so `--font-weight-medium`
  is 400 **under `html[data-platform="win32"]`** — never in `@theme`, because SF
  Pro has a real Medium and a Mac should get it. `font-medium` therefore means
  Regular on Windows, which is Fluent's own ramp; `main.tsx` stamps the
  attribute from the bridge before the first render.
- **The figures are proportional** until `tnum` asks otherwise, which `body`
  does.

`scripts/accessibility/fonts.ts` holds the rest: no `@fontsource` package
installed or imported and no `@font-face`, the tokens leading with the named
faces and ending in a generic, the medium remap present under the platform
attribute and absent from `@theme`, the stamp in `main.tsx`, `tnum` on `body`,
no `font-family` outside `index.css` that is not a token, and nothing writing
either token at runtime. The one mix that survives is the map's place names,
baked into openfreemap's glyph atlases where no CSS reaches; `.maplibregl-map`
in `index.css` says so.

### Theming

**Two themes** declared in `src/lib/themeOptions.ts` — Day and Night — each with
a complete token block in `src/index.css` and a palette entry in
`src/services/themePalettes.ts`, plus System, which is a rule for choosing
between them rather than a third palette.

**Night holds the `dark` id**, and that matters mechanically: next-themes writes
`color-scheme` only for the literal strings `light` and `dark`, so while the
neutral dark theme was stored under another id the native scrollbars and form
controls stayed on the light side of the divide for the theme most people use.
`RETIRED_THEMES` lands every stored `midnight` and `paper` on a real one.

Run `npm run check` after any colour edit — `scripts/themes/` enforces token
completeness, contrast and CSS-vs-palette drift.

### The brand mark

**Outside the theme system.** It is a stack of five isometric plates —
`src/lib/brandMark.ts`, ported from `logo/inwire-layers.svg` — and it carries
its own colours rather than taking `currentColor`, because a stack given one
colour is a silhouette of a hexagon. The rule is narrow and worth keeping: the
colours live with the geometry, `BrandMark.tsx` holds none, and **one ramp
serves both themes** so there is no per-theme mark to keep in step.

**One source, every icon generated from it.** The art is ported into
`brandMark.ts` rather than committed as the artist's `.ico`, because a binary
dropped in beside the pipeline is exactly the drift the regenerate-and-compare
check exists to catch. `logo/` holds the author's originals and nothing builds
from them. `electron/resources/icon.ico` is named explicitly in
`electron-builder.yml` and written from the same buffer as
`local-agent/icon.ico`; `BrowserWindow` takes the same file.

`scripts/brand/icon.ts` measures the rest rather than trusting it:

- **Every plate is `--primary` at a different lightness** — `#0b6bcb`, hue 210,
  saturation 0.90, L at 0.22 / 0.34 / 0.46 / 0.58 / 0.70 — which is what makes
  five flat shapes read as one object rather than five coloured tiles. The check
  converts every fill and holds hue and saturation to `MARK_ACCENT`'s own, so
  moving the accent moves the rule. The order is load-bearing too: darkest
  first, because the plates overlap and painter's order IS the depth. `#c42b1c`
  is deliberately absent — it is the close button's red and stays the alarm.
- **The mark is tiered and the boundary is measured.** `primary` is five plates
  at **32px and up**; `small` is **every other plate** — three — below 32, which
  is what the title row's 16px mark gets. 32 is where five plates stop
  resolving: the gap is 9 in a 100 box, so 2.9px at 32 and 1.4px at 16, and at
  1.4px the stack is one blue lump. Taking every other plate rather than
  redrawing keeps the two tiers one mark — same span, same ends of the ramp,
  twice the gap — and both fill the identical box.
- **Flat fills, no gradient**, because every artefact is rasterised from this
  one source down to 16px, where a gradient is mush.
- **No background behind the icon, anywhere.** Every PNG is RGBA with alpha 0 in
  the corners and in the gaps between plates, and the `.ico` payloads are those
  PNGs verbatim. The check decodes the top-left pixel of every committed raster
  and asserts alpha 0 — ten lines rather than a PNG decoder, because on the
  first pixel of the first row every PNG filter type reduces to the identity.
- **The two `.ico` files are byte-identical.**

