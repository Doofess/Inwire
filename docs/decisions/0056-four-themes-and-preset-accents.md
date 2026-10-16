# 0056 — Four themes, Follow Windows with High Contrast, and preset accents

**Status:** accepted 2026-10-16. The themes, Follow Windows and the accent
swatches have landed.

## Context

The owner asked for themes that look like the desktop apps people already
spend their day in: **Codex desktop and VS Code**. Both offer more than a
light and a dark theme. VS Code also has a High Contrast theme that it picks
for itself when Windows asks for one. Inwire had two themes, Day and Night,
because four had already been cut to two once (`docs/history.md`, "Four
themes became two").

## Decision

### Four themes: Light, Dark, Dim and High Contrast

The ids are `light`, `dark`, `dim` and `contrast`. `light` and `dark` keep the
ids they had, so a stored choice survives. `RETIRED_THEMES` still maps
`midnight` and `paper` onto a real theme.

**Why four is not the cut being undone.** Paper and Graphite were cut because
each one was only the warm counterweight of a theme that stayed: a spare, not a
choice. These two are different:

- **Dim** is a grey, the Codex and GitHub "dimmed" ground (`#1c2026`). It sits
  beside a near-black Dark for people who find near-black too harsh over a long
  session, not as a warmer copy of Dark.
- **High Contrast** is an accessibility theme. Its text is at 7:1 or better,
  its borders at 3:1, and state shows as an outline as well as a tint. No
  other theme does that job.

`scripts/themes/registry.ts` holds every pair of themes at least 5 ΔE apart on
each surface, so neither new theme can drift into being a copy of another.

**Dark is near black, not pure black: `#101112`.** Pure black is High
Contrast's ground now. Dark at `#101112` sits 5.2 ΔE from it, and the ladder
above it keeps the steps Night had:

| token | value |
|---|---|
| card | `#141516` |
| secondary | `#1d1e1f` |
| accent | `#252628` |
| border | `#2e2f30` |

`--card` stays under about `#222` on every dark theme, or the colour-blind
packet set fails `packet-themes.ts`.

### Follow Windows includes High Contrast

System still follows Windows between Light and Dark. On top of that, when
`(prefers-contrast: more)` or `(forced-colors: active)` matches, it resolves to
`contrast` (`systemThemeFor` in `src/lib/themeOptions.ts`,
`src/hooks/useSystemTheme.ts`). `enableSystem` stays false: next-themes only
knows `light` and `dark`, and following stays our own store.

**And it is Inwire's High Contrast that shows, not Windows' colours.** A
Windows contrast theme also turns on forced colours, and Chromium then repaints
the page in the system's colours. The canvases, the map and the window ground
do not go through that, so under a light contrast theme such as Desert the page
went light over a black ground. `.contrast` sets `forced-color-adjust: none`,
the way VS Code draws its own High Contrast theme: the audited 7:1 palette is
the whole window. The cost is that someone on a light contrast theme gets a
black one. `scripts/themes/follow-windows.ts` holds the declaration, and
`docs/verification.md` has the hand check against each of Windows' four.

### Selection is mixed from the accent, at a share per theme

The selected row is `--primary` text on a `color-mix` of `--primary` into
`--background`. **The share is set per theme: Light 6%, Dark 22%, Dim 13% and
High Contrast 19%.** A single share for every theme failed contrast. The
plan's 14% for light and 22% for dark failed primary-on-selection in Light, Dim
and High Contrast. The registry checks primary on the mix for every theme. In
High Contrast the selected row and the rail's active cell are also outlined.

### Theme tiles draw the theme

Each tile in Settings → Appearance is a small picture of its theme: a title
row, a rail, a side strip, and three rows with the middle one selected. System
is Light and Dark cut on the diagonal.

**Giving a wrapper the theme's class is not enough, and finding that out is
why `.theme-scope` exists.** Tailwind's `@theme` declares every `--color-*`
on `:root`. There it resolves against the *document's* theme, and descendants
inherit the resolved value. So `bg-card` inside a `.dim` wrapper still painted
the document's card, and every tile looked like whatever theme was open.
`.theme-scope` in `src/index.css` points the `--color-*` that the miniature
uses back at the tokens, so that they resolve at the wrapper. The registry
fails if the miniature uses a colour utility that `.theme-scope` does not
re-point. The light block is selected by `.light` as well as `:root` for the
same reason: a Light tile inside a dark document needs a selector to match.

### Accents are presets, and the mark stays fixed

Seven swatches: Blue, Teal, Green, Violet, Rose, Amber and Graphite. **Presets,
not a free colour picker,** because an accent is the selected row's text, the
rail's active fill, the focus ring and the download trace, and a colour nobody
checked fails one of those in one theme without saying so. With seven, every
one is checked in every theme: `scripts/themes/registry.ts` loops swatches ×
themes for the foreground on the fill, primary on background, card, secondary
and the selected row (7:1 in High Contrast), the rail's active fill, distance
from `--destructive` and `--warning`, and download against upload.

The setting is `accentColor`, applied as `data-accent-color` on `<html>` at
module scope in `main.tsx`, so there is no default flash. It is not called
"accent" because shadcn's `--accent` already means the hover fill.

**An accent overrides four tokens and nothing else:** `--primary`,
`--primary-foreground`, `--ring` and `--speed-download`. The one exception is
Violet, which would be upload's own purple, so it moves `--speed-upload` to the
theme's orange.

**One table, one generated copy.** `src/lib/accents.ts` is the table. Blue is
the theme blocks' own values and gets no rule, so the stylesheet is right before
any module runs. The other six are printed by `scripts/themes/accent-css.ts` and
pasted between markers in `src/index.css`, and `scripts/themes/accents.ts` fails
if the two drift - the same arrangement as the status colours.

Two starting values were tuned against the checks rather than by eye. Light
Green went from `#15803d` to `#16763a` and light Amber from `#b45309` to
`#a54d07`: both failed primary on `--secondary` (4.43) or on the selected row
(4.34).

**The picker** is a row of round swatches under the theme tiles, a
`radiogroup` with a roving tab stop. The arrow keys move and apply, and the
focus outline sits outside the checked ring so the two never coincide. The theme
tiles draw the chosen accent by carrying `data-accent-color` themselves.

**The brand mark is not themed by the accent.** It is identity, and the same
ramp produces the icon, the PDF and the xlsx (`src/lib/brandMark.ts`).

## Consequences

- Four token blocks are kept in step by the registry: completeness, contrast,
  ΔE between pairs, the per-theme selection mix, and drift between the status
  tokens and the palettes.
- The tile grid is five across and has to be corrected by hand when
  `THEME_OPTIONS` changes. The comment beside it says so.
- `electron/windowColors.ts` has a ground for each of the four themes, so a
  window opens in its own theme with no flash.
