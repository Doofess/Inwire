# 0057 — One command registry: the palette, the analyst keys and every keyed tooltip read it

**Status:** accepted 2026-10-16. The registry, the palette, the analyst
shortcuts, the filter field's recents and match chip, settings search and the
motion tokens have landed (`d678e86..595772b`).

## Context

The hamburger menu was deleted because every entry in it duplicated a visible
control (`d3b4326`), and the window has kept that discipline since. What it left
is a set of keys with no home. `Ctrl+1..5` lived in `useKeyboardNavigation`
beside `Ctrl+B`, a tooltip spelled its own `(Ctrl+B)` next to the hook that
bound the key, and a key that was rebound would go on being advertised under its
old name. There was no way to run a command by name, and no key for the three
things an analyst does most: aim at the display filter, jump to a frame and
start or stop a capture without reaching for the mouse.

The owner asked for a command palette, and for the keys and tooltips to stop
being three copies of one fact.

## Decision

### A data-only registry, bound by id

`src/lib/commands.ts` is a list of `CommandSpec`: `id`, `title`, `group`, an
optional `keys` chord, `keywords` the palette matches on and a pure `when`
predicate over a plain `CommandContext`. **It has no `run`.** The actions are
`App`'s own handlers, bound by id in `App.tsx`, because a callback in `App.tsx`
is unreachable from any script (CLAUDE.md §6) and everything worth asserting -
which keys exist, which commands are offered when, how a title reads - is
therefore in the module a plain `tsx` script can import.

The five views are generated from `APP_VIEWS`, whose order is the `Ctrl+digit`
numbering, so the rail and the registry cannot disagree about which key opens
which view.

**Keyed dispatch is by id.** `useKeyboardNavigation` asks `matchChord` which
command a keydown names and switches on `command.id`.
`scripts/commands/registry.ts` fails on a keyed command the hook has no `case`
for. `matchChord` treats Meta as Ctrl, requires
Shift to match exactly (so `Ctrl+Shift+K` is not `Ctrl+K`) and never matches
with Alt held, because AltGr arrives as Ctrl+Alt on Windows and is how some
keyboards type `/`.

**A short list of chords is handled before the input guard.** Focus is usually in
the display filter, so the palette (`Ctrl+K`, `Ctrl+Shift+P`), `Ctrl+/`,
`Ctrl+G` and `Ctrl+E` must act from inside a text field; a palette key that
stood down for every input would almost never work. That list is
`CHORDS_BEFORE_INPUT_GUARD`. The view digits and `Ctrl+B` are deliberately not
on it: a digit typed with a modifier into a field has always been the field's.
A plain `k` or `/` typed in the filter stays text, because only the chord
matches. Space keeps the positive scope it had (the body, or inside
`[role="grid"]`).

**Tooltips read the registry.** `titleWithKeys(id, title?)` prints the house form
`Name (Ctrl+X)`, which the rail and the title row already used; `title`
overrides the label for a control whose name depends on state ("Hide side bar").
`scripts/commands/registry.ts` fails on any file under `src/components/` that
spells a `(Ctrl+` of its own outside a comment.

### No palette-only features

Every command duplicates a visible control: a rail button, the title row's side
bar toggle, the filter field, the Settings icon. The palette is a faster route
to the window, never a second window, which is the rule `d3b4326` set when the
menu went and the reason the registry has no command that a pointer cannot also
reach. A feature reachable only by typing its name is a feature most people never
find.

### The palette in ADR 0034's Escape chain

The palette is the first consumer of Escape and sits at the head of the chain
ADR 0034 describes. It listens on `window` in the capture phase and calls
`stopPropagation`, like every inner consumer, so an Escape with the palette open
over the Settings sheet closes the palette only; the sheet stays, and a second
Escape closes it. `App`'s own bubble-phase listener is last by construction and
needed no change. Focus returns to the element that had it when the palette
opened, except after "Focus display filter", whose purpose is to put it
somewhere else. The palette uses the existing card and popover styles.

One accepted overlap: its listener is registered after `FrameMetaRail`'s on the
same phase, so an Escape with the palette over an open meta rail closes both.

### The prefixes

`Ctrl+K` opens the palette. With no prefix it searches commands and the filter
field's own suggestions (recent filters and presets) together. The first
character otherwise selects a mode, in VS Code's vocabulary because those are
the keys these hands already know:

| prefix | mode |
|---|---|
| `>` | commands only. `Ctrl+Shift+P` opens the palette with it |
| `:` | go to a frame, answered from the buffer by `lookupFrame` and `goToFrame`, the same pair the frame-number box uses. A number outside the buffer, or not a number, shows `lookupFrame`'s inline reason and keeps the palette open |
| `?` | the prefixes, then the shortcut list |

The scorer is local (`src/lib/fuzzy.ts`); there is no `cmdk` and no new
dependency. Each row shows its keys on the right. Parsing is
`src/lib/paletteQuery.ts` and the rows are `src/lib/paletteModel.ts`, so the
component draws and decides nothing.

### The analyst keys

- `Ctrl+/` focuses the display filter.
- `Ctrl+G` opens the palette with `:`. `FrameNumberBox` stays in Frame Detail.
- `Ctrl+E` starts or stops a capture. It asks the same question as Space, in
  `src/lib/captureKey.ts`: stopping is always allowed; starting is refused
  whenever the rail's Start would have to ask something - no adapter chosen,
  frames in the buffer (starting again clears a capture that cannot be resumed,
  which is the rail's confirm prompt and never a keystroke), no agent, or Start
  blocked by a filter or ring settings the agent refused. The key is advertised
  only on plain Start and on Stop.

### The three owner rulings (2026-10-16)

- **Match-count chip.** A chip appears in the filter field only while a filter
  is applied, and reads the same `packetCounts` store as the status bar. It dims
  for the whole scan and shows the share only once it is known, so there is no
  invented 0%. It is its own component, so the ten-times-a-second count
  re-renders the chip and not the field.
- **Filter presets are the pins.** "Pinned first" means the saved presets are
  the pins. On focus the last 8 applied filters show under "Recent", above the
  preset groups, and can be cleared. There is no second pin concept. Only an
  expression that compiles is remembered, and a stored list that is junk loads
  as empty.
- **Ctrl+G is the `:` prefix.** It opens the palette in go-to-frame mode and
  reuses `lookupFrame` and `goToFrame` rather than adding a second box.

### Accepted: the Ctrl+/ layout limit

`Ctrl+/` matches `e.key === '/'` with Shift not held. On a layout where `/`
needs Shift the chord arrives as `Ctrl+Shift+/` and does not match. Accepted:
the filter is also reachable by click and by the palette (`>` then "Focus display filter"), and matching it by position would
bind a different key on every layout.

### Settings search

A box at the top of Settings searches every section and lists each hit with its
section name; a hit scrolls to its row and lights it, and a query that matches
nothing says so. A row whose value differs from its default carries a 2px accent
bar and a Reset that restores that row's own field only (three rows share one
performance store, and resetting one must not undo another). Anchor ids are
`setting-row-<slug>`, because `setting-<slug>` already belongs to the switches.
`src/lib/settingsIndex.ts` is the index and `resetSetting` the rule.

### Motion tokens

Two durations and a curve, in `src/index.css`:

| token | value |
|---|---|
| `--motion-fast` | 120ms |
| `--motion-panel` | 180ms |
| `--ease-out` | `cubic-bezier(0.2, 0, 0, 1)` |

They animate the side bar (`--motion-fast`), the sheets and the palette
(`--motion-panel`), as opacity and a few pixels of travel, never a width: the
side bar's width is the user's. **Selection, arrow keys and filter results never
animate**, because they answer a keystroke and must land on it. No toast gets
one, because the app has no toasts and none were added.

**They are declared on `html`, not `:root`.** `scripts/themes/registry.ts`
requires every token in the `:root` baseline to be redeclared by each theme; a
duration is not a colour and does not vary by theme, so putting them there would
be four identical copies.

**Reduced motion zeroes them by two routes.** `[data-motion='reduce']`, which is
the app's own setting folded together with the OS preference, and
`@media (prefers-reduced-motion: reduce)`, which covers the frame painted before
`lib/motion.ts` has run and yields to `data-motion='full'` so "Always" still
beats an OS that asks for less. `scripts/themes/motion-tokens.ts` holds the
values, both routes and the surfaces that must not use them.

## Later, not built

Recorded so a future session inherits the reasoning. Each needs its own ADR
when it is started.

- A context footer hint bar.
- Focus mode, and layout presets with per-preset widths.
- Activity badges, and a notification centre with Do Not Disturb.
- Long jobs as in-place toasts.
- A tree breadcrumb and a sticky follow-stream strip.
- Row density settings.
- A theme export string.
- The speed test's "Flow" view, showing the test's own TCP streams with "Open in
  capture".

## Consequences

- A key is written once. Rebinding one in `commands.ts` moves its tooltip, its
  palette row and its entry in the `?` list together, and a spelled-out
  `(Ctrl+` in a component fails the suite.
- A new keyed command with no `case` in the hook fails the suite, and a chord
  that must work from a text field is a deliberate addition to
  `CHORDS_BEFORE_INPUT_GUARD`.
- `Ctrl+E` is silent where it is refused. The rail says why; a key cannot.
- The Escape chain gains a first link, and `App`'s listener comment now names a
  palette that exists.
