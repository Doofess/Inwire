# The verification matrix

Everything this repository knows to check and **cannot** check by itself.

`npm run check` runs every assertion script under `scripts/` on any machine, with
no Electron and no browser. That is the point of it, and it is also its ceiling:
it cannot see a window, it has no second user account, it cannot click a UAC
prompt, and it cannot tell you that a colour looks right. Three of the worst bugs
in the Electron migration were invisible to every script here and were all found
by hand — maplibre's worker URL, `node:os` in the preload, and COEP blocking
`pipeline.worker`.

So this file is the other half. CLAUDE.md and ADR 0029 both refer to "the
verification matrix"; this is it.

**How to read it.** Each item says what to do and **what a failure looks like**,
because almost everything below fails silently — that is why it is here rather
than in a script. Nothing is timed; the point is that somebody looked.

---

## 0. Before you start

Run the things that *are* scripted but are kept out of `npm run check` because
they are slow or reach outside the process. They cover the half of the app
`smoke.ts` structurally cannot, and running them first means the by-hand pass
below is not also debugging the store.

```
npm run build && npm run check          # 143 scripts, the fast suite
npx tsx scripts/electron/disk-drive.ts          # ~2 min: past the RAM budget, onto disk
npx tsx scripts/electron/import-drive.ts        # ~1 min: 400,000 frames, scroll to frame 1
npx tsx scripts/electron/update-center-drive.ts # ~1 min: a loopback feed, the real app
```

`npm run check` does **not** build. `smoke.ts` tests whatever is in `dist/` and
prints the build's age, so a stale `dist/` is a pass about old code.

The chrome pass in §1 needs a packaged build, not `npm run dev`: the `app://`
handler, the MIME table, the 404 rule and the CSP all behave differently under a
dev server, and the title bar's colour cache is read from the real user-data
directory.

```
npm run pack        # release/win-unpacked/
```

To drive it with traffic and no Administrator rights, no Npcap and no service:

```
npx tsx scripts/electron/serveStub.ts --burst 40
```

then launch the app beside it and pick **Ethernet (stub)**.

---

## 1. The window's own chrome

`frame: false`, with the app drawing its own minimize / maximize / close. The
whole section exists because the window is drawing furniture Windows used to
draw, and every failure here is visual.

**Two things do not work, by decision, and are not defects:** the Snap Layouts
flyout on a maximise-button hover (it needs `WM_NCHITTEST` to answer
`HTMAXBUTTON`, which Electron does not expose) and the Alt+Space system menu
(there is no native caption to raise it from). Do not file either; do not
"fix" either by reaching for `titleBarOverlay`.

### Dragging and the resize frame

- [ ] **Drag the window by the empty part of the title row.** It moves.
- [ ] **Try to drag the window by the rail.** It does **not** move, anywhere -
      the rail is entirely no-drag now that the brand mark and its 40px cell have
      gone to the title row. Every rail button still presses; a control that
      forgot `.app-no-drag` has exactly one symptom, a click that does nothing.
- [ ] **The top-left corner is one continuous surface.** The title row spans the
      whole window and the rail starts below it, both on `--secondary`, with no
      border between them - so no horizontal line cuts across the corner and the ground
      runs unbroken from the mark down into the rail. A line there means somebody
      put `border-b` back on the title row.
- [ ] **The content pane is inset into that corner and the corner is SHARP**, and
      its 1px edge runs down the rail's side and across under the title row,
      meeting at a right angle. In **Night** the ground either side of that edge
      differs by 13/255 — the chrome is `--secondary` — so the edge should read
      on its own; the border is still what carries it in **Day**, where the two
      are much closer. A second line running past the corner means the rail got
      its `border-r` back and is drawing beside the pane's.
- [ ] **All four of its corners are square**, this one included. A radius on
      any surface that meets the window - this pane, the title row, the rail -
      is the app drawing a curve inside the one Windows already draws. Buttons,
      cards and popovers inside the workspace are rounded and always were; the
      rule is about the shell's edges.
- [ ] **The brand mark is at the top-left corner**, on the rail's axis so it
      lines up with the icons below it — which is `gutter + width / 2`, not half
      the rail's width, since the rail is an inset card. It is the layered
      stack, drawn at its **small** tier because the mark is 24 CSS pixels and
      the boundary is 32 — **three** plates, not five. Count them; five at this
      size merge into one blue lump, and that is the single most likely thing to
      be wrong after any edit to `BrandMark`. It should read as the app's
      corner, not as a detail in it: 24 in a 32px row, with the art's own 10%
      margin leaving roughly 19px of ink.
- [ ] **It is legible on both chromes.** The mark carries its own colours rather
      than inheriting one, and a single ramp serves Day and Night: check the
      darkest plate has not sunk into `--secondary` on Night, and that the
      lightest is still distinct from the chrome in Day.
- [ ] **The taskbar and Alt-Tab show five plates**, at 32px — that is the
      primary tier, and 32 is exactly where it starts. Explorer at "extra large"
      shows the 256px entry, also five. If the taskbar icon looks like a blue
      smear, the `.ico` was packed with the wrong tier per size.
- [ ] **Nothing is behind the mark.** This is the one to check on a light
      wallpaper and a dark one: in the taskbar, in Alt-Tab, and in Explorer, the
      plates sit on whatever is behind them with **no square, no tile and no
      halo** — including in the gaps between plates, which are transparent too,
      not filled. A dark rectangle around the icon means an opaque ground came
      back into the rasteriser.
      The ground under it moved from `--card` to `--secondary` — a step brighter
      — so this is worth a fresh look rather than a remembered pass.
- [ ] **Settings takes the workspace, and nothing dims.** Press the rail's
      Settings icon: it fills the workspace card, the title row, the rail and
      the status bar stay live and undimmed, and there is **no scrim** and no
      floating panel. The card's own border and rounded corners are the only
      ones — Settings must not draw a second card inside the first.
- [ ] **The rail marks it the way it marks a view** — the translucent accent
      fill. Press the icon again and it closes. There is no second marker shape
      anywhere in the strip now: the outline that meant "this control is ON"
      went with its last caller, so an outlined button is a defect rather than a
      state.
- [ ] **Three ways out, and they agree.** The title row's back step reads
      "Back to Packets" (or whichever view is underneath) and closes it; Escape
      closes it; the rail icon toggles it. There is **no X and no Close
      button**.
- [ ] **It does not navigate.** Open Statistics, then Settings, then close it —
      you are back in Statistics, not in Packets. That is what makes it a sheet
      rather than a view.
- [ ] **Network is a rail button in the CAPTURE group, directly under
      Export/Import.** Press it: the report opens in the **side bar**, beside
      the packet list rather than over it, and the icon takes the same
      translucent accent fill a view's does. Press it again and it closes. It is
      **not** in the rail's numbering — `Ctrl+1..5` are the five views and none
      of them is this.
- [ ] **The capture it describes is still on screen.** That is the whole reason
      it stopped being a sheet: "Observed (capture)" is a live column, and as a
      sheet it covered its own subject.
- [ ] **It is gone from Settings.** Open Settings: the tabs run Appearance,
      Interface, Accessibility, Display Filters, Colouring Rules, Custom
      Dissectors, Decryption, Driver Info, Updates. No Network tab.
- [ ] **Settings is the only sheet, and a panel is not one.** Open Network in
      the side bar, then press the rail's Settings icon: Settings takes the
      workspace card and **the Network panel stays open and lit**. That is
      correct — the two are different containers — and it is the item most
      likely to be filed as a bug by somebody remembering the old behaviour.
      The back step, Escape and choosing a view each close the **sheet** and
      must leave the column alone.
- [ ] **Export/Import moved up.** It is the fourth icon in the capture group,
      under the schedule clock — not at the bottom beside Settings.
- [ ] **The two glyphs at the top and bottom are different.** The adapter button
      in the capture group is an `EthernetPort`; Network is the node graph. If
      they look like the same icon twice, that is the exact failure this strip
      has shipped once before.
- [ ] **Choosing a view from inside Settings works.** Open Settings, then click
      any view icon in the rail: the pane closes and that view is on screen.
      Same with `Ctrl+1..5`. This shipped broken — the rail's marker moved and
      the pane stayed up, so every icon looked dead and the back step was the
      only way out.
- [ ] **Applying a filter from inside Settings works too.** Open Settings, type
      `tcp` in the title row's field and press Enter: the pane closes and you
      land in Packets. **Clearing it leaves Settings open**, because clearing
      navigates nowhere.
- [ ] **Escape closes Settings before anything else.** With Settings open over
      Frame Detail, one Escape closes Settings and leaves you in Frame Detail; a
      second returns you to Packets.
- [ ] **The display filter is in the title row's centre**, about 26rem wide,
      centred in the **window** rather than in the gap between the corner and
      the caption buttons. There is no filter row above the packet list and no
      44px strip where it used to be.
- [ ] **It does not drag the window.** Click into the field, type, press the X,
      press the bookmark, open the presets list and pick one. Every one of those
      must work without the window moving — the slot opts out once, so a failure
      here means the wrapper lost `app-no-drag`.
- [ ] **The chevron at the field's right edge opens AND closes the presets.**
      Press it: the list appears and the glyph turns over. Press it again: the
      list goes. That second press is the whole point — clicking the field
      already opens the list, and before this the only ways to put it away were
      Escape and a click elsewhere.
- [ ] **It wins over the completions.** Type `tcp.po` so the field-name
      completions appear, then press the chevron: the presets replace them.
      Typing again brings the completions back. A chevron that flips its glyph
      and leaves the completions up is the failure to look for.
- [ ] **It does not steal focus.** Click into the field, type, then press the
      chevron and keep typing — the caret must still be in the field.
- [ ] **The empty field reads as an example.** It says `e.g. tcp.port == 443`,
      muted. The old placeholder was three real clauses with nothing marking
      them as a sample, so an empty field looked like a filter already applied.
- [ ] **Applying a filter goes to Packets.** From **Statistics**, type
      `tcp` and press Enter: you land in the packet list looking at the result.
      From **Packets** it just applies. **Clearing does not navigate** — clear
      the filter while in Statistics and you stay there.
- [ ] **There is no agent banner anywhere.** Stop the agent: the fault is named
      once, in the status bar's left group, and nothing appears above the packet
      list.
- [ ] **Restoring shows in the status bar.** Relaunch with a stored capture: a
      spinner and `Restoring n/m` appear at the left of the bar and go when it
      finishes.
- [ ] **The back step appears only where there is somewhere to go.** It sits
      **immediately left of the filter field**, not in the corner beside the
      mark. In **Packets**, **Statistics** and the **Routing Map** nothing is
      there. In **Frame Detail** a chevron appears reading "Back to Packets"; in
      **Follow Stream** it reads "Back to Frame Detail".
- [ ] **The filter field does not move when it appears.** Step between Packets
      and Frame Detail and watch the field's left edge: a `w-9` spacer mirrors
      the button on the right, so only the chevron appears. If the field slides
      18px, that spacer is gone.
- [ ] **It is a step, not the exit.** From Follow Stream press it once: you land
      in Frame Detail, not in the packet list. Press it again for Packets.
      **Escape from Follow Stream goes straight to Packets** in one hop — the
      two keys are deliberately different and this is the pair to check
      together.
- [ ] **Either way out of a stream lands on the frame it was followed from.**
      Follow a stream from frame N, leave by the back step, and the selection is
      N; do it again and leave with Escape, same answer. If the capture has
      since dropped frame N from the buffer you get the refusal toast rather
      than a silent wrong frame.
- [ ] **Follow Stream's footer has no button** — just the totals line.
- [ ] **The detail-panes toggle is beside the caption buttons**, left of
      minimize, with a small gap. Press it: the protocol tree and hex dump go
      and come back, and the packet list takes the height. It is narrower than
      the three caption buttons and has a rounded hover, so it does not read as
      a fourth one.
- [ ] **It does not move the window.** Press and hold on it and drag — the
      window must stay put and the press must register. This is the failure
      `app-no-drag` exists for, and it looks like a click that did nothing.
- [ ] **Settings → Interface has no panes switch**, and its "Pane arrangement"
      row greys out while the panes are hidden. Two ways in is how the two
      disagree.
- [ ] **Nothing in the status bar is clickable.** Hover every item in the bar:
      no hover highlight, no pointer cursor, and Tab from the workspace does not
      stop on any of them. The one exception is the packet counter's
      `+N UNSEARCHED` rescan, which is a real button and still runs a
      whole-capture scan.
- [ ] **`INWIRE` is gone.** No word beside the mark, in either theme. The window
      still names itself in the **taskbar and Alt-Tab** — hover the taskbar entry
      and start a capture: it reads `Ethernet - capturing - Inwire`. That string
      is what the wordmark was duplicating, and it is the thing to check is still
      working, because nothing in the window shows it.
- [ ] The corner block is still **138px** and the packet counter is still centred
      in the **window**, not in the space left beside the mark. Maximize and
      restore: the counter stays on the window's centre line.
- [ ] **Drag the window by the mark.** It moves: the corner block is inside the
      drag region and carries no `app-no-drag`.
- [ ] **Double-click the empty title row** → maximizes; again → restores. **Check
      this first.** It is the one caption behaviour that is neither clearly kept
      nor clearly lost with `frame: false` — Chromium is supposed to handle it
      for `-webkit-app-region: drag`, and if it does not, it has to be
      reimplemented on the row's `dblclick`.
- [ ] **Right-click the title row** still does nothing — there is no native
      caption behind it. Accepted, with Alt+Space.
- [ ] **Drag each of the four window edges and all four corners. They resize.**
      This is `thickFrame`, which defaults to true and is never set - if edge
      resizing is gone, somebody set it false and took the drop shadow and the
      minimise animation with it.
- [ ] The drop shadow is there, and a restored window has Windows 11's corner
      radius - `roundedCorners`, also a default that is never set.
- [ ] Minimize and restore from the taskbar: the window **animates** rather than
      appearing. Same option, same tell.

### The side bar

The column between the rail and the workspace — VS Code's primary side bar.
Four rail buttons open it — Interfaces, Schedule, Export/Import and Network —
and `Ctrl+B` toggles whichever was last open. **Most of this section is geometry
and none of that can be scripted**: the assertions read the class strings, they
cannot see what two cards look like where they meet.

- [ ] **The seam is ONE line.** Open the side bar: exactly one 1px line runs
      between the rail and the column, full height. The two failures are a
      **doubled** line (both cards drawing it) and **no** line (neither), and
      both of those render perfectly happily.
- [ ] **The two read as one surface.** The rail's right corners are square, the
      column's right corners are round, and there is no gap between them.
      Closed again, the rail closes up with all four corners rounded and 4px of
      `--secondary` showing between it and `<main>`.
- [ ] **The icon column does not move by a pixel** when the side bar opens.
      Screenshot both states and flip between them. This is the `w-11` interior
      arithmetic — 42px between two borders centres a 36px target on whole
      pixels — and it is exactly what breaks if the rail ever gives its facing
      border away to make the seam.
- [ ] **The grounds differ.** The rail is `--secondary` and the column is
      `--card`. In **Night** that step is what makes the hairline readable at
      all; in **Day** the border carries it. If the column looks like a wider
      rail, it took the wrong ground.
- [ ] **In Night specifically, look for a hard white rectangle at the seam.**
      The two dropdowns this replaced carried `border-0 shadow-lg` to suppress a
      near-white outline on a floating panel, and that suppression is gone with
      them — the column needs the border it shares with the rail.
- [ ] **The gap moves, it does not double.** Opening the side bar must shift
      `<main>`'s left edge by exactly the column's width — not by the width plus
      4px. `<main>` gives up its `ml-1` and the sash stands in its place.
- [ ] **The sash.** Drag it: the column resizes and the packet list reflows.
      Drag it to the far left — it stops at 170px. Drag right — it stops while
      the list is still usable. **Right-click, double-click and Enter** each
      reset it to 288. Tab to it, then arrows nudge, Shift-arrow steps bigger,
      Home and End hit the bounds.
- [ ] **It paints nothing at rest** — no grey bar between the two cards, unlike
      the two dividers inside the packets view. Hover turns it accent.
- [ ] **The width survives a restart**, and so does the open panel. Then
      **Settings → Interface → Restore defaults** must leave both untouched.
- [ ] **A width chosen wide survives a narrow window.** Drag the column to its
      600px ceiling, shrink the window until the column is forced to narrow,
      then widen the window again: the column must come back to 600. The stored
      width is clamped only against `[170, 600]` and the window's reserve is
      applied on the render path, so a drag or an arrow press that *commits* the
      narrowed figure is the bug — and it is invisible until the window grows
      back, which may be the next day.
- [ ] **At 1024×680 with the side bar open**: the column clamps to **192px**
      (`MAIN_RESERVE_PX` is 780, so it narrows rather than being refused, and
      192 is still above VS Code's 170 floor). Frame number, time, source and
      destination are all still on screen without scrolling; Protocol, Length
      and Info scroll. This is where the push is paid for, and it is the
      documented trade rather than a defect. Check the Interfaces panel is still
      usable at 192 — that is the narrowest any panel is ever asked to be.
- [ ] **Escape never closes it.** From Packets, from Statistics, and with
      Settings open. Escape from Statistics must still land on Packets in one
      press. `Ctrl+1..5` must leave it open too. ADR 0034 is the argument; this
      item exists because "Escape dismisses everything" is the assumption all
      four of these surfaces arrived with.
- [ ] **Settings open WITH a panel open.** Both rail buttons lit, Settings in
      the workspace card, the panel in the column beside it. This is the
      screenshot that proves the two are orthogonal containers rather than two
      names for one slot.
- [ ] **Tab goes rail → panel → `<main>` and is not trapped.** The panel is a
      place, not a menu; nothing captures focus.
- [ ] **Arrows inside a panel do not step the packet selection.** Focus a row in
      the Interfaces list and hold Down past the end of the list — it wraps to
      the top, and the status bar's packet counter must not move. Without the
      `stopPropagation` in `useRovingFocus`, one key does two things and only
      one of them is visible.
- [ ] **A field inside a panel keeps its own keys.** In the schedule's preset
      name field, Home goes to the start of the line rather than moving focus;
      in `DateTimeCalendar`'s Hour and Minute, Up increments rather than
      jumping out of the field.
- [ ] **Adapter sampling starts and stops with the PANEL.** Open Interfaces:
      the sparklines move. Switch to another panel and confirm
      `unsubscribe_interface_stats` in the agent's log. Switch back: they
      restart **empty**, not with a ten-minute-old chart. Then drop and restore
      the agent with the panel open — this is the known edge, listed rather
      than pre-fixed: the unsubscribe on a dead pipe is a no-op and the
      reconnected agent is not sampling, so the chart may freeze. Report it if
      it reproduces rather than treating it as a surprise.
- [ ] **Network reaches out only when asked.** Open the Network panel and scroll
      past every section with the status bar visible: it must read `no lookups`
      the whole way down. Only pressing **Show public identity** may change
      that. This is the privacy catch the stacking created — `PublicIdentity`
      used to be mounted only when its nav item was chosen, and the nav is gone.
- [ ] **Network with a real disagreement.** Change a DNS server, capture a
      little traffic, and read the section: the amber block and its sentence are
      unmissable in a 300px column, and the **SEEN** tag is what marks the
      surprising line — position cannot carry that in one column, which is why
      the words moved onto the values.
- [ ] **Export/Import is cheap to open beside a live capture.** Start a capture,
      open the panel and leave it open: the frame rate in the list must not
      drop. `prepare()` does its hydrate → anonymise → name pass at press time,
      not on render, which is the whole reason a modal could get away with the
      old shape and a persistent panel cannot.
- [ ] **Export with an invalid filter**: the message renders **in flow** and
      pushes the list below it down. Nothing floats over the format list and
      nothing overflows the column's right edge — that is `variant="panel"`
      doing its job, and the deleted `pt-9` reservation not coming back.
- [ ] **Import a bad file**: the error dialog is still a **modal**. A refusal
      that has to be acknowledged is a detour, and detours keep their scrim.

### Snap

- [ ] **Win+Left / Win+Right.** On a 1920px display this gives a 960px window,
      which is **below** `MIN_WINDOW_WIDTH` of 1024 — Windows allows that and the
      layout must survive it. The two bottom panes hold their share and the
      packet list scrolls horizontally. Nothing overlaps the window controls.
- [ ] Hovering the maximize button does **not** open Snap Layouts. Expected; see
      the top of this section.

### The app's own buttons

`WindowControls.tsx`. 46x32 with 10px glyphs, which are Windows' own metrics —
the target size and spacing are what muscle memory aims at.

- [ ] **All three work**: minimize, maximize, restore-down, close. The maximize
      glyph becomes the two-rectangle restore glyph while maximized.
- [ ] **Each is actually clickable.** A control that lost `.app-no-drag` drags
      the window instead, and the only symptom is a click that does nothing — on
      close, a window that cannot be closed.
- [ ] **With frames in the buffer, press close.** `guardClose`'s native "Quit
      Inwire?" box appears. Cancel → the window stays and the capture is intact.
      The button calls `window.close()`, never `destroy()`; destroying would skip
      this box and discard a capture on one click. (No automated test can answer
      it, which is why `smoke.ts` clears `setUnsavedCapture` before closing.)
- [ ] In **Settings → Appearance**, switch through both themes — Day and Night.
      The buttons follow, because they are CSS. Paper and Graphite are gone; the
      picker's third entry is System, which is a rule rather than a palette.
- [ ] **The quit confirm is drawn in the app's theme.** With frames in the
      buffer, in **Night**, press close: the "Quit Inwire?" box is **dark**. In
      **Day** it is light. It is a native dialog, so it follows `nativeTheme`
      rather than the cascade, and nothing in the suite can see it.
- [ ] **...and System still follows the OS afterwards.** Turn System on, cancel a
      quit confirm, then change Windows' own app theme (Settings → Personalisation
      → Colours). Inwire follows within a second. `guardClose` holds the
      `themeSource` override only while the box is up for exactly this reason: a
      standing one pins `prefers-color-scheme` in the renderer, which is what
      `useSystemThemePreference` reads, and the app would be following itself.
- [ ] **Hover close** → Windows' red `#c42b1c`, white glyph, in every theme.
      Hover the other two → the theme's accent.
- [ ] **Click another window so Inwire loses focus.** The whole title row dims,
      controls included — it is one `opacity` on the row, so they cannot dim out
      of step. Click back: it restores.
- [ ] The window name is **centred in the window**, not in what is left beside
      the buttons. Sitting left of centre means the spacer and the controls
      disagree about 138px.


### No flash at launch

This matters more than it did. A frameless window IS the app's surface, so the
wrong ground is a full-window flash rather than a strip.

- [ ] Set the theme to **Day**, quit, and launch again. The window is **light
      from the first frame**. A dark window turning light a beat later means the
      cache in `window-state.json` was not read before the window was
      constructed. Day is the one to test with - the fallback is dark, so a
      broken cache is invisible on the dark themes.
- [ ] Delete `window-state.json` from the user-data directory and launch. It
      opens dark with no error, then corrects once the renderer reports its
      theme.

### Scaling

The reserve is ours now — 138 CSS pixels at every scale factor, because the
buttons are elements. Under the old overlay it had to come from
`env(titlebar-area-width)`, because Windows drew it wider at 150%.

- [ ] At **100%**, **150%** and **200%** display scaling (Settings → System →
      Display → Scale), the three controls are crisp, sit inside the 40px row,
      and nothing in the title row overlaps them. Log out and back in if Windows
      asks.
- [ ] The glyphs are **sharp, not blurred** — they are 1px axis-aligned SVG
      strokes with `shapeRendering="crispEdges"`, and half-pixel placement is
      what would soften them.
- [ ] At 200% the window still meets its 1024x680 minimum in *logical* pixels.

### One typeface, one icon set

The app is set in the faces the OS ships — on Windows, Segoe UI Variable Small
on the chrome and Cascadia Mono on the data — and draws every icon from Lucide.
This section is written for Windows, the only desktop today; when the macOS
and Linux desktops arrive it needs a pass on each with the machine in hand,
because every tell below names a Windows glyph. Nothing
is downloaded and nothing is self-hosted, so a font failure here is not a
missed load: it is a family name DirectWrite does not resolve, which falls
through the stack silently to `sans-serif` (Arial) or `monospace` (Courier
New). Both look like fonts rather than like bugs, which is why this is here.

- [ ] In **Day** and **Night**, at **100%**, **150%** and **200%**: the title
      row's counter, the rail tooltips, the Settings tabs and the packet list
      header are one face, and it is the face of the Windows Settings app open
      beside it. The tell for a fallen-through stack is Arial: its `a` has a
      spur at the bottom right and its `R` a straight leg; Segoe's `a` has no
      spur and its `R` a curved one.
- [ ] The hex dump's 16-byte rows and the packet list's columns line up under
      Cascadia Mono — every glyph the same advance, the ASCII gutter a straight
      edge, no row wrapping. Consolas is a legitimate fallback and reads
      narrower and squarer; Courier New is not, and reads thin and serifed.
- [ ] Timestamps in the packet list line up digit for digit, and so does the
      title row's counter as it climbs. Segoe UI Variable's figures are
      **proportional by default** — a `1` narrower than a `0` — so a counter
      that jitters sideways means `body`'s `font-feature-settings` did not
      reach it. Zeros in the hex dump carry a slash, which is Cascadia's own.
- [ ] Settings row labels (`font-medium`) are **Regular**, and section
      headings (`font-semibold`) are visibly heavier than them. If the two are
      one weight, either the `html[data-platform="win32"]` rule in `index.css`
      is gone or `<html>` carries no `data-platform` — check it in DevTools —
      and Chromium has snapped 500 up to Semibold.
- [ ] No `->`, `==` or `!=` in an Info column or the hex dump's ASCII gutter
      is drawn as a single joined glyph. That is Cascadia *Code* leaking in;
      the token names Cascadia *Mono*, which has no ligatures.
- [ ] Generated fields and empty states in the protocol tree are italic and
      **sheared** — Windows ships no Cascadia Mono Italic, and the synthesised
      slant is accepted at 11px over importing a webfont for one style.
- [ ] Every icon in the rail, the title row, the side bar's panels, the Settings
      tabs and the packet list toolbar is the same stroke weight. Lucide and
      Tabler are both 2px on a 24 grid, so a survivor from the old set is hard
      to see — look for rounder corners or square terminals.
- [ ] `LoaderCircle` spins during an export and during an import.
- [ ] In the Routing Map's side panel, a located row shows a **filled** pin and
      an unlocated one a hollow pin with a slash. `fill-current` on `MapPin` is
      what keeps that, and it is the one call site the swap changed beyond the
      name. Lucide's pin is a path plus a separate circle, so filled it is a
      solid teardrop rather than Tabler's pin-with-hole — expected, not a bug.
- [ ] The rail's Stop button, while capturing, is a **filled** red square.
- [ ] The rail's adapter button is an Ethernet port, not a tree; Frame Detail's
      is a tree. They were `TbNetwork` and `TbBinaryTree` and are `EthernetPort`
      and `ListTree` — two of the four judgement calls in the mapping.
- [ ] The Gateway & DNS tab's icon is a router, and Hex View with no bytes
      shows a struck-through database — `Router` and `DatabaseX`, the other
      two judgement calls.

### Still there after all of it

- [ ] **Alt** reveals the menu bar; **Alt** again hides it. `autoHideMenuBar` is
      load-bearing: `role: 'editMenu'` is the only source of Ctrl+C/V/A/Z for
      every input in the app.
- [ ] In the filter box: **Ctrl+A**, **Ctrl+C**, **Ctrl+V**, **Ctrl+Z** all work.
- [ ] **Alt+Space** does nothing. Expected; see the top of this section.
- [ ] Maximize and restore, and look at the padding along the top edge in both.
      A maximized window has no rounded corners to avoid; a restored one must not
      paint into them.
- [ ] The title row's **centre is the packet counter**, not the window's name —
      `2,224 / 2,224` and a percentage badge, in the app's mono face. It is the
      only copy of those figures in the app now; the filter bar's badge and the
      counts widget are both gone.
- [ ] **The window name still exists and is the OS's.** Check the **taskbar** and
      **Alt-Tab**, not the row: `<adapter> - capturing - Inwire` while capturing,
      `Inwire` otherwise. It is set from the renderer, which is the only side
      that knows the adapter's name. A row that shows the counter and a taskbar
      that shows nothing means `useWindowTitle` stopped being called.
- [ ] **The counter is legible against the row's dim.** Blur the window: the
      whole row goes to `opacity-60`, including the figures. They must still be
      readable, and the badge must not become the brightest thing in a blurred
      window.
- [ ] **Drag the window by the row, starting on the counter's figures.** It must
      move — the numbers are inside the drag region and carry no `app-no-drag`.
- [ ] **Then drag starting on the `+N UNSEARCHED` button**, with one on screen
      (see the disk section). It must **not** move the window, and a click must
      re-run the scan. That button is the one control in the title row and the
      only rescan affordance in the app; if it drags instead of firing, its
      `app-no-drag` has been lost and the only symptom is a click that does
      nothing.

---

## 2. The rail

Eleven icons, **36px** targets, three groups, **452px** against the **618px** the
rail gets - a 680px minimum window, less the 32px title row above it, the 24px
status bar below, the cluster's 4px bottom gutter and the card's own two 1px
borders. The strip is `w-11`, **44px**, and the target came back down to 36 when
it narrowed: a 44px target in a 44px card has the button's edges BE the card's.
`scripts/session/view.ts` adds that up from the Tailwind classes and prints the
slack; what it cannot see is whether 36-in-44 reads as icons or as boxes.

- [ ] At **1024×680** — the smallest allowed window, and 680 rather than 640
      because the full-width title row takes 32px off the top before the rail
      starts — every group is visible and Settings is not cut off at the bottom.
      There are **166px** of slack, room for four more icons, so this is no
      longer the tight case it was.
- [ ] **The icons are 36px in a 44px card**, glyphs 20px, which leaves **3px of
      air** either side inside the card's two borders. That constant is the
      thing to judge, not the outer width: 32-in-48, 36-in-56, 44-in-56 and
      36-in-44 are four points on one line. The buttons should read as icons in
      a strip, not as a column of boxes whose edges are the card's own.
- [ ] The active **view** is a **translucent wash of the theme's accent** —
      `--primary` at 20%, so a blue tint rather than a solid blue button — with
      the glyph in `--foreground`. There must be **no 2px edge** down its left
      side: that was the other half of the old marker and an edge in the fill's
      own colour over the fill is a second mark for one fact.
- [ ] **Active and hover are not the same thing.** Hover the icon next to the
      active one: the tint under the pointer is neutral grey, the active one is
      blue. `scripts/themes/registry.ts` holds them 12.4 deltaE apart in Day and
      15.1 in Night, but whether they read as *different kinds of thing* is the
      part a number cannot tell you.
- [ ] **The glyph is readable on the wash** — 11.1:1 in Day, 8.4:1 in Night. The
      glyph is `--foreground` and not the accent, because `--primary` on a tint
      of itself cannot clear 4.5:1 in Day at any alpha.
- [ ] **The rail and title row are one step brighter than the panes** and read as
      one surface with each other. In Night the strip is `#232323` against the
      panes' `#1a1a1a`; in Day it is a light grey against white.
- [ ] **The marker does not appear on hover.** Sweep the pointer down the rail:
      hover is a background tint only. If the accent fill fires on hover, two
      items read as active at once.
- [ ] **Ctrl+1..5** switch views, and each tooltip names the key that opens it.
- [ ] **Tab** into the rail, then **arrow keys**: focus moves through the buttons
      and stops at the ends; **Home**/**End** jump. **Space** and **Enter**
      activate.
- [ ] **Space on a focused rail button presses that button and does not
      start/stop capture.** This was a real bug: Space was scoped by excluding
      inputs, so a focused rail button both activated and toggled capture. It is
      scoped positively now — body, or inside `[role="grid"]`.
- [ ] **Arrow keys inside the rail do not also move the packet selection.**
- [ ] **The capture group reads Start/Stop, adapter, schedule, Export/Import,
      Network**, top to bottom - the order they are used in. Five icons; the
      bottom group is Settings alone, which is what makes the divider above it
      mean something: everything above opens a surface beside the workspace, the
      one below takes the workspace itself.
- [ ] **Four of those five open the side bar, not a popover.** The adapter and
      the schedule were Radix dropdowns flying out of the rail and
      Export/Import was a 768px modal; if any of them still flies out or dims
      the app behind it, that is a revert. Only Start/Stop opens anything over
      the rail, and only the discard prompt.
- [ ] **The schedule button carries a dot when a schedule is set**, and its
      countdown is in the **panel's header** ("Stops in 14:58") rather than in a
      tooltip. Without the dot a clock looks identical whether or not anything
      is scheduled, which is the failure the adapter's badge exists to avoid —
      and the dot is now the rail's only mark besides the fill, so it carries
      "this control has something to report" for both buttons that used to wear
      an outline.
- [ ] **There is no Find packet button.** Anything left over from it — a popover
      opening off the schedule, a packet list quietly short of rows — is a revert
      that did not finish.
- [ ] With no stream being followed, **Follow Stream is disabled** and its tooltip
      says why. It is disabled rather than hidden: a group that changes length
      would move the divider and the bottom group below it.
- [ ] The group dividers are visible **in both themes**. On Night, `border` on
      `card` is #343434 on #1a1a1a and was very nearly invisible at 1px — this is
      a real defect that shipped and was found only by looking.
- [ ] The brand mark in the title row is **not** read as the same glyph as the
      **Start capture** button below it. **They are on the same axis again** —
      the wordmark is deleted, so the mark is centred in a `w-14` block and sits
      directly above the rail's column of icons — which makes this **more** likely
      than it was, not less: a chevron above a play triangle is two arrows, and if
      it reads as one control repeated, the mark is the one that has to change.
      This item was written the other way round while the word led the mark; the
      thing it warns about is the cost of having taken that word out.
- [ ] Disconnect the agent (stop `serveStub.ts`): the adapter icon takes a status
      tint **and** a warning badge, and the **status bar's left group** names the
      diagnosis. Tint alone fails for a colour-blind user and says nothing
      actionable. There is no banner above the packet list any more — that went
      with the filter row, on the rule that one fault wants one place.
- [ ] Start a capture: the Start/Stop glyph changes from an outlined record to a
      filled red stop, and the **status bar** reads `● Capturing` with the
      adapter beside it and the elapsed time. **No cross-fade** — the old
      `AnimatePresence` was deleted deliberately.
- [ ] With frames in the buffer, press Start again: the discard prompt opens **to
      the right** of the button, not below it (there is no room below a control in
      a 44px strip). Escape closes it without discarding.

---

## 3. The two panes under the packet list

The bottom row is PACKET INSPECTION | HEX VIEW, one draggable divider, the
tree's share stored as `detailsPaneRatio` with the hex dump taking the
remainder. There was a third pane - a pane-sized copy of the Routing Map,
leading the row - and it is deleted, which took `geoPaneRatio`, the second
divider and the "one map, never two" section below with it.
`scripts/preferences/interface.ts` holds the clamping; what needs a person is
the dragging and the bars lining up.

- [ ] **The packet table's header row is the same ground as the pane titles
      below it** — all three `--card`. It used to be a step brighter, which is the
      chrome's colour, and it was the only column header in the window that did
      not match the bars under it.
- [ ] **The header's column separators are opaque, and they stay put while the
      list scrolls under them.** Scroll a coloured capture fast and watch the
      vertical lines in the header: they must be the app's own grey and must
      not take a tint from the packet passing beneath. They did, and the tell
      was subtle enough to survive several looks — a collapsed border on a
      sticky header is painted by the TABLE, under the body rows, so the line
      read as transparent rather than as missing. The bottom rule under the
      header is the same border with the same bug and must be checked the same
      way.
- [ ] **The body's column separators go the right way, in both themes.** On
      **Night** each line is a groove — slightly DARKER than the row it sits on
      — and on **Day** slightly lighter. A bright cage over dark rows means the
      step lost its sign, which is the one thing about this token that is
      per-theme: Day is `+0.02` of oklab lightness and Night is `-0.05`. The
      rule it replaced was a fraction of white shared by both, which moved a
      Day row by 0.010 and a Night row by 0.320 — thirty-two times as far, from
      one number that looked theme-neutral.
- [ ] **The selected row's separators come from the selection, not the list.**
      Arrow onto a coloured row: its lines step from the accent fill like every
      other row's step from theirs. It is the one row painted by a class rather
      than an inline style, so it is the one that can fall back to the list's
      ground without anything else changing.
- [ ] **The two title bars line up**, to the pixel, across the divider. This is
      the item with a real bug behind it: they carried identical classes and
      still differed by 4px, because Hex View's bar holds copy buttons and the
      other holds text. `PaneHeader` fixes the height at `h-9`; a bar that
      drifts again means somebody padded instead of using it.
- [ ] **The divider resizes the pane on its LEFT**, and the dump absorbs the
      difference. Drag it: the tree changes width, and the dump takes what is
      left over.

### The status bar, and the byte readout in it

The application has a bottom bar again. It had one for a revision and it was
deleted, so this section carries the checks that say which of the two is on
screen. The short form: the bar is back, the indent is not.

- [ ] **The chrome is a C and the cluster floats inside it.** The title row
      across the top and the bar across the bottom run edge to edge; between
      them the rail and the workspace are two cards, inset by a 4px gutter on
      the left, the right and the bottom, and **flush against the title row at
      the top**. The gutter shows the chrome's own `--secondary`. A card that
      reads *darker* or *lighter* than the gutter is a different bug from a
      missing line.
- [ ] **Two separate outlines, with daylight between them.** The rail is a
      closed rounded rectangle and so is the workspace, with a 4px gap down the
      middle showing the chrome's ground. Follow each outline all the way round
      — neither should share an edge with the other, and neither should have a
      flat side facing the gap.
- [ ] **Four rounded corners per card** — 8px on all eight corners in the band.
      A square corner facing the gap means the two have gone back to meeting
      flush.
- [ ] **The gap is even top to bottom**, and the same width as the gutter at the
      window's left edge and under the cards. All three are 4px, from the same
      Tailwind step.
- [ ] **Nothing is rounded against the window itself.** The title row and the
      status bar still run corner to corner and are square. The only curve at
      the window's edge is Windows'.
- [ ] **One line per seam, not two.** A `border-l` returning to `<main>` puts a
      second rule beside the rail's — a thickened edge in Day, invisible in
      Night, which is why the script checks it rather than the eye. The strips
      are the same trap: a `border-t` on the status bar draws a line 4px under
      the cards' own **and** makes the bar 23px.
- [ ] **The icon column is centred in the rail card.** With a border on each
      side the interior is 54px for a 44px target — 5px of air either side. If
      the icons look a pixel left of centre, the facing border has moved to
      `<main>`.
- [ ] **The bar spans the full window**, under the rail as well as the panes,
      and **its contents are not indented.** The right-hand group sits at the
      window's right edge, wherever the panes above it happen to end. A readout
      pushed sideways to line up under the hex dump is the bug that was reverted
      once; the machinery for it no longer exists.
- [ ] **Dragging the bar does not move the window.** It is not a drag region.
      Every item in it is clickable and lands in Settings.
- [ ] At **1024×680** with a capture running, an adapter selected, a fault on
      the agent and a byte hovered — **everything visible at once** — nothing
      wraps, clips, or pushes the counter off the right edge. The adapter's
      label is what truncates first.

**The cross-highlight between the two bottom panes**, which is where a
performance fix could have broken a behaviour:

- [ ] **Hover a field in the protocol tree**: its bytes light up in the dump,
      hex and ASCII both.
- [ ] **Hover a byte in the dump**: the field containing it lights up in the
      tree. Both directions, or the store lost a publisher.
- [ ] **Sweep the pointer along a row of bytes** without stopping. The highlight
      follows continuously and never flickers off between cells — the dump binds
      one delegated `mouseout` for the whole pane, and if it stopped checking
      `relatedTarget` the highlight would blank for a frame on every byte
      crossed. This is the check that a screenshot cannot make.
- [ ] **Move the pointer off the dump entirely** — onto the divider, or the row
      background between the hex and ASCII columns. The highlight clears.
- [ ] **Move from the tree straight into the dump and back.** Whichever pane the
      pointer is in owns the highlight; leaving one must not blank what the
      other just lit.
- [ ] **On a large frame** — a 64KB segmentation-offload frame is the case —
      sweeping the dump should feel immediate. It used to re-render the whole
      application once per byte, so the tell was a lag that got worse the bigger
      the frame, and was invisible on a 54-byte one.
- [ ] **With a capture running and a large frame selected**, the dump should sit
      still. It is the app's only `React.memo` boundary; if it re-renders ten
      times a second, a prop crossing it stopped being stable — `permissions` is
      the one to look at first.

**The byte readout**, which is the item with the history:

- [ ] **Hover a byte in the Packets view's hex dump**: the readout appears at
      the right end of the bar — offset, hex, decimal, bits and ASCII. Move off
      the dump and it **disappears entirely**. There is no "hover any byte"
      prompt: that sentence taught you what the pane did when it lived in the
      pane, and in a window-wide bar it would be a permanent sentence about a
      pane that may not be on screen.
- [ ] **Hover a one-byte field in the protocol tree**: the bar does **not**
      react. This is the check with the history. The first bar was fed a range
      derived in `App` that the tree also publishes, so it answered "this byte"
      for a hover in a pane that was not the dump.
- [ ] **Hover a byte, then switch to Frame Detail** (Ctrl+2) and back. The bar
      is empty in between. The packets view stays mounted behind
      `display: none`, so this is the case a pointer event cannot cover.
- [ ] **Hover a byte in Frame Detail's own dump**: the same bar cell fills.
      That view's footer now carries only `Frame N of M`.
- [ ] **Drag the tree/dump divider.** Nothing in the bar moves or realigns —
      which is the whole difference from the version that was deleted.
- [ ] **Turn the detail panes off** (the title row's toggle): the bar stays and
      its byte cell is empty.
- [ ] **Neither hex pane has a footer any more.** The dump's last row sits
      directly above the workspace's bottom border.

**The left group**, which should read as a diagnosis:

- [ ] **With the agent stopped**, the first item carries a warning triangle and
      names the fault, and the second reads **No adapter**. The capture and
      dropped-frame items are **absent** rather than showing zeroes. Clicking
      either of the two opens Settings.
- [ ] The warning hue is on the **glyph**, not the label — the label stays at
      full-strength text. In **Day** check this specifically: `--warning` on the
      chrome is 4.06:1, which is why it never carries text.
- [ ] **Start a capture**: a pulsing dot and an elapsed clock appear, and the
      clock advances once a second. Leave it running past a minute and past an
      hour if you can: `4:12` becomes `1:04:12`.
- [ ] **Dropped frames appear only when there are some.** If the driver's own
      counters could not be read the number carries a `+` and the tooltip says
      the real total may be higher — it must never read as a plain zero.

**The right group:**

- [ ] The **packet counter is here, not in the title row**, and the title row's
      centre is empty. The `+N UNSEARCHED` rescan button came with it and still
      re-runs a whole-capture scan.
- [ ] The **outbound indicator** sits between the byte readout and the counter,
      and it is words rather than a glyph. With geo-IP and reverse DNS both off
      it reads `no lookups`; turn either on in Settings → Interface and it names
      them — `geo-IP`, `rDNS`, or both — at full strength rather than muted. It
      must read the same in greyscale, which is the check: the state is the
      text, never the colour. This is the one item that is deliberately visible
      in its quiet state, because "nothing is going out" is the claim worth
      confirming in a packet analyzer.
- [ ] **The two ends of the bar match.** The agent link at the left starts 8px
      in and the packet counter at the right stops 8px short — the counter is
      not a `StatusItem` and brings no padding, so the group supplies it.

- [ ] **The divider drags**, and the hex dump absorbs the change: widen the
      details tree and the dump narrows, and back again.
- [ ] **Right-click, double-click and Enter** on the divider reset it to its
      default, which is 0.5 — an even split, and the value it had before the map
      spent a third of the row.
- [ ] **Keyboard**: tab to the divider and use the arrows; Home and End go to
      the limits, which are 0.1 and 0.9 again. There was a second divider with
      **mirrored** arrows, because the map sat on the far side of it; there is
      one divider and no mirroring.
- [ ] **Drag the tree as wide as it goes.** The hex dump keeps a tenth, and that
      is now the normalizer's ceiling rather than a rule applied at render time -
      the render-time clamp existed because two shares could add past 1.
- [ ] **Narrow the window to 1024** with both open. The dump absorbs it; the
      stored share does not change, so widening gives back exactly what you set.
- [ ] **Stacked arrangement** (Settings → Interface): both stack, and the
      divider's arrows flip to up/down.
- [ ] **Turn the panes off** (the title row's toggle): both go.

### One map, and it is the view

There were two copies of the map - the Routing Map view and a pane in this row -
and the rule was that exactly one could ever be live, because a hidden MapLibre
instance is still a WebGL context and a tile fetcher. The pane is deleted, so
the rule is a fact about the tree rather than something to check. What is left
is worth a look after anything touching the view list:

- [ ] Open **Routing Map** from the rail (Ctrl+4 — Frame Detail took Ctrl+2 and
      pushed it along). It fills the pane, like Statistics — **not a modal**: no
      scrim, nothing floating, and Escape returns to Packets rather than closing
      an overlay.
- [ ] **There is no map in the Packets view at all** — the bottom row is two
      panes, and nothing in it re-initialises when you come back from the map.
- [ ] Switch Packets → Routing Map → Statistics → Packets a few times. No leaked
      context warnings in the console, and the packet list's scroll offset and
      selection survive throughout.
- [ ] The map carries its **zoom buttons, its help panel and the OSM credit** in
      the bottom-right and top-right corners. All three used to be conditional on
      size, and the condition was the 256px pane that no longer exists.

### No dock, and nothing left of it

- [ ] **The rail has no widgets group and no collapse chevron.** Three groups:
      capture, views, and the bottom pair.
- [ ] **Settings → Interface has no Widgets list.** The two controls that stood
      there — the old three-way Dashboard mode, then the reorderable widget list
      — are both gone.
- [ ] On a profile that had `inwire.dock` and `inwire.dashboard` in
      `localStorage`, nothing reads them and nothing breaks. They are left in
      place rather than cleared; no code path touches either key.


## 4. The views

- [ ] **Ctrl+1..5** and the rail reach all five — Packets, Frame Detail,
      Statistics, Routing Map, Follow Stream. Each is a pane, not a modal: there
      is no scrim and nothing is full-screen. Frame Detail took Ctrl+2 and the
      three after it each moved a key; `APP_VIEWS` order is the numbering, so the
      rail's tooltips must agree.
- [ ] Scroll the packet list deep, select a frame, go to **Statistics**, come
      back. **The scroll offset and the selection are exactly where you left
      them** — Packets stays mounted, hidden with `display:none`.
- [ ] A row action in **Statistics** (apply filter, select frame, follow stream)
      switches to Packets with the filter applied.
- [ ] **Follow Stream** from a packet's context menu, then leave it: selection and
      scroll return to the originating packet.
- [ ] Clear the followed stream while the view is open: it returns to Packets
      rather than showing an empty pane.
- [ ] **The rail's Follow Stream button follows the selection.** With nothing
      followed yet, select a TCP or UDP frame: the icon **enables**, and pressing
      it (or `Ctrl+5`) opens *that frame's* conversation. Select a frame on a
      different stream and press it again: the pane shows the **new** stream.
      All three of those were broken together — the button read "a stream is
      already open" rather than "the selection has one".
- [ ] Select an **ARP or a broadcast** — a frame with no stream — while a stream
      is open. The icon stays **enabled** and reopens the stream already being
      read. It must not flicker disabled as you arrow down the list.
- [ ] With nothing followed and a non-stream frame selected, the icon is
      **disabled** and its tooltip names the condition: select a frame on a TCP
      or UDP stream.
- [ ] **There is no filter row in any view.** Switch through Packets,
      Statistics, the Routing Map, Follow Stream and Frame Detail: every pane
      starts directly under the title row, and nothing shifts down by a row's
      height on any of those transitions. The field is in the title row and
      belongs to the app, which is the fourth and last form of a rule that spent
      three revisions arguing about where to put a ROW.
- [ ] **Applying a filter from a non-Packets view goes to Packets.** Open
      Statistics, type `tcp` and press Enter: you land in the list looking at
      what you just selected. **Clearing navigates nowhere**, because the empty
      filter selects the whole capture and every view already shows that.
- [ ] **Escape**, innermost first: a focused input blurs; then the filter presets
      dropdown, the discard popover; then a non-Packets view
      returns to Packets. Escape on Packets with nothing focused does nothing.
      There is no command palette in that chain — `cmdk` left `dependencies` with
      the hamburger menu.
      There is no geo overlay in that chain any more — the map is a view, so it
      leaves by the same door every other view does.

### Frame Detail

It was a modal over the packet list, opened by double-clicking a row and
dismissed with Escape or an X. Everything here is a consequence of it being a
view, and every item fails silently.

- [ ] **Double-click a row.** The Frame Detail view opens on that frame, and the
      packet list's own selection is on it too — go back to Packets (Ctrl+1) and
      the row is selected and in view.
- [ ] **Open Frame Detail with nothing selected** — a fresh window, Ctrl+2. The
      pane shows the go-to-frame box and the capture's frame range as the input's
      placeholder. This is the view's front door; an empty pane here is the bug.
- [ ] Type a frame number and press the arrow. The pane fills, and the packet
      list's selection moved with it.
- [ ] Type **a word**, a number outside the range, and a number inside the range
      the buffer has dropped. Each reports inline **under the input** — not as a
      band that pushes the block down and pulls it back up as you type.
- [ ] **← and → step frames** and move the packet list's selection with them.
      **↑ and ↓ still work on the packet list** when you go back — the modal used
      to disable the app's whole keyboard handler while it was open, and nothing
      does that now.
- [ ] **Escape returns to Packets**, like every other view. On a window narrow
      enough that the meta rail is an icon strip, summon the rail: Escape puts
      the rail away and **does not also leave the view** — that is the
      `stopPropagation`, and it is the one Escape this pane still claims.
- [ ] **Space does not start or stop a capture** while a field or the frame box
      has focus. It is scoped positively — body, or inside `[role="grid"]`.
- [ ] Select a frame, switch to Frame Detail, switch back. **The bottom panes
      show the same frame** and did not re-fetch its tree — one `usePacketDetail`
      serves both, and a second would be a second replay request.
- [ ] Widen and narrow the window across ~1234px of canvas: fields and bytes go
      from two columns with a draggable divider to one stacked document, and the
      divider's position survives the round trip.

### Statistics → Graphs

The tab that replaced the Traffic timeline and Packet sizes widgets. The charts
are the same components; what is new is that every control they had is inline
instead of in Settings.

- [ ] **Both charts are there**, throughput above frame sizes, each taking half
      the height, and neither is inside a scroller — the timeline measures its
      own container, so a parent that grew to fit it would size the SVG from a
      box the SVG is defining.
- [ ] **Every control changes the chart and sticks.** Metric, chart type and
      interval on the throughput plot; bars/table on the sizes. Switch the tab
      away and back, then restart the app: each is where you left it
      (`inwire.graphs`).
- [ ] **The overlay filter is the one worth exercising.** Type `tcp.port == 443`
      into it during a capture: a second series appears over the total, and the
      total does **not** change — that is the whole point of it not being the
      app's display filter. Clear it and the second series goes.
- [ ] The charts count the **whole buffer**, not the filtered view, like every
      other tab here. Apply a display filter in the packet list and the throughput
      plot must not move.
- [ ] **Switch theme with the tab open.** The timeline is an imperative D3 draw,
      so it redraws from `themeKey` rather than from CSS — a chart still in the
      old accent means that prop stopped arriving.
- [ ] Close the app in **Statistics** and relaunch: it opens on Statistics. Close
      it in **Follow Stream** and relaunch: it opens on **Packets**, because the
      conversation it named lived in a buffer that is being rebuilt.

### The inspection panes are the app's accent, not the frame's

The packet list still paints rows by colour rule; the panes that describe one
frame no longer borrow that hue. Nothing in `scripts/` can see this — the check
that held the accents to a card, a hue axis and each other went with them.

- [ ] Select a **TCP** frame, then a **DNS** frame, then one the rules do not
      match at all. In the inspection pane and the hex pane, every accent —
      the `#Frame N` label, the tree's layer headings, the cross-reference
      links, the byte count, the selected byte in the dump — must be **the same
      colour on all three**: the theme's own accent, `#38bdf8` in Night.
- [ ] **Step through frames in the Frame Detail view with ← and →.** The pane
      must not change hue as the protocol changes. It used to, which is the
      behaviour being removed.
- [ ] The **rows themselves are unchanged** — still a fill per matched rule, and
      the Frame Detail pane still names the rule in words. If the rows went flat, the
      wrong thing was deleted: `getPacketStyle` is the list's, `getPacketAccent`
      was the panes'.
- [ ] Both themes. Day's accent is its own blue, not Night's.

---

## 5. The agent and the pipe

### The security descriptor took effect

The SDDL is `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`.
`local-agent/test_protocol.py` pins its *shape* and
`scripts/electron/agent-link.ts` drives the real client against a real pipe.
**Neither can tell you the descriptor took effect.** That needs a second Windows
account, and it is the reason this file exists.

- [ ] As a **standard (non-admin) user**, launch Inwire. It connects, enumerates
      interfaces and captures. `IU` is what grants that — the service is
      LocalSystem and the app deliberately is not.
- [ ] From a **remote machine**, try to open `\\<host>\pipe\inwire-agent`. It is
      refused. A pipe answers over SMB unless the descriptor says otherwise, which
      is why `WD`, `AN` and `NU` are absent.
- [ ] Kill the app while capturing. The capture stops when the last client
      disconnects — and so, now, does the **service** (see below).

### The agent's lifetime is the app's

ADR 0035. None of this can be asserted from a script: it needs the real SCM, a
real service, and a person watching a status bar. Each item fails silently.

- [ ] **Before launching**, `sc query InwireAgent` reports `STOPPED`. On a fresh
      boot nothing has started it — that is the whole point of demand start, and
      a `RUNNING` here means the installer registered it `auto`.
- [ ] Launch Inwire. **`sc query` reports `RUNNING` within a second or two, and
      no UAC prompt appears.** A prompt means the unelevated `sc start` was
      refused and `serviceStart.ts` escalated — check that the installer's
      `GrantServiceStartToInteractiveUsers` ran.
- [ ] **Watch the status bar's left group while it launches.** It reaches "Agent
      connected" without passing through a lingering "Agent not running". The
      2,000 ms `connectedDelay` that caused exactly that is deleted; if it reads
      wrong for a beat, something is gating `connected` on the socket again
      rather than on `hello`.
- [ ] Close Inwire. **`sc query` reports `STOPPED` within about four seconds** —
      two watchdog ticks at two seconds. It stops itself; nothing runs `sc stop`.
- [ ] **Kill Inwire from Task Manager** rather than closing it. The service still
      stops, which is the case a quit-path `sc stop` could not cover and the
      main reason the self-stop is in the agent.
- [ ] Launch, then close, then launch again quickly. The second launch starts the
      service again cleanly. (If the second launch finds it mid-stop, `sc start`
      fails and the bounded retry covers it — the bar should still reach
      connected.)
- [ ] **Two Windows users, via Fast User Switching.** Both run Inwire and both
      capture. One quitting does **not** stop the other's capture: the agent
      counts clients, and this is why the app was never granted `WP`.
- [ ] **Settings → Capture Health → Restart Driver** still works, and Npcap
      install still cycles the link and re-enumerates adapters. Both go through
      paths the lifetime change touched.

### Capture Health says what nothing else does

- [ ] The tab is named **Capture Health**, and it carries no Status row, no
      Version pill, no Capture row and no "Listening on" list. All four are in
      the status bar permanently; the panel exists for the loss account.
- [ ] During a capture it shows **Received** and four drop stages — driver,
      agent, in transit, and the buffer trim. "Dropped in transit" reads
      `Not reported` against an agent too old to send `droppedPipe`, and **never
      `0`**: a stage nobody measured must not read as a stage that lost nothing.
- [ ] The buffer trim is worded apart from the four and says **"still on disk"**.
      Those frames were captured and are readable; the status bar's single total
      does fold them in, which is a known overstatement.
- [ ] There is **no "Link (estimated)" row**. It was Chromium's rounded guess at
      downlink and RTT among rows of exact counts off the wire.

### The buffer sizes itself

ADR 0036. The numbers differ per machine, which is the point.

- [ ] **Settings → Interface → Buffer size** offers **Auto** first, and it is
      selected on a fresh profile. Picking it must not leave the control with
      nothing checked — `Segmented` is a Radix `RadioGroup` and a `NaN` budget
      renders exactly that.
- [ ] The description under it reads a plausible packet count for this machine,
      not one computed from `NaN` or from zero.
- [ ] Pick an explicit size, restart, and it is still that size. Pick Auto,
      restart, and it is still Auto — `'auto'` is a stored value, not the
      absence of one.

### Npcap

- [ ] On a machine with **no Npcap**, the agent connects and reports no
      interfaces, and `DriverInfoPanel` says the driver is missing and links to the
      tab that fixes it. It must not read as "not connected" — `diagnoseAgent`
      short-circuits on `connected`, and a driverless agent *is* connected.
- [ ] **Settings → Updates → Npcap**: told the version this machine has, the row
      reads `up-to-date`. (`update-center-drive.ts` automates this one against a
      loopback feed; it is here because the real feed host does not resolve yet.)
- [ ] Click install. A **UAC prompt appears**, and Npcap's own wizard is shown
      with its licence. There is no silent install and `/S` appears nowhere — it
      is the OEM feature and the free licence does not grant it.
- [ ] **Decline the UAC prompt.** The row goes back to what it was and shows
      nothing. A decline is `cancelled`, never `failed`.
- [ ] After an install, interfaces re-enumerate without restarting the app — the
      link is cycled, not `refresh_adapters`.
- [ ] **Driver access mode.** If Npcap is installed without *"Restrict Npcap
      driver's access to Administrators only"*, the row says so and offers the
      reinstall. Ticking that checkbox is the one step the app cannot do.
- [ ] On a machine where the registry and the DACL **disagree**, the DACL wins.

---

## 6. What is still owed

Not checkable yet, recorded so it is not mistaken for done.

- **Electron fuses.** `runAsNode`, `enableNodeCliInspectArguments` and
  `enableNodeOptionsEnvironmentVariable` are **not** flipped. Until they are, any
  local process can run the signed exe with `ELECTRON_RUN_AS_NODE=1` and pass
  every signature check. Flipping mutates the exe, so it must land **before**
  signing.
- **Code signing.** Phase 6 is blocked on a certificate (EV or Azure Trusted
  Signing) outside this repository.
- **Authenticode verification of downloads.** A sha256 says the bytes are the ones
  the feed named. It says nothing about the publisher.
- **The update feed.** `updates.inwire.app` does not resolve, so the Inwire row
  reads "Not checked" and every check is a quiet no-op.
- **`crossOriginIsolated` in the packaged app.** Set via `ISOLATION_HEADERS` and
  verified by hand once; nothing depends on it, and an assertion must exist before
  anything does.
- ~~**`scripts/electron/smoke.ts` on a machine that has the real agent.**~~
  **Fixed (ADR 0035).** It used to **skip** — "something else is already serving
  `\\.\pipe\inwire-agent`" — because the installed InwireAgent service owns that
  name and the script will not race a LocalSystem service for it. The refusal
  was right and the outcome was wrong: smoke drives the adapter-picking flow,
  so **every item in §1's side bar block and §2's capture group was by-hand only
  on this machine**, and a green `npm run check` was not evidence that picking
  an adapter still worked. `INWIRE_AGENT_PIPE` now gives each run a private pipe
  name, and the stub is served on it. Kept here rather than deleted because the
  shape recurs: a script that skips on the one machine it matters on is a script
  nobody is running.
- **A keyboard way INTO the side bar.** VS Code has `Ctrl+0`. `Ctrl+B` toggles
  the column and Tab reaches it, but nothing focuses it directly. Not built
  deliberately — ADR 0034 records it as guessing at a problem nobody has raised
  yet rather than as an omission.
