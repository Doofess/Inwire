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
npm run build && npm run check          # 139 scripts, the fast suite
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
- [ ] **The content pane is inset into that corner with a rounded top-left**, and
      its 1px edge follows the curve all the way round - down the rail's side and
      across under the title row. In **Night** the ground either side of that edge
      now differs by 13/255 rather than 4 — the chrome moved to `--secondary` —
      so the curve should read on its own; the border is still what carries it in
      **Day**, where the two are much closer. A *straight* line running
      past the corner instead means the rail got its `border-r` back and is
      drawing over the curve.
- [ ] Its other three corners are **square**. A radius on any of them is a second
      curve inside the one Windows already draws on the window itself.
- [ ] **The brand mark is at the top-left corner**, centred on the rail's 56px
      axis so it lines up with the icons below it. It is the spiral sphere, drawn
      at its **micro** tier because the lockup is 16 CSS pixels — two turns of
      the band, not three and a half. The full tier here is a smudge, and it is
      the single most likely thing to be wrong after any edit to `BrandMark`.
- [ ] **It is legible on both chromes.** The mark carries its own two colours
      rather than inheriting one, and a single ramp serves Day and Night: check
      the dark end has not sunk into `--secondary` on Night, which is the failure
      that a lighter far colour would fix at the cost of flattening the form.
      The ground under it moved from `--card` to `--secondary` — a step brighter
      — so this is worth a fresh look rather than a remembered pass.
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

The app is set in IBM Plex — Sans on the chrome, Mono on the data — and draws
every icon from Lucide. Both replaced a pair chosen independently (Geist with
JetBrains Mono; Tabler), and both fail silently: a face that did not load falls
back to Segoe UI and looks fine on its own, and a glyph from the wrong set
matches nothing beside it and looks fine on its own.

- [ ] In **Day** and **Night**, at **100%**, **150%** and **200%**: the title
      row's counter, the rail tooltips, the Settings tabs and the packet list
      header are one face. The tell for a failed load is Segoe UI's wider `a`
      and open-tailed `g`; Plex's `g` is closed.
- [ ] The hex dump's 16-byte rows and the packet list's columns line up under
      Plex Mono — every glyph the same advance, the ASCII gutter a straight
      edge, no row wrapping.
- [ ] Timestamps in the packet list line up digit for digit (`tnum`), and
      zeros in the hex dump carry a slash or dot (`zero`). Plex has both
      features; the check is that `body`'s `font-feature-settings` reaches them.
- [ ] Generated fields and empty states in the protocol tree render in a true
      mono italic, not a sheared roman — `400-italic.css` is the only italic
      imported, so a bold italic anywhere in mono would be synthesised.
- [ ] Every icon in the rail, the filter row, the Settings tabs and the packet
      list toolbar is the same stroke weight. Lucide and Tabler are both 2px on
      a 24 grid, so a survivor from the old set is hard to see — look for
      rounder corners or square terminals.
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

Ten icons, **44px** targets, three groups, 494px against the 648px the rail gets
- a 680px minimum window, less the 32px title row above it. The rail was full at
630 with 36px targets; six deleted icons paid for both the slack and the larger
ones. `scripts/session/view.ts` holds that arithmetic; what it cannot see is
whether 44px in a 56px strip reads as icons or as boxes.

- [ ] At **1024×680** — the smallest allowed window, and 680 rather than 640
      because the full-width title row takes 32px off the top before the rail
      starts — every group is visible and Settings is not cut off at the bottom.
      There are 154px of slack now, so this is no longer the tight case it was.
- [ ] **The icons are 44px in a 56px strip**, glyphs 24px. Judge it against the
      window buttons and the packet rows: the buttons should read as icons with
      6px of rail either side, not as a column of boxes whose edges are the
      rail's own. This is the one thing the arithmetic cannot tell you.
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
- [ ] **The capture group reads Start/Stop, adapter, schedule**, top to bottom -
      the order they are used in.
- [ ] **The schedule picker opens to the right** and carries a dot when a
      schedule is set. Without the dot a clock looks identical whether or not
      anything is scheduled, which is the failure the adapter's badge exists to
      avoid. Its summary ("Stops in 14:58") is the tooltip now; there is no room
      for a label in 56px.
- [ ] **There is no Find packet button.** The capture group is three icons.
      Anything left over from it — a popover opening off the schedule, a dot on a
      rail button, a packet list quietly short of rows — is a revert that did not
      finish.
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
      tint **and** a warning badge, and a one-line banner appears at the top of
      the filter row with the diagnosis and its action. Tint alone fails for a
      colour-blind user and says nothing actionable.
- [ ] Start a capture: the Start/Stop glyph changes from an outlined record to a
      filled red stop, and the filter row reads `● Capturing on <adapter>`. **No
      cross-fade** — the old `AnimatePresence` was deleted deliberately.
- [ ] With frames in the buffer, press Start again: the discard prompt opens **to
      the right** of the button, not below it (there is no room below a control in
      a 56px strip). Escape closes it without discarding.

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
- [ ] **The two title bars line up**, to the pixel, across the divider. This is
      the item with a real bug behind it: they carried identical classes and
      still differed by 4px, because Hex View's bar holds copy buttons and the
      other holds text. `PaneHeader` fixes the height at `h-9`; a bar that
      drifts again means somebody padded instead of using it.
- [ ] **The divider resizes the pane on its LEFT**, and the dump absorbs the
      difference. Drag it: the tree changes width, and the dump takes what is
      left over.

### The byte inspector

It was the application's bottom bar for one revision, spanning the window with
its text inset to line up under this pane. It is Hex View's own footer again.

- [ ] **There is no window-spanning bar.** Nothing runs under the rail; the
      strip is inside the Hex View pane and stops at that pane's left edge.
      A full-width strip that survived the revert is the bug.
- [ ] **Hover a byte in the dump**: the footer fills with offset, decimal, hex,
      bits and ASCII.
- [ ] **Hover a one-byte field in the protocol tree**: the footer does **not**
      react. That is the change — the bar used to, because it read a range
      derived in `App` that the tree also publishes, and the footer reads this
      pane's own hover.
- [ ] **Drag the divider.** The footer is inside the pane, so it resizes with it
      and there is nothing to keep in step by hand.
- [ ] **Turn the detail panes off** (Settings → Interface): the footer goes with
      the pane. In the **stacked** arrangement it sits under the dump.
- [ ] The **Frame Detail** view's own footer is unaffected — it always had one,
      spanning that pane and carrying the buffer position at its right end.

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
- [ ] **Turn the panes off** (Settings → Interface, "Detail panes"): both go.

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
- [ ] The filter row is shown in **Packets and nowhere else**. Switch through
      Statistics, the Routing Map, Follow Stream and Frame Detail: each pane
      starts directly under the title row, and the pane above it does not shift
      down by a row's height on the way back to Packets. It used to show in all
      five, where it narrowed nothing on screen — Statistics counts the whole
      capture on purpose, and the other three read a feed, a conversation and a
      single frame.
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
- [ ] Kill the app while capturing. The agent survives, and the capture stops when
      the last client disconnects.

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
