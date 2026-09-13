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
- [ ] **Drag it by the rail's top cell** (the brand mark). It moves — that is the
      only draggable part of the rail.
- [ ] **Try to drag it by the rail below the top cell.** It does **not** move, and
      the buttons still press. A control that forgot `.app-no-drag` has exactly
      one symptom: a click that does nothing at all.
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
      layout must survive it. The dock clamps to its floor; the packet list
      scrolls horizontally. Nothing overlaps the window controls.
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
- [ ] In **Settings → Appearance**, switch through all four themes — Day, Paper,
      Graphite, Dark. The buttons follow, because they are CSS.
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
- [ ] At 200% the window still meets its 1024x640 minimum in *logical* pixels.

### Still there after all of it

- [ ] **Alt** reveals the menu bar; **Alt** again hides it. `autoHideMenuBar` is
      load-bearing: `role: 'editMenu'` is the only source of Ctrl+C/V/A/Z for
      every input in the app.
- [ ] In the filter box: **Ctrl+A**, **Ctrl+C**, **Ctrl+V**, **Ctrl+Z** all work.
- [ ] **Alt+Space** does nothing. Expected; see the top of this section.
- [ ] Maximize and restore, and look at the padding along the top edge in both.
      A maximized window has no rounded corners to avoid; a restored one must not
      paint into them.
- [ ] The window title tracks the state, in the taskbar as well as the title row:
      `Inwire` when empty, `<adapter> - capturing - Inwire` while capturing, and
      `<n> packets - Inwire` once stopped with frames still in the buffer. It is
      set from the renderer, which is the only side that knows the adapter's name.

---

## 2. The rail

Thirteen icons, 36px targets, four groups, 579px against a 640px minimum window
height. `scripts/session/view.ts` holds that arithmetic; what it cannot see is
whether the strip reads as two kinds of control.

- [ ] At **1024×640** — the smallest allowed window — every group is visible and
      Settings is not cut off at the bottom. 61px of slack is one icon's worth.
- [ ] The active **view** carries a 2px left accent edge *and* a filled
      background. The active **widget** carries a dot *and* an outline. They are
      deliberately different shapes, because one is a radio and one is a checkbox.
- [ ] **Neither marker appears on hover.** Sweep the pointer down the rail: hover
      is a background tint only. If the accent edge fires on hover, two items read
      as active at once.
- [ ] **Ctrl+1..4** switch views, and each tooltip names the key that opens it.
- [ ] **Tab** into the rail, then **arrow keys**: focus moves through the buttons
      and stops at the ends; **Home**/**End** jump. **Space** and **Enter**
      activate.
- [ ] **Space on a focused rail button presses that button and does not
      start/stop capture.** This was a real bug: Space was scoped by excluding
      inputs, so a focused rail button both activated and toggled capture. It is
      scoped positively now — body, or inside `[role="grid"]`.
- [ ] **Arrow keys inside the rail do not also move the packet selection.**
- [ ] With no stream being followed, **Follow Stream is disabled** and its tooltip
      says why. It is disabled rather than hidden: a group that changes length
      would move the divider and every widget below it.
- [ ] The group dividers are visible **in all four themes**. On Graphite, `border`
      on `card` is #292524 on #1c1917 and was very nearly invisible at 1px — this
      is a real defect that shipped and was found only by looking.
- [ ] The brand mark at the top is **not** the same glyph as the adapter button
      42px below it. (It was, in the first version.)
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

## 3. The dock

`inwire.dock`, 240–640px, 260 default, `scripts/session/dock.ts` holds the
arithmetic and the migration. What needs a person is the gesture and whether
each widget is readable at the floor.

- [ ] **Zero widgets open**: no dock at all, and no empty column. Close the last
      one and its rail icon goes dark — there is no hidden-but-toggled state.
- [ ] **One widget.** **Two.** **All five.** The stack scrolls if it has to; the
      packet list keeps the frame number, the time and both addresses.
- [ ] **Drag the resize handle.** The charts reflow live. The packet list gives up
      width; it does not jump. No motion on the width — 0ms, deliberately.
- [ ] Drag it to both extremes at **1024** wide: it stops at 240 and at 328, and
      both ends accept the drag rather than refusing it.
- [ ] Focus the handle and use **arrow keys**, **Home**, **End**. It is a
      `role="separator"` with real aria values.
- [ ] **Narrow the window** with a wide dock open: the dock shrinks. **Widen it
      again**: the dock returns to the width you chose. The stored value is
      deliberately not clamped.
- [ ] **All five widgets at the 240px floor.** Each renders its real self; there
      is no compact form and deliberately never will be. **Geo map is the one to
      look at hardest** — its `aspect-[11/8]` gives a 163px-tall map there.
- [ ] The title truncates to `TRAFFI…` at 260px. That is accepted, not a defect;
      do not "fix" it without reopening the width decision.
- [ ] **Drag an item by its grip.** Only the grip drags — a drag inside
      live-scrolling chart content would compete for the pointer. The dragged item
      goes to 0.4 opacity, a **placeholder gap** opens, and a 2px insertion line
      follows the pointer's half of the row. Never a live swap.
- [ ] **Restart.** The order survives.
- [ ] **Pin** an item. It moves to the top, stays above everything unpinned, and
      cannot be dragged out of that position. There is **no close-all control** —
      the plan gave `pinned` a second meaning it does not have yet; see
      `dockPrefs.ts`.
- [ ] A pinned item that is **closed** (from its rail icon) stays closed on
      restart. Pin holds a position; it does not open anything.
- [ ] **Geo map's expand window** opens from inside the dock and closes back into
      it. Escape closes the overlay before it touches the view.
- [ ] While capturing at a real rate, watch a chart in the dock and the packet
      list together. The charts redraw on their own throttles (100ms element size,
      150ms timeline, one rAF for the map) — **those throttles must not be
      removed**, and a dock that stutters the list means one has been.

### The migration, which runs once and cannot be repeated

`seedFromDashboard()` reads `inwire.dashboard` and writes `inwire.dock` before the
store's first read. It runs **once per user**, on first launch of this build.

- [ ] On a profile that used a previous build with the right-hand column
      **expanded**, the widgets that were enabled are open, in the order they were
      in.
- [ ] On a profile whose column was **collapsed to icons or hidden**, the dock
      opens **empty** and the tour explains the rail. The selection underneath a
      collapsed column is discarded deliberately — honouring it would open up to
      five widgets nobody asked for.
- [ ] On a fresh profile, **Traffic Timeline alone** is open.
- [ ] Custom widget titles and per-widget config survive — those stay in
      `inwire.dashboard`, which is why `normalizeDashboard` stops *reading*
      `mode`/`width` but does not delete them.

---

## 4. The views

- [ ] **Ctrl+1..4** and the rail reach all four. Each is a pane, not a modal:
      there is no scrim and nothing is full-screen.
- [ ] Scroll the packet list deep, select a frame, go to **Statistics**, come
      back. **The scroll offset and the selection are exactly where you left
      them** — Packets stays mounted, hidden with `display:none`.
- [ ] A row action in **Statistics** (apply filter, select frame, follow stream)
      switches to Packets with the filter applied.
- [ ] **Follow Stream** from a packet's context menu, then leave it: selection and
      scroll return to the originating packet.
- [ ] Clear the followed stream while the view is open: it returns to Packets
      rather than showing an empty pane.
- [ ] The filter row is **hidden in Network** and shown in Statistics. Network
      describes the machine, not the capture.
- [ ] **Escape**, innermost first: a focused input blurs; then the palette, the
      filter presets dropdown, the discard popover; then the geo overlay; then a
      non-Packets view returns to Packets. Escape on Packets with nothing focused
      does nothing.
- [ ] Close the app in **Statistics** and relaunch: it opens on Statistics. Close
      it in **Follow Stream** and relaunch: it opens on **Packets**, because the
      conversation it named lived in a buffer that is being rebuilt.

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
