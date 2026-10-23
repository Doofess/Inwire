# The renderer shell

Moved out of the root `CLAUDE.md` so it loads when you work under
`src/components/` rather than in every session. It describes the shell — the
title row, the rail, the status bar, the side bar and the card cluster — plus
the views, the settings sheet, the frame views, and the render-path facts that
are easy to undo by accident.

**`App.tsx` lives one directory up** and is named throughout; the arrangement
decisions below are what it implements.
## The renderer

`sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, no service
workers, every permission request denied. The preload is a **single CommonJS
file** — a sandboxed preload cannot be ESM and cannot `require` a relative
module, so `electron/build.cjs` bundles it.

**The shell is a title row, a rail, a status bar and a side bar.** There is no
menu and no filter row. The first three are always there; the fourth is a column
that expands out of the rail and is the only part of the chrome with a width the
user chose.

**Closed** — the rail and `<main>` float apart, which is VS Code's `.nosidebar`
case.

```
┌─────────────────────────────────────────────────────────┐
│  ◉  ‹  [ tcp.port == 443 ]  ▾           ▤    ─ □ ✕      │
│ ╭────╮ ╭──────────────────────────────────────────────╮ │
│ │rail│ │ packets (hidden, never unmounted)            │ │
│ │44px│ │   ├─ packet list                             │ │
│ │    │ │   └─ INSPECTION │ HEX VIEW                   │ │
│ │    │ │ detail | statistics | geo | stream           │ │
│ │    │ │ settings - the sheet, INSTEAD of the stack   │ │
│ ╰────╯ ╰──────────────────────────────────────────────╯ │
│ ● Capturing 04:12  Ethernet     0x42 'B'  44/178,200 ◍  │
└─────────────────────────────────────────────────────────┘
```

**Open** — the side bar butts against the rail and the two read as one surface:
one seam, drawn by the rail, and the sash takes over the 4px gap `<main>` used
to supply. `<main>` keeps its own four borders and simply gets narrower.

```
┌─────────────────────────────────────────────────────────┐
│  ◉  ‹  [ tcp.port == 443 ]  ▾           ▤    ─ □ ✕      │
│ ╭────┬──────────────╮╷╭───────────────────────────────╮ │
│ │rail│ INTERFACES   │╷│ packets                       │ │
│ │44px│ ──────────── │╷│   ├─ packet list              │ │
│ │    │ Ethernet ▁▃▅ │╷│   └─ INSPECTION │ HEX         │ │
│ │    │ Wi-Fi    ▁▁▂ │╷│                               │ │
│ ╰────┴──────────────╯╵╰───────────────────────────────╯ │
│ ● Capturing 04:12  Ethernet     0x42 'B'  44/178,200 ◍  │
└─────────────────────────────────────────────────────────┘
```

#### Views and navigation

**A view is a way of looking at the capture**, and that one question decides the
list. `APP_VIEWS` order **is** the `Ctrl+1..5` numbering — there is no second
table. Settings is not in it (nothing in it changes when a packet arrives) and
neither is Network (it describes the *machine*).

**The views are a drill-down**: `Packets` is the capture, `Frame Detail` is one
frame of it, `Follow Stream` is one conversation that frame belongs to. The
title row's back step follows `backTargetFor` in `viewPrefs.ts`, a TOTAL record
so a new view cannot be added without deciding whether it is a root — Statistics
and the Routing Map are roots, and a back step there would have to invent a
destination.

**Escape is a different key and stays one hop**, any non-Packets view to
Packets, which is why `stream` has two answers. **The side bar is deliberately
not in that chain** (ADR 0034): it is persisted, and a place is a setting while
a detour is not, so an Escape that closed it would silently rewrite a stored
preference AND make the documented one hop into two.

**`stream` is a legal stored value that `restoredView` refuses**, because the
conversation it named lived in a buffer that is being rebuilt — and that fact
has to move with the JSX. `scripts/session/view.ts` reads the render guard for
every view out of `App.tsx` and asserts that the one view needing a second
condition — `stream`, which needs a target — is exactly the one `restoredView`
refuses.

#### The title row

The mark, the side bar's toggle, a back step, the filter field, the detail
panes' toggle, the caption buttons. No navigation and no packet count; `useWindowTitle` still sends
`windowTitleFor(...)` to main, so the taskbar and Alt-Tab are unchanged.

**The display filter is in the centre** because it belongs to the app rather
than to a row a view could hide: it does not act on what is in view —
`captureScan` answers it over the whole capture on disk. **Applying a filter
goes to Packets**; clearing does not navigate, because the empty filter selects
the whole capture and every view already shows that. The field is
`max-w-[26rem]` and centred in the WINDOW, not in the space between the corner
and the controls. The placeholder is `e.g. tcp.port == 443`, marked as a sample,
because an unmarked expression reads as a filter already applied.

**Its presets chevron is a toggle**, because clicking the field already opens
the presets and closing is what the field cannot do. It also decides the list
when the completions and the presets both claim the space beneath: `FilterBar`
records WHO opened the list rather than that it is open, and the chevron tracks
the VISIBLE list so it never offers to close something nobody can see.

**The back step carries a `w-9` spacer mirroring it on the right**, or the
filter would shift 18px on every view change that gained or lost one.

**The detail panes' toggle is a CONTROL, not a setting** — reached for mid-task
rather than chosen once, which is why it left `Settings → Interface`. The pane
*arrangement* stays there and still greys out when the panes are off. It is
`w-9` rather than the caption buttons' 46, which is Windows' metric and not ours
to borrow.

**The drag-region rule.** The title row is `.app-drag` and everything
interactive in it is `.app-no-drag`; **the rail is entirely no-drag**. A control
that forgets `no-drag` moves the window instead of being pressed, and the only
symptom is a click that does nothing — on the close button, a window that cannot
be closed. Both classes are in `index.css` and deliberately not `:root` custom
properties, because `scripts/themes/registry.ts` requires every token in that
block to be redeclared by every theme.

`scripts/electron/window-chrome.ts` asserts the no-drag class sits on the shared
button class rather than on each button, that the panes toggle carries it beside
`WindowControls` rather than inheriting from that group, and that Settings has
no second way in. `scripts/session/view.ts` asserts the mark's block is
`ml-1 w-13` — the rail's width AND the band's gutter, because a card's axis is
`gutter + width / 2`.

#### Commands, the palette and the analyst keys

**`src/lib/commands.ts` is the one list** the palette, the window's keys and
every keyed tooltip read (ADR 0057). It is data only - `run` is bound by id in
`App.tsx` - and **no command exists only there**: each duplicates a control on
screen, which is `d3b4326`'s rule from when the menu went.

**`Ctrl+K` opens the palette and `Ctrl+Shift+P` opens it on `>`.** The first
character picks the mode: none searches commands and the filter field's recents
and presets together, `>` commands only, `:` go to a frame (through
`lookupFrame` and `goToFrame`, so a number outside the buffer shows the same
inline reason the frame-number box gives and the palette stays open), `?` the
prefixes and the shortcut list. `CommandPalette.tsx` only draws
`lib/paletteModel.ts`'s rows. Focus returns to the element that had it,
except after "Focus display filter"; Tab is held inside it, and a key an IME is
composing with is the IME's. Pressing `Ctrl+K` again resets what was typed, and
a list that changes under the same query (the context moves during a capture)
keeps the highlight on the same row (`keepActive`).

**Escape goes to the newest surface that asked for it** (`lib/escapeStack.ts`,
`hooks/useEscapeLayer.ts`): one capture-phase window listener and a stack of
layers - the palette, the presets list while it is visible, the rail's restart
confirm, the import error, Frame Detail's meta rail. The top layer takes the
key and stops it, so a palette over a sheet closes the palette and a second
Escape closes the sheet. A surface pushes a layer only while it is showing; one
that listened on the window itself would race the others by mount order, which
is what this replaced. `scripts/commands/escape-stack.ts` fails on a converted
file that listens for Escape on the window again. The tour overlay is not on
it, and App's view Escape stays a bubble-phase listener beneath them all.
**A chord is read as typed, and by its physical key only when the layout types
no ASCII** (`matchChord`'s `code`), so `Ctrl+K` works on a Hebrew or Russian
layout and AZERTY's `A` stays `A`.

**The analyst keys work from inside a text field**, because focus is usually in
the filter: `Ctrl+/` focuses the display filter, `Ctrl+G` opens the palette on
`:`, `Ctrl+E` starts or stops a capture. They are the chords in
`CHORDS_BEFORE_INPUT_GUARD`; the view digits and `Ctrl+B` are not, since a
digit typed with a modifier into a field is the field's. **`Ctrl+E` is Space's
decision** (`lib/captureKey.ts`): stopping is always allowed, and starting is
refused whenever the rail's Start would have to ask - no adapter, frames in the
buffer, no agent, or Start blocked - so the key is advertised only on plain
Start and on Stop. `Ctrl+/` matches `e.key === '/'` with no Shift, so on a
layout where `/` needs Shift it does not fire; accepted.

**A tooltip's "(Ctrl+X)" comes from `titleWithKeys(id, title?)`**, never from
text in a component. `scripts/commands/registry.ts` fails on a `(Ctrl+` spelled
in any file under `src/components/` outside a comment.

**The filter field carries a match chip and remembers recents.** `MatchChip`
(in `FilterBar.tsx`) shows `44 of 178,200` only while a filter is applied, from
the same `packetCounts` store as the status bar; it is its own component so the
ten-times-a-second count re-renders the chip and not the field, it dims for the
whole scan, and it names the share only once `scanPercentage` is known. On focus
the last 8 applied filters show under "Recent", above the preset groups, with a
Clear (`services/recentFilters.ts`, key `inwire.recentFilters`). Only a filter
that compiles is remembered, and junk in storage loads as `[]`. The saved
presets are the pins; there is no second pin concept.

#### Settings, the one sheet

`components/common/SettingsPane.tsx` takes the workspace card: no scrim, no
radius, no border, because `<main>` is the card and a second one inside it is a
card in a card. It covers the workspace, the view underneath is untouched, and
closing it puts that view back rather than navigating anywhere.

**The slot stays a union, and it has three members now.** `App` models it as
`sheet: 'settings' | 'speedtest' | 'monitoring' | null` rather than a boolean, which makes "the
card holds exactly one surface" a fact the type carries — a boolean invites a
second boolean beside it, and then "both open" is representable in a card that
shows one. **The speed test's sheet** (`speedtest/SpeedTestSheet.tsx`, ADR 0054)
follows every rule below; what it adds is that leaving it does not stop a test,
because the test's state is `services/speedTest/state.ts`'s, a module store, not
the sheet's - so App also does not re-render at the test's ten updates a
second. It is opened from the Network panel's *Speed test* section, never from
the rail. **It is laid out as an instrument** (0054's amendment): a phase
strip, the headline (two medians, RPM and the bufferbloat grade), the latency
boxes on one log axis, a throughput trace per direction with the last run as a
ghost, a footer, then history - one component each beside the sheet. **While a
test runs the dial stands in for the headline** (`SpeedGauge.tsx`, 0054's
second amendment): the owner wants the speedometer every speed test app has,
and it went once already, so it is a decision rather than leftover decoration.

**The monitoring sheet** (`monitoring/MonitoringSheet.tsx`, ADRs 0058-0060) is
the third member and follows the same rules: no rail button, opened from the
Network panel's *Monitoring* section and the palette's `monitoring.open`, and
leaving it does not stop collection, because the client is
`getMonitoringClient()`'s module singleton and the sheet only reads it through
`useMonitoring()` - nothing on the way out resets it. **The first open is what
connects**: main reports no status until `ensureConnected()`, so the panel says
*Not started* until then, and that is the truth rather than a placeholder.
`nothingArriving()` is pure, so the sheet runs its own one-second clock to
re-ask it. Its one way into the capture is "Filter capture by this host",
which is `setFilterText` plus `applyFilter` and therefore closes the sheet onto
Packets like any applied filter. Like the speed test, the view underneath keeps
its rail marker while it is up; only Settings clears it.
`scripts/electron/monitoring-ui.ts` drives all of it against datagrams it sends
itself; `monitoring-shots.ts` photographs every state.

**Three ways out and no fourth**: the title row's back step, reading
"Back to &lt;the view underneath&gt;"; Escape, outermost surface first; and
choosing any view on the rail. **The rail's Settings icon opens and never
toggles**, and while the sheet is up it is the only rail button marked - the
view underneath keeps its place in `view` but loses its marker. Both were
reported as bugs: a toggle made Settings the one button that, pressed again,
sent you back to the last view, and the kept marker showed two surfaces
selected in a card that holds one.

**Landing on a view closes it, and the close belongs to the TRANSITION rather
than to the pane** — the view underneath is untouched while the sheet is up, so
only the code that *chooses* a view can know one is being chosen.
`handleViewChange` closes it, which is the one door the rail and `Ctrl+1..5`
share, and so does `applyFilter`, whose field is reachable with the sheet up and
which navigates to Packets. Clearing navigates nowhere and closes nothing. Both
are asserted, because a navigation nobody can see fails silently.

**Settings search is across every section** (`lib/settingsIndex.ts`), by
word prefix rather than fuzzily - every word typed must start a word of the
row, so `dns` finds Reverse DNS and not Density - and ranked label first, then
keywords, section and description. While results show, no tab is lit. A hit
carries its section's name, switches the tab and lights its row, which
`settingAnchorId` finds as `setting-row-<slug>` - not `setting-<slug>`, which
the switches already own. A query that matches nothing says so, and the first
Escape clears the query before the sheet's own Escape leaves. **A row whose
value differs from its default carries a 2px accent bar and a Reset**
(`settingsLayout.tsx`); `resetSetting` restores that row's own field only,
because three rows share the performance store. The sheet's root wears
`.motion-sheet`, an entrance and nothing else, so it still has no radius or
border.

**The colouring chain is shipped rather than chosen**, which is why there is no
Colouring Rules tab: `parity-check.ts` compares `frame.coloring_rule.name`
against tshark frame for frame, `packetThemes.ts` keys an appearance off every
rule id it expects to exist, and the expert bands assume their own order — three
statements about the chain in `services/colorRules.ts`. The editor's storage key
is in `RETIRED_PREFERENCE_KEYS`, so a chain edited under an old build stops
painting rather than painting something nobody can correct, and
`scripts/color-rules/library.ts` fails if a loader for a stored chain comes back.

#### The frame views

**Frame Detail is a view, and four things are deletions rather than ports from
the modal it replaced**: no `detailPacketId` (it reads `selectedPacket`, so
stepping frames moves the list and coming back lands where you were), no second
`usePacketDetail` (`App` passes `selectedPacketDetail` in, because two hooks on
one frame are two replay requests for one tree), no keyboard gate (the hook
binds Up/Down and the pane binds Left/Right on the same selection), and no
Escape of its own — `App` returns any non-Packets view to Packets in the bubble
phase, and the pane claims the capture phase for exactly one thing, the meta
rail over the canvas, with `stopPropagation`.

**Its empty state is its front door**: `FrameNumberBox`, asking for a frame
number and nothing else, which is what makes `detail` restorable where `stream`
is not.

**The packets view's bottom row is two panes, the tree and the hex dump.** One
divider resizing the pane to its LEFT; the tree's share is stored as a fraction
(`detailsPaneRatio` in `interfacePrefs.ts`, 0.5 with a 0.9 ceiling) and the dump
takes the remainder, because a dump narrower than its own 16-byte row wraps into
nonsense where the tree merely truncates field names — so `flex-1` absorbs
window resizes while the tree keeps the width the user chose. `MIN_PANE_PX`
(220) stops either being dragged to nothing.

**Both wear `components/common/PaneHeader.tsx`, fixed at `h-9`** — a component
rather than a copied class string, because vertical padding sizes a box from its
CONTENTS and identical `px-4 py-2` headers sat 4px apart on adjacent panes. The
packet table's own header row is `bg-card` (`HEADER_CHROME` in `PacketList.tsx`)
and not `--secondary`, which is the chrome's colour rather than a content
surface's.

**Follow Stream's ladder paints with the packet list's colour rules**
(ADR 0055): each chip is `colorEngine.getPacketStyle` in the active packet
theme, so a reset, a retransmission or a zero window reads the same on the
ladder as in the list, and there is no second palette to keep in step. A quiet
run - consecutive frames under one rule, one direction, at least two of them
carrying data - folds into a band (`ladderRuns.ts`). Pure ACKs from the other
lane ride along in it, counted apart and never breaking or colouring it,
because a receiver acknowledges every second segment. A frame with SYN, FIN, RST, an analysis flag or an
expert category never folds, because it is the one somebody opened the stream
to find. A frame named from outside (the selection, a hover, the state map)
opens the band hiding it once per id - per click for the map - not once per
fold, so a band the user closes stays closed. Rows are nudged apart to `MIN_ROW_GAP`, so
the drawing can be taller than the box: bringing a frame into the time window
is not the same as showing it, and `revealScroll` scrolls the box once the
layout has placed the row. `scripts/session/ladder-runs.ts`.

**The RFC 793 state map is docked beside the ladder**, not a tab, because it
is read *against* the frames: hovering an arrow lights the transition it
caused, and clicking a state scrolls the ladder to the frame that entered it.
A click is a `ScrollRequest` object, so a second click on one state is a new
request. The dock is a container query on the pane, `@min-[1180px]`, because
with the side bar open a 1600px window can hand the pane less than a 1024px
one: at and above it the map is always there; below it the map can be put
away for a slim strip, and is open by default because hiding it at the minimum
window hides the feature. Where the lanes are narrow the row's line under the
arrow drops "ordered, not to scale" before it overruns them (`rowMeta`). A
state node takes focus from the keyboard and draws its own `--ring` rect, and
carries `outline-none`, because the browser's outline on an SVG `<g>` painted
a black box over the map on a mouse click. `scripts/session/state-map.ts`
holds the geometry: no label covers most of its own edge, which is why
UNKNOWN to LISTEN is drawn bare.

**Statistics → Conversations → TCP is the whole capture**, from the same
digest, with an Outcome column; the other levels still count the buffer and
keep their "frames X-Y only" note, and the TCP level says "Whole capture", that
the digest is rebuilding, or that a rebuild missed frames and is not the whole
capture. **A TCP or UDP row click opens the stream on the
ladder**; filtering moved to a trailing button on the row, and IP and Ethernet
rows still filter on click, because an IP row is many streams. Follow Stream
and Show conversation in the row menu must never call `onReturnToPackets`: it
ran in the same batch and `setView('packets')` won, so both items landed on
Packets (`scripts/session/digest-rows.ts` reads the handlers).

**`GraphsTab` renders outside `StatisticsPane`'s scroller**, and that is easy to
undo by accident: every other tab is a table and wants `overflow-y-auto`, but
`TrafficTimelineChart` measures its own container, so a parent that grows to fit
its child would size the SVG from a box the SVG is itself defining.

**The speed test's server is an overlay on the map, not traffic** (ADR 0054):
a DOM marker and one arc, read from the speed test's history, never from
`packets` - so it is in no route, pin, count, legend or export, and the arc
joins `ArcLayer` only at `syncConnectionsLayer`'s final `setArcs`.
`scripts/speed-test/map-overlay.ts` reads GeoMap's source to hold that. Its
two colours are tokens, `--speed-download` (the accent) and `--speed-upload`
(purple), which the sheet's headline and traces, the history and the tooltip
all share.

**Exactly one MapLibre instance is ever live** — a fact about the component tree
rather than a condition somebody keeps true, since the Routing Map is a view and
there is no second copy. `display: none` hides a MapLibre instance without
unmounting it, which is why guarding was the weaker answer.
`services/graphPrefs.ts` (`inwire.graphs`) holds what the two charts draw.

#### The card cluster

**Between the two strips the rail, the side bar and `<main>` are CARDS**, which
is VS Code's Modern UI arrangement ported rather than invented — read
`src/vs/workbench/browser/media/floatingPanels.css` in `microsoft/vscode`, and
`.part.activitybar.left` in particular, before changing any of it. **Both of
that file's arrangements are live here and one boolean chooses.** Four facts,
each load-bearing for the others:

- **A 4px gutter** on the band (`pl-1 pr-1 pb-1` in `App.tsx`) holds both cards
  off the window left, right and bottom, and they meet the title row **flush**
  at the top. The chrome's `--secondary` shows in the gutter and is the
  cluster's backdrop.
- **8px on the corners nothing covers** (`--vscode-cornerRadius-large`), **4px
  between cards** (`--vscode-spacing-size40`). Closed, every corner is rounded
  and the cards FLOAT apart; open, the rail's two RIGHT corners square and the
  side bar's two left ones do, because the seam runs between them. The left
  corners are unconditional in both codebases — they face the gutter and can
  never square — so the only corner an edit can get wrong is the one that
  varies.
- **The 4px gap is always one number on the element to the RIGHT**, never a
  `mr-1` on the left card, because two margins are two numbers that have to
  agree. **Which element supplies it moves with the arrangement**: closed it is
  `ml-1` on `<main>`, open it is the sash, which IS the gap. So `<main>`'s
  margin is conditional — `${sideBarOpen ? '' : 'ml-1'}` — and doubling it is
  what a session adding the sash without touching `<main>` would ship.
- **The radius does not break the square-corner rule, it steps around it.**
  Nothing drawing against the window's OWN edge may carry a corner, because
  Windows draws the only curve out there; the gutter means neither card touches
  the window. Delete the gutter and the radius goes in the same commit.
- **The rail draws all four borders in both arrangements and the card that meets
  it gives one up** — the side bar takes `border border-l-0`, shorthand first so
  the give-up is explicit rather than an omission. **Which side owns the seam is
  arithmetic, not taste**: `w-11` under `border-box` is 42px of interior between
  two 1px borders, which centres a 36px target on whole pixels, where handing
  the facing border away leaves 43 and puts the icon column on a half pixel.
  `floatingPanels.css` records the identical finding — so the rail's
  `border border-border` must stay complete and must never become `border-r-0`.

**Neither strip draws an edge of its own**, because `border-box` takes a border
out of the element's height: a `border-b` on the `h-8` title row leaves 31px for
caption buttons that are 46x32, and a `border-t` on the `h-6` bar makes it 23.
The cards close their own edges, which costs the rail 6px —
`scripts/session/view.ts` subtracts them: 680 − 32 − 24 − 4 − 2 = **618**.

**`<main>` has four square corners and `overflow-hidden`.** No surface that
meets the window draws a corner of its own. This is a rule about the SHELL;
radii inside the workspace are untouched by it and are everywhere (242
`rounded-*` utilities). The clip stays because every child of the column scrolls
inside it and their scrollers resolve against this box.

**One seam, and only when the side bar is open**, which is the same fact the
grounds carry. The chrome is `--secondary` — a 13/255 delta against
`--background` in Night, where `--card` was 4/255 and the seam was invisible —
and the side bar is `bg-card` read across that seam, because the rail is chrome
and the column is a titled content surface; a `bg-secondary` column would merge
into the rail and the seam would vanish. The 1px border carries the edge in Day.
`scripts/session/view.ts` asserts the seam **as a pair** — the rail draws it,
the side bar gives its border up — because the two failures are a **doubled**
line and **no** line, each one line wrong in the opposite direction. `<main>`
never has a seam: a 4px gap always runs to its left.

#### The side bar

**A resizable column between the rail and `<main>`**, and it **pushes** rather
than overlays. **The title row's `PanelLeft` button, right of the mark, is the
one control that opens and closes it**; `Ctrl+B` is the same handler
(`toggleSideBar` in `App.tsx`). Four rail buttons pick WHICH panel, opening
the column if it is closed, and never close it - they used to toggle, so
pressing the lit icon to look at a panel again hid the column (owner's report,
2026-10-15). `components/sidebar/` is
the directory, `SideBar.tsx` is the card, `sideBarPrefs.ts` is the state. The
four panels are Interfaces, Schedule, Export/Import and Network.
`ImportErrorDialog` **stays a modal**: a refusal that must be acknowledged is a
detour by every test here.

**Network is a panel and not a view.** It is not in `APP_VIEWS`, it has no
`Ctrl+n`, and `viewPrefs.ts` lands a stored `'network'` back on Packets. **Its
first section is the speed test** (`speedtest/SpeedTestSection.tsx`): the last
result, Run - a tinted outline, the one thing in the panel to press, still
quieter than the facts around it - and Results and history, which opens the
speed-test sheet. Sized for the panel's 170 px floor: the figures stack rather
than squeeze. **Its second section is monitoring**
(`monitoring/MonitoringSection.tsx`): one status line from
`monitoringSummary` and Open monitoring, which opens the monitoring sheet. Its
organising idea is the pairing — the OS says how the machine was told to behave,
the capture shows what actually happened — so it has to sit *beside* the frames
it is comparing against rather than on top of them. Capture Health stays a
Settings tab and is the other read-only report about this machine.

**The persisted state is `inwire.sideBar`** — one key holding `panel`, `open`
and `width`, so a restore is one storage event and one atomic apply.
`MIN_SIDE_BAR_PX` is **170**, cited to VS Code's `sidebarPart.ts`, and
deliberately NOT `MIN_PANE_PX` (220), which defends a hex dump's 16-byte row.
`restoredPanel()` sits beside `restoredView` even though it is the identity
today: it is where a future panel that needs something handed to it declares
itself unrestorable.

**A width is stored unclamped and clamped at the point of use.** The store
clamps only against `[170, 600]`, the window never touches what is stored, and
`usableSideBarWidth(stored, available)` applies `MAIN_RESERVE_PX` on the render
path every time. The failure the split prevents is silent: a drag that committed
the window-clamped figure would let two presses at a narrow window permanently
rewrite a 600px choice, and widening would never give it back.

**`MAIN_RESERVE_PX` is 780**, the width kept for `<main>` before the panel
narrows — measured, because the packet list's fixed columns take ~785px, and the
rule is "guarantee the identity (frame number, time, both addresses) and let the
rest scroll". At the 1024 minimum it still leaves a 192px column, above VS
Code's own 170 floor, so the panel narrows rather than being refused.

**`Ctrl+B` toggles it**, VS Code's own key, through a ref in
`useKeyboardNavigation` rather than a dep — this hook binds a `keydown` on
`window`, and re-registering it ten times a second during a capture is the exact
thing its opening comment exists to prevent.

**Escape does not close it and navigating does not close it**, the exact inverse
of the sheet rule a few lines away in the same file. ADR 0034 exists for those
two negatives specifically, because a negative decision leaves no code behind to
explain itself. `scripts/session/side-bar.ts` asserts them by reading the
**bodies** of `handleViewChange`, `applyFilter` and the Escape effect between
two known ends, not by a character window — the first version of that check
failed on correct code, because `useKeyboardNavigation`'s options object
legitimately contains `setSideBar`.

**The sash is an in-flow `w-1` sibling and IS the 4px gap.** At rest it paints
nothing, two card borders already drawing that edge. **Every resize handle in
the app hovers to `bg-handle-hover`, not to the accent** - a neutral that
follows every theme, because the accent blue reads as a stray line against
Dark's near-black (the owner's report). It is the foreground at 25%, and at 70%
in High Contrast, where a quarter-strength line is not a statement. It carries the full
divider vocabulary: `role="separator"`, `aria-valuenow/min/max` in px, arrows
with Shift for bigger steps, Home/End, and a reset on double-click, right-click
and Enter.

**Adapter sampling is tied to the panel's MOUNT**, not to an App effect keyed on
which panel is open, because a subscription that cannot outlive its display *by
construction* is the stronger tie. The notify callback goes through a **ref**:
its dep list is empty today, and the day it gains one a naked dep array would
rebuild the subscription on every App render — a write down the pipe thirty
times a second with no symptom on screen.

#### The rail

`ActivityRail.tsx` is 44px and starts below the title row — there is no cell
above its first group, because a cell would put the mark below the corner it is
meant to occupy and cost height the rail has not got. **Three groups**:
**capture** (Start/Stop, adapter, schedule, Export/Import, Network — in the
order they are used), **views** (Packets, Frame Detail, Statistics, Routing Map,
Follow Stream), and a bottom group of one, Settings, pinned with `mt-auto`.
Everything above the divider opens a surface beside the workspace; the one below
takes the workspace itself.

**The Follow Stream button follows the SELECTION**, the one entry in the view
group that is a verb rather than a place: `handleViewChange` in `App.tsx`
intercepts `stream` and routes it through `handleFollowStream` with the selected
frame's target. **`Ctrl+5` goes through the same handler**, which is why that
handler sits above `useKeyboardNavigation` rather than with the rest of the
stream state — a `const` cannot be read before it is declared, and the
alternative was the shortcut and the button meaning two different things. The
button stays enabled while a stream is open even if the selection has none, so
the view is reachable while reading a conversation and the icon does not flicker
as somebody arrows past an ARP; the selection wins when both are true.

**The strip is full at 452px of 618** — 11 icons at 36px, two dividers and the
bottom group's padding, against a 680px minimum window less the title row, the
status bar, the gutter and two borders. `scripts/session/view.ts` adds that up
from the Tailwind classes, holds each class to what the sum assumes, and prints
"the rail is FULL" when the answer is no more icons. The rule it produced:
**rearranging the strip is free and growing it is not**, because every group
gaps the same. **The constant through every icon resize is 3px of air either
side**, inside the card's two borders — that is the number to reason from, not
the outer width.

**The two strips are funded differently and that is deliberate**: the window
minimum carries the title row, because the rail had no slack to spare when it
arrived; the rail's own slack carries the status bar, because raising the
minimum to 704 would have cost every small laptop 24px of window for a strip
that fits without it. **If the slack is ever spent, the views group scrolls** —
capture has to stay reachable because it is how a capture starts, and the bottom
group is pinned with `mt-auto`, so an overflow there pushes Settings off the
edge rather than scrolling.

**The active state is a translucent fill in the theme's own accent** —
`--primary` at 20%, `--foreground` on the glyph — and **it never appears on
hover**, because the active marker is the strongest indicator in the UI and
firing it on hover flashes it five times as a pointer crosses the rail. Two
facts about this palette fix the details: a **solid** fill reads as a button
rather than a selection, and `--primary` on a tint of ITSELF cannot reach 4.5:1
in Day at any alpha (it peaks at 3.97 and falls, `#0b6bcb` being a mid-blue the
tint lightens toward), so the glyph takes `--foreground`.
`scripts/themes/registry.ts` reads the alpha **out of `ActivityRail.tsx`** and
holds four numbers to it, the load-bearing pair being the fill's deltaE from the
rail's ground and from its own hover — an active marker a hover can be mistaken
for is not a marker.

**The vocabulary is two marks and `railButton` takes one argument.** The fill
means *this surface is on screen*, however it is arranged; the **dot** means
*the thing behind this button has something to report*. `view.ts` asserts the
signature and that no raw `ring-1 ring-inset` brings a third shape back without
a name. 44 disagrees with `FrameMetaRail`'s 48, accepted rather than overlooked:
one is a group of icons inside a pane, the other is three groups in the chrome.

#### The status bar

24px at the window's bottom edge, `components/status/StatusBar.tsx`. The chrome
is a **C**: the title row across the top, the rail down the left, the bar across
the bottom, all one `--secondary` ground.

**The left group is the session and the right group is the frame.** Left: the
agent link, the adapter, capture state with elapsed time, dropped frames, and
the restore readout — in the order they fail in. Right: the byte readout, the
outbound-lookups indicator, then the packet counter at the edge, which is what
makes the numbers findable without reading the bar. The counter brings no cell
padding, being `PacketCountsReadout` moved here whole rather than a
`StatusItem`, so the group carries `pr-2`.

Five rules, all asserted by `scripts/session/status-bar.ts`, which greps the
whole directory because the easy way to break one is to skip the shared cell:

- **Nothing in the bar is pressable.** `StatusItem` renders a `<span>` with no
  `onClick` at all, so putting one back is a decision rather than a prop. The
  one real control is the packet counter's **`+N UNSEARCHED` rescan**, the only
  way in the app to re-run a whole-capture filter scan — and a bar where most
  things react to a click is worse at advertising the one that does something.
- **An item renders nothing when its subject is absent**, rather than showing a
  zero that was never measured. `droppedKernel` is `null` when the driver's
  counters could not be read and must never be folded into a total as 0.
- **No length in the bar is built from a pane's size.** A status bar groups by
  PRIORITY, never by correspondence with what sits above it —
  `Ln 56, Col 2` is at the window's right edge in every editor that has one. So
  `--details-pane-size` stays on the root element even though only the panes
  read it, and the check fails if the bar ever starts reading it.
- **The hovered byte is a store carrying the byte's VALUE, not an index**
  (`services/hoveredByte.ts`). The bar cannot read `HexViewer`'s local state,
  and a byte derived from `activeByteRange` would also fire for the protocol
  tree's one-byte fields. Carrying the value makes that conflation impossible
  rather than merely avoided: only code that already had the bytes in hand can
  publish one.
- **The outbound indicator carries no glyph** and says `no lookups` or names
  them (`geo-IP`, `rDNS` or both). The state is the text, because the one item
  about *this app's own* behaviour should not be the one you hover to read. The
  warning colour is deliberately not on it: `--warning` on `--secondary` is
  4.06:1, under the floor.

**`agentStatusLabel` is a TOTAL record with no fallback**, so a new kind will
not compile without a label. Its predecessor was a `Partial` with
`?? 'Agent not reachable'` behind it, which read correctly only because its
callers asked while the agent was silent — this bar asks unconditionally, so a
healthy agent read as gone. **A `Partial` with a `??` behind it turns a missing
key into a confident wrong answer.** `scripts/electron/agent-health.ts` holds
the part a type cannot: that healthy states do not read as faults, and that the
text agrees with `agentNeedsAttention` about whether a warning glyph is drawn.

#### Render-path facts that are easy to undo

App re-renders ~10x a second during a capture, which is what all of these are
about. `scripts/session/byte-range.ts` asserts the last three.

- **`LinkedHexViewer` in `components/packet-details/LinkedDetailPanes.tsx` is
  the application's only `React.memo` boundary.** Every other expensive surface
  is unmounted unless its view is active, except the dump, mounted whenever
  Packets is. What the memo rests on: `permissions` in `App.tsx` is a `useMemo`
  with an empty dep list **for this reason alone**, because it was an object
  literal rebuilt every render, and a changed prop is a memo that never hits and
  never says so. The tree beside it is deliberately not memoized —
  `onSelectFrame` closes over `packets`, so its identity changes on every flush.
- **The highlighted byte range is a store** (`services/byteRange.ts`), because
  the cross-highlight between the two bottom panes is state shared by two
  siblings and it lived in `App`, where every pointer move over a byte
  re-rendered the whole application — on a 64KB frame the dump alone is ~79
  virtualized rows of 32 spans. `App` may `resetByteRange` where the selection
  goes and may not publish. **It is not `hoveredByte.ts` and must not be merged
  with it**: that store carries a byte's VALUE so only a dump can publish one,
  this carries a RANGE so the tree can. `PacketDetailPane` subscribes to neither
  and keeps its own `useState`, owning both halves of its own cross-highlight
  and already off App's render path.
- **The dump's hover is delegated, not per byte** — every byte is two elements,
  so a handler pair each was ~5,000 closures built and diffed per render on a
  large frame. `HexDumpView` binds one `mouseover`/`mouseout` pair and reads
  `data-byte`. The `mouseout` must check `relatedTarget`, because it also fires
  moving BETWEEN cells and an unconditional clear would blank the readout on
  every byte crossed. The cells are `transition-colors` and not
  `transition-all`, since the hovered cell also takes `scale-110` and a shadow.
- **`services/packetCounts.ts`**: the counter publishes and its readout
  subscribes, because threading a ten-times-a-second number down through props
  was the regression that shipped once already (`b0ce1fc`).

`lib/windowChrome.ts` is the renderer's half of the bridge: it reports the
resolved theme and the window title to main, and subscribes once at module scope
to maximized/focused.

**`common/QuitConfirmDialog.tsx` swallows every `keydown` while it is open**,
with one capture-phase listener on `window` that calls
`stopImmediatePropagation` - which only silences listeners added after it, so it
works because the dialog is mounted **before `<App/>`** in `main.tsx`. Move it
inside App and Escape navigates the view behind the confirm.

Live agent batches are parsed and dissected in `src/workers/pipeline.worker.ts`,
which owns the ordering window and trackers. React receives batched summaries
and bytes. File import currently runs the same parser on the renderer thread;
see `docs/architecture.md` for that separate path.

