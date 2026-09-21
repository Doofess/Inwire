# History

**Nothing in this document describes current code.** It is the archaeology that
`CLAUDE.md` used to carry: the surfaces that were deleted, the arguments each
live decision won against, and the migration's phase-by-phase record. It was
split out so the document every session reads at startup costs what the current
design costs, and no more.

Read this when you want to know *why* something is not in the app, or when a
change looks like it is re-opening a settled question. Read `CLAUDE.md` for what
is true now.

Two warnings. **Paths here are not checked.** `scripts/docs/claude-md-refs.ts`
resolves every backticked path in `CLAUDE.md`, `local-agent/CLAUDE.md` and
`README.md`; this file is deliberately not in that list, because most of what it
names no longer exists. **And the reasoning here is as of its deletion.** A
decision recorded as won may have been reversed since; `CLAUDE.md` is the status
of record and this is the trail.

---

## 1. The shell, revision by revision

The renderer's chrome was rebuilt three times. What follows is each container
that was tried, and what it cost.

### `Header.tsx` — the 64px accent bar

The first shell was a full-width accent-coloured header with a hamburger drawer
hanging off it. Its contents split three ways when it went: into the title row,
the activity rail and the (then) filter row. The four `--chrome*` tokens existed
to paint it, and the **Colourful** theme setting existed to choose whether they
were accented — by the end the only thing that switch still changed was making
the brand mark invisible, white on white in the light themes. Its checks in
`scripts/themes/registry.ts` went on passing throughout, because they measured
the mark against `--chrome`, the bar it had stopped sitting on. That is the
shape worth remembering: **a check that outlives its subject passes for ever.**

### `AppMenu.tsx` — the hamburger drawer

Seven entries. **Three already had a rail button** (Capture Statistics, Network,
Settings), **Export/Import became** the one new rail button, and the rest went
to Settings: the two passive name-resolution switches to `Interface` beside the
two outbound lookups already there, and Custom Dissectors to a tab of its own
beside Decryption. Nothing that duplicated a visible control survived, which was
the menu's own stated rule turned on itself. `cmdk` left `dependencies` with it.

### `FilterRow.tsx` — the 44px strip

A row spanning the window to hold one line of text, and the rule it carried had
been rewritten three times: "only Network hides it", then "no view hides it",
then "it is rendered by NAMING Packets". All three argued about where to put a
ROW; none asked why a filter had to live somewhere a view could hide it. It does
not act on what is in view — `captureScan` answers it over the whole capture on
disk — so it belongs to the app, and it moved into the title row's centre.

The row also carried the **agent-fault banner**, which named the fault above the
packet list while the status bar named it below; one fault wants one place. And
it carried the **restore readout**, which was the first thing dropped when space
ran short — a strange fate for the only sign the app is busy doing what it was
asked. Both moved to the status bar's left group.

Two smaller things went with it: the filter's **count badge** (`filterPercentage`),
which read `100%` beside `2,224 / 2,224` — one figure said twice in the weaker
unit — and a **presets chevron that only opened the list**, which was a second
door onto a room whose first door is the whole width of the bar. The chevron
came back as a *toggle*, which is a different control.

### The dock, and the widget apparatus

The dock replaced a right-hand column, which had replaced a `DashboardAside`
with a collapse-to-a-rail morph. When it went, the whole apparatus went with it
rather than being relocated again: `components/dock/`, `WidgetCard`,
`WidgetOverlay`, `RenderedWidget`, `dashboardWidgets.tsx`,
`DashboardWidgetList`, both preference keys (`inwire.dock`, `inwire.dashboard`),
and the two assertion scripts that covered them.

The question it kept re-raising in a new shape: **what is a widget, if every
widget that survives has somewhere better to be?** Six existed. Packet counts
became a readout; Protocol breakdown and Top talkers were deleted outright; the
map became a view; and the traffic timeline and packet-size charts became a
Statistics tab. Each of those is a surface with one home and its own controls,
which is what a widget was simulating with an open flag, a pin, a drag-reorder,
a per-widget config bag and a shared overlay.

`<main>` was a **row** for exactly one revision, so the dock could run the
pane's full height beside the filter row — an arrangement that existed to say a
widget summarising the whole capture had no business sitting under a row that
narrows the list. Deleting the dock answered the same question by removing the
thing that raised it. `<main>` is a column again.

The rail had a **fourth group** for the widgets: six icons with a 20px collapse
header in the divider slot above them. None of the three surviving widgets
needed an open flag, a pin, a drag-reorder or an overlay.

Three things the dock knew, all of which found new subjects:

- **`LIST_RESERVE` was 640 and did not fit every column.** Measured: the fixed
  columns take ~785px, so Protocol, Length and Info were off-screen at the
  reserve and the list scrolled horizontally to reach them. It was still right,
  for a reason about the window rather than the columns — a reserve large enough
  to keep every column would have meant the dock could not open **at all** at the
  1024 minimum. The general form is "guarantee the identity — frame number,
  time, both addresses — and let the rest scroll", and its live subject is
  `MAIN_RESERVE_PX` in `sideBarPrefs.ts`. That constant is **780**, not 480, and
  the 300px correction is the reserve's own history repeating: 480 was picked as
  a number that felt like enough, and at 480 the identity the rule exists to
  guarantee would have been the thing that scrolled.
- **A width or a share is stored unclamped and clamped at the point of use.**
  `clampDockWidth` applied against the window, so narrowing shrank an open dock
  and widening gave back the width the user chose; a width clamped on the way
  out would never have grown back. The rule outlived the dock, then outlived the
  two pane shares it moved to, and its live subject is `inwire.sideBar`.
- **`Dock` was the application's only `React.memo` boundary.** App re-renders
  ~10x a second during a capture and every widget did a full pass over the
  buffer, so the dock had to absorb that. The surviving surfaces are unmounted
  unless their view is active, which is a stronger version of the same
  guarantee — except the hex dump, which is mounted whenever Packets is, and
  which is the boundary now.

### The first application status bar

It carried the byte inspector, and a full-width bar's natural left edge is the
window's — while a line about the hex dump, a pane away from the thing it
describes, starts under the rail. So the readout was pushed sideways with a CSS
length built from `--details-pane-size`, and the bar was a row of two blocks so
that a percentage would resolve against `<main>`'s content box rather than the
window. All of that machinery existed to make a window-spanning bar look like it
belonged somewhere narrower, which is the definition of a bar in the wrong
place. It was deleted and the readout went back to Hex View's own footer.

**What was wrong was the alignment, not the bar.** A status bar groups its items
left and right by PRIORITY and never by correspondence with what sits above
them — `Ln 56, Col 2` is at the window's right edge in every editor that has
one, and nobody expects it over the cursor. Adopting that rule deleted the
machinery instead of rebuilding it.

The second failure is subtler than the indent. The bar could not read
`HexViewer`'s local hover state, so it was handed a byte derived from
`activeByteRange` — which is **also** what the protocol tree publishes for a
one-byte field, so the bar answered "this byte" for a hover in a pane that was
not the dump. The replacement is `services/hoveredByte.ts`, a store carrying the
byte's **value** rather than an index, which makes the conflation impossible
rather than merely avoided.

Two more things the second bar changed. Every item used to **open the Settings
tab that fixes what it reports**; the bar is a readout now, and the one real
control in the strip is the packet counter's rescan. And the **outbound
indicator was a glyph** — a shield when nothing was going out, a globe when
something was, with the names hidden below `xl` — so the one item about *this
app's own* behaviour was the one you had to hover to read.

**`--geo-pane-size` had never been in the React style object at all**, only in
the imperative drag path, so the map pane had no width until somebody dragged
something. The bar that found it is gone and the property is gone with its pane;
the trap it records is that **a layout custom property written only by the drag
path has no value until a drag.**

### Find packet

A substring match over protocol, addresses, info and id across the rows in hand.
It was deleted in favour of Frame Detail's go-to-frame box, which takes **a
frame number and nothing else**. The argument: the display filter already
answers those questions in a language that says what it means, and answers them
over the **whole capture on disk** rather than over the window — so the search
was the weaker of two overlapping answers, and two search boxes in one window is
what the rail exists to prevent. `inwire.packetSearch` is in
`RETIRED_PREFERENCE_KEYS`.

Deleting it and promoting Frame Detail were **one change**: the rail lost an
icon from the capture group and gained one in the views group, and because both
groups gap the same the two deltas cancel.

### The Updates button

`onOpenUpdates` and `onOpenSettings` were the same handler, and `updateAvailable`
was passed `false` at the only call site, so its badge could never light.
Export/Import took the slot. If the badge is wanted back it needs a real
`updateAvailable` first, and Settings is the icon to hang it on.

### Two modals that became places

**Settings** was `fixed inset-0`, a 70% scrim, a `max-w-5xl` panel at
`max-h-[90vh]`, an X and a Close button — all of which said "you are somewhere
else for a moment", about the surface that holds the filter presets, the
decryption keys and the Update Center. The X and the Close button did not
survive the move: a surface with four doors is one nobody knows how to leave.

**The packet detail window** was `fixed inset-0`, a scrim and a 92vh panel,
opened by double-clicking a row and dismissed with Escape or an X — which meant
the one surface that shows a frame in full could only be reached from the one
surface that shows frames in summary, and was *dismissed* rather than *left*.
Four things fell out of promoting it to a view, each a deletion rather than a
port: `detailPacketId`, a second `usePacketDetail`, the keyboard gate in
`useKeyboardNavigation`, and its own Escape.

### The title row's centre

It showed `windowTitleFor(...)` — `Inwire` idle, `Ethernet - capturing - Inwire`
capturing. That string is unchanged and still names the window for the OS
through `useWindowTitle`; what it stopped doing is spending the centre of the
one strip nobody can look away from on the app's own name, which the mark at the
corner already gives. The packet counter took the slot next, and then moved on
to the status bar — which is where `windowChrome.ts` always argued it belonged:
**a number that changes is the most distracting thing that can go in a title
bar.** That comment's second half — "the count is already on screen, in the
filter bar" — stopped being true twice over.

The **`INWIRE` wordmark** was in the corner beside the mark. The word named the
app in a caption that already names it twice. With it gone the mark sits
directly above the column of rail icons rather than 8px to their left; that
alignment is why the mark used to live in a rail cell, and losing it was the
stated cost of letting the word lead.

The **back step** was in that 138px corner too, which is where an application
usually puts one and is the argument it lost: the corner is the app's identity,
a control appearing and disappearing there reads as part of the mark's block,
and it was as far from the row's only other navigation as the row allows.

**`<main>`'s top-left corner carried `rounded-tl-xl`** on the argument that it
is the one corner where two chrome edges meet rather than an edge of the window,
so it was allowed to curve. Squaring it made the shell's rule general instead of
nearly-general. `overflow-hidden` was load-bearing for that curve — the deleted
`FilterRow` painted its own `bg-background` straight into the corner — and it
stays for a different reason now.

### Custom Dissectors

**It was never wired to anything.** `App.handleUpdateDissectors` was `() => {}`
with a comment admitting it: the engine was built in a `useMemo`, handed to the
settings pane, and **no dissection path ever asked it about a frame**. Rules
were edited, validated and stored, and applied to nothing. The comment called
that "a gap rather than a design" and left the seam in place for an
implementation that did not come — which is the reverse of this repository's
rule everywhere else, because **a surface that does nothing is worse than a
missing one: it tells the user the feature exists.** Nothing in the assertion
suite covered any of it, which is its own small verdict on what it was worth.

Settings had widened from `max-w-3xl` to `max-w-5xl` to take its editor.

### Colouring Rules

Deleted because **the chain is shipped rather than chosen.** Colouring is the
one part of this UI whose whole job is to be opinionated about which frames
matter, and an opinion the user can rewrite is one the app can no longer stand
behind — three separate things are statements about the shipped chain.
`canChangeColorRules` and `canEditDissectors` left `Capabilities` with their
readers, and `SettingsPane` takes no `permissions` at all now.

### Network, and its four containers

It was the third view, on `Ctrl+3`, and it failed the test the view list
applies: **a view is a way of looking at the capture.** Network describes the
*machine* — adapters, DNS, public identity — and nothing in it changes when a
packet arrives. The tell was the filter row, which had to be hidden above
Network and nowhere else.

"Not a view" was then read as "therefore a Settings tab", and Settings is where
the app is *configured* while Network configures nothing; so it became a
**sheet** taking the workspace card. **The sheet is what the side bar
corrected**: this panel's organising idea is the pairing — the OS says how the
machine was told to behave, the capture shows what actually happened — and as a
sheet it covered the capture in order to describe the machine the capture came
from. "Observed (capture)" was a live column with its subject hidden behind it.

### The map's second copy

The map had a small copy in the packets view's bottom row, guarded on
`view === 'packets'`, because `display: none` hides a MapLibre instance without
unmounting it. Deleting it made "exactly one map is ever live" a fact about the
component tree instead of a condition somebody has to keep true — **which is the
reason to prefer deleting a surface over guarding it.**

As a pane it ran widest-subject to narrowest: the map is the whole conversation
between two places, the tree is one frame of it decoded, the dump is that
frame's bytes. Deleting it took back `geoPaneRatio`, the second divider, the
render-time clamp that kept two independent shares from adding past 1, and the
`view === 'packets'` guard.

### The rail's icon sizes

The target went **36 → 44 → 36** and the glyph **20 → 24 → 20**, at 8px an icon
each way. Six deleted icons and a 20px header paid for the first; the second is
what a 44px rail costs, since a 44px target inside it would leave the button's
edges touching the card's own. The constant through all of it is **3px of air
either side**, inside the card's two borders.

That arithmetic decided real design questions rather than merely recording them:
it is why the two name-resolution switches went to Settings rather than the
rail, and why the brand mark lives in the title row and not in a rail cell. Both
still hold on their own arguments now that the number no longer forces them.

### The rail's third marker shape

There were three at the widest: the fill, an **outline** meaning "this control
is ON", and a **dot** for a widget open in the dock. The outline's last two
callers were the adapter and the schedule, and both open a side bar panel now,
so both wear the fill. What the outline carried moved to the dot. The
`'view' | 'toggle'` parameter went with the branch rather than being kept for a
future caller, because **a marker shape nothing draws is a shape the next
session has to guess the meaning of.**

The active fill was also **two things**: an `--accent` fill under a 2px left
edge. `--accent` is one step off the rail's ground, so the edge did the work and
the fill was barely a tint — weaker still once the rail moved to `--secondary`.
Tinting with the accent HUE inverts that, and an edge in the same colour drawn
over a button already filled with it is a second mark for one fact.

`DASHBOARD_RAIL_WIDTH` was the other half of the sentence about why the rail
disagrees with `FrameMetaRail`'s 48, and it went with `dashboardPrefs.ts`.

### What each side bar panel gained

**Nothing was pasted in, and that was the rule the work was done under.** Each
of the four was shaped by a constraint the column removes:

- **Interfaces** was a 288px Radix dropdown capped at `max-h-80` and dismissed
  on select. The sparkline's `MAX_SPARKLINE_WIDTH = 130` was derived in its own
  comment from `w-72` minus padding — wrong by construction in a column whose
  width is a preference — so it is derived from the stored width now. Radix's
  typeahead is **lost**, said plainly: it was reachable only while a menu was
  open, had no affordance, and covered three to eight rows.
- **Schedule** was capped at 512px tall, which is why only one field's calendar
  could open — `CaptureSchedulePicker` said so in as many words. Two disclosures
  now, and the countdown `describeSchedule(...)` was computing **only to fill a
  rail tooltip** is the header's `detail` line: a live "Stops in 14:58".
- **Export/Import** was a 768px modal with a scrim over an app whose subject is
  on screen behind it. `ExportPanel`'s `pt-9` reservation for a floating
  validation banner was deleted, not tuned — in a 300px column it was 36px whose
  only job was to be empty.
- **Compare**'s two columns stack, `CompareHeader` is deleted, and the `w-40`
  nav went with them.

### `inwire.dashboard` → `inwire.graphs`

A new key rather than a rename, because the old one was a
`Record<string, string | number>` config bag validated against a widget
catalogue — shaped that way so a settings list could be generated from it. There
is no catalogue and no generated list; the fields are fields.

### `DriverInfoPanel`'s four deleted rows

Status, Version, Capture and Listening on said what the status bar now says
permanently, and the first of them did it through a SECOND status label table
that could disagree with `agentHealth.ts`'s. All four are deleted and the tab is
**Capture Health**.

---

## 2. The window frame, reversed

The window was framed, then frameless, and the premise the framed decision
rested on was **two-thirds wrong** — which is what made the reversal cheap and
is worth recording as a class of error.

The comment in `window.ts` used to say `frame: false` would hand back "the
resize borders, snap layouts, the system menu on Alt+Space and the shadow".
Electron's typings say `thickFrame` (default **true**) is what keeps edge
resizing, the drop shadow and the window animations, and `roundedCorners`
(default **true**) is Windows 11's radius. **A frameless window on defaults
keeps all of it.** What is actually lost is Snap Layouts and Alt+Space, both now
recorded in `docs/verification.md` as accepted losses.

The overlay era left two things behind. The dim on blur was a **pre-composited
colour pushed over IPC** — the whole `mixHex`/`setTitleBarOverlay` apparatus —
where the controls being ours makes it `opacity` on a row. And the button
reserve had to come from `env(titlebar-area-width)`, because Windows drew it at
~138px at 100% scaling and ~207px at 150%; `.titlebar-reserve` and the `env()`
are gone.

The chrome's ground moved from `--card` to `--secondary`. `--card` against
`--background` is a 4/255 delta in Night, so the seam where the chrome meets
`<main>` was invisible and the 1px border was the only thing the eye could
follow along it; at `--secondary` the delta is 13/255. That argument was first
made about a rounded notch cut out of the chrome; the corner is square now and
the deltas are unchanged, because they were always about two grounds meeting
rather than about a curve.

---

## 3. Two version numbers became one

**There were six stamps and two scripts covering different subsets of them.**
`local-agent/test_protocol.py` read the *legacy* `.iss` — and it is Python, so
`scripts/check.ts` (which discovers TypeScript) never ran it; a second script
read both `.iss` files and ran unprompted. Between them the shipping installer's
stamps went unread by anything at all for months.

The agent had a number of its own because it was once installed by its own
installer against a web page of any age. One installer carries both halves now
and replaces them in one transaction, so two numbers could only ever disagree by
mistake. The collapse is why the product jumped to **4.0.0**: the survivor has
to be at least the highest either half ever shipped, and the agent had shipped
3.9.0 while the app was on 1.0.0.

---

## 4. The Electron migration

*The table is a record of what landed when. Read `CLAUDE.md` §3 for the result;
read this for the order things happened in.*

| Phase | What | Landed |
|---|---|---|
| 1 | The Electron shell, `app://inwire` | `ce9d4d8` |
| 2 | The capture store on real files, in its own process | `9971b45`, `bcf3c58` |
| 3 | The named pipe; the token deleted; the agent bundled | `677cc41`…`4bbbfc7` |
| 4 | Native save dialogs | `8b7be01` |
| 5 | The web page deleted | `6d97c46`…`4010d7b` |
| 6 | Installer, signing, updates | deprioritised — `d2423f2` |
| 7 | Rebuild what the browser forced | `73e5c26`…`3879433`, `380976e`, `b07f165` |
| 8 | Import-to-disk; `captureScan` wired to the filter bar | `1bfcbf9`, `93cd08b`, `7c5dd21`, `992b1d5` |

The plan was `~/.claude/plans/lets-pick-up-where-agile-shore.md`, repurposed for
the Update Center.

**Phase 7 landed on 2026-09-13**, in the thirteen commits that row spans: the
window's own title bar, the activity rail (56px then, 44 now), the dock that
replaced the right-hand column, the hamburger's deletion, and Custom Dissectors
and Network becoming Settings tabs.

**The shell had a second pass after that date**, which is why the Phase 7 row
still names the dock — built in that phase and deleted after it. What changed
since: the dock and its whole widget apparatus deleted, Custom Dissectors
deleted, Frame Detail promoted from a modal to a view (so `Ctrl+2` is it and the
three views after it each moved a key), Find packet deleted, the app-wide status
bar reverted to `HexViewer`'s own footer and then rebuilt properly, the filter
row scoped to Packets alone and then deleted, and the chrome moved from `--card`
to `--secondary` with the `INWIRE` wordmark deleted.

**The Npcap question was answered rather than blocking.** It was "does the
silent install need an OEM licence", and the answer is yes — so the installer
stopped installing it. ADR 0032.

**The ADRs the migration owed are written**: 0027 (the app is a desktop app),
0028 (where the store runs, with the boundary measured), 0030 (one installer),
0031 (the whole-capture filter). 0029 was already there. 0032 followed, for the
update path.

**On the wire, nothing changed when the WebSocket went.** The 18-byte record and
every control message were already transport-agnostic; only the framing is new.

---

## 5. Typography and theming, before the current answer

### Three typeface pairs

The tokens carried **Geist with JetBrains Mono**, then **IBM Plex for one day**
(`7b4dded`), then Segoe UI Variable with Cascadia Mono. Plex closed the seam the
unrelated pair showed under every table header and was retired on taste — square
and dated beside the desktop. Segoe with Cascadia closes the same seam, being
Microsoft's two faces drawn for the same screen, and costs no webfont at all.

**There was a typeface picker**, in the Accessibility tab: Geist / Atkinson
Hyperlegible / Nunito, rewriting `--font-sans` at runtime. It was deleted
because a setting that moved the sans and not the mono put the seam back for
exactly the readers who reached for it. **Atkinson Hyperlegible went with it,
and that is a real loss taken knowingly** — it was drawn to separate I/l/1 and
O/0 for low-vision readers, Segoe does not do that job, and nothing replaced it.
Reopening that question means a picker where every option carries a matched
mono.

### Four themes became two

Day, Night, **Paper** and **Graphite**. Paper and Graphite were cut because each
existed as the other survivor's warm counterweight, which was an argument for
four and not one for keeping a spare of each.

**Night took the `dark` id from Graphite**, and that was the cut paying for
itself: next-themes writes `color-scheme` only for the literal strings `light`
and `dark`, so while the neutral dark theme was stored as `midnight` the native
scrollbars and form controls stayed on the light side of the divide for the
theme most people use.

### The Colourful setting

See `Header.tsx` above. Four `--chrome*` tokens, a 64px accent header and a menu
drawer, all deleted; by the end the switch only made the brand mark invisible.

---

## 6. Two brand marks before this one

The first was **generated rather than drawn** — one ribbon spiralling round a
sphere, a spiral spec and a projection emitting about 140 flat fills per tier.
The second was a **head-on RJ45 connector**, drawn, with eight contacts and a
bevelled cavity. The third and current one is five isometric plates.

What has not changed across all three is the module's JOB: **one source, every
icon generated from it, colours there and not in the component** — which is why
the art is ported into `brandMark.ts` each time rather than committed as the
artist's `.ico`. A binary dropped in beside the pipeline is exactly the drift
the regenerate-and-compare check exists to catch.

Two details that moved with the art. **`MARK_SIZE` was 256** while the mark was
drawn at that size; the current one is authored in a 100 box, so the box followed
the art — scaling the coordinates to keep the old constant would have made every
number a decimal. And the previous mark **painted an opaque `#0c0a09` square
behind itself**, on the argument that Windows composites against grounds nobody
can predict — which is true, and is an argument for a mark that reads on any
ground rather than for shipping a black tile into the taskbar, Alt-Tab and
Explorer.

**`Inwire.exe` had no icon at all** until the current pipeline landed:
`electron-builder.yml` had no `win.icon` and `directories.buildResources`
pointed at a folder that did not exist, so the packaged app shipped Electron's
default and nothing in the suite could see it.

---

## 7. Lessons that outlived their subjects

Collected because each is a shape rather than a fact, and each was paid for.

- **A check that outlives its subject passes for ever.** The Colourful checks
  measured the mark against a bar it had stopped sitting on.
- **A fixture only proves something if the end that authored it is not the end
  being tested.** Three witnesses agreed on `set_interfaces` and none of them
  was the app.
- **A message is a snapshot: it always copies.** A `plainForStore` that returned
  the packet unchanged when there was nothing to fold would have fixed nothing,
  because the block is attached a microtask later.
- **A `shift()` inside a predicate runs once per comparison, not once per
  match**, and a non-null assertion over a `find` is where `undefined` gets into
  a list.
- **A `useCallback` in `App.tsx` is unreachable from this suite**, so arithmetic
  worth testing has to be lifted somewhere a script can import it.
- **A layout custom property written only by the drag path has no value until a
  drag.**
- **A marker shape nothing draws is a shape the next session has to guess the
  meaning of.**
- **A surface that does nothing is worse than a missing one**: it tells the user
  the feature exists.
- **Prefer deleting a surface over guarding it.** "Exactly one map is live"
  became a fact about the component tree rather than a condition to keep true.
- **A `Partial` record with a `??` behind it turns a missing key into a
  confident wrong answer** rather than an absence anybody would see.
- **Rearranging a fixed strip is free; growing it is not.** Derived once is a
  coincidence; the same arithmetic twice, in opposite directions, is a rule.
