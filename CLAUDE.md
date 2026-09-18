# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

> **Must not come back.** These were deleted deliberately and re-adding any of
> them undoes a decision, not a cleanup:
>
> - the **pairing token**, `authenticate`, `authRequired`, `auth_required` /
>   `auth_failed` — the pipe's ACL is the authentication (ADR 0029)
> - the **origin allowlist** and `is_origin_allowed` on Windows
> - **`ws://localhost:8999` on Windows** — the port is not opened at all
> - a **browser build**, a **service worker**, an **SPA fallback**, or anything
>   under `public/` that is not a static asset the app itself loads
> - a **phone layout** — the window minimum is 1024 and `md:` is 768
> - **`nodeIntegration`** in the renderer, in any form, for any convenience
> - **`thickFrame: false` and `roundedCorners: false`.** The window *is*
>   frameless and draws its own controls - that entry was reversed deliberately,
>   and the one it replaced was wrong on the facts. What it claimed frameless
>   costs, Electron's typings say those two options cost: `thickFrame` defaults
>   true and is the only reason edge resizing, the drop shadow and the window
>   animations survive; `roundedCorners` defaults true and is Windows 11's
>   radius. Neither is ever set, at any value, and `scripts/electron/shell.ts`
>   asserts the words do not appear (`electron/window.ts`)
> - **`titleBarOverlay` / `titleBarStyle`.** Bringing either back means Windows
>   drawing a second set of caption buttons on top of the app's own - which
>   renders rather than throws
> - **`window.destroy()` on the close path.** The quit guard is registered on
>   the `close` event, so destroying skips the "unsaved frames" confirm and
>   discards a capture on one click
> - **`/S` on Npcap's installer**, anywhere, for any reason — it is the OEM
>   silent-install feature and the free licence does not grant it (ADR 0032).
>   Npcap's wizard is shown, because its licence is shown with it
> - **a mirrored copy of Npcap.** It is fetched from npcap.com or not at all
> - **in-process capture in the app** — a native capture addon in main or in a
>   `utilityProcess`, or any capture handle opened by Electron. The separate
>   agent is a security and lifetime decision, not browser-era weight
>   (ADR 0033)

## 1. What this is

Inwire is a **Windows desktop network packet analyzer**: an Electron app whose
renderer is React + Vite served from a custom `app://inwire` scheme, plus a
Python capture agent that ships inside the same installer and runs as a
LocalSystem service. The app talks to the agent over a named pipe. Protocol
dissection, filtering, colour rules, expert analysis, statistics and pcap /
pcapng import and export all happen client-side in TypeScript.

Everything is local. There is no account, no backend, no telemetry, and no
server of any kind in this repository. The only outbound requests are four
optional lookups from the renderer and two from main - the update feed and
npcap.com - all listed under **Invariants**, and every one of them behind a
switch or a click.

What it is **not**, any more: a web app. There is no browser build, no
`server.ts`, no Express, no hosted deployment. macOS and Linux still have a
tarball-installed agent that speaks WebSocket, but there is no desktop app for
them yet.

**The agent survived that deletion on its own merits.** A page could not open a
capture handle, which is why the agent was built — but that is no longer why it
is here, and a session reading the topology below should not conclude it is
weight the browser left behind. It is kept so Npcap can be installed
**admin-only**, so a capture can outlive the window, and so the capture handle
never lives in the process that parses hostile bytes. ADR 0033.

## 2. Commands

- `npm run dev` — Vite plus Electron, for iterating on the UI. Runs the
  renderer from a dev server; the `app://` handler, the MIME table, the 404
  rule and the CSP all behave differently here, so this is not where those get
  tested.
- `npm run start:app` — build and launch Electron against `app://` **without
  packaging**. The only way short of a full pack to exercise the protocol
  handler and everything downstream of it. It goes through
  `electron/start.cjs` rather than `electron .` for one reason: `devFeed.cjs`,
  so a launch does not open by failing DNS against a domain nobody has
  registered. Same `dist/`, same handler.
- `npm run build` — Vite builds the renderer into `dist/`, then
  `electron/build.cjs` esbuilds `main`, `preload` and the store entry into
  `dist-electron/` as **`.cjs`**.
- `npm run pack` — `electron-builder --dir` into `release/win-unpacked/`.
- `npm run lint` — `tsc --noEmit` over both programs. It does more than the
  name suggests: `strict`, `noUnusedLocals`, `noUnusedParameters` and
  `noFallthroughCasesInSwitch` are on, so an unused import or an unread local
  fails the build. `noImplicitReturns` is deliberately off.
- `npm run check` — lint, then every assertion script under `scripts/`,
  discovered by walking the directory.
- One script on its own: `npx tsx scripts/capture/reader.ts`.
- `npx tsx scripts/parity/parity-check.ts` — the dissection acceptance gate.
  Skips without the untracked fixtures.
- `pyinstaller local-agent/inwire_agent.spec` — builds the agent to
  `local-agent/dist/inwire-agent-windows/` (a **directory**; see
  `local-agent/CLAUDE.md`).
- `iscc installer/setup.iss` — compiles the unified installer to
  `installer/output/Inwire-Setup.exe`. Needs `npm run pack` and the PyInstaller
  build to have run first.

**Every assertion script runs under plain `tsx`, with no Electron and no
browser.** That is a property to protect, not an accident: it is what makes the
suite runnable in CI on ubuntu and fast enough to run on every commit. The
pattern for anything that needs Electron is to split the decision into a module
that does not import it — `electron/pipeTransport.ts` beside `agentPipe.ts`,
`electron/saveTarget.ts` beside `saveFile.ts`, `src/services/agentHealth.ts`
beside `electron/agentService.ts`.

## 3. Process topology

```
  agent (Python, LocalSystem service)
    │  named pipe \\.\pipe\inwire-agent, SDDL-gated
    ▼
  main (Node)  ── app:// handler · window · menu · quit guard
    │            agent supervisor + health · native dialogs
    │
    ├── utilityProcess: capture store  ── NodeBlockFile → %LOCALAPPDATA%
    │     ▲ MessageChannelMain
    │     │
    └─────┼──────────────── MessageChannelMain ──────────────┐
          │                                                  ▼
  renderer (sandboxed Chromium)                      pipeline Worker
    React UI ── pipelineClient ──────────────────────  dissection
    ferries both ports across, then sees no frame      trackers
```

### The agent — `local-agent/agent.py`

Runs as LocalSystem, deliberately, for three reasons in this order (ADR 0033).
It is what lets Npcap be installed **admin-only**, because with the agent
holding the handle the app never needs to open one. It is what lets a capture
outlive the window — boot-time start, a ring buffer, unattended monitoring —
none of which a process that dies with its UI can offer. And it keeps the
capture handle and the driver's user-mode library out of the process that
parses hostile bytes, and off Electron's native-module ABI. The Windows fact
behind the first of those: Npcap's **default** install leaves the capture
devices open to every local user, so any local account can read this machine's
traffic and inject raw frames; restricting them to Administrators is the
recommended install, and a LocalSystem agent is what makes that cost the user
nothing. Sniffs nothing until a client sends `start_capture`, and stops when
the last client disconnects. Reads frames with `pcap_next_ex` directly rather than through
scapy's socket wrapper, raises the driver's kernel buffer to 32 MB with
`pcap_setbuff`, and reports what the driver dropped via `pcap_stats`. Frames
are queued on the sniffer thread, bounded by both a count and a byte budget,
and drained into batched binary messages by one pump task.

It carries the driver's timestamps, a per-capture sequence number, and the
interface index. It does **not** dissect: a record has no source, destination,
protocol, ports or info, because the app dissects the bytes itself and always
overwrote those anyway (ADR 0010).

On Windows its only transport is the named pipe, created with the security
descriptor `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`. `IU` is the point — the
service is LocalSystem and the app deliberately is not. `WD`, `AN` and `NU` are
absent because a pipe answers over SMB unless the descriptor says otherwise.
`local-agent/pipe_server.py`; ADR 0029.

### main — `electron/main.ts`

A thin adapter over things only a privileged process can hold. It owns the
`app://` handler, the window, the menu, the quit guard, the pipe client, the
agent's service diagnosis, native save dialogs, and the capture store's
lifetime. Every decision worth testing is in a module beside it: `appPaths.ts`,
`window.ts`, `csp.ts`, `menu.ts`, `windowState.ts`, `saveTarget.ts`,
`pipeTransport.ts`, `agentService.ts`, `windowColors.ts`.

**The window is frameless and draws its own controls.** `frame: false`, and a
32px title row carrying the app's own minimize / maximize / close. This reverses
an earlier decision; the banner says which options must never come back and why.

**The premise the old decision rested on was two-thirds wrong**, which is worth
recording because it is what made the reversal cheap. The comment in
`window.ts` used to say `frame: false` would hand back "the resize borders, snap
layouts, the system menu on Alt+Space and the shadow". Electron's typings say
`thickFrame` (default **true**) is what keeps edge resizing, the drop shadow and
the window animations, and `roundedCorners` (default **true**) is Windows 11's
radius. A frameless window on defaults keeps all of it.

What is actually lost, and accepted: **Snap Layouts** (the flyout on a
maximise-button hover - it needs `WM_NCHITTEST` to answer `HTMAXBUTTON`, and
Electron exposes no hook; Win+Arrow snapping is unaffected) and **Alt+Space**
(there is no native caption to raise the system menu from). Both are in
`docs/verification.md` as accepted losses rather than as things to re-check.

Three things follow, each a trap with a comment on it:

- **The controls are ours, so they follow the cascade.** `WindowControls.tsx`,
  46×32 with 10px glyphs - Windows' own metrics, because the target size and
  spacing are what muscle memory aims at. The dim on blur is `opacity` on the
  row, not a pre-composited colour pushed over IPC, which is the whole
  `mixHex`/`setTitleBarOverlay` apparatus deleted. One colour is hardcoded and
  only one: close hovers to `#c42b1c`, which is learned rather than designed.
- **The ground is cached in `window-state.json`.** `backgroundColor` is fixed
  when the window is constructed, before a renderer exists to report a theme -
  so the alternative is opening every window in one theme and correcting a beat
  later. That was survivable when a native caption sat above the page; on a
  frameless window the ground IS the app's surface, so it is a full-window
  flash. `windowColors.ts` is the table, and the theme still lives in
  `localStorage` - this is a cache of what it resolved to, written by the
  renderer, never the source of truth. Same argument as window bounds, which is
  why it is the same file.
- **The reserve is a constant again, and that is what frameless bought.** Under
  the overlay the button area had to come from `env(titlebar-area-width)`,
  because Windows drew it at ~138px at 100% scaling and ~207px at 150%. The
  buttons are elements now, so they are 138 CSS pixels at every scale factor;
  `.titlebar-reserve` and the `env()` are gone.

`maximize`/`unmaximize`/`focus`/`blur` are forwarded to the renderer over
`WINDOW_STATE_CHANNEL`, because a window drawing its own chrome has to know what
the OS used to draw: a restored window must not paint into the frame's rounded
corners, and neither fact has a CSS media query. `setTitle` is driven from the
renderer, which is the only side that knows the adapter's name.

**No captured frame passes through main's JavaScript as anything but an opaque
buffer.** Main deframes the pipe's byte stream and posts the payload onward
without looking at it.

### The capture store — `electron/store/`, a `utilityProcess`

Owns the capture files. A separate process rather than a Node worker inside the
renderer, for three reasons: `nodeIntegrationInWorker` is renderer-wide and
incompatible with `sandbox: true`; it does not work with `type: 'module'`
workers, which `captureClient.ts` uses; and it would hand `child_process` to
the same renderer that parses hostile bytes. `entry.ts` is the process,
`host.ts` forks it and brokers the channel, `volume.ts` is the `node:fs`
implementation of the four capture files.

Forked with `stdio: 'pipe'`, because a packaged GUI app has no console to
inherit and every `fail()` message the protocol calls "never silent" would go
nowhere. A dead store is a handled state: `child.on('exit')` tells the renderer
over a separate channel, because a `MessagePort` that goes quiet would hang
every pending read for the life of the window.

`execArgv: ['--max-old-space-size=2048']` is there and **does not work** — the
flag arrives and V8's limit stays at its 4192 MB default, because the isolate
already exists by the time Electron looks at it. `store/heapGuard.ts` enforces
the ceiling instead, by sampling the heap and standing down deliberately with a
message a V8 abort cannot give. See **What blocks watching the disk filter
work**.

### The renderer

`sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, no
service workers, every permission request denied. The preload is a **single
CommonJS file** — a sandboxed preload cannot be ESM and cannot `require` a
relative module, so `electron/build.cjs` bundles it.

**The shell is a rail, a title row and a filter row, and there is no menu.**
`Header.tsx` is deleted and its contents are split three ways; `AppMenu.tsx` -
the hamburger drawer that hung off the title row - is deleted too. Of its seven
entries, **three already had a rail button** (Capture Statistics, Network,
Settings), **Export/Import became** the one new rail button, and the rest went to
Settings: the two passive name-resolution switches to `Interface` beside the two
outbound lookups already there, and Custom Dissectors to a tab of its own beside
Decryption - the pair that change what the dissector can **read** rather than
what is shown. Nothing that duplicated a visible control survived, which was the
menu's own stated rule turned on itself. The title row holds **no navigation**
now, and `cmdk` left `dependencies` with it.

**The title row holds one control, and it is the detail panes' toggle.**
`PanelBottom` beside the caption buttons, `w-9` rather than the 46px those take,
because 46 is Windows' caption metric and a control of ours borrowing it claims
to be part of that set. It was a switch in `Settings -> Interface`, and the
distinction that moved it is the one that panel exists to make: a SETTING is
chosen once, a CONTROL is reached for mid-task. The pane ARRANGEMENT stays in
Settings, and still greys out when the panes are off, which is the only trace of
the switch left there. `scripts/electron/window-chrome.ts` asserts the button
carries `app-no-drag` - beside `WindowControls` rather than inside it, so it
inherits nothing from that group's shared class - and that Settings has no second
way in.

**Its centre WAS the packet counter, and that is the one control it had.** The
row used to show `windowTitleFor(...)` there - `Inwire` idle,
`Ethernet - capturing - Inwire` capturing. That string is unchanged and still
names the window for the OS through `useWindowTitle`, so the taskbar and Alt-Tab
are as they were; what it stopped doing is spending the centre of the one strip
nobody can look away from on the app's own name, which the mark at the corner
already gives. `components/common/PacketCountsReadout.tsx` took the slot, and
with it the **`+N UNSEARCHED` rescan button** - the only way in the app to re-run
a whole-capture filter scan, which deleting the counts widget would otherwise
have deleted. It carries `app-no-drag` itself; without it the button moves the
window and never fires.

`windowChrome.ts` argues against exactly this and the comment is kept: a number
that changes is the most distracting thing that can go in a title bar. Its second
half - "the count is already on screen, in the filter bar" - is what stopped
being true, twice over: the filter bar's badge went, and then so did the widget
that replaced it.

**Network left the rail too, and for a reason worth keeping.** It was the third
view, on Ctrl+3, and it failed the test the view list applies: a view is a way of
looking at the capture. Network describes the *machine* - adapters, DNS, public
identity - and nothing in it changes when a packet arrives. The tell was the
filter row, which had to be hidden above Network and nowhere else, because a
display filter there was a control with nothing in view to act on. It is a
Settings tab now, next to Driver Info, which is the other read-only report about
this machine. `scripts/session/view.ts` has carried three versions of that rule
and now holds the third: **the filter row is rendered by naming Packets**, never
by excluding the views that do not want it. Version two was "no view hides the
filter row", written the day Network stopped being a view - and being an
exclusion rule, every view added afterwards inherited the row without anybody
deciding it should. Four did, and all four fail Network's own test: Statistics is
handed `packets` rather than `filteredPackets` deliberately, the Routing Map
draws the throttled feed, Follow Stream reads one conversation, and Frame Detail
shows the one selected frame. The filter narrowed nothing on screen in any of
them.

Settings widened from `max-w-3xl` to `max-w-5xl` to take the dissector editor,
which is two columns rather than a list of setting rows.

**The map is a view and the charts are a Statistics tab**, which is where the
dock's contents went. Both placements answer the same question the view list
already asks - *is this a way of looking at the capture?* The map is: every arc
on it is a conversation in the buffer and it changes when a packet arrives,
which is exactly what Network could not say about itself before it became a
Settings tab. The throughput plot and the size distribution are too, but they
are the same aggregate the tables beside them already compute, drawn rather than
tabulated - so they are a tab of `StatisticsPane`
(`components/statistics/GraphsTab.tsx`)
rather than a fourth view.

One thing follows from that and is easy to undo by accident: **`GraphsTab`
renders outside the pane's scroller.** Every other tab is a table and wants
`overflow-y-auto`; `TrafficTimelineChart` measures its own container, so a
parent that grows to fit its child would size the SVG from a box the SVG is
itself defining.

There was a second, and it is worth reading as a rule rather than as history:
the map had a small copy in the packets view's bottom row, guarded on
`view === 'packets'`, because `display: none` hides a MapLibre instance without
unmounting it. **That copy is deleted.** The map is the view and nothing else,
so "exactly one map is ever live" is a fact about the component tree instead of
a condition somebody has to keep true - which is the strongest form the answer
could take, and the reason to prefer deleting a surface over guarding it.

**The packet detail window is a view too, and it is the last modal that was a
place.** It was `fixed inset-0`, a scrim and a 92vh panel, opened by
double-clicking a row and dismissed with Escape or an X - which meant the one
surface that shows a frame in full could only be reached from the one surface
that shows frames in summary, and was *dismissed* rather than *left*. It passes
the same test the map passed: it is a way of looking at the capture, and what it
looks at is one of the frames in the buffer.

Four things fell out of the move, and each of them is a deletion rather than a
port:

- **No `detailPacketId`.** The modal kept a frame of its own, separate from the
  list's selection, which is why closing it dropped you wherever the list had
  been left. The pane reads `selectedPacket` like the bottom panes do, so
  stepping frames in it moves the list, and leaving and coming back lands on the
  frame being read.
- **No second `usePacketDetail`.** The modal was mounted only while open, so its
  own hook was the only one running; a pane sits beside a packet list that is
  *hidden rather than unmounted*, whose panes already ask for exactly this
  frame. `App` passes `selectedPacketDetail` in, because two hooks on one frame
  would be two replay requests for one tree.
- **No keyboard gate.** `useKeyboardNavigation` used to bail out entirely while
  the modal was open. The hook binds Up/Down and the pane binds Left/Right, on
  the same selection, so there is nothing to keep apart.
- **No Escape of its own,** except one. `App` returns any non-Packets view to
  Packets on Escape, in the bubble phase, last in the chain. The pane still
  listens in the capture phase for exactly one thing - the meta rail summoned
  over the canvas on a narrow window - and claims that key with
  `stopPropagation`, which is the layering contract every popover here keeps.

**Its empty state is the feature that replaced Find packet.** A view with a rail
button can be opened with nothing selected, so the pane's no-frame state is its
front door rather than an apology: `FrameNumberBox`, the same control the meta
rail carries, asking for a frame number and nothing else. That is what makes
`detail` restorable where `stream` is not - it needs nothing handed to it - and
`scripts/session/view.ts` ties those two facts together, so a view rendered
without a second condition has to be one `restoredView` will hand back.

`services/graphPrefs.ts` (`inwire.graphs`) holds what the two charts are drawing.
It is the surviving half of `inwire.dashboard`, and a new key rather than a
rename because the old one was a `Record<string, string | number>` config bag
validated against a widget catalogue - shaped that way so a settings list could
be generated from it. There is no catalogue and no generated list; the fields are
fields.

```
┌─────────────────────────────────────────────────────────┐
│  ◉   32px TitleRow                          ─ □ ✕       │
│ ╭────╮ ╭──────────────────────────────────────────────╮ │
│ │rail│ │ FilterRow (banner, filter, restore)          │ │
│ │44px│ ├──────────────────────────────────────────────┤ │
│ │    │ │ packets (hidden, never unmounted)            │ │
│ │    │ │   ├─ packet list                             │ │
│ │    │ │   └─ INSPECTION │ HEX VIEW                   │ │
│ │    │ │ detail | statistics | geo | stream           │ │
│ ╰────╯ ╰──────────────────────────────────────────────╯ │
│ ● Capturing 04:12  Ethernet     0x42 'B'  44/178,200 ◍  │
└─────────────────────────────────────────────────────────┘
```
**`<main>` is a column again, and there is no dock.** It was a row for exactly
one revision - the dock ran the pane's full height with the filter row beside
it - and that arrangement existed to say that a widget summarising the whole
capture had no business sitting under a row that narrows the list. Deleting the
dock answered the same question by removing the thing that raised it.

**The packets view's bottom row is two panes: the tree and the hex dump.** One
divider, resizing the pane to its LEFT, and the tree's share is stored as a
fraction with the dump taking the remainder (`detailsPaneRatio` in
`interfacePrefs.ts`). The dump is the remainder because it is the pane with no
minimum content width worth defending - the tree truncates field names, but a
dump narrower than its own 16-byte row wraps into nonsense, so `flex-1` means it
absorbs window resizes while the tree keeps the width the user chose.

**There was a third pane at the head of the row, and it was the map.** It ran
widest subject to narrowest - the map is the whole conversation between two
places, the tree is one frame of it decoded, the dump is that frame's bytes - and
deleting it takes back everything that arrangement cost: `geoPaneRatio`, the
second divider, the render-time clamp that kept two independent shares from
adding past 1, and the `view === 'packets'` guard that kept a second MapLibre
instance from being built behind a hidden section. `detailsPaneRatio` is 0.5 with
a 0.9 ceiling again, which is what it was before the map took a third of the row.

**The packet table's own header row wears the same ground as those bars.** It
was `--secondary`, one step brighter, which made it the only column header in the
window that did not match the pane titles under it; `HEADER_CHROME` in
`PacketList.tsx` is `bg-card` now. A table's header row is the same kind of thing
as a pane's title bar - the strip that names what is below it - and `--secondary`
is the chrome's colour rather than a content surface's.

**Both wear one title bar, and it is a component rather than a copied class
string.** `components/common/PaneHeader.tsx`, fixed at `h-9`. They carried
identical `px-4 py-2` headers and still sat at different heights, because
vertical padding sizes a box from its CONTENTS: Hex View's bar holds copy
buttons (~20px), the other holds 12px text (~16px). Four pixels, on adjacent
panes, with a divider between them. The height is fixed here and the padding is
horizontal only. The map wore the same bar for exactly as long as it was in the
row; the Routing Map view has a side panel instead, which is where its located
count lives.

**There is an application status bar, and it is the second attempt.** 24px at
the window's bottom edge, `components/status/StatusBar.tsx`. The chrome is a
**C**: the title row across the top, the rail down the left, the bar across the
bottom, all one `--secondary` ground.

**Between those two strips the rail and `<main>` are two CARDS**, which is VS
Code's Modern UI arrangement ported rather than invented - read
`src/vs/workbench/browser/media/floatingPanels.css` in `microsoft/vscode`, and
`.part.activitybar.left` in particular, before changing any of it. Four facts,
each load-bearing for the others:

- **A 4px gutter** on the band (`pl-1 pr-1 pb-1` in `App.tsx`) holds both cards
  off the window on the left, the right and the bottom. They meet the title row
  **flush** at the top, which is also VS Code's. The chrome's `--secondary`
  shows in the gutter and is the cluster's backdrop, which is the first time
  that ground has been visible at all.
- **8px on every corner of both cards**, and a 4px gap between them: they
  FLOAT apart rather than meeting flush. That is VS Code's `.nosidebar` case -
  a rail with nothing to connect to "closes up as a standalone panel with every
  corner rounded". The gap is `ml-1` on `<main>`, not `mr-1` on the rail, which
  is their convention too and keeps it one number rather than two that have to
  agree. 8px is `--vscode-cornerRadius-large`; 4px is `--vscode-spacing-size40`.
- **The radius does not break the square-corner rule, it steps around it.** The
  rule is that nothing drawing against the window's OWN edge may carry a corner,
  because Windows draws the only curve out there. The gutter means neither card
  touches the window. Delete the gutter and the radius goes in the same commit.
- **Each card draws its own four borders**, so there is no shared seam and no
  question of who owns it. They met flush for a revision, with the rail drawing
  the seam and `<main>` giving up its `border-l`; the border belongs to the rail
  either way, and the reason is arithmetic: `w-11` under `border-box` is 42px of
  interior between two 1px borders, which centres a 36px target on whole pixels,
  where handing the facing border away leaves 43.

**Neither strip draws an edge of its own, and that is arithmetic too.**
`border-box` takes a border out of the element's height, so a `border-b` on the
`h-8` title row leaves 31px for caption buttons that are 46x32 because Windows'
are, and a `border-t` on the `h-6` bar makes it 23. The cards close their own
edges instead. The gutter and the borders cost the rail 6px, which is why
`scripts/session/view.ts` subtracts them: 680 - 32 - 24 - 4 - 2 = **618**.

**The first attempt is why the second one is shaped the way it is**, so the
post-mortem is kept rather than replaced. It carried the byte inspector, and a
full-width bar's natural left edge is the window's - while a line about the hex
dump, a pane away from the thing it describes, starts under the rail. So the
readout was pushed sideways with a CSS length built from `--details-pane-size`,
and the bar was a row of two blocks so that a percentage would resolve against
`<main>`'s content box rather than the window. All of that machinery existed to
make a window-spanning bar look like it belonged somewhere narrower, which is
the definition of a bar in the wrong place. It was deleted and the readout went
back to Hex View's own footer.

**What was wrong was the alignment, not the bar.** A status bar groups its items
left and right by PRIORITY and never by correspondence with what sits above
them - `Ln 56, Col 2` is at the window's right edge in every editor that has
one, and nobody expects it over the cursor. Adopting that rule deletes the
machinery instead of rebuilding it: the byte readout is an ordinary right-group
item with no inset, and there is no length anywhere in the bar built from a
pane's size.

The second failure is the one worth remembering, because it is subtler than the
indent. The bar could not read `HexViewer`'s local hover state, so it was handed
a byte derived from `activeByteRange` - which is **also** what the protocol tree
publishes for a one-byte field, so the bar answered "this byte" for a hover in a
pane that was not the dump. The replacement is `services/hoveredByte.ts`, a
store carrying the byte's **value** rather than an index. That choice is what
makes the conflation impossible rather than merely avoided: the only code that
can put a byte in the bar is code that already had the bytes in hand, which is a
dump and never a tree.

**The left group is the session and the right group is the frame.** Left: the
agent link, the adapter, capture state with elapsed time, and dropped frames -
in the order they fail in. Two of those were previously reachable only through a
hover tooltip or a Settings tab, which is the gap `DriverInfoPanel` was written
to close and this closes ambiently.

**The right group is the byte readout, the outbound indicator, then the packet
counter.** The counter had the corner and the indicator sat between; they were
swapped so the numbers are at the edge, which is what makes them findable
without reading the bar. The trade is real either way - a right-aligned group
shifts left as its widest member grows, so whichever item is not at the edge is
the one that moves when the counts gain a digit.

**The counter's share badge is deleted**, and `filterPercentage` with it. It
read `100%` beside `2,224 / 2,224`, which is one figure said twice in the weaker
unit; the pair of numbers says it exactly rather than rounded. The badges that
remain report a whole-capture scan, which no pair of numbers on screen can
describe.

**A healthy agent read "Agent not reachable" in this bar**, and the shape of
that is worth keeping. `agentSilentLabel` was a
`Partial<Record<AgentHealth['kind'], string>>` of the five SILENT kinds with
`?? 'Agent not reachable'` behind it. Its two callers - the rail's tooltip and
the filter row's banner - only ask while the agent is silent, so the missing
`connected` entry could not be reached; this bar's link item asks
unconditionally, because its job is to name the state whatever it is. Capture
ran perfectly and the bar said the agent was gone, with the tooltip beside it
saying the opposite because that one was a conditional rather than a lookup.

`Partial` meant the type could not object to the missing key, and the `??`
turned the hole into a confident wrong answer rather than an absence anybody
would see. It is `agentStatusLabel` now, a TOTAL record with no fallback, so a
new kind will not compile without a label - and `scripts/electron/agent-health.ts`
holds the part a type cannot: that the healthy states do not read as faults, and
that the text agrees with `agentNeedsAttention` about whether a warning glyph is
drawn. That file had claimed "every branch to a label" in prose and had never
checked one.

**Nothing in the bar is pressable.** Each item opened the Settings tab that
fixes what it reports, and that is gone: the bar is a readout. `StatusItem`
renders a `<span>` and has no `onClick` at all, so putting one back is the
decision rather than a prop. The one real control in the strip is the packet
counter's `+N UNSEARCHED` rescan, which is not a `StatusItem` - and a bar where
most things react to a click is worse at advertising the one that does something
than a bar where nothing does. `scripts/session/status-bar.ts` greps the whole
directory, because the easy way to reintroduce a button is to skip the shared
cell. Right: the byte readout, the packet counter, and an indicator
for the app's own outbound lookups. An item renders nothing at all when its
subject is absent, rather than showing a zero that was never measured -
`droppedKernel` is `null` when the driver's counters could not be read and must
never be folded into a total as 0.

**The packet counter moved here from the title row**, which is where
`windowChrome.ts` always argued it did not belong: a number that changes is the
most distracting thing that can go in a title bar, and it was there only because
nothing better existed. The title row's centre is empty now. `useWindowTitle`
still sends `windowTitleFor(...)` to main, so the taskbar and Alt-Tab are
unchanged.

`--details-pane-size` stays on the **root** element even though only the panes
read it. It was moved there so the FIRST bar could resolve against the same
base; the second deliberately does not read it, and
`scripts/session/status-bar.ts` fails if it ever starts - which turns a stale
note into the marker for the rule.

Moving the properties to the root fixed a bug as well as enabling the bar:
`--geo-pane-size` had never been in the React style object at all, only in the
imperative drag path, so the map pane had no width until somebody dragged
something. The bar is gone and that fix is not. That property is gone with the pane; the trap it records is that a
layout custom property written only by the drag path has no value until a drag.

**The title row spans the window and the rail hangs below it**, which is what
puts the app's mark at the true top-left corner. The segment under it is the two
cards' own `border-t` and **the row does not draw it**, which is what lets the
`h-8` row keep all 32 of its pixels for caption buttons that are 46x32 because
Windows' are. The ground is unbroken across it: the row and the rail are both
`bg-secondary`, and it runs from the mark down past the card's edge into the
gutter and into Windows' own rounded corner - the OS's radius, not one this app
draws (`roundedCorners` defaults true and is never set).

**That chrome is `--secondary`, one step brighter than the panes.** It was
`--card`, the same ground every titled surface uses, and the split is worth
having: `--card` against `--background` is a 4/255 delta in Night, so the seam
where the chrome meets `<main>` was invisible and the 1px border was the only
thing the eye could follow along it. At `--secondary` the delta is 13/255 and
the edge reads on its own. The border stays, because it is what carries the edge
in Day. That argument was first made about a rounded notch cut out of the
chrome; the corner is square now and the deltas are unchanged, because they were
always about two grounds meeting rather than about a curve.

**The `INWIRE` wordmark in the corner is deleted, and the mark took the rail's
axis back.** The word named the app in a caption that already names it twice -
`windowTitleFor(...)` still goes to main through `useWindowTitle`, so the taskbar
and Alt-Tab are unchanged. With it gone the mark sits directly above the column
of rail icons rather than 8px to their left; that alignment is why the mark used
to live in a rail cell, and losing it was the stated cost of letting the word
lead. Its block is `ml-1 w-13` - the rail's width AND the band's gutter, because
the rail is a card and its axis is `gutter + width / 2` rather than half its own
width. Matching only the width put the mark 4px off for one commit, so
`scripts/session/view.ts` reads both halves out of the source.

**`<main>` is inset into the corner that L makes, and all four of its corners
are square.** Three of them always were - they run into the window's own edges,
and a radius there would be the second curve inside Windows' that
`TitleRow.tsx` refuses to draw. The top-left carried `rounded-tl-xl` on the
argument that it is the one corner where two chrome edges meet rather than an
edge of the window, so it was allowed to curve. **It is square now**, which
makes the shell's rule general instead of nearly-general: no surface that meets
the window draws a corner of its own, and the only curve at the window's edge is
the one Windows puts there. This is a rule about the SHELL - the title row, the
rail, this pane. Radii inside the workspace are untouched by it and are
everywhere: 242 `rounded-*` utilities across the renderer, on buttons, cards,
popovers and pills.

**There is no seam between the two cards**, because they do not touch: a 4px
gap runs between them and each closes its own outline. That went through both of
VS Code's arrangements on the way here - the rail drawing a shared seam while
`<main>` gave up its `border-l`, then the two floating apart - and
`scripts/session/view.ts` asserts whichever is in force, because two lines in one
place is one line too many and so is none. What has not changed is why a line is
needed at all: at `--secondary` against `--background` the grounds differ by
13/255 in Night (the paragraph above has the deltas) and the border carries it in
Day.

`overflow-hidden` stays and its reason changed. It was load-bearing for the
curve - `FilterRow` paints its own `bg-background` straight into that corner, so
without the clip the curve was drawn and then covered by the child sitting in
it. With the corner square, what keeps it is that every child of the column
scrolls inside it and their scrollers resolve against this box.

`ActivityRail.tsx` is 44px and starts below that row - there is no cell above
its first group, because a cell would put the mark below the corner it is meant
to occupy and cost height the rail has not got. **Three groups**: **capture**
(Start/Stop, adapter, schedule - in the order they are used), **views**
(Packets, Frame Detail, Statistics, Routing Map, Follow Stream), and a bottom
group of actions (Export/Import, Settings) pinned with `mt-auto`.

**There was a fourth group and it was the widgets.** Six icons toggling panels
in the dock, with a 20px collapse header in the divider slot above them. All of
it went with the dock; of the three widgets that were left, the map became a
**view** in the group above and the traffic timeline and packet-size charts
became a **tab of the Statistics pane**. None of them needed an open flag, a
pin, a drag-reorder or an overlay.

**The rail's Follow Stream button follows the SELECTION**, which is the one
entry in the view group that is a verb rather than a place. It was wired like the
other four - `streamAvailable` meant "a stream is already open" and the click was
a bare `setView('stream')` - and that produced three symptoms which are all the
same bug: selecting a frame on a TCP stream left the button disabled, following
one from the Frame Detail pane enabled it, and from then on it reopened *that*
stream for ever because nothing it read ever changed with the selection. It is
`handleViewChange` in `App.tsx` now, which intercepts `stream` and routes it
through `handleFollowStream` with the selected frame's target. **`Ctrl+5` goes
through the same handler**, which is why that handler sits above
`useKeyboardNavigation` rather than with the rest of the stream state: a `const`
cannot be read before it is declared, and the alternative was the shortcut and
the button meaning two different things.

The button stays enabled while a stream is open even if the selection has none,
so the view is reachable while reading a conversation, and so the icon does not
flicker as somebody arrows past an ARP. The selection wins when both are true.

**Find packet is deleted, and Frame Detail is a view.** Those are one change:
the rail lost an icon from the capture group and gained one in the views group,
and because both groups gap the same the two deltas are one icon plus one gap
each and cancel - the strip is the same height with a different set of icons in
it. `Ctrl+2` is Frame
Detail now and Statistics, the Routing Map and Follow Stream each moved a key,
which follows from `APP_VIEWS` order being the numbering rather than from a
second table.

What was lost is worth stating rather than glossing: Find packet was a substring
match over protocol, addresses, info and id across the rows in hand, and the
go-to-frame box that replaced it takes **a frame number and nothing else**. The
argument for the trade is that the display filter already answers those questions
in a language that says what it means, and answers them over the **whole capture
on disk** rather than over the window - so the search was the weaker of two
overlapping answers, and two search boxes in one window is what the rail exists
to prevent. `inwire.packetSearch` is in `RETIRED_PREFERENCE_KEYS`.

**There was an Updates button and it was a second Settings button.**
`onOpenUpdates` and `onOpenSettings` were the same handler, and `updateAvailable`
was passed `false` at the only call site, so its badge could never light.
Export/Import took the slot. The Update Center is unchanged and still lives where
ADR 0032 put it, at `Settings -> Updates`; if the badge is wanted back it needs a
real `updateAvailable` first, and Settings is the icon to hang it on.

10 icons at **36px**, two dividers and the bottom group's padding come to
**414px** against the 618px the rail gets - a **680px** minimum window, less the
32px title row above it, the **24px status bar** below, the cluster's 4px bottom
gutter, and the card's own two 1px borders - 204px of slack.
`scripts/session/view.ts` adds that up from the Tailwind classes, holds each
class to what the sum assumes, and prints "the rail is FULL" when the answer is
no more icons. **The two strips are funded differently and that is deliberate**:
the window minimum carries the title row, because the rail had no slack to spare
when it arrived; the rail's own slack carries the status bar, because by then six
deleted icons had left 154px and raising the minimum to 704 would have cost every
small laptop 24px of window for a strip that fits without it.

**The icons got bigger when six of them were deleted, and smaller again when
the rail was narrowed.** The target went 36 → 44 → 36 and the glyph 20 → 24 →
20, at 8px an icon each way. Six deleted icons and a 20px header paid for the
first; the second is what a 44px rail costs, since a 44px target inside it would
leave the button's edges touching the card's own. **The constant through all of
it is 3px of air either side**, inside the card's two borders - that is the
number to reason from, not the outer width, and 32-in-48, 36-in-56, 44-in-56 and
36-in-44 are four points on the one line.

That arithmetic has decided real design questions rather than merely recording
them. It is why the two name-resolution switches went to Settings rather than the
rail, and why the brand mark lives in the title row and not in a rail cell. Both
still hold on their own arguments now that the number no longer forces them.

**If the slack is ever spent, the views group is the one that scrolls.** It used
to be the widgets group and there is no widgets group; capture has to stay
reachable because it is how a capture starts, and the bottom group is pinned with
`mt-auto`, so an overflow there does not scroll anything - it pushes Settings off
the bottom edge.

The active state is a **translucent fill in the theme's own accent** -
`--primary` at 20%, `--foreground` on the glyph - and it never appears on hover:
the active marker is the strongest indicator in the UI, and firing it on hover
flashes it five times as a pointer crosses the rail. **It was two things, an
`--accent` fill under a 2px left edge**, and the fill was the weaker half:
`--accent` is one step off the rail's ground, so the edge did the work and the
fill was barely a tint - weaker still once the rail moved to `--secondary`.
Tinting with the accent HUE inverts that, and an edge in the same colour drawn
over a button already filled with it is a second mark for one fact.

Two numbers decided the details and both are Day's doing. A **solid** `--primary`
fill reads as a button rather than a selection, so it is translucent. And
`--primary` on a tint of ITSELF cannot reach 4.5:1 in Day at any alpha - it peaks
at 3.97 and falls from there, because `#0b6bcb` is a mid-blue and the tint
lightens toward it - so the accent-on-accent-tint pattern is out and the glyph
takes `--foreground` instead. That is a fact about this palette rather than about
the floor, which is why the glyph changed and the floor did not.
`scripts/themes/registry.ts` reads the alpha **out of `ActivityRail.tsx`** and
holds four numbers to it: the glyph's contrast on the composite, and the fill's
deltaE from both the rail's ground and its own hover - the second being the pair
that matters, since an active marker a hover can be mistaken for is not a
marker. There used to be a third shape - a dot and
an outline, for a widget that was open in the dock - and with the dock gone every
icon in the strip is a view or an action, so one shape is all there is to say
**for a view**. The pair survives on the two
controls that are neither: the adapter and the schedule take
`railButton(active, 'toggle')`, which is the outline, and the schedule carries
the dot when one is set. Find packet was the third and is deleted; what was
deleted before it was the widget icons, not the vocabulary. 44 disagrees with
`FrameMetaRail`'s 48 - this rail was 8px wider and is now 4px narrower, so the
disagreement changed sign rather than went away - and that is accepted rather
than overlooked: one is a group of icons inside a pane, the other is three groups
in the window's chrome. `DASHBOARD_RAIL_WIDTH` was the other half of that
sentence and went with `dashboardPrefs.ts`.

**The drag-region rule.** The title row is `.app-drag` and everything
interactive in it is `.app-no-drag`; **the rail is entirely no-drag**, and has
been since the top cell went with the brand mark. A control that forgets
`no-drag` moves the window instead of being pressed, and the only symptom is a
click that does nothing — which on the close button is a window that cannot be
closed, so `scripts/electron/window-chrome.ts` asserts the class is on the
shared button class rather than on each button. Both classes are in `index.css`
and deliberately not `:root` custom properties: that block is the theme baseline
and `scripts/themes/registry.ts` requires every token in it to be redeclared by
every theme, which a layout constant has no business being.

`viewPrefs.ts` holds the active view, persisted — which argues against
`DashboardAside`'s rule that "'which panel did I have open' is not a setting",
and does so knowingly: a modal is a detour, a pane is a place. `stream` is a
legal stored value that `restoredView` refuses to restore, because the
conversation it named lived in a buffer that is being rebuilt. Those two facts
have to move together and now do: `scripts/session/view.ts` reads the JSX guard
for every view out of `App.tsx` and asserts that the one view needing a second
condition to render - `stream`, which needs a target - is exactly the one
`restoredView` refuses.

**The dock is deleted, and so is everything under it.** It replaced a right-hand
column, which had replaced a `DashboardAside` with a collapse-to-a-rail morph;
what went with it this time is the whole apparatus rather than another
relocation - `components/dock/`, `WidgetCard`, `WidgetOverlay`,
`RenderedWidget`, `dashboardWidgets.tsx`, `DashboardWidgetList`, both preference
keys (`inwire.dock`, `inwire.dashboard`), and the two assertion scripts that
covered them.

The question that answers is the one the dock kept re-raising in a new shape:
**what is a widget, if every widget that survives has somewhere better to be?**
Six existed. Packet counts became the title row's readout; Protocol breakdown and
Top talkers were deleted outright; the map became a view; and the traffic
timeline and packet-size charts became a Statistics tab. Each of those is a
surface with one home and its own controls, which is what a widget was
simulating with an open flag, a pin, a drag-reorder, a per-widget config bag and
a shared overlay.

Three things the dock knew that are worth not rediscovering:

- **`LIST_RESERVE` was 640 and did not fit every column.** Measured: the fixed
  columns take ~785px, so Protocol, Length and Info were off-screen at the
  reserve and the list scrolled horizontally to reach them. It was still right,
  for a reason about the window rather than the columns - a reserve large enough
  to keep every column would have meant the dock could not open **at all** at the
  1024 minimum. The constant is gone with the dock; the reasoning is the general
  form of "guarantee the identity - frame number, time, both addresses - and let
  the rest scroll".
- **A width or a share is stored unclamped and clamped at the point of use.**
  `clampDockWidth` applied against the window, so narrowing shrank an open dock
  and widening gave back the width the user chose; a width clamped on the way out
  would never have grown back. That rule outlived the dock, and then outlived
  the thing it applied to: it was two shares while the map was a pane in that
  row - `detailsPaneRatio` and `geoPaneRatio`, stored independently with the
  interaction ("the hex dump keeps at least a tenth") applied at the point of use
  in `App.tsx`. One share has no interaction to defer, so the 0.1..0.9 ceiling in
  the normalizer is the whole clamp again and `MIN_PANE_PX` is what stops either
  pane being dragged to nothing.
- **`Dock` was the application's only `React.memo` boundary**, and the one that
  replaced it is the hex pane. App re-renders ~10x a second during a capture and
  every widget did a full pass over the buffer, so the dock had to absorb that;
  the surviving surfaces are unmounted unless their view is active, which is a
  stronger version of the same guarantee - except the dump, which is mounted
  whenever Packets is and is the most expensive thing under App. `LinkedHexViewer`
  in `components/packet-details/LinkedDetailPanes.tsx` is the boundary, and what
  it rests on is worth knowing: `permissions` in `App.tsx` is a `useMemo` with an
  empty dep list **for this reason alone**, because it was an object literal
  rebuilt every render, and a changed prop is a memo that never hits and never
  says so. The tree beside it is deliberately not memoized - `onSelectFrame`
  closes over `packets`, so its identity changes on every flush and the memo
  could not hold.
- **The highlighted byte range is a store for the same reason the counter is.**
  `services/byteRange.ts`. It is the cross-highlight between the two bottom panes
  - hover a field, its bytes light up; hover a byte, its field lights up - so it
  is state shared by two siblings and it lived in their common parent, which is
  `App`. Every pointer move over a byte therefore re-rendered the whole
  application; on a 64KB frame the dump alone is ~79 virtualized rows of 32
  spans. The panes subscribe now and `App` holds nothing - it may `resetByteRange`
  where the selection goes and may not publish, which
  `scripts/session/byte-range.ts` asserts along with the memo's preconditions.
  **It is not `hoveredByte.ts` and must not be merged with it**: that store
  carries a byte's VALUE so only a dump can publish one, this carries a RANGE so
  the tree can. `PacketDetailPane` subscribes to neither and keeps its own
  `useState`, because it owns both halves of its own cross-highlight and is
  already off App's render path.
- **The dump's hover is delegated, not per byte.** Every byte is two elements,
  so a handler pair each was ~5,000 closures built and diffed per render on a
  large frame; `HexDumpView` binds one `mouseover`/`mouseout` pair on its
  container and reads `data-byte`. The `mouseout` has to check `relatedTarget`,
  because it also fires when the pointer moves BETWEEN two cells and an
  unconditional clear would blank the readout for a frame on every byte crossed.
  The cells are `transition-colors` rather than `transition-all` for the same
  class of reason: the hovered cell also takes `scale-110` and a shadow, and
  `transition-all` declared the transition on all of them.
- What survives unchanged is `services/packetCounts.ts`:
  the counter publishes and its readout subscribes, because threading a
  ten-times-a-second number down through props was the regression that shipped
  once already (`b0ce1fc`).

`lib/windowChrome.ts` is the renderer's half of the bridge: it reports the
resolved theme and the window title to main, and subscribes once at module scope
to maximized/focused.

The React app never dissects and never parses an agent message. That is
`src/workers/pipeline.worker.ts`, which holds the ordering window, the
trackers, and `pcapParser.ts`.

### The frame path, end to end

```
agent → pipe → main (deframe) → MessagePortMain → pipeline Worker
      → dissect → 100 ms flush → renderer main thread → React state
```

Main hands the Worker one end of a `MessageChannelMain`. The renderer's main
thread receives that port from the preload and transfers it straight into the
Worker — it carries the port exactly once and then plays no part in the frame
path, which is the property ADR 0007 bought.

**There is one copy, and it is unavoidable.** `MessagePortMain.postMessage`
accepts only ports in its transfer list; an `ArrayBuffer` is cloned, not
transferred. At the agent's ~256 kB batch about thirty times a second that is
single-digit MB/s. Measured on the pipe itself: **4,000 batches of 64 kB —
262 MB — in 539 ms, or 487 MB/s**, so the transport is not the ceiling. The
cost of the cross-process clone specifically has **not** been measured; see
**Direction**.

## 4. The capture format and the agent protocol

### On disk — `src/services/capture/`

A capture is a directory named `cap-YYYYMMDD-HHMMSS-xxxx` holding four files:
`index.iwidx`, `prefix.iwpfx`, `summary.iwsum`, `frames.iwbyt`. Written by
`captureWriter.ts` through `chunkCodec.ts`, read back by `captureReader.ts`,
addressed by `captureIndex.ts`, searched by `captureScan.ts` and `matchSet.ts`.

`blockFile.ts` is the seam; `nodeBlockFile.ts` is the real-file implementation
and **loops** its `readSync`/`writeSync`, because a short read on a 5 GB
`frames.iwbyt` would otherwise read as a torn tail and truncate a healthy
capture. `serialQueue.ts` exists because the writer once used `void handle(msg)`
and `append` overtook an async `open`, losing 500 frames silently.

Recovery: a capture whose trailing chunk is incomplete loses that chunk and
nothing else. `scripts/capture/recovery-on-disk.ts`.

### On the wire — `src/services/agentFraming.ts` / `local-agent/pipe_frame.py`

A pipe is a byte stream, so framing is ours: a `u32` length, a `u8` kind
(`FRAME_JSON` 0, `FRAME_BINARY` 1), little-endian to match `packet_batch.py`.
Both ends refuse a declared length past `MAX_FRAME_BYTES` (8 MB) **before
allocating anything** — the agent is a privileged service and a five-byte
header must never ask for four gigabytes.

Above the framing nothing changed when the WebSocket went. The 18-byte record
in `local-agent/packet_batch.py` and `src/services/agentBinary.ts`, and every
control message in `src/services/agentProtocol.ts`, are transport-agnostic.
Both ends assert the same hand-written byte vectors — `scripts/agent/binary.ts`
and `scripts/agent/pipe-framing.ts` against `local-agent/test_protocol.py` —
which is the only thing keeping two implementations of one format in agreement.

`src/services/agentLink.ts` is the vocabulary between main and the Worker.

### Two version numbers

**`AGENT_VERSION`** is a wire-protocol version and an **ordering**: it is the
left-hand side of `isAgentOutdated`, so it only ever climbs. Reset it and an
agent left behind by an earlier install reads as newer than required, which
shows as "not connected" rather than "update your agent". Locked across **four**
places — `local-agent/agent.py`, `src/services/agentProtocol.ts`
(`REQUIRED_AGENT_VERSION`), and `MyAgentVersion` in **both**
`installer/setup.iss` (the one that ships) and
`local-agent/installer/setup.iss` (the legacy agent-only one).

Two things enforce it, and the split matters. `local-agent/test_protocol.py`
reads the legacy `.iss` and refuses a reset — but it is Python, and
`scripts/check.ts` only discovers TypeScript, so it fires only when somebody
runs it. `scripts/agent/installer-versions.ts` covers **both** `.iss` files and
runs on every `npm run check`. It exists because the shipping installer's two
stamps were read by nothing at all: they agreed with the code by hand. It holds
the same anti-reset floor, compared as numbers rather than as a string —
`"3.10.0"` sorts before `"3.9.0"` lexically, so a string floor would reject the
first version past 3.9 and every one after it.

**`MyAppVersion`** is the product, locked to `package.json`, and is what
Windows compares to decide whether an install is an upgrade. The two stopped
moving together the moment one installer carried both: a UI release ships an
installer and no new agent at all.

## 5. Invariants

Each with what enforces it. "Unenforced" means exactly that.

**A capture is deleted only when the user asks.** ADR 0012. The mechanism is
`planPrune` in `src/services/capture/captureDirectory.ts`, which removes only
directories matching `CAPTURE_ID_PATTERN` and never anything else in the
folder — on OPFS an empty keep-list was harmless, on `%LOCALAPPDATA%` it is a
recursive delete of a directory a person can drop files into. Enforced by
`scripts/capture/prune-guard.ts`.

**No captured frame crosses the renderer's main thread.** ADR 0007. Main pumps
the pipe into a port the renderer transfers into the Worker without reading.
*Unenforced* — nothing fails if someone adds a frame-carrying message to
`FromPipeline`. The 100 ms flush is the one place frames legitimately arrive,
already dissected.

**The renderer does not iterate the capture to answer a question about it.**
Rows come from `src/lib/rowSource.ts` over `captureClient.ts`; bytes come from
`src/services/packetBytes.ts`. *Partially enforced* —
`scripts/session/row-source.ts` covers the row path.

**A display filter has one answer, and the store computes it over the whole
capture.** The expression is sent to the store, which compiles it with the
renderer's own `filter/compile.ts` and returns a bitmap over capture ordinals
(`captureScan.ts`, `matchSet.ts`, ADR 0031). There is deliberately no second
evaluator: a prefix-block accelerator would answer differently from the
in-memory filter on exactly the frames nobody can see to check. Enforced by
`scripts/capture/store-protocol.ts`, which compares the scan's ordinals against
the same expression run in memory, and by `scripts/session/capture-row-space.ts`
for the arithmetic that splits disk rows from window rows.

**No Node in the renderer, and the preload imports only `electron`.** Enforced
by `scripts/electron/preload-sandbox.ts`, which reads the **built** bundle: what
esbuild inlined is harmless, what it left as a runtime `require` is fatal. This
one exists because `node:os` in the preload type-checked, bundled, and then
took the whole bridge down with no message anywhere.

**Electron fuses, and ASAR integrity.** `runAsNode`,
`enableNodeCliInspectArguments` and `enableNodeOptionsEnvironmentVariable` off;
`onlyLoadAppFromAsar` on. **NOT IMPLEMENTED.** electron-builder does stamp ASAR
integrity (it logs `updating asar integrity executable resource` during
`npm run pack`), but no fuse is flipped. Flipping mutates the exe, so this must
land **before** signing — without `runAsNode: false` any local process can run
the signed exe with `ELECTRON_RUN_AS_NODE=1` and pass every signature check.

**CSP is served as a header, not a meta tag.** `electron/csp.ts`, applied in
`hardenSession`. `OUTBOUND_HOSTS` is the whole list of places this app can
reach: **geojs** (map geolocation), **cloudflare-dns** (DoH reverse lookups),
**ipapi.co** (the Network panel's public-identity section) and **openfreemap**
(basemap tiles). Enforced by `scripts/electron/shell.ts`, which also asserts
that the agent's old port `8999` is **not** in the policy — a `connect-src`
entry nothing dials is a hole with no user. Three of the four are behind a consent switch and the fourth is not, and
**which switch is not uniform**: geojs and ipapi.co are behind
`nameResolution.geoIp`, the DoH resolver is behind `nameResolution.reverseDns`
— they are two separate Settings rows — and the basemap tiles are behind
neither, loading whenever the map is shown. See **Direction**.

**Main reaches two more hosts, and they are deliberately not in the policy.**
The update feed and `npcap.com` are dialled by `net.fetch` in the main process,
which is not a page and which no CSP governs — so a `connect-src` entry for
either would grant the *renderer* permission to reach a host it never touches,
which is the same hole with no user as `8999`. What is kept is the list:
`MAIN_OUTBOUND_HOSTS` in `electron/csp.ts` records both with their purposes,
and `shell.ts` asserts they are **absent** from the policy, that the recorded
feed host is the one `updateCenter/manifest.ts` actually dials, and that the
recorded Npcap host is the one its download allowlist admits. Both are behind
an explicit action: the feed behind `inwire.updates`, which is off until asked,
and Npcap behind a click.

**Cross-origin isolation is on.** `ISOLATION_HEADERS` in `electron/main.ts`
sets COOP/COEP on every `app://` response, so `crossOriginIsolated` is true and
`SharedArrayBuffer` exists. Nothing depends on it yet. Enforced by
`scripts/electron/smoke.ts`, which evaluates `crossOriginIsolated` in the
running window — so this is checked on every `npm run check`, not by hand. The
one gap left is the build it drives: `smoke.ts` launches `dist/`, so the
*packaged* app is still only verified by hand.

**The pipe's ACL is the authentication.** See the banner at the top.
`local-agent/test_protocol.py` pins the SDDL's shape — `IU` present, `WD`/`AN`/
`NU` absent, `D:P` — and `scripts/electron/agent-link.ts` drives the real client
against a real pipe. Neither can tell you the descriptor took **effect**; that
needs a second Windows user account and is in `docs/verification.md`.

**The two TypeScript programs share their strictness flags, and stay
separate.** `tsconfig.json` (renderer plus scripts) and
`tsconfig.electron.json`. There are **two, not three** — the migration plan
called for a third for `scripts/` and it was not split, deliberately: an
assertion script imports `src/` directly and must type-check against the same
lib the renderer uses. Enforced by `scripts/electron/tsconfigs.ts`, which
checks both halves — the four flags matching, *and* that `electron/` is
excluded from the root program and has no DOM. Either alone is worthless: a
lost `exclude` puts main back under the config where `window` compiles.

**`src/services/` and `src/lib/` import no Electron and no `node:*`.** This is
what keeps the assertion scripts runnable under plain `tsx`. Enforced by
`scripts/capture/node-safe.ts`, with one recorded exception —
`nodeBlockFile.ts`, which imports `node:fs` because that is its whole job. The
rule with teeth is the third one there: that module must not be **reachable**
from `src/main.tsx`, which is a walk of the import graph rather than a grep,
because the hazard is transitive. `captureClient.ts` sits one import away from
it and is reached from `App.tsx`.

**Dissection matches tshark.** `test/fixtures/` holds two real captures
(untracked; ADR 0004) and tshark ground truth.
`npx tsx scripts/parity/parity-check.ts` diffs Protocol, Source, Destination,
Time, Length, Info and the matched colour rule against it, held to the floors in
`test/fixtures/acceptance.json`. **Floors only rise** —
`scripts/parity/acceptance.ts` fails a lowered one.

## 6. Gotchas found only by running the packaged app

Each of these type-checked, built, and failed silently at runtime.

**maplibre's worker under `app://`.** `defaultWorkerUrl()` tests `/^https?:/`
against `import.meta.url`; under `app://` it returns `""` and `new Worker("")`
loads `index.html` as a module worker — the worker dies before registering a
handler and maplibre reports nothing, tiles just stay `loading` forever. Fixed
with `setWorkerUrl`, which **must** come before `setRTLTextPlugin` because that
builds the worker pool. Guarded by `scripts/electron/shell.ts`.

**`node:os` in a sandboxed preload.** Not resolvable; the preload throws while
loading, `exposeInMainWorld` never runs, `window.inwire` is `undefined`, and
nothing says so. Guarded by `scripts/electron/preload-sandbox.ts`.

**COEP blocks same-origin workers.** A dedicated worker's script must carry
`Cross-Origin-Embedder-Policy` itself. Set on the document via
`onHeadersReceived` — which does not fire for `protocol.handle` responses —
both `pipeline.worker` and maplibre's worker failed with
`coep-frame-resource-needs-coep-header`. The headers live on the Response in
`registerAppProtocol`. *Unenforced.*

**A synchronous pipe handle serialises writes behind a blocked read.** Without
`FILE_FLAG_OVERLAPPED`, the writer thread's `WriteFile` queues behind the reader
thread's `ReadFile` and waits for bytes that are not coming. `hello` and the
first reply arrived; everything after did not — it works on the handshake,
which is what gets tested, and stops on the traffic. `local-agent/pipe_server.py`
now gives every operation its own `OVERLAPPED` with its own event.

**A cached "is the style ready?" that a lost GPU context invalidated.** The
tell in a terminal is Chromium's own `command_buffer_proxy_impl.cc ... GPU state
invalid after WaitForGetOffsetInRange` - a driver reset, a GPU process crash or
a laptop changing adapter, reaching the renderer as a lost WebGL context.

MapLibre handles the WebGL half well: `_contextLost` calls `preventDefault()` so
the browser will restore, snapshots the style, then **destroys it and sets
`map.style = null`**; `_contextRestored` puts it back with `setStyle(...,
{ diff: false })`, whose `style.load` is already `GeoMap`'s recovery path for a
theme change - skin, declutter, land wall, sky, projection, arcs, a fresh
`PinLayer`. What MapLibre cannot know is that `GeoMap` caches the answer to "may
I touch the style?" in `styleReadyRef`, deliberately, because `isStyleLoaded()`
asks a different and much slower question.

Left true across the gap, every guard waved through a call against a style that
no longer existed - and `_contextRestored` calls `resize()` before its own style
has loaded, `resize()` fires `moveend`, `GeoMap` answers that with
`syncConnectionsLayer()`, and `addLayer` threw **Style is not done loading.**
out of MapLibre's restore, abandoning it before its closing `_update()`.

**The cost was narrower than it first looked, and saying so is the point.** The
layers do come back either way: `style.load` fires from the `setStyle`
regardless. That was established by losing the context a second time and reading
which custom layers MapLibre names in its own warning - both, with the bug in or
out. What the stale flag bought was an uncaught exception on every GPU recovery,
not lost data. The fix is one line in a `webglcontextlost` handler, because
`syncConnectionsLayer` already reschedules when the style is not ready.
`scripts/electron/gpu-restore-drive.ts`.

**A `queue.shift()` inside a `find` predicate.** The dock's drag-reorder read

```ts
items.map((item) => (item.open ? items.find((i) => i.type === queue.shift())! : item))
```

which shifts once per element `find` **compares**, not once per open slot. The
queue drained in the first couple of comparisons, `shift()` returned `undefined`,
nothing matched, and the non-null assertion let `undefined` into the list - so the
next render read `undefined.open` and took the renderer down. Deterministic on the
first drag that actually moved anything, and it shipped because nothing in the
suite could reach a `useCallback` in `App.tsx`.

It was also **persisted**: `createPreferenceStore`'s `set` does not normalise, only
`loadPreference` does, so the hole was written out as `null`. The key self-heals
because `normalizeItems` skips those and appends the missing types closed - which
is the whole argument for repairing rather than rejecting, arriving unasked.

The arithmetic was moved out to `reorderItems` in `dockPrefs.ts`, beside
`dockOrder`, where `scripts/session/dock.ts` could reach it and every refusal
returned the list unchanged rather than asserting - and putting the bug back made
that script throw the same `Cannot read properties of undefined` the renderer
did. **Both files went with the dock and neither is here to run**; the entry is
kept for the shape, which outlives its subject: a `shift()` inside a predicate
runs once per *comparison*, not once per match, and a non-null assertion over a
`find` is where `undefined` gets into a list. The general lesson is the one above
it - a `useCallback` in `App.tsx` is unreachable from this suite, so arithmetic
worth testing has to be lifted somewhere a script can import it.

**`readSync` returns short counts.** Not an error, a partial read. `readExact`
threw on short and recovery read that as a torn tail. `nodeBlockFile.ts` loops;
`scripts/capture/block-file.ts` injects short reads.

**Auto-pause made the disk buffer unreachable.** `AUTO_PAUSE_AT` was 0.99 and
`planBufferTrim` acts above `1 + BUDGET_SLACK` = 1.05, so capture stopped before
the trim ever ran. Replaced by `DISK_RESERVE_BYTES` in
`src/services/bufferBudget.ts`; `scripts/session/buffer-budget.ts` asserts the
inversion.

**`prune([])` on a real directory.** Harmless on OPFS, a recursive delete of
`%LOCALAPPDATA%\Inwire\captures` here — and reached whenever `loadSessionMeta()`
returns nothing. `scripts/capture/prune-guard.ts`.

**`{userappdata}` in an elevated Inno installer** is the account that answered
the UAC prompt, or `systemprofile` under Intune. Dissolved: nothing per-user is
provisioned any more.

**`uac_admin=True` makes `--version` raise a UAC prompt.** Harmless in the
installer, which is already elevated; it hangs a command run by hand.

**`reg query` error shapes.** A missing key gives `error.code === 1` (a
**number**) with empty stdout; success gives no error at all. `provesAbsent` in
`electron/agentService.ts` originally tested `code === undefined`, which is the
shape of success — so a missing service read as unknown and a failure to ask
read as missing, sending somebody to reinstall over a working install.
`scripts/electron/agent-health.ts`.

**`Start-Process -ArgumentList ''` throws.** It does not run the program with
no arguments — it fails parameter validation with *"Cannot validate argument on
parameter 'ArgumentList'. The argument is null or empty."* The component that
takes no arguments is **Npcap**, deliberately, because the alternative is `/S`
— so the Update Center failed on the one install it exists to perform, one
second after the click, with "the installer could not be started" and no UAC
prompt at all.

Nothing in the 177-assertion suite could have caught it. The argument list was
right, the marker parsing was right, and PowerShell's *parser* accepts the line
— `[Parser]::ParseInput` returns no errors, and that check was already being
run. It is the cmdlet's parameter validation that rejects it, at run time, only
when the variable happens to be empty. Found by clicking the button on a real
machine, which is the only thing that would have.

Fixed by splatting a hashtable and omitting the key when there is nothing to
pass, which keeps the command line a constant. `elevate.ts`; four assertions in
`scripts/electron/update-center.ts`, including that no bare `-ArgumentList`
survives in either script.

## 7. Testing

Assertion scripts under `scripts/`, discovered by `scripts/check.ts` walking
the directory; a handful are listed there as SKIP with a reason each
(measurements with no right answer, or things needing the untracked fixtures). Plain `tsx`, no runner, no Electron, no browser. A script
prints `PASS`/`FAIL` lines and exits non-zero.

**`docs/verification.md` is the other half**, and it is a real document rather
than an aspiration: everything this repository knows to check and cannot check by
itself - the window's own chrome against both themes and three scaling
factors, Snap Layouts, the drag regions, the two bottom panes and their
divider, the pipe's security descriptor taking effect (which needs a second
Windows account), and the UAC prompt. Each item says what a failure *looks like*, because everything in it
fails silently - which is the reason it is there and not in a script.

Three rules keep it that way, and all three are now checked:

1. `src/services/` and `src/lib/` must import no Electron and no `node:*` —
   `scripts/capture/node-safe.ts`.
2. `nodeBlockFile.ts` must not be reachable from `src/main.tsx` — the same
   script, by walking the import graph from the renderer's entry point. The
   failure names the chain, because "something reaches it" is not actionable
   and "App.tsx -> captureClient.ts -> nodeBlockFile.ts" is.
3. Both tsconfigs carry the same strictness flags —
   `scripts/electron/tsconfigs.ts`.

The fixtures are two real captures, untracked because they contain personal
addresses (ADR 0004): `inwire` (general browsing) and `bulk` (a long TLS
transfer, and 30 TCP streams with exactly one SYN, which makes it the one that
catches anything assuming a capture opens with a handshake). They assert
per-column mismatch floors and the expert-category counts in
`scripts/expert/categories.ts`.

**`scripts/capture/store-protocol.ts`** drives the store's whole message union
through `CaptureHost` against a memory volume. It proves the protocol, not
Electron's IPC — there is no `MessagePort` and no second process — and it opens
with the rule that has a hanging UI behind it: every request answers, even when
it fails. The scan's state machine is four of its assertions, each checked by
putting the bug back.

**`scripts/session/capture-row-space.ts`** drives the arithmetic that decides
what row *i* of the list is. Getting that wrong shows the wrong frame at the
right row height, so the check is a count computed two ways: the list has
exactly as many rows as the filter has matches over the whole capture.

`scripts/parity/synthetic.ts` covers protocols the fixtures do not contain:
frames built byte by byte from an RFC, written to a real `.pcap`, handed to
tshark, compared as exact strings.

**`scripts/electron/smoke.ts` drives the real app.** Playwright's
`_electron.launch`, a real Electron process over a real named pipe against
`scripts/electron/stubAgent.ts`, which speaks the production protocol: pick an
adapter, Start, wait for rows, read the Info column. A pass means bytes went
from a socket through main, a `MessagePort`, the Worker, the dissector and
React onto the screen.

It exists because three of the worst bugs in the migration were invisible to
every other script here and were all found by hand — the maplibre worker URL,
`node:os` in the preload, and COEP blocking `pipeline.worker`. Verified by
reintroducing two of them: the preload one reports the bridge `undefined`, and
the COEP one reports the agent never connecting, because the Worker never
loaded.

Four things about running it. It uses a **temporary profile** via
`INWIRE_USER_DATA`, because the app prunes its capture directory at startup and
would otherwise delete a developer's stored capture on every `npm run check`.
It tests whatever is in `dist/` — `npm run check` does not build, so it prints
the build's age and says so when that is over two hours. Every locator carries
a 30-second timeout, because Playwright's default is **none** and a control
that never renders would hang the whole suite with no output rather than fail.
And it clears `setUnsavedCapture` before closing: closing with frames in the
buffer opens `guardClose`'s native "Quit Inwire?" box, which is not in the page
and which no test can answer. Killing the process instead was tried and is
worse — `kill()` reaches main and orphans the GPU, renderer, store and crashpad
children.

**An import is no longer capped by memory.** `PcapService.streamCaptureFile`
hands frames over as it dissects them; `App` writes each batch to the capture
store and keeps the newest `framesForBudget(...)` in the buffer. A 400,000-frame
file imports whole where it used to stop at ~181,000 and say the rest had not
been loaded. What bounds the pass is `IMPORT_PATCH_WINDOW` - frames stay in
reach of a patch for 100,000 frames, the same rule `captureWriter.ts` follows,
because dissection amends frames it has already emitted by indexing into the
array it is building. `scripts/capture/import-stream.ts` compares the streamed
result field for field against the whole-array one, with the window forced
small enough that frames actually leave it - at the real 100,000 a test capture
never fills it, and the first version of that comparison passed with the offset
arithmetic removed entirely.

Still true of an import: the file is read with one `arrayBuffer()`, and the
dissection blocks the main thread. Streaming changed where the frames end up,
not who does the work.

**`scripts/electron/gpu-restore-drive.ts` reaches the GPU.** It loses a real
WebGL context under the running map and restores it, which is the one failure in
this app that needs a live GL context to exist at all - so it cannot be a plain
`tsx` script like everything else. In `NOT_TESTS`; run it by hand after anything
touching GeoMap's style or layer lifecycle. It skips rather than fails on a
machine with no map on screen, because the map only exists once geo-IP lookup
has been consented to.

**`scripts/electron/disk-drive.ts` and `import-drive.ts` reach the disk.** `smoke.ts` captures a
few thousand frames, which fit in the RAM buffer, so it never touches a stored
row; one drives a capture past the 128 MB budget until the window trims, then
filters the whole capture and reads the top of the result back off disk; the
other imports a 400,000-frame file and scrolls back to frame 1. One to two
minutes each, so both are in `NOT_TESTS` and run by hand — after anything on
the store path. They are what prove the half of the app that `smoke.ts`
structurally cannot.

**`scripts/electron/update-center-drive.ts` reaches the network and the
registry.** It stands up an HTTP feed on a loopback port, points
`INWIRE_UPDATE_FEED` at it and drives the real app against it - and it builds
the manifest from **this machine's own installed Npcap version**, which is
what lets the central assertion be exact: told the version it has, the row
must read `up-to-date`; told one digit more, it must offer it. That pair is
the `wpcap.dll` trap, and a build that read the libpcap number fails the
first half on any machine with Npcap on it. It also drives the **driver-access
row**, against whichever mode this machine is in: the label, the
recommendation and the reinstall control appear together or not at all. In
`NOT_TESTS`; run it by hand after anything on the update path. It installs
nothing - the UAC prompt is the one step that stays with a person.

**To drive the app by hand**, `npx tsx scripts/electron/serveStub.ts` serves the
same stub until Ctrl+C (`--burst n` for n frames per 100 ms tick); launch the app beside it and pick "Ethernet (stub)".
Otherwise testing by hand needs the real service, which needs Administrator,
Npcap and traffic — and a development machine that still has a pre-3.8.0 agent
installed has no pipe at all, so the app shows "not connected" and there is
nothing to click.

## 8. Migration status

*As of 2026-09-15.*

Phases 1–5 of the Electron migration are done, and so is 7 but for its last
item. The plan is
`~/.claude/plans/lets-pick-up-where-agile-shore.md`, which was repurposed for
the Update Center — its banner is the status of record for what was left.

| Phase | What | Landed |
|---|---|---|
| 1 | The Electron shell, `app://inwire` | `ce9d4d8` |
| 2 | The capture store on real files, in its own process | `9971b45`, `bcf3c58` |
| 3 | The named pipe; the token deleted; the agent bundled | `677cc41`…`4bbbfc7` |
| 4 | Native save dialogs | `8b7be01` |
| 5 | The web page deleted | `6d97c46`…`4010d7b` |
| 6 | Installer, signing, updates | **deprioritised** — `d2423f2`; see below |
| 7 | Rebuild what the browser forced | `73e5c26`…`3879433`, `380976e`, `b07f165`; the offline basemap is what is left |
| 8 | Import-to-disk; `captureScan` wired to the filter bar | **in progress** — `1bfcbf9`, `93cd08b`, `7c5dd21`, `992b1d5`; scaled scrolling is what is left |

**Phase 6 is deprioritised, not blocked.** It waits on a code-signing
certificate (EV or Azure Trusted Signing) outside this repository — but signing,
the fuses, the VM matrix and the Npcap OEM licence were all set aside
deliberately, because this is a machine the author works on rather than a fleet
they ship to. The installer compiles; the fuses are still to flip, and must land
**before** signing. Read the row as a choice, not a gap.

**Phase 7 landed on 2026-09-13**, in the thirteen commits that row spans: the
window's own title bar, the activity rail (56px then, 44 now), the dock that replaced the
right-hand column, the hamburger's deletion, and Custom Dissectors and Network
becoming Settings tabs. §3 describes the result. Its **no-GPU fallback landed
with it** — `src/components/analytics/renderTier.ts`, two tiers rather than
three, asserted by `scripts/perf/render-tier.ts`. What remains of the phase is
the **offline basemap**: `tiles.openfreemap.org` is still in `OUTBOUND_HOSTS`
(`electron/csp.ts`) and there is no `d3-geo`. See **Direction**.

**The shell had a second pass after that date, and §3 is where it is described,
not here.** This table is a record of what landed when, so its Phase 7 row still
names the dock - which was built in that phase and deleted after it. What changed
since: the dock and its whole widget apparatus deleted, **Frame Detail promoted
from a modal to a view** (so `Ctrl+2` is it and the three views after it each
moved a key), **Find packet deleted** in favour of that view's go-to-frame box,
the app-wide status bar reverted to `HexViewer`'s own footer, the filter row
scoped to Packets alone, and the chrome moved from `--card` to `--secondary` with
the `INWIRE` wordmark deleted. Read §3 for the result; read this row for the
order things happened in.

**The Npcap question is answered rather than blocking.** It was "does the
silent install need an OEM licence", and the answer is yes - so the installer
stopped installing it. See **The Update Center** and ADR 0032.

**Phase 8's filter works end to end**, watched: a 178,200-frame capture with a
115,476-frame window, `udp.srcport == 49152` matching 44 frames across the
whole capture where the window alone holds 28, and the top of the filtered list
reading frames 4,096 apart off disk. `scripts/electron/disk-drive.ts` is that
run, kept.

Getting there turned up the bug that had made the entire disk path inert since
the store became a process — see **The bug that hid the whole disk path**.

**The ADRs the migration owed are written**: 0027 (the app is a desktop app),
0028 (where the store runs, with the boundary measured), 0030 (one installer),
0031 (the whole-capture filter). 0029 was already there. 0032 followed, for
the update path.

### The bug that hid the whole disk path

Recorded because it shipped, it was reported thousands of times, and nobody
could see it.

**The store stored no rows at all.** A buffered `Packet` carries its 33
commonest fields in a `FieldBlock` — a **class instance** — and a structured
clone drops prototypes. The moment the store became a `utilityProcess` rather
than a Worker in the same context, every frame arrived with a `cols` object
that had no `read` on it, `encodeChunk` threw `block.read is not a function`,
`CaptureHost` caught it and posted a non-fatal `failure`, and the next append
did the same. For the life of every capture.

What that looked like: a capture directory whose `frames.iwbyt` grew and whose
`index.iwidx` stayed empty. `chunkCount` 0. `ordinalOf` answering **-1** for
every frame, which the app reads as "not addressable yet" and turns into
`below = 0` — so the list showed the RAM window, said the window was the whole
capture, and looked entirely normal. The restore, the scrollback below the
window and the whole-capture filter were all inert.

Two things had to be true for it to hide:

- **Nothing crossed a boundary in a test.** Every assertion script handed
  `CaptureHost` the objects it had just built, in one JavaScript context, where
  the prototype survives. `scripts/capture/store-protocol.ts` now puts every
  appended frame through `v8.serialize`/`deserialize` first, which is the same
  serialiser a `postMessage` uses — and that reproduces it in a second.
- **Nothing reached the disk path in the app.** `smoke.ts` captures a few
  thousand frames, which fit in the buffer. `scripts/electron/disk-drive.ts`
  now drives a capture past the RAM budget and asserts the two counts diverge,
  which is the one thing that cannot be faked.

The fix is `src/services/capture/storePacket.ts`: frames are flattened at the
boundary, dense columns folded back into `fields`. Flattened rather than
rehydrated because the block holds 4,096 rows and a batch is ~300 frames, so
the same half-megabyte would cross fourteen times as it fills.

**It has a second half, which is the part worth remembering.** `prepareBatch`
calls `persist` *before* `absorb`, and `CaptureClient.send` awaits the port —
so the store is handed frames that do not yet have a block, and the
`postMessage` serialises them a microtask later, after the field writer has
attached one. A `plainForStore` that returned the packet unchanged when there
was nothing to fold therefore fixed nothing. **A message is a snapshot**: it
always copies.

`fieldAccess.ts` now throws a named error for a block with no methods, naming
the rule and the fix rather than `read is not a function`, and `CaptureHost`
logs the stack to stderr — which main pipes to a log — as well as the message
to the app. The original was visible only as `state.error` in a panel nobody
had open.

### What the store actually costs

`npx tsx scripts/perf/store-boundary.ts`, over 100,000 realistic frames in
batches of 300:

| | |
|---|---|
| `CaptureWriter` + `NodeBlockFile`, no boundary | 26.68 µs a frame — **37,477 f/s** |
| serialize + deserialize (`v8`) | 5.27 µs a frame |
| the whole hop over a real `MessagePort` | 5.26 µs a frame |
| **both together** | 31.94 µs a frame — **31,308 f/s** |

The crossing is **16%**, and 1,955 B a frame on the wire. This is the number
ADR 0028 was waiting for, and it says the opposite of what was assumed: moving
the store back in-process would buy 16%.

One thing that looked worth having and is not: the writer's per-frame
`writeSync` costs 3.40 µs where the same bytes in one write a batch cost 0.28,
which reads as 12% of the writer — and batching the writer for real measured
**3% slower**, twice, because copying 1,100 bytes a frame into a coalescing
buffer costs more than a `writeSync` to a file the OS has cached. Tried,
measured, reverted; the comparison is still in the script, labelled as the trap
it is.

### The store's memory ceiling is enforced by us

`execArgv: ['--max-old-space-size=2048']` in `electron/store/host.ts` **does
not work**. The flag arrives — the store's own `process.execArgv` reads it
back — and `heap_size_limit` is 4192 MB, V8's 64-bit default, because V8 fixes
the limit when it creates the isolate. `v8.setFlagsFromString` at the top of
the entry point does not move it either. Both measured against the running app,
after the store was seen to die at 4,060 MB.

`electron/store/heapGuard.ts` samples the heap every two seconds, warns once at
80% while the capture can still be stopped whole, and seals and stands down at
the ceiling with a message — which a V8 abort cannot give. The wall is the
lower of our 2 GB and 90% of V8's own limit. `scripts/capture/heap-guard.ts`.

Still unfixed: the store's inbound queue is unbounded, and each pending
`append` holds its frames. It has not been seen to matter since the throughput
was measured — the store takes 31,000 frames a second and the app feeds it far
less — so the 4 GB heap remains unexplained rather than diagnosed.

## 9. The Update Center

*The only place this app updates anything.* ADR 0032.

One Settings section (`Settings → Updates`) listing every updatable component:
the app, the capture agent, the Npcap driver, and two databases that are
declared and have no consumer yet. `electron/updateCenter/` is the pipeline,
`src/services/updateCenter.ts` is what the renderer accepts and calls things,
`UpdateCenterPanel.tsx` arranges it and decides nothing.

**The installer no longer installs Npcap.** It used to download it and run it
with `/S` — Npcap's **OEM silent-install feature**, used against the free
installer, whose licence does not grant it. The pin was also a compile-time
`#define` (1.79, against a current 1.88), so correcting it meant shipping a new
installer; and `[Run]` ignores exit codes, so a failed driver install produced a
"successful" product install with no capture capability and nothing on screen.

### The pipeline

```
detect  → the installed version (registry / hello / app.getVersion)
fetch   → net.fetch, in MAIN, streamed to a fresh random temp directory
verify  → sha256, and the size must match exactly
elevate → powershell -EncodedCommand <constant>, path in the environment
confirm → re-read the installed version; the row proves itself
notify  → for Npcap: cycle the agent link so interfaces re-enumerate
```

The fetch is in main because **the renderer must never learn the path** — the
path is what gets run elevated. It also gets Chromium's network stack, so a
proxy works without this code knowing what a proxy is.

Elevation could not live anywhere else either. The renderer has no rights; the
agent is LocalSystem but runs in **session 0, which has no visible desktop**, so
an installer wizard launched from there draws where nobody can see it and blocks
for ever on a click that cannot happen.

### Three things about Npcap that are all traps

Each produces a confident wrong answer rather than an error.

| Source | ProductName | Version on a machine running Npcap 1.88 |
|---|---|---|
| `System32\Npcap\wpcap.dll` | **libpcap** | **1.10.6** |
| `System32\Npcap\Packet.dll` | Npcap | 1.88 |
| `Uninstall\NpcapInst\DisplayVersion` | — | 1.88 |

**Nothing reads `wpcap.dll`.** It carries the libpcap API version it
implements. Compared against a feed advertising 1.88 it says "update available"
for ever — including immediately after a successful install.

**`/reg:32` is asked first.** Npcap's installer is 32-bit, so `NpcapInst` lands
under `WOW6432Node`, and a plain `reg query` of the 64-bit view exits **1 with
empty stdout** — exactly the shape `agentService.ts`'s `provesAbsent` reads as
*proof of absence*. That helper reused unchanged reports "not installed" on a
machine where the driver is running.

**`installed` and `version` are two answers.** `HKLM\SOFTWARE\Npcap` holds no
version and on x64 does not exist at all, so a driver present with an
unreadable version says so rather than being rounded to either.

### The elevated command line is a constant

`ELEVATE_ARGV` is the same array on every call — a fixed base64 blob — and the
installer path travels in the child's **environment**, read back from `$env:`.
Nothing interpolates and nothing is quoted, so a path with a space cannot become
two arguments. That keeps `agentPipe.ts`'s invariant literally: *"the arguments
are constants."* The failure mode of the alternative is not a crash; it is
running a different file, elevated.

`Start-Process -Verb RunAs` reports a **declined UAC prompt by throwing**, and
its message is localised, so the result comes back as one machine-readable
marker line on stdout — same reasoning as `reg` over `sc query`. A decline is
`cancelled`, never `failed`: the row goes back to what it was and shows nothing.

**Awaiting our own installer deadlocks.** `setup.iss` sets
`CloseApplications=yes`, so Inno asks Inwire to exit before replacing the
payload; blocked in `-Wait`, each waits for the other and nothing is on screen.
So there are two scripts — `ELEVATE_ARGV` waits, `LAUNCH_ARGV` does not — and
`awaitsInstaller(kind)` is the single predicate that chooses, so a third caller
cannot reintroduce it. Our installer's exit code is unobservable as a result,
which is the right trade against a hang.

### The driver's access mode, which is the fourth trap

Npcap's installer has a checkbox — *"Restrict Npcap driver's access to
Administrators only"* — and it is **not ticked by default**. Unticked, the
capture devices are open to `WD`; measured here, `\\.\NPCAP` carries
`D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;WD)`, so any local account can read
this machine's traffic and inject raw frames. Inwire captures through the
agent, so the restriction costs its users nothing and is what the Npcap row
recommends. ADR 0033.

**Two facts answer it and they can disagree.** `AdminOnly` under
`HKLM\SOFTWARE\Npcap` is what the installer *recorded* — 32-bit view first,
same two traps as the version read, `electron/updateCenter/npcapAdminOnly.ts`.
The DACL on the device object is what the kernel *enforces*, read by the agent
because it is the SYSTEM process, and carried in `hello` as `npcapAccess`. The
**DACL wins**: the registry can be edited without the driver being restarted,
and "administrators only" over a device still granting `WD` is the one
direction a wrong answer must not go.

The agent sends the **SDDL string and not a verdict**, the same rule ADR 0010
sets for frames. `src/services/npcapAccess.ts` decides, and
`scripts/electron/update-center.ts` holds that decision to captured registry
output and captured descriptors — including `D:NO_ACCESS_CONTROL`, which is a
NULL DACL and therefore the *most* open answer while containing no ACEs at all.

`unknown` is a third answer and never rounded to either, and it carries no
recommendation: advising a kernel-driver reinstall on the strength of having
failed to read anything would be advice about a state nobody established.

**Changing the mode is a reinstall**, so the row grows a second button —
`canReinstall`, which is `up-to-date` only and therefore mutually exclusive
with `canApply`. It runs the identical download → verify → elevate path and
names the checkbox in the notice above it, because ticking it is the one step
Inwire cannot do: the alternative is a flag, and the flag is `/S`.

### After Npcap installs, the link is cycled

`AgentPipeLink.recycle()` — not `refresh_adapters`. That command re-reads
adapter *configuration* and never touches `AVAILABLE_INTERFACES`, the
capture-interface list the picker is built from, **and is itself filtered by
that stale list**, so a brand-new adapter is excluded from its own snapshot. The
agent re-reads the list in `register()`, once per client connection, so a
reconnect is what re-enumerates. Preferred over `restart_agent`, which also
works but kills a service the app deliberately has no rights to stop.

### The feed

One JSON document at `UPDATE_FEED_URL` — `https://updates.inwire.app/manifest.json`,
overridable by `INWIRE_UPDATE_FEED` in dev. **The domain does not resolve
yet** — it is not registered — so every check is a quiet no-op until it does,
which is the same path an offline machine takes and is already the ordinary
case rather than an error.

**Development does not take that path any more.** `npm run dev` and
`npm run start:app` stand up `electron/devFeed.cjs` on a loopback port and
point `INWIRE_UPDATE_FEED` at it, so a launch reaches a feed that answers
instead of printing `net::ERR_NAME_NOT_RESOLVED` on every run — the shape that
teaches somebody to stop reading their own log. An `INWIRE_UPDATE_FEED`
already in the environment wins and no server is started.

Its default manifest **offers nothing, and that is a constraint rather than a
choice**: `DOWNLOAD_HOSTS` is `null` for `inwire`, `agent`, `oui` and `geoip`,
meaning "the host the feed came from", and `hostOf` returns null for anything
that is not https. A loopback feed is http, so those four rows can never
validate there — and one malformed row for a known id rejects the *whole*
document, which would trade `not reachable` for `could not be read`. Npcap is
the exception, because its allowlist names npcap.com outright, so
`--npcap <version>` is the one row that can be served. Every row then rests at
`unknown`, exactly where an unreachable feed left it.

It is the
only remote input in this repository that can nominate an executable to be run
elevated, so it is validated strictly and **rejected whole** — the opposite of
how preferences are read, because a defaulted field here could mean "download
this URL with no hash".

The hash is not the interesting defence: whoever controls the feed writes the
hash too. What stops a compromised feed nominating an arbitrary binary is the
**download-host allowlist** — Npcap from npcap.com, our own artifacts from the
host the feed came from — matched **exactly**, never by suffix, because
`endsWith('npcap.com')` also accepts `evilnpcap.com`.

**Unreachable is quiet**: no dialog, one info line, nothing cleared, and "last
checked" does not move. A *malformed* feed takes the identical path, because a
document we cannot read is one we have no answer from, and rendering that as
"no updates available" would be a confident lie.

**The check is opt-in and off by default**, which is the product invariant
rather than a cautious default: a request Inwire makes unbidden appears in the
user's own capture. `inwire.updates` keeps `asked` separate from `automatic`,
because "no" and "not yet asked" are different and collapsing them turns a
one-time prompt into a recurring one.

### What it does not prove

A sha256 says the bytes are the ones the feed named. It says nothing about the
feed being honest and nothing about the publisher — **Authenticode verification
is owed and not built**. The freshly-created random temp directory stops a file
being *pre-planted* at the path and cannot stop the same user swapping it
afterwards, since that user can already rewrite the app's own payload. Both are
written down because a hash check next to a UAC prompt looks like more assurance
than it is.

The **Inwire row cannot be exercised yet**: there is no feed host and no
signature, so it reads "Not checked". The Npcap row works today.

### The state that had been a tooltip

`agentHealth` cannot express "driver missing" and still cannot, because it is a
*link* diagnosis and the link is fine: `diagnoseAgent` short-circuits on
`status === 'connected'`, and a driverless agent **is** connected — it answers,
it is healthy, it has nothing to listen on. `DriverInfoPanel` now describes that
directly from the two facts it already has, and links to the tab that fixes it.
Before this, the entire signal for the state a fresh install lands in was a
hover tooltip on a header button.

## 10. Direction

Validated sequencing, recorded so a future session inherits the reasoning.
These are **not** work in progress and get an ADR when each is started.

**A Rust agent, as the first post-migration project.** Why it is worth doing:
one signed exe instead of a 34 MB `--onedir` tree of unsigned `.pyd` files, no
interpreter to start, sub-second service start. Why it is *contained*: the
protocol is transport- and language-agnostic and both ends already assert the
same hand-written byte vectors, so the rewrite is bounded by tests that already
exist. Two gotchas to carry over: `wpcap.dll` lives in `System32\Npcap` and is
**not** on the default DLL search path, and the SCM integration wants the
`windows-service` crate rather than hand-rolled `StartServiceCtrlDispatcher`.
**It keeps the service model**: it replaces what the agent is written in, not
where it runs, and it does not fold capture into the app (ADR 0033).

**Engine-side dissection.** Move the pipeline Worker's work into the store
`utilityProcess` with a `worker_threads` pool over `SharedArrayBuffer`, sharded
by stream and merged back into timestamp order; the renderer becomes a viewer
that asks for rows. The store protocol was built so this is a relocation rather
than a rewrite. **Trigger:** a profile showing the cross-process copy on the
frame path, or a sustained rate above ~100 MB/s. Not before — and the first
step is measuring `append` and `readBytes` **across the boundary**, which has
**now been done** — `scripts/perf/store-boundary.ts`, and it does not say what
this entry assumed. The hop is **5.26 µs a frame** against the writer's
**26.68 µs**: 16% of the cost, 31,308 frames a second for the two together.
Moving the store back in-process would buy that 16%, which is not an argument
for anything. The trigger above still stands; the boundary is not it.

**Offline by default, as a product invariant.** No outbound connection the user
did not ask for. A packet analyzer that makes requests visible in the user's own
capture is a trust problem specific to this audience. First steps: an offline
`d3-geo` map to replace openfreemap's tiles, then the geolocation lookups behind
an explicit opt-in or a bundled database. The near-term step is an assertion
that every host in `OUTBOUND_HOSTS` has a recorded purpose and a consent gate.

**The dependency rule.** A shipped dependency must beat the platform API that
replaces it, and no native module lands without a measurement. The platform
answers already chosen or available: `printToPDF` for reports, `net.fetch` for
the updater, `dialog` for file I/O, `powerMonitor` for sleep gaps. The current
`dependencies` list still carries `jspdf`, `jspdf-autotable`, `pdfjs-dist`,
`exceljs` and `three` — the pass that weighs each against a platform API has
**not** happened. All five are genuinely imported and reachable from
`src/main.tsx`, which is the distinction that matters: they are **unweighed, not
unused**, and a census is what establishes that rather than a reading of this
paragraph.

**One was unused and is gone: `@heroicons/react`.** It was installed, 15 MB, imported by
nothing anywhere in `src/`, `electron/` or `scripts/`. It came back for an
afternoon as the candidate to replace Tabler and left again on evidence — no
outline cut below 24px, in an app that draws most of its icons at 12 and 14,
and 15 of 76 glyphs with no equivalent at all. **The icon set is
`lucide-react`**: 76 distinct glyphs across 41 files, imported where they are
used, held to one set by `scripts/themes/icon-set.ts` — which also insists
`Map` and `Image` are aliased, because both shadow globals and `tsc` will not
say so. It is worth the paragraph because it is the failure mode the dependency
rule does not catch: the rule asks whether a dependency beats the platform, and
a dependency nothing imports never gets asked. The cheap census is a grep per
entry in `dependencies`, and it is worth repeating before any pass that weighs
the five above.

**Cross-origin isolation is in place** (see Invariants) but nothing uses it.
`scripts/electron/smoke.ts` already asserts `crossOriginIsolated` against
`dist/`; what is still owed is the same assertion against a **packaged** build,
which is where the protocol handler and the headers behave differently.

**Not to do:** no V8 startup snapshots (VS Code-scale complexity for tens of
milliseconds); no MSIX (it cannot install a kernel driver or a LocalSystem
service cleanly); no Electron Forge migration (no Inno maker, and the update
channel is the trap — installed fleets only move forward on the updater they
shipped with). Electron gets security fixes for three majors; this is on 44, so
plan a bump roughly every other release.

## 11. Decisions ledger

`docs/decisions/README.md` is the index. One line each:

| ADR | | Status |
|---|---|---|
| 0001 | Two-phase packet model: summary on arrival, tree on demand | re-scoped by 0011 |
| 0002 | One field registry feeds tree, filters and columns | accepted |
| 0003 | Move the whole pipeline into one Worker | corrected by 0007 |
| 0004 | Fixtures stay untracked | accepted |
| 0005 | Agent wire format | **authentication half superseded by 0029** |
| 0006 | pcapng writer scope | accepted |
| 0007 | Bytes cross the worker boundary, trees do not | accepted |
| 0008 | Where TLS key material lives | accepted; **weakened by 0027** — see below |
| 0009 | Facts that did not come off the wire | accepted |
| 0010 | The agent captures raw frames and dissects nothing | accepted |
| 0011 | Dissection's cost was not the tree | accepted |
| 0012 | Stored captures persist until the user says otherwise | accepted; **mechanism superseded by 0025** (the rule stands) |
| 0013 | What a million frames actually cost | superseded by 0025 |
| 0014 | Bounding the trackers | accepted |
| 0015 | The colour index | accepted |
| 0016 | Pooling the per-frame lists | accepted |
| 0017 | The dense/sparse split | measured; **implemented by 0018** |
| 0018 | Implementing the field split | accepted |
| 0019 | Packet direction | accepted |
| 0020 | The leaf protocols | corrected by 0022 |
| 0021 | Where the parity chase stops | accepted |
| 0022 | A stream protocol is not expensive any more | accepted |
| 0023 | Decomposing the parser | accepted |
| 0024 | Carrying a message across segments | accepted |
| 0025 | The capture lives on disk | accepted; **Decision 1's mechanism superseded by 0027** |
| 0026 | One capture on disk | accepted; its quota arithmetic is void on a real disk |
| 0027 | The app is a desktop app | accepted |
| 0028 | Where the capture store runs, and what the boundary costs | accepted |
| 0029 | The app and the agent talk over a named pipe | accepted |
| 0030 | One installer, two destinations, the app never elevates | accepted; **its Npcap paragraph voided by 0032** |
| 0031 | A display filter answers over the whole capture | accepted |
| 0032 | Npcap is managed by the app, not shipped by the installer | accepted; **voids 0030's Npcap paragraph** |
| 0033 | The agent stays a separate service, and Npcap should be admin-only | accepted |

**ADR 0008 weakened, and it now says so itself.** Its argument was that key
material "is exactly as old as the tab"; a desktop app open for days breaks
that. That is a banner on the ADR rather than a note only here, which is the
point — a reader who follows the pointer is the one who needed telling. The
decision still stands; what moved is the bound, and the question is recorded as
reopened rather than answered. `crashReporter` stays **off** for the same
reason — a renderer minidump is a copy of `KeyLogStore`, so the usual advice to
enable it with `uploadToServer: false` for local dumps conflicts with 0008 and
is declined until the key-lifetime question is reopened.

---

## Architecture reference

The sections below describe the dissection engine, which the migration did not
change. They are the short form; the ADRs hold the reasoning.

### Data flow inside the renderer

`App.tsx` is the application's controller with a view attached.
`hooks/useKeyboardNavigation.ts` holds the window's shortcuts (everything reads
through a ref, or a `keydown` listener would re-register ten times a second
during a capture). **Space is scoped positively** — the body, or inside
`[role="grid"]` — and not by excluding the controls that must not receive it.
The old exclusion rule was correct only while nothing else in the window was
focusable; with a dozen rail buttons, Space on a focused one both activated it
and ran this handler's `preventDefault`, so the button's own activation was
suppressed and capture toggled anyway. Scoped positively, every control added
from here on is safe by default rather than by being remembered. `Ctrl+1..5`
switch views, and `APP_VIEWS` order **is** the numbering. **There is no
detail-window gate any more**: this hook used to bail out entirely while
`detailPacketId` was set, because a modal covered the window. Frame Detail is a
view, so the hook binds Up and Down and the pane binds Left and Right, and both
move the same selection. `hooks/usePacketBuffer.ts` holds the buffer — the arrival
queues, the accounting, the dense-field writer, the flush.
`hooks/useAgentConnection.ts` owns the agent link: status, version, interfaces,
capture state, drop counters, adapters, the agent's own log, and the health
diagnosis. Its four callbacks are held in a **ref**, not passed as effect deps,
or a new callback identity each render would reconnect once per render.

The flush lives in `services/packetBuffer.ts`, not in the hook, so it can be
called without React — which is what `scripts/session/ingest.ts` does, running
every commit twice because React does. `prepareBatch` is what must happen
exactly once; `commitBatch` must survive repetition.

A posted `Packet` carries its **bytes** and not its **tree**: a tree is 10.6 kB
against the frame's 1.2 kB (ADR 0007). Trees are dissected on demand by
replaying that frame's conversation (`services/pipeline/replay.ts`), because a
frame's tree is not a function of its own bytes — the TLS record cursor, the
QUIC keys, the DNS pairings and the TCP sequence bases are all state the frames
before it built.

The per-frame lists are pooled (`dissect/tokenPool.ts`, ADR 0016) and the 33
most common fields live in typed columns rather than in the bag
(`dissect/fieldBlock.ts`, ADRs 0017 and 0018) — 1,876 → 663 B a frame. The bag
is still the contract: a frame that never joined a buffer carries its whole bag.

The buffer is bounded by **bytes**, not a frame count
(`services/bufferBudget.ts`), because a frame is 60 bytes to 64 kB.

### The dissector

`services/pcapParser.ts` is the front door, decomposed into
`dissectors/networkLayer.ts`, `dissectors/tcpTransport.ts`,
`dissectors/udpTransport.ts`, `dissectors/portless.ts` and
`dissect/transportShared.ts` (ADR 0023). The link layer is read, not assumed
(`dissectors/linkLayer.ts`). IPv4 and IPv6 fragments are reassembled through
`services/l3Tracker.ts`. Leaf UDP protocols dispatch from a table
(`dissectors/udpDispatch.ts`); protocols are also found by content where no port
claimed the payload (`dissectors/heuristics.ts`), under the rule that every
detector must reject every other's payloads.

TCP analysis is Wireshark's `tcp_analyze_sequence_number` as a pure function
(`dissect/tcpAnalysis.ts`). TLS reassembles records across segments with a
per-direction cursor; JA3/JA3S/JA4 are computed from the hellos. Decryption
runs in the summary pass, not on demand, because TLS records, HTTP/2 frames and
HPACK tables are all cross-frame state.

Every key a dissector writes into `Packet.fields` must be registered in
`dissect/fieldRegistry.ts` with its Wireshark abbreviation, and every abbrev is
held to `tshark -G fields` by `scripts/dissect/wireshark-abbrevs.ts` — the
registry's promise is that a filter learnt in Wireshark works here, and that
check found 40 of 339 fields wrong.

### Display filters

`services/filter/`: `lexer.ts` → `parser.ts` → `compile.ts`, with `fields.ts`
resolving names through the registry. `==` is equality, not "contains". A
bareword is a layer test read from `Packet.frameProtocols` and nothing else. A
name this build cannot produce matches nothing. `scripts/filter/engine.ts` holds
a 50,000-frame pass to a 50 ms budget.

### Enrichment, export and theming

Name resolution is **passive** — every name comes out of the capture
(`services/nameResolution.ts`). Direction (`services/direction.ts`, ADR 0019) is
the fact a capture taken on an endpoint has and one taken anywhere else does
not. Process attribution comes from the agent's socket table
(`services/flowAnnotations.ts`, ADR 0009), under the rule *enrich only from the
captured machine, never from a third party*.

Export: `PcapService.generatePcapBinary` writes classic libpcap;
`services/pcapngWriter.ts` writes pcapng, which is the only one that can name
the adapter, keep nanosecond timestamps, carry the names the capture taught us,
and record what the capture missed. `services/anonymise.ts` is
prefix-preserving over Crypto-PAn; MACs keep their OUI.

**Typography is the faces the host OS ships** — on Windows, Segoe UI Variable
on `--font-sans` for the chrome and Cascadia Mono on `--font-mono` for the
data, declared once in `src/index.css` and nowhere else, and **no webfont is
imported at all**. The system face is hand-hinted for the 12px most of the UI
is set in, and it is the face every other window on the desktop wears. Windows
is the only desktop today and macOS and Linux are coming, so the stacks lead
with the named Windows faces and fall through to `system-ui` and
`ui-monospace` — SF Pro and Menlo on a Mac, fontconfig's answer on Linux —
which is the same decision in that OS's own words; the port's typography task
is to look at what those resolve to on a real machine, not to pick faces. The tokens
carried IBM Plex for one day (`7b4dded`) and Geist with JetBrains Mono before
that. Plex closed the seam the unrelated pair showed under every table header
and was retired on taste — square and dated beside the desktop — and Segoe
with Cascadia closes the same seam, being Microsoft's two faces drawn for the
same screen. Three facts were **measured against Chromium's DirectWrite path**
rather than assumed, and `index.css` records them on the tokens:
`"Segoe UI Variable"` does not resolve — DirectWrite exposes three
optical-size families with five named weights each and no axis, so **Small**
leads, being the cut for 12px and under; weight **500 snaps up to Semibold**
in both faces, so `--font-weight-medium` is 400 **under
`html[data-platform="win32"]`** — never in `@theme`, because SF Pro has a real
Medium and a Mac should get it — and `font-medium` means Regular on Windows,
which is Fluent's own ramp; `main.tsx` stamps the attribute from the bridge
before the first render; and Segoe UI Variable's figures are
proportional until `tnum` asks otherwise, which `body` does. **Cascadia Mono,
not Cascadia Code** — Code ligates `->` and `==`, and an Info column is a
place where the bytes must be drawn as written. Windows ships no Cascadia Mono
Italic, so the mono italic in the protocol tree is a sheared roman; accepted.
**There is no typeface picker.** The Accessibility tab used to offer Geist /
Atkinson Hyperlegible / Nunito and rewrite `--font-sans` at runtime; it is
deleted because a setting that moved the sans and not the mono put the seam
back for exactly the readers who reached for it. **Atkinson Hyperlegible went
with it, and that is a real loss, taken knowingly**: it was drawn to separate
I/l/1 and O/0 for low-vision readers, Segoe does not do that job, and nothing
replaced it. Reopening that question means a picker where every option
carries a matched mono. `scripts/accessibility/fonts.ts` holds the rest: no
`@fontsource` package installed or imported and no `@font-face`, the tokens
leading with the named faces and ending in a generic, the medium remap present
under the platform attribute and absent from `@theme`, the stamp in `main.tsx`,
`tnum` on `body`, no `font-family` outside `index.css` that is not a
token, and nothing writing either token at runtime. The one mix that survives
is the map's place names, baked into openfreemap's glyph atlases where no CSS
reaches; `.maplibregl-map` in `index.css` says so.

Theming is **two** themes declared in `src/lib/themeOptions.ts` - Day and Night
- each with a complete token block in `src/index.css` and a palette entry in
`src/services/themePalettes.ts`, plus System, which is a rule for choosing
between them rather than a third palette. Paper and Graphite were cut: each
existed as the other survivor's warm counterweight, which was an argument for
four and not one for keeping a spare of each. **Night took the `dark` id from
Graphite**, and that was the cut paying for itself - next-themes writes
`color-scheme` only for the literal strings `light` and `dark`, so while the
neutral dark theme was stored as `midnight` the native scrollbars and form
controls stayed on the light side of the divide for the theme most people use.
`RETIRED_THEMES` lands every stored `midnight` and `paper` on a real one. **There is no Colourful setting**: the four
`--chrome*` tokens painted a 64px accent header and a menu drawer that are both
deleted, and by the end the only thing the switch still changed was making the
brand mark invisible - white on white in Day and Paper. Its checks in
`scripts/themes/registry.ts` went on passing throughout, because they measured
the mark against `--chrome`, the bar it had stopped sitting on.

**The brand mark is outside all of this.** It is a stack of five isometric
plates - `src/lib/brandMark.ts`, ported from `logo/inwire-layers.svg` - and it
carries its own colours rather than taking `currentColor`, because a stack given
one colour is a silhouette of a hexagon. The rule is narrow and worth keeping:
the colours live with the geometry, and `BrandMark.tsx` holds none. Two
consequences are deliberate. **One ramp serves both themes**, so there is no
per-theme mark to keep in step. And **there is no second half to match**: the
`INWIRE` wordmark is deleted (§3), so the question this paragraph used to answer
at length - whether a lockup's two halves may carry different colours - has no
subject.

**The box is 100 and the numbers are the author's.** `MARK_SIZE` was 256 while
the mark was drawn at that size; this one is authored in a 100 box, so the box
followed the art. The point is that the coordinates in the module read straight
against `logo/inwire-layers.svg` with no arithmetic in between - scaling them to
keep the old constant would have made every number a decimal.

**Every plate is `--primary` at a different lightness.** `#0b6bcb`, hue 210,
saturation 0.90, with L at 0.22 / 0.34 / 0.46 / 0.58 / 0.70. That is what makes
five flat shapes read as one object rather than as five coloured tiles, and
`scripts/brand/icon.ts` measures it rather than trusting it: it converts every
fill and holds its hue and saturation to `MARK_ACCENT`'s own, so moving the
accent moves the rule. The order is load-bearing too, and also asserted -
darkest first, because the plates overlap and painter's order IS the depth.
`#c42b1c` is deliberately absent: it is the close button's red and stays the
alarm, and an icon that shares a hue with "this went wrong" spends it.

**The mark is tiered**, and the boundary is measured rather than chosen.
`primary` is five plates at **32px and up**; `small` is **every other plate** -
three - and is used **below 32**, which is what the title row's own 16px mark
gets. 32 is where five plates stop resolving: the gap is 9 in a 100 box, so
2.9px at 32 and 1.4px at 16, and at 1.4px the stack is one blue lump. Taking
every other plate rather than redrawing is what keeps the two tiers one mark:
same span, same ends of the ramp, twice the gap - so `small` is three bands at
the same 2.9px that works at 32. `icon.ts` asserts all of that, including that
the two tiers fill the identical box.

**Flat fills, no gradient**, so the no-gradient rule survives intact and the
bounds stay readable off the path data. That rule is not style: every artefact
below is rasterised from this one source down to 16px, where a gradient is mush.

**There is no background behind the icon, anywhere.** Every PNG is RGBA with
alpha 0 in the corners and in the gaps between the plates, and the `.ico`
payloads are those PNGs verbatim. The mark before this one painted an opaque
`#0c0a09` square behind itself, on the argument that Windows composites against
grounds nobody can predict - which is true, and is an argument for a mark that
reads on any ground rather than for shipping a black tile into the taskbar,
Alt-Tab and Explorer. `icon.ts` decodes the top-left pixel of every committed
raster and asserts alpha 0; it can do that in ten lines rather than with a PNG
decoder because on the first pixel of the first row every PNG filter type
reduces to the identity.

**Two marks came before this one and both are worth a sentence.** The first was
generated rather than drawn - one ribbon spiralling round a sphere, a spiral spec
and a projection emitting about 140 flat fills per tier. The second was a head-on
RJ45 connector, drawn, with eight contacts and a bevelled cavity. What has not
changed across all three is the module's JOB: one source, every icon generated
from it, colours there and not in the component - which is why the art is ported
into `brandMark.ts` each time rather than committed as the artist's `.ico`. A
binary dropped in beside the pipeline is exactly the drift the
regenerate-and-compare check exists to catch. `logo/` holds the author's
originals and nothing builds from them; `icon.ts` asserts that
`electron-builder.yml` names a file this pipeline writes.

**`Inwire.exe` had no icon at all until this landed** - `electron-builder.yml`
had no `win.icon` and `directories.buildResources` pointed at a folder that did
not exist, so the packaged app shipped Electron's default and nothing in the
suite could see it. It is `electron/resources/icon.ico` now, named explicitly,
written from the same buffer as `local-agent/icon.ico` with `icon.ts` asserting
the two are byte-identical. `BrowserWindow` takes the same file, which is what
`npm run dev` and `npm run start:app` show.

Run `npm run check` after any colour edit —
`scripts/themes/` enforces token completeness, contrast and CSS-vs-palette
drift.

### Vite config quirks — read the inline comments before touching

`vite.config.ts`: `maplibre-gl` is excluded from `optimizeDeps` because the
pre-bundler breaks its worker asset resolution; a plugin emits
`maplibre-gl-worker.mjs` at an unhashed name because maplibre computes the URL
from its own filename; the watcher ignores `local-agent/`, `release/`,
`release-artifacts/` and `dist-electron/` — the last two because chokidar holds
directory handles and electron-builder finishes a pack by **renaming**
`release/win-unpacked.tmp`, which fails with EPERM under a live dev server.

### Env vars

`vite.config.ts` reads `DISABLE_HMR`; `electron/main.ts` reads
`INWIRE_DEV_SERVER`, set by `npm run dev`. `updateCenter/manifest.ts` reads
`INWIRE_UPDATE_FEED`, set by both dev commands to the loopback feed and read
once rather than baked into a build. All have working defaults. There is
no `.env` of any kind. The root-level `security_spec.md` that described a
Firebase backend is gone; what was worth keeping - the twelve denial tests any
future sharing feature would have to pass - is
`docs/ideas/sharing-threat-model.md`, under a banner saying none of it exists.
