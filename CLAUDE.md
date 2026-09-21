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
>   frameless and draws its own controls. `thickFrame` defaults true and is the
>   only reason edge resizing, the drop shadow and the window animations
>   survive; `roundedCorners` defaults true and is Windows 11's radius. Neither
>   is ever set, at any value, and `scripts/electron/shell.ts` asserts the words
>   do not appear (`electron/window.ts`)
> - **`titleBarOverlay` / `titleBarStyle`.** Bringing either back means Windows
>   drawing a second set of caption buttons on top of the app's own — which
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
>   agent is a security and lifetime decision, not browser-era weight (ADR 0033)
> - **the surfaces that were replaced, each by something §3 names**: the dock
>   and its widgets (`components/dock/`, `dockPrefs.ts`, `dashboardPrefs.ts`,
>   `dashboardWidgets.tsx`, `scripts/session/dock.ts`), the hamburger menu
>   (`AppMenu.tsx`), the accent header (`Header.tsx`), the filter row
>   (`FilterRow.tsx`), Custom Dissectors (`customDissectorEngine.ts`,
>   `CustomDissectorsPanel.tsx`) and the pairing token's `config.json`

**`docs/history.md` holds what this document used to carry**: the post-mortems
of surfaces that no longer exist, the arguments each live decision won against,
and the migration's phase-by-phase record. Nothing in it describes current code.
Read it when you want to know *why* something is not here; read this for what is.

## 1. What this is

Inwire is a **Windows desktop network packet analyzer**: an Electron app whose
renderer is React + Vite served from a custom `app://inwire` scheme, plus a
Python capture agent that ships inside the same installer and runs as a
LocalSystem service. The app talks to the agent over a named pipe. Protocol
dissection, filtering, colour rules, expert analysis, statistics and pcap /
pcapng import and export all happen client-side in TypeScript.

Everything is local. There is no account, no backend, no telemetry, and no
server of any kind in this repository. The only outbound requests are four
optional lookups from the renderer and two from main — the update feed and
npcap.com — all listed under **Invariants**, and every one behind a switch or a
click.

What it is **not**, any more: a web app. There is no browser build, no
`server.ts`, no Express, no hosted deployment. macOS and Linux still have a
tarball-installed agent that speaks WebSocket, but there is no desktop app for
them yet.

**The agent survived that deletion on its own merits.** A page could not open a
capture handle, which is why the agent was built — but that is no longer why it
is here. It is kept so Npcap can be installed **admin-only**, and so the capture
handle never lives in the process that parses hostile bytes. ADR 0033.

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
- `npm run sync:version` — regenerates `local-agent/agent_version.py` from
  `package.json`. See **One version number**.
- One script on its own: `npx tsx scripts/capture/reader.ts`.
- `npx tsx scripts/parity/parity-check.ts` — the dissection acceptance gate for
  the packet-list **columns**. **It fails without the untracked fixtures**, it
  does not skip — deliberately, because ADR 0004 wants "a failure that says how
  to get it, not a silent skip". That is why it is in `check.ts`'s `NOT_TESTS`
  and can never run under `npm run check`.
- `npx tsx scripts/parity/tree-coverage.ts` — the same question for the
  protocol **tree** (ADR 0039). It *does* skip cleanly without tshark or the
  fixtures, which is what lets it run under `npm run check` where the line above
  cannot. Floors are **counts, not percentages**: the denominator of a coverage
  ratio is Wireshark's vocabulary, so a ratio would fail on a reference upgrade
  that changed nothing here.
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
  agent (Python, LocalSystem service, DEMAND START — ADR 0035)
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

Runs as LocalSystem for **two** reasons (ADR 0033). It is what lets Npcap be
installed **admin-only**, because with the agent holding the handle the app
never needs to open one — Npcap's *default* install leaves the capture devices
open to every local user, so any local account can read this machine's traffic
and inject raw frames. And it keeps the capture handle and the driver's
user-mode library out of the process that parses hostile bytes, and off
Electron's native-module ABI.

**There was a third and it is retired.** "A capture can outlive the window" is
no longer true: the service is **demand start**, the app asks the SCM for it at
`whenReady()` before the window is created, and the agent stops **itself** two
watchdog ticks after its last client leaves. It stops itself rather than being
stopped, because the app deliberately holds no `WP` (SERVICE_STOP) right and
granting one would grant it to every interactive logon — so a second Windows
user could stop a capture the first is running. A self-stop also survives the
app being killed from Task Manager, which an `sc stop` on the quit path would
not. ADR 0035.

Sniffs nothing until a client sends `start_capture`, and stops when the last
client disconnects. Reads frames with `pcap_next_ex` directly rather than
through scapy's socket wrapper, raises the driver's kernel buffer with
`pcap_setbuff`, and reports what the driver dropped via `pcap_stats`. Frames
are queued on the sniffer thread, bounded by both a count and a byte budget,
and drained into batched binary messages by one pump task.

**The kernel buffer is sized per core, not flat, and that is a finding rather
than a preference.** Npcap splits an adapter's buffer into one segment per
processor and drops a frame when the segment for the *receiving* core is full —
so a flat 32 MB was 32/N MB of real slack against a burst, which is 1 MB per
core on a 32-core machine: Npcap's own default. 4 MB per core now, floored at
the old 32 MB and capped at 256 MB because this is non-paged kernel memory.
`docs/bursts-and-what-wireshark-does.md` is the whole comparison, including the
one place we are behind: no snaplen lever, because the wire record's `capLen` is
a `u16` and we dissect everything.

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

A thin adapter over things only a privileged process can hold: the `app://`
handler, the window, the menu, the quit guard, the pipe client, the agent's
service diagnosis, native save dialogs, and the capture store's lifetime. Every
decision worth testing is in a module beside it: `appPaths.ts`, `window.ts`,
`csp.ts`, `menu.ts`, `windowState.ts`, `saveTarget.ts`, `pipeTransport.ts`,
`agentService.ts`, `windowColors.ts`.

**The window is frameless and draws its own controls.** `frame: false`, and a
32px title row carrying the app's own minimize / maximize / close. What is lost
and accepted: **Snap Layouts** (the flyout on a maximise-button hover — it needs
`WM_NCHITTEST` to answer `HTMAXBUTTON` and Electron exposes no hook; Win+Arrow
snapping is unaffected) and **Alt+Space** (there is no native caption to raise
the system menu from). Both are in `docs/verification.md` as accepted losses
rather than as things to re-check.

Three things follow, each a trap:

- **The controls are ours, so they follow the cascade.** `WindowControls.tsx`,
  46×32 with 10px glyphs — Windows' own metrics, because the target size and
  spacing are what muscle memory aims at. The dim on blur is `opacity` on the
  row, not a pre-composited colour pushed over IPC. One colour is hardcoded and
  only one: close hovers to `#c42b1c`, which is learned rather than designed.
- **The ground is cached in `window-state.json`.** `backgroundColor` is fixed
  when the window is constructed, before a renderer exists to report a theme —
  so the alternative is opening every window in one theme and correcting a beat
  later, which on a frameless window is a full-window flash. `windowColors.ts`
  is the table; the theme still lives in `localStorage` and this is a cache of
  what it resolved to, written by the renderer, never the source of truth. Same
  argument as window bounds, which is why it is the same file.
- **The button reserve is a constant**, 138 CSS pixels at every scale factor,
  because the buttons are elements. Under the old overlay it had to come from
  `env(titlebar-area-width)`, which Windows drew at ~138px at 100% scaling and
  ~207px at 150%.

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

`execArgv: ['--max-old-space-size=2048']` is there and **does not work** — see
**The store's memory ceiling**.

### The renderer

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

The mark, a back step, the filter field, the detail panes' toggle, the caption
buttons. No navigation and no packet count; `useWindowTitle` still sends
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

#### Settings, the one sheet

`components/common/SettingsPane.tsx` takes the workspace card: no scrim, no
radius, no border, because `<main>` is the card and a second one inside it is a
card in a card. It covers the workspace, the view underneath is untouched, and
closing it puts that view back rather than navigating anywhere.

**The slot stays a union.** `App` models it as `sheet: 'settings' | null` rather
than a boolean, which makes "the card holds exactly one surface" a fact the type
carries — a boolean invites a second boolean beside it, and then "both open" is
representable in a card that shows one.

**Three ways out and no fourth**: the title row's back step, reading
"Back to &lt;the view underneath&gt;"; Escape, outermost surface first; and the
rail's Settings icon, a toggle carrying the same active marker a view does.

**Landing on a view closes it, and the close belongs to the TRANSITION rather
than to the pane** — the view underneath is untouched while the sheet is up, so
only the code that *chooses* a view can know one is being chosen.
`handleViewChange` closes it, which is the one door the rail and `Ctrl+1..5`
share, and so does `applyFilter`, whose field is reachable with the sheet up and
which navigates to Packets. Clearing navigates nowhere and closes nothing. Both
are asserted, because a navigation nobody can see fails silently.

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

**`GraphsTab` renders outside `StatisticsPane`'s scroller**, and that is easy to
undo by accident: every other tab is a table and wants `overflow-y-auto`, but
`TrafficTimelineChart` measures its own container, so a parent that grows to fit
its child would size the SVG from a box the SVG is itself defining.

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

**A resizable column between the rail and `<main>`**, opened by four of the
rail's buttons, and it **pushes** rather than overlays. `components/sidebar/` is
the directory, `SideBar.tsx` is the card, `sideBarPrefs.ts` is the state. The
four panels are Interfaces, Schedule, Export/Import and Network.
`ImportErrorDialog` **stays a modal**: a refusal that must be acknowledged is a
detour by every test here.

**Network is a panel and not a view.** It is not in `APP_VIEWS`, it has no
`Ctrl+n`, and `viewPrefs.ts` lands a stored `'network'` back on Packets. Its
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
nothing, two card borders already drawing that edge, and it carries the full
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

The React app never dissects and never parses an agent message. That is
`src/workers/pipeline.worker.ts`, which holds the ordering window, the trackers,
and `pcapParser.ts`.

### The frame path, end to end

```
agent → pipe → main (deframe) → MessagePortMain → pipeline Worker
                                                   ├─→ bytes → capture store → disk
                                                   └─→ dissect → 100 ms flush
                                                       → renderer main thread → React state
```

**The Worker writes the bytes itself, before it dissects anything** (ADR 0038).
Ids are assigned and the bytes posted for a whole released group ahead of the
dissection loop, over a **second** `MessagePort` to the store. What that buys
concretely: a frame whose dissection throws still reaches disk — before this,
`ingest`'s catch reported the failure and the frame was gone, not on disk, not
in the list, not in any counter.

The Worker rather than main, because main treats a batch as an opaque buffer and
decoding it there to get ids would end that. The Worker rather than the
renderer's main thread, because of ADR 0007 — and it is the only place holding a
frame's bytes and its id at the same moment.

**Two ports into the store, and only one of them answers.** `entry.ts` took
`event.ports[0]` from any parent message and assigned it to its single `port`,
which was correct with one channel and silently wrong with two: the second would
replace the first and every reply would go down a port nothing was reading. The
role travels with the port now; `scripts/electron/store-ports.ts` holds it.

**The app never chooses between "bytes and row" and "row only".** There is no
`attachRows` message. Rows keep arriving as `append`, and `CaptureWriter`
answers one local question — *do I already have a slot for this id?* That is
what makes an import, a live capture and a build with no ingest port all
correct, with no renderer-side knowledge of which case it is in.

Main hands the Worker one end of a `MessageChannelMain`. The renderer's main
thread receives that port from the preload and transfers it straight into the
Worker — it carries the port exactly once and then plays no part in the frame
path, which is the property ADR 0007 bought. The store's ingest port travels the
identical route for the identical reason.

**There is one copy, and it is unavoidable.** `MessagePortMain.postMessage`
accepts only ports in its transfer list; an `ArrayBuffer` is cloned, not
transferred. At the agent's ~256 kB batch about thirty times a second that is
single-digit MB/s. Measured on the pipe itself: **4,000 batches of 64 kB —
262 MB — in 539 ms, or 487 MB/s**, so the transport is not the ceiling. The
cross-process clone's own cost is in **What the store actually costs**.

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

The 18-byte record in `local-agent/packet_batch.py` and
`src/services/agentBinary.ts`, and every control message in
`src/services/agentProtocol.ts`, are transport-agnostic. Both ends assert the
same hand-written byte vectors — `scripts/agent/binary.ts` and
`scripts/agent/pipe-framing.ts` against `local-agent/test_protocol.py` — which
is the only thing keeping two implementations of one format in agreement.

**Control messages are covered in both directions, and the missing half cost a
working capture.** `scripts/agent/control-vectors.json` holds what the agent
*emits* and is checked against the app's parser; nothing held the agent to what
the app *sends*. So the Rust agent could read `set_interfaces` as a list of
adapter **indices** where the app and `agent.py` send device **names** — agreed
with by an interop harness written from the Rust source and by a unit test
asserting `[0,2]`. Three witnesses, none of them the app. The app's message
failed to parse, the selection stayed unset, and `start_capture` fell back to
adapter 0: a dead `WAN Miniport`, opened and reported as `sniffing`, delivering
nothing. `scripts/agent/command-vectors.json` is the inbound fixture that closes
it — produced by the app's own `encodeAgentCommand`, checked by
`scripts/agent/command-vectors.ts` against the app and by `agent-rs`'s
`command_vectors` test against the Rust parser. The lesson generalises: **a
fixture only proves something if the end that authored it is not the end being
tested.**

`src/services/agentLink.ts` is the vocabulary between main and the Worker.

### One version number

**The agent's version is Inwire's version.** ADR 0035. `package.json` is the
only place it is authored; everything else derives from it or is a literal that
`scripts/agent/version.ts` holds to it on every `npm run check`:

| Where | How it gets there |
|---|---|
| `package.json` | **the source** |
| `local-agent/agent_version.py` | generated by `npm run sync:version`, committed |
| `local-agent/agent.py` | `from agent_version import AGENT_VERSION` |
| `src/services/agentProtocol.ts` | `REQUIRED_AGENT_VERSION`, a literal, checked |
| `installer/setup.iss` | `MyAppVersion`, a literal, checked |

**It is an ordering, and that is why the product jumped to 4.0.0.** The number
is the left-hand side of `isAgentOutdated`, so an agent left behind by an
earlier install must read as *older*; one that reads as newer than required
shows in the UI as "not connected", a state with no instruction attached to it.
Collapsing two numbers means the survivor has to be at least the highest either
half ever shipped — the agent had shipped 3.9.0 while the app was on 1.0.0. The
anti-reset floor is compared as numbers rather than as a string: `"3.10.0"`
sorts before `"3.9.0"` lexically, so a string floor would reject the first
version past 3.9 and every one after it.

`MyAppVersion` is also what Windows compares to decide whether an install is an
upgrade. `local-agent/installer/setup.iss` keeps a frozen `MyAgentVersion
"3.9.0"` and `MyAppVersion "1.0.0"`: nothing builds it, and it is the record of
what an agent-only install actually put on a machine — which is what the unified
installer reads in order to remove it. `version.ts` asserts those stay frozen.

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
`hardenSession`. `OUTBOUND_HOSTS` is the whole list of places the renderer can
reach: **geojs** (map geolocation), **cloudflare-dns** (DoH reverse lookups),
**ipapi.co** (the Network panel's public-identity section) and **openfreemap**
(basemap tiles). Enforced by `scripts/electron/shell.ts`, which also asserts
that the agent's old port `8999` is **not** in the policy — a `connect-src`
entry nothing dials is a hole with no user. Three of the four are behind a
consent switch and **which switch is not uniform**: geojs and ipapi.co are
behind `nameResolution.geoIp`, the DoH resolver behind
`nameResolution.reverseDns` (two separate Settings rows), and the basemap tiles
behind neither, loading whenever the map is shown. See **Direction**.

**Main reaches two more hosts, and they are deliberately not in the policy.**
The update feed and `npcap.com` are dialled by `net.fetch` in the main process,
which is not a page and which no CSP governs — so a `connect-src` entry for
either would grant the *renderer* permission to reach a host it never touches,
the same hole with no user as `8999`. What is kept is the list:
`MAIN_OUTBOUND_HOSTS` in `electron/csp.ts` records both with their purposes, and
`shell.ts` asserts they are **absent** from the policy, that the recorded feed
host is the one `updateCenter/manifest.ts` actually dials, and that the recorded
Npcap host is the one its download allowlist admits. Both are behind an explicit
action: the feed behind `inwire.updates`, off until asked, and Npcap behind a
click.

**Cross-origin isolation is on.** `ISOLATION_HEADERS` in `electron/main.ts`
sets COOP/COEP on every `app://` response, so `crossOriginIsolated` is true and
`SharedArrayBuffer` exists. Nothing depends on it yet. Enforced by
`scripts/electron/smoke.ts`, which evaluates `crossOriginIsolated` in the
running window — so this is checked on every `npm run check`, not by hand. The
one gap: `smoke.ts` launches `dist/`, so the *packaged* app is still only
verified by hand.

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

**And the tree matches it too, which nothing checked until ADR 0039.** Those
columns were the whole gate: `parity-check.ts` does not even build
`packet.layers`, so a dissector that stopped emitting half its rows passed
every check here, and *which rows does the reference have that we do not* had
no answer at all. `scripts/parity/tree-coverage.ts` diffs `tshark -T pdml`
against the union of the tree's abbrevs and the flat field bag.

Its floors are **counts, never ratios**, and the reason generalises: the
denominator of a coverage percentage is the *reference's* vocabulary, so a
ratio would fail on the Wireshark upgrade `test/fixtures/README.md` instructs
you to perform — a build that changed nothing, broken by its own oracle.
`wireshark-abbrevs.ts` won the same argument by checking `ours ⊆ theirs`.
Beside the floors sits **one ceiling, which may only fall**:
`filterableNotInTree`, where every entry is a filter the app accepts for a row
the detail pane refuses to draw. Two more numbers are recorded and **never
enforced** — `absentDistinct`, the size of the ranked gap list, and
`valueMismatches` — because a ceiling on either would turn a measurement into a
backlog, which is what ADR 0021 ended. `valueMismatches` was briefly a ceiling
and that was wrong: most of its entries are the reference formatting a value
differently by design (`eth.src` resolved to a vendor, `tcp.seq` annotated
"(relative sequence number)"), so the number moves on changes that improve the
tree. A layer with no floor is named in `unimplemented` with a sentence, not
floored at 0: a zero floor protects nothing and reads as measured-and-accepted.

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

**A cached "is the style ready?" that a lost GPU context invalidated.** The tell
in a terminal is Chromium's own `command_buffer_proxy_impl.cc ... GPU state
invalid after WaitForGetOffsetInRange` — a driver reset, a GPU process crash or
a laptop changing adapter, reaching the renderer as a lost WebGL context.

`_contextLost` **destroys the style and sets `map.style = null`**;
`_contextRestored` puts it back with `setStyle(..., { diff: false })`. What
MapLibre cannot know is that `GeoMap` caches the answer to "may I touch the
style?" in `styleReadyRef`, deliberately, because `isStyleLoaded()` asks a
different and much slower question. Left true across the gap, every guard waved
through a call against a style that no longer existed — and `_contextRestored`
calls `resize()` before its own style has loaded, `resize()` fires `moveend`,
`GeoMap` answers with `syncConnectionsLayer()`, and `addLayer` threw **Style is
not done loading.** out of MapLibre's restore.

**The cost was narrower than it first looked, and saying so is the point**: the
layers come back either way, established by losing the context a second time
with the bug in and out. What the stale flag bought was an uncaught exception on
every GPU recovery, not lost data. The fix is one line in a `webglcontextlost`
handler, because `syncConnectionsLayer` already reschedules when the style is
not ready. `scripts/electron/gpu-restore-drive.ts`.

**A `queue.shift()` inside a `find` predicate** shifts once per element `find`
**compares**, not once per match, and a non-null assertion over a `find` is
where `undefined` gets into a list — which the next render reads as
`undefined.open` and takes the renderer down. It was **persisted** too, because
`createPreferenceStore`'s `set` does not normalise and only `loadPreference`
does. The subject is deleted; the reason it shipped is not: **a `useCallback` in
`App.tsx` is unreachable from this suite**, so arithmetic worth testing has to
be lifted somewhere a script can import it.

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

**`Start-Process -ArgumentList ''` throws.** It does not run the program with no
arguments — it fails parameter validation with *"Cannot validate argument on
parameter 'ArgumentList'. The argument is null or empty."* The component that
takes no arguments is **Npcap**, deliberately, because the alternative is `/S`
— so the Update Center failed on the one install it exists to perform, one
second after the click, with no UAC prompt at all. Nothing in the suite could
have caught it: the argument list was right, the marker parsing was right, and
PowerShell's *parser* accepts the line (`[Parser]::ParseInput` returns no
errors, and that check was already running). It is the cmdlet's parameter
validation that rejects it, at run time, only when the variable happens to be
empty. Fixed by splatting a hashtable and omitting the key when there is nothing
to pass, which keeps the command line a constant. `elevate.ts`; four assertions
in `scripts/electron/update-center.ts`, including that no bare `-ArgumentList`
survives in either script.

**A structured clone drops prototypes, and that made the whole disk path
inert.** A buffered `Packet` carries its 33 commonest fields in a `FieldBlock` —
a **class instance** — so once the store became a `utilityProcess` every frame
arrived with a `cols` object that had no `read` on it and `encodeChunk` threw,
for the life of every capture. It looked normal: `frames.iwbyt` grew,
`index.iwidx` stayed empty, `ordinalOf` answered **-1**, which the app reads as
"not addressable yet" and turns into `below = 0`, so the list showed the RAM
window and said the window was the whole capture. Two things had to be true for
it to hide, and both are now closed:

- **Nothing crossed a boundary in a test.** Every assertion script handed
  `CaptureHost` objects it had just built, in one JavaScript context.
  `scripts/capture/store-protocol.ts` now puts every appended frame through
  `v8.serialize`/`deserialize` first — the same serialiser a `postMessage` uses.
- **Nothing reached the disk path in the app.** `smoke.ts` captures a few
  thousand frames, which fit in the buffer. `scripts/electron/disk-drive.ts`
  drives a capture past the RAM budget and asserts the two counts diverge.

The fix is `src/services/capture/storePacket.ts`: frames are flattened at the
boundary, dense columns folded back into `fields` — flattened rather than
rehydrated because the block holds 4,096 rows and a batch is ~300 frames, so the
same half-megabyte would cross fourteen times as it fills. **The second half is
the part worth remembering**: `prepareBatch` calls `persist` *before* `absorb`
and `CaptureClient.send` awaits the port, so the store is handed frames that do
not yet have a block and the `postMessage` serialises them a microtask later —
so a `plainForStore` that returned the packet unchanged when there was nothing
to fold would have fixed nothing. **A message is a snapshot: it always copies.**
`fieldAccess.ts` now throws a named error for a block with no methods, and
`CaptureHost` logs the stack to stderr as well as the message to the app.

## 7. Testing

Assertion scripts under `scripts/`, discovered by `scripts/check.ts` walking the
directory; a handful are listed there as SKIP with a reason each (measurements
with no right answer, or things needing the untracked fixtures). Plain `tsx`, no
runner, no Electron, no browser. A script prints `PASS`/`FAIL` lines and exits
non-zero.

**`docs/verification.md` is the other half**, and it is a real document rather
than an aspiration: everything this repository knows to check and cannot check
by itself — the window's own chrome against both themes and three scaling
factors, Snap Layouts, the drag regions, the two bottom panes and their divider,
the pipe's security descriptor taking effect (which needs a second Windows
account), and the UAC prompt. Each item says what a failure *looks like*,
because everything in it fails silently.

**Three rules keep the suite runnable under plain `tsx`**, and all three are
invariants with enforcers in §5: no Electron or `node:*` under `src/services/`
and `src/lib/`, `nodeBlockFile.ts` unreachable from `src/main.tsx`, and matching
strictness flags in both tsconfigs. The reachability check walks the import
graph and names the chain, because "something reaches it" is not actionable and
"App.tsx -> captureClient.ts -> nodeBlockFile.ts" is.

The fixtures are two real captures, untracked because they contain personal
addresses (ADR 0004): `inwire` (general browsing) and `bulk` (a long TLS
transfer, and 30 TCP streams with exactly one SYN, which makes it the one that
catches anything assuming a capture opens with a handshake). They assert
per-column mismatch floors and the expert-category counts in
`scripts/expert/categories.ts`.

**`scripts/capture/store-protocol.ts`** drives the store's whole message union
through `CaptureHost` against a memory volume. It proves the protocol, not
Electron's IPC, and it opens with the rule that has a hanging UI behind it:
every request answers, even when it fails. The scan's state machine is four of
its assertions, each checked by putting the bug back.

**`scripts/session/capture-row-space.ts`** drives the arithmetic that decides
what row *i* of the list is. Getting that wrong shows the wrong frame at the
right row height, so the check is a count computed two ways: the list has
exactly as many rows as the filter has matches over the whole capture.

`scripts/parity/synthetic.ts` covers protocols the fixtures do not contain:
frames built byte by byte from an RFC, written to a real `.pcap`, handed to
tshark, compared as exact strings.

**Three files build their own capture, and what they have in common is worth
stating: a measurement that cannot see a feature cannot defend it.** The
fixtures turned out not to contain a single ICMP error frame, a single frame of
real HTTP, or a single readable certificate — both captures negotiate TLS 1.3,
which encrypts the Certificate message, so tshark emits no `x509af.*` on them
either. So `scripts/icmp/dissect.ts`, `scripts/http/dissect.ts` and
`scripts/tls/certificate.ts` each build the frames, write a `.pcap`, dissect it
with the real parser and cross-check against tshark's own answers for that file.
Each skips the cross-check cleanly with no tshark and still runs its own
assertions. The certificate one authors its DER rather than pasting a blob from
`openssl`, so the structure reads as RFC 5280's own ASN.1 — the fields under
test are the ones an `openssl req` one-liner does not emit.

They pay for themselves in findings rather than in coverage: the reference
splits a URI query on `+` as well as `&`, it files an unknown header under
`http.request.line` on a connection and `http.unknown_header` in its SSDP NOTIFY
path, and it emits every URI in a certificate under one name. None of that is
visible to a count of abbrevs.

**`scripts/electron/smoke.ts` drives the real app.** Playwright's
`_electron.launch`, a real Electron process over a real named pipe against
`scripts/electron/stubAgent.ts`, which speaks the production protocol: pick an
adapter, Start, wait for rows, read the Info column. A pass means bytes went
from a socket through main, a `MessagePort`, the Worker, the dissector and React
onto the screen. It exists because three of the worst bugs in the migration were
invisible to every other script here — the maplibre worker URL, `node:os` in the
preload, and COEP blocking `pipeline.worker` — and two of them were verified by
reintroduction. Four things about running it:

- A **temporary profile** via `INWIRE_USER_DATA`, because the app prunes its
  capture directory at startup and would otherwise delete a developer's stored
  capture on every `npm run check`.
- It tests whatever is in `dist/` — `npm run check` does not build, so it prints
  the build's age and says so when that is over two hours.
- Every locator carries a **30-second timeout**, because Playwright's default is
  **none** and a control that never renders would hang the whole suite with no
  output rather than fail.
- It clears `setUnsavedCapture` before closing, because closing with frames in
  the buffer opens `guardClose`'s native "Quit Inwire?" box, which is not in the
  page and which no test can answer. Killing the process instead was tried and
  is worse — `kill()` reaches main and orphans the GPU, renderer, store and
  crashpad children.

**An import is not capped by memory.** `PcapService.streamCaptureFile` hands
frames over as it dissects them; `App` writes each batch to the capture store
and keeps the newest `framesForBudget(...)` in the buffer. What bounds the pass
is `IMPORT_PATCH_WINDOW` — frames stay in reach of a patch for 100,000 frames,
the same rule `captureWriter.ts` follows, because dissection amends frames it
has already emitted by indexing into the array it is building.
`scripts/capture/import-stream.ts` compares the streamed result field for field
against the whole-array one **with the window forced small enough that frames
actually leave it** — at the real 100,000 a test capture never fills it, and the
first version of that comparison passed with the offset arithmetic removed
entirely. Still true: the file is read with one `arrayBuffer()`, and the
dissection blocks the main thread.

**Four drivers reach what plain `tsx` cannot.** All are in `NOT_TESTS` and run
by hand:

- **`scripts/electron/gpu-restore-drive.ts`** loses a real WebGL context under
  the running map and restores it. Run after anything touching GeoMap's style or
  layer lifecycle. It skips rather than fails on a machine with no map on
  screen, because the map only exists once geo-IP lookup has been consented to.
- **`scripts/electron/disk-drive.ts`** drives a capture past the 128 MB budget
  until the window trims, then filters the whole capture and reads the top of
  the result back off disk.
- **`import-drive.ts`** imports a 400,000-frame file and scrolls back to frame 1.
  Both take one to two minutes and prove the half of the app `smoke.ts`
  structurally cannot. Run after anything on the store path.
- **`scripts/electron/update-center-drive.ts`** stands up an HTTP feed on a
  loopback port, points `INWIRE_UPDATE_FEED` at it and drives the real app — and
  it builds the manifest from **this machine's own installed Npcap version**,
  which is what lets the central assertion be exact: told the version it has,
  the row must read `up-to-date`; told one digit more, it must offer it. That
  pair is the `wpcap.dll` trap, and a build that read the libpcap number fails
  the first half on any machine with Npcap on it. It also drives the
  **driver-access row** against whichever mode this machine is in. It installs
  nothing — the UAC prompt is the one step that stays with a person.

**To drive the app by hand**, `npx tsx scripts/electron/serveStub.ts` serves the
same stub until Ctrl+C (`--burst n` for n frames per 100 ms tick); launch the
app beside it and pick "Ethernet (stub)". Otherwise testing by hand needs the
real service, which needs Administrator, Npcap and traffic.

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

`execArgv: ['--max-old-space-size=2048']` in `electron/store/host.ts` **does not
work**. The flag arrives — the store's own `process.execArgv` reads it back —
and `heap_size_limit` is 4192 MB, V8's 64-bit default, because V8 fixes the
limit when it creates the isolate. `v8.setFlagsFromString` at the top of the
entry point does not move it either. Both measured against the running app,
after the store was seen to die at 4,060 MB.

`electron/store/heapGuard.ts` samples the heap every two seconds, warns once at
80% while the capture can still be stopped whole, and seals and stands down at
the ceiling with a message — which a V8 abort cannot give. The wall is the
lower of our 2 GB and 90% of V8's own limit. `scripts/capture/heap-guard.ts`.

Still unfixed: the store's inbound queue is unbounded, and each pending `append`
holds its frames. It has not been seen to matter since the throughput was
measured — the store takes 31,000 frames a second and the app feeds it far less
— so the 4 GB heap remains unexplained rather than diagnosed.

## 8. Status

The Electron migration is done bar two items, and `docs/history.md` has the
phase-by-phase record.

**Signing and the fuses are deprioritised, not blocked.** They wait on a
code-signing certificate (EV or Azure Trusted Signing) outside this repository —
but signing, the fuses, the VM matrix and the Npcap OEM licence were all set
aside deliberately, because this is a machine the author works on rather than a
fleet they ship to. The installer compiles; the fuses are still to flip, and
must land **before** signing.

**The offline basemap is the last of "rebuild what the browser forced".**
`tiles.openfreemap.org` is still in `OUTBOUND_HOSTS` (`electron/csp.ts`) and
there is no `d3-geo`. See **Direction**. The no-GPU fallback landed —
`src/components/analytics/renderTier.ts`, two tiers rather than three, asserted
by `scripts/perf/render-tier.ts`.

**The whole-capture filter works end to end**, watched: a 178,200-frame capture
with a 115,476-frame window, `udp.srcport == 49152` matching 44 frames across
the whole capture where the window alone holds 28, and the top of the filtered
list reading frames 4,096 apart off disk. `scripts/electron/disk-drive.ts` is
that run, kept. **Scaled scrolling is what is left.**

## 9. The Update Center

*The only place this app updates anything.* ADR 0032.

One Settings section (`Settings → Updates`) listing every updatable component:
the app, the capture agent, the Npcap driver, and two databases that are
declared and have no consumer yet. `electron/updateCenter/` is the pipeline,
`src/services/updateCenter.ts` is what the renderer accepts and calls things,
`UpdateCenterPanel.tsx` arranges it and decides nothing.

**The installer no longer installs Npcap.** It used to, with `/S` — Npcap's
**OEM silent-install feature**, which the free licence does not grant. Two other
things were wrong with it and are worth knowing before anyone proposes moving
driver installs back into Inno: the version pin was a compile-time `#define`, so
correcting it meant shipping a new installer, and `[Run]` ignores exit codes, so
a failed driver install produced a "successful" product install with no capture
capability and nothing on screen.

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

One JSON document at `UPDATE_FEED_URL` —
`https://updates.inwire.app/manifest.json`, overridable by
`INWIRE_UPDATE_FEED` in dev. **The domain does not resolve yet** — it is not
registered — so every check is a quiet no-op until it does, which is the same
path an offline machine takes.

**Development does not take that path.** `npm run dev` and `npm run start:app`
stand up `electron/devFeed.cjs` on a loopback port and point
`INWIRE_UPDATE_FEED` at it, so a launch reaches a feed that answers instead of
printing `net::ERR_NAME_NOT_RESOLVED` on every run — the shape that teaches
somebody to stop reading their own log. An `INWIRE_UPDATE_FEED` already in the
environment wins and no server is started.

Its default manifest **offers nothing, and that is a constraint rather than a
choice**: `DOWNLOAD_HOSTS` is `null` for `inwire`, `agent`, `oui` and `geoip`,
meaning "the host the feed came from", and `hostOf` returns null for anything
that is not https. A loopback feed is http, so those four rows can never
validate there — and one malformed row for a known id rejects the *whole*
document, which would trade `not reachable` for `could not be read`. Npcap is
the exception, because its allowlist names npcap.com outright, so
`--npcap <version>` is the one row that can be served.

It is the only remote input in this repository that can nominate an executable
to be run elevated, so it is validated strictly and **rejected whole** — the
opposite of how preferences are read, because a defaulted field here could mean
"download this URL with no hash".

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

### "Driver missing" is not a link diagnosis

`agentHealth` cannot express it, because `diagnoseAgent` short-circuits on
`status === 'connected'` and a driverless agent **is** connected — it answers,
it is healthy, it has nothing to listen on. `DriverInfoPanel` (the Capture
Health tab) describes that directly from the two facts it already has, and links
to the tab that fixes it. That tab is also the app's only full account of frames
it lost, which has no other home: four figures do not fit a 24px strip. ADR 0035.

## 10. Direction

Validated sequencing, recorded so a future session inherits the reasoning.
These are **not** work in progress and get an ADR when each is started.

**The Rust agent is written, in `agent-rs/`, and is not yet what ships.**
ADR 0037. The throughput argument the plan rested on was **measured and
dropped**: the Python sniffer thread costs 2.87 µs of work per frame at a
utilisation of 0.003, and the frames being lost were lost to a sleep in the
pump. What justified it instead: **449 KB in one file** against a 34 MB
`--onedir` tree of unsigned `.pyd` files (signing a wrapper does not sign what
the wrapper loads); **213 ms just to `import agent.py`**, load-bearing once
demand start put the agent's cold start on the critical path of opening Inwire
(ADR 0035); and a defect that is unrepresentable rather than fixed — a `Capture`
is `Send` and not `Sync`, so a libpcap handle cannot cross to the event loop.

**What is proven**: the wire format, the pipe and the whole capture path against
the app's own client, with conservation asserted to a residual of 0 over 632,924
frames — **and the SCM's side**, registered in the installed agent's place and
driven elevated. An **unelevated** `sc start` reaches `RUNNING` in **16 ms at
checkpoint 0**; the client moved **184,614 frames / 4,039 MB, residual 0** over
the production pipe; the idle self-stop reports `STOPPED` **2,436 ms** later
**with exit code 0**, which is what stops the installer's `restart/5000` policy
from resurrecting a demand-start service for ever. `docs/verification.md` holds
the table. `npcap_access.py` is not ported and the Rust agent sends `None`,
which falls back to the registry.

**Every message the app can read, the Rust agent can send**, and that is a check
rather than a claim: `scripts/agent/message-coverage.ts` reads the `type: '...'`
literals out of `agentProtocol.ts` and asserts each is emitted somewhere in
`agent-rs/src/`. ADR 0037's "not ported" list was written from what was
consciously skipped rather than from the protocol, which is how `interface_stats`
came to be missing from it — the app subscribed, the agent answered with a
generic `state`, and the sparkline drew nothing with nothing erroring anywhere.
The allow-list now holds one entry, `packet`, the binary frame path, which has
no JSON form.

**The two agents share one log file and one log format**: `agent_log.rs` matches
`"%(asctime)s %(levelname)-7s %(message)s"` byte for byte, and `agent_log.py`'s
parser strips exactly that computed seven-character width rather than a greedy
`\s+`, because the agent indents some lines on purpose. A subscriber that
connects after a swap sees continuous history across both implementations.

**What blocks the swap** is `0030`/`0032`'s constraint rather than this one: a
code-signing certificate, and elevation to replace the installed binary.
`wpcap.dll` living in `System32\Npcap` and off the default DLL search path was
the gotcha to carry over, and `npcap.rs` carries it.

**Engine-side dissection.** Move the pipeline Worker's work into the store
`utilityProcess` with a `worker_threads` pool over `SharedArrayBuffer`, sharded
by stream and merged back into timestamp order; the renderer becomes a viewer
that asks for rows. The store protocol was built so this is a relocation rather
than a rewrite. **Trigger:** a profile showing the cross-process copy on the
frame path, or a sustained rate above ~100 MB/s.

**The boundary is measured and it is not the trigger.** The hop is 5.26 µs a
frame against the writer's 26.68 — 16% of the cost (see **What the store
actually costs**). ADR 0038 took the *write* off the dissector's critical path,
which is half of what this entry was for: bytes go to disk before anything
dissects them, and the writer never stalls behind a slow dissector. What it did
**not** do is make dissection asynchronous — within one Worker, decoding and
dissection are still serialized, so a dissector uniformly slower than arrival
backs up the Worker's own queue and everything lags together. That is what the
pool is for, and its trigger is unchanged.

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
`exceljs` and `three` — the pass that weighs each has **not** happened. All five
are genuinely imported and reachable from `src/main.tsx`, which is the
distinction that matters: **unweighed, not unused**.

**The failure mode the rule does not catch is a dependency nothing imports** —
the rule asks whether a dependency beats the platform, and one nothing imports
never gets asked. The cheap census is a grep per entry in `dependencies`, worth
repeating before any pass that weighs the five above. **The icon set is
`lucide-react`**: 76 glyphs across 41 files, held to one set by
`scripts/themes/icon-set.ts`, which also insists `Map` and `Image` are aliased,
because both shadow globals and `tsc` will not say so.

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
| 0034 | The side bar is a place: Escape does not close it, nor does navigating | accepted |
| 0035 | The agent lives as long as the app, and shares its version | accepted; **retires 0033 reason #2** |
| 0036 | The buffer sizes itself, and the renderer stands down before V8 aborts | accepted |
| 0037 | The capture agent is Rust on Windows | accepted; **proven as a service; not yet what ships** |
| 0038 | Bytes and rows are two arrivals; dissection is off the capture path | accepted |
| 0039 | What the tree is held to: counts, not ratios | accepted |

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
`hooks/useKeyboardNavigation.ts` holds the window's shortcuts — everything reads
through a ref, or a `keydown` listener would re-register ten times a second
during a capture. **Space is scoped positively** — the body, or inside
`[role="grid"]` — and not by excluding the controls that must not receive it.
The old exclusion rule was correct only while nothing else in the window was
focusable; with a dozen rail buttons, Space on a focused one both activated it
and ran this handler's `preventDefault`, so the button's own activation was
suppressed and capture toggled anyway. Scoped positively, every control added
from here on is safe by default rather than by being remembered.

`hooks/usePacketBuffer.ts` holds the buffer — the arrival queues, the
accounting, the dense-field writer, the flush. `hooks/useAgentConnection.ts`
owns the agent link: status, version, interfaces, capture state, drop counters,
adapters, the agent's own log, and the health diagnosis. Its four callbacks are
held in a **ref**, not passed as effect deps, or a new callback identity each
render would reconnect once per render.

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
(`services/bufferBudget.ts`), because a frame is 60 bytes to 64 kB. **And the
bound sizes itself to the machine** — `'auto'` is what ships, an eighth of
physical RAM capped at half of V8's heap limit, with a 128 MB floor (ADR 0036).
The thing that had been holding it at a fixed 512 MB was not memory: the buffer
lives in the renderer's JS heap, V8 fixes that heap's limit when it creates the
isolate — **4,192 MB, measured** — and past it V8 aborts rather than degrading.
`src/services/rendererHeapGuard.ts` is what makes a bigger number safe to ship.
On a 32 GB machine the budget resolves to 2,096 MB and is bound by the heap
rather than by RAM, which is the whole answer to "why not as much RAM as the
machine has".

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

### Enrichment and export

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

### Typography

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
once rather than baked into a build. All have working defaults. There is no
`.env` of any kind. The root-level `security_spec.md` that described a Firebase
backend is gone; what was worth keeping — the twelve denial tests any future
sharing feature would have to pass — is `docs/ideas/sharing-threat-model.md`,
under a banner saying none of it exists.
