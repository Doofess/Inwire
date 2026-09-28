# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

> **Must not come back.** These were deleted deliberately and re-adding any of
> them undoes a decision, not a cleanup:
>
> - the **pairing token**, `authenticate`, `authRequired`, `auth_required` /
>   `auth_failed`, in the app or the Windows agent. The pipe's ACL is the
>   authentication (ADR 0029). The Rust agent's `hello` has no `authRequired`
>   at all, and `scripts/agent/control-vectors.ts` fails on any `auth*` key.
>   The Python agent is the one place these may still appear, for the
>   macOS/Linux WebSocket, where 0029 kept the token
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
capture agent that ships inside the same installer and runs as a LocalSystem
service — the **Rust** one in `agent-rs/` (ADR 0037); the Python one in
`local-agent/` is what macOS and Linux run. The app talks to the agent over a
named pipe. Protocol
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
- `npm run sync:version` — rewrites `local-agent/agent_version.py`,
  `agent-rs/Cargo.toml` and the crate's entry in `agent-rs/Cargo.lock` from
  `package.json`. See **One version number**.
- `npm run build:agent` — the agent the installer ships. A locked release
  build on the **GNU** toolchain, named with `+stable-x86_64-pc-windows-gnu`
  because `agent-rs/rust-toolchain.toml` cannot carry a host (the file says why),
  then `scripts/agent/stamp-agent.ts` writes VERSIONINFO, the app's icon and an
  `asInvoker` manifest onto a copy at `agent-rs/dist/inwire-agent-windows.exe`.
  Cargo's own output has no resources; that copy is the payload. Then it signs
  that copy through `scripts/sign/sign.ps1` — **after** the stamp, because a
  resource edit rewrites the bytes a signature covers; with no certificate
  configured that step warns and leaves it unsigned. `-- -Test` runs
  `cargo test` first.
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
- `npx tsx scripts/parity/snaplen.ts` — the same questions of the fixtures cut
  with `editcap -s 64` and `-s 128`, which is what a snaplen capture is (ADR
  0050). Skips like tree-coverage, so it runs under `npm run check`.
  `--write-floors` records a new measurement.
- `pyinstaller local-agent/inwire_agent.spec` — builds the Python agent for
  Windows to `local-agent/dist/inwire-agent-windows/` (a **directory**; see
  `local-agent/CLAUDE.md`). **Not shipped any more**; the `-Python` switch of
  `agent-rs/switch-agent.ps1` is what still uses it, for a comparison.
- `iscc installer/setup.iss` — compiles the unified installer to
  `installer/output/Inwire-Setup.exe`. Needs `npm run build:agent` and
  `npm run pack` to have run first. Unsigned; a plain compile is for trying the
  installer, not for shipping it.
- `npm run dist:signed` — the release: `build:agent`, `pack`, then
  `iscc /DSIGN` with `INWIRE_REQUIRE_SIGNING=1`, so a missing certificate is a
  failure rather than a warning. Under `/DSIGN` the preprocessor runs
  `scripts/sign/verify-payload.ps1` over exactly what `[Files]` installs and
  refuses to compile around a single unsigned PE file - a signed installer
  wrapping unsigned contents is the thing it exists to make impossible.
  `scripts/sign/` holds the rest: the certificate is this PC's own
  (`new-cert.ps1`, trusted by the one elevated `trust-cert.ps1`), and
  `sign.ps1` is the only thing that signs (ADR 0047). It compiles with the
  **newest** Inno Setup it finds (7 here), because an upgrade keeps an installed
  `unins000.exe` with a newer version, even an unsigned one.

**Every assertion script runs under plain `tsx`, with no Electron and no
browser.** That is a property to protect, not an accident: it is what makes the
suite runnable in CI on ubuntu and fast enough to run on every commit. The
pattern for anything that needs Electron is to split the decision into a module
that does not import it — `electron/pipeTransport.ts` beside `agentPipe.ts`,
`electron/saveTarget.ts` beside `saveFile.ts`, `src/services/agentHealth.ts`
beside `electron/agentService.ts`.

## 3. Process topology

```
  agent (Rust, LocalSystem service, DEMAND START — ADRs 0035, 0037)
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

### The agent — `agent-rs/` on Windows, `local-agent/agent.py` elsewhere

Two implementations of one behaviour, held together by shared golden vectors
(ADR 0037); what follows describes both, and names the Python where it says a
Python thing. Runs as LocalSystem for **two** reasons (ADR 0033). It is what lets Npcap be
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
`docs/bursts-and-what-wireshark-does.md` is the whole comparison.

**The driver narrows the capture, when asked** (ADR 0050). `start_capture`
carries a libpcap capture filter and a snaplen, and the agent applies both per
adapter before a frame is read - so a frame the filter refuses never reaches the
kernel ring, which is the one lever that makes a burst of unwanted traffic cost
nothing. A start whose options it cannot read is refused
(`invalid_capture_options`), never captured on defaults; a filter one adapter's
link type will not compile fails that adapter alone, in libpcap's words.
`check_capture_filter` asks the same question of a dead handle, for the panel's
live verdict. The Rust agent opens with `pcap_create`/`pcap_activate` so the
snaplen and **nanosecond** precision can be set between them.

It carries the driver's timestamps - nanoseconds, with each interface saying how
many digits were measured (`tsPrecision`) - a per-capture sequence number, and
the interface index. It does **not** dissect: a record has no source, destination,
protocol, ports or info, because the app dissects the bytes itself and always
overwrote those anyway (ADR 0010).

On Windows its only transport is the named pipe, created with the security
descriptor `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`. `IU` is the point — the
service is LocalSystem and the app deliberately is not. `WD`, `AN` and `NU` are
absent because a pipe answers over SMB unless the descriptor says otherwise.
`agent-rs/src/pipe.rs` and `local-agent/pipe_server.py`; ADR 0029.

**On Windows it is the Rust agent, at parity with the Python one, and signed**
(ADRs 0037, 0047). Side by side on the real adapter the two delivered the same
106,948 frames byte for byte. They answered every command, error, ownership and
watchdog case with the same messages to the same clients; 0047 lists the five
deliberate deviations.

What the port bought was never throughput:

- one ~750 KB file a certificate covers, against a 23 MB `--onedir` tree of
  unsigned `.pyd` files
- a first `hello` in under 100 ms against ~430 ms, which matters because
  demand start put the cold start on the path of opening the app
- ~11 MB against ~67 MB, plus a PowerShell child per adapter read
- a libpcap handle that cannot cross to the event loop, because a `Capture` is
  `Send` and not `Sync`

`scripts/agent/message-coverage.ts` fails if the app can read a message that
`agent-rs/src/` never emits. Both agents write one log format to one file.
`wpcap.dll` lives in `System32\Npcap`, which is off the default DLL search path,
so `npcap.rs` loads it by full path. **A fix that lands in one agent and not the
other is the failure mode to watch for.**

An upgrade installs the Rust exe under the Python agent's path and file name,
so the ImagePath does not move. `install` updates the registration in place.
`agent-rs/switch-agent.ps1 -Python` puts the Python agent back for a comparison,
which replaces the signed exe with an unsigned tree.

### main — `electron/main.ts`

A thin adapter over things only a privileged process can hold: the `app://`
handler, the window, the menu, the quit guard, the pipe client, the agent's
service diagnosis, native save dialogs and the streaming save behind them, and
the capture store's lifetime. Every decision worth testing is in a module beside
it: `appPaths.ts`, `window.ts`, `csp.ts`, `menu.ts`, `windowState.ts`,
`saveTarget.ts`, `saveSession.ts`, `pipeTransport.ts`, `agentService.ts`,
`windowColors.ts`.

**An export is saved in pieces** (ADR 0046): `inwire:save-stream-open` shows the
dialog and opens `<target>.<random>.partial`, `-write` appends, and `-close`
renames it onto the target or deletes it. The chosen name appears only on
commit, so a cancelled or failed export leaves nothing that looks finished. A
token belongs to the webContents that opened it, and a window that goes away or
a quit deletes its partials. `saveSession.ts` holds every rule; `saveStream.ts`
is the Electron adapter.

**"Save as captured" is a copy, not an export** (ADR 0052): `inwire:save-captured`
takes a capture id - never a path - and main copies the agent's own pcapng
files out of that capture's folder, byte for byte, one through a save dialog
and a ring's into a new folder of their own, each through a `.partial`, and a
set whole or not at all. `capturedFiles.ts` holds the rules and
`scripts/electron/captured-files.ts` drives them; `saveCaptured.ts` is the
adapter.

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
implementation of the five capture files.

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

**The whole of it is in `src/components/CLAUDE.md`**, which loads when you work
under that directory: the drag-region rule, the card cluster ported from
VS Code's `floatingPanels.css`, the rail's three groups and why it is full at
452px of 618, the status bar's five rules, the settings sheet, the frame views,
and the render-path facts that are easy to undo by accident.

**The React app never dissects and never parses an agent message.** That is
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

**Two ports into the store, and only one of them is the reply port.**
`entry.ts` took `event.ports[0]` from any parent message and assigned it to its
single `port`, which was correct with one channel and silently wrong with two:
the second would replace the first and every reply would go down a port nothing
was reading. The role travels with the port now; `scripts/electron/store-ports.ts`
holds it.

The Worker's port carries **records** as well as bytes, posted after each
flush's bytes, and it asks one question back: a **`revisitKit`** — a frame's
record, its row, and the bytes of it and every frame the record names (ADR
0049). That answer goes down the Worker's own port as a callback on the
request, so the port still never becomes `port`, and a failure still reports on
the client port. `store-ports.ts` holds the host to exactly that one answer.

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

A capture is a directory named `cap-YYYYMMDD-HHMMSS-xxxx` holding five files:
`index.iwidx`, `prefix.iwpfx`, `summary.iwsum`, `frames.iwbyt` and
`records.iwrec` — the last one deflated block of frame records per chunk (ADR
0049), written before the chunk's index record so recovery covers it unchanged.
The index is **version 3**, an 80-byte stride carrying the records' extent and
each chunk's **segment**; version 2 (no segments) and version 1 (64 bytes, no
records) still open and are continued as themselves, and a version 1 capture's
trees fall back to the replay.

**A capture follows the agent's ring** (ADR 0052). Its data is in segments -
segment 0 is the four files beside the index, segment *n* a `seg-NNNNNN`
directory - a segment per ring file, filed by the agent's `capture_boundary`
messages
(`pipeline/ringFiling.ts`). When the agent deletes a file the store deletes
the segments holding only frames at or below that file's last sequence
number, **floor first**: the header records the first chunk still held, every
lookup answers below it as a hole, and ordinals never move, so the list, a
filter's bitmap and an export start at the floor rather than renumbering.
`segments.ts` is the rule and `scripts/capture/segment-guard.ts` holds each
refusal in it; it narrows ADR 0012 to exactly this delete. Written by
`captureWriter.ts` through `chunkCodec.ts`, read back by `captureReader.ts`,
addressed by `captureIndex.ts`, searched by `captureScan.ts` and `matchSet.ts`.

`blockFile.ts` is the seam; `nodeBlockFile.ts` is the real-file implementation
and **loops** its `readSync`/`writeSync`, because a short read on a 5 GB
`frames.iwbyt` would otherwise read as a torn tail and truncate a healthy
capture. `serialQueue.ts` exists because the writer once used `void handle(msg)`
and `append` overtook an async `open`, losing 500 frames silently.

Recovery: a capture whose trailing chunk is incomplete loses that chunk and
nothing else. `scripts/capture/recovery-on-disk.ts`.

**A chunk is version 2 and records each frame's `linkType`**; version 1 still
decodes, and `RowBlock.linkTypesStored` says which meaning an absent one has —
Ethernet in v2, *not recorded* in v1. It had to be stored because the only other
source is a table keyed by adapter label, and every frame of an import carries
one label whatever its link type (ADR 0046).

### On the wire — `src/services/agentFraming.ts` / `local-agent/pipe_frame.py`

A pipe is a byte stream, so framing is ours: a `u32` length, a `u8` kind
(`FRAME_JSON` 0, `FRAME_BINARY` 1), little-endian to match `packet_batch.py`.
Both ends refuse a declared length past `MAX_FRAME_BYTES` (8 MB) **before
allocating anything** — the agent is a privileged service and a five-byte
header must never ask for four gigabytes.

The 22-byte record in `local-agent/packet_batch.py` and
`src/services/agentBinary.ts` - version 4, whose lengths are `u32` so a frame
past 64 KB is carried rather than refused (ADR 0052), and whose timestamp is a
`u64` of epoch nanoseconds because no `f64` could carry them (ADR 0050) - and
every control message in
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
| `agent-rs/Cargo.toml`, and the crate's entry in `Cargo.lock` | rewritten by `npm run sync:version`, committed, checked |
| `agent-rs/src/lib.rs` | `VERSION = env!("CARGO_PKG_VERSION")` — `hello` and `--version` |
| the shipped agent's VERSIONINFO | stamped by `stamp-agent.ts`, which refuses unless `package.json`, `Cargo.toml` and the binary's own `--version` agree; `built-version.ts` reads it back |
| `src/services/agentProtocol.ts` | `REQUIRED_AGENT_VERSION`, a literal, checked |
| `installer/setup.iss` | `MyAppVersion`, a literal, checked |

The lock entry is in the table because `npm run build:agent` builds `--locked`:
a lock still naming the previous version fails the release build instead of
being quietly rewritten by it.

**It is 0.x, because Inwire is in development, and it is compared for
equality** (ADR 0051). `isAgentMismatched` asks whether the agent the app
reached reports this build's own number; any other, older or newer, is one a
different install left behind, and shows as outdated with the installer as the
fix. It used to be an ordering, which held the number at 4.x - an agent from a
higher-numbered build read as newer than required and passed - and a floor
under it; both are gone. What still orders is the installer's refusal to
install over a newer Inwire, so a machine with 4.x uninstalls it once.

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
`scripts/capture/prune-guard.ts`. **One exception, which the user asks for by
setting it** (ADR 0052): a capture following the agent's ring loses a segment
when the agent deletes the file it held - `segments.ts`, enforced by
`scripts/capture/segment-guard.ts`.

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
`onlyLoadAppFromAsar` on. Flipped in `electron/afterPack.cjs` — **before** the
platform gate, because a fuse belongs to the binary on every platform — and
enforced by `scripts/electron/fuses.ts`, which reads the wire out of the packed
exe and skips cleanly when nothing is packed. Flipping mutates the exe, so it
must stay **before** signing, and it does: electron-builder runs the signing
hook after `afterPack`.

What it was worth, quoted from the build this replaced rather than described:
`ELECTRON_RUN_AS_NODE=1 Inwire.exe -e "console.log(process.version)"` printed
`v24.20.0`. Signing would not have helped — the file is unmodified, so every
signature check passes; the capability is the binary's.

**The wire holds ASCII digits**, 49 for a set fuse and 48 for a cleared one, so
`Boolean(value)` is true for both — which failed three correct rows the first
time that check was written. `getCurrentFuseWire` reads it; running the exploit
is better evidence and a worse test, because with the fuse on `-e` stops being
Node's argument and **launches the app**, so a suite checking by execution opens
a window on every run. That one belongs in `docs/verification.md`.

`enableEmbeddedAsarIntegrityValidation` is deliberately still off. Integrity is
stamped (`npm run pack` logs `updating asar integrity executable resource`);
turning the *validation* on is a separate decision whose failure mode is an app
that will not start, and it wants its own commit.

**Every signature goes through one script, and no certificate is in the
repository.** ADR 0047. electron-builder (via `electron/sign.cjs`), Inno's
`SignTool=` line and `npm run build:agent` all call `scripts/sign/sign.ps1`. It
finds the certificate by thumbprint, from `INWIRE_SIGN_THUMBPRINT` or the
gitignored `.signing.json`, so a real certificate is a thumbprint change.

`scripts/sign/signing.ts` enforces three things:

- the routing above
- no tracked `.cer` or `.pfx`
- this machine's thumbprint in no committable file

At build time, `iscc /DSIGN` refuses an unsigned PE file in the payload.
**Nothing verifies a signature at runtime**; §8 says what one is worth.

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

**And it is actually applied, which is a separate check.** `shell.ts` asserts
what the policy *says*; nothing asserted that it reaches the document, and the
failure is silent in the worst direction — a policy that stops being applied
removes a restriction, so every other check keeps passing and the app keeps
working. `smoke.ts` appends an `<img>` from a blocked origin and requires a
`securitypolicyviolation`. That probe has to be one the **page** performs: a
`page.evaluate` of `eval` goes through CDP, which is exempt from page CSP, and a
blocked `fetch` is indistinguishable from a machine with no outbound route.
`onHeadersReceived` carries a URL filter so the map's tiles no longer round-trip
through main's JavaScript to be handed a header that means nothing on a tile —
that filter is what made the check necessary.

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
needs a second Windows user account and is in `docs/verification.md`. The
shipped agent's copy, `PIPE_SDDL` in `agent-rs/src/pipe.rs`, is the same literal,
and *nothing asserts it*: `test_protocol.py` reads only the Python one.

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

**The renderer's weight only falls.** `scripts/perf/bundle-size.ts` holds
`dist/assets` to `test/perf/ceilings.json`, which is the other direction of
`test/fixtures/acceptance.json`'s "floors only rise" and is enforced the same
way, against `git show HEAD:`. It is the **only** performance number in this
repository that is a gate, and the line is not importance but whose property the
number is: a
byte count belongs to the build and is the same everywhere, where a launch time
belongs to the machine. So launch and map-load timings are *printed* by
`smoke.ts` and asserted by nothing (ADR 0041). It skips cleanly with no `dist/`,
because CI runs `check` before `build` on purpose.

**The map is the one lazy route, and it is warmed rather than merely lazy.**
`GeoMap.tsx` reaches maplibre-gl and `three` - 1.51 MB of the eager chunk, behind
a rail button most launches never press - so `geoMapLoader.tsx` puts it behind
`React.lazy` and calls `warmGeoMap()` from an idle callback after mount. Both
halves are the decision: a bare `React.lazy` would move MapLibre's worker-pool
spawn (three Workers, 487 kB each, acquired by `setRTLTextPlugin` at that
module's scope) onto the click that opens the map, in front of the 2-4 serial
round trips to openfreemap the first basemap pixel already waits on. ADR 0043,
which also **amends 0041's 32 ms per 413 kB to a measurement of one split**: it
predicts ~117 ms here and the real figure is ~35 ms. Take your own before sizing
a split with it.

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

**And a cut frame is held to it as well** (ADR 0050). A snaplen hands every
dissector frames that stop early, and the fixtures used to show what that cost:
cut at 64 bytes, TCP read each cut segment as a short one and the next as a
hole behind it, so a capture that lost nothing reported "previous segment not
captured" on most of its frames. Lengths now come from headers, a cut TLS
segment is a hole to the record cursor and named from what it kept, and
`[Packet size limited during capture]` marks every frame whose content ran past
the cut (`dissect/captureShort.ts` - a superset of Wireshark's marks, on
purpose). `scripts/parity/snaplen.ts` holds `tcp.len` exactly, and the analysis,
Protocol, Info and marks as floors in `test/fixtures/acceptance.json`, beside a ceiling on the
marks tshark makes that this build does not; `revisit.ts` rebuilds every frame
of every cut from its record.

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

**An upgrade keeps a newer uninstaller, even an unsigned one.** Inno skips
`unins000.exe` when the installed copy is newer ("Existing file is a newer
version. Skipping."). The first signed build came from a per-user Inno 6.7.3 and
was installed over an Inno 7 install, so the old unsigned uninstaller stayed
while every other file was signed. `build-signed.ps1` now picks the newest ISCC,
ranked by `Setup.e32`'s version.

The same install kept an unsigned `dxcompiler.dll` from an older build, because
Inno never removes files; `[InstallDelete]` names it now. Check the installed
files, not the build. `docs/verification.md` has the command; ADR 0047.

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

**A transfer list into the store's utility process drops the message.** The
pipeline Worker posted each flush's frame records to the store with their
buffers in the transfer list, and not one arrived: no error in the Worker, none
in the store, `recordsAttached` and `recordsMissed` both 0. The other end of
that port is a `MessagePortMain`, and a message transferring an `ArrayBuffer`
into it simply does not show up. Imports never showed it, because their records
go through the renderer's port with no transfer list. So **nothing is ever
transferred to the store**; it is copied. The one transfer that stays is the
Worker's bytes to the renderer, which is a DOM port both ends.

**And that transfer detaches every view of the moved bytes.** Once a flush is
posted, each of its frames' buffers is gone from the Worker, and any tracker
that kept a *view* of one now reads it as empty - no exception, just a
different answer. A TLS conversation kept its client and server randoms that
way, and the ServerHello's frame joins the client random against the key log,
so on a live capture every connection whose two hellos crossed a flush said
"no key log entry for this connection" and stayed encrypted. Anything a
tracker keeps past its frame is copied (`.slice()`).
`scripts/pipeline/moved-bytes.ts` dissects every real capture twice, once
detaching each frame's buffer after it, and fails on any tree that changes;
`scripts/pipeline/arrival.ts` detaches too, so every revisit gate runs under
the live Worker's conditions.

**Both surfaced only in a live capture**, which `scripts/electron/live-revisit-drive.ts`
now takes through the installed agent - along with a third: Stop sent the
store's `finish` straight away, ahead of the frames the Worker still held in
its ordering window, so a stopped capture's tail sat staged, unwritten, until
the store next closed. Stop now waits for the Worker's `drain` and flushes the
last rows before it seals (`handlePauseCapture`). Worker failures reach only
`console.warn`, which is why about 5% of live frames failing to dissect went
unnoticed; the drive listens for them.

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
because everything in it fails silently. It also carries the **packed** app's
GPU check, because `enableNodeCliInspectArguments` is fused off and Playwright
attaches through the Node inspector — so the packaged exe cannot be driven, and
that is the fuse working rather than a gap to close.

**`scripts/perf/profile.ts` is the instrument ADR 0011's finding came from**,
and which was never committed until ADR 0042. It re-executes itself under
`node --cpu-prof` and prints self time by function, and the rule it enforces by
existing is: **no dissector change on performance grounds until it has named the
function that change is meant to make cheaper.** The last time somebody reasoned
their way to a hot spot here they were wrong by an order of magnitude and in the
wrong function; the second time, it refuted four of five candidates. Beware
`__name` — esbuild's `keepNames` helper, which is a property of `tsx` and absent
from production, and which charged 10% of the first profile to the one file the
plan was about to optimise. It is folded into the tooling row by name.

**And self time says *where*, never *why*.** The profiler's one surviving
dissector candidate, `hexOfRange`, was read as the cost of building a string
nobody reads, and an ADR sized a change to `ProtocolField`'s contract against
it. The actual cost was `toString(16).padStart(2, '0')` twice per byte for one
of 256 answers, in a loop four dissectors each carried a copy of; a lookup table
took **8.2% off the whole dissection** with no contract change, and the refactor
was withdrawn rather than deferred (ADRs 0042 and 0044). Eliminate "this hot
leaf is written badly" before anything that changes a type.

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

**Eight drivers reach what plain `tsx` cannot.** All are in `NOT_TESTS` and run
by hand:

- **`scripts/electron/live-revisit-drive.ts`** captures real traffic through
  the installed agent - a headless browser loading pages - then copies the
  capture off disk, dissects it in order as its oracle, and opens frames old
  enough to have left the Worker's tree cache. Each must be rebuilt from its
  record (a spy on the Worker's `postMessage` sees `detail`, never `replay`),
  and the store's own counters must say every frame was sealed with its row
  and its record. Run after anything on the live frame path. About three
  minutes; needs Npcap, the service and an Ethernet adapter.
- **`scripts/electron/capture-options-drive.ts`** types a capture filter into
  the panel, waits for the installed agent's verdict (a typo must block Start in
  libpcap's words), sets a snaplen and captures real traffic. Every frame on
  disk must be one the filter admits - judged from its own headers, not by
  asking libpcap again - no longer than the snaplen, marked where cut, never
  "previous segment not captured" unless its headers show the hole, and
  stamped to the nanosecond (ADR 0050). Run after anything on the capture-start
  path or the agent's open; needs the 0.5.0 agent installed.
- **`scripts/electron/capture-file-drive.ts`** captures real traffic until an
  autostop the panel set, then reads the pcapng the installed agent wrote into
  the capture's folder (ADR 0052): laid out as dumpcap's, exactly the limit's
  frames, the same frames the store holds, and **owned by this user, not
  SYSTEM**. A raw pipe client naming a folder this user cannot write must be
  refused with nothing created - the check that the agent writes as the
  client. Run after anything on the agent's writer or the capture-start path.
- **`scripts/electron/revisit-drive.ts`** imports the real `inwire` capture,
  and the key-log capture with its key log followed, and opens frames whose
  trees need the frames before them, or decrypted content (ADR 0049).

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

The Electron migration is done, bar the offline basemap and signing for any
machine other than this one. `docs/history.md` has the phase-by-phase record.

**The Windows build ships the Rust agent, signed for this PC only.** ADR 0047.
The agent, `Inwire.exe`, its DLLs, the uninstaller and `Inwire-Setup.exe` are
all signed by one certificate that `trust-cert.ps1` made trusted here. The
owner installed the result elevated once, over the Python agent.

On any other machine the certificate is an untrusted root. SmartScreen and
Smart App Control ignore the local Root store everywhere. A public release waits
on a publicly trusted certificate, which is a thumbprint change here. That was
set aside deliberately, with the VM matrix and the Npcap OEM licence, because
this is a machine the author works on rather than a fleet they ship to.

**Still owed on the agent:**

- a capture through the UI against it
- the two-client and second-account items in `docs/verification.md`

**The fuses are flipped**, which was the one item here that had to precede
signing rather than follow it. `electron/afterPack.cjs` does it and
`scripts/electron/fuses.ts` holds it; see the invariant above for what an open
`runAsNode` was worth on the build before.

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

*The only place this app updates anything.* ADR 0032. One Settings section
listing every updatable component: the app, the capture agent, the Npcap driver,
and two databases that are declared and have no consumer yet.

**The detail lives in `electron/updateCenter/CLAUDE.md`**, which loads when you
work in that directory. Four things worth knowing before you go there, because
each produces a confident wrong answer rather than an error: `wpcap.dll` reports
libpcap's version and not Npcap's; Npcap's installer is 32-bit so `/reg:32` is
asked first; `installed` and `version` are two separate answers; and the
driver's access mode is decided by the DACL on the device, not by the registry.

**`/S` on Npcap's installer is forbidden** — it is the OEM silent-install
feature and the free licence does not grant it. That prohibition is in the
banner at the top of this file and stays there.
## 10. Direction

Validated sequencing, recorded so a future session inherits the reasoning.
These are **not** work in progress and get an ADR when each is started.

**The Rust agent is no longer a direction: it ships** (ADRs 0037 and 0047;
§3 says what it is). What is left on this line is the Python agent's future.

- **macOS and Linux keep it.** Those platforms have no desktop app to talk to,
  and a socket file needs a permission design of its own (0029).
- **On Windows it is only a baseline**, which `switch-agent.ps1 -Python` puts
  back for a side-by-side comparison.
- **Its `--onedir` build** and the hidden-imports list in
  `local-agent/CLAUDE.md` can go once nothing on Windows compares against it.
- **The trigger for porting macOS and Linux** is 0037 §1's reason for not
  porting them: a desktop app there to talk to.

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
did not ask for - **and consent is not only about whether, it is about how
many**. `resolveHostname` fired one DoH request per address from inside a loop
over newly-arrived packets, so consenting to reverse DNS meant 300 simultaneous
streams to Cloudflare, visible to this audience in their own capture. It is
bounded to four in flight now, with the same shared-promise and
retryable-failure discipline the geo batcher beside it already carried;
`scripts/geoip/reverse-dns-queue.ts` counts the overlap, which a count of total
requests cannot see. A packet analyzer that makes requests visible in the user's own
capture is a trust problem specific to this audience. First steps: an offline
`d3-geo` map to replace openfreemap's tiles, then the geolocation lookups behind
an explicit opt-in or a bundled database. The near-term step is an assertion
that every host in `OUTBOUND_HOSTS` has a recorded purpose and a consent gate.

**The dependency rule.** A shipped dependency must beat the platform API that
replaces it, and no native module lands without a measurement. The platform
answers already chosen or available: `net.fetch` for the updater, `dialog` for
file I/O, `powerMonitor` for sleep gaps. Reports are the exception that won:
`jspdf` generates the PDF rather than `printToPDF`, because it runs under plain
`tsx` and so the report is testable by an assertion script, which a page
printed by Chromium is not. The current `dependencies` list still carries
`jspdf-autotable`, `exceljs` and `three` beside it — the pass that weighs each
has **not** happened. All four are genuinely imported and reachable from `src/main.tsx`, which is the
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

The table that used to sit here reproduced that index, dates and links
stripped. Read the file instead — it is one `cat` away, it is kept current by
the same commit that adds an ADR, and it carries the acceptance dates and the
supersession notes this copy had to restate by hand.
**ADR 0008 weakened, and it now says so itself.** Its argument was that key
material "is exactly as old as the tab"; a desktop app open for days breaks
that. That is a banner on the ADR rather than a note only here, which is the
point — a reader who follows the pointer is the one who needed telling. The
decision still stands; what moved is the bound, and the question is recorded as
reopened rather than answered. `crashReporter` stays **off** for the same
reason — a renderer minidump is a copy of `KeyLogStore`, so the usual advice to
enable it with `uploadToServer: false` for local dumps conflicts with 0008 and
is declined until the key-lifetime question is reopened.

**And ADR 0045 amends 0008 on one point: the key log is FOLLOWED.** A browser
appends each connection's secrets as the connection starts, so a key log read
once before a capture holds nothing for any connection in it - which is how
live QUIC kept reading `Protected Payload (KP0)` with a key log loaded. Main
follows the file (`electron/keyLogFollower.ts`, arithmetic in `keyLogTail.ts`)
and remembers the path, so key material now enters memory at launch. **The
renderer never names the file** - it can ask for one picked in main's own dialog
or main's own `SSLKEYLOGFILE`, and `scripts/electron/keylog-follow.ts` holds
every handler and preload method to taking no path. Only the path is written.
**The 25 ms poll is what sees a browser, not `fs.watch`**: Chrome appends through
a handle it holds open, which on Windows raises no change notification, so at
the original one-second poll every connection's first burst stayed opaque
(`scripts/tls/replay-stored-capture.ts` is how that was found).

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
against the frame's 1.2 kB (ADR 0007). A frame's tree is not a function of its
own bytes — the TLS record cursor, the QUIC keys, the DNS pairings and the TCP
sequence bases are all state the frames before it built — so **arrival records
it** (ADR 0049, Wireshark's model). Dissectors reach that state only through
`dissect/trackerApi.ts`; at arrival a `FrameRecorder` (`dissect/frameRecord.ts`)
stands in front of the trackers and writes every answer down, and on a click a
`FrameRevisit` hands the same answers back to the same dissector code, so a
tree costs one frame's dissection wherever the frame is. Facts from outside any
conversation — the clock, HTTP/1's shared body budget, direction — go through
`dissect/dissectEnv.ts` and are recorded too. **A record never holds a key or
plaintext.** Keys are derived again from the key log, and a revisit whose log
disagrees with arrival's misses. Plaintext answers go to a second, memory-only
log per frame, held by the Worker's `DerivedStore`
(`services/pipeline/derivedStore.ts`) and emptied with the key log. A revisit
that lacks either, or asks a question arrival did not, throws `RecordMiss` and
falls back to replaying the conversation (`services/pipeline/replay.ts`).
`scripts/pipeline/revisit.ts` revisits every frame of the fixtures, the
key-log capture four ways, and fails on any wrong tree.

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

**Export is the whole capture, streamed** (ADR 0046). `services/export/runExport.ts`
is fetched by `await import` when a format is pressed and does the whole job:
the save dialog first, then — for CSV, Excel, JSON and pcapng — a **survey** pass
over the rows without bytes that fixes the field columns, the metadata and the
name table, then the frames a page at a time into a `ByteSink`
(`lib/saveSink.ts`) that writes `<target>.<random>.partial` and renames it on
commit. `exportFrames.ts` reads ordinals `[0, below)` off the store and then the
window from memory, with `below` asked of the store and never taken from the
list. A filtered export is the **list's own scan** — `MatchSet` below the window,
`FilterEngine` over it — and never a scan of its own, because the store runs one
at a time. Progress and Cancel live in `exportJob.ts`, so they survive the side
bar switching panels.

The writers are one file per format under `services/export/writers/`, each
`write(page)` / `finish()`; the capture formats go through `orderByTime.ts`.
pcapng is still the only one that names the adapter, keeps nanosecond
timestamps, and carries the names the capture taught us and what it missed.
**Every format but one carries the metadata** from `captureMeta.ts` — pcapng's
section comment, CSV's `# key: value` preamble, JSON's `meta`, Excel's Capture
sheet, the PDF's cover — and a count nobody reported prints as *not available*,
never 0. **Classic pcap has nowhere to put it and carries none.** CSV and Excel
carry every dissected field as a column headed by its Wireshark abbreviation.
Excel is the one buffered format, so it is refused past a cell budget measured
by `scripts/perf/xlsx-cost.ts`, and the refusal names CSV.

**The PDF is an analysis, not a packet list**: `services/report/analysis.ts`
folds the pages, `findings.ts` writes the sentences, and
`components/export/pdfReport.ts` draws it with jsPDF. PDF import is gone with
`pdfjs-dist`.

`services/anonymise.ts` is prefix-preserving over Crypto-PAn; MACs keep their
OUI. **One `Anonymiser` per job**, built before the first page — two would map
one host to two pseudonyms across a page boundary — and colour rules, fields,
names and the analysis are all taken from the real frame first and redacted
after. `scripts/session/side-bar.ts` holds that. The export tests
(`scripts/export/`, `scripts/report/`) run on the real fixtures and skip cleanly
without them.

### Typography, theming and the brand mark

Moved to the `inwire-visual-design` skill (`.claude/skills/inwire-visual-design/`),
which loads when you work on fonts, colours or the mark rather than every session.
The short version: the faces are **the host OS's own** and no webfont is imported;
there are **two themes**, Day and Night, and Night holds the `dark` id for
`color-scheme`; and the brand mark is **five plates of `--primary` at different
lightnesses**, generated from `src/lib/brandMark.ts` and never committed as art.
Run `npm run check` after any colour edit.
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
