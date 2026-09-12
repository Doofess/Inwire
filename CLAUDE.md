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
  handler and everything downstream of it.
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
`pipeTransport.ts`, `agentService.ts`.

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
shows as "not connected" rather than "update your agent". Locked across three
places — `local-agent/agent.py`, `src/services/agentProtocol.ts`
(`REQUIRED_AGENT_VERSION`), and `MyAgentVersion` in
`local-agent/installer/setup.iss` — by `local-agent/test_protocol.py`, which
also refuses a reset.

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
entry nothing dials is a hole with no user. Every one of the four is behind the
`nameResolution.geoIp` consent switch *except* the basemap tiles, which load
whenever the map is shown; see **Direction**.

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
`SharedArrayBuffer` exists. Verified by hand against the packaged app; nothing
depends on it yet. *Unenforced* — an assertion must exist before anything does.

**The pipe's ACL is the authentication.** See the banner at the top.
`local-agent/test_protocol.py` pins the SDDL's shape — `IU` present, `WD`/`AN`/
`NU` absent, `D:P` — and `scripts/electron/agent-link.ts` drives the real client
against a real pipe. Neither can tell you the descriptor took **effect**; that
needs a second Windows user account and is on the verification matrix.

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

*As of 2026-09-12.*

Phases 1–5 of the Electron migration are done. The plan is
`~/.claude/plans/lets-pick-up-where-agile-shore.md`.

| Phase | What | Landed |
|---|---|---|
| 1 | The Electron shell, `app://inwire` | `ce9d4d8` |
| 2 | The capture store on real files, in its own process | `9971b45`, `bcf3c58` |
| 3 | The named pipe; the token deleted; the agent bundled | `677cc41`…`4bbbfc7` |
| 4 | Native save dialogs | `8b7be01` |
| 5 | The web page deleted | `6d97c46`…`4010d7b` |
| 6 | Installer, signing, updates | **in progress** — `d2423f2` |
| 7 | Rebuild what the browser forced | planned |
| 8 | Import-to-disk; `captureScan` wired to the filter bar | **in progress** — `1bfcbf9`; scaled scrolling is what is left |

Phase 6 is blocked on one thing outside this repository: a code-signing
certificate (EV or Azure Trusted Signing). The installer compiles and the
fuses are still to flip.

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
yet**, so every check is a quiet no-op until it does, which is the same path
an offline machine takes and is already the ordinary case rather than an
error. It is the
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
**not** happened.

**Cross-origin isolation is in place** (see Invariants) but nothing uses it. An
assertion that `crossOriginIsolated` is true in the packaged app must exist
before anything depends on it.

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
| 0008 | Where TLS key material lives | accepted; weakened — see below |
| 0009 | Facts that did not come off the wire | accepted |
| 0010 | The agent captures raw frames and dissects nothing | accepted |
| 0011 | Dissection's cost was not the tree | accepted |
| 0012 | Stored captures persist until the user says otherwise | accepted |
| 0013 | What a million frames actually cost | superseded by 0025 |
| 0014 | Bounding the trackers | accepted |
| 0015 | The colour index | accepted |
| 0016 | Pooling the per-frame lists | accepted |
| 0017 | The dense/sparse split | accepted |
| 0018 | Implementing the field split | accepted |
| 0019 | Packet direction | accepted |
| 0020 | The leaf protocols | corrected by 0022 |
| 0021 | Where the parity chase stops | accepted |
| 0022 | A stream protocol is not expensive any more | accepted |
| 0023 | Decomposing the parser | accepted |
| 0024 | Carrying a message across segments | accepted |
| 0025 | The capture lives on disk | accepted |
| 0026 | One capture on disk | accepted; its quota arithmetic is void on a real disk |
| 0027 | The app is a desktop app | accepted |
| 0028 | Where the capture store runs, and what the boundary costs | accepted |
| 0029 | The app and the agent talk over a named pipe | accepted |
| 0030 | One installer, two destinations, the app never elevates | accepted |
| 0031 | A display filter answers over the whole capture | accepted |
| 0032 | Npcap is managed by the app, not shipped by the installer | accepted; **voids 0030's Npcap paragraph** |
| 0033 | The agent stays a separate service, and Npcap should be admin-only | accepted |

**ADR 0008 weakened and it is not written down there yet.** Its argument was
that key material "is exactly as old as the tab"; a desktop app open for days
breaks that. `crashReporter` stays **off** for the same reason — a renderer
minidump is a copy of `KeyLogStore`, so the usual advice to enable it with
`uploadToServer: false` for local dumps conflicts with 0008 and is declined
until the key-lifetime question is reopened.

---

## Architecture reference

The sections below describe the dissection engine, which the migration did not
change. They are the short form; the ADRs hold the reasoning.

### Data flow inside the renderer

`App.tsx` is the application's controller with a view attached.
`hooks/useKeyboardNavigation.ts` holds the window's shortcuts (everything reads
through a ref, or a `keydown` listener would re-register ten times a second
during a capture). `hooks/usePacketBuffer.ts` holds the buffer — the arrival
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

Theming is four themes declared in `src/lib/themeOptions.ts`, each with a
complete token block in `src/index.css` and a palette entry in
`src/services/themePalettes.ts`. Run `npm run check` after any colour edit —
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
`INWIRE_DEV_SERVER`, set by `npm run dev`. Both have working defaults. There is
no `.env` of any kind. `security_spec.md` describes a Firebase backend that
does not exist under `src/`; treat it as a spec for something unbuilt.
