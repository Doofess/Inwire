# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

> **Must not come back.** These were deleted deliberately and re-adding any of
> them undoes a decision, not a cleanup. Product scope, the vision beyond
> Wireshark parity and the bar for issues live in `SCOPE.md`; each rejected
> product concept has a file in `.out-of-scope/`. This list is the code-level
> remainder:
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

The banner's "§3" is the shell described in `src/components/CLAUDE.md`. A
collection socket is not in the list on purpose: the monitoring collector binds
an unprivileged UDP socket in the **app** (see `src/services/monitoring/CLAUDE.md`),
never in the agent, which has no privileged collection socket and must not gain one.

## Working on Inwire

Inwire is a Windows desktop packet analyzer built with Electron, React and TypeScript.
The Windows installer ships a Rust capture agent; Python remains the Unix agent
and the Windows comparison baseline. There is no Unix desktop app yet.
Capture and analysis are local; optional network services require user action.
NetFlow v5 monitoring is implemented (ADRs 0058-0060): an opt-in collector the
user starts each launch, run by the app, not by the agent.

Everything is local: no account, no backend, no telemetry. The only outbound
requests are the four renderer lookups and the three main-process ones listed in
`electron/csp.ts` (`OUTBOUND_HOSTS`, `MAIN_OUTBOUND_HOSTS`), each behind a switch or click.

## Read the right source

- `SCOPE.md`: product boundaries, implemented versus planned work, rejected ideas.
- `SECURITY.md`: reporting, trust boundaries, data handling and known limitations.
- `CONTRIBUTING.md`: setup, contribution workflow and decision policy.
- `docs/architecture.md`: current runtime, data ownership and implementation traps.
- `docs/testing.md`: validation by area, fixtures, integration drives, and the
  enforcing script for every invariant below.
- `docs/decisions/README.md`: decision index, status and supersession notes.
- `docs/history.md` and historic specs explain past decisions, not current behavior.

Read the relevant sections for your task; do not load every reference by default.
An accepted ADR is a decision, not proof that its implementation has landed; check code.

## Path-scoped guides

These load on their own when you work under the directory. Do not copy their
contents here.

- `src/components/CLAUDE.md`: shell, rail, status bar, drag regions, render path.
- `electron/CLAUDE.md`: main-process rules, CSP, windowing, utility processes, fuses.
- `electron/updateCenter/CLAUDE.md`: Update Center, Npcap version and driver access.
- `agent-rs/CLAUDE.md`: the shipped Windows agent and its parity with Python.
- `local-agent/CLAUDE.md`: Python agent, PyInstaller build, installer, release checklist.
- `src/services/capture/CLAUDE.md`: on-disk capture format, ring segments, recovery.
- `src/services/pipeline/CLAUDE.md`: Worker frame path, ports, drain, catch-up, shards.
- `src/services/monitoring/CLAUDE.md`: NetFlow v5 collector, journal, rollups, limits.
- `scripts/CLAUDE.md`: how assertion scripts and drivers are written and launched.

## Architecture and code map

| Area | Responsibility / starting point |
|---|---|
| `agent-rs/` | Windows LocalSystem service: Npcap capture, original pcapng, raw stream |
| `local-agent/` | Python implementation and shared-protocol comparison baseline |
| `electron/main.ts` | Window, app scheme, native dialogs, pipe and process lifetimes |
| `electron/preload.ts` | Narrow sandbox-compatible bridge; runtime import is only Electron |
| `electron/store/` | Capture filesystem ownership in a separate utilityProcess |
| `electron/monitoring/` | Monitoring utilityProcess: UDP socket, journal file, quit drain |
| `electron/speedTest/` | Speed-test engine in its own unprivileged utilityProcess |
| `src/workers/pipeline.worker.ts` | Live ordering, trackers, dissection and TCP shards |
| `src/workers/monitoring.worker.ts` | Sandboxed NetFlow decode, rollups and queries; holds no file |
| `src/App.tsx` | Application controller, capture lifecycle and view composition |
| `src/hooks/usePacketBuffer.ts` | Bounded display buffer, not the entire capture |
| `src/types/packet.ts` | Shared packet/domain types |
| `src/services/` | Parser, filters, capture format, monitoring, analysis and export |
| `src/lib/` | UI-facing hooks and utilities |
| `scripts/` | Assertions, measurements and integration drivers |

Live flow: agent → named pipe → main → pipeline Worker → store and UI batches.
Main may inspect fixed batch metadata for flow control; it does not dissect packets.
The renderer transfers ports to Workers without parsing raw agent batches.
The UI receives dissected summaries and raw bytes; full trees are requested on demand.
File import uses the same dissection engine but currently runs on the renderer thread.
The capture store and agent-written original pcapng have separate responsibilities.
Monitoring flow: exporter → UDP in the monitoring utilityProcess (journal on disk)
→ datagrams over a port to the monitoring Worker → rollups and queries → the sheet.
It shares no state with the capture path and its files are not captures.

## Commands

Use Node 24+ and `npm ci`. Npcap is needed for live capture, not pure assertions.
Rust, Python and installer prerequisites are described in `CONTRIBUTING.md`.

| Command | Purpose |
|---|---|
| `npm run dev` | Vite and Electron for UI iteration |
| `npm run start:app` | Build and launch the real app scheme without packaging |
| `npm run build` | Build renderer and Electron entries into dist directories |
| `npm run pack` | Build and package an unpacked Windows app |
| `npm run lint` | Type-check both strict TypeScript programs |
| `npm run check` | Type-check, then discover and run assertion scripts |
| `npm run sync:version` | Synchronize generated Python and Rust version copies |
| `npm run build:agent` | Build, stamp, then sign the Windows Rust agent |
| `npm run dist:signed` | Build the release and refuse unsigned installer payloads |

`lint` does more than its name: `strict`, `noUnusedLocals`, `noUnusedParameters` and
`noFallthroughCasesInSwitch` are on, so an unused import or an unread local fails.
`noImplicitReturns` is off on purpose; do not turn it on.
Run one assertion with `npx tsx scripts/capture/reader.ts`, substituting its path.
`check` does not build: integration checks may use stale dist output or skip if absent.
For renderer/bridge/Worker changes, run `build` before `check` on Windows.
Do not `npm run build` under a running `start:app`: its lazy chunks break.
`dev` does not exercise production app-scheme handling, CSP or worker asset URLs.
Agent builds use the GNU Rust toolchain (`+stable-x86_64-pc-windows-gnu`, named on
the command line because `rust-toolchain.toml` cannot carry a host); building does
not replace the installed service. Signing runs after the version stamp, because a
resource edit rewrites the bytes a signature covers.

Every invariant below has an asserting script; `docs/testing.md` names it. An
invariant marked "unenforced" there means exactly that.

## Boundaries to preserve

### Privilege and privacy

- Only the separate agent opens capture handles; never Electron or its utilityProcesses.
- Keep renderer sandboxing and context isolation; do not add Node access to Workers.
  `scripts/electron/preload-sandbox.ts` reads the built preload: only `electron` may be required.
- Keep pure services importable under plain tsx; no Electron or `node:*` under
  `src/services/` and `src/lib/` (`scripts/capture/node-safe.ts`). The explicit exception
  is `src/services/capture/nodeBlockFile.ts`, which must stay unreachable from
  `src/main.tsx`; the check walks the import graph and names the chain.
- Windows uses the named pipe ACL, not application credentials or a network listener.
  Interactive local users may connect; capture ownership controls their commands.
  `PIPE_SDDL` in `agent-rs/src/pipe.rs` is the same literal as the Python one and
  nothing asserts it; `test_protocol.py` reads only Python's.
- The agent writes capture files as its connected client, never with SYSTEM's file rights.
- Persist no TLS keys or decrypted derived records. Key-log following remembers a path;
  an explicit pcapng Decryption Secrets Block export is the user-controlled exception.
  The renderer never names the key-log file (`scripts/electron/keylog-follow.ts`).
- Keep crash reporting off: a renderer minidump is a copy of `KeyLogStore` (ADR 0008).
- No unrequested outbound connections. Check purposes and consent in `electron/csp.ts`;
  renderer CSP does not govern main-process or utilityProcess requests.
  Reverse DNS stays at four requests in flight (`scripts/geoip/reverse-dns-queue.ts`).
- Monitoring listens only when the user has configured an exporter and pressed Start.
  The app binds the UDP socket, in a utilityProcess, unprivileged; the exporter address
  is an intake filter, not authentication. A bind of `0.0.0.0` is refused.
- Never commit personal capture fixtures, key logs, certificates or signing credentials
  (`scripts/sign/signing.ts`). `test/` holds the owner's loose real files: gitignored.

### Capture correctness

- Preserve evidence before dissection: assign frame IDs and persist bytes before parsing.
- Bound live queues. When behind, catch up from agent pcapng; never silently skip a gap.
- Keep control messages flowing when binary batches are shed for backpressure.
- Stop through the shared lifecycle: drain the pipeline, await store writes, then seal.
  Separate MessagePorts have no cross-port ordering; preserve the store barrier.
- The store's client and ingest ports have distinct replies; never overwrite the client port.
- RAM eviction is not capture deletion. Preserve the stored session and its explicit
  replacement/discard workflow; ring expiry follows the user's configured ring policy.
- Prune only recognized capture directories; never broaden deletion to arbitrary files
  (`planPrune`, `scripts/capture/prune-guard.ts`). Monitoring files are not captures.
- Filters, statistics and exports must distinguish the full capture from the RAM window.
  Use `src/lib/rowSource.ts` and the store protocol rather than UI-array shortcuts.
- Use the shared filter compiler and list scan; a second export scan cancels the first.
- Preserve stable ordinals and ring floors when combining disk and memory rows.
- Revisit is stateful: tracker answers are recorded at arrival; missing records fall back
  to replay. A tree cannot generally be rebuilt from frame bytes alone.
- Keep adapters and capture options fixed while capture runs; changes apply next Start.

### Protocols, performance and compatibility

- Register fields in `src/services/dissect/fieldRegistry.ts` using real tshark abbreviations.
- Keep summary dissection synchronous; do not add async work to per-frame decoding.
- Measure dissection against tshark; read ADR 0021 before chasing intentional differences.
- Parity floors only rise and performance ceilings only fall. Never relax them to pass
  (`scripts/parity/acceptance.ts`, `scripts/perf/bundle-size.ts`).
- Profile before performance changes (`scripts/perf/profile.ts`); name the expensive
  function and measure the result. Self time says where, never why.
- A shipped dependency must justify itself against the platform API; measure native additions.
- Agent protocol changes must account for both implementations and their golden vectors.
- `package.json` owns the product version. Synchronize derived copies and align remaining
  checked literals (`scripts/agent/version.ts`); app/agent compatibility is exact equality,
  not newer-is-compatible (ADR 0051). The version stays 0.x until release.
- Keep legacy identifiers that migrate old installs; renaming them breaks migration.

## Gotchas index

Each of these built, type-checked and failed silently. The fact lives in one place.

| Trap | Where it is held |
|---|---|
| maplibre's worker URL is `""` under `app://`; `setWorkerUrl` before `setRTLTextPlugin` | `src/components/analytics/GeoMap.tsx`, `scripts/electron/smoke.ts` |
| Lost WebGL context leaves `styleReadyRef` stale | `src/components/analytics/GeoMap.tsx`, `scripts/electron/gpu-restore-drive.ts` |
| `node:os` in the sandboxed preload kills the bridge silently | `electron/CLAUDE.md`, `scripts/electron/preload-sandbox.ts` |
| COEP headers must be on the `protocol.handle` Response, not `onHeadersReceived` | `electron/CLAUDE.md`, `scripts/electron/smoke.ts` |
| Synchronous pipe handle serialises writes behind a blocked read | `agent-rs/CLAUDE.md`, `local-agent/CLAUDE.md` |
| Structured clone drops prototypes; a store message is a snapshot | `src/services/capture/CLAUDE.md`, `scripts/capture/store-protocol.ts` |
| A transfer list into the store's utility process drops the message | `src/services/pipeline/CLAUDE.md`, `scripts/electron/store-ports.ts` |
| Transferred buffers detach every view; trackers must `.slice()` | `src/services/pipeline/CLAUDE.md`, `scripts/pipeline/moved-bytes.ts` |
| Stop must wait for the Worker's drain before the store's `finish` | `src/services/pipeline/CLAUDE.md`, `scripts/pipeline/live-flow.ts` |
| `readSync` returns short counts | `src/services/capture/CLAUDE.md`, `scripts/capture/block-file.ts` |
| Auto-pause made the disk buffer unreachable | `src/services/capture/CLAUDE.md`, `scripts/session/buffer-budget.ts` |
| `prune([])` on a real directory is a recursive delete | `src/services/capture/CLAUDE.md`, `scripts/capture/prune-guard.ts` |
| `Start-Process -ArgumentList ''` throws; splat a hashtable | `electron/updateCenter/elevate.ts`, `scripts/electron/update-center.ts` |
| `reg query` error codes: missing key is numeric `1`, success has no error | `electron/updateCenter/CLAUDE.md`, `scripts/electron/agent-health.ts` |
| Fuse wire holds ASCII 49/48, so `Boolean()` is true for both | `electron/CLAUDE.md`, `scripts/electron/fuses.ts` |
| `uac_admin=True` makes `--version` raise a UAC prompt | `local-agent/CLAUDE.md` |
| Inno keeps a newer `unins000.exe` and old DLLs on upgrade | `electron/CLAUDE.md`, `docs/verification.md` |
| `execArgv --max-old-space-size` does not move the store's heap limit | `electron/CLAUDE.md`, `scripts/capture/heap-guard.ts` |
| `wpcap.dll` reports libpcap's version, not Npcap's; it is off the DLL search path | `electron/updateCenter/CLAUDE.md`, `agent-rs/CLAUDE.md` |
| `queue.shift()` inside `find` shifts once per comparison; `useCallback` in `App.tsx` is unreachable from tests | `scripts/CLAUDE.md` |
| Worker failures reach only `console.warn` (`useAgentConnection.ts`) | `src/services/pipeline/CLAUDE.md` |
| A monitoring stop reason must survive quit and suspend | `src/services/monitoring/CLAUDE.md`, `scripts/monitoring/runtime-host.ts` |

## Read before changing an area

| Change | Read first |
|---|---|
| App controller, shell, navigation or shortcuts | `src/components/CLAUDE.md`, including App changes outside that folder |
| Typography, themes, icons or brand | `.claude/skills/inwire-visual-design/SKILL.md` |
| Capture/Worker/store, import or export | `docs/architecture.md`, `src/services/capture/CLAUDE.md`, `src/services/pipeline/CLAUDE.md` |
| Dissection, fields, filters or revisit | ADRs 0001-0003, 0007, 0021 and 0049 in the decision index |
| Live backpressure, threading or rings | ADRs 0052-0053 and `docs/testing.md` |
| Agent behavior or packaging | `agent-rs/CLAUDE.md`, `local-agent/CLAUDE.md`, ADR 0037 |
| Update Center or Npcap | `electron/updateCenter/CLAUDE.md` and ADR 0032 |
| Main process, windowing, CSP or fuses | `electron/CLAUDE.md` |
| Security, bridge or signing | `SECURITY.md`, `docs/architecture.md`, ADRs 0029/0033/0047 |
| New product capability | `SCOPE.md`, `.out-of-scope/`, then the relevant accepted ADR |
| Monitoring (NetFlow v5) | `src/services/monitoring/CLAUDE.md`, ADRs 0058-0060 |

Use `src/lib/commands.ts` for command metadata; App binds implementations by id.
Preserve the shared view registry, navigation handlers and outermost-first Escape chain.
Use theme tokens and the existing icon set rather than per-component substitutes.
Follow source comments when changing Vite worker assets or sandboxed preload bundling.
Put testable decisions beside Electron adapters in modules that do not import Electron.

## Validate the changed behavior

Run `npm run check` before handing off. Report failures and skipped prerequisites honestly.
Most assertions are plain tsx; some launch real Electron when their prerequisites exist.
The discovery rules and exclusions live in `scripts/check.ts`, not a manual test list.

| Changed area | Additional validation |
|---|---|
| Documentation | `npx tsx scripts/docs/claude-md-refs.ts`; check links and factual claims |
| Renderer / Electron / Worker | Fresh build, then check; production scheme via start:app |
| Shell, GPU, installer or privilege | Relevant items in `docs/verification.md` against packaged app |
| Dissection / fields / colouring | Column parity plus tree, snaplen and revisit checks as applicable |
| Store / import / filtering | Disk and import drives in `docs/testing.md` |
| Live capture / options / pcapng | Relevant live drives against the installed current agent |
| Rust agent | `npm run build:agent -- -Test`, then applicable protocol and live checks |
| Python agent | Its protocol/interface suites and relevant cross-implementation vectors |
| Monitoring | `scripts/monitoring/` assertions; drives and measurements are in `NOT_TESTS` |

Column parity: `npx tsx scripts/parity/parity-check.ts` fails without private fixtures
(deliberately, ADR 0004; it is in `NOT_TESTS`). `scripts/parity/tree-coverage.ts` and
`scripts/parity/snaplen.ts` skip cleanly without tshark or fixtures.
Read `test/fixtures/README.md`; do not treat a skip as evidence of parity.
Use synthetic captures when the real fixtures cannot exercise the changed behavior.
Do not publish fixture addresses, hostnames or bytes in diffs, reports or screenshots.

Every scripted Electron launch uses `scripts/electron/launchApp.ts`, backgrounded by default.
Use an isolated `INWIRE_USER_DATA` and private `INWIRE_AGENT_PIPE` for integration tests.
The real profile contains captures; an automated launch must not prune the user's data.
Close through the test helper's normal cleanup; killing main can orphan child processes.
Packaged Electron fuses prevent some inspector-based automation; use the manual matrix.
Do not claim hardware, UAC, cross-user ACL or packaged behavior from pure assertions alone.

## Keep this guide useful

Keep this root near 300 lines, using short statements rather than dense paragraphs.
Add a root rule only when it affects many tasks or prevents a costly recurring mistake.
Put subsystem mechanics in the path-scoped guide; prefer a pointer over another summary.
Keep decisions and their measurements in ADRs; put retired explanations in history.
Avoid current version numbers, script counts, machine timings and progress diaries here.
Update the owning document when behavior changes; do not maintain competing copies.
Check code and supersession notes before treating an old document as current authority.
Record decisions that close off future options with an ADR, following `CONTRIBUTING.md`.
