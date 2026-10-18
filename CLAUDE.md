# Working on Inwire

Inwire is a Windows desktop packet analyzer built with Electron, React and TypeScript.
The Windows installer ships a Rust capture agent; Python remains the Unix agent
and the Windows comparison baseline. There is no Unix desktop app yet.
Capture and analysis are local; optional network services require user action.
Network-wide monitoring is the next direction, not an implemented collector.

## Read the right source

- `SCOPE.md`: product boundaries, implemented versus planned work, rejected ideas.
- `SECURITY.md`: reporting, trust boundaries, data handling and known limitations.
- `CONTRIBUTING.md`: setup, contribution workflow and decision policy.
- `docs/architecture.md`: current runtime, data ownership and implementation traps.
- `docs/testing.md`: validation by area, fixtures, integration drives and releases.
- `docs/decisions/README.md`: decision index, status and supersession notes.
- `docs/history.md` and historic specs explain past decisions, not current behavior.
Read the relevant sections for your task; do not load every reference by default.
An accepted ADR is a decision, not proof that its implementation has landed.

## Architecture and code map

| Area | Responsibility / starting point |
|---|---|
| `agent-rs/` | Windows LocalSystem service: Npcap capture, original pcapng, raw stream |
| `local-agent/` | Python implementation and shared-protocol comparison baseline |
| `electron/main.ts` | Window, app scheme, native dialogs, pipe and process lifetimes |
| `electron/preload.ts` | Narrow sandbox-compatible bridge; runtime import is only Electron |
| `electron/store/` | Capture filesystem ownership in a separate utilityProcess |
| `src/workers/pipeline.worker.ts` | Live ordering, trackers, dissection and TCP shards |
| `src/App.tsx` | Application controller, capture lifecycle and view composition |
| `src/hooks/usePacketBuffer.ts` | Bounded display buffer, not the entire capture |
| `src/types/packet.ts` | Shared packet/domain types |
| `src/services/` | Parser, filters, capture format, analysis and export |
| `src/lib/` | UI-facing hooks and utilities |
| `scripts/` | Assertions, measurements and integration drivers |

Live flow: agent → named pipe → main → pipeline Worker → store and UI batches.
Main may inspect fixed batch metadata for flow control; it does not dissect packets.
The renderer transfers ports to Workers without parsing raw agent batches.
The UI receives dissected summaries and raw bytes; full trees are requested on demand.
File import uses the same dissection engine but currently runs on the renderer thread.
The capture store and agent-written original pcapng have separate responsibilities.
The speed-test engine runs in its own unprivileged utilityProcess.

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

Run one assertion with `npx tsx scripts/capture/reader.ts`, substituting its path.
`check` does not build: integration checks may use stale dist output or skip if absent.
For renderer/bridge/Worker changes, run `build` before `check` on Windows.
`dev` does not exercise production app-scheme handling, CSP or worker asset URLs.
Agent builds use the GNU Rust toolchain; building does not replace the installed service.

## Boundaries to preserve

### Privilege and privacy

- Only the separate agent opens capture handles; never Electron or its utilityProcesses.
- Keep renderer sandboxing and context isolation; do not add Node access to Workers.
- Keep pure services importable under plain tsx; no Electron or Node runtime imports.
  The explicit exception is `src/services/capture/nodeBlockFile.ts`, unreachable from UI.
- Windows uses the named pipe ACL, not application credentials or a network listener.
  Interactive local users may connect; capture ownership controls their commands.
- The agent writes capture files as its connected client, never with SYSTEM's file rights.
- Persist no TLS keys or decrypted derived records. Key-log following remembers a path;
  an explicit pcapng Decryption Secrets Block export is the user-controlled exception.
- Keep crash reporting off while it could persist key material.
- No unrequested outbound connections. Check purposes and consent in `electron/csp.ts`;
  renderer CSP does not govern main-process or utilityProcess requests.
- Never commit personal capture fixtures, key logs, certificates or signing credentials.

### Capture correctness

- Preserve evidence before dissection: assign frame IDs and persist bytes before parsing.
- Bound live queues. When behind, catch up from agent pcapng; never silently skip a gap.
- Keep control messages flowing when binary batches are shed for backpressure.
- Stop through the shared lifecycle: drain the pipeline, await store writes, then seal.
  Separate MessagePorts have no cross-port ordering; preserve the store barrier.
- The store's client and ingest ports have distinct replies; never overwrite the client port.
- RAM eviction is not capture deletion. Preserve the stored session and its explicit
  replacement/discard workflow; ring expiry follows the user's configured ring policy.
- Prune only recognized capture directories; never broaden deletion to arbitrary files.
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
- Parity floors only rise and performance ceilings only fall. Never relax them to pass.
- Profile before performance changes; name the expensive function and measure the result.
- A shipped dependency must justify itself against the platform API; measure native additions.
- Agent protocol changes must account for both implementations and their golden vectors.
- `package.json` owns the product version. Synchronize derived copies and align remaining
  checked literals; app/agent compatibility is exact equality, not newer-is-compatible.
- Keep legacy identifiers that migrate old installs; renaming them breaks migration.

## Must not come back

These are decisions, not cleanup opportunities. See `SCOPE.md` and `.out-of-scope/`.

- A Windows pairing token, origin allowlist, auth handshake or localhost WebSocket port.
  Unix Python transport still has its own authentication; do not remove it by analogy.
- A browser build, hosted backend, service worker, SPA fallback or phone layout.
- `nodeIntegration`, in-process capture, or privileged collection sockets in the agent.
- Npcap silent installation (`/S`) or a mirrored/bundled Npcap installer.
- The removed dock, hamburger menu, accent header, filter row or custom dissector editor.
- Window overrides `thickFrame`, `roundedCorners`, `titleBarOverlay` or `titleBarStyle`.
  Existing native defaults preserve resizing/shadow; the app draws its own controls.
- `window.destroy()` for normal close: it bypasses the unsaved-capture guard.

## Read before changing an area

| Change | Read first |
|---|---|
| App controller, shell, navigation or shortcuts | `src/components/CLAUDE.md`, including App changes outside that folder |
| Typography, themes, icons or brand | `.claude/skills/inwire-visual-design/SKILL.md` |
| Capture/Worker/store, import or export | `docs/architecture.md` and the relevant protocol/types |
| Dissection, fields, filters or revisit | ADRs 0001–0003, 0007, 0021 and 0049 in the decision index |
| Live backpressure, threading or rings | ADRs 0052–0053 and `docs/testing.md` |
| Agent behavior or packaging | `local-agent/CLAUDE.md`, `agent-rs/rust-toolchain.toml`, ADR 0037 |
| Update Center or Npcap | `electron/updateCenter/CLAUDE.md` and ADR 0032 |
| Security, bridge or signing | `SECURITY.md`, `docs/architecture.md`, ADRs 0029/0033/0047 |
| New product capability | `SCOPE.md`, `.out-of-scope/`, then the relevant accepted ADR |
| Monitoring implementation | ADRs 0058–0060; measurement scripts are not a runtime collector |

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

Column parity: `npx tsx scripts/parity/parity-check.ts` fails without private fixtures.
Tree coverage and snaplen checks skip when their tools or fixtures are unavailable.
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

Keep this root near 200 lines, using short statements rather than dense paragraphs.
Add a root rule only when it affects many tasks or prevents a costly recurring mistake.
Put subsystem mechanics in linked docs; prefer a conditional pointer over another summary.
Keep decisions and their measurements in ADRs; put retired explanations in history.
Avoid current version numbers, script counts, machine timings and progress diaries here.
Update the owning document when behavior changes; do not maintain competing copies.
Check code and supersession notes before treating an old document as current authority.
Record decisions that close off future options with an ADR, following `CONTRIBUTING.md`.
In handoff, say what changed, which checks ran, and what remains unverified.