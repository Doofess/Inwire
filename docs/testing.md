# Testing and release workflows

Run commands from the repository root unless a working directory is stated.
Use Node.js 24+ and install the locked dependencies with `npm ci`.
[CONTRIBUTING.md](../CONTRIBUTING.md) covers setup and contribution policy;
[verification.md](verification.md) covers checks that require a person,
packaged application, hardware or another Windows account.

## The normal gate

```powershell
npm run check
```

This runs `npm run lint` over the renderer/scripts and Electron TypeScript
programs, then [scripts/check.ts](../scripts/check.ts). It does not build.
For changes to the app or its bundled dependencies, build first:

```powershell
npm run build
npm run check
```

The build emits the renderer into `dist/` and Electron CommonJS entries into
`dist-electron/`. Integration scripts inspect or launch those files; a stale
build tests old code. The smoke script prints the build's age. On Windows,
with output and Playwright available, it drives the real app through the pipe,
main process, Worker, dissector and React against a stub agent. Missing
prerequisites produce explicit skips, which are not evidence about that path.

[CI](../.github/workflows/ci.yml) intentionally runs `check` before `build`
on Linux and Windows. Output-dependent checks skip on that fresh checkout.
Separate jobs test and build the Rust agent on Windows, and test the Python
agent and parse its Unix installer on Linux and macOS. Local validation must
cover any paths skipped by those jobs.

## Adding an assertion script

The runner recursively discovers `.ts` files under `scripts/` that contain
`process.exit` or import `../parity/treeOracle`. It excludes itself and the
explicit `NOT_TESTS` entries. A new script needs no registration if it meets
those rules. Print useful `PASS`/`FAIL` output and exit nonzero on failure.
Run one script with, for example, `npx tsx scripts/capture/reader.ts`.

Keep logic usable under plain `tsx`: put privileged adapters beside pure
decision modules, such as `agentPipe.ts` beside `pipeTransport.ts`.
`src/services/` and `src/lib/` import neither Electron nor `node:*`, except
the explicitly isolated `nodeBlockFile.ts`, which must remain unreachable
from `src/main.tsx`. Preserve the separate TypeScript configurations and
their matching strictness flags.

Generators, measurements and drivers requiring real hardware or lengthy
captures belong in `NOT_TESTS` with a reason when the discovery rule would
otherwise select them. Do not exclude a runnable assertion to conceal failure.
Use meaningful captures: a test of buffer eviction must force frames out of
the window; a certificate test needs a readable certificate. Synthetic
protocol scripts can author frames and compare them with tshark while still
running their own assertions when tshark is absent.

## Choose checks for the changed path

All rows assume the normal TypeScript gate, plus a fresh build for app changes.
Driver paths below are relative to `scripts/`; run them with `npx tsx`.
Read each driver's prerequisites before starting it.

| Changed path | Additional validation |
|---|---|
| Scheme handler, preload, IPC, Worker, renderer startup | Built-app smoke through `npm run check`; manual `npm run start:app` |
| Window chrome, drag/resize, GPU, packaging | `npm run pack`, then relevant items in [verification.md](verification.md) |
| Dissection, display fields or colour rules | Column parity, tree coverage and relevant synthetic protocol scripts; snaplen for truncation changes |
| Capture store, row space or import | `scripts/electron/disk-drive.ts` and `scripts/electron/import-drive.ts` |
| Live frame path or record reconstruction | `scripts/electron/live-revisit-drive.ts`; `scripts/electron/revisit-drive.ts` for imported/decrypted detail |
| Capture-start options or agent open | `scripts/electron/capture-options-drive.ts` |
| Agent capture-file writer or autostop | `scripts/electron/capture-file-drive.ts` |
| Agent lifetime, health or connection | `scripts/electron/agent-live-drive.ts`; agent tests below |
| Ownership across clients | `scripts/agent/two-client-drive.ts`; second-account security check in [verification.md](verification.md) |
| Update Center | `scripts/electron/update-center-drive.ts`; UAC and installer checks remain manual |
| GeoMap style or layer lifecycle | `scripts/electron/gpu-restore-drive.ts` with a map visible; packaged GPU checks |
| Export | Relevant `scripts/export/` assertions and a capture beyond the RAM window; open exports in their target programs |
| Speed test | Relevant `scripts/speed-test/` assertions; `scripts/electron/speed-test-drive.ts` performs an outbound real test |
| Fonts, colours or brand mark | Theme assertions in `check`, [visual design guidance](../.claude/skills/inwire-visual-design/SKILL.md) and visual verification |

The disk driver captures beyond the RAM budget, filters the whole capture and
reads old rows back from disk. The import driver imports a large generated
capture and returns to its first frame. The live-revisit driver requires the
installed service, Npcap, traffic and an Ethernet adapter; it compares rebuilt
details against ordered dissection. Capture-options and capture-file drivers
exercise a real installed agent, including filter/snaplen and file ownership.
The update driver uses a loopback feed and installs nothing.

## Safe Electron launches

Every script that launches the app uses
[launchApp.ts](../scripts/electron/launchApp.ts), never Playwright's
`_electron.launch` or a child-process Electron launch directly.
[background-launch.ts](../scripts/electron/background-launch.ts) enforces this.
The helper sets `INWIRE_BACKGROUND_WINDOW=1`: the window paints offscreen
without stealing focus or appearing in the taskbar. A hidden window throttles
animation frames and can stall waits. Foreground display is an explicit
`launchApp({ visible: true })` opt-out when needed for the task.

Use a temporary `INWIRE_USER_DATA` profile: app startup prunes its capture
directory, so a test must not touch a developer's stored captures. Give stub
integration runs their own `INWIRE_AGENT_PIPE` and serve the stub on that same
name, as [smoke.ts](../scripts/electron/smoke.ts) does, to avoid competing with
the installed service. Give locators finite timeouts. Before graceful shutdown,
clear the test's unsaved-capture state so the quit confirmation cannot hang;
killing main can orphan its child processes.

For manual traffic without Npcap, `npx tsx scripts/electron/serveStub.ts`
serves the production protocol on the default pipe. Launch the app in another
terminal and choose **Ethernet (stub)**; `--burst n` changes frames per tick.
This convenience requires the default pipe to be free. Use the private-pipe
pattern above for automated integration beside an installed agent.

Use `npm run dev` for UI iteration. Use `npm run start:app` for the real
`app://inwire` handler, MIME table, 404 behavior and CSP without packaging;
its launcher also supplies the loopback development update feed. The packed
executable needs its own manual pass: inspector fuses prevent Playwright from
attaching to it, and that restriction must remain intact.

## Private fixtures and parity

[test/fixtures/README.md](../test/fixtures/README.md) names the real captures,
hashes, ground-truth generation and optional inputs. Captures, derived ground
truth and TLS key logs are private and untracked. Do not add them to a commit
or publish their contents. A fixture's traffic must contain the feature being
validated; the general browsing captures cannot prove every protocol.

```powershell
npx tsx scripts/parity/parity-check.ts
npx tsx scripts/parity/tree-coverage.ts
npx tsx scripts/parity/snaplen.ts
```

The column gate requires the captures and recorded tshark ground truth; it
**fails** with instructions when they are absent and is excluded from `check`.
Tree coverage requires tshark and captures; snaplen additionally requires
editcap. Both skip cleanly without their prerequisites and run under `check`.
Regenerate ground truth after a Wireshark upgrade using the fixture guide.

`test/fixtures/acceptance.json` records column percentage floors, tree count
floors and ceilings, plus snaplen expectations. Floors may only rise and
ceilings only fall; `scripts/parity/acceptance.ts` compares them with `HEAD`.
Tree floors use counts because the reference's vocabulary changes between
versions. A partial `tree-coverage.ts --frames N` run is a measurement and
disables whole-file assertions. `--write-floors` records measurements; review
the diff and never use it to hide a regression. For a new protocol cluster,
`scripts/parity/cluster-diff.ts` compares values by frame and prefix; presence
counts alone do not prove correctness.

## Agent validation and versions

Windows ships the Rust agent. Its tests and shared wire, command and control
vectors protect compatibility with the Python agent used on macOS/Linux.
Changes to common behavior need validation in both implementations.

```powershell
npm run build:agent -- -Test
npx tsx scripts/agent/built-version.ts
python local-agent/test_protocol.py
python local-agent/test_interface_stats.py
```

For transport changes, `scripts/agent/pipe-interop.ts` drives the real client
against the Rust `pipe_serve` example. `agent-interop.ts` uses `agent_serve`
and a real capture device; `agent-compare.ts` compares both agents on one
adapter with separate pipe names. These Windows drivers are excluded from
`check`; their headers describe the companion processes and prerequisites.

The Rust build uses `stable-x86_64-pc-windows-gnu` and `--locked`; `-Test`
runs its tests first. It then stamps VERSIONINFO, the icon and an `asInvoker`
manifest onto `agent-rs/dist/inwire-agent-windows.exe` and signs that copy.
Cargo's unstamped output is not the installer payload. Signing warns and
leaves development output unsigned if no certificate is configured.

Rebuilding does not replace the installed service. From an elevated prompt,
use `agent-rs/switch-agent.ps1 -Rust`, then check `-Status` and the copied
file's age/version before running live drivers. Never register a LocalSystem
service from a user-writable build directory. `-Python` installs the unsigned
PyInstaller comparison tree; restore `-Rust` or reinstall afterward.
[local-agent/CLAUDE.md](../local-agent/CLAUDE.md) covers Python packaging.

For Unix installer changes, run `sh -n local-agent/unix/install.sh` and verify
the Python agent imports on the relevant OS, as CI does. Real pipe ACL effects
need another Windows account; protocol tests alone cannot prove access rights.

Author the version in `package.json`, run `npm run sync:version`, and update
the checked literals in `src/services/agentProtocol.ts` and
`installer/setup.iss`. Commit the generated Python version, Cargo manifest
and lock entry. `scripts/agent/version.ts` checks consistency, and the stamp
step verifies the built binary agrees. Agent compatibility uses equality;
the installer separately prevents downgrades. Legacy standalone-installer
versions remain frozen as upgrade-detection records.

## Performance evidence

Before a performance-motivated dissector change, name the expensive function
with `npx tsx scripts/perf/profile.ts --fixture inwire` or `--file <capture>`.
The profiler reads inputs before measuring dissection and reports self time
separately from total time. Treat `tsx`/`__name` work as tooling, and check
whether a hot loop can be improved before changing a shared type contract.
Profile the workload that showed the problem; `--file` dissects it in memory,
so trim a large capture with editcap first.

`scripts/perf/store-boundary.ts` measures writer, serialization and MessagePort
costs separately. Compare the complete changed path before accepting an
optimization: batching writes previously lost more to copying than it saved.
For store memory changes, exercise backpressure and the heap guard in the
running app; a forwarded V8 heap flag alone does not prove an effective limit.
See [ADRs 0042–0044 and 0053](decisions/README.md) for the measurements.

Launch time, throughput, map load and machine-dependent costs are printed
measurements, not pass marks. The renderer's byte size is a build property:
`scripts/perf/bundle-size.ts` enforces `test/perf/ceilings.json`, with separate
eager and total budgets. Ceilings may only fall, checked against `HEAD`; a
fresh build is needed because the script skips without `dist/`. Do not turn a
machine-specific timing into a gate or raise a ceiling to make a change pass.

## Packaging and release

For an unsigned installer to try locally, run `npm run build:agent`,
`npm run pack`, then `iscc installer/setup.iss`. The result is
`installer/output/Inwire-Setup.exe`. `pack` rebuilds the app and writes
`release/win-unpacked/`; it does not build the agent. Read the relevant
[manual verification items](verification.md) before shipping.

`npm run dist:signed` owns the release sequence: build/stamp/sign the agent,
build/pack the app with fuses applied before signing, verify every installed
PE payload, compile/sign the installer and uninstaller, then verify Setup.
It sets `INWIRE_REQUIRE_SIGNING=1`, making missing signing configuration fatal.
Do not edit resources after signing. The release script chooses the newest
installed Inno compiler to avoid retaining an older unsigned uninstaller.

[scripts/sign/](../scripts/sign/) contains certificate setup, the sole signer
and payload verification. Keep certificates and `.signing.json` untracked.
A locally trusted certificate is not a public trust solution; the remaining
distribution limitations are recorded in [verification.md](verification.md).
