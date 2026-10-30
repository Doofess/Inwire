# scripts/CLAUDE.md

How assertion scripts and drivers are written and run; loaded when you work under `scripts/`. What each invariant's script is called is in `docs/testing.md`; the monitoring scripts are listed in `src/services/monitoring/CLAUDE.md`.

## Plain tsx

- Every assertion script runs under plain `tsx`: no Electron, no browser, no test runner. It prints `PASS`/`FAIL` lines and exits non-zero on failure. Keep that, it is what lets CI run the suite on ubuntu on every commit.
- `scripts/check.ts` finds scripts by walking this directory. A script that is a measurement or needs private fixtures or a machine state goes in its `NOT_TESTS` with a reason; otherwise it runs under `npm run check`.
- When a decision needs Electron, split it into a module that does not import it and test that: `electron/pipeTransport.ts` beside `agentPipe.ts`, `electron/saveTarget.ts` beside `saveFile.ts`, `src/services/agentHealth.ts` beside `electron/agentService.ts`. A `useCallback` in `src/App.tsx` is unreachable from here, so arithmetic worth testing is lifted into a module a script can import.
- `scripts/electron/tsconfigs.ts` keeps the two TypeScript programs on the same four strictness flags. Scripts type-check in the root program with the renderer's lib.
- A fixture proves something only if the end that authored it is not the end being tested (`scripts/agent/command-vectors.json` is made by the app's encoder, not by Rust).
- A check that mutates nothing proves nothing. Put the bug back and watch it fail, as `scripts/capture/segment-guard.ts` does. A first version of the import comparison passed with its offset arithmetic removed.
- Cross-process truths need a boundary in the test: `scripts/capture/store-protocol.ts` serialises with `v8.serialize`. A test that hands objects across in one context hides prototype loss.
- A queue shift inside a `find` predicate shifts once per comparison, not once per match; use `findIndex` then `splice`, and test the arithmetic outside React.

## Fixtures

- `test/fixtures/` holds two real captures, untracked (they contain personal addresses, ADR 0004), plus tshark ground truth. `scripts/parity/parity-check.ts` **fails** without them and says how to get them; it is in `NOT_TESTS`. `tree-coverage.ts` and `snaplen.ts` skip cleanly without tshark or fixtures. Column floors are percentages and tree floors are counts; both only rise (`scripts/parity/acceptance.ts`).
- The fixtures contain no ICMP error, no readable HTTP and no certificate (TLS 1.3 encrypts it). `scripts/icmp/dissect.ts`, `scripts/http/dissect.ts` and `scripts/tls/certificate.ts` build their own frames, write a `.pcap`, and cross-check tshark when present. A measurement that cannot see a feature cannot defend it; add a synthetic one.
- `test/` also holds the owner's loose real files (a 2.7 GB burst pcapng, exports). Gitignored; never commit or print their contents.

## Launching the app

- Start Electron only through `scripts/electron/launchApp.ts`, which sets `INWIRE_BACKGROUND_WINDOW=1`. `scripts/electron/background-launch.ts` fails a script that calls `_electron.launch` itself. A visible launch is the explicit `launchApp({ visible: true })`, and nothing uses it.
- Use a temporary profile (`INWIRE_USER_DATA`) and a private `INWIRE_AGENT_PIPE`: the app prunes its capture directory at startup and would delete a developer's capture.
- `scripts/electron/smoke.ts` runs the real app against `scripts/electron/stubAgent.ts` over a real pipe. It tests `dist/`, not source: it prints the build's age and says so past two hours. Every locator carries a 30 second timeout, because Playwright's default is none and a missing control would hang the suite silently. It clears `setUnsavedCapture` before closing; closing with frames in the buffer opens the quit confirm and waits forever. Do not `kill()` main: it orphans the GPU, renderer, store and crashpad children.
- `npx tsx scripts/electron/serveStub.ts` serves the stub for hand testing (`--burst n`); launch the app beside it and pick "Ethernet (stub)".

## Drives (in `NOT_TESTS`, run by hand)

- `live-revisit-drive.ts`, `capture-options-drive.ts`, `capture-file-drive.ts`: real traffic through the installed current agent; need Npcap, the service and an Ethernet adapter.
- `revisit-drive.ts`, `disk-drive.ts`, `import-drive.ts`: the store path; one to three minutes each. `import-heap-drive.ts --pcap <file>`: the renderer's heap after a large import (#19); needs a file of millions of frames. `gpu-restore-drive.ts`: skips without a map on screen. `update-center-drive.ts`: builds its manifest from this machine's Npcap and installs nothing.
- Run the matching drive after a change on its path, and say which you could not run.

## Performance

- `scripts/perf/profile.ts` (`node --cpu-prof`) is the only instrument for dissection speed. No dissector change on performance grounds until it names the function the change makes cheaper. Beware `__name`, an esbuild `keepNames` artefact of `tsx` that is absent in production.
- `scripts/perf/bundle-size.ts` holds `dist/assets` to `test/perf/ceilings.json`; ceilings only fall, checked against `git show HEAD:`. It is the only performance number that is a gate, and it skips with no `dist/`. Launch and map timings are printed, never asserted.
