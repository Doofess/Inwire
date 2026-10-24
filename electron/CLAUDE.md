# electron/CLAUDE.md

Rules for the main process, the preload and the utility-process hosts; loaded when you work under `electron/`. The Update Center has its own guide in `electron/updateCenter/CLAUDE.md`, the renderer shell in `src/components/CLAUDE.md`, and `docs/architecture.md` has the topology.

## Main is a thin adapter

- Put every decision worth testing in a module that does not import Electron, beside the adapter: `appPaths.ts`, `window.ts`, `csp.ts`, `menu.ts`, `windowState.ts`, `saveTarget.ts`, `saveSession.ts`, `pipeTransport.ts`, `agentService.ts`, `windowColors.ts`. Assertion scripts run under plain `tsx` and cannot load Electron.
- No captured frame passes through main's JavaScript as anything but an opaque buffer. Main deframes the pipe and posts the payload onward unread.
- Main treats nothing from the renderer as a path. `inwire:save-captured` and the captured-file reads take a capture id and the agent's file name, never a path (`electron/capturedFiles.ts`, `scripts/electron/captured-files.ts`).
- Exports are saved in pieces: dialog, `<target>.<random>.partial`, append, then rename or delete on close. A token belongs to the webContents that opened it; a closed window or a quit deletes its partials (`electron/saveSession.ts` holds every rule).

## Window

- The window is frameless and draws its own controls. Never set `thickFrame`, `roundedCorners`, `titleBarOverlay` or `titleBarStyle`, at any value. `scripts/electron/shell.ts` asserts the words do not appear in comment-stripped `electron/window.ts` and `electron/main.ts`, so do not even write them as code.
- The close path never calls `window.destroy()`; the quit guard is on the `close` event and destroying skips the unsaved-frames confirm.
- `backgroundColor` is fixed at construction, before a renderer can report a theme. `window-state.json` caches the resolved ground (`electron/windowColors.ts` is the table); `localStorage` stays the source of truth.
- `maximize`, `unmaximize`, `focus` and `blur` are forwarded to the renderer over `WINDOW_STATE_CHANNEL`; `setTitle` is driven from the renderer.
- A crashed renderer keeps its window and webContents, and nothing reloads it on its own. `isDestroyed()` is not enough before a send, or Electron logs "Render frame was disposed" per send: every main-to-page send asks `canSend` from `electron/rendererLife.ts`. Main logs the crash as `[renderer] gone: <reason> (exit code N)` (the code lives only there, never in the UI), then loads the crash screen into the same window: `crash.html`, a second Vite entry (`src/crash.tsx`) that imports nothing of `App`, drawn in the quit confirm's card (`AlertCard`) with Reload (`location.replace('/')`) and Quit (`window.close()`, so an unsaved capture still asks). `crashResponse` decides; the OS's Reload / Quit box is only the fallback, for when the crash screen itself dies or will not load, and a background launch never shows it but answers from `INWIRE_CRASH_ANSWER`. Wording is `src/lib/crashScreen.ts`. Held by `scripts/electron/renderer-life.ts` and `scripts/electron/smoke.ts`.
- Snap Layouts and Alt+Space are accepted losses (`docs/verification.md`); do not re-check them.
- Scripted launches set `INWIRE_BACKGROUND_WINDOW=1`: shown with `showInactive()` parked at -20000,-20000, out of the taskbar. A hidden window gets two animation frames a second and stalls every rAF wait. `scripts/electron/background-launch.ts` fails any script that calls `_electron.launch` itself.

## Renderer, preload and CSP

- `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, no service workers, every permission request denied.
- The preload is one CommonJS file bundled by `electron/build.cjs` and imports only `electron`. A `node:os` import type-checks, bundles, then removes `window.inwire` with no message; `scripts/electron/preload-sandbox.ts` reads the built bundle.
- The CSP is a header applied in `hardenSession` (`electron/csp.ts`), never a meta tag. `OUTBOUND_HOSTS` is the renderer's whole reach: geojs and ipapi.co (behind `nameResolution.geoIp`), cloudflare-dns (behind `nameResolution.reverseDns`), openfreemap tiles (no switch of their own; the map renders only after geo-IP consent, `GeoMap.tsx`).
- `MAIN_OUTBOUND_HOSTS` (update feed, npcap.com, the speed test's Cloudflare endpoint) are dialled by main or a utilityProcess and stay **out** of the policy: a `connect-src` entry would grant the renderer a host it never touches. `scripts/electron/shell.ts` asserts they are absent, that port 8999 is absent, that the recorded feed and Npcap hosts are the ones actually dialled, and that the speed test accepts only a loopback `INWIRE_SPEEDTEST_TARGET`.
- `scripts/electron/smoke.ts` proves the policy is applied: a page-initiated `<img>` from a blocked origin must raise `securitypolicyviolation`. A `page.evaluate` goes through CDP and is exempt, and a blocked `fetch` looks like no network.
- `ISOLATION_HEADERS` (COOP and COEP) go on the `Response` built in `registerAppProtocol`. `onHeadersReceived` does not fire for `protocol.handle` responses, and without COEP on the worker's own response `pipeline.worker` and maplibre's worker fail with `coep-frame-resource-needs-coep-header`. `onHeadersReceived` carries a URL filter so map tiles do not round-trip through main. `smoke.ts` evaluates `crossOriginIsolated`.
- Nothing depends on cross-origin isolation yet; the packaged build is verified by hand.

## Utility processes

- Fork every utilityProcess with `stdio: 'pipe'`. A packaged GUI app has no console to inherit and the protocol's "never silent" failures would go nowhere. Current hosts: `store/host.ts` (`inwire-capture-store`), `speedTest/host.ts` (`inwire-speed-test`), `monitoring/host.ts` (`inwire-monitoring`).
- A dead child is a handled state: report `exit` to the renderer over a channel of its own, because a `MessagePort` that goes quiet hangs every pending request.
- Never put a transfer list on a message to the store: a message transferring an `ArrayBuffer` into a `MessagePortMain` does not arrive. Copy. The one transfer that stays is the Worker's bytes to the renderer, a DOM port at both ends.
- The store must keep the port's role with the port (`'ingest'` or `'client'`), never assign `event.ports[0]` to a single `port` (`store/entry.ts`, `scripts/electron/store-ports.ts`).
- `execArgv: ['--max-old-space-size=2048']` in `store/host.ts` does **not** move V8's limit; `heap_size_limit` stays 4192 MB. The ceiling is `store/heapGuard.ts` (warn at 80%, seal and stand down at the wall); keep it (`scripts/capture/heap-guard.ts`).
- The store's inbound queue is bounded: `bytesTaken` credit from the store, 50,000 unanswered frames in the Worker (`src/services/pipeline/liveFlow.ts`), and main sheds whole batches past 256 MB owed (`electron/pipeCredit.ts`, `scripts/electron/pipe-credit.ts`).
- Main starts the agent service at `whenReady()` before the window exists. Diagnose with `electron/agentService.ts`; `provesAbsent` tests `error.code === 1`, a number (`scripts/electron/agent-health.ts`).
- Monitoring's host, quit drain and suspend hook are in `src/services/monitoring/CLAUDE.md`; the `will-quit` handler in `main.ts` must call `planQuitDrain` and `runQuitDrain`, not reimplement them.

## Packaging

- `electron/afterPack.cjs` flips the fuses (`runAsNode`, `enableNodeCliInspectArguments`, `enableNodeOptionsEnvironmentVariable` off; `onlyLoadAppFromAsar` on) before the platform gate and before signing. Flipping mutates the exe, so a signature taken first is void. `enableEmbeddedAsarIntegrityValidation` stays off until its own commit: its failure is an app that will not start.
- `scripts/electron/fuses.ts` reads the wire, which holds ASCII digits (49 set, 48 cleared), so `Boolean(value)` is true for both. Compare the character.
- Every signature goes through `scripts/sign/sign.ps1`; no `.cer` or `.pfx` is tracked (`scripts/sign/signing.ts`). Under `iscc /DSIGN`, `scripts/sign/verify-payload.ps1` refuses an unsigned PE file in the payload.
- Inno keeps an installed `unins000.exe` that is newer, even unsigned, and never removes files an old build installed; `[InstallDelete]` names `dxcompiler.dll`. Compile with the newest Inno Setup `build-signed.ps1` finds, and check the installed files, not the build (`docs/verification.md`).
- Crash reporting stays off (`electron/keyLogFollower.ts` cites ADR 0008). A minidump is a copy of `KeyLogStore`.
- The key log is followed by main with a fast poll (`POLL_MS`) beside `fs.watch`; the poll is what sees a browser: Chrome appends through an open handle, which raises no change notification on Windows (`electron/keyLogFollower.ts`, `keyLogTail.ts`, ADR 0045).
