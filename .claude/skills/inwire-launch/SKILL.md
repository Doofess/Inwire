---
name: inwire-launch
description: Use to run, drive or screenshot the real Inwire app, for example to see a change working or to do a UI review pass. Launches in the background through scripts/electron/launchApp.ts with a throwaway profile and the stub agent, then shoots every state in both themes and reads each image.
---

# Launch, drive and photograph Inwire

The owner works on this machine while the app runs, so a window that takes
focus gets in the way. UX matters a great deal here: every user-facing change
gets a screenshot pass, covering every state, in both themes.

## Before launching

- Run `npm run build` first. Scripts test `dist/`, not source. The exception
  is when `npm run start:app` is running, because building under it breaks its
  lazy chunks. In that case use its build and say so.
- Start Electron only through `scripts/electron/launchApp.ts`. It sets the
  background-window flag. `scripts/electron/background-launch.ts` fails any
  script that calls Playwright's launch itself.

## Use an existing shot script when one covers the area

- `npx tsx scripts/electron/palette-shots.ts --out <dir> [--themes light,dark,dim,contrast]`
- `npx tsx scripts/electron/readme-shots.ts <out-dir> [--themes dark,light]`
- `npx tsx scripts/electron/monitoring-shots.ts <out-dir> [--widths 1024,1600] [--themes ...] [--only <prefix>]`
- `npx tsx scripts/electron/speed-test-shots.ts <out-dir> [--widths 1024,1600]`

Write output to the session's scratchpad, never into the repo. If a feature's
states have no script, extend the nearest one rather than writing a throwaway.

## An ad-hoc driver

Put the driver in the scratchpad and import from the repo by absolute path.
Follow `scripts/electron/monitoring-shots.ts`:

1. `startStubAgent(pipe, n)` from `scripts/electron/stubAgent.ts`, on a
   **private** pipe name. Never use the real agent's pipe.
2. A `mkdtemp` profile directory, passed as `INWIRE_USER_DATA`. The app prunes
   its capture directory at startup, so the real profile would lose captures.
3. `launchApp({ args: ['.'], env: { ...process.env, INWIRE_USER_DATA, INWIRE_AGENT_PIPE } })`,
   then `firstWindow()`.
4. Switch themes in place: set `localStorage` `theme`, then dispatch a
   `StorageEvent` with `key: 'theme'`, as `monitoring-shots.ts` does inside
   `shot()`. Shoot Light and Dark at minimum, and all four themes for theme
   work, at widths 1024 and 1600.
5. Give every locator a 30 s timeout. Playwright's default is none, so a
   missing control hangs silently.
6. Close with `app.close()`, never `kill()`. Killing it orphans the GPU,
   renderer and store children. If frames are buffered, clear
   `setUnsavedCapture` first, or the quit confirmation waits forever
   (`scripts/CLAUDE.md`).
7. Close the stub agent, then remove the profile directory.

`page.evaluate` under tsx breaks on named inner functions with "`__name` is not
defined", an esbuild artefact. Pass a function with no named helpers inside,
or pass a string.

## Look at the result

Read every image and judge it: layout at both widths, contrast in both themes,
empty, loading, error and full states. A run that exits 0 is not a review.
Screenshots meant to be shared must show no fixture addresses or hostnames
from `test/`.
