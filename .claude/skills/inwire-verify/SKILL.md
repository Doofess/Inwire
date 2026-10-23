---
name: inwire-verify
description: Use before saying an Inwire change is done, fixed or passing. Picks the checks for the changed paths from docs/testing.md, runs those first, then lint and the full npm run check in the background, and reports every result verbatim, including what was not run.
---

# Verify an Inwire change

The claim "done" needs this turn's evidence. Run the narrow checks first,
because they answer in seconds and say which change broke what. Then run the
full gate once.

## 1. What changed

- `git status --porcelain`, plus `git diff --name-only <base>...HEAD` for a
  branch. Use the branch's merge base with `main`.
- Group the paths by area. The root `CLAUDE.md` "Validate the changed behavior"
  table is already in context. For the detail, grep `docs/testing.md` for
  `## Choose checks for the changed path` and read only that section.

## 2. Narrow checks, in the foreground

- **Changed assertions.** Run every assertion script that covers a changed
  path: `npx tsx scripts/<area>/<name>.ts`. Run each one separately and read
  its `FAIL` lines.
- **Docs.** For a changed CLAUDE.md, doc, skill or agent, run
  `npx tsx scripts/docs/claude-md-refs.ts`.
- **This setup.** For a change under `.claude/`, run
  `npx tsx scripts/claude/setup.ts` and `npx tsx scripts/claude/hooks.ts`.
- **Renderer, Electron or Worker code.** Run `npm run build` first, because
  `check` does not build and integration checks would test stale output.
  Never build under a running `npm run start:app`, because that breaks its lazy
  chunks. Check whether it is running first: from Git Bash,
  `tasklist //FI "IMAGENAME eq electron.exe"`; from PowerShell,
  `Get-Process electron -ErrorAction SilentlyContinue`. If Electron is running,
  do not build, and say so.
- **TypeScript.** Run `npm run lint`. It is strict and fails on unused locals.

## 3. The full gate, in the background

`npm run check` takes over ten minutes. Run it with `run_in_background: true`,
writing its output to a log in the session's scratchpad. A hook refuses a
foreground run without `timeout: 600000`. Wait for the completion notification;
never `sleep`. Then read only:

- the log's last line: `All N assertion scripts passed`, or the failure count;
- `grep ^FAIL` on the log, plus the 25 lines `check.ts` prints for each
  failure.

A failure that does not reproduce when the script runs alone under the full
run's load is reported as flaky, with both runs quoted. Never call it a pass.

## 4. Bundle size

`scripts/perf/bundle-size.ts` fails when `dist/assets` grows past its
ceiling.

- Report the growth.
- If the change's own feature code explains it, raise the ceiling with
  `npx tsx scripts/perf/bundle-size.ts --write-ceilings`. Commit that in its
  own commit, whose message names the reason and the size, and say so in the
  report.
- Investigate growth the change does not explain. Never raise a ceiling just to
  make a check pass, and never relax a parity floor.

## 5. Drives that check does not run

Drives and measurements are in `NOT_TESTS` (`scripts/check.ts`). For each
one that the changed path calls for in `docs/testing.md`, either run it (they
take minutes; read its prerequisites first) or list it as **not run**, with
the missing prerequisite. A skip or `NOT RUN` is never a pass.

## 6. Report

Quote the following, verbatim:

- the lint exit;
- each narrow script's last line;
- the build result;
- `All N assertion scripts passed` (or the failures);
- the documentation-check line;
- the list of what was not run, and why.
