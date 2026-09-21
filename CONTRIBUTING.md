# Contributing

## Getting it running

You need Node 24+, Python 3.10+ and Npcap. `README.md` has the full list,
including what you additionally need to build the installer.

```
npm ci
npm run start:app
```

`npm run start:app` rather than `npm run dev` is the one worth knowing about.
`dev` serves the renderer from a Vite dev server, where the `app://` protocol
handler, the MIME table, the 404 rule and the CSP all behave differently from a
real build. Anything touching those has to be tested under `start:app`.

You do not need a capture device to work on most of this. `npx tsx
scripts/electron/serveStub.ts` serves a stub agent that speaks the production
protocol; launch the app beside it and pick "Ethernet (stub)".

## The one gate

```
npm run check
```

Type-checks both TypeScript programs, then runs every assertion script under
`scripts/`. It must pass. It is also fast, so run it often rather than at the
end.

Four things about the suite that are worth knowing before you add to it:

**Every assertion script runs under plain `tsx`** — no Electron, no browser, no
test runner. That is a property to protect, not an accident: it is what lets the
suite run on a Linux CI box and finish quickly enough to run on every commit.
When something genuinely needs Electron, the pattern is to split the *decision*
into a module that does not import it — `electron/pipeTransport.ts` beside
`agentPipe.ts`, `src/services/agentHealth.ts` beside `electron/agentService.ts` —
and test that.

**A script prints `PASS`/`FAIL` lines and exits non-zero.** There is no runner
and no framework. `scripts/check.ts` finds them by walking the directory, so a
new file in `scripts/` is picked up with no registration step.

**Parity floors only rise.** `test/fixtures/acceptance.json` records how closely
each column and each protocol layer matches the reference analyzer.
`scripts/parity/acceptance.ts` fails a lowered floor. If your change improves
coverage, re-record it; if it appears to reduce coverage, that is the suite
telling you something.

**A number in prose gets checked where it can be.** The README's layer count is
held to `LAYERS.length`; the agent's version is held across every file that
states it. If you write a figure into documentation, prefer one that names its
own source, because that is the kind that can be held to it.

## What cannot be checked here

`docs/verification.md` is the other half of the suite: everything this repository
knows to check and cannot check by itself — the window's own chrome across both
themes and three scaling factors, the drag regions, the pipe's security
descriptor actually taking effect (which needs a second Windows account), the
elevation prompt. Every item says what a failure *looks like*, because everything
in it fails silently. If you change the shell, the installer or anything
privileged, read it.

A handful of scripts drive the real application and are excluded from
`npm run check` because they take minutes or need hardware. They are listed in
`scripts/check.ts`'s `NOT_TESTS` with a reason each, and they are worth running
by hand after touching what they cover.

## Commits

Subject lines here are declarative sentences about what changed and why it
matters — "SSDP is an HTTP message, so it gets HTTP's fields" — rather than
`fix:` prefixes. The body is prose explaining the reasoning, especially the
alternative that was rejected. `git log` is the design record for everything that
did not warrant an ADR.

## Decisions

Anything that closes off a future option gets an ADR in `docs/decisions/`, with
the measurement behind it where there is one. ADRs are not edited after
acceptance — a reversal is a new file with a banner on the old one, and
`docs/decisions/README.md` is the index that tracks supersessions.

`CLAUDE.md` is the working guide to the codebase and is kept current;
`docs/history.md` holds the archaeology of things that were deleted, so the
reasoning survives without every session paying to read it.

## The fixtures

`test/fixtures/` holds two real captures used for parity testing. They are **not
in the repository** and will not be: they contain real names and addresses
(ADR 0004). `test/fixtures/README.md` explains how to produce equivalents. Any
script that needs them either skips cleanly or fails with a message saying how to
get them — never silently.
