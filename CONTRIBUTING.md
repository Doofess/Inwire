# Contributing

## Getting started

Use Node.js 24+ and run these commands from the repository root:

```powershell
npm ci
npm run start:app
```

The desktop app runs on Windows. Python 3.10+ is needed for the Python agent
and its tests; Npcap is needed for live capture. Building the Windows agent
requires rustup with `stable-x86_64-pc-windows-gnu`, and compiling the installer
requires Inno Setup 6.3 or newer. See [Build and run](README.md#build-and-run).

`npm run dev` serves the renderer through Vite for UI iteration.
`npm run start:app` builds and launches against `app://inwire`, exercising the
real protocol handler, MIME types, 404 behavior and CSP. Use it when changing
those boundaries. Packaging has additional checks described in the
[manual verification matrix](docs/verification.md).

## Validation

Run `npm run check` for changes. It type-checks both TypeScript programs and
runs the discovered assertion scripts. It does not build: when changing the
app, run `npm run build` before `npm run check` so integration scripts exercise
the current output. Windows integration scripts can launch Electron against a
stub; on other platforms or without their prerequisites they skip explicitly.

[Testing and release workflows](docs/testing.md) explains discovery, isolated
background launches, agent tests, fixture parity, performance measurements and
the validation needed for each kind of change. Run the relevant checks there;
a passing TypeScript suite does not replace agent tests or privileged manual
verification.

Keep reusable decisions independent of Electron so plain `tsx` scripts can
test them. Assertion scripts print `PASS`/`FAIL` and exit nonzero on failure;
check [the discovery rules](scripts/check.ts) when adding one.

Capture fixtures and TLS key logs contain private information and remain
untracked. Follow [the fixture guide](test/fixtures/README.md); the column
parity gate fails with instructions when its inputs are absent. Acceptance
floors only rise and ceilings only fall. Documentation figures should name
their source and have an assertion where practical.

## Scope and decisions

Read [SCOPE.md](SCOPE.md) before proposing product features. Decisions that
close off a future option get an ADR in `docs/decisions/`, with measurements
where applicable. Accepted ADRs retain their record: a reversal gets a new
file and a supersession banner on the old one. Update the
[decision index](docs/decisions/README.md) in the same change.

Keep [CLAUDE.md](CLAUDE.md) current as the short working guide. Put detailed
procedures in the linked documentation and historical reasoning in
[docs/history.md](docs/history.md), so every session need not reload it.

## Commits

Subject lines are declarative sentences about the change and why it matters,
such as “SSDP is an HTTP message, so it gets HTTP's fields,” rather than `fix:`
prefixes. Explain the reasoning and relevant rejected alternatives in the
body. Git history is the design record for changes that do not warrant an ADR.
