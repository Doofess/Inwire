# 0041 — One performance ceiling that may only fall, and why the rest are measurements

**Status:** accepted

## Context

Seventeen files live under `scripts/perf/`. Four of them assert anything —
`buffer-budget.ts` (a calibration error), `hot-path-allocations.ts` (a code
shape), `incremental-aggregate.ts` and `render-tier.ts` (correctness). **None
asserts a size or a time.**

So nothing in this repository failed when the pipeline got slower. Parity has
`test/fixtures/acceptance.json` and a ratchet that fails a lowered floor;
performance had prose in ADRs and a habit. The eager renderer chunk reached
**4.38 MB** without a gate noticing, and nothing measured app launch, map load
or filter latency at all.

The obvious reaction is to start ratcheting numbers. ADR 0021 already ruled on
why that ends badly, and `tree-coverage.ts`'s `valueMismatches` is the worked
example: a number with no right answer, held to a ceiling, becomes a backlog
that fires on changes that improved things.

## Decision

**Exactly one performance number is a gate, and it is a byte count.**

`scripts/perf/bundle-size.ts` holds `dist/assets` to ceilings in
`test/perf/ceilings.json`. They may only **fall** — the mirror of
`acceptance.json`'s "floors only rise" — enforced by reading the committed copy
with `git show HEAD:`, reusing `scripts/parity/acceptance.ts`'s comparison
rather than writing a second one, and with `?? Infinity` for the same reason
that file uses `?? 0`: deleting a ceiling is the cheapest way to raise one.

**Everything else that moves with the machine is printed, never asserted.**

The dividing line is not importance, it is *whose property the number is*:

- **A byte count is a property of the build.** The same `npm run build` produces
  the same bytes on any machine, so a ceiling on it fails only when somebody
  added weight. That is a defect every time.
- **A launch time is a property of the machine** — its disk, its antivirus,
  whether the profile is warm, what else is running. A ceiling on it fails for
  reasons that have nothing to do with the commit, which is how a gate becomes
  something people delete.

So `smoke.ts` prints time-to-document and time-to-first-painted-UI, and asserts
neither. `scripts/perf/profile.ts` prints self time by function and asserts
nothing at all.

## Two properties the gate needs, and both were nearly missed

**It must skip cleanly with no `dist/`.** CI runs `npm run check` *before*
`npm run build`, deliberately, so that every `dist/`-dependent script reports
SKIP rather than failing. A gate that fails because nothing was built teaches
people to ignore its output.

**`eager` and `total` are two numbers, not one.** `pdf.worker`, `exceljs` and
the maplibre worker are lazily fetched and land in `dist/assets` beside the
entry chunk. Ceilinged together, a lazy chunk growing looks identical to the
startup path growing — which is the one thing this exists to see.

## A measurement that silently measures something else is worse than none

Recorded because it happened during the work that produced this ADR, and it
produced a wrong conclusion that reached a commit message.

`smoke.ts` timed the first painted UI with `page.waitForFunction` given a
**string** predicate. Playwright builds that predicate with `eval` inside the
page; this app's production CSP is `script-src 'self' 'unsafe-inline'` with no
`'unsafe-eval'`, so it threw `EvalError` on the first poll. It was wrapped in
`.catch(() => {})`. The published number was Playwright retrying a forbidden
eval, not React mounting — and it read as a plausible ~215 ms above the document
time, which is exactly what a real mount would have cost.

On it rested the claim that removing 413 kB from the eager chunk changed launch
by **1 ms**, and the decision to abandon a 930 kB code split. Corrected — a
function predicate, injected over CDP, which the policy does not govern — the
real figure is **~32 ms for 413 kB**, against a same-build reproducibility of
2 ms.

Two rules come out of it:

- **No silent `catch` around a measurement.** A predicate that cannot run must
  fail the run rather than quietly publish a different number.
- **Establish the instrument's noise before trusting a delta.** Two runs of the
  *same* build agreeing to 2 ms is what made 32 ms believable; without that
  baseline it is indistinguishable from the ±4% `throughput.ts` already records.

## Amendment: "may only fall" had no way to record growth, and the check was inverted

Found the first time an ordinary feature added bytes - 619 of them, a
reverse-DNS queue and a selection anchor, against a chunk that had just fallen
by 1.51 MB.

The script's failure text already said what to do: "if the growth is intended,
lower nothing and raise this ceiling deliberately in its own commit with the
reason." **Its ratchet refused to allow that**, and worse, the condition was
inverted. `measured <= before || next <= before` passes whenever the build still
fits the *old* ceiling - so a ceiling could be inflated freely in advance, and
the one case it refused was recording growth that had already happened.

A raise is now allowed on exactly two conditions, both checked: the build really
outgrew the old ceiling, **and** the new ceiling equals this build's size. No
pre-emptive headroom, because a ceiling above the build is a budget nobody is
spending, which is how 4.38 MB arrived without a gate noticing. No raise past
the build, because a raise records growth rather than buying slack for the next
one.

Unbanked headroom - a ceiling sitting above the build after a drop nobody
recorded - is **printed, not asserted**, for this ADR's own reason: there is no
right number of bytes for it to be.

Verified in all four directions: a raise to exactly this build passes, a raise
past it fails, a raise while the build still fits fails, and a lowering passes.

## Consequences

- `test/perf/ceilings.json` joins `test/fixtures/acceptance.json` as a tracked
  file that only moves one way, and a commit that raises one has to say why.
- The suite grows by one gate and gains two printed numbers that nothing in this
  repository could previously see.
- `docs/verification.md` gains the packed-build GPU check, because the fuses
  make the packaged app undriveable by Playwright and that is the fuses working.
