# Accounts, backends, sharing services and telemetry

**Rejected:** a user account, cloud sync, a hosted sharing service for captures, crash or usage telemetry, or any server this repository would operate.

**Why:** Inwire is local and offline by default, as a product invariant (`CLAUDE.md` §10, `SCOPE.md`). The audience watches its own traffic; a packet analyzer whose requests show up in the user's capture is a trust problem specific to that audience. Monitoring data (flows, counters, speed-test results) is covered by the same rule: it stays on the machine unless the user exports it.

**Rests on:** ADR 0009 (facts that did not come off the wire need consent), `OUTBOUND_HOSTS` with a recorded purpose per host.

**If sharing is ever reconsidered:** `docs/ideas/sharing-threat-model.md` is the acceptance matrix it would have to pass. It is a wish list with a test plan, not a plan.
