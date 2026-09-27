# 0051 — The version is 0.x while Inwire is in development

**Status:** accepted 2026-09-28. **Amends [0035](0035-the-agent-lives-as-long-as-the-app.md)
§3**: the agent's version is still the product's, but the app compares it for
equality rather than order. **Retires the anti-reset floor** that
`scripts/agent/version.ts` and `local-agent/test_protocol.py` held at 3.9.0, and
[0030](0030-one-installer-two-destinations.md)'s "it only ever climbs".

## Context

The owner: *inwire is still in dev so the version should be 0.xx.* The product
read 4.1.0, and the number could not go down, for a reason 0035 recorded.
`isAgentOutdated` ordered the agent's number against
`REQUIRED_AGENT_VERSION`. An agent from a higher-numbered build read as *newer than required*,
and newer passed. So unifying the app's number (1.0.0) with the agent's (3.9.0)
had to move the product up to 4.0.0. Two checks then held a floor under it.

The ordering was answering the wrong question. One installer puts the app and
the agent down together (0030), so the only agent the app can trust is the one
built with it. An agent reporting a different number came from a different
install, whichever way the number moved. A newer one is no easier to talk to
than an older one: 4.0.0 sends version 2 wire records, which a 4.1.0 app
refuses.

## Decision

**The product is 0.4.1.** The version is 0.x until Inwire is released. The
4.1 is kept in the minor and patch, so the order of what was built stays
readable.

**The app compares for equality.** `isAgentMismatched` replaces
`isAgentOutdated`: any agent whose number is not this build's is shown as
"outdated", and the fix is the Inwire installer. The comparison is segment by
segment as numbers, so "0.4.01" is "0.4.1" and "0.10.0" is not "0.1.0". Both
floors are deleted, since nothing orders the number any more.

**The installer still orders, and the reset trips it once.** `InitializeSetup`
refuses to install over a newer Inwire. That is right: an older installer over
a newer install leaves a directory of mixed vintages that the older uninstaller
does not know about (0030). So a machine with 4.x installed uninstalls it once,
and the 0.x installer then goes on as a fresh install. There is one such
machine, this one. A permanent exception in `InitializeSetup` for the
pre-reset numbers would be code carried forever to save one uninstall.

## Consequences

- The Update Center's dev feed and `update-center-drive.ts` declare
  `minAppVersion` `0.0.0`. At `1.0.0`, a 0.x app would read Npcap's row as
  "needs a newer Inwire".
- An uninstall keeps captures, settings and the key-log path. It removes the
  program files, the service and the agent's log (`[UninstallDelete]`).
- The frozen legacy installer's stamps (3.9.0 and 1.0.0) are unaffected. They
  record what an agent-only install put on a machine, not an ordering.
- Leaving 0.x is a decision for release, and it wants its own ADR.
