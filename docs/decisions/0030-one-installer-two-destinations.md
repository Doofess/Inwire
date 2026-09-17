# 0030 — One installer, two destinations, and the app never elevates

> **Its Npcap paragraph is void, corrected by**
> **[0032](0032-the-update-center.md).** The installer does not install Npcap and
> must not: the silent flag is Npcap's OEM feature and the free licence does not
> grant it, so the driver is a prerequisite the Update Center manages behind a
> UAC prompt and Npcap's own wizard. Everything else here - one installer, two
> destinations, the app never elevates - stands.

**Status:** accepted for the mechanics; **signing and updates are deliberately
unfinished** and are not decided here. **Extends `0027`**; depends on `0029`
for why the service and the app can be different principals at all.

## Context

Before this there were two installers. The product was a web page, so there was
nothing to install but the agent: `local-agent/installer/setup.iss` registered
`InwireAgent` as a LocalSystem service, minted a pairing token, wrote
`config.json` under `%ProgramData%` and printed the token on its finish page
for the user to paste into a browser tab.

`0027` made the app a thing that has to be installed, and `0029` deleted the
token. What is left is one product with two parts that want different
treatment: a Chromium application that must never run elevated, and a
kernel-adjacent capture service that must.

## Decision

**One Inno Setup installer, at the repository root, under its own AppId, laying
down two trees:**

```
{app}\          the Electron application
{app}\agent\    the PyInstaller agent, registered as the InwireAgent service
```

Both under `{autopf}\Inwire`. The installer is elevated because registering a
service requires it. **The application it installs never is.**

It also uninstalls the standalone agent. That installer's AppId is named in
this one as a constant it deliberately does **not** share, because the two
register a service by the same name and two auto-starting copies fighting over
one adapter is not a state worth having.

## Why the agent is beside the app and not inside it

`{app}\agent\` is a sibling of the application payload, not a subdirectory of
it, and the reason is updates rather than tidiness: an application update
rewrites the payload, and a running service holds its own executable open. A
binary that is both "the thing being replaced" and "the thing holding a lock"
makes every update a stop-and-restart with a failure mode in the middle.

The agent is `--onedir`, which is a decision the agent's own documentation
argues and this one only depends on: a `--onefile` build extracts unsigned DLLs
to `%TEMP%\_MEI<random>` and executes them, which Defender's prevalence ASR
rule blocks outright, and which pays the extraction cost at every service start
on a service that starts at boot.

## The elevation boundary, and the one place it is crossed

The app runs as the user. The service runs as LocalSystem. An unelevated
process cannot start, stop or configure a service it does not have rights to,
and the default rights on a LocalSystem service admit administrators only —
which would leave the app unable to do anything about an agent that is
installed but stopped, the single most likely thing to go wrong.

So the installer, which is already elevated, grants what the app needs and
nothing more:

```
sc sdset InwireAgent ... (A;;CCLCSWRPLOCRRC;;;IU)
```

`IU` again, the same principal `0029`'s pipe descriptor names. The rights are
enumerated rather than taken wholesale: query, enumerate dependents, **start**,
interrogate, read the descriptor. **`WP` — stop — is withheld.** The app has no
business stopping a capture service it does not own, and `restart_agent` already
exists over the pipe for the case where it needs the agent to cycle.

The fallback when that grant is absent — an older install, a machine where the
descriptor was changed — is a UAC prompt through
`Start-Process -Verb RunAs`, built from constant arguments so there is nothing
in it a caller could influence.

## What the installer has to get right that a first draft did not

Recorded because each is a silent failure rather than an error message.

**Stopping the service before replacing it.** `sc stop` returns immediately;
the service stops when it stops. `WaitForServiceStopped` polls, and reads exit
codes **1062** (not started) and **1060** (no such service) as success, because
those are the two ways "it is not running" arrives and both are
locale-independent where the message text is not.

**Closing the app before replacing it.** `CloseApplications=yes` uses the
Restart Manager, which asks the window to close rather than killing it — which
matters for a program holding a capture, because the quit guard is what gets to
ask the user about it.

**Refusing a downgrade.** Windows compares `MyAppVersion` to decide whether an
install is an upgrade; installing an older build over a newer one leaves a
directory of mixed vintages. `CompareVersions` in `InitializeSetup` refuses it.

**Npcap, and an elevated download with a hash.** The driver is fetched at
install time and its SHA-256 is pinned in the script. An elevated installer
that downloads an executable and runs it without checking what arrived is the
same class of mistake as everything `0029` deleted.

## Two version numbers, because one installer now carries two products

`AGENT_VERSION` is a **wire-protocol version and an ordering** — the left-hand
side of `isAgentOutdated` — so it only ever climbs. Resetting it makes an agent
left behind by an earlier install read as newer than required, which surfaces
as "not connected" rather than "update your agent". Three places hold it and
`test_protocol.py` refuses a reset.

`MyAppVersion` is the **product**, locked to `package.json`, and is what
Windows compares. The two stopped moving together the moment one installer
carried both: a UI release ships an installer and no new agent at all.

## What is not decided here

**Signing.** The installer compiles and is unsigned. Everything about the
Electron fuses is downstream of that — flipping `runAsNode` and friends mutates
the executable, so it must happen before a signature and there is no point
doing it before there is one. Both wait.

**Updates.** electron-updater cannot drive an Inno installer, so the update
path is hand-rolled by construction: a signed feed, `net.fetch`, verify
Authenticode, run `/VERYSILENT /CLOSEAPPLICATIONS`, quit. None of it exists,
and the question it turns on — whether every update raises a UAC prompt, and
what a second privileged component would cost to avoid that — is open.

Recording those as undecided is the point of writing this now rather than
later: the mechanics above are settled and being built on, and pretending the
rest is settled too would make this ADR wrong in a year.

## Consequences

- `0012`'s "a capture is deleted only when the user asks" gains a third door:
  uninstall. The installer removes what it installed and leaves
  `%LOCALAPPDATA%\Inwire\captures` alone, which is the only answer consistent
  with `0025` Decision 3.
- Nothing per-user is provisioned any more, which retires a trap:
  `{userappdata}` in an elevated Inno installer is the account that answered
  the UAC prompt, or `systemprofile` under Intune — and it is the *roaming*
  profile, so a machine-specific secret would replicate to a file server.
  `0029` deleted the secret; this removes the last reason to write there.
- The clean-VM matrix — a fresh machine, one with the 3.7.0 agent, a second
  Windows user, a SYSTEM-context silent install — remains unrun, and the SDDL
  grant above is the item on it that most needs a second account to verify.
  `test_protocol.py` pins the descriptor's shape; nothing yet proves it took
  effect.
