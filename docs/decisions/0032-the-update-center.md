# 0032 — Npcap is a prerequisite the app manages, not a payload the installer ships

**Status:** accepted. **Corrects `0030`'s Npcap paragraph**, which is void: the
installer no longer downloads or installs the driver. **Fills in the "Updates"
half of `0030`'s "What is not decided here"** — the pipeline exists; the feed
and the signature do not.

## Context

`0030` decided that Npcap is fetched at install time rather than bundled, and
gave the right reason: the free licence forbids redistribution, and downloading
on the user's own machine is not redistribution. That much still holds.

What it did not examine is the *other* half of the same licence. The installer
ran the driver with `/S`, and `/S` is Npcap's **OEM silent-install feature**. So
the arrangement avoided redistribution and then used a commercial feature of
the free product to install it silently — which is the thing the OEM licence is
sold for.

Three further problems, none of them about licensing:

- **The pin was a compile-time constant.** `#define NpcapUrl` named 1.79 while
  1.88 was current, and correcting it meant shipping a new installer. The
  constant's own comment had already written the fix: *"the URL will eventually
  404 as Npcap ages releases out, and the fix for that is a version+hash pair
  served from a feed we control rather than a literal here."*
- **`[Run]` ignores exit codes.** A failed driver install produced a
  "successful" product install with no capture capability and nothing on
  screen — the same class of failure the file's own comment moves service
  registration out of `[Run]` to avoid, three lines below.
- **The app could not describe the resulting state.** `agentHealth` has seven
  states and none of them is about a driver, because `diagnoseAgent`
  short-circuits on `status === 'connected'` and a driverless agent *is*
  connected: it answers, it is healthy, and it has nothing to listen on. The
  entire user-facing signal was a hover tooltip on a header button.

And the app was about to need a download-and-verify pipeline anyway, for
itself. `0030` deferred that as "a signed feed, `net.fetch`, verify
Authenticode, run `/VERYSILENT`, quit — **none of it exists**."

## Decision

**One Update Center, in Settings, listing every updatable component — and
Npcap moves out of the installer into it.**

A component is `{ id, displayName, installed, available, state }`; detection
and the update decision are pure functions over that. Every row runs the same
path: **detect → fetch → verify → elevate → re-detect**. The only per-component
differences are the installer's arguments and whether it is awaited.

## Npcap's version is the trap, three times over

Recorded at length because all three produce a confident wrong answer rather
than an error, and because the first one would have broken the feature in the
exact case it exists to handle.

**`wpcap.dll` does not carry Npcap's version.** Measured on a machine running
Npcap 1.88:

| File | ProductName | Version |
|---|---|---|
| `System32\Npcap\wpcap.dll` | **libpcap** | **1.10.6** |
| `System32\Npcap\Packet.dll` | Npcap | 1.88 |
| `System32\drivers\npcap.sys` | Npcap | 1.88 |

`wpcap.dll` reports the libpcap API version it implements. Compare that against
a feed advertising 1.88 and the row says "update available" **for ever** —
including immediately after a successful install, which is the worst available
failure for a row whose only job is to say whether you are current.

**Npcap registers in the 32-bit view only.** Its installer is 32-bit, so
`NpcapInst` lands under `WOW6432Node`. A plain `reg query` of the 64-bit view
exits **1 with empty stdout**, which is precisely the shape `agentService.ts`'s
`provesAbsent` reads as *proof of absence*. Reusing that helper unchanged
reports "Npcap is not installed" on a machine where it is installed and the
driver is RUNNING.

**`HKLM\SOFTWARE\Npcap` holds no version**, and on a 64-bit machine does not
exist at all. The installer's `IsNpcapInstalled` got away with three presence
probes because it only ever asked "any Npcap?". So `installed` and `version`
are **two answers, not one**: a driver present with an unreadable version says
so rather than being rounded to either.

## The command line is a constant, and the path is not on it

`agentPipe.ts` states the invariant: *"The arguments are constants. Nothing the
renderer sends reaches this command line, because a privileged command built
from a message is a privileged command an injected script can write."*

An updater must name a downloaded file, which looks like it has to break that.
It does not. The PowerShell script is fixed, encoded once as base64 UTF-16LE
and passed to `-EncodedCommand`, so the argument vector is **identical on every
call**. The file path travels in the child process's environment and is read
back from `$env:`. Nothing interpolates, nothing is quoted, and a path
containing a space or a quote cannot become a second argument because it never
passes through an argument parser.

The alternative — interpolating a quoted path into `-Command` — fails by
running a different file, elevated. That is not a bug a reviewer catches by
reading.

**Elevation is main's, and could not be anywhere else.** The renderer has no
rights and no `child_process`, and must never have either. The agent is already
LocalSystem and could spawn anything, which is exactly why it must not: it runs
in **session 0**, which has no visible desktop, so an installer wizard launched
from there draws where nobody can see it and blocks for ever on a click that
cannot happen.

**A declined UAC prompt is a normal outcome.** `Start-Process -Verb RunAs`
reports it by *throwing*, and the message is localised, so the result comes
back as one machine-readable marker line — the same reasoning that makes
`agentService.ts` prefer `reg` over `sc query`. The row returns to what it was
and shows nothing: somebody thought better of it, which is the prompt working.

## Awaiting our own installer deadlocks

`setup.iss` sets `CloseApplications=yes`, so Inno uses the Restart Manager to
ask Inwire to exit before replacing the payload. Blocked in `-Wait`, the
installer waits for us and we wait for the installer. Nothing is on screen; the
app simply stops.

So there are two scripts. Npcap does not close us and is awaited normally; our
own installer is **launched and not awaited**, and the app quits behind it. The
cost is that its exit code is unobservable — the installer outlives the process
that would read it — and that is the right trade against a hang.

## The feed, and how little it is trusted

One JSON document, and it is the only remote input in this repository that can
nominate an executable to be **run elevated**. So it is validated strictly and
**rejected whole**, which is the opposite of how preferences are read:
`interfacePrefs.ts` clamps field by field because a bad preference costs a
wrong colour, and here a defaulted field could mean "download this URL with no
hash".

The hash is not the interesting defence. Whoever controls the feed writes the
hash too, so what stops a compromised feed nominating an arbitrary binary is
the **download-host allowlist**: Npcap comes from npcap.com, and our own
artifacts from the host the feed itself was served from. Matched exactly, never
by suffix — `endsWith('npcap.com')` also accepts `evilnpcap.com`.

**Unreachable is quiet.** No dialog, no error state, one info line. Nothing is
cleared and "last checked" does not move. This is the ordinary case on a
machine that is offline, and an offline packet analyzer is a supported way to
run this app; anything louder trains somebody to dismiss a box every launch. A
*malformed* feed takes the identical path, because a document we cannot read is
one we have no answer from, and rendering that as "no updates available" would
be a confident lie.

## The check is opt-in, and that is the product invariant rather than a default

`CLAUDE.md`'s standing direction is "no outbound connection the user did not
ask for", and it is sharper here than in most applications: a request Inwire
makes unbidden appears **in the user's own capture**, on the screen they are
already looking at.

So the automatic check is off, `asked` is a separate field from `automatic`
because "no" and "not yet asked" are different states, and unreadable storage
defaults both to off.

**The feed host is deliberately NOT in `connect-src`.** `net.fetch` in main is
not a page and no CSP governs it, so the entry would grant the renderer
permission to reach a host it never dials — the same "hole with no user" that
`csp.ts` refuses for port 8999. What is kept is the *list*:
`MAIN_OUTBOUND_HOSTS` records both hosts with their purposes, and
`scripts/electron/shell.ts` asserts they are absent from the policy, that the
recorded feed host matches the one the updater dials, and that the recorded
Npcap host is the one the allowlist admits.

## Consequences

- **`0030`'s "Npcap, and an elevated download with a hash" is void.** The
  installer no longer downloads, hashes or installs the driver, and the SHA256
  constant it argued for is deleted. Its uninstall promise stands and is now
  written into both `.iss` files: Npcap is left alone, because other tools on
  the machine may be using it.
- The legacy `local-agent/installer/setup.iss` lost the same block, where it
  was worse — the same `/S` with `''` as the expected hash, meaning no
  integrity check at all on an elevated download.
- **`0030`'s open UAC question is answered for Npcap and still open for us.**
  Every Npcap install raises exactly one prompt, which is unavoidable and
  correct for a kernel driver. Whether *application* updates should raise one
  per update, and what a second privileged component would cost to avoid it,
  is untouched.
- **The Inwire row cannot be exercised yet.** There is no feed host and no
  signature, so `UPDATE_FEED_URL` ships as an RFC 2606 `.invalid` placeholder
  that cannot resolve, and the row reads "Not checked". The Npcap row works
  today against a local feed.
- **A sha256 is not a signature.** It proves the bytes are the ones the feed
  named; it says nothing about the feed being honest, and nothing about the
  publisher. Authenticode verification is owed and not built. Written down
  because a hash check next to a UAC prompt looks like more assurance than it
  is — as does the freshly-created random temp directory, which stops a file
  being *pre-planted* at the path and cannot stop the same user swapping it
  afterwards, since that user can already rewrite the app's own payload.
- `agentHealth` still cannot express "driver missing", and that stays true: it
  is a *link* diagnosis and the link is fine. `DriverInfoPanel` describes the
  state directly instead, from the two facts it already has — connected, and no
  interfaces — and links to the tab that fixes it.
