# The Update Center

Moved out of the root `CLAUDE.md` so it loads when you work in this directory
rather than in every session. *The only place this app updates anything.* ADR 0032.
## The Update Center

*The only place this app updates anything.* ADR 0032.

One Settings section (`Settings → Updates`) listing every updatable component:
the app, the capture agent, the Npcap driver, and two databases that are
declared and have no consumer yet. `electron/updateCenter/` is the pipeline,
`src/services/updateCenter.ts` is what the renderer accepts and calls things,
`UpdateCenterPanel.tsx` arranges it and decides nothing.

**The installer no longer installs Npcap.** It used to, with `/S` — Npcap's
**OEM silent-install feature**, which the free licence does not grant. Two other
things were wrong with it and are worth knowing before anyone proposes moving
driver installs back into Inno: the version pin was a compile-time `#define`, so
correcting it meant shipping a new installer, and `[Run]` ignores exit codes, so
a failed driver install produced a "successful" product install with no capture
capability and nothing on screen.

### The pipeline

```
detect  → the installed version (registry / hello / app.getVersion)
fetch   → net.fetch, in MAIN, streamed to a fresh random temp directory
verify  → sha256, and the size must match exactly
elevate → powershell -EncodedCommand <constant>, path in the environment
confirm → re-read the installed version; the row proves itself
notify  → for Npcap: cycle the agent link so interfaces re-enumerate
```

The fetch is in main because **the renderer must never learn the path** — the
path is what gets run elevated. It also gets Chromium's network stack, so a
proxy works without this code knowing what a proxy is.

Elevation could not live anywhere else either. The renderer has no rights; the
agent is LocalSystem but runs in **session 0, which has no visible desktop**, so
an installer wizard launched from there draws where nobody can see it and blocks
for ever on a click that cannot happen.

### Three things about Npcap that are all traps

Each produces a confident wrong answer rather than an error.

| Source | ProductName | Version on a machine running Npcap 1.88 |
|---|---|---|
| `System32\Npcap\wpcap.dll` | **libpcap** | **1.10.6** |
| `System32\Npcap\Packet.dll` | Npcap | 1.88 |
| `Uninstall\NpcapInst\DisplayVersion` | — | 1.88 |

**Nothing reads `wpcap.dll`.** It carries the libpcap API version it
implements. Compared against a feed advertising 1.88 it says "update available"
for ever — including immediately after a successful install.

**`/reg:32` is asked first.** Npcap's installer is 32-bit, so `NpcapInst` lands
under `WOW6432Node`, and a plain `reg query` of the 64-bit view exits **1 with
empty stdout** — exactly the shape `agentService.ts`'s `provesAbsent` reads as
*proof of absence*. That helper reused unchanged reports "not installed" on a
machine where the driver is running.

**`installed` and `version` are two answers.** `HKLM\SOFTWARE\Npcap` holds no
version and on x64 does not exist at all, so a driver present with an
unreadable version says so rather than being rounded to either.

### The elevated command line is a constant

`ELEVATE_ARGV` is the same array on every call — a fixed base64 blob — and the
installer path travels in the child's **environment**, read back from `$env:`.
Nothing interpolates and nothing is quoted, so a path with a space cannot become
two arguments. That keeps `agentPipe.ts`'s invariant literally: *"the arguments
are constants."* The failure mode of the alternative is not a crash; it is
running a different file, elevated.

`Start-Process -Verb RunAs` reports a **declined UAC prompt by throwing**, and
its message is localised, so the result comes back as one machine-readable
marker line on stdout — same reasoning as `reg` over `sc query`. A decline is
`cancelled`, never `failed`: the row goes back to what it was and shows nothing.

**Awaiting our own installer deadlocks.** `setup.iss` sets
`CloseApplications=yes`, so Inno asks Inwire to exit before replacing the
payload; blocked in `-Wait`, each waits for the other and nothing is on screen.
So there are two scripts — `ELEVATE_ARGV` waits, `LAUNCH_ARGV` does not — and
`awaitsInstaller(kind)` is the single predicate that chooses, so a third caller
cannot reintroduce it. Our installer's exit code is unobservable as a result,
which is the right trade against a hang.

### The driver's access mode, which is the fourth trap

Npcap's installer has a checkbox — *"Restrict Npcap driver's access to
Administrators only"* — and it is **not ticked by default**. Unticked, the
capture devices are open to `WD`; measured here, `\\.\NPCAP` carries
`D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;WD)`, so any local account can read
this machine's traffic and inject raw frames. Inwire captures through the
agent, so the restriction costs its users nothing and is what the Npcap row
recommends. ADR 0033.

**Two facts answer it and they can disagree.** `AdminOnly` under
`HKLM\SOFTWARE\Npcap` is what the installer *recorded* — 32-bit view first,
same two traps as the version read, `electron/updateCenter/npcapAdminOnly.ts`.
The DACL on the device object is what the kernel *enforces*, read by the agent
because it is the SYSTEM process, and carried in `hello` as `npcapAccess`. The
**DACL wins**: the registry can be edited without the driver being restarted,
and "administrators only" over a device still granting `WD` is the one
direction a wrong answer must not go.

The agent sends the **SDDL string and not a verdict**, the same rule ADR 0010
sets for frames. `src/services/npcapAccess.ts` decides, and
`scripts/electron/update-center.ts` holds that decision to captured registry
output and captured descriptors — including `D:NO_ACCESS_CONTROL`, which is a
NULL DACL and therefore the *most* open answer while containing no ACEs at all.

`unknown` is a third answer and never rounded to either, and it carries no
recommendation: advising a kernel-driver reinstall on the strength of having
failed to read anything would be advice about a state nobody established.

**Changing the mode is a reinstall**, so the row grows a second button —
`canReinstall`, which is `up-to-date` only and therefore mutually exclusive
with `canApply`. It runs the identical download → verify → elevate path and
names the checkbox in the notice above it, because ticking it is the one step
Inwire cannot do: the alternative is a flag, and the flag is `/S`.

### After Npcap installs, the link is cycled

`AgentPipeLink.recycle()` — not `refresh_adapters`. That command re-reads
adapter *configuration* and never touches `AVAILABLE_INTERFACES`, the
capture-interface list the picker is built from, **and is itself filtered by
that stale list**, so a brand-new adapter is excluded from its own snapshot. The
agent re-reads the list in `register()`, once per client connection, so a
reconnect is what re-enumerates. Preferred over `restart_agent`, which also
works but kills a service the app deliberately has no rights to stop.

### The feed

One JSON document at `UPDATE_FEED_URL` —
`https://updates.inwire.app/manifest.json`, overridable by
`INWIRE_UPDATE_FEED` in dev. **The domain does not resolve yet** — it is not
registered — so every check is a quiet no-op until it does, which is the same
path an offline machine takes.

**Development does not take that path.** `npm run dev` and `npm run start:app`
stand up `electron/devFeed.cjs` on a loopback port and point
`INWIRE_UPDATE_FEED` at it, so a launch reaches a feed that answers instead of
printing `net::ERR_NAME_NOT_RESOLVED` on every run — the shape that teaches
somebody to stop reading their own log. An `INWIRE_UPDATE_FEED` already in the
environment wins and no server is started.

Its default manifest **offers nothing, and that is a constraint rather than a
choice**: `DOWNLOAD_HOSTS` is `null` for `inwire`, `agent`, `oui` and `geoip`,
meaning "the host the feed came from", and `hostOf` returns null for anything
that is not https. A loopback feed is http, so those four rows can never
validate there — and one malformed row for a known id rejects the *whole*
document, which would trade `not reachable` for `could not be read`. Npcap is
the exception, because its allowlist names npcap.com outright, so
`--npcap <version>` is the one row that can be served.

It is the only remote input in this repository that can nominate an executable
to be run elevated, so it is validated strictly and **rejected whole** — the
opposite of how preferences are read, because a defaulted field here could mean
"download this URL with no hash".

The hash is not the interesting defence: whoever controls the feed writes the
hash too. What stops a compromised feed nominating an arbitrary binary is the
**download-host allowlist** — Npcap from npcap.com, our own artifacts from the
host the feed came from — matched **exactly**, never by suffix, because
`endsWith('npcap.com')` also accepts `evilnpcap.com`.

**Unreachable is quiet**: no dialog, one info line, nothing cleared, and "last
checked" does not move. A *malformed* feed takes the identical path, because a
document we cannot read is one we have no answer from, and rendering that as
"no updates available" would be a confident lie.

**The check is opt-in and off by default**, which is the product invariant
rather than a cautious default: a request Inwire makes unbidden appears in the
user's own capture. `inwire.updates` keeps `asked` separate from `automatic`,
because "no" and "not yet asked" are different and collapsing them turns a
one-time prompt into a recurring one.

### What it does not prove

A sha256 says the bytes are the ones the feed named. It says nothing about the
feed being honest and nothing about the publisher — **Authenticode verification
is owed and not built**. The freshly-created random temp directory stops a file
being *pre-planted* at the path and cannot stop the same user swapping it
afterwards, since that user can already rewrite the app's own payload. Both are
written down because a hash check next to a UAC prompt looks like more assurance
than it is.

The **Inwire row cannot be exercised yet**: there is no feed host, and the
build is signed only with a certificate this PC trusts (ADR 0047), so the row
reads "Not checked". Verifying a signature here would have to wait for a
publicly trusted certificate anyway, because a check pinned to this one would
pass on this PC and nowhere else. The Npcap row works today.

### "Driver missing" is not a link diagnosis

`agentHealth` cannot express it, because `diagnoseAgent` short-circuits on
`status === 'connected'` and a driverless agent **is** connected — it answers,
it is healthy, it has nothing to listen on. `DriverInfoPanel` (the Capture
Health tab) describes that directly from the two facts it already has, and links
to the tab that fixes it. That tab is also the app's only full account of frames
it lost, which has no other home: four figures do not fit a 24px strip. ADR 0035.

