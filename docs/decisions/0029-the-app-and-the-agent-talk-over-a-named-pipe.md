# 0029 — The app and the agent talk over a named pipe

**Status:** accepted. **Supersedes the authentication half of `0005`** — the
pairing token, the origin allowlist and the peer verification that was planned
to follow them. It does not replace them with anything. It deletes them.

> **One detail is amended by
> [0047](0047-windows-ships-the-rust-agent-signed-on-this-pc.md).** Below, this
> ADR says `hello` reports `authRequired: false`.
>
> - **Windows:** the agent's `hello` now carries no `authRequired` field at all.
>   No app reads the field, and the parser accepts a `hello` with or without it,
>   so sending it only kept the word on the wire.
> - **The check:** `scripts/agent/control-vectors.ts` holds the Rust agent to
>   sending no `auth*` key, in any message.
> - **The Python agent** still sends the field, for the macOS and Linux
>   WebSocket, where this ADR kept the token.

> **Also amended by
> [0068](0068-another-user-can-serve-the-agents-pipe.md).** The descriptor
> decides who may *connect*, not who may *serve*: the agent now refuses a pipe
> name it did not create, and another interactive user can still add an
> instance while it runs.

## Context

The agent listened on `ws://localhost:8999`. Everything defensive that grew
around it grew because a loopback TCP port is reachable by **every process on
the machine**:

- an **origin allowlist** checked during the WebSocket handshake, which `0005`
  itself described accurately — it "keeps an ordinary web page out and stops
  nothing that can set a header", which is any process on the machine;
- a **256-bit pairing token** in `%ProgramData%\Inwire\config.json`, compared
  with `hmac.compare_digest`, locked to SYSTEM and administrators with `icacls`,
  and **pasted into the app by hand** — because the browser could not read
  `%ProgramData%`, which was the entire point of putting it there;
- `authRequired` on `hello`, an `authenticate` command, `auth_required` and
  `auth_failed` error codes, `TOKEN_UNREADABLE` as a fail-closed sentinel, an
  `AgentPairingPanel`, and a localStorage key holding the token;
- and a further step that was designed and not built: verifying the *peer* by
  Authenticode thumbprint, to answer the part a bearer token cannot.

That last item is the tell. The token was never a good answer, and the planned
follow-on existed because everybody knew it: a secret stored in the app's own
storage is readable by any process running as that user, which is exactly the
attacker the token was introduced to stop. Three phases of scaffolding, each
defending the previous one, all of them defending a port.

The move to Electron removed the constraint that made the port necessary. A web
page can open a WebSocket and nothing else; a desktop process can open anything
the operating system offers.

## Decision

**On Windows the app reaches the agent over a named pipe, `\\.\pipe\inwire-agent`,
and the loopback port is not opened at all.**

The pipe is created by the agent with an explicit security descriptor:

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)
```

`D:P` is a protected DACL, so nothing is inherited. `SY` and `BA` are SYSTEM and
administrators. **`IU` — the interactive user — is the whole point**: the agent
runs as LocalSystem and the app deliberately does not, and the default DACL on a
pipe created by a LocalSystem service admits SYSTEM and administrators *only*,
so without that ACE the app could never connect to the service that exists to
serve it.

What is deliberately **absent** is as load-bearing as what is present. `WD`
(everyone), `AN` (anonymous) and `NU` (network) do not appear, because a named
pipe is reachable over SMB as `\\host\pipe\name` unless the descriptor says
otherwise. `PIPE_REJECT_REMOTE_CLIENTS` says the same thing a second time.

**So the pairing question is not answered for a pipe client — it is never
asked.** `hello` reports `authRequired: false`, there is no token to present and
nothing to paste. `register` reads a `kernel_authenticated` attribute off the
connection with `getattr`, so the agent needs no knowledge of which transport it
has and the WebSocket needs no counterpart.

### What this does not stop

An administrator, and code injected into the app's own process. Both were true
of the token too. What changed is the **enforcer**: the kernel decides, against
a descriptor set at creation, rather than the agent comparing a string that the
attacker we cared about could read as easily as we could.

### One transport, and the platform picks it

On Windows the port is not opened. Leaving it listening beside the pipe would
keep the entire attack surface the pipe exists to remove.

macOS and Linux **keep the WebSocket, and keep the token with it**. Those
platforms install from the tarball and have no bundled app yet, and a Unix
socket is not the same object with a different name: there is no
interactive-user SID to name, so who may open one comes down to a file mode, a
group, or reading the peer's credentials and having a policy about them. That is
worth designing rather than approximating, and until it is designed the honest
thing is to leave those platforms exactly as they were.

## What had to be built, and what did not

**The message protocol did not change.** Not one message in `agentProtocol.ts`
or `packet_batch.py` moved: the 18-byte record, every control message, and the
fixed byte vectors both ends assert are all transport-agnostic. That is what
made a named pipe a reasonable thing to do at all, and it is worth stating
plainly because it is the opposite of what a transport swap usually costs.

What the WebSocket supplied underneath the protocol was **framing** — message
boundaries and a text/binary distinction — and a pipe is a byte stream with
neither. So `services/agentFraming.ts` and its exact counterpart
`local-agent/pipe_frame.py`: a `u32` length, a `u8` kind, little-endian to match
`packet_batch.py`. Both ends refuse a declared length past `MAX_FRAME_BYTES`
**before allocating anything**, because the agent is a privileged service and a
five-byte header must never be able to ask for four gigabytes. The vectors are
written out by hand in `scripts/agent/pipe-framing.ts` and `test_protocol.py`,
following the rule `scripts/agent/binary.ts` established: a wire format with one
implementation of itself agrees with itself no matter what it does.

The kind byte is a byte rather than an inference from a leading `{`, so that a
malformed batch beginning with `0x7b` is a framing error and not a parse error.

## Where the connection lives, and what that inverts

The socket used to be in the pipeline Worker, **and not by preference**:
`is_origin_allowed` refuses a connection with no `Origin`, and only a renderer
sends one, so the socket could not have moved to the main process even had it
belonged there.

A named pipe inverts that exactly. It has no `Origin`, and **no renderer and no
Web Worker can open one at all** — `net.connect` is Node. So the handle moves to
main, which is where an OS resource belonged in the first place.

What must not move with it is the property `0007` bought: **the renderer's main
thread never sees a captured frame.** Main pumps the pipe into one end of a
`MessageChannelMain`; the renderer pulls the other end out of the preload and
transfers it straight into the Worker. It carries the port exactly once and then
plays no part. Main touches each batch as an opaque buffer — one copy per
~256 kB batch at ~30 batches a second, because `MessagePortMain`'s transfer list
accepts only ports and there is no zero-copy hop out of the main process.

Measured end to end against a real pipe: **4,000 batches of 64 kB — 262 MB — in
539 ms, or 487 MB/s.** A saturated gigabit adapter is 125 MB/s and this agent's
own stream is a 256 kB batch about thirty times a second, so the copy is not the
number worth optimising.

## The finding that only a live pipe could give

A handle created without `FILE_FLAG_OVERLAPPED` is a **synchronous** handle, and
Windows serialises every operation on one. The first implementation had a reader
thread and a writer thread on one such handle: the writer's `WriteFile` queued
behind the reader's blocked `ReadFile` and waited for bytes that were not
coming.

Driven against the real client, `hello` and the first reply arrived and
everything after them did not — writes landed only when one happened to fall in
the gap between the reader returning and blocking again. Which is the worst
possible shape a bug can take: it works on the handshake, which is what anyone
tests, and stops on the traffic, which is what the pipe is for.

Every operation now carries its own `OVERLAPPED` with its own event — its own,
not a shared one, because two concurrent operations signalling one event is the
same bug wearing a different hat. The waits are bounded rather than `INFINITE`
so that `stop()` is observed, instead of a thread pinned for the life of the
process by a client that never speaks again. The writer waits for each frame to
complete before starting the next, because two outstanding writes on one handle
have no defined order and a packet batch delivered out of order is a capture
that lies about the wire.

Threads rather than `loop.start_serving_pipe`, and that is also not a
preference: the proactor creates its pipe instances itself, with the creating
process's default DACL — which for a LocalSystem service is precisely the
descriptor that locks the app out. Passing our own descriptor means creating the
instances ourselves.

## Consequences

- **Existing users lose their pairing token and will not miss it.** There is no
  migration, because there is nothing to migrate to.
- **`config.json`'s token and `allowedOrigins` are inert on Windows.** They are
  still written by the installer and still read by the Unix path; removing them
  from the installer belongs with the unified installer, not here.
- **Findings 3, 5 and 6 of the migration plan dissolve rather than being
  fixed** — the stale `allowedOrigins` that would have 403'd `app://inwire` for
  every existing install, `{userappdata}` being the wrong user under an elevated
  installer, and `--init-config` printing `<token unreadable>` into a store that
  would then believe it had a token. All three were about provisioning a secret
  that no longer exists.
- **The CSP lost an entry rather than gaining one.** `scripts/electron/shell.ts`
  now asserts that `8999` does **not** appear in the packaged policy: a
  `connect-src` entry for a port nothing dials is a hole with no user.
- **The security descriptor is the one thing the assertions cannot reach.**
  `test_protocol.py` pins the SDDL's shape — `IU` present, `WD`/`AN`/`NU`
  absent, `D:P` — and `scripts/electron/agent-link.ts` drives the real client
  against a real pipe on Windows and a Unix socket elsewhere. Neither can tell
  you the descriptor **took effect**. That needs a machine with a second user
  account, so it is in `docs/verification.md` rather than in CI.
