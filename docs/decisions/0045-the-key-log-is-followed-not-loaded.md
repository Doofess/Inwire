# 0045 — The key log is followed, not loaded, and the choice is remembered

**Status:** accepted. **Amends [0008](0008-key-material.md)** on one point, stated
below; everything else in 0008 stands.

## Context

Live decryption did not work, reported from a real session: a key log loaded,
`SSLKEYLOGFILE` set at User scope, a capture started - and every QUIC packet
still read `Protected Payload (KP0)` with nothing after it.

**The decryptor was not the problem.** The key log came in through
`<input type="file">` and `file.text()`: one snapshot, taken at the click. A key
log is not a document, it is a journal - the browser appends a connection's
secrets the moment it derives them, for as long as it runs. The one on the
machine this was found on was **17,084 lines and had been written a minute
before it was measured**. So a snapshot taken before a capture holds no secret
for any connection the capture sees, which looks exactly like decryption being
broken.

The fixtures never showed it: a key log handed to an import is complete before
the import starts. And the person was asked to load the file again on every
launch, because nothing remembered it.

## Decision

**Main follows the file.** `electron/keyLogFollower.ts` reads it from the top
when a renderer attaches, then reads what is appended - a 25 ms poll, which is
the only thing that sees a browser's writes (see **The race**), and `fs.watch`
for a writer that opens and closes the file per line. Complete lines go to the
renderer as text, which feeds both key stores exactly as the file picker did
(the Worker's, which live capture decrypts with, and the main thread's, which
imports use). The arithmetic - where to read from, what a shrunken file means,
where a line ends when a read stops mid-line - is `electron/keyLogTail.ts`,
under plain `tsx`.

**The path is remembered** in `keylog.json` under userData, and following
resumes at launch with nobody clicking anything.

**`SSLKEYLOGFILE` is offered by name.** Main's environment is the user's, so the
panel can say "Follow SSLKEYLOGFILE" with the path it names, and the open dialog
starts there.

"Load a file once" stays, for the case it was right for: a static key log that
belongs to an imported capture.

## The security half, which is most of the design

**The renderer never names a file.** It can ask main to follow one picked in
main's own native dialog, or the one main's own `SSLKEYLOGFILE` names, and
nothing else. No IPC handler reads an argument and no preload method takes one.
A renderer that could name a path would be a renderer that could read any file
on this machine, and this renderer parses hostile bytes for a living.
`scripts/electron/keylog-follow.ts` holds that as source text - checked by
giving one handler a path argument and one preload method a parameter, which
fails two assertions.

**What is written to disk is a path, never a secret.** The secrets are already
on disk, in the browser's own file; the app adds a pointer to it and nothing
else. The same script holds the follower to exactly one `writeFileSync`, of
`{ path }`.

## What this amends in 0008

0008's position was that key material enters memory only by an explicit action
in that session. **It now enters at launch**, because the person chose to follow
a file and that choice is remembered until they stop it. That is the amendment,
and it is deliberate: a key log that has to be re-chosen on every launch is the
friction that produced the report above.

Everything else in 0008 holds. Key material is still memory-only in this
process, still never written to a preference or a stored session, still out of
an export unless its switch is turned on. `crashReporter` stays off for 0008's
reason, which this makes stronger rather than weaker: a renderer minidump would
now be a copy of every secret streamed since launch.

## Two defects found on the way, both fixed here

- **Clear did not clear the copy that decrypts.** Settings -> Decryption ->
  Clear emptied the main thread's store and said "new ones will not be
  decrypted", while the pipeline Worker - which does every live decryption -
  kept every secret. There was no message for it. There is now, and it drops the
  Worker's cached trees too, the other place a decrypted payload lives. Clear
  also stops following, or the next line the browser wrote would start
  decrypting again under a panel that had just said it would not.
- **`keyLog.add` was written for a file loaded once.** It counted and stored
  every line every time, so loading a file twice doubled the count and the lines
  an export writes back - and the panel's "added no new secrets" could never be
  shown. And it bumped `generation` on every call, which tells every live TLS and
  QUIC conversation to re-derive its keys. Fed every append, both matter: a
  line already held is skipped now, and the generation moves only when something
  was learned. `scripts/tls/key-log.ts`, checked with the old `add` put back.

## The race, and what is and is not measured

A secret has to reach the Worker before the packets it opens are dissected. The
slack is the Worker's 100 ms ordering window, plus however long the agent holds
a batch.

**The first measurement of the follower's side was wrong, and it shipped.**
`smoke.ts` appended with `appendFileSync` and timed **3-11 ms** into the
Decryption panel. That was timing `fs.watch`, which a browser never triggers:
Chrome appends through a handle it holds open, and on Windows such a write
raises no change notification - **0 events for 10 appends held open, against 10
at 0.4 ms opened and closed each time.** Every real browser was seen by the
one-second poll alone.

**Found on a real capture, not by a driver.** A 3-minute live capture taken
while following Chrome's key log had **180 of 326** protected QUIC packets
opaque, and the pattern per connection was always the same: the first ~65-150
ms of 1-RTT packets opaque, everything after decrypted. Re-dissected offline
from the stored bytes with the same key log, **all 180 decrypt** - so the
handshakes were captured, the keys were right, and they arrived late. That is
this section's race, lost by ~900 ms to the poll interval rather than to the
browser.

**Fixed by polling at 25 ms** (`POLL_MS` in `keyLogTail.ts`). An idle check is an
open, an `fstat` and a close - **21 µs** measured - so forty a second is under a
thousandth of a core. The status push that ran on every check now runs only
when something changed. `smoke.ts` now writes through a held-open handle, the
way a browser does: **901-963 ms** into the panel on the old build, **11-39 ms**
on the new, three and five runs, printed rather than asserted (ADR 0041).
`keylog-follow.ts` holds the poll to at most half of `ORDERING_HOLD_MS`.

**And then measured end to end, live, once, with the owner's say-so.** A
one-off driver (not committed: it captures a real adapter, which
`agent-live-drive.ts` records drivers here do not do unasked) launched the app
following a throwaway key log, captured the real Ethernet adapter, and ran a
headless Chrome writing that key log across seven HTTP/3 pages; the stored
capture was then put through `scripts/tls/replay-stored-capture.ts`. Same
script, same pages, the poll the only difference:

| poll | protected QUIC | opaque live | opaque on replay | **lost to timing** |
|---|---|---|---|---|
| 1,000 ms | 9,977 | 7,754 | 51 | **7,703 (77%)** |
| 25 ms | 10,576 | 182 | 182 | **0** |

The residual opaque packets are whole connections from other software on the
machine, whose secrets were never in the throwaway log - opaque on replay too,
so not the race. That also answers what this section left open: **the
browser's own flush latency is inside the window** - with the follower fixed,
nothing was lost. The replay script is the instrument to run if early packets
on a connection ever stay opaque while later ones decrypt.

**What success looks like, because it is easy to misread**: a decrypted QUIC
packet's Info still *begins* `Protected Payload (KP0)` - that is the packet type,
and the reference analyzer writes it the same way. Decrypted, it continues with
`PKN: <n>` and the frames inside (`STREAM`, `ACK`, ...), and the tree gains the
decrypted frames and the HTTP/3 above them.

## Consequences

- `smoke.ts` seeds a remembered path into its profile before launch and requires
  it to be followed with its line loaded, then appends two lines and requires
  them to arrive - each half checked by breaking it.
- A key log only grows (`SSLKEYLOGFILE` is never rotated by the browser), so the
  first read after a launch is the whole file - 2.8 MB here - sent in reads of
  at most 1 MB so no single message is unbounded.
- Packets dissected before their secret arrived stay opaque in the list, as
  every frame dissected before a key log load always has. When opened, a frame
  older than the Worker's 4,000-tree cache is rebuilt by replay with the keys
  held *now*, so its tree decrypts. **A recent one does not**: its cached eager
  tree is the opaque one, until it ages out. Dropping the cache whenever a
  secret arrives would fix that and would also turn nearly every click during a
  followed capture into a replay - the thing the cache exists to avoid - so it
  is not done until a real capture shows early packets losing the race at all.
