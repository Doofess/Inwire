# 0026 — One capture on disk, and no launch prompt

**Status:** accepted. Closes the question `0025` §4 left open.

## Context

ADR 0025 moved the capture to OPFS and kept the retention rule the app already
had: one capture directory, the one the stored session names, everything else
removed at startup and at Start. It said that was an interim position —

> The retention the user asked for — keep the last three, prompt on launch —
> changes the policy, and changing a policy that deletes frames deserves its own
> step and its own ADR rather than arriving as a side effect of moving the bytes.

That step was planned: a `captureLibrary.ts` with `list`/`open`/`discard`/
`pruneToThree`, a Keep / Discard prompt at launch showing each capture's size
and date, and a byte budget from `estimate()` rather than a count of three
(3 × 5 GB does not fit a 10.8 GB quota, so the count would rarely have been what
bit first).

It is not being built. One capture is the rule.

## Decision

**Retention stays at exactly one capture, and there is no launch prompt.** The
session restores the capture its metadata names; startup and Start remove every
other directory.

## Why this is the better answer and not merely the cheaper one

The three-capture library was designed against a smaller capture. Its value is
being able to go back to the capture before last — and the reason it looked
worth having is that a capture used to be minutes of traffic bounded by 512 MB
of RAM. On disk a capture is **5 GB**, which at the measured 1,156 B/frame is
4.3 million frames and 22 minutes at full rate. Wanting the previous one is
mostly wanting a longer current one.

Three of them also do not fit. `estimate().quota` measured **10.8 GB** on the
development machine, so a count of three would have had to be a byte budget
anyway, and a byte budget that keeps "as many as fit" is a different feature
from "the last three" with a different UI and a different failure mode.

And the prompt is the part that ages worst. A Keep / Discard dialog in front of
the app on launch is a question asked at the moment the reader least wants one,
about data they have not seen yet, in a build where **Export is how a capture
leaves** — a capture worth keeping past a session is a capture worth writing to
a file, which is a thing the app already does and a thing the operating system
already manages.

## What this costs, stated plainly

- **Starting a new capture destroys the previous one.** That was already true
  and is now permanent: `clearSession()` did it to IndexedDB before 0025 and
  `prune` does it to OPFS after. Discard and Start are the two doors, and both
  are the user asking.
- **A capture does not survive a second capture, only a refresh.** The rule ADR
  0012 established — a capture outlives the app and only the user removes it —
  holds for the capture you have, not for the one before it.

## Consequences

- `captureLibrary.ts`, `list()`, `pruneToThree()` and the startup prompt are not
  written. `sessionLifecycle.decideStartupAction` keeps its two outcomes and
  does not gain `'prompt'`; `scripts/session/lifecycle.ts` keeps its existing
  property, which is the stronger one anyway: **no input may produce a
  deletion.**
- `prune(keep)` in the capture protocol is the whole of retention, and its
  `keep` list is one element for the foreseeable future. It stays a list rather
  than a single id because the *shape* costs nothing and a segmented capture
  (v2, where one capture is several directories) needs it.
- The next step in the disk-backed buffer is the row source — making the frames
  below the RAM window reachable — which is what actually delivers the capture
  size this whole line of work is for.
