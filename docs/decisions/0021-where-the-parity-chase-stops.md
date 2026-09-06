# 0021 — Where the parity chase stops, and what is left is not a defect

**Status:** accepted

## Context

ADR 0020 recorded 883 Info mismatches and asserted that 97.5% of them were one
problem. `scripts/tcp/reassembly.ts` was written to check that claim and found
it was one *area*, not one problem. Four commits and this one later the gap is
**130** — inwire 50, bulk 80 — and the question is no longer "what is the
cause" but "which of the causes left is a defect".

Two were, and are fixed. A record this build could not read named itself
`Unknown (25)` where the reference names nothing (37c65cd, 194 → 170), and a
record with an unfilled hole in it completed anyway, inventing a PDU and
tagging thirty consecutive frames as segments of it (691bec3, 170 → 130).

What is left divides cleanly, and the division is the point.

## Decision

**Stop chasing the Info column here.** Three of the remaining buckets cannot be
closed single-pass, and one is the reference analyzer's own inconsistency.

### The largest bucket is not ours to fix (64 of bulk's 80)

`we claim TLS, tshark shows TCP` — we print `Ignored Unknown Record` on a
segment tshark prints as a plain TCP summary. Measured, **50 of those 64 sit
between two segments tshark itself called `Ignored Unknown Record`**. Frame
2047 is typical: in a 35-frame window on that stream tshark labels 34 frames
`Ignored Unknown Record` and that one frame nothing, with no property of the
segment to distinguish it — its first payload byte (0x34) is exactly as invalid
a content type as its neighbours' (0x50, 0x81).

These are lone exceptions inside desynchronised regions where the two builds
otherwise agree, in a stretch of a capture where every byte is ciphertext being
read as a record header by both analyzers. Matching them means reproducing an
artefact of Wireshark's desegmentation bookkeeping, and our answer — the same
label as the 34 frames around it — is the more consistent one to read.

The other **14 are one contiguous run** (#1762–#1782): `[TCP Out-Of-Order]`
segments tshark attributes to a PDU with `[TCP PDU reassembled in N]`. Placing
an out-of-order segment inside a PDU is a two-pass fact.

### Refusing to claim TLS on an out-of-order segment is worse, not better

The obvious response to that run — a segment this build cannot place should not
claim TLS — was tried and measured: **inwire 50 → 65, bulk 80 → 107.** An
out-of-order segment often *does* carry a readable record, and reading it is how
a direction resynchronises. The floors caught it in one run.

### Two-pass facts, named rather than left open

- **A retransmission attributed to a PDU that completed earlier** (20 of
  inwire's 50). tshark tags `[TCP Retransmission] … [TCP PDU reassembled in
  1976]` — a frame number *behind* the segment carrying the tag.
- **`(no response found!)`** on an unanswered echo request (3). Needs to know
  no reply arrives in the whole capture.
- **`[TCP Dup ACK]` vs `[TCP Window Update]`, the zero-window probe and its
  ACK** (4). Traced to a deliberate divergence and its price is recorded at the
  line: this build seeds `fwd.nextSeq` from a bare ACK because **bulk holds
  30 TCP streams and exactly one SYN**, and the reference's stricter rule costs
  2,000 frames on captures of traffic already in flight.
- **Five QUIC Initials** where this build prints the decrypted frame types and
  the reference prints `Initial, DCID=…`. Frames we read and it does not.
- **Six inwire frames on three connections** where tshark buffers a 1-byte
  segment, lands on a different record boundary and desynchronises, printing
  `Ignored Unknown Record` where this build prints `Application Data`. Matching
  it means reproducing tshark's desync and printing *worse* output.

## Consequences

194 → 130 Info mismatches; floors at inwire 99.6% / bulk 99.4%. Both fixes
are pinned in `scripts/tls/dissect.ts`, which grew from 60 checks to 64.

The rule this leaves behind is the one worth keeping: **a bucket in
`scripts/tcp/reassembly.ts` is a defect only until it is measured.** Two of the
three avenues tried here were plausible from the mismatch list, were built, and
made things worse — the out-of-order refusal by 42 frames and the reference's
own `nextseq` guard by 2,000. Neither was visible without running it, and the
acceptance floors are what turned both into a five-minute answer instead of a
regression. Read the first divergence per connection, build the smallest thing
that tests the hypothesis, and let the floors decide.
