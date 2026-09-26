# 0049 — A frame's tree is rebuilt from its own record

**Status:** accepted 2026-09-26. **Amends [0007](0007-what-crosses-the-worker-boundary.md)** on
how a tree that is not carried gets built: from the frame's record, not by
replaying its conversation. **Touches [0038](0038-bytes-and-rows-are-two-arrivals.md)**:
the pipeline Worker's store port now also carries records out and revisit
kits back. **Touches [0045](0045-the-key-log-is-followed-not-loaded.md)**: no
key is ever written into a record.

## Context

0007 stopped carrying a protocol tree with every frame: a tree is ~16 kB in
the heap against the frame's ~1.1 kB, and one frame at a time is ever looked
at. The tree of the frame being looked at was rebuilt instead - and since a
tree is not a function of its frame's bytes (relative sequence numbers, stream
indices, the TLS record cursor, DNS and ICMP pairings are all state the frames
before it built up), rebuilding meant **replaying the frame's whole
conversation** at the moment somebody clicked it.

The owner did not want that: *"we need something better than that."* Measured
on the real fixtures before anything changed:

- a replay costs 22-27 us per frame of stream depth - median 8 / 33 ms, worst
  87 / 146 ms (`bulk` frame 13801, 4,639 frames into its stream);
- a frame below the RAM window got a **context-free one-frame dissection**,
  which is the right tree for under 8% of frames;
- the whole stream was fetched from disk before the 20,000-frame cap applied;
- a false `[Reassembly context] ... earlier frames are no longer in the buffer`
  row appeared on every TCP stream that did not open with a SYN.

Per-stream checkpoints were offered (replay at most 256 frames). The owner
chose **Wireshark's model** instead: its first pass stores what each frame
needed (`p_add_proto_data`), and a frame shown later is dissected once, from
that.

## Decision

**At arrival every frame's dissection is recorded; on a click its tree is
rebuilt from its bytes and its record, with no replay.**

- **The seam is the tracker interface** (`dissect/trackerApi.ts`). Dissectors
  take `Pick`s of the tracker classes, not the classes. At arrival a
  `FrameRecorder` (`dissect/frameRecord.ts`) stands in front of the real
  trackers and writes down every answer in call order; on revisit a
  `FrameRevisit` stands in their place and gives the answers back to the same,
  unchanged dissector code. One dissector, never two.
- **A record is a call log**, checked on replay: each entry names the method,
  and a revisit that asks a different question from arrival throws
  `RecordMiss`. A miss is never a wrong tree.
- **Facts from outside any conversation** go through `dissect/dissectEnv.ts`
  and are recorded too: the clock a certificate is judged by, HTTP/1's shared
  body budget, and the frame's direction - a live capture learns this
  machine's identity part way through.
- **Live state** (the TLS cursor and conversation, LDAP/SMB2/BGP) is recorded
  as a snapshot when it is handed over. The TLS conversation **never with its
  keys**: a revisit derives them from the key log held at that moment, which
  is also what opens a frame that arrived before its keys did. The cursor's
  buffered body is **named, not copied** - frame, offset, length and an FNV-1a
  hash per piece (`bufferSources`), so the store answers with those frames'
  own bytes and a revisit that finds different bytes misses.
- **Decrypted content is never recorded.** An answer that carries plaintext -
  HTTP/3 frames from a 1-RTT stream, a packet opened with a key-log key, a
  decrypting connection's HTTP state - is marked, and a revisit misses there.
  (The owner's rule: plaintext stays in memory. Rebuilding those trees without
  a replay is the open item below.)
- **Records live in a fifth capture file, `records.iwrec`**, one deflated
  block per chunk, written before the chunk's index record so recovery covers
  them unchanged. The index is version 2 (an 80-byte stride with the records'
  extent); version 1 captures still open, have no records, and are continued
  as version 1.
- **The pipeline Worker posts a flush's records** to the store right after its
  bytes, on its own port, and **asks that port for a `revisitKit`** on a click
  its tree cache cannot answer: the record, the row, and the bytes of the frame
  and of every frame the record names, in one reply. An import records on the
  renderer's thread and sends each batch's records ahead of its rows.
- **Replay is the fallback, not the path**: a frame with no record (a version
  1 capture, a frame whose dissection threw) or a record that misses. It now
  caps before fetching bytes, says so when the frame itself is not held, and
  adds the "earlier frames" row only when frames have really left the buffer.

## Consequences

- **A click costs a record read and one frame's dissection**, whatever the
  frame's depth and wherever it is in the capture: 45-72 us a frame on the
  fixtures, against up to 146 ms. Frames below the RAM window get their real
  tree for the first time.
- **Every frame of the real fixtures revisits into the identical tree** -
  inwire 12,858, bulk 14,782, icmpErrors 66, zero misses, zero wrong
  (`scripts/pipeline/revisit.ts`, which fails on any miss). Through the store
  and a v8 clone, every inwire frame rebuilds from its kit alone
  (`scripts/capture/records.ts`).
- **In the built app**, `scripts/electron/revisit-drive.ts` imports the real
  `inwire` capture and opens deep TCP, TLS, DNS and QUIC frames: each tree is on
  screen in ~20 ms, and a spy on the Worker's `postMessage` sees a `detail` and
  no `replay`. That spy is the part that matters. A replay draws the same tree,
  and the first run of the drive passed on correct trees while every click was
  replaying: the import never asked for records. `scripts/capture/records.ts`
  now drives an import through `importAnyFile` for exactly that reason.
- **Records cost ~58-64 B a frame on disk**, about 5% of a capture.
- **Recording costs arrival time:** 8% of dissection on `inwire`, 24% (~5 us a
  frame) on `bulk`, whose TLS-continuation frames dissect in ~20 us and each
  snapshot a cursor. Measured, not yet reduced; encoding snapshots by a fixed
  field order was rejected because records outlive builds and a changed
  literal would decode old records silently wrong.
- **Two rows added outside the dissector** are applied again on revisit from
  the stored row: the process that owned the socket, and `[Response In]`,
  the one thing a later frame writes into a tree. The JA4 "matches process"
  row is not - the replay never added it either.

## Open

- **Decrypted traffic without a replay.** Answers carrying plaintext miss
  today. The plan is a memory-only store of derived content in the Worker
  (decoded header lists, plaintext buffers), with the bounded replay after a
  restart. It needs a real capture with a key log to be gated.
- **The arrival cost on TLS-heavy traffic**, measured above.
