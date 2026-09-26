# 0049 — A frame's tree is rebuilt from its own record

**Status:** accepted 2026-09-26. Record version 3 (the key log checks); version 2 records miss and fall back to the replay. **Amends [0007](0007-what-crosses-the-worker-boundary.md)** on
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
- **The key log is asked again, and checked, never replayed.** A revisit
  derives a conversation's keys from the key log it holds now, the first time
  a record needs them. What the record keeps is only whether arrival had keys
  (`keysAtArrival`), and at a ServerHello whether the log had secrets for the
  connection and whether any log was loaded - a `checked` env answer, recorded
  as a yes or no and compared with the live log on revisit. A key log that
  came later, or was cleared, makes the revisit miss rather than draw a
  record opened, or shut, differently from arrival. The first run with a real
  key log found why this has to be explicit: keys were only ever derived when
  a ServerHello was parsed, so a revisit of any later frame silently drew its
  records undecrypted - 19 wrong trees, where the design promised none.
- **Decrypted content is never recorded; it is kept in memory.** An answer
  that carries plaintext - HTTP/3 frames from a 1-RTT stream, a packet opened
  with a key-log key, a decrypting connection's HTTP state - is only marked in
  the record. The recorder writes the answer itself to a second log for that
  frame, which the pipeline Worker holds in a `DerivedStore`
  (`services/pipeline/derivedStore.ts`): memory only, 64 MB, oldest out, and
  emptied when the key log is cleared or the capture reset. A revisit given
  that log reads a marked answer from it; one without it - after a restart,
  past the budget, after a clear - misses, and the frame is replayed. That is
  the owner's rule, *plaintext stays in memory*, kept exactly. An import
  decrypts on the renderer's thread, so it hands its log to the Worker after
  its reset, and the store is sent only `{ id, record }` of each entry.
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
  inwire 12,858, bulk 14,782, icmpErrors 66, and the key-log capture's 14,615
  without its keys: zero misses, zero wrong (`scripts/pipeline/revisit.ts`,
  which fails on any miss). **With its keys and the Worker's memory, all
  14,615 frames revisit, zero misses** - the 7,276 decrypted ones read their
  decrypted answers from memory. Without that memory, and with the key log
  present at only one of the two passes, every frame is equal or misses. Zero
  wrong in all eight runs. Through the store
  and a v8 clone, every inwire frame rebuilds from its kit alone
  (`scripts/capture/records.ts`).
- **In the built app**, `scripts/electron/revisit-drive.ts` imports the real
  `inwire` capture and opens deep TCP, TLS, DNS and QUIC frames, then imports
  the key-log capture with its key log followed and opens HTTP/3 and HTTP/2
  frames: each tree is on screen in ~20 ms, and a spy on the Worker's
  `postMessage` sees a `detail` and no `replay`. With the import's hand-over of
  its decrypted answers removed, the four decrypted frames fail that check. That spy is the part that matters. A replay draws the same tree,
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

- **How far back the memory reaches.** The key-log capture's decrypted
  answers are 8.2 MB for 75 seconds, ~590 B a frame; 64 MB holds about nine
  minutes of browsing like that, and a decrypted frame older than that is
  replayed. Sizing it the way the buffer is sized (ADR 0036) is the lever.
- **The arrival cost on TLS-heavy traffic**, measured above.
- **A QUIC packet arrival could not open stays unopened on revisit** when its
  keys arrived later. That equals what arrival showed, so it is stale rather
  than wrong; a replay with the fuller key log would open it. TLS misses in
  that case, and QUIC does not yet, because its keys are derived inside the
  tracker, whose calls a revisit does not repeat.
