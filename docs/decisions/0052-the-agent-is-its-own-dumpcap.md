# 0052 — The agent is its own dumpcap

**Status:** accepted 2026-09-28; phases 1-7 landed (below), and the 0.5.0
build passed the three live drives installed on 2026-09-29. **Amends
[0005](0005-agent-wire-format.md)** (the wire record is version 4, with 32-bit
lengths), **[0050](0050-a-capture-is-narrowed-by-the-driver.md)** (the
snaplen's ceiling is dumpcap's 262,144), and narrowly
**[0012](0012-stored-captures-persist.md)** and
**[0025](0025-the-capture-lives-on-disk.md)**: a capture that follows a ring
loses the frames of each file the agent deletes, and nothing else.

## Context

0050 did items 1–3 of the dumpcap comparison natively: capture filters, a
snaplen and nanosecond stamps. Items 4–7 remained:
- pcapng as captured, with interface blocks and end-of-capture statistics
- ring files and autostop
- a capture engine of the dumpcap kind
- files laid out as Wireshark's are

**Bundling Wireshark's dumpcap was designed and set aside.** Its costs were
measured on this machine:
- up to 250 ms of latency (`CAP_READ_TIMEOUT`, with no `mintocopy`)
- drop counts only at exit
- one failing adapter ends the whole capture
- ring files cannot be streamed to stdout
- 4.7 MiB of GPLv2/LGPL files with source obligations
- a child process started by a LocalSystem service

The agent already does dumpcap's core over the same libpcap handle. What
dumpcap adds on top is a pcapng writer and file rotation. The owner asked for
those in the Rust agent.

## Decision

**The agent writes the capture's pcapng itself**, laid out block for block as
dumpcap lays it out:
- **SHB:** CPU, OS, program.
- **IDB:** option codes ascending (name, connection name, `if_tsresol`, filter,
  OS, adapter model).
- **EPB:** no options.
- **ISB:** per interface at close, with a comment, start, end, received and
  dropped.

`agent-rs/src/pcapng.rs` is held to the two captures dumpcap itself wrote: every
block of both is rebuilt byte for byte from its parsed facts.

**One difference is kept on purpose.** dumpcap writes an ISB's times in
microseconds inside a section whose interfaces declare nanoseconds, so a reader
applying the spec places them 1,000 times too early. The agent writes them in
the interface's units. And where dumpcap writes no ISB into ring files, the
agent writes one into each file as it closes.

**The wire record is version 4: 22 bytes, with `u32` capLen and origLen.** The
file holds frames up to the snaplen, now dumpcap's 262,144, and the stream to
the app has to carry the same frames. Version 3's 16-bit lengths refused a frame
past 65,535 bytes (`frame_too_long`, `droppedOversize`). An offloaded send can
be that long. Both the message and the counter are deleted, not left as dead
code, because no frame can be refused now. `origLen` replaced the 16-bit
`extra` difference, which had to clamp. Product 0.5.0.

**Where the files go, and why that is safe:**
- They go inside the capture's own folder,
  `%LOCALAPPDATA%\Inwire\captures\cap-…\pcapng\`. The owner chose this, so one
  capture is still one folder.
- Main tells the agent the capture root in a message it authors itself
  (`set_capture_root`). `start_capture` names only the capture id, checked
  against the id pattern. The renderer never names a path.
- **The agent never writes with its own rights.** It impersonates the client
  that started the capture (`ImpersonateNamedPipeClient`, then a duplicated
  token set on the writer thread). A client can therefore only make the service
  write where that client could write itself.

**Ring files and autostop belong to the agent**, as they do to dumpcap:
- New files by size, frame-time duration or packets, keeping the newest N.
- Stop after N packets, bytes, seconds or files.
- The app's list follows the ring. When the agent deletes a file, the store
  evicts the frames that file held.

**How the store follows the ring.** A capture's data is in segments - segment
0 is the four files beside the index, as before, and segment *n* is
`seg-NNNNNN/` - and index version 3 records each chunk's segment and, in its
header, the **floor**: the first chunk still held.
- **The agent says where each file begins** (`capture_boundary {index,
  firstSeq}`), under the lock that hands out sequence numbers and before the
  file's first frame is queued. One pipe is first in, first out, so the
  pipeline Worker always has a file's threshold before any frame past it, and
  files every frame by its sequence number (`pipeline/ringFiling.ts`). The
  writer thread's own `capture_file` reports could land on either side of the
  frames they name, which is why they are not what files a frame.
- **The store starts a segment per ring file**, and when the agent deletes a
  file it deletes the segments holding only frames at or below that file's
  last sequence number - **floor first**, so a crash between the two leaves a
  directory nothing reads, which recovery removes. `segments.ts` is the rule
  and `scripts/capture/segment-guard.ts` holds each refusal in it: never
  segment 0, never the segment being written or one with a frame still
  staged, never one holding a frame filed under another run of the agent or
  under none, oldest first. **By sequence number rather than by file**,
  because a boundary the pipe shed would file a whole ring file under the one
  before it; by file, deleting that one would take frames the agent still
  has, where by sequence number the segment waits one file longer.
- **Ordinals never move.** Lookups answer below the floor as a hole, and the
  list, a filter's bitmap, an export and the RAM window all start at the
  floor rather than renumbering - so a cached row, a scan and a selection stay
  right as the front leaves. `scripts/capture/segments.ts` drives all of it
  through the real host over the real `inwire` capture.
- **Two adapters' frames cross in the ordering window**, so a frame of file
  *k* can reach the store after file *k+1*'s segment began. It joins the later
  segment and is kept one file longer than its file. With one adapter the
  list's first frame is the oldest kept file's first frame exactly.

**"Save as captured" copies the agent's files** out of the capture's folder,
byte for byte (`electron/capturedFiles.ts`): the renderer sends a capture id,
main copies only names the agent gives, one file through a save dialog and a
ring's into a new folder of its own. An export still rebuilds a file from the
store, and is what a filter or anonymising uses.

**An import keeps what a capture file says about itself**
(`captureFileFacts.ts`): each IDB's name, description, filter and snaplen, the
last ISB's received and dropped, and the SHB's application. The metadata
states them, and a pcapng export of the imported capture carries the filter,
snaplen and counts back out, so a dumpcap or agent file round-trips with them
(`scripts/export/import-facts.ts`, with `capinfos` as the oracle).

**Not done, on purpose:** a filtered or anonymised export does not copy the
agent file's IDB and ISB blocks. The export already writes the capture's
filter, snaplen and drops from the capture's own options; what copying would
add is the adapter's model and the OS, and an anonymised file must not carry
those anyway.

## Phases

1. `pcapng.rs`. **Landed.**
2. Wire version 4, snaplen up to 262,144, product 0.5.0. **Landed with this
   ADR.**
3. The writer thread, the sequencer, impersonation, ring files, autostop, and
   Stop draining instead of discarding. **Landed**: over the real pipe, a
   capture's file holds every frame of the fixture though its client read none
   of them; a ring keeps exactly its newest files; an autostop is exact in the
   file and in the stream.
4. The app: `set_capture_root`, the options, and a single stop path.
   **Landed.**
5. The store follows the ring. **Landed.**
6. Save-as-captured, and import reading IDB and ISB options. **Landed.**
7. Docs. **This record, CLAUDE.md and `docs/verification.md`.**

**Driven live, 2026-09-29**, against the 0.5.0 build installed elevated:
- `scripts/electron/capture-file-drive.ts`: an autostop at exactly 5,000
  packets, whose file is owned by the user rather than SYSTEM and holds the
  store's frames byte for byte; a ring of ten 1 MB files keeping three, which
  left files 8-10 and segments 8-10 with the list starting at file 8's first
  frame; and a root the user cannot write, which was refused with nothing
  created.
- `capture-options-drive.ts` and `live-revisit-drive.ts`: both pass. The
  revisit drive failed once on its last case, a UDP frame whose tree was not on
  screen within 15 seconds, and then passed twice. It now prints what went to
  the Worker when a case fails.

**One thing the drives found about the drives, not the app:** a capture the
agent writes a file for is filed from segment 1 even without a ring, because
the first `capture_boundary` opens a segment. A reader that only knows
segment 0 (`recoverIndex`) sees such a capture as empty, so every reader of a
live capture uses `recoverCapture`.

**Still owed, and needing a person:** the second-account check in
`docs/verification.md`, that the agent refuses to write into a folder the
client's account cannot.

## The Python agent's deviations

It speaks version 4 and writes no files. There is no desktop app on macOS or
Linux to ask it to, and it refuses ring and autostop options with a sentence
rather than ignoring them.
