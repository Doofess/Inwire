# 0052 — The agent is its own dumpcap

**Status:** accepted 2026-09-28, landing in phases (below). **Amends
[0005](0005-agent-wire-format.md)** (the wire record is version 4, with 32-bit
lengths) and **[0050](0050-a-capture-is-narrowed-by-the-driver.md)** (the
snaplen's ceiling is dumpcap's 262,144). The ring buffer will amend
[0012](0012-stored-captures-persist.md) and
[0025](0025-the-capture-lives-on-disk.md) narrowly when it lands.

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
5. The store follows the ring.
6. Save-as-captured, and import reading IDB and ISB options.
7. Docs.

## The Python agent's deviations

It speaks version 4 and writes no files. There is no desktop app on macOS or
Linux to ask it to, and it refuses ring and autostop options with a sentence
rather than ignoring them.
