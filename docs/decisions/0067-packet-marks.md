# 0067 — Packet marks: a per-capture file the store owns, keyed by frame id, read by `frame.marked`

**Status:** accepted 2026-10-24 by the owner, as UX audit group 4. The owner
chose four rulings: a mark is kept with the capture, it is drawn as an inverted
row, and the set is used by Unmark all, Export marked only, jumping between
marks and the `frame.marked` filter field.

## Context

Wireshark's Mark Packet (`Ctrl+M`) is how an analyst sets frames aside while
reading a capture: mark the five that matter, then jump between them, filter on
them or export only them. Inwire had no equivalent. Four things had to be
decided, and each closes off an option:

- **Where the set lives.** The renderer holds a RAM window, not the capture, so
  a set held only there cannot answer a filter scan over disk rows, and it dies
  with the window.
- **What a mark names.** Ordinals move when a ring expires its floor; a row
  index moves with every filter.
- **Whether a mark is evidence.** pcapng has a per-packet flags word, but
  writing it would edit the original capture the agent wrote.
- **How a filter reads it.** `frame.marked` is a tshark field, and the filter
  compiler is shared by the Worker, the renderer and the store's scan.

## Decision

- **One file per capture, `marks.iwmrk`, beside the index, owned by the
  store.** It is `{"v":1,"ids":[...]}` (`src/services/marks.ts`), written whole
  on every change, and an empty set truncates it so a cleared set cannot come
  back. Unlike `streams.iwdig` it is **a source, not a cache**: nothing else
  records which frames were marked, so it is never rebuilt, and a missing or
  torn file opens as no marks rather than failing the open.
- **A mark is a frame id**, the id the pipeline assigns before dissection and
  the store keeps for the life of the capture. A mark on a frame the ring has
  expired stays in the file and matches nothing.
- **The renderer holds the live set and the store holds its copy.** The open
  reply carries the stored ids (`ready.marks`); every change is a one-way
  `marks` message naming its capture id, and the store ignores a message for a
  capture it does not have open, so a change that outlives a Clear View or a
  Reopen cannot mark the next capture.
- **Never in pcapng.** The agent's original pcapng and every export stay
  unmarked; marks are the analyst's notes about a capture, not part of it.
- **`frame.marked` is answered through a filter context**, `compile(expr,
  { marked })`, not from the packet. `frame.marked == 1` finds the marked
  frames; a bare `frame.marked` matches every frame, as in Wireshark, because
  the field is present on every frame. The store's scan compiles with the set
  it holds at the scan's start.

## Consequences

- Marks survive a restart and a Reopen, and go with the capture's directory
  when it is pruned or discarded.
- A filter naming `frame.marked` must be re-run when the set changes; the
  renderer's incremental filter cache is invalidated for it.
- Exporting "marked only" asks the store for the marked ordinals rather than
  running a scan.
- An imported file streams into the store like a live capture, so its marks
  are kept the same way; the file the user opened is never written.
