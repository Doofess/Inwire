# 0055 — A stream is told as its states, from a digest the store keeps

**Status:** accepted 2026-10-09; Stage 1 (TCP) landed 2026-10-24: the store's
digest and `streams.iwdig`, the ladder, the docked state map and the
conversation list's TCP level. Stage 2 (UDP and QUIC) landed 2026-10-26: the
digest folds UDP flows and QUIC connections too, the conversation list's UDP
and QUIC levels are the whole capture, and Follow Stream reads either from
disk (section 7). Stage 3 (TLS, DNS and DHCP) landed 2026-10-27: a TLS phase
line on a TCP stream, a DNS flow's answer tally with marks on the ladder, and a
DHCP level by transaction with Follow Stream on an exchange (section 8). The owner asked for
a Conversations pane that shows "the networking that's going on" in a stream,
pointing at the RFC 793 state diagram, and the same idea for UDP and for any
other protocol that has a stream.

## Context

The pieces exist and none of them tell a connection's story:

- **The Conversations tab** (Statistics, `Ctrl+3`) has counts, bytes and
  timings for each pair. It has no state, no close reason and no RTT, and
  clicking a row applies a filter.
- **Follow Stream's ladder** (`components/ladder/`) has two lanes and an arrow
  per frame. It colours direction rose and sky, and colours four expert
  categories on top of that. The owner rejected those colours: arrows should
  look like the packet list's rows.
- **Both read only the RAM window.** On a long capture the table quietly
  describes the newest frames, and a stream whose start has left memory cannot
  be followed from its start. Only the PDF report folds conversations over the
  whole capture, and it does that by reading every row off disk.
- **The Worker knows most of a TCP connection's life and keeps it to itself.**
  `TcpStreamTracker` notes SYN, SYN-ACK, FIN and RST per connection and who
  sent the first FIN. That state sits per shard under multi-threaded capture
  (ADR 0053) and is evicted at 16,384 connections. Imports do not use it at
  all: they are dissected on the renderer's main thread with a tracker of
  their own.

The owner settled the design question by question (2026-10-09). The answers
are the decisions below.

## Decision

**1. The view.** Follow Stream's ladder is the main view, and an **RFC 793
state map** is docked beside it.

- **Each lane writes its side's inferred state** as it changes (SYN_SENT,
  ESTABLISHED, FIN_WAIT_1 and so on).
- **The state map** is the whole RFC graph, simultaneous open and close
  included, plus reset edges to CLOSED labelled with who sent the RST. States
  not visited are dimmed. The path taken is drawn in the theme's accent
  (`--primary`), one side at a time, chosen by a Client | Server switch.
- **The two are linked both ways.** Hovering an arrow lights the transition it
  caused, and clicking a state scrolls the ladder to the frame that entered it.
- **Long quiet runs fold into one band**, for example "data ×12,400 · 18 MB ·
  6,200 ACKs · 3.2 s". A band breaks on a SYN, FIN or RST, on any `tcp.analysis`
  flag, on a gap, and on a change of matched colour rule. Pure ACKs from the
  other side (no payload, no flag but ACK) ride along in the band they
  acknowledge and are counted apart from its data. Without that, a receiver
  that acknowledges every second segment cuts a bulk transfer into runs of two
  (owner, 2026-10-24). Clicking a band expands it.

**2. Colour comes from the colour rules and nowhere else.** An arrow's label is
a chip painted exactly like that frame's row in the packet list:
`ColorRulesEngine.getPacketStyle` under the current `packetTheme`. Direction is
shown by the lane and the arrowhead. The rose/sky pair and `CATEGORY_STROKE`
are deleted. An expert finding becomes a small marker on the arrow. A band
takes exactly one rule's colour because a change of rule breaks it, so its
colour is never an average. A riding ACK's own rule neither breaks the band nor
colours it: the band belongs to its data, in the data's rule.

**3. The list.** The conversation table gains an **outcome** column, and
clicking a row opens the stream view. Filtering moves to the context menu and
to a button on the row.

The TCP outcomes are:

| Outcome | What was seen |
|---|---|
| `closed cleanly` | FINs both ways, the last one ACKed |
| `closing` | FINs both ways, the last ACK not seen |
| `half-closed by client` / `by server` | one side's FIN, the other side still sending or silent |
| `reset by client` / `by server` | an RST, with who sent it |
| `refused` | SYN answered by RST |
| `no reply` | SYN, and nothing back |
| `handshake unfinished` | SYN and SYN-ACK, no final ACK and nothing after |
| `open` | established, no FIN or RST before the capture stopped |

Any outcome can carry **`joined mid-stream`**, meaning the handshake was not
captured.

For stages 2 and 3:

- **Plain UDP** says what it saw: `one-way`, `request/response` or `two-way`,
  plus `went quiet` when the flow stopped well before the capture did.
- **Protocols that define phases** replace that with their own:
  - DNS: `unanswered`
  - QUIC: Initial → Handshake → 1-RTT → `closed by server` / stateless reset
  - TLS over TCP: ClientHello → ServerHello → … → `close_notify` / alert
  - DHCP: DORA
- **QUIC gets its own level** in the table, because a QUIC connection is not a
  five-tuple. Its connection IDs migrate. **TLS stays a phase** on top of TCP.

**4. States are inferred, and the view says where they are not seen.** One
vantage point sees segments, not either host's state.

- The sender changes state when it sends. The receiver changes state when the
  segment would have arrived, and that is assumed, never observed.
- A stream that starts without a SYN begins in `unknown` and becomes
  ESTABLISHED, marked "joined mid-stream (handshake not captured)".
- A gap the analysis already names (`lost_segment`) is marked where it is.
- A stream still open when the capture ended is marked "state unknown after
  the capture ended".
- TIME_WAIT is drawn as **expected**, never as observed.
- LISTEN is never drawn as observed, because nothing on the wire shows a host
  listening.

This is the same discipline as the expert info's "previous segment not
captured": the view never claims more than the capture holds.

**5. The capture store builds the per-stream record: the stream digest.** Not
the Worker and not the trackers.

- **One place, every path.** Rows from a live capture (after the shards'
  merge, in id order) and rows from an import both arrive at the store as
  `append`. That is the only place every row of every capture passes in order.
  The Worker would cover only live captures. The trackers are split across
  shards, evict at 16,384, and are rebuilt for an import on another thread.
- **It folds rows, not tracker state.** Everything it needs is already on a
  row: the five-tuple, `tcp.stream` (`Packet.streamId`), `tcp.flags.*`,
  `analysisFlags`, length, time and protocol label. So the digest needs no new
  message from the dissector, and it is held to the same rows the list shows.
  Of what `InfoPatch` changes, only `protocolLabel` matters to it, and the
  store forwards that.
- **A digest is derived data, and the rows are always its source.** It is
  persisted as a snapshot in a sixth file, `streams.iwdig`. The snapshot is
  written on `finish` (pause, stop and close), each time a capture's writer
  seals everything. On `open` the snapshot is used only if it covers exactly
  the frames recovery kept. Otherwise, after a crash or for a capture written
  before this ADR, the store rebuilds the digest by folding the capture's rows
  off disk in slices, the way a scan runs. Nothing about the five existing
  files changes, and no index version moves.
- **It is not deleted with a ring's segment.** A stream's summary outlives
  frames the ring took, and the ladder marks "frames before #N were removed by
  the ring". That deletes nothing the user asked to keep, which is what ADR
  0012 is about. A rebuild after a crash covers only what is still on disk.
- **The ladder reads a stream's frames from disk.** The prefix file already
  stores each frame's `tcp.stream` at offset 12. A new `streamOrdinals`
  request walks the prefix blocks between the stream's first and last chunk
  (the digest knows both) and returns ordinals. It never cancels or waits for
  the filter bar's scan, which `scan` would. Rows are then read with
  `rowsForOrdinals` in pages.
- **Colour and folding happen in the renderer.** The store does not know the
  colour rules, so a band is cut where the rows say it should be: the matched
  rule, as well as the flags and analysis. A stream of a hundred thousand
  segments is read once when it opens, with progress shown, and its folded
  bands are cached for the life of the view.

**6. Order of work.**

1. TCP end to end: the digest, the outcome column on the TCP level, ladder
   states and bands, the state map, colour-rule chips.
2. Generic UDP and the QUIC level.
3. TLS, DNS and DHCP phases, each a small description of its phases plugged
   into the same view.

**7. Stage 2: UDP flows and QUIC connections.** The same digest, the same
snapshot file and the same view, with these rulings.

- **S2-1: no stateless-reset outcome.** Telling one from a datagram needs the
  token, which the capture never shows in the clear.
- **S2-2: a UDP flow's outcome.** `one-way` when only one direction was heard.
  `request/response` when both were and neither sent more than 2 frames, which
  covers a retried query. Anything larger both ways is `two-way`.
- **S2-3: a QUIC row's phase is its last coalesced packet's.** The dissector
  overwrites `quic.long.packet_type` per packet, so a Handshake row stands for
  an Initial from the same side before it. The type bits are read by the
  version the connection's first long header gave, v1 or v2 (0x6b3343cf).
  A Version Negotiation is no phase. A close is claimed only when a decrypted
  CONNECTION_CLOSE is the row's last frame, so a capture without keys shows a
  connection as established or unfinished, never as closed. This under-claims
  on purpose.
- **S2-4: separate types beside TCP's.** UDP and QUIC summaries are their own
  types and maps, not a union through the TCP summary. TCP's ladder, state map
  and tests stay as they were, and only the new kinds' code is new.
- **S2-5: a QUIC connection is listed under its first five-tuple.** A later
  address or port sets `migrated`, shown as "· migrated" after the outcome.
  Its frames are found by connection number, so a migrated connection keeps
  them all.

And these, which the stage's work settled:

- **One routing rule.** The UDP level counts every UDP row with a
  `udp.stream`, a QUIC datagram included (Wireshark's UDP tab and Endpoints →
  UDP do the same), and a QUIC datagram with a `quic.connection.number` also
  counts in that connection; a row with neither number is no flow. `inFlow`
  (`udpKeyOf` and `quicKeyOf`) is the one membership test: the digest folds by
  it, the store's `flowOrdinals` matches with it and Follow Stream's RAM tail
  filters with it, so the three cannot disagree. `flowKeyOf` is only which of
  the two a click on a frame opens, the connection first.
- **The client end.** A well-known port outranks the first Initial, as it
  outranks a SYN for TCP: a server's Initial heard first means the client's
  was missed, and the connection is marked joined mid-stream.
- **"Went quiet".** A UDP flow or QUIC connection whose last frame came 30 s
  or more before the capture's last frame says so after its outcome.
- **A flow's frames come from the rows.** The prefix holds only `tcp.stream`,
  so `flowOrdinals` decodes the rows of the flow's chunks, a few chunks per
  answer, and like `streamOrdinals` never touches the filter bar's scan. Each
  answer says how far through the flow's chunks it has searched, so a sparse
  flow over a long capture shows "N% searched" rather than a count stuck at 0.
- **Only rows the writer stored are folded.** A row held for its bytes is
  folded when they come. A row sealed as missed is not, because its slot is a
  placeholder; before this, such a row made the next open rebuild.
- **The snapshot is format 3** and carries the capture's last frame time. A
  format 2 snapshot is refused and the digest rebuilt from the rows.
- **QUIC's phases are a line, not a map.** Follow Stream shows them above the
  ladder, each a button that brings its frame into view. A UDP flow has no
  states to show, and both kinds band by direction and colour rule alone.
- Ethernet and IP stay the RAM window: an address pair is many streams, and
  nothing about it is a state.

**8. Stage 3: TLS, DNS and DHCP.** Three protocols that name their own phases,
told in the view stages 1 and 2 built. The owner chose, 2026-10-26: TLS as a
phase line plus a note on the TCP outcome only when TLS failed, no TLS level;
DNS as a count per answer kind with marks on the ladder; DHCP as its own level
keyed by transaction, with a phase line. One digest still folds them all at the
same `feed`, from fields a row already carries, and the snapshot is format 4.

- **S3-1: TLS facts from a row.** Only rows with both `tcp` and `tls` fold;
  QUIC's TLS is QUIC's phases. ClientHello is `tls.handshake.ja4` present,
  ServerHello `tls.handshake.ja3s`, Certificate `tls.x509.subject_cn` (plaintext
  TLS 1.2 or a decrypted record), application data any record of the row whose
  type is 23 (`inwire.tls.app_data`), a decrypted record by its inner type,
  which the row's `tls.record.content_type` also carries, as the reference's
  does. A readable alert of description 0 is `close_notify`, any
  other `alert: <name>`, and level 2 is fatal; content type 21 with no
  description is `encrypted alert`, never `close_notify` and never a failure.
  The hello and certificate facts are read only on a handshake record or a
  decrypted one. On a TLS 1.3 stream (`tls13`, a ServerHello with
  `supported_version` 0x0304) the server's encrypted handshake is type 23 too,
  so without keys the server's application data waits for the client's, whose
  first opaque record is its Finished. With keys a decrypted handshake is 22
  and marks nothing; a row stored before the inner type was recorded carries
  the outer 23 and still marks it at the handshake. The TLS map sits beside
  the TCP map, never inside it, so TCP's summaries stay byte for byte.
- **S3-2: the TLS notes.** ` · TLS alert` after the TCP outcome for a readable
  fatal alert from either side; ` · TLS unanswered` for a ClientHello the server
  never answered in TLS at all when the TCP outcome is not `open`. Any server
  step counts as an answer, because a ServerHello whose record lost a segment
  is never read while the server's later records still show it spoke. Nothing
  else is appended.
- **S3-3: classic DNS only.** A flow is tallied when one of its ports is 53.
  mDNS and LLMNR keep the plain UDP outcome, because their answers come from
  other flows; DNS over TCP is a TCP stream.
- **S3-4: queries are matched by `dns.id` within the flow**, not by the
  tracker's `dns.response_to`, so the tally does not depend on tracker eviction
  or shards. A repeated open id counts once, timed from its last copy, as the
  ladder's marks time it; at most 64 stay open (`MAX_OPEN_QUERIES`) and an
  evicted one counts as unanswered until a late answer takes it back. A
  response with no open query counts by its rcode, unless it is the second
  answer, within 5 s, to a query an answer already closed (a retry whose two
  copies were both answered). An open query is `unanswered` once 5 s
  (`DNS_WAIT_SECONDS`) separate it from the capture's last frame, otherwise
  `waiting`, decided at render time as "went quiet" is - and in a finished
  capture (a file, or one that stopped or paused) always `unanswered`, because
  no answer can still arrive.
- **S3-5: a DNS flow's text is its tally alone**, e.g. `40 answered · 1 error`,
  with no "went quiet": a finished query is not a flow that stopped. The ladder
  marks an error answer with its rcode name and an unanswered query with
  `no answer`, once every page of the flow has been read. A frame with a mark
  never folds into a band.
- **S3-6: DHCPv4 only.** DHCPv6 rows carry no message type or transaction id,
  so DHCPv6 stays a UDP flow.
- **S3-7: a DHCP side comes from the message type**, not from ports or
  addresses, which change mid-exchange (0.0.0.0, broadcast, the offered
  address) and lie through a relay. Discover, Request, Decline, Release and
  Inform are the client's; Offer, ACK and NAK the server's. The client is its
  hardware address on port 68, written without the port. The server is the
  server identifier option, else the first server message's source, else where
  a client message was sent when that was not a broadcast (a renewal goes to
  its server), else not seen.
- **S3-8: a DHCP outcome**, folded message by message: the last ACK or NAK
  decides `acked` or `NAK`; a Decline after the ACK is `declined`; a Release is
  `released`; otherwise an Offer is `offer not taken`, unless a Request
  followed it, which with a Request or Inform alone is `no reply`; otherwise
  `no offer`. A client that reuses a transaction id for a later exchange merges
  the two into one row; accepted.
- **S3-9: TLS and DHCP are not kept in the relabel ring.** Their protocol label
  never matters to them, and DHCP's 32-bit key would not fit the ring.

And these, which the stage's work settled:

- **The phase line is one component.** QUIC's line became `PhaseLine`, which
  TLS (`TLS phases`) and DHCP (`DHCP phases`) reuse with the same classes and
  no new colours.
- **A DHCP exchange is its own level and its own target.** Conversations →
  DHCP is the whole capture, client as A (`hostname (MAC)` when a row carried
  a hostname, else the MAC), B `not seen` when no server message was read; Follow Stream opens `Follow DHCP Exchange 0x<xid>`, filtered by
  `dhcp.id`, and a DHCP row still counts in its UDP flow.
- **The snapshot is format 6.** Format 4 was stage 3 as first landed; the DNS
  tally and the TLS summary gained fields afterwards (the evicted and settled
  ids, `tls13`), so a format 4 snapshot is refused like a format 3 one and the
  digest rebuilt from the rows. Format 5 marked a decrypted TLS row as
  application data whatever it carried; a decrypted row now has
  `tls.record.content_type` of its inner type (the reference's own reading) and
  only a decrypted 23 marks it, so a format 5 snapshot is refused too.

## Considered and rejected

- **The state diagram on its own.** It explains why but leaves out when, who,
  and what was in between. The owner took both views.
- **A summary built in the pipeline Worker.** It misses every import, splits
  across shards, and forgets at the tracker's cap.
- **A re-scan from disk each time the pane opens**, as the PDF report does.
  Correct, but it costs seconds on every open of a large capture. Folding at
  arrival costs the store a map lookup a row. Task 4 of the plan measures it
  against `scripts/perf/store-boundary.ts`.
- **A per-chunk journal sealed with each chunk**, like `records.iwrec`. It is
  durable through a crash. But the digest folds at `append` while rows seal up
  to two seconds later, so a journal would have to hold each frame's
  contribution until its chunk sealed, which is a second staging ring. A
  snapshot plus a rebuild gets the same answer after a crash for the cost of
  one read pass.
- **Evaluating colour rules in the store**, so bands could be cut there. The
  rules are renderer preferences and an edit would invalidate every band. Rows
  are read anyway to draw arrows.

## Consequences

- **A capture directory has six files.** `planPrune` already removes whole
  directories, so a prune needs no change. `bytesOnDisk` counts the new file.
- **Conversations has two scopes.** The TCP, UDP and QUIC levels are the
  whole capture. The Ethernet and IP levels are the RAM window. The pane says
  which.
- **Opening a capture after a crash rebuilds its digest.** This takes as long
  as a scan of the whole capture. The TCP level shows the rebuild's progress
  and is usable from its first slice.
