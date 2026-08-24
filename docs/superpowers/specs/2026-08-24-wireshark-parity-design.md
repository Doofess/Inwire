# Wireshark Parity, Phase 1: TCP relative numbers, Frame/Ethernet/IP metadata, ICMP correlation, TCP options

## Context

The user compared NetView's packet list and protocol-detail tree against a
real Wireshark capture and asked for NetView's packet handling to get as
close as possible to Wireshark's. That comparison surfaced seven concrete
gaps; this spec covers the four the user picked to start with. The other
three (TLS handshake message decoding, DNS answer/CNAME-chain parsing, and
multi-segment TCP reassembly into higher-layer PDUs) are meaningfully larger
and are explicitly deferred to a later phase - not designed here.

**In scope for this phase:**
1. TCP relative sequence/ack numbers, `[Next Sequence Number]`,
   `[Conversation completeness]`, `[Stream Packet Number]`
2. Richer Frame/Ethernet/IP layer metadata (MAC vendor resolution, DSCP/ECN,
   IP flags/fragment fields, header checksum verification, `[Stream index]`,
   frame timing deltas, protocols-in-frame list)
3. ICMP echo request/reply correlation (`id=`/`seq=`/`ttl=`,
   `(reply in N)` / `(request in N)`)
4. TCP Keep-Alive detection, and MSS/WS/SACK_PERM/SACK-block parsing from
   TCP options - which requires fixing a real pre-existing bug (see below)

**Explicitly out of scope for this phase** (noted so it isn't silently
dropped, per the earlier discussion):
- TLS handshake message parsing, DNS answer/CNAME chain parsing, TCP
  segment reassembly - bigger, later phases.
- `[Frame is marked]` / `[Frame is ignored]` - these are Wireshark
  user-interaction state (manually marking/ignoring a frame in the UI), not
  protocol data: there is nothing to parse, this would be a new standalone
  UI feature unrelated to dissection.
- "Coloring Rule Name/String" in the Frame layer - would require threading
  `ColorRulesEngine` into `PacketDetailsTree` and gets stale awkwardly since
  rules can change without re-decoding. The row color already conveys this;
  not worth the added coupling for what it adds.
- "Time shift for this packet" - an operator-applied manual clock
  adjustment feature; not applicable here.
- `[Time delta from previous displayed frame]` - depends on the *current*
  filter state at view time, which the decode step can't know (decoding
  happens once, before any filter is applied). Only "previous **captured**
  frame" (`timeDelta`, already computed) and "time since first frame"
  (`relativeTime`, already computed) are implemented.

## Architecture

All four items extend the existing single-pass decode pipeline
(`decodeRawEthernetPacket` → `decodeTransportLayer` in
`src/services/pcapParser.ts`), the same shape the TCP-retransmission work
from earlier this session already established: a per-capture-session
tracker class holds cross-packet state, and the decoder reads a few more
bytes out of `rawBytes` that are already available but currently ignored.
Three of the four items are purely additive - "compute more from what's
already there plus past state" - and fit that existing shape exactly.

**ICMP correlation does not fit that shape** and is the one piece of this
phase with real architectural weight: annotating a request packet with
`(reply in N)` requires reaching back and editing a packet that was already
returned from `decodeRawEthernetPacket` and (in the live-capture path)
already pushed into React state. This is called out in its own section
below with its own data-flow diagram, because it's the one piece of this
phase that isn't "just extend the tracker."

### New/extended state

- **`TcpStreamTracker`** (`src/services/tcpStreamTracker.ts`, already
  exists) gains:
  - `baseSeq: Map<directionKey, number>` - first-seen sequence number per
    direction, used as the relative-numbering reference (Wireshark's ISN).
  - `packetCountByStream: Map<streamId, number>` - `[Stream Packet Number]`.
  - `connState: Map<streamId, { sawSyn, sawSynAck, sawFinOrRst }>` -
    backs `[Conversation completeness]`.
  - `lastWasKeepAlive: Map<directionKey, boolean>` - lets the *reply* to a
    Keep-Alive probe be labeled `[TCP Keep-Alive ACK]`.
  - New methods: `getRelativeSeq(...)`, `recordStreamPacket(streamId)`,
    `updateConnectionState(...)`, `getConversationCompleteness(streamId)`,
    `getExpectedNext(...)` (needed for Keep-Alive detection).
- **New `IcmpEchoTracker`** (`src/services/icmpEchoTracker.ts`) - same
  shape as `TcpStreamTracker`: `Map<"id:seq:direction", frameNumber>` for
  pending requests, with `recordRequest()` / `matchReply()`. Reset alongside
  the other trackers on buffer-clear.
- **New `src/services/macVendors.ts`** - a small curated
  `Record<string /* first 3 octets, uppercase hex, no separators */, string>`
  lookup table (my own compilation of well-known IEEE-registered OUI
  prefixes - not a copy of Wireshark's `manuf` database), plus a
  `resolveMacVendor(mac: string): string` helper that formats
  `"Vendor_xx:xx:xx (aa:bb:cc:dd:ee:ff)"` on a hit and falls back to the
  raw MAC when the OUI isn't in the table - matching Wireshark's own
  fallback behavior for unknown vendors.

### Data model changes

`ProtocolField` already supports `children?: ProtocolField[]`, so every new
piece of "raw value" that Wireshark shows as an expandable sub-item (e.g.
`Sequence Number: 8713 (relative)` with `Sequence Number (raw): 3264341190`
nested under it) uses that existing mechanism - no type changes needed
there. No changes to the `Packet` type are needed for items 1, 2, or 4.

`decodeTransportLayer`'s signature gains one more parameter: `ttl: number`
(the IPv4 TTL / IPv6 hop limit, already computed by the caller but
currently not passed down), so the ICMP branch can format `ttl=` into its
own info string the same way TCP/UDP already format their own info
strings internally.

## Component design

### 1. TCP relative seq/ack numbers + conversation completeness

- `decodeTransportLayer`'s TCP branch calls
  `tcpTracker.getRelativeSeq(srcIp, srcPort, dstIp, dstPort, seqNum)` (and
  the same for `ackNum` using the *reverse* direction's base, since an ACK
  number is relative to the *other* side's ISN) before building the info
  string and fields.
- **Info column changes from raw to relative**, matching Wireshark's
  default: `Seq=0 Ack=1` instead of `Seq=3264341190 Ack=1194127964`. Raw
  values move to nested sub-fields in the tree, not the info string.
- New TCP layer fields (as children of the existing Sequence
  Number/Acknowledgment Number fields): `Sequence Number (raw)`,
  `[Next Sequence Number]` (relative seq + payload length, or +1 for
  SYN/FIN), `[Stream Packet Number]`, `[Conversation completeness]` (plain
  English: `"Complete"` / `"Incomplete (no SYN seen)"` /
  `"Incomplete (no FIN/RST seen)"` / `"Data only"` - not Wireshark's
  internal numeric bitmask, which isn't meaningfully portable to a
  from-scratch implementation).
- 32-bit sequence-number wraparound is handled via unsigned modular
  subtraction (`((seqNum - baseSeq) >>> 0)` is *not* correct across the
  wrap boundary in JS - must compute via
  `(seqNum - baseSeq + 2**32) % 2**32` using `Number`, since these values
  can exceed the safe range for naive bitwise ops).

### 2. Frame/Ethernet/IP metadata

- **Ethernet layer**: `Source`/`Destination` field values become
  `resolveMacVendor(mac)`'s formatted string; the layer summary line
  updates the same way. Raw MAC stays available (it's inside the formatted
  string, e.g. `"MicroStarINT_52:db:17 (04:7c:16:52:db:17)"`).
- **IP layer**, new fields inserted in Wireshark's field order:
  - `Differentiated Services Field` (parent field, hex value) with
    children `DSCP` and `ECN` (standard IETF RFC-2474/RFC-3168 codepoint
    names - CS0-CS7, AFxx, EF, Not-ECT/ECT(0)/ECT(1)/CE - these are
    IETF-standardized terms, not Wireshark-specific).
  - `Identification` (hex + decimal).
  - `Flags` (parent) with children `Reserved bit`, `Don't fragment`,
    `More fragments` (each a bit extracted from the flags/fragment-offset
    16-bit field).
  - `Fragment Offset`.
  - `Header Checksum` with a computed-and-verified
    `[Header checksum status: Correct/Incorrect]` child - this **actually
    validates** the checksum (standard ones'-complement sum over the
    header, cheap to compute) rather than showing "Unverified" the way
    Wireshark does by default (checksum offload makes Wireshark's live
    validation unreliable for locally-generated TX packets; NetView isn't
    subject to that same offload-blindness since it decodes whatever bytes
    the agent/pcap actually delivered, but it's worth watching for this
    to occasionally read "Incorrect" on synthetic/malformed captures - that
    is the correct/expected result there, not a bug).
  - `[Stream index]` (TCP only, reuses the same `streamId` already
    surfaced at the TCP layer).
- **Frame layer**, new fields: `[Time delta from previous captured frame]`
  (from the already-computed `timeDelta`), `[Time since reference or first
  frame]` (from the already-computed `relativeTime`), `[Protocols in
  frame]` (colon-joined lowercase layer names, computed from the `layers`
  array right before the function returns, since all layers are known by
  then).

### 3. ICMP echo request/reply correlation

- ICMP echo request/reply payloads carry a 2-byte identifier and 2-byte
  sequence number immediately after the 4-byte ICMP header (type/code/
  checksum) - not currently parsed at all. Parse both, plus format `ttl=`
  from the new `ttl` parameter, into the ICMP info string:
  `Echo (ping) request  id=0x0004, seq=351/24321, ttl=255`.
- `IcmpEchoTracker.recordRequest(id, seq, frameNumber)` is called when an
  echo *request* is decoded. `IcmpEchoTracker.matchReply(id, seq,
  replyFrameNumber)` is called when an echo *reply* is decoded; if a
  pending request matches, it returns that request's frame number.
- **Data flow differs by capture source, and this is the key risk in this
  phase:**
  - **Pcap import** (`PcapService.parsePcapFile`): the whole file is
    decoded into one local `parsedPackets` array before returning. When a
    reply matches a pending request, the request's already-built `Packet`
    object sitting earlier in that same array is patched directly
    (`parsedPackets[requestIndex].info += ...`). No React involved, no
    architectural conflict.
  - **Live capture** (`App.tsx`'s WebSocket handler): each packet is
    appended via `setPackets(prev => [...prev, safePkt])` as it arrives.
    When a reply's `matchReply()` call finds a pending request, the *same*
    state update needs to also patch that earlier packet by `id`:
    `setPackets(prev => prev.map(p => p.id === requestId ? { ...p, info: p.info + \` (reply in #${newId})\` } : p).concat(safePkt))`
    (exact shape to be finalized during implementation - the point is this
    touches `App.tsx`'s state-update pattern, not just `pcapParser.ts`).
  - If no reply ever arrives (packet loss, or the capture ends first), the
    request simply never gets the `(reply in N)` suffix - matches
    Wireshark's own behavior for unanswered pings.
- `IcmpEchoTracker` resets alongside `TcpStreamTracker`/`PacketGenerator` on
  buffer-clear, and a fresh instance is created per pcap import.

### 4. TCP Keep-Alive + options parsing

- **Prerequisite bug fix**: `decodeTransportLayer`'s TCP branch currently
  hardcodes the header length as 20 bytes everywhere (payload start,
  `Len=` calculation, the hostname-scan start offset from the earlier
  session's work). It must instead read the real header length from the
  Data Offset field (top 4 bits of the byte at `transportOffset + 12`,
  in 32-bit words: `headerLen = (byte >> 4) * 4`). Any packet that
  actually carries TCP options today has its payload boundary computed
  wrong - this is a real correctness bug independent of the options-parsing
  feature, and fixing it is a prerequisite for this item, not optional.
- When `headerLen > 20`, walk the options bytes starting at
  `transportOffset + 20`, recognizing: kind `1` (NOP, 1 byte, skip), kind
  `0` (End of Options), kind `2` (MSS, 4 bytes, 2-byte big-endian value),
  kind `3` (Window Scale, 3 bytes, 1-byte shift count), kind `4` (SACK
  Permitted, 2 bytes, no value), kind `5` (SACK blocks, variable length -
  each 8-byte block is a Left Edge/Right Edge pair), kind `8` (Timestamps,
  10 bytes - parsed for offset-walking correctness but not surfaced in the
  info string, since it wasn't in the screenshots). Unrecognized option
  kinds are skipped using their own length byte so the walk doesn't
  desync.
- Info string additions, matching Wireshark's exact ordering: SYN/SYN-ACK
  packets get ` MSS=1460 WS=256 SACK_PERM` appended when those options are
  present; any packet carrying SACK blocks gets ` SLE=x SRE=y` (repeated
  per block) appended instead.
- **Keep-Alive detection**: reuses `TcpStreamTracker`'s existing sequence
  tracking. A segment is a Keep-Alive when: payload length is 0 or 1 byte,
  it carries none of SYN/FIN/RST, and its sequence number is exactly one
  less than `getExpectedNext()` for that direction (i.e., it's
  re-sending the single already-ACKed last byte specifically to probe an
  idle connection - the standard TCP keepalive mechanism). Detected as a
  new `'keepalive'` outcome from `checkSequence()` (alongside the existing
  `'ok'`/`'retransmit'`/`'out-of-order'`), which prefixes the info string
  with `[TCP Keep-Alive]` instead of falling through to the retransmit
  path. The tracker also records that the last segment in that direction
  was a Keep-Alive so the plain ACK reply on the *other* direction can be
  labeled `[TCP Keep-Alive ACK]`.

## Testing / verification

Same approach as the earlier TCP-retransmission work in this session:
synthetic hand-built packets exercised via a throwaway `tsx` script,
covering at minimum:
- A TCP stream with a SYN carrying MSS/WS/SACK_PERM, confirming relative
  Seq/Ack start at 0/1 as expected and the options appear correctly in
  both the info string and the field tree.
- A Keep-Alive probe followed by its ACK, confirming both get labeled and
  neither is mis-flagged as a plain retransmission.
- A stream that includes real TCP options (so header length > 20),
  confirming the payload-boundary bug fix doesn't regress `Len=` or the
  hostname-scan logic from the earlier session.
- An ICMP echo request followed later by its matching reply, confirming
  both the pcap-import path (array patch) and the live-capture path
  (`setPackets` patch) correctly produce `(reply in N)` / `(request in N)`.
- An IPv4 header with a non-zero DSCP/ECN and a deliberately-corrupted
  checksum, confirming the new IP fields decode correctly and checksum
  validation reports `Incorrect` when it should.
- `npm run lint` (`tsc --noEmit`) clean, and a manual live-capture smoke
  test in the browser afterward (this session's dev agent connection is
  already available), the same way the retransmission work was verified
  end-to-end on real traffic.
