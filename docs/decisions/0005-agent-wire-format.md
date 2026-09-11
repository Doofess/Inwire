# 0005 - Agent wire format: `seq`, `iface`, `ts_us`, `capture_stats`, ownership, token

> **Superseded in part by [0029](0029-the-app-and-the-agent-talk-over-a-named-pipe.md).**
> Everything here about the *messages* still stands and is untouched by the move
> off the WebSocket. Everything about **authentication** - the pairing token, the
> origin allowlist, and the peer verification this ADR anticipated - is gone on
> Windows, where the agent's only transport is a named pipe whose security
> descriptor names who may open it. Deleted rather than replaced: the kernel
> answers the question those were asked to answer. They remain in force on macOS
> and Linux, which still use the socket. This note is the one edit to an accepted
> ADR the convention allows - a pointer, changing nothing it says.

**Status:** Accepted 2026-09-04. Protocol version 3.1.0.

## Context

The packet message (`agent.py:405-429`) carries a fractional-ms `timestamp`, no
sequence number and no interface identity, so the browser cannot order across
interface threads and attributes every frame to the first selected adapter. Drops are
counted in the agent (`_dropped_sends`) and only logged. `state` is not broadcast.
Any local process can connect by supplying an `Origin` header.

## Decision

### Packet message (JSON, until Phase 11)

Added fields; the old ones remain until 3.2 so a 3.0 app still works against 3.1:

```json
{"type":"packet","seq":12345,"iface":0,"ts_us":1788477971653284,
 "orig_len":1514,"raw":"<base64>", "timestamp":1788477971653.284, ...}
```

- `seq`: uint64, one counter for the process, incremented under a `threading.Lock`
  in `sniff_callback`, starts at 0 on every `start_capture`.
- `iface`: index into `hello.interfaces` / the last `state.interfaces`; those lists
  gain a stable `"id"` (index) and keep `name`/`label`.
- `ts_us`: integer epoch microseconds from `pkt.time`. `timestamp` is derived from
  it and deprecated.
- `orig_len`: wire length; `raw` may be shorter if a snaplen is ever applied.

### `capture_stats` (agent -> app, once per second while sniffing)

```json
{"type":"capture_stats","iface":0,"received":10234,"dropped_kernel":12,
 "dropped_agent":300,"seq_high":10233}
```

`received` and `dropped_kernel` come from `pcap_stats` on the interface's capture
socket when scapy exposes it (`conf.L2listen` -> `.ins` pcap handle on Windows/libpcap
backends); otherwise `dropped_kernel` is `null`, never 0. `dropped_agent` is the
send-queue counter, reset per capture. The app reports both in Driver Info and adds an
expert Note at the first frame after each increase.

### `state` (agent -> app)

Broadcast on every `start_capture`, `stop_capture`, `set_interfaces`, and on capture
failure; carries `state`, `interfaces` (with ids), `owner` (connection id or null).

### Errors

`error.code` is a closed set the app switches on: `empty_interfaces`,
`restart_unavailable`, `capture_failed` (with `iface`, `message`),
`capture_busy`, `unknown_command`, `unauthorized`.

### Capture ownership

The connection that sends `start_capture` owns the capture. `stop_capture` and
`set_interfaces` from another connection get `capture_busy` unless the owner has
disconnected. Packets and `capture_stats` go only to the owner and to connections that
sent `subscribe_packets`. `hello` reports the owner so a reconnecting tab can reclaim
(it presents the `capture_id` it was given).

### Authentication

The installer writes `"token": "<32 random bytes, base64url>"` into `config.json`
(admin-readable only; `[Dirs]` gets explicit permissions). Clients send it as the
WebSocket subprotocol `inwire.v1.<token>`; a missing or wrong token is rejected at the
handshake with 401 before `hello`. The app learns the token once through the
`inwire://token/<...>` handler the installer already registers, or by paste in Driver
Info, and stores it in localStorage. Origin allowlist stays as a second check. Ships
in Phase 2b; the agent accepts token-less connections from allowed origins with a
warning until the app side lands, then 3.2.0 makes it mandatory.

### Binary batching (Phase 11, protocol 3.2.0)

Text frames stay control-only. Binary frames:

```
u8  version=1
u32 count
per frame: u64 ts_us | u32 seq | u8 iface | u32 orig_len | u32 incl_len | bytes[incl_len]
```

Flushed every 20 ms or 256 frames. The app decodes a batch into one `ArrayBuffer` and
hands `DissectInput` views to the Worker without copying.

## As implemented (3.1.0, 2026-09-04)

Field names follow the existing wire's camelCase rather than the snake_case
sketched above: `seq`, `iface`, `tsUs`, `origLen` on a packet; `capture_stats`
carries `intervalMs`, `seqHigh`, `droppedAgent` and one entry per interface
`{iface, received, kernelReceived, droppedKernel}` (the kernel pair is `null`,
never 0, when `pcap_stats` is unreadable). Interface entries carry `id`. Errors
add `invalid_interfaces`. Capture ownership and the token are Phase 2b.

## As implemented (3.2.0, 2026-09-04, Phase 11)

The batch is as sketched, with three changes made while writing it:

```
'IWP1' | u8 version=1 | u8 flags | u16 count
per frame: u32 seq | u16 iface | u16 pad | f64 tsUs | u32 origLen | u32 capLen | bytes
```

- **A magic tag**, so a decoder can tell a batch from a JSON control message and
  refuse anything it does not recognise rather than reading it hopefully.
- **`tsUs` as f64, not u64.** Epoch microseconds are exact in a double until the
  year 2255, and a double is what both ends already hold the value as - a u64
  would mean a BigInt on the browser side and a conversion per frame.
- **A record carries no metadata at all.** The source, destination, protocol,
  ports and info the JSON message sent were overwritten before they were ever
  displayed: whenever the bytes are present the browser dissects them itself.
  Sending them was a third of the message for a value of nothing.

Flushed every 10 ms or 512 frames, whichever comes first. Measured on the
`inwire` fixture (`scripts/perf/wire-size.ts`): **23.7 MB of JSON becomes 15.4 MB
of binary, and 12,858 WebSocket messages become 26.** The scheduling change
matters more than the bytes - the agent used to schedule one coroutine per
captured frame, which is what its log records as ">=260,000 packets dropped: the
client is not keeping up".

The mandatory token stays in Phase 2b: it is an authentication change, and
shipping it in the same version as the frame format would have meant one version
bump that could fail for two unrelated reasons.

## Consequences

- Three-place version lock: 3.1.0 for the JSON additions and ownership; 3.2.0 for
  binary frames. The token moves the lock again when Phase 2b lands.
- `verify_protocol.py` grows checks for `state` on every command, `capture_stats`
  while sniffing, `capture_busy` from a second client, and 401 without a token.
