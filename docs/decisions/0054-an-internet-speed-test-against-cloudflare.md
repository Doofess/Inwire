# 0054 — An internet speed test, against Cloudflare, measured by our own engine

**Status:** accepted 2026-10-09; landed the same day. The owner asked for a
speed test "similar to Ookla", placed in the Network side panel with the dial
taking the workspace as a sheet. The research behind it is Part 2 of
`docs/ideas/network-monitoring-and-speed-test.md`.

## Context

A packet analyzer that can say *why* a link was slow first needs to say how
fast it is. The market's answers were studied in the research document; three
facts decide this one:

- **Ookla, fast.com and nPerf cannot be used.** None has a public API; Ookla's
  CLI is licensed for personal non-commercial use and embedding is a paid
  "Speedtest Custom" product. "Similar to Ookla" is therefore the experience -
  a GO, a dial, ping/download/upload - on another backend.
- **Cloudflare can.** `speed.cloudflare.com` serves `GET /__down?bytes=N` and
  takes `POST /__up`, no key. Its MIT library `@cloudflare/speedtest` posts
  every result to `/__results` by default, so the method is ported and the
  library is not shipped.
- **M-Lab NDT7 publishes every client's IP address permanently.** Out of scope
  here; if it comes, it comes as its own opt-in.

## Decision

**1. Cloudflare, one click per test, nothing kept anywhere but here.** The
host is recorded in `MAIN_OUTBOUND_HOSTS.speedTest` with its purpose and held
absent from the renderer's CSP (`scripts/electron/shell.ts`, which also holds
that the engine dials exactly that host and that the renderer's two calls carry
no argument). The press of Run or GO is the consent; the copy beside it says
Cloudflare sees this machine's address and that a test moves up to 800 MB.
History is a local preference (`inwire.speedTestHistory`), never uploaded, and
clearable from the sheet.

**2. Node's `https`, not `net.fetch`.** Chromium's stack may negotiate HTTP/3
with Cloudflare, which would put the test on QUIC where the capture's TCP
analysis cannot see it; Node speaks HTTP/1.1 over TCP.

**3. In its own `utilityProcess`, forked per test** (`electron/speedTest/`).
Measured before deciding: a 4-connection download from Cloudflare in Node held
the event loop **15 ms at p99 and 20 ms at worst** (`monitorEventLoopDelay`,
5 ms resolution, 560 Mb/s), because TLS is decrypted on the thread that runs
the JavaScript - and main's event loop pumps the capture pipe at up to
487 MB/s during exactly the burst a speed test causes. The process costs one
fork per test and gives the test a core of its own; main relays a dozen small
messages a second, unread.

**4. The method** (`src/services/speedTest/method.ts`, pure, held by
`scripts/speed-test/method.ts`):

| | |
|---|---|
| Idle latency | 21 empty requests on one warm connection, the first (the handshakes) dropped; the median, and jitter as the mean successive difference |
| Latency source | **the server's own TCP RTT** from `Server-Timing: cfL4 …rtt=<µs>`, idle and loaded alike; elsewhere time to first byte net of the server time it reports. Measured: TTFB net of `cfSpeedEdge`+`cfSpeedWorker` still read 5-15 ms over a 3 ms round trip |
| Transfers | download, then upload; 4 connections, +2 each second the total rose ≥10%, up to 8; 10 s each |
| Requests | 5 MB each - Cloudflare refuses a limited address its large requests first (5 MB answered 200 where 10 and 25 MB answered 429) |
| Caps | 600 MB down, 200 MB up - a 429 was measured after about a gigabyte in a few minutes |
| Figure | bytes in 100 ms slices, the first 2 s (slow start) and the partial last slice dropped, the **median** slice with p10/p90 kept |
| Loaded latency | an empty request every 150 ms on a connection of its own during each transfer |
| Bufferbloat | the grade from loaded minus idle: A+ <5 ms, A <30, B <60, C <200, D <400, F |
| Upload body | one random megabyte, repeated - incompressible, and TLS hides the repetition |

**5. The surfaces.** A *Speed test* section first in the Network panel (the
last result, Run, Results and history) and a second member of App's `sheet`
union, `'speedtest'`, by Settings' rules: it takes the workspace card, the view
underneath is untouched, the back step, Escape or any view leaves it, and
leaving does not stop a test - its state is a module store
(`services/speedTest/state.ts`), so App does not re-render at the dial's ten
updates a second. The rail gets nothing; it is full by design.

## Consequences

- **Cloudflare's limits are the product's limits.** A test from an address
  that has just tested may be refused; the sheet says so in those words with
  Try again, and the engine fails fast rather than waiting out the transfer.
- **A link faster than about 1 Gb/s reaches the cap in under five seconds**,
  and its figure is then the cap's.
- **The drives run against a loopback server.** `INWIRE_SPEEDTEST_TARGET`
  points the engine at `http://127.0.0.1:<port>` (loopback only, held by
  `shell.ts`), the precedent being `INWIRE_UPDATE_FEED`;
  `scripts/electron/speed-test-ui.ts` is in the gate on that basis, and
  `speed-test-drive.ts` runs the real thing by hand.

## Next

- **Tag the test's frames in the capture.** Main knows each test connection's
  timing; the capture can carry "speed test - download, connection 3/6".
- **Say why it was slow**, per connection, from the capture's TCP analysis:
  window-limited, loss-limited, bufferbloat, sender-limited, competing traffic.
- **LAN tests** against a host the user names (`iperf3 -s`), with Inwire as a
  client only - no listening port, and never one in the agent.
