# 0054 — An internet speed test, against Cloudflare, measured by our own engine

**Status:** accepted 2026-10-09; landed the same day. The owner asked for a
speed test "similar to Ookla", placed in the Network side panel with the dial
taking the workspace as a sheet. The research behind it is Part 2 of
`docs/ideas/network-monitoring-and-speed-test.md`. **Amended 2026-10-15**: the
dial is gone - see *Amendment: latency under load* below.

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
Cloudflare sees this machine's address and that a test moves up to 2 GB.
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
| Transfers | download, then upload; **12 connections** from the start, +2 each half second the total rose ≥5%, up to 24; 10 s each |
| Requests | 5 MB each - Cloudflare refuses a limited address its large requests first (5 MB answered 200 where 10 and 25 MB answered 429) |
| Caps | **1.6 GB down, 400 MB up** - "up to 2 GB" in the consent line; a 429 was measured after about a gigabyte in a few minutes, and the engine fails fast and says so |
| Figure | bytes in 100 ms slices, the first **1.5 s** (slow start) and the partial last slice dropped, the **median** slice with p10/p90 kept; uploads counted per 16 KB write |
| Jitter | the server's `rtt_var` from `cfL4` (RFC 6298's RTTVAR) - the `rtt` beside it is smoothed, and successive values read 0.0 ms |
| Loaded latency | an empty request every 150 ms on a connection of its own during each transfer |
| Bufferbloat | the grade from loaded minus idle: A+ <5 ms, A <30, B <60, C <200, D <400, F |
| Upload body | one random megabyte, repeated - incompressible, and TLS hides the repetition |

**5. The surfaces.** A *Speed test* section first in the Network panel (the
last result, Run, Results and history) and a second member of App's `sheet`
union, `'speedtest'`, by Settings' rules: it takes the workspace card, the view
underneath is untouched, the back step, Escape or any view leaves it, and
leaving does not stop a test - its state is a module store
(`services/speedTest/state.ts`), so App does not re-render at the test's ten
updates a second. The rail gets nothing; it is full by design.

## Measured against Ookla, on the owner's machine (2026-10-09)

The owner ran Ookla on the same machine (Intel I225-V, 2.5 GbE, Bezeq) and
called the first build's figures "very different". They were, and most of the
difference was ours:

| | download Mb/s | upload Mb/s | ping ms (idle / loaded ↓ / loaded ↑) |
|---|---|---|---|
| Ookla, Bezeq International, Petah Tikva (on-net), "Multi" | 2,157.20 | 251.67 | 1 / 10 / 8 |
| Inwire, first build (4→8 connections, 600 MB cap) | 1,507 | 241 | 1.8 / 3.2 / 4.6 |
| Inwire, 6 connections (experiment) | 1,866 | 230 | 2.2 / 7.3 / 23.8 |
| Inwire, 12 connections (experiment) | 2,106 | 236 | 2.0 / 4.7 / 19.8 |
| **Inwire as built, three runs in the app** | **2,133 · 2,087 · 2,083** | **241.2 · 241.2 · 241.2** | 2.7 · 2.0 · 1.8 / 8.2 · 7.3 · 8.5 / 21 · 17 · 26 |

- **The engine was never the ceiling.** Against a loopback server in its own
  process it counts 11.6 Gb/s down and 15.2 up over plain HTTP, 7.1-8.0 down
  and 9.3-9.4 up over TLS - three times the link. Main's event loop sat at its
  15.6 ms timer floor through every real test (p99 16.5 ms): the test's own
  process is doing the TLS.
- **The method was.** The 600 MB cap ended a 2 Gb/s download at 3.4 s,
  fourteen slices past warm-up, and the ramp (from 2 s, every second, +10%) had
  not fired - the whole download ran on four connections. The ramp alone could
  not fix it: on a fast link one half second differs from the next by noise,
  not by 5%. So a transfer opens on twelve.
- **What is left is the route, and it is genuine.** Ookla chose a server inside
  Bezeq, a millisecond away; this test crosses from Bezeq to Cloudflare's Tel
  Aviv data centre, 2 ms away. The results carry a hint saying so on demand,
  *Comparing with another test?*, rather than a banner.
- **The three identical uploads were a unit, not a coincidence**: counted per
  64 KB write, a 100 ms slice moved in steps of 5.24 Mb/s and 241.2 is 46 of
  them. Counted per 16 KB write now.
- **speed.cloudflare.com in a browser could not be driven**: its Turnstile
  check refuses an automated browser ("Verification failed"), and getting round
  a bot check is not something this build does. The owner can run it by hand
  for the third column.

## The server on the globe, the colours, the ISP

- **The latest test's data centre is on the Routing Map** as a labelled chip -
  *Speed test · Cloudflare Tel Aviv*, the result on hover - with an arc from
  this machine's network when the map knows where that is. Placed from the
  test itself: `/meta`'s own coordinates, or the colo code against a table of
  Cloudflare's 309 data centres generated from its `/locations`
  (`scripts/speed-test/gen-colos.ts`), used by the engine's process only. No
  lookup, nothing new outbound; a server neither places has no pin, and the
  results say *Server location unknown*. **An overlay, not traffic**: read
  from history, never from `packets`, the arc joining the arc layer only at its
  final `setArcs` - in no route, pin, count or export
  (`scripts/speed-test/map-overlay.ts`). A DOM marker, so `setStyle` and a lost
  GPU context leave it standing; the arc rides the routes' own re-add
  (`gpu-restore-drive.ts` passes). *Show the server on the map* opens the map
  and flies there, jumping under reduced motion.
- **Upload is purple, download the accent**, as speed tests draw them: tokens
  `--speed-download` (held equal to `--primary`) and `--speed-upload` in both
  theme blocks, measured by `scripts/themes/registry.ts` - #7c3aed on Day
  (5.70:1 on a card, 5.32 on the ground), #c084fc on Night (7.76, 7.95). The
  dial changed colour in 250 ms as it reset (gone since the amendment
  below); arrows and labels stay, so colour is never the only signal.
- **The ISP stands beside the server** - "Cloudflare · Tel Aviv (TLV) —
  Bezeq" - in the running view, the results, each history row, the panel and
  the globe's tooltip: Cloudflare's own AS organisation for this address, from
  `/meta`, and nothing when it is absent.

## Consequences

- **Cloudflare's limits are the product's limits.** A test from an address
  that has just tested may be refused; the sheet says so in those words with
  Try again, and the engine fails fast rather than waiting out the transfer.
- **A link faster than about 2.5 Gb/s reaches the download cap in under five
  seconds**, and its figure stands on fewer slices; still past warm-up.
- **A test moves up to 2 GB.** Cloudflare's rate limit means a second test
  straight after the first can be refused; the sheet says so.
- **The drives run against a loopback server.** `INWIRE_SPEEDTEST_TARGET`
  points the engine at `http://127.0.0.1:<port>` (loopback only, held by
  `shell.ts`), the precedent being `INWIRE_UPDATE_FEED`;
  `scripts/electron/speed-test-ui.ts` is in the gate on that basis, and
  `speed-test-drive.ts` runs the real thing by hand.

## Amendment: latency under load (2026-10-15)

The owner called the dial "too generic and generated", and it was: a consumer
gauge answering "how fast", where the question a network person brings is *how
does this link behave when it is busy?* The sheet is now laid out as an
instrument, top to bottom (`components/speedtest/`):

- **A phase strip** - connect, ping, download, upload - lit as the test moves.
- **The headline**: download and upload as two figures, and under them
  responsiveness in RPM with its band and the bufferbloat grade.
- **Latency under load**, the centrepiece: one box per phase - idle,
  downloading, uploading - on a shared **log** axis, because idle at 2 ms
  beside upload at 26 ms is a 2 px box on a linear one. The grade's band
  edges (5, 30, 60, 200, 400 ms of rise) are ticks on that axis, and a bracket
  from the idle median to the worse loaded one says "+N ms under load", which
  is exactly the input the grade is computed from.
- **A throughput trace per direction**: the raw 100 ms slices as a step line,
  the warm-up shaded and labelled *not counted*, the previous run behind it as
  a ghost, and the loaded-latency probes as dots on the same time axis, so a
  spike lines up with the slice it hit.
- **A footer**: the change against the previous test, connections used, the
  server with *Show on map*, and Test again.

Four decisions inside that, each of which a later session could reasonably
undo:

- **The headline stays the median.** It is what *Measured against Ookla*
  above calibrated, so a run here still reads beside Ookla's number. The P90
  of the slices and the mean (bytes over time past the warm-up) are cursors on
  the trace, never the headline - a P90 headline would read 10-20% above every
  other tester and look like a bug in the other direction.
- **RPM is labelled "Responsiveness (approx.)"**. `rpm()` is a minute over
  the median loaded round trip of one empty request on a warm connection;
  Apple's `networkQuality` and the IETF responsiveness draft
  (draft-ietf-ippm-responsiveness) count every round trip a fresh request
  makes. The bands are theirs - **Low under 300, Medium 300-1000, High over
  1000** (`RPM_BANDS` in `services/speedTest/method.ts`) - and nothing here
  says "as Apple computes it".
- **The boxes are drawn from client-side time to first byte; the figures and
  the grade from the server's RTT.** `cfL4`'s `rtt` is the server's smoothed
  estimate, which is the right number to grade on - the grade compares medians
  and smoothing does not move one - and the wrong one to draw a spread from:
  it compresses the quartiles toward the median until every box is a line.
  Each probe now records both (`LatencySample`), and the summary in
  `SpeedResult` is built by the engine, so a run nobody watched still has it.
- **The trace's y scale ignores the warm-up.** A first slice that bursts while
  TCP's window opens would otherwise set a scale that flattens the ten seconds
  that count. The warm-up is still drawn; it just does not size the plot.

History gained optional fields (`rpm`, `loadedDownMs`, `loadedUpMs`) under the
same key with no version bump, so an entry from before reads "–", never 0. The
last run's trace is kept under its own key so the ghost survives a restart.
`scripts/speed-test/stats.ts`, `state.ts` and `speed-test-ui.ts` hold the
summaries, the reducer and the sheet; `GAUGE_MARKS` and `gaugeFraction` went
with the dial.

## Next

- **Tag the test's frames in the capture.** Main knows each test connection's
  timing; the capture can carry "speed test - download, connection 3/6".
- **Say why it was slow**, per connection, from the capture's TCP analysis:
  window-limited, loss-limited, bufferbloat, sender-limited, competing traffic.
- **LAN tests** against a host the user names (`iperf3 -s`), with Inwire as a
  client only - no listening port, and never one in the agent.
