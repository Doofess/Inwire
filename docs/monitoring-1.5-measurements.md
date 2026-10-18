# Monitoring milestone 1.5: segment measurements

What splitting the monitoring journal into segments costs on this machine,
measured for ADR [0062](decisions/0062-monitoring-segments-retention-archive.md)
before any of it is built, and the adoption time
[0061](decisions/0061-monitoring-dataset-location-adoption-discard.md) quotes.
Every number is a property of the machine it ran on.
`npx tsx scripts/monitoring/measurement.ts segments` reproduces them, writing
about 10 GB to the OS temp folder and deleting it; `--quick` writes about
1.5 GB. The script is in `check.ts`'s `NOT_TESTS` for that reason.

**Not run is not passed.** What this report would like to say and could not
measure is listed under **Not run**.

## The machine and the traffic

The machine is the one in
[`monitoring-v5-measurements.md`](monitoring-v5-measurements.md#the-machine):
Windows 11 Pro 10.0.26300, not elevated, Node 26.8.1, 31.7 GB of RAM; the
files went to the OS temp folder on the system disk. Journals are written by the product's own `MonitoringJournal`
over `NodeBlockFile`, not by a prototype. Each one starts with a `start`
boundary, then holds generated v5 datagrams from the same `TrafficModel` at the
planning point of 7 datagrams a second, filed under synthetic receipt times.

## One segment: how long an open takes

An open is milestone 1's recovery scan: every entry header read and every CRC
checked (ADR 0059).

| Segment | Entries | Traffic it holds | Open | Rate |
|---|---|---|---|---|
| 64 MiB | 47,392 | 1.88 h | 159 ms | 402 MiB/s |
| **256 MiB** | **189,281** | **7.34 h** | **622 ms** | **411 MiB/s** |
| 1 GiB | 756,788 | 29.16 h | 2,363 ms | 433 MiB/s |

The rate barely moves with size, so the open cost of a dataset is set by its
bytes, not by how they are cut into files. Size is chosen for the other
costs: how much evidence one expiry removes at a time, and how many files a
dataset holds.

## Many segments: the cost of a file

Opening, reading the header and closing a file, over files holding one entry
each, so the bytes are negligible:

| Files | Header reads | Per file | Full recover of each |
|---|---|---|---|
| 1 | 0.59 ms | 588 µs | 0.7 ms |
| 32 | 9.30 ms | 291 µs | 21.1 ms |
| 64 | 17.96 ms | 281 µs | 41.0 ms |
| 256 | 65.78 ms | 257 µs | 159.9 ms |

At 256 MiB a segment, the 8 GiB default is 32 files, and their headers cost
about 9 ms. Even 256 files, a 1 MiB segment's worth of a small limit, cost
a sixth of a second.

## Rolling to a new segment

Creating the file, writing its header and flushing: a mean of **0.99 ms**, the
worst **1.18 ms**, over the rolls the 256 MiB run made. The measurement wrote
milestone 1's 64-byte header; 0062's is 128 bytes, which is the same single
write.

## Expiring one segment

One 256 MiB segment holds 7.3 hours, 440 minutes. Expiring it means writing
its minutes to the archive and deleting the file. The archive's minutes were
sized at ADR 0059's measured 59 MiB of deflated rollups a day, so 18.0 MiB for
these 440 minutes.

| Step | Time |
|---|---|
| archive append and flush, 18.0 MiB | 52 ms |
| unlink the segment | 14.3 ms |

The archive bytes are a stand-in of the right size, not rollups the Worker
computed. Computing them is a replay of the segment, which ADR 0059 measured
as a streamed rebuild: a day in 18.0 s, so about 5.5 s for a segment's 7.3
hours.

## Adopting the 8 GiB default

32 segments of 256 MiB, 8.00 GiB and 6,057,024 entries, recovered one after
another: **20.3 s, 403 MiB/s**. `LIMITS.openScanBytesPerSecond` assumes
64 MiB/s, which allows 128 s, so the bound holds with room. The files had just
been written, so the OS cache was warm; see **Not run**.

## What this decided

- **Segment size is `clamp(limit / 32, 1 MiB, 256 MiB)`.** At the 8 GiB
  default that is 256 MiB and 32 files. At the 16 MiB minimum it is 1 MiB, so
  even the smallest limit has segments to expire. A larger segment would open
  no faster per byte and would make each expiry remove more evidence at once.
- **Expiry is cheap next to its replay.** Archive and unlink take tens of
  milliseconds; the replay that computes the minutes is the cost, a few
  seconds a segment, and it runs in the Worker.
- **Adoption needs no new bound.** The existing open-scan limit already covers
  8 GiB.

## Not run

- **Adoption from a cold disk.** The 20.3 s ran with the segments in the OS
  cache. A dataset adopted after a reboot, or from a slower or removable disk,
  reads from the device. The 64 MiB/s bound is what the sheet's progress and
  timeout assume until this is measured.
- **Expiry with real rollups.** The archive write used bytes of the measured
  size, not Worker output; the end-to-end expiry is measured when it is built.
- **A dataset on a network folder.** The chooser allows any folder the user
  can write; a network path's open and flush latency is unmeasured.
