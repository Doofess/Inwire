"""Per-frame timing for the capture path.

There is no timing instrumentation anywhere else in this project, so every
claim about what capture costs is an estimate. This is the smallest thing that
turns the sniffer thread's per-frame cost into a measurement, so a change to
that path can be shown to have worked rather than asserted to.

**The interesting cost is not in the callback.** By the time `sniff_callback`
runs, the read is already over - the sniffer thread spent its time in libpcap
before it called us. Timing the callback body alone would measure the cheap end
and report that everything is fine.

## The number this module used to report was the arrival rate

It reported `impliedFramesPerSecond = frames / wall`, and called it a ceiling.
It is not one, and it cannot be: **wall time includes every microsecond the
thread spent waiting for a frame that had not arrived yet.** On a quiet link
the number is small because the link is quiet; on a busy one it is larger for
the same reason. It can never exceed the rate traffic happened to arrive at, so
it can never tell you the thread could not keep up - which is the one question
it was being asked.

That mattered beyond this file. `packet_batch.py` cites a "~12,000 f/s driver
limit" derived from it, and every performance judgement made about the capture
path rested on the same arithmetic.

## What is measured now

Three quantities, kept apart, and a fourth derived from them:

  pcapUs        time inside the `pcap_next_ex` call, for reads that RETURNED a
                frame. **Mostly the wait on a quiet link**, and therefore not a
                cost - see below.
  copyUs        the `string_at` and the timestamp arithmetic that follow it.
                Ours, and always work.
  callbackUs    what our own code costs once it has the bytes.
  busyUs        `copyUs + callbackUs`: what one frame costs the thread in work
                we can account for.
  idleUs        arrival interval less `busyUs` - the headroom.

## Why the ceiling is not derived from `pcapUs`, and the second version of the
## same mistake

The first version of this module divided by wall-clock and called the result a
ceiling, which made it the arrival rate. The fix was to time the read instead -
and that was **still wrong at low rates**, because `pcap_next_ex` *blocks*
until a frame arrives or `to_ms` expires. A successful read on a quiet link is
mostly waiting, so the "cost" it reported was the gap between frames wearing a
different name.

Measured while finding this: a real 493 f/s adapter reported **1,439 us a
frame**, which is 1/493 of a second. It was reporting the link again.

So the call and the copy are timed apart. `sustainableFramesPerSecond` is
`1e6 / busyUs` and is an **upper bound**: it counts the work this code does and
cannot see the driver's own per-frame cost, which is only visible when frames
are arriving back to back. `utilisation` is `busyUs / arrivalPerFrameUs` and is
the number to read first - near 1.0 the sniffer thread is the bottleneck, and
well under it the bottleneck is elsewhere and no work here will move it.

`waitBound` is true when `pcapUs` is most of the arrival interval, which means
the thread spent its time waiting and **the driver's share of the cost was not
measurable from this sample**. A ceiling reported next to `waitBound: true` is
an upper bound with nothing under it; take the reading again under load.

**`readUs` is `None` on two of the three branches, and is never rounded to
zero.** `sniff_on_interface` has three, and only the fast one can be timed from
outside:

  pcap_next_ex       the fast path, and the one almost every capture takes.
                     `read_frame` is a call this module can bracket, so the
                     read is measured.
  recv_raw           Linux AF_PACKET. Also bracketable, also measured.
  sniff(prn=...)     the last resort, for a socket that has not overridden
                     `recv_raw`. The callback is invoked from **inside**
                     scapy's own loop, so there is no read for us to bracket:
                     `readUs` is `None` and `sustainableFramesPerSecond` is
                     `None` with it. An unmeasured half reported as 0 would
                     make this the fastest path in the table while being the
                     slowest one, which is the confident-wrong-answer failure
                     this codebase keeps writing down.

Read a measurement against the branch the log line named at capture start.

Off unless `INWIRE_PROFILE_CAPTURE` is set, and the disabled path is one
attribute read per frame - this sits on the hot path it is measuring, and an
observer that costs what it observes is not one.
"""
import os
import threading
import time


def profiling_enabled() -> bool:
    """True when INWIRE_PROFILE_CAPTURE is set to anything but a falsy word.

    An env var rather than a config key: this is a development instrument, and
    putting it in config.json would mean an installed service could be asked
    to carry timing overhead by a file edit, which is not a control anyone
    wants on a machine they are capturing from.
    """
    raw = os.environ.get("INWIRE_PROFILE_CAPTURE", "").strip().lower()
    return raw not in ("", "0", "false", "no", "off")


class CaptureProfile:
    """Accumulates per-frame timings for one capture.

    Locked, because there is one sniffer thread per adapter and they all report
    here. The lock is taken only while profiling is on; with it off, `frame()`
    returns before touching it.
    """

    def __init__(self, enabled: bool | None = None):
        self.enabled = profiling_enabled() if enabled is None else enabled
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        """Starts a fresh measurement. Called when a capture starts."""
        with self._lock:
            self._frames = 0
            self._callback_s = 0.0
            self._pcap_s = 0.0
            self._copy_s = 0.0
            # How many frames arrived by a branch that could time its own read.
            # Kept apart from `_frames` so a capture that ran on the fast path
            # and then fell back reports the read it actually measured rather
            # than one averaged over frames nobody timed.
            self._read_frames = 0
            self._started = time.perf_counter()

    def frame(self, callback_seconds: float, pcap_seconds: float | None = None,
              copy_seconds: float | None = None) -> None:
        """Records one frame: the callback, the pcap call, and the copy.

        `pcap_seconds` is `None` from the `sniff(prn=...)` branch, which has no
        read this module can bracket. Passing 0.0 there would be a measurement
        of something that was never measured.

        `copy_seconds` defaults to the call's own time for the `recv_raw`
        branch, where the library allocates the bytes itself and the two are
        genuinely the same operation.
        """
        if not self.enabled:
            return
        with self._lock:
            self._frames += 1
            self._callback_s += callback_seconds
            if pcap_seconds is not None:
                self._pcap_s += pcap_seconds
                self._copy_s += pcap_seconds if copy_seconds is None else copy_seconds
                self._read_frames += 1

    def snapshot(self) -> dict | None:
        """What has been measured so far, or None when profiling is off.

        Microseconds throughout, because a frame costs tens to hundreds of them
        and reporting milliseconds would round the answer away.
        """
        if not self.enabled:
            return None
        with self._lock:
            frames = self._frames
            callback_s = self._callback_s
            pcap_s = self._pcap_s
            copy_s = self._copy_s
            read_frames = self._read_frames
            wall_s = time.perf_counter() - self._started
        if frames == 0:
            return {"frames": 0}

        arrival_per_frame_us = wall_s / frames * 1_000_000
        callback_us = callback_s / frames * 1_000_000
        # Averaged over the frames whose read was actually timed, not over all
        # of them - see `_read_frames`.
        pcap_us = (pcap_s / read_frames * 1_000_000) if read_frames else None
        copy_us = (copy_s / read_frames * 1_000_000) if read_frames else None

        snap = {
            "frames": frames,
            "wallSeconds": round(wall_s, 3),
            # The interval between arrivals. NOT a cost and NOT a ceiling; this
            # is the quantity the old `perFrameUs` was, under a name that says
            # which one it is.
            "arrivalPerFrameUs": round(arrival_per_frame_us, 2),
            "arrivalFramesPerSecond": int(frames / wall_s) if wall_s > 0 else 0,
            "callbackUs": round(callback_us, 2),
            "pcapUs": round(pcap_us, 2) if pcap_us is not None else None,
            "copyUs": round(copy_us, 2) if copy_us is not None else None,
            "readFrames": read_frames,
        }

        if copy_us is None:
            # Nothing to add the callback to, so there is no honest ceiling and
            # no honest headroom. Both stay absent rather than being rounded
            # from a half that was never measured.
            snap["busyUs"] = None
            snap["idleUs"] = None
            snap["sustainableFramesPerSecond"] = None
            snap["utilisation"] = None
            snap["waitBound"] = None
            return snap

        # **The copy, not the call.** `pcap_next_ex` blocks until a frame
        # arrives, so including it would put the gap between frames back into
        # the per-frame cost - which is the mistake this module has now made
        # twice and must not make a third time.
        busy_us = copy_us + callback_us
        snap["busyUs"] = round(busy_us, 2)
        snap["idleUs"] = round(arrival_per_frame_us - busy_us, 2)
        snap["sustainableFramesPerSecond"] = int(1_000_000 / busy_us) if busy_us > 0 else 0
        # The first number to read. At 1.0 this thread is the bottleneck; well
        # under it, the bottleneck is downstream and work here buys nothing.
        snap["utilisation"] = (round(busy_us / arrival_per_frame_us, 3)
                               if arrival_per_frame_us > 0 else None)
        # **Waiting, not working**, and the test cannot be "the call took most
        # of the interval": under real saturation it does, because the thread
        # does nothing else. What separates the two is whether our own work is
        # anywhere near the call, and whether the thread is loaded at all.
        #
        #   waiting     pcap 10,000 us, work 300 us, utilisation 0.03
        #   saturated   pcap      2 us, work   4 us, utilisation 0.9
        #
        # So: the call dwarfs our work AND the thread is not near saturation.
        snap["waitBound"] = (pcap_us is not None
                             and busy_us > 0
                             and pcap_us > busy_us * 2
                             and snap["utilisation"] is not None
                             and snap["utilisation"] < 0.5)
        return snap

    def describe(self) -> str:
        """One log line, for the periodic report."""
        snap = self.snapshot()
        if snap is None:
            return "capture profiling is off"
        if snap["frames"] == 0:
            return "capture profile: no frames yet"
        if snap["sustainableFramesPerSecond"] is None:
            # The sniff(prn=...) branch. Says what it could not measure rather
            # than reporting a ceiling derived from half the cost.
            return (
                "capture profile: {frames} frames, arriving every "
                "{arrivalPerFrameUs} us (~{arrivalFramesPerSecond}/s), "
                "{callbackUs} us in callback; the read is not separable on this "
                "branch, so there is no ceiling to report"
            ).format(**snap)
        return (
            "capture profile: {frames} frames, arriving every "
            "{arrivalPerFrameUs} us (~{arrivalFramesPerSecond}/s); "
            "work {busyUs} us/frame ({copyUs} copy + {callbackUs} callback), "
            "pcap_next_ex {pcapUs} us{waited}, utilisation {utilisation}, "
            "ceiling <= ~{sustainableFramesPerSecond} frames/s"
        ).format(waited=" (mostly waiting)" if snap["waitBound"] else "", **snap)
