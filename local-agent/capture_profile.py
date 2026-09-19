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

  readUs        time inside `read_frame`, accumulated **only for reads that
                returned a frame**. The handle is opened with `to_ms=100`, so a
                timeout return is the thread idling, not working, and counting
                it would inflate the cost of a quiet link until it looked like
                the expensive one.
  callbackUs    what our own code costs once it has the bytes.
  busyUs        the two together: what one frame actually costs the thread.
  idleUs        arrival interval less `busyUs` - the headroom.

`sustainableFramesPerSecond` is `1e6 / busyUs`, and THAT is the ceiling: what
this thread could do if frames never stopped arriving. `utilisation` is
`busyUs / arrivalPerFrameUs`, which is the number to read first - at 1.0 the
sniffer thread is the bottleneck, and well under it the bottleneck is
somewhere else and no amount of work here will move it.

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
            self._read_s = 0.0
            # How many frames arrived by a branch that could time its own read.
            # Kept apart from `_frames` so a capture that ran on the fast path
            # and then fell back reports the read it actually measured rather
            # than one averaged over frames nobody timed.
            self._read_frames = 0
            self._started = time.perf_counter()

    def frame(self, callback_seconds: float, read_seconds: float | None = None) -> None:
        """Records one frame, what our callback cost, and what the read cost.

        `read_seconds` is `None` from the `sniff(prn=...)` branch, which has no
        read this module can bracket. Passing 0.0 there would be a measurement
        of something that was never measured.
        """
        if not self.enabled:
            return
        with self._lock:
            self._frames += 1
            self._callback_s += callback_seconds
            if read_seconds is not None:
                self._read_s += read_seconds
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
            read_s = self._read_s
            read_frames = self._read_frames
            wall_s = time.perf_counter() - self._started
        if frames == 0:
            return {"frames": 0}

        arrival_per_frame_us = wall_s / frames * 1_000_000
        callback_us = callback_s / frames * 1_000_000
        # Averaged over the frames whose read was actually timed, not over all
        # of them - see `_read_frames`.
        read_us = (read_s / read_frames * 1_000_000) if read_frames else None

        snap = {
            "frames": frames,
            "wallSeconds": round(wall_s, 3),
            # The interval between arrivals. NOT a cost and NOT a ceiling; this
            # is the quantity the old `perFrameUs` was, under a name that says
            # which one it is.
            "arrivalPerFrameUs": round(arrival_per_frame_us, 2),
            "arrivalFramesPerSecond": int(frames / wall_s) if wall_s > 0 else 0,
            "callbackUs": round(callback_us, 2),
            "readUs": round(read_us, 2) if read_us is not None else None,
            "readFrames": read_frames,
        }

        if read_us is None:
            # Nothing to add the callback to, so there is no honest ceiling and
            # no honest headroom. Both stay absent rather than being rounded
            # from a half that was never measured.
            snap["busyUs"] = None
            snap["idleUs"] = None
            snap["sustainableFramesPerSecond"] = None
            snap["utilisation"] = None
            return snap

        busy_us = read_us + callback_us
        snap["busyUs"] = round(busy_us, 2)
        snap["idleUs"] = round(arrival_per_frame_us - busy_us, 2)
        snap["sustainableFramesPerSecond"] = int(1_000_000 / busy_us) if busy_us > 0 else 0
        # The first number to read. At 1.0 this thread is the bottleneck; well
        # under it, the bottleneck is downstream and work here buys nothing.
        snap["utilisation"] = (round(busy_us / arrival_per_frame_us, 3)
                               if arrival_per_frame_us > 0 else None)
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
            "cost {busyUs} us/frame ({readUs} read + {callbackUs} callback), "
            "idle {idleUs} us, utilisation {utilisation}, "
            "ceiling ~{sustainableFramesPerSecond} frames/s"
        ).format(**snap)
