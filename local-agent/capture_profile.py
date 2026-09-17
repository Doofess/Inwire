"""Per-frame timing for the capture path.

There is no timing instrumentation anywhere in this project, so every claim
about what capture costs is an estimate. This is the smallest thing that turns
one number - the per-frame cost of the sniffer thread - into a measurement, so
a change to that path can be shown to have worked rather than asserted to.

**The interesting cost is not in the callback.** By the time `sniff_callback`
runs, the read is already over - the sniffer thread spent its time in libpcap
before it called us. Timing the callback body alone would measure the cheap end
and report that everything is fine.

So this measures both halves and reports them apart:

  wall / frames      what one frame costs the sniffer thread, end to end
  callback           what our own code costs inside it
  driver + read      the remainder, which is where the frame came from

That remainder is the number the capture path exists to reduce. Comparing it
before and after a change is the whole point of this module.

**What the remainder is depends on which branch of `sniff_on_interface` is
running, and this docstring used to name the wrong one.** It said
`sniff(prn=...)` hands the callback "a fully dissected scapy packet", so the
remainder was scapy building an Ether/IP/TCP object graph that
`packet_to_record` then discarded. That was true before 3.5.0 and is now the
*fallback*:

  pcap_next_ex       the fast path, and the one almost every capture takes.
                     `read_frame` goes straight to libpcap, so there is NO
                     scapy dissection at all and the remainder is the driver
                     read plus one `string_at` copy. This is the path
                     `read_frame`'s own 12x measurement is about.
  recv_raw           Linux AF_PACKET, which has no libpcap handle. A plain
                     `recvfrom` returning bytes; no dissection either.
  sniff(prn=...)     the last resort, for a socket that has not overridden
                     `recv_raw` and so reports no timestamp. THIS is the one
                     where the remainder is scapy.

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
            self._started = time.perf_counter()

    def frame(self, callback_seconds: float) -> None:
        """Records one frame and what our own callback cost for it."""
        if not self.enabled:
            return
        with self._lock:
            self._frames += 1
            self._callback_s += callback_seconds

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
            wall_s = time.perf_counter() - self._started
        if frames == 0:
            return {"frames": 0}
        per_frame_us = wall_s / frames * 1_000_000
        callback_us = callback_s / frames * 1_000_000
        return {
            "frames": frames,
            "wallSeconds": round(wall_s, 3),
            "perFrameUs": round(per_frame_us, 2),
            "callbackUs": round(callback_us, 2),
            # What is left once our own code is taken out: the driver read plus
            # scapy's dissection. The target of any change to this path.
            "driverAndDissectUs": round(per_frame_us - callback_us, 2),
            # Derived rather than measured: one thread, so this is what the
            # sniffer could sustain if nothing else ever blocked it.
            "impliedFramesPerSecond": int(1_000_000 / per_frame_us) if per_frame_us > 0 else 0,
        }

    def describe(self) -> str:
        """One log line, for the periodic report."""
        snap = self.snapshot()
        if snap is None:
            return "capture profiling is off"
        if snap["frames"] == 0:
            return "capture profile: no frames yet"
        return (
            "capture profile: {frames} frames, {perFrameUs} us/frame "
            # "driver+read", not "driver+dissect": on the pcap_next_ex path
            # there is no dissection in the remainder at all - see the module
            # docstring for which branch puts scapy back into it. The KEY keeps
            # its old name because test_protocol.py pins it by name; only the
            # words a person reads are corrected here.
            "({callbackUs} us in callback, {driverAndDissectUs} us driver+read), "
            "~{impliedFramesPerSecond} frames/s ceiling"
        ).format(**snap)
