"""Per-interface traffic rates for the capture-interface picker's sparklines.

Wireshark's welcome screen draws a live sparkline beside every adapter so you
can tell which one is actually carrying traffic before you commit to capturing
on it. This produces the numbers behind that.

Deliberately NOT built on packet capture. Opening a capture handle on every
adapter to count frames would mean the agent sniffing all nine interfaces
whenever the menu is open - the exact always-on capture the agent is designed
not to do - and it would compete with the real capture for the same Npcap
buffers. The OS already maintains cumulative per-adapter counters; reading
them costs nothing, needs no elevation beyond what the agent already has, and
keeps working whether or not a capture is running.
"""
import psutil

# Windows embeds Unicode direction marks in localized adapter names, and they
# appear in both psutil's keys and scapy's labels. Stripping them is what makes
# the two comparable. (agent.py has its own copy of this for building labels;
# importing it here would be circular, and the constant is two characters.)
_RTL_MARKS = ("‎", "‏")


def _normalize(text: str) -> str:
    for mark in _RTL_MARKS:
        text = text.replace(mark, "")
    return text.strip()


def map_devices_to_nics(interfaces, nic_names) -> dict:
    """Maps capture device names to the OS counter keys for the same adapter.

    `interfaces` is the agent's [(device_name, label)] list, where device_name
    is an opaque capture path (`\\Device\\NPF_{GUID}` on Windows) and label is
    "{friendly name} ({driver description})". `nic_names` is what the counter
    source keys its results by, which is the friendly name alone.

    Matching is longest-prefix rather than exact because the label carries the
    driver description too, and longest-first because "Ethernet" is a prefix of
    "Ethernet 2" - shortest-first would map both adapters onto one counter.

    Adapters with no counterpart are simply absent from the result: Windows
    lists WAN Miniports as capture devices but keeps no counters for them, and
    a flat line is the honest rendering of an adapter nothing is known about.
    """
    normalized_nics = sorted(
        ((_normalize(nic), nic) for nic in nic_names),
        key=lambda pair: len(pair[0]),
        reverse=True,
    )

    mapping = {}
    for device_name, label in interfaces:
        clean_label = _normalize(label or "")
        for clean_nic, original_nic in normalized_nics:
            if clean_nic and clean_label.startswith(clean_nic):
                mapping[device_name] = original_nic
                break
    return mapping


class InterfaceRateSampler:
    """Turns the OS's cumulative counters into per-second rates.

    Holds the previous reading and differences against it, so the first sample
    after construction reports zero rather than reporting the machine's uptime
    total as if it had all arrived in one interval.
    """

    def __init__(self, interfaces, counter_source=None):
        # Injected so the tests can drive counters directly instead of waiting
        # on real traffic.
        self._counter_source = counter_source or (
            lambda: psutil.net_io_counters(pernic=True)
        )
        self._interfaces = list(interfaces)
        self._mapping = None
        self._previous = None
        self._previous_at = None

    def sample(self, now: float):
        """Returns [{name, packetsPerSec, bytesPerSec}] for every interface.

        `now` is a monotonic seconds value. Rates are computed against the
        actual elapsed time rather than the nominal interval, so a late tick
        reports the rate over the interval that really happened.
        """
        counters = self._counter_source()

        # Built on the first sample rather than at construction: an adapter
        # can appear after the agent starts, and the mapping is only knowable
        # once the counter source has been read at least once.
        if self._mapping is None:
            self._mapping = map_devices_to_nics(self._interfaces, counters.keys())

        elapsed = (now - self._previous_at) if self._previous_at is not None else 0.0
        results = []
        for device_name, _label in self._interfaces:
            nic = self._mapping.get(device_name)
            entry = counters.get(nic) if nic else None
            packets = bytes_total = 0.0

            if entry is not None and self._previous is not None and elapsed > 0:
                before = self._previous.get(nic)
                if before is not None:
                    now_packets = entry.packets_sent + entry.packets_recv
                    was_packets = before.packets_sent + before.packets_recv
                    now_bytes = entry.bytes_sent + entry.bytes_recv
                    was_bytes = before.bytes_sent + before.bytes_recv
                    # A counter that went backwards means it was reset (adapter
                    # disabled/re-enabled) or wrapped. Reporting the negative
                    # difference would draw a downward spike that never
                    # happened, so the interval is treated as unknown.
                    if now_packets >= was_packets and now_bytes >= was_bytes:
                        packets = (now_packets - was_packets) / elapsed
                        bytes_total = (now_bytes - was_bytes) / elapsed

            results.append({
                "name": device_name,
                "packetsPerSec": round(packets, 2),
                "bytesPerSec": round(bytes_total, 2),
            })

        self._previous = counters
        self._previous_at = now
        return results
