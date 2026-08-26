#!/usr/bin/env python3
"""
Turning the agent's own log into something a browser can display.

The agent runs as a LocalSystem service writing to
%ProgramData%\\NetView\\agent.log, a path no browser page can read. This
module holds the two halves of getting those lines onto the WebSocket -
reading the tail of the file for backlog, and a logging.Handler that
forwards each new record live - with no reference to the socket or to
agent.py's globals, so all of it is testable on its own.
"""

import logging
import os
import re
import threading

# Mirrors logging_setup's formatter, "%(asctime)s %(levelname)-7s %(message)s":
#   2026-08-26 22:14:02,123 INFO    client connected (1 total)
#
# Everything after the level is captured raw, because the separator's width
# is not fixed and cannot be matched greedily. levelname is left-justified to
# LEVEL_FIELD_WIDTH and then followed by one literal space, so "INFO" is
# trailed by four spaces while "CRITICAL" - which overflows the field - is
# trailed by one. Consuming that run with \s+ would also swallow a message's
# own leading indentation, and agent.py logs indented lines on purpose (the
# per-interface lines at startup). parse_log_line strips exactly the
# computed width instead, which is reversible; a greedy match is not.
LOG_LINE_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) "
    r"(?P<level>[A-Z]+)"
    r"(?P<rest>.*)$"
)

# The `-7` in logging_setup's "%(levelname)-7s".
LEVEL_FIELD_WIDTH = 7

BACKLOG_LINES = 200
# Rotation lets agent.log reach 1 MB; a subscriber needs the recent end of
# it, and the socket should not carry the rest.
BACKLOG_BYTES = 65536


def parse_log_line(raw):
    """One raw line of agent.log -> one protocol log entry.

    A line that does not match the formatter's shape - a traceback
    continuation line, most often - is not dropped. It comes back with
    time and level None and its text preserved, because the lines
    around a crash are precisely the ones worth reading.
    """
    match = LOG_LINE_RE.match(raw)
    if match is None:
        return {"time": None, "level": None, "message": raw}
    level = match.group("level")
    # The padding the formatter added, plus its one literal separator space.
    # max(0, ...) because a level longer than the field (CRITICAL) is not
    # padded at all, and a negative slice offset would eat real characters.
    separator_width = max(0, LEVEL_FIELD_WIDTH - len(level)) + 1
    return {
        "time": match.group("time"),
        "level": level,
        "message": match.group("rest")[separator_width:],
    }


def read_log_tail(path, max_lines=BACKLOG_LINES, max_bytes=BACKLOG_BYTES):
    """The last `max_lines` lines of the log file, oldest first.

    Every failure mode returns [] rather than raising: a missing or
    unreadable log must not stop a client subscribing, it just means the
    panel starts empty and fills from live lines instead.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                # That seek almost certainly landed mid-line. Without this
                # read, the first entry would be a truncated fragment
                # displayed as though it were a whole line.
                fh.readline()
            data = fh.read()
    except OSError:
        return []

    # errors="replace" rather than a decode failure: a single bad byte
    # anywhere in the window must not cost the user their whole backlog.
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


# A bare Formatter purely for its formatTime(): with no datefmt it produces
# "%Y-%m-%d %H:%M:%S,%03d", byte-identical to what logging_setup writes into
# the file, so backlog entries and live entries carry the same time format.
_TIME_FORMATTER = logging.Formatter()


class WebSocketLogHandler(logging.Handler):
    """Forwards every log record to `sink` as a protocol log entry.

    Installed on the `netview` logger, this delivers each line the instant
    it is logged - no polling, no file-position bookkeeping, and nothing a
    RotatingFileHandler rollover mid-session can desync. It also keeps
    working when the log file itself is unwritable, which is the case where
    seeing the log matters most.

    `sink` is expected to be cheap and non-blocking: the real one returns
    immediately when nobody is subscribed.
    """

    def __init__(self, sink, level=logging.INFO):
        super().__init__(level)
        self.sink = sink
        # Thread-local rather than a plain attribute: sniffer threads log
        # concurrently with the asyncio loop, and one shared flag would let
        # one thread's guard swallow another thread's legitimate line.
        self._local = threading.local()

    def emit(self, record):
        # Any log call reachable from the sink re-enters emit(), which calls
        # the sink again, unboundedly. Nothing on today's send path logs, but
        # one warning added there later would produce an infinite loop with
        # no obvious cause. This makes that structurally impossible instead
        # of relying on nobody ever adding it.
        if getattr(self._local, "emitting", False):
            return
        self._local.emitting = True
        try:
            self.sink({
                "time": _TIME_FORMATTER.formatTime(record),
                "level": record.levelname,
                "message": record.getMessage(),
            })
        except Exception:
            # A logging handler must never raise into the code that logged.
            # handleError already no-ops when there is no stderr, which under
            # the console=False service build is always.
            self.handleError(record)
        finally:
            self._local.emitting = False
