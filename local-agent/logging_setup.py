#!/usr/bin/env python3
"""
Logging for the NetView agent.

Once the agent runs as a service there is no console, so a file is the only
diagnostic channel that exists for either the user or a maintainer. This is
not optional polish - it is the entire observability story (see spec).
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

LOG_FILENAME = "agent.log"
# An agent running for months must not be able to fill a disk.
MAX_BYTES = 1_000_000
BACKUP_COUNT = 3

_configured = False


def setup_logging(directory, to_stderr=True, level=logging.INFO):
    """Configures and returns the shared `netview` logger.

    Idempotent: calling it twice returns the same logger without stacking
    duplicate handlers (which would print every line twice).
    """
    global _configured
    logger = logging.getLogger("netview")
    if _configured:
        return logger

    logger.setLevel(level)
    # propagate=False keeps these records out of the root logger, so a library
    # that configures logging.basicConfig() cannot double-print them.
    logger.propagate = False
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")

    try:
        os.makedirs(directory, exist_ok=True)
        file_handler = RotatingFileHandler(
            os.path.join(directory, LOG_FILENAME),
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:
        # An agent that cannot write its log must still run. When there is a
        # console this says so; under the SCM it is silently degraded, which
        # is still better than refusing to capture.
        if to_stderr:
            print(f"[agent] WARNING: cannot open log file in {directory}: {exc}", file=sys.stderr)

    if to_stderr:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    _configured = True
    return logger
