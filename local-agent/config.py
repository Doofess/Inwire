#!/usr/bin/env python3
"""
Where the NetView agent's settings live, and which browser origins may
connect to it.

Deliberately imports neither scapy nor websockets: this module is the one
piece of the auth path that can be exercised with plain assertions, with no
capture driver and no running server (see test_protocol.py).
"""

import json
import os

# Port 3000 covers both the Vite dev server (`vite --port=3000`) and the
# Express production server (server.ts, PORT || 3000); 4173 is Vite's preview
# default. `localhost` and `127.0.0.1` are *different origins* to a browser,
# so each port needs both spellings or one of them silently fails to connect.
DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]


def config_dir() -> str:
    """%ProgramData%\\NetView on Windows: readable by every user, writable
    only by administrators, and populated before anyone logs in - which a
    LocalSystem service needs, since it starts at boot with no user session.
    Falls back to ~/.netview elsewhere purely so this module stays importable
    for development on macOS/Linux."""
    if os.name == "nt":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(base, "NetView")
    return os.path.join(os.path.expanduser("~"), ".netview")


def config_path() -> str:
    return os.path.join(config_dir(), "config.json")


def normalize_origin(origin: str) -> str:
    """An origin's scheme and host compare case-insensitively, and a trailing
    slash is not part of an origin at all. Browsers send neither variation,
    but a hand-edited config file easily contains both - and a config typo
    that silently blocks every connection is exactly the failure this whole
    module is written to avoid."""
    return origin.strip().rstrip("/").lower()


def _defaults() -> dict:
    return {"allowedOrigins": list(DEFAULT_ALLOWED_ORIGINS)}


def parse_config(raw_text, on_warning=None) -> dict:
    """Turns config.json's contents into a settings dict.

    Every failure mode - unreadable JSON, wrong shape, missing key - falls
    back to DEFAULT_ALLOWED_ORIGINS instead of raising. A headless service
    that refuses every connection because of a stray comma, with no console
    to say so, is the worst outcome available here; running on defaults and
    logging a warning is strictly better.
    """
    def warn(message):
        if on_warning is not None:
            on_warning(message)

    if raw_text is None:
        return _defaults()

    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, TypeError, ValueError):
        warn("config.json is not valid JSON - using default allowed origins")
        return _defaults()

    if not isinstance(data, dict):
        warn("config.json is not a JSON object - using default allowed origins")
        return _defaults()

    origins = data.get("allowedOrigins")
    if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
        warn("config.json has no valid 'allowedOrigins' string list - using default allowed origins")
        return _defaults()

    return {"allowedOrigins": [normalize_origin(o) for o in origins]}


def load_config(on_warning=None) -> dict:
    """Reads and parses config.json, falling back to defaults if it is absent
    or unreadable."""
    try:
        with open(config_path(), "r", encoding="utf-8") as handle:
            return parse_config(handle.read(), on_warning=on_warning)
    except FileNotFoundError:
        # Not a warning: no config file is the normal state until someone
        # customizes one, and the installer only seeds it on Windows.
        return parse_config(None, on_warning=on_warning)
    except (OSError, ValueError) as exc:
        # ValueError catches UnicodeDecodeError, which is not an OSError: a
        # config.json saved in a non-UTF-8 encoding (e.g. Notepad's ANSI
        # default on Windows) must fall back to defaults like any other
        # unreadable file, not raise out of every caller - including the
        # origin gate, which re-reads this on every connection.
        if on_warning is not None:
            on_warning(f"could not read config.json ({exc}) - using default allowed origins")
        return parse_config(None, on_warning=on_warning)


def is_origin_allowed(origin, allowed_origins) -> bool:
    """A missing Origin header means a non-browser client, and is rejected.
    Browsers always send Origin on a WebSocket handshake, so its absence is
    never a legitimate NetView tab - only curl, a script, or a native process
    (see spec: Authentication)."""
    if not origin or not isinstance(origin, str):
        return False
    normalized = normalize_origin(origin)
    return any(normalized == normalize_origin(allowed) for allowed in allowed_origins)
