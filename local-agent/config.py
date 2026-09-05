#!/usr/bin/env python3
"""
Where the Inwire agent's settings live: which browser origins may connect to
it, and the pairing token a connection has to present.

The two are different kinds of control and both are here. An origin is a
header the client chooses, so it keeps an ordinary page from reaching the
agent but stops nothing that can set a header - which is any local process.
The token is a secret in a file only an administrator can read, so it is the
control that actually distinguishes the user's browser from another program
running as the user.

Deliberately imports neither scapy nor websockets: this module is the one
piece of the auth path that can be exercised with plain assertions, with no
capture driver and no running server (see test_protocol.py).
"""

import hmac
import json
import os
import secrets
import shutil
import subprocess

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
    """%ProgramData%\\Inwire on Windows: populated before anyone logs in -
    which a LocalSystem service needs, since it starts at boot with no user
    session. Inherits ProgramData's default ACLs, which typically restrict
    writes to administrators, though nothing here enforces that itself.
    Falls back to ~/.inwire elsewhere purely so this module stays importable
    for development on macOS/Linux."""
    if os.name == "nt":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(base, "Inwire")
    return os.path.join(os.path.expanduser("~"), ".inwire")


def config_path() -> str:
    return os.path.join(config_dir(), "config.json")


def legacy_config_dir():
    """Where this agent kept its settings before the app was renamed."""
    if os.name == "nt":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(base, "NetView")
    return os.path.join(os.path.expanduser("~"), ".netview")


def migrate_legacy_config(on_warning=None) -> bool:
    """Carry config.json across the rename, once, at startup.

    config.json holds the browser origin allowlist. Losing it does not fall
    back to something harmless - it falls back to the DEFAULT origins, so any
    site the operator added by hand stops being able to connect, and the
    symptom is a 403 during the WebSocket handshake with nothing in the log
    saying a file moved.

    Deliberately NOT called from load_config: that runs on every incoming
    connection (the allowlist is re-read per connection so an edit needs no
    restart), and a filesystem copy does not belong on that path.

    Returns True only when a file was actually copied."""
    target = config_path()
    if os.path.exists(target):
        return False
    source = os.path.join(legacy_config_dir(), "config.json")
    if not os.path.exists(source):
        return False
    try:
        os.makedirs(config_dir(), exist_ok=True)
        shutil.copyfile(source, target)
        return True
    except OSError as exc:
        # The agent still starts, on default origins. Worth a warning because
        # the operator's own additions are the thing that just went missing.
        if on_warning is not None:
            on_warning(f"could not carry config.json over from {source} ({exc})")
        return False


def normalize_origin(origin: str) -> str:
    """An origin's scheme and host compare case-insensitively, and a trailing
    slash is not part of an origin at all. Browsers send neither variation,
    but a hand-edited config file easily contains both - and a config typo
    that silently blocks every connection is exactly the failure this whole
    module is written to avoid."""
    return origin.strip().rstrip("/").lower()


class _TokenUnreadable:
    """The token could not be determined, which is NOT the same as there being
    none.

    `token: None` means "this installation has no pairing token, so every
    local connection is allowed" - the pre-3.3.0 behaviour, and correct when
    config.json genuinely does not exist. Returning that for a file that DOES
    exist but cannot be parsed turns a stray comma into "authentication is
    silently off", which is the one failure this control cannot be allowed to
    have: it is the only thing separating the user's browser from any other
    program running as the user.

    So a file we cannot read yields this instead. It is not None, so the agent
    reports authRequired and gates every command; and it is not a str, so
    `tokens_match` refuses it without a special case. The way out is the log,
    which Driver Info shows: repair config.json, or reinstall the agent.
    """
    def __repr__(self):
        return "<token unreadable>"


TOKEN_UNREADABLE = _TokenUnreadable()


def _defaults(token=None) -> dict:
    return {"allowedOrigins": list(DEFAULT_ALLOWED_ORIGINS), "token": token}


def make_token() -> str:
    """A pairing token for one installation.

    256 bits from the OS entropy source, hex-encoded so it can be read off a
    screen and typed. The installer writes one; nothing derives it from the
    machine, because a token anyone could recompute is not one.
    """
    return secrets.token_hex(32)


def tokens_match(offered, expected) -> bool:
    """Constant-time comparison, which matters more here than it looks.

    Both ends are on one machine, so an attacker can measure this loop far more
    precisely than they could across a network - the usual argument that timing
    attacks are impractical is the argument that does not apply locally.
    """
    if not isinstance(offered, str) or not isinstance(expected, str):
        return False
    return hmac.compare_digest(offered.strip(), expected.strip())


def parse_config(raw_text, on_warning=None) -> dict:
    """Turns config.json's contents into a settings dict.

    Every failure mode - unreadable JSON, wrong shape, missing key - falls
    back to DEFAULT_ALLOWED_ORIGINS instead of raising. A headless service
    that refuses every connection because of a stray comma, with no console
    to say so, is the worst outcome available here; running on defaults and
    logging a warning is strictly better.

    The **token** does not get that treatment. Defaulting an origin list opens
    the door to the origins we would have allowed anyway; defaulting a token to
    None opens it to everything. Text we cannot parse yields TOKEN_UNREADABLE,
    which fails closed. Only a genuinely absent file yields None.
    """
    def warn(message):
        if on_warning is not None:
            on_warning(message)

    if raw_text is None:
        return _defaults()

    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, TypeError, ValueError):
        warn("config.json is not valid JSON - using default allowed origins, "
             "and authentication is REQUIRED but cannot be satisfied until the "
             "file is repaired")
        return _defaults(TOKEN_UNREADABLE)

    if not isinstance(data, dict):
        warn("config.json is not a JSON object - using default allowed origins, "
             "and authentication is REQUIRED but cannot be satisfied until the "
             "file is repaired")
        return _defaults(TOKEN_UNREADABLE)

    # The token is read whether or not the origin list parses, because the two
    # are independent controls and losing one should not silently disable the
    # other. An empty or non-string token is no token: a config that sets
    # "token": "" must not be read as "authentication is on, and the password
    # is nothing".
    token = data.get("token")
    token = token.strip() if isinstance(token, str) and token.strip() else None

    origins = data.get("allowedOrigins")
    if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
        warn("config.json has no valid 'allowedOrigins' string list - using default allowed origins")
        return {"allowedOrigins": list(DEFAULT_ALLOWED_ORIGINS), "token": token}

    return {"allowedOrigins": [normalize_origin(o) for o in origins], "token": token}


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
            on_warning(f"could not read config.json ({exc}) - using default allowed "
                       "origins, and authentication is REQUIRED but cannot be "
                       "satisfied until the file is readable")
        # A file that exists and cannot be read is not a file with no token in
        # it. parse_config(None) would say "no token"; this says "unknown",
        # which fails closed. See _TokenUnreadable.
        return _defaults(TOKEN_UNREADABLE)


def restrict_config_permissions(path, on_warning=None) -> bool:
    """Locks config.json down to SYSTEM and administrators.

    This is not belt and braces - it is the whole of what makes a token mean
    anything. `%ProgramData%` grants `BUILTIN\\Users` read by default and a
    file created there inherits it, so a token written without this step is
    readable by precisely the processes it exists to exclude: every program
    running as the logged-in user. Verified on a real install before this
    existed, where `Get-Acl` showed `BUILTIN\\Users : ReadAndExecute`.

    Applied on every run rather than only at creation, so an install that
    predates this gets fixed on upgrade instead of staying open.
    """
    try:
        if os.name == "nt":
            # /inheritance:r drops the inherited Users entry; /grant:r replaces
            # rather than adds, so running this twice is the same as once.
            result = subprocess.run(
                ["icacls", path, "/inheritance:r",
                 "/grant:r", "*S-1-5-18:(F)", "/grant:r", "*S-1-5-32-544:(F)"],
                capture_output=True, text=True, check=False,
            )
            if result.returncode != 0:
                raise OSError(result.stderr.strip() or f"icacls exited {result.returncode}")
        else:
            os.chmod(path, 0o600)
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        if on_warning is not None:
            on_warning(
                f"could not restrict permissions on {path} ({exc}) - the pairing "
                "token may be readable by other users on this machine"
            )
        return False


def ensure_config(on_warning=None) -> dict:
    """Creates config.json, or fills in a pairing token it is missing, and
    returns the settings.

    Called by the installer through the agent (`--init-config`) rather than
    written by the installer itself. Inno Setup's Pascal Script has `Random`,
    seeded from the clock; `secrets` is seeded from the OS entropy pool, and a
    token whose value can be narrowed down by knowing roughly when a machine
    was set up is not a token. This is also the only implementation of it, so
    Windows and Unix cannot drift apart.

    An existing token is never replaced - that would invalidate one the user
    has already pasted into a browser - and neither is anything else in the
    file. A *missing* token is filled in, including on upgrade: leaving every
    install that predates the token unauthenticated for ever would defeat the
    point of having one.
    """
    path = config_path()
    existing = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict):
                existing = loaded
        except (OSError, ValueError) as exc:
            # An unreadable file is not overwritten: it may be a config
            # somebody is in the middle of editing, and replacing it would
            # throw away their work to fix a problem they can see.
            if on_warning is not None:
                on_warning(f"could not read {path} ({exc}) - leaving it alone")
            return load_config(on_warning=on_warning)

        token = existing.get("token")
        if isinstance(token, str) and token.strip():
            restrict_config_permissions(path, on_warning=on_warning)
            return load_config(on_warning=on_warning)

    merged = dict(existing)
    merged.setdefault("allowedOrigins", list(DEFAULT_ALLOWED_ORIGINS))
    merged["token"] = make_token()

    try:
        os.makedirs(config_dir(), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(merged, handle, indent=2)
    except OSError as exc:
        # The agent still runs, on defaults and with no token - which is to say
        # unauthenticated, which is worth a warning rather than a silent
        # downgrade.
        if on_warning is not None:
            on_warning(f"could not write {path} ({exc}) - the agent will accept any local client")
        return _defaults()

    restrict_config_permissions(path, on_warning=on_warning)
    return {"allowedOrigins": [normalize_origin(o) for o in merged["allowedOrigins"]],
            "token": merged["token"]}


def is_origin_allowed(origin, allowed_origins) -> bool:
    """A missing Origin header means a non-browser client, and is rejected.
    Browsers always send Origin on a WebSocket handshake, so its absence is
    never a legitimate Inwire tab - only curl, a script, or a native process
    (see spec: Authentication)."""
    if not origin or not isinstance(origin, str):
        return False
    normalized = normalize_origin(origin)
    return any(normalized == normalize_origin(allowed) for allowed in allowed_origins)
