#!/usr/bin/env python3
"""
Logging for the Inwire agent.

Once the agent runs as a service there is no console, so a file is the only
diagnostic channel that exists for either the user or a maintainer. This is
not optional polish - it is the entire observability story (see spec).
"""

import logging
import os
import stat
import sys
from logging.handlers import RotatingFileHandler

LOG_FILENAME = "agent.log"
# An agent running for months must not be able to fill a disk.
MAX_BYTES = 1_000_000
BACKUP_COUNT = 3

# The service's descriptor for its log folder, the same literal as
# agent-rs/src/agent_log.rs: owned by Administrators, protected (nothing
# inherited from ProgramData), SYSTEM and Administrators full control, Users
# read-and-execute only. The service rotates this folder as SYSTEM with
# remove/rename, so a user who owned it or could plant entries in it could aim
# SYSTEM's delete or rename anywhere.
LOG_DIR_SDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000

_configured_with = None
# Folders that have been set up hardened in this process. Hardening is sticky:
# the service calls setup_logging with harden=True, then agent.main() calls it
# again without, because main() cannot know whether it runs as the service. If
# that second call rebuilt the handler plainly, SYSTEM would be appending
# through whatever a user had planted in the folder.
_hardened_directories = set()


def _directory_key(directory):
    return os.path.normcase(os.path.abspath(directory))


def _harden_directory(directory):
    """Gives `directory` LOG_DIR_SDDL, protected, and propagates it to children.

    A reparse point is refused, not followed: re-ACLing a junction's target
    would be done as SYSTEM.

    The folder is opened once and the check and the change both use that
    handle. A user who owns a pre-existing folder can replace it between a
    check made on its path and a change made on its path, so neither names the
    path twice. The handle is opened with every share flag and explicit rights:
    SetSecurityInfo propagates inheritable entries to what is already inside,
    but not through a handle opened exclusively or with MAXIMUM_ALLOWED.
    """
    import win32file  # noqa: PLC0415 - Windows only, imported where used
    import win32security  # noqa: PLC0415

    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        LOG_DIR_SDDL, win32security.SDDL_REVISION_1,
    )
    owner = descriptor.GetSecurityDescriptorOwner()
    dacl = descriptor.GetSecurityDescriptorDacl()
    information = (
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION
    )
    access = _READ_CONTROL | _WRITE_DAC
    if owner is not None:
        information |= win32security.OWNER_SECURITY_INFORMATION
        access |= _WRITE_OWNER
    handle = win32file.CreateFile(
        directory,
        access,
        win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
        None,
        win32file.OPEN_EXISTING,
        win32file.FILE_FLAG_BACKUP_SEMANTICS | win32file.FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    try:
        attributes = win32file.GetFileInformationByHandle(handle)[0]
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError(f"{directory} is a reparse point and is not followed")
        if not attributes & _FILE_ATTRIBUTE_DIRECTORY:
            raise OSError(f"{directory} is not a directory")
        win32security.SetSecurityInfo(
            handle, win32security.SE_FILE_OBJECT, information, owner, None, dacl, None,
        )
    finally:
        handle.Close()


def _log_paths(directory):
    """`agent.log` and its rotated names: the only entries the agent opens,
    renames or deletes in its folder."""
    names = [LOG_FILENAME] + [f"{LOG_FILENAME}.{n}" for n in range(1, BACKUP_COUNT + 1)]
    return [os.path.join(directory, name) for name in names]


def _is_link_or_directory(info):
    return bool(
        stat.S_ISLNK(info.st_mode)
        or stat.S_ISDIR(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _clear_planted_links(directory):
    """Removes what a user planted under a log name: a symlink, junction or
    directory, or a regular file with more than one name.

    Only the entry goes, never what it points at: rmdir on a junction removes
    the junction, and removing one name of a hard link leaves the file and its
    other names alone. Errors are ignored here because _log_names_are_safe is
    what decides what to do about an entry that stayed.
    """
    for path in _log_paths(directory):
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if _is_link_or_directory(info):
            try:
                os.rmdir(path)
            except OSError:
                try:
                    os.remove(path)
                except OSError:
                    pass
        elif stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            try:
                os.remove(path)
            except OSError:
                pass


def _log_names_are_safe(directory):
    """True when every log name is absent or a plain regular file with one name.

    Checked after _clear_planted_links: an entry that is still a link, a
    directory or a multi-link file is one the agent must not rotate into or
    append to, so setup_logging then installs no file handler at all. A name
    whose state cannot be read counts as unsafe.
    """
    for path in _log_paths(directory):
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            return False
        if _is_link_or_directory(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return False
    return True


def setup_logging(directory, to_stderr=True, level=logging.INFO, harden=False):
    """Configures and returns the shared `inwire` logger.

    Idempotent: calling it twice with the same (directory, to_stderr, harden)
    returns the same logger without stacking duplicate handlers (which would
    print every line twice). A second call with *different* settings must
    actually take effect - a stale StreamHandler from an earlier
    to_stderr=True call would otherwise keep writing to a stderr the service
    has no console for.

    `harden` is for the Windows service only (a hand run is not SYSTEM and
    cannot set the owner). It secures the folder with LOG_DIR_SDDL first and
    clears planted links; if that fails there is no file handler at all. It is
    sticky: once a folder has been set up hardened, a later call for it without
    `harden` keeps the hardened setup.
    """
    global _configured_with
    logger = logging.getLogger("inwire")
    key = _directory_key(directory)
    if harden:
        _hardened_directories.add(key)
    elif key in _hardened_directories:
        harden = True
    if _configured_with == (directory, to_stderr, harden):
        return logger

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    logger.setLevel(level)
    # propagate=False keeps these records out of the root logger, so a library
    # that configures logging.basicConfig() cannot double-print them.
    logger.propagate = False
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")

    unsecured = None
    try:
        os.makedirs(directory, exist_ok=True)
        if harden:
            try:
                _harden_directory(directory)
            except Exception as exc:  # noqa: BLE001 - any failure means no file log
                unsecured = exc
                raise OSError(str(exc)) from exc
            _clear_planted_links(directory)
            if not _log_names_are_safe(directory):
                # An entry that could not be removed is run past, not trusted:
                # no file log, exactly as for a folder that is a junction.
                unsecured = OSError("a log file name is held by a link, a directory or a file with other names")
                raise unsecured
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

    if not logger.handlers:
        # No file handler (unwritable directory) and no stderr handler:
        # without an explicit NullHandler, Python's logging.lastResort would
        # write WARNING+ records to the real stderr, which under the SCM is
        # not a console anyone can see and is precisely what to_stderr=False
        # asked us not to do.
        logger.addHandler(logging.NullHandler())

    _configured_with = (directory, to_stderr, harden)
    if unsecured is not None:
        logger.warning(
            "agent log folder %r could not be secured (%s) - logging to subscribers only",
            directory, unsecured,
        )
    return logger
