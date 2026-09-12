"""What the Npcap driver's device object admits, as an SDDL string.

Npcap's installer has a checkbox - *"Restrict Npcap driver's access to
Administrators only"* - and it is **not ticked by default**. Unticked, the
capture devices are open to every local user, so any account on this machine
can read its traffic and write raw frames onto the wire. Inwire recommends
ticking it, and a recommendation has to know whether it has already been
taken; see docs/decisions/0033.

Two things record the answer and they can disagree. `HKLM\\SOFTWARE\\Npcap`
carries `AdminOnly`, which is what the installer wrote; the device object's
DACL is what the kernel actually enforces. The registry can be edited without
the driver being restarted, so the DACL is the one that decides who gets in -
and reading it is what this module is for. The registry half is read by the
app, which does not need a privileged process for it.

## The agent reports the string and decides nothing

`docs/decisions/0010` is the rule: the agent states facts and the app decides.
The same applies here. An SDDL is a fact about the machine; "administrators
only" is a verdict, and a verdict computed here would be a second
implementation of a decision the app already has to be able to make from the
registry alone. So `hello` carries the string, `src/services/npcapAccess.ts`
turns it into an answer, and `scripts/electron/update-center.ts` asserts that
turn against captured strings.

## Why `\\\\.\\NPCAP` and not `\\Device\\NPCAP`

`GetNamedSecurityInfo` with `SE_FILE_OBJECT` resolves a Win32 path. The NT
object-manager path fails with "the system cannot find the path specified" -
measured, not assumed. The Win32 device name works, and works without
elevation, because reading a DACL needs `READ_CONTROL` and every shape of this
descriptor grants that to somebody who can already open the app.

Nothing here raises. A driver that is not installed, a pywin32 that is not
present, a platform that is not Windows and a call that fails all answer
`None`, which the app renders as "unknown" - never as either verdict.
"""

import sys

# The control device. Per-adapter devices are `\\.\npcap\{GUID}` and carry the
# same descriptor, so asking the one that is always there is enough.
NPCAP_DEVICE = r"\\.\NPCAP"


def read_driver_sddl(device: str = NPCAP_DEVICE):
    """The device object's DACL as SDDL, or None if it could not be read.

    None is a real answer and not an error: the driver may not be installed,
    which is the state a fresh machine is in and the one the Update Center
    exists to fix.
    """
    if sys.platform != "win32":
        return None
    try:
        import win32security
    except ImportError:
        return None
    try:
        descriptor = win32security.GetNamedSecurityInfo(
            device,
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
        )
        return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            descriptor,
            win32security.SDDL_REVISION_1,
            win32security.DACL_SECURITY_INFORMATION,
        )
    except Exception:
        # Deliberately broad. Every failure mode here - no driver, no
        # permission, a path shape a future Npcap changes - means the same
        # thing to the caller, and an exception escaping would take down the
        # hello that carries it.
        return None
