# PyInstaller spec for the Inwire local agent - Windows service build.
# Build with:  pyinstaller inwire_agent.spec
#
# Entry point is service_windows.py: the Service Control Manager host, and
# also the install/remove/start/stop/debug CLI the Inno Setup installer
# drives. agent.py, config.py and logging_setup.py are imported lazily or by
# name, so they are listed as hidden imports rather than discovered.
#
# Scapy loads many optional protocol layers dynamically, and pywin32's
# service machinery pulls win32timezone at runtime - both must be declared
# explicitly or PyInstaller silently drops them and the exe fails at start.
#
# ## onedir, not onefile, and this is a distribution decision
#
# A onefile build extracts its bundled DLLs to `%TEMP%\_MEI<random>` at every
# start and executes them from there. That is a textbook malware pattern:
# Defender's "Block executable files from running unless they meet a
# prevalence, age, or trusted list criterion" ASR rule blocks it outright, and
# the extracted DLLs are unsigned however well signed the exe around them is,
# because signing the wrapper does not sign what the wrapper writes to disk.
# It also costs the extraction on every service start, on a service that
# starts at boot.
#
# onedir ships the DLLs beside the exe, where they can be signed, where an
# administrator can see what is installed, and where nothing is written to
# %TEMP% at all. The cost is that the install is a directory rather than a
# file, which the installer was always going to be.
#
# ## VERSIONINFO
#
# The exe had none - no company, no product, no version - which is what an
# unsigned dropper also has, and it is the first thing anyone looks at in a
# file's Properties. It is generated below from `agent_version.py` rather than
# written out here, because a second copy of a version number is a version
# number that will disagree.
#
# There is now exactly ONE place a version is authored - `package.json` - and
# `agent_version.py` is generated from it by `npm run sync:version`, with
# `scripts/agent/version.ts` failing the build if any copy drifts (ADR 0035).
# This comment used to describe a FOUR-place lock held by two scripts covering
# different subsets, which itself replaced a "three-place lock" comment that was
# already out of date. A literal in this file would sit outside all of it.

import re
from pathlib import Path

block_cipher = None

_HERE = Path(SPECPATH)


def _agent_version() -> str:
    # `agent_version.py`, not `agent.py`: the literal moved when the agent's
    # version became the product's. Reading agent.py would now match nothing and
    # this raises rather than defaulting - a VERSIONINFO silently stamped 0.0.0
    # is the dropper-shaped exe this whole block exists to stop shipping.
    text = (_HERE / 'agent_version.py').read_text(encoding='utf-8')
    match = re.search(r'^AGENT_VERSION = "(\d+)\.(\d+)\.(\d+)"', text, re.M)
    if not match:
        raise SystemExit('inwire_agent.spec: could not read AGENT_VERSION from agent_version.py')
    return match.group(0), tuple(int(part) for part in match.groups())


_, _parts = _agent_version()
_version_text = '.'.join(str(part) for part in _parts)
# Windows wants four numbers. The fourth is the build field and this project
# does not use it, so it is zero rather than something invented.
_filevers = _parts + (0,)

_version_file = _HERE / 'build' / 'version_info.txt'
_version_file.parent.mkdir(parents=True, exist_ok=True)
_version_file.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={_filevers},
    prodvers={_filevers},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0),
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', 'Inwire'),
         StringStruct('FileDescription', 'Inwire capture agent'),
         StringStruct('FileVersion', '{_version_text}'),
         StringStruct('InternalName', 'inwire-agent-windows'),
         StringStruct('OriginalFilename', 'inwire-agent-windows.exe'),
         StringStruct('ProductName', 'Inwire'),
         StringStruct('ProductVersion', '{_version_text}')])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding='utf-8')

a = Analysis(
    ['service_windows.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Our own modules - imported inside functions or via sys.path, so
        # PyInstaller's static analysis does not see them.
        'agent',
        # Generated from package.json, and `agent.py` imports it at module
        # scope for AGENT_VERSION. A dropped one is a service that dies on
        # import with `console=False`, so with nothing on screen at all.
        'agent_version',
        'agent_log',
        'config',
        'interface_stats',
        'logging_setup',
        # The binary packet frame (3.2.0). Listed rather than left to static
        # analysis for the same reason as the rest: this build has no console,
        # so a module PyInstaller quietly dropped shows up as a service that
        # will not start and says nothing about why.
        'packet_batch',
        # The named pipe and its framing (3.8.0) - the agent's only transport
        # on Windows, so a dropped one here is an app that never connects.
        'pipe_frame',
        'pipe_server',
        # Adapter configuration (3.6.0). It imports winreg, which is
        # stdlib, and scapy.arch.windows, which is already listed below.
        'adapters',
        'sockets',
        # Scapy's dynamically loaded layers.
        'scapy.layers.all',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'scapy.arch.windows',
        # pywin32 service machinery. win32timezone is the classic omission:
        # it is imported at runtime by pywintypes and its absence shows up
        # only as a service that refuses to start.
        'win32timezone',
        'servicemanager',
        'win32serviceutil',
        'win32service',
        'win32event',
        # The pipe's own pywin32 surface. win32security is what builds the
        # security descriptor, which IS the access control on Windows - drop
        # it and the agent starts, listens on nothing, and says so only in a
        # log file the app cannot reach because it cannot connect.
        'win32security',
        'win32pipe',
        'win32file',
        'winerror',
    ],
    hookspath=[],
    runtime_hooks=[],
    # `websockets` is the transport on macOS and Linux and is never imported on
    # Windows (agent.py sets it to None). Excluded rather than left to be
    # collected: a signed installer should not carry a library the product
    # cannot reach, and PyInstaller would otherwise pull it in through the
    # tarball's requirements.
    excludes=['websockets'],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    # onedir: the binaries, zipfiles and datas go to COLLECT below rather than
    # into the exe. Passing them here as well is what silently makes a onefile
    # build out of a spec that looks like a onedir one.
    [],
    exclude_binaries=True,
    name='inwire-agent-windows',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,         # no console window, ever - this is the whole point
    uac_admin=True,        # install/remove need elevation when run by hand;
                           # the SCM ignores the manifest when it starts a service
    icon='icon.ico',
    version=str(_version_file),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    # The directory the installer copies to %ProgramFiles%\Inwire\agent.
    name='inwire-agent-windows',
)
