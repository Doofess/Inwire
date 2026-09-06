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

block_cipher = None

a = Analysis(
    ['service_windows.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Our own modules - imported inside functions or via sys.path, so
        # PyInstaller's static analysis does not see them.
        'agent',
        'agent_log',
        'config',
        'interface_stats',
        'logging_setup',
        # The binary packet frame (3.2.0). Listed rather than left to static
        # analysis for the same reason as the rest: this build has no console,
        # so a module PyInstaller quietly dropped shows up as a service that
        # will not start and says nothing about why.
        'packet_batch',
        # Adapter configuration (3.6.0). It imports winreg, which is
        # stdlib, and scapy.arch.windows, which is already listed below.
        'adapters',
        'sockets',
        # Scapy's dynamically loaded layers.
        'scapy.layers.all',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'scapy.arch.windows',
        'websockets.legacy.server',
        # pywin32 service machinery. win32timezone is the classic omission:
        # it is imported at runtime by pywintypes and its absence shows up
        # only as a service that refuses to start.
        'win32timezone',
        'servicemanager',
        'win32serviceutil',
        'win32service',
        'win32event',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='inwire-agent-windows',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,         # no console window, ever - this is the whole point
    uac_admin=True,        # install/remove need elevation when run by hand;
                           # the SCM ignores the manifest when it starts a service
    icon='icon.ico',
)
