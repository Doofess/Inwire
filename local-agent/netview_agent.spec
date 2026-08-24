# PyInstaller spec for the NetView local agent - Windows one-click build.
# Build with:  pyinstaller netview_agent.spec
#
# Entry point is bootstrap_windows.py, which installs Npcap if missing and
# then runs agent.py in-process - both files get bundled into one exe.
# Scapy loads many optional protocol layers dynamically, so they must be
# listed explicitly as hidden imports or PyInstaller will silently drop them.

block_cipher = None

a = Analysis(
    ['bootstrap_windows.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'scapy.layers.all',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'scapy.arch.windows',
        'websockets.legacy.server',
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
    name='netview-agent-windows',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,          # keep a console window so capture/install errors are visible
    uac_admin=True,        # embeds requireAdministrator - Windows shows UAC on double-click
    icon='icon.ico',
)
