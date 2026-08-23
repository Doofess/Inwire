#!/usr/bin/env python3
"""
NetView Agent - Windows one-click installer + launcher.

This is the entry point PyInstaller compiles into netview-agent-windows.exe.
Double-clicking the exe:
  1. Triggers the Windows UAC prompt (via the embedded manifest -
     requestedExecutionLevel=requireAdministrator). This is the one
     unavoidable extra click Windows itself requires for driver install +
     raw-socket capture; no installer can skip it.
  2. Installs Npcap (the packet-capture driver) silently if it isn't
     already present, downloading it fresh from the official npcap.com
     distribution - never bundled, so no redistribution licensing question.
  3. Starts the capture agent in-process, listening on ws://localhost:8999.
"""

import os
import subprocess
import sys
import tempfile
import urllib.request
import winreg

NPCAP_INSTALLER_URL = "https://npcap.com/dist/npcap-1.79.exe"


def npcap_installed() -> bool:
    for hive, path in [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
    ]:
        try:
            winreg.OpenKey(hive, path)
            return True
        except FileNotFoundError:
            continue
    return os.path.exists(r"C:\Windows\System32\Npcap\npcap.sys")


def install_npcap() -> None:
    print("[installer] Npcap driver not found - downloading from npcap.com ...")
    installer_path = os.path.join(tempfile.gettempdir(), "npcap-installer.exe")
    try:
        urllib.request.urlretrieve(NPCAP_INSTALLER_URL, installer_path)
    except Exception as exc:
        print(f"[installer] ERROR: could not download Npcap ({exc}).")
        print("[installer] Install it manually from https://npcap.com/#download and re-run this agent.")
        input("Press Enter to exit...")
        sys.exit(1)

    print("[installer] Installing Npcap silently...")
    result = subprocess.run([installer_path, "/S", "/winpcap_mode=no"])
    if result.returncode != 0:
        print("[installer] Npcap installation failed. Try running the downloaded installer manually:")
        print(f"[installer]   {installer_path}")
        input("Press Enter to exit...")
        sys.exit(1)
    print("[installer] Npcap installed successfully.")


def main() -> None:
    if not npcap_installed():
        install_npcap()

    print("[installer] Starting NetView Agent...")
    import asyncio
    import agent  # bundled alongside this script in the same frozen exe

    try:
        asyncio.run(agent.main())
    except KeyboardInterrupt:
        print("\n[agent] shutting down.")


if __name__ == "__main__":
    main()
