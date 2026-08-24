; NetView Agent installer
; Build with Inno Setup 6: iscc setup.iss
;
; Bundles the PyInstaller exe, silently installs Npcap if missing, and
; registers the netview:// custom URI scheme so the browser can launch
; the agent with a single click (same pattern Zoom/Slack/VS Code use).
;
; NOTE ON LICENSING: redistributing/silently installing the Npcap installer
; in a packaged product requires an Npcap OEM license (https://npcap.com/oem/).
; The free Npcap installer is fine for personal/internal use but its EULA
; restricts silent bundling in distributed software. Confirm your license
; covers this before shipping the installer below.

#define MyAppName "NetView Agent"
#define MyAppVersion "1.0.0"
#define MyAppExeName "netview-agent-windows.exe"
#define MyAppPublisher "NetView"
#define NpcapInstaller "npcap-1.79.exe"

[Setup]
AppId={{4C2F8E1A-6B3D-4E9F-8A2C-1D5E7F9A3B6C}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=output
OutputBaseFilename=NetView-Agent-Setup
SetupIconFile=..\icon.ico
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "redist\{#NpcapInstaller}"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Registry]
; --- netview:// custom URI scheme -> launches the agent exe ---
Root: HKCR; Subkey: "netview"; ValueType: string; ValueName: ""; \
    ValueData: "URL:NetView Agent Protocol"; Flags: uninsdeletekey
Root: HKCR; Subkey: "netview"; ValueType: string; ValueName: "URL Protocol"; \
    ValueData: ""; Flags: uninsdeletevalue
Root: HKCR; Subkey: "netview\DefaultIcon"; ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#MyAppExeName}"",0"
Root: HKCR; Subkey: "netview\shell\open\command"; ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Run]
; Install Npcap silently only if it isn't already present on the system.
Filename: "{tmp}\{#NpcapInstaller}"; Parameters: "/S /winpcap_mode=no"; \
    StatusMsg: "Installing Npcap packet capture driver..."; Check: not IsNpcapInstalled
; Optional: launch the agent right after setup finishes.
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} now"; \
    Flags: nowait postinstall skipifsilent

[Code]
function IsNpcapInstalled: Boolean;
begin
  Result :=
    RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Npcap') or
    RegKeyExists(HKLM, 'SOFTWARE\Npcap') or
    FileExists(ExpandConstant('{sys}\Npcap\npcap.sys'));
end;
