; NetView Agent installer
; Build with Inno Setup 6.3.0 or newer:  iscc setup.iss
;
; 6.3.0 is the floor because [Setup] uses ArchitecturesInstallIn64BitMode=
; x64compatible, an identifier introduced in 6.3.0 that replaced the older
; bare `x64`. CreateDownloadPage (used in [Code]) needs only 6.1, so the
; architecture identifier is what sets the requirement.
;
; Installs the agent as a Windows service that starts at boot and shows no
; UI of any kind. Npcap is downloaded from the official distribution at
; install time rather than bundled: redistributing and silently installing
; the Npcap installer inside a packaged product requires an Npcap OEM
; licence, and downloading it on the user's machine is not redistribution.

#define MyAppName "NetView Agent"
#define MyAppVersion "2.0.0"
#define MyAppExeName "netview-agent-windows.exe"
#define MyAppPublisher "NetView"
#define NpcapUrl "https://npcap.com/dist/npcap-1.79.exe"

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

[Dirs]
; Config and log live here, present before anyone logs in - which a
; LocalSystem service needs. Inherits ProgramData's default ACLs, which
; typically restrict writes to administrators; this does not itself set any
; permissions.
Name: "{commonappdata}\NetView"

[Icons]
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Registry]
; --- netview:// custom URI scheme ---
; Vestigial: its purpose was launching a manually-started agent from the
; browser, which an always-running service makes unnecessary. Left registered
; rather than removed, to avoid churn in a file this release already rewrites.
Root: HKCR; Subkey: "netview"; ValueType: string; ValueName: ""; \
    ValueData: "URL:NetView Agent Protocol"; Flags: uninsdeletekey
Root: HKCR; Subkey: "netview"; ValueType: string; ValueName: "URL Protocol"; \
    ValueData: ""; Flags: uninsdeletevalue
Root: HKCR; Subkey: "netview\DefaultIcon"; ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#MyAppExeName}"",0"
Root: HKCR; Subkey: "netview\shell\open\command"; ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Run]
Filename: "{tmp}\npcap-installer.exe"; Parameters: "/S /winpcap_mode=no"; \
    StatusMsg: "Installing the Npcap capture driver..."; \
    Check: NeedsNpcap; Flags: waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Parameters: "install --startup auto"; \
    StatusMsg: "Registering the NetView Agent service..."; \
    Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Parameters: "start"; \
    StatusMsg: "Starting the NetView Agent service..."; \
    Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "stop"; \
    Flags: runhidden waituntilterminated; RunOnceId: "StopNetViewAgent"
Filename: "{app}\{#MyAppExeName}"; Parameters: "remove"; \
    Flags: runhidden waituntilterminated; RunOnceId: "RemoveNetViewAgent"

[Code]
var
  DownloadPage: TDownloadWizardPage;

function IsNpcapInstalled: Boolean;
begin
  Result :=
    RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Npcap') or
    RegKeyExists(HKLM, 'SOFTWARE\Npcap') or
    FileExists(ExpandConstant('{sys}\Npcap\npcap.sys'));
end;

function NeedsNpcap: Boolean;
begin
  Result := not IsNpcapInstalled;
end;

function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  Result := True;
end;

procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage(
    SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), @OnDownloadProgress);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = wpReady) and NeedsNpcap then
  begin
    DownloadPage.Clear;
    DownloadPage.Add('{#NpcapUrl}', 'npcap-installer.exe', '');
    DownloadPage.Show;
    try
      try
        DownloadPage.Download;
      except
        // Abort rather than continue: finishing the install would leave a
        // registered service that can never capture anything.
        SuppressibleMsgBox(
          'Could not download the Npcap capture driver.'#13#10#13#10 +
          AddPeriod(GetExceptionMessage) + #13#10#13#10 +
          'Install it manually from https://npcap.com/#download and run this setup again.',
          mbCriticalError, MB_OK, IDOK);
        Result := False;
      end;
    finally
      DownloadPage.Hide;
    end;
  end;
end;

procedure WriteDefaultConfig;
var
  ConfigPath: String;
  Lines: TArrayOfString;
begin
  ConfigPath := ExpandConstant('{commonappdata}\NetView\config.json');
  // Never overwrite an existing config: a reinstall or upgrade must not
  // silently discard a customized origin allowlist.
  if FileExists(ConfigPath) then
    Exit;

  SetArrayLength(Lines, 8);
  Lines[0] := '{';
  Lines[1] := '  "allowedOrigins": [';
  Lines[2] := '    "http://localhost:3000",';
  Lines[3] := '    "http://127.0.0.1:3000",';
  Lines[4] := '    "http://localhost:4173",';
  Lines[5] := '    "http://127.0.0.1:4173"';
  Lines[6] := '  ]';
  Lines[7] := '}';
  SaveStringsToFile(ConfigPath, Lines, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    WriteDefaultConfig;
end;
