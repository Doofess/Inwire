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
#define MyAppVersion "2.1.0"
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
; Service registration is NOT done here. [Run] entries ignore exit codes, and
; a failed registration would leave a "successful" install with no service and
; nothing on screen to say so. RegisterAgentService (in [Code]) runs it with
; Exec() and checks the result instead.

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

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';

  // A running service holds an open handle on its own executable, and Windows
  // refuses to replace a file that is in use. Without this, upgrading over an
  // existing install dies partway through extraction with "An error occurred
  // while trying to replace the existing file: DeleteFile failed; code 5.
  // Access is denied." naming netview-agent-windows.exe - leaving only bad
  // choices: skip the file and keep the OLD binary under a NEW version's
  // install, or abandon setup. [UninstallRun] stops the service too, but only
  // on uninstall; an upgrade-in-place never goes through it.
  //
  // Three steps, because a graceful stop alone is not enough. The agent can be
  // alive but unable to service a stop request - its packet fan-out queues
  // work onto the asyncio loop without backpressure, so a high-rate interface
  // can starve the loop until the SCM's stop control is never processed. In
  // that state `net stop` fails, and an installer that only asked politely
  // walks straight into the locked file. That is the state a machine is most
  // likely to be in when the user has gone looking for an update.

  // 1. Ask nicely. sc.exe rather than net.exe: sc returns as soon as the stop
  //    has been REQUESTED, so a wedged service costs a moment here instead of
  //    blocking the wizard for the SCM's full 30-second timeout.
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop NetViewAgent', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 2. Give a healthy service time to shut down and release its own exe.
  Sleep(5000);

  // 3. Guarantee the handle is gone. A no-op when step 1 already worked -
  //    taskkill simply reports no matching process, and the non-zero result
  //    is ignored, exactly as it is on a first-time install where there is no
  //    service at all. Force is warranted: the alternative is a failed
  //    upgrade, and the agent holds no unsaved state - its config and log are
  //    separate files it is not mid-write on.
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#MyAppExeName}', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 4. Windows releases the file handle a moment after the process dies.
  Sleep(2000);
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

procedure RegisterAgentService;
var
  ExePath, LogPath: String;
  ResultCode: Integer;
begin
  ExePath := ExpandConstant('{app}\{#MyAppExeName}');
  LogPath := ExpandConstant('{commonappdata}\NetView\agent.log');

  // Options MUST precede the command. pywin32's HandleCommandLine parses with
  // getopt, which stops at the first non-option token - so "install --startup
  // auto" never sees --startup at all: it prints its usage screen and exits 1
  // without registering anything.
  if not Exec(ExePath, '--startup auto install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    SuppressibleMsgBox('Could not launch the NetView Agent service installer.' + #13#10#13#10 +
      SysErrorMessage(ResultCode), mbCriticalError, MB_OK, IDOK);
    Exit;
  end;
  if ResultCode <> 0 then
  begin
    SuppressibleMsgBox('Registering the NetView Agent service failed (exit code ' +
      IntToStr(ResultCode) + ').' + #13#10#13#10 +
      'The files were installed but the service is not registered, so capture will not work.' + #13#10#13#10 +
      'See ' + LogPath + ' for details.', mbCriticalError, MB_OK, IDOK);
    Exit;
  end;

  if not Exec(ExePath, 'start', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    SuppressibleMsgBox('Could not launch the NetView Agent service.' + #13#10#13#10 +
      SysErrorMessage(ResultCode), mbCriticalError, MB_OK, IDOK);
    Exit;
  end;
  if ResultCode <> 0 then
    SuppressibleMsgBox('The NetView Agent service was registered but did not start (exit code ' +
      IntToStr(ResultCode) + ').' + #13#10#13#10 +
      'It is set to start automatically, so a reboot may resolve it.' + #13#10#13#10 +
      'See ' + LogPath + ' for details.', mbError, MB_OK, IDOK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Config first: the service reads it on every connection, and seeding it
    // before the service starts avoids a first-run window with no allowlist.
    WriteDefaultConfig;
    RegisterAgentService;
  end;
end;
