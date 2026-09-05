; Inwire Agent installer
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

#define MyAppName "Inwire Agent"
#define MyAppVersion "3.4.1"
#define MyAppExeName "inwire-agent-windows.exe"
#define MyAppPublisher "Inwire"
#define NpcapUrl "https://npcap.com/dist/npcap-1.79.exe"

; What this product was called before it was renamed. Retained ONLY so an
; existing install can be cleaned up - nothing new is ever written under these
; names. The AppId above is deliberately unchanged: it is what makes Windows
; treat this as an upgrade of that install rather than a second product, so
; there is one entry in Add/Remove Programs instead of two.
#define LegacyAppName "NetView Agent"
#define LegacyExeName "netview-agent-windows.exe"
#define LegacyServiceName "NetViewAgent"

[Setup]
AppId={{4C2F8E1A-6B3D-4E9F-8A2C-1D5E7F9A3B6C}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
; Without this, an upgrade keeps the directory the previous version recorded -
; which is the OLD product name, so the renamed agent would install itself into
; a folder still called after the old one. The old directory is removed by
; [InstallDelete] below, after PrepareToInstall has released its file handles.
UsePreviousAppDir=no
OutputDir=output
OutputBaseFilename=Inwire-Agent-Setup
SetupIconFile=..\icon.ico
; Without this the Add/Remove Programs entry has no icon at all - SetupIconFile
; only brands the installer itself. Confirmed blank on an installed 2.6.0.
UninstallDisplayIcon={app}\{#MyAppExeName}
; The setup exe's own file-version resource; blank (0.0.0.0) unless set here.
VersionInfoVersion={#MyAppVersion}.0
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[InstallDelete]
; The previous install, by its old name. Safe to remove outright: it was put
; there by this same AppId, it holds nothing but the agent executable and its
; uninstaller, and PrepareToInstall has already stopped the service and killed
; the process that was holding the exe open.
Type: filesandordirs; Name: "{autopf}\{#LegacyAppName}"
Type: filesandordirs; Name: "{commonprograms}\{#LegacyAppName}"

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; Config and log live here, present before anyone logs in - which a
; LocalSystem service needs. Inherits ProgramData's default ACLs, which
; typically restrict writes to administrators; this does not itself set any
; permissions.
Name: "{commonappdata}\Inwire"

[Icons]
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Registry]
; The scheme under the product's previous name. Deleted rather than left: its
; DefaultIcon and open command both point into the old install directory, which
; [InstallDelete] above removes, so leaving the key registers a protocol handler
; for an executable that is no longer there. The old install's own uninstaller
; would have removed it, but an upgrade never runs that.
Root: HKCR; Subkey: "netview"; ValueType: none; Flags: deletekey

; --- inwire:// custom URI scheme ---
; Vestigial: its purpose was launching a manually-started agent from the
; browser, which an always-running service makes unnecessary. Left registered
; rather than removed, to avoid churn in a file this release already rewrites.
Root: HKCR; Subkey: "inwire"; ValueType: string; ValueName: ""; \
    ValueData: "URL:Inwire Agent Protocol"; Flags: uninsdeletekey
Root: HKCR; Subkey: "inwire"; ValueType: string; ValueName: "URL Protocol"; \
    ValueData: ""; Flags: uninsdeletevalue
Root: HKCR; Subkey: "inwire\DefaultIcon"; ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#MyAppExeName}"",0"
Root: HKCR; Subkey: "inwire\shell\open\command"; ValueType: string; ValueName: ""; \
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
    Flags: runhidden waituntilterminated; RunOnceId: "StopInwireAgent"
Filename: "{app}\{#MyAppExeName}"; Parameters: "remove"; \
    Flags: runhidden waituntilterminated; RunOnceId: "RemoveInwireAgent"

[UninstallDelete]
; The rotating log and its backups are litter once the agent is gone. The
; config (origin allowlist; the token from 3.2 on) is deliberately kept so a
; reinstall finds the origins someone added - it is small and named in the
; README as the one thing uninstall leaves behind.
Type: files; Name: "{commonappdata}\Inwire\agent.log"
Type: files; Name: "{commonappdata}\Inwire\agent.log.*"

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
  // Access is denied." naming inwire-agent-windows.exe - leaving only bad
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

  // 0. The service under the product's PREVIOUS name, if this machine is
  //    coming from a build that predates the rename. It has to be deleted, not
  //    just stopped: it is registered auto-start, so a stopped one is back at
  //    the next boot, and both agents bind ws://localhost:8999 - the second to
  //    start simply fails, intermittently, depending on boot order. Deleting a
  //    service that was never there returns non-zero and is ignored, which is
  //    also what a first-time install does here.
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#LegacyServiceName}', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#LegacyExeName}', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#LegacyServiceName}', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 1. Ask nicely. sc.exe rather than net.exe: sc returns as soon as the stop
  //    has been REQUESTED, so a wedged service costs a moment here instead of
  //    blocking the wizard for the SCM's full 30-second timeout.
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop InwireAgent', '',
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

// The pairing token this install will use, captured so the finished page can
// show it. Empty when the config already existed, which is the upgrade case.
var
  PairingToken: String;

function NewLine: String;
begin
  Result := Chr(13) + Chr(10);
end;

// Seeds config.json, with a pairing token, by running the agent's own
// --init-config.
//
// Not written here in Pascal: Inno Setup's Random is seeded from the clock,
// and a token whose value narrows down to "whenever this machine was set up"
// is not a token. The agent uses Python's `secrets`, and being the only
// implementation is what keeps Windows and Unix from drifting apart.
//
// The origin check keeps an ordinary web page out of the agent and stops
// nothing that can set a header, which is any process on this machine. This is
// the control that tells the user's browser from another program running as
// the user, and it works because it lands in ProgramData, which an ordinary
// process cannot read.
procedure WriteDefaultConfig;
var
  ExePath, OutPath: String;
  // LoadStringFromFile wants an AnsiString, not a String.
  Existing: AnsiString;
  ResultCode: Integer;
begin
  PairingToken := '';
  ExePath := ExpandConstant('{app}\{#MyAppExeName}');
  OutPath := ExpandConstant('{tmp}\pairing-token.txt');

  // The exe is built console=False, so its stdout has to be redirected
  // through cmd to be captured at all.
  if not Exec(ExpandConstant('{cmd}'), '/C ""' + ExePath + '" --init-config > "' + OutPath + '""',
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    SuppressibleMsgBox('Could not create the agent configuration.' + #13#10#13#10 +
      SysErrorMessage(ResultCode), mbError, MB_OK, IDOK);
    Exit;
  end;

  if LoadStringFromFile(OutPath, Existing) then
    PairingToken := Trim(Existing);
  DeleteFile(OutPath);
end;

procedure RegisterAgentService;
var
  ExePath, LogPath: String;
  ResultCode: Integer;
begin
  ExePath := ExpandConstant('{app}\{#MyAppExeName}');
  LogPath := ExpandConstant('{commonappdata}\Inwire\agent.log');

  // Options MUST precede the command. pywin32's HandleCommandLine parses with
  // getopt, which stops at the first non-option token - so "install --startup
  // auto" never sees --startup at all: it prints its usage screen and exits 1
  // without registering anything.
  if not Exec(ExePath, '--startup auto install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    SuppressibleMsgBox('Could not launch the Inwire Agent service installer.' + #13#10#13#10 +
      SysErrorMessage(ResultCode), mbCriticalError, MB_OK, IDOK);
    Exit;
  end;
  if ResultCode <> 0 then
  begin
    SuppressibleMsgBox('Registering the Inwire Agent service failed (exit code ' +
      IntToStr(ResultCode) + ').' + #13#10#13#10 +
      'The files were installed but the service is not registered, so capture will not work.' + #13#10#13#10 +
      'See ' + LogPath + ' for details.', mbCriticalError, MB_OK, IDOK);
    Exit;
  end;

  // Restart-on-failure actions, set between registering and starting.
  //
  // This is what makes Driver Info's "Restart Agent" possible at all: the
  // agent restarts by exiting, and without these the SCM would treat that exit
  // as a dead service and leave it stopped until someone started it by hand.
  // The agent re-asserts the same policy at startup and refuses to exit on
  // request when it cannot confirm it, so a failure here degrades to the
  // button being unavailable rather than to an agent that cannot come back -
  // which is why this is not treated as a fatal install error.
  //
  // reset= 86400 means three failures inside a day stop the restarts, so a
  // genuine crash loop is left stopped instead of being retried forever.
  Exec(ExpandConstant('{sys}\sc.exe'),
       'failure InwireAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if not Exec(ExePath, 'start', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    SuppressibleMsgBox('Could not launch the Inwire Agent service.' + #13#10#13#10 +
      SysErrorMessage(ResultCode), mbCriticalError, MB_OK, IDOK);
    Exit;
  end;
  if ResultCode <> 0 then
    SuppressibleMsgBox('The Inwire Agent service was registered but did not start (exit code ' +
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

// The token has to reach a person. It is written to a file only an
// administrator can read - which is the point of it - so the one moment it can
// be shown to the person installing is here.
procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and (PairingToken <> '') then
  begin
    // NewLine rather than #13#10 written out: the preprocessor reads a '#'
    // at the start of a line as a directive, so a continuation line may not
    // begin with one.
    WizardForm.FinishedLabel.Caption :=
      'Inwire Agent is installed and running.' + NewLine + NewLine +
      'Paste this pairing token into Inwire once, under Settings -> Driver Info:'
      + NewLine + NewLine + '    ' + PairingToken + NewLine + NewLine +
      'It is also in %ProgramData%\Inwire\config.json, readable by administrators.';
  end;
end;
