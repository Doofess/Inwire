; Inwire — the whole product, app and agent, in one installer.
; Build with Inno Setup 6.3.0 or newer:  iscc installer\setup.iss
;
; 6.3.0 is the floor because [Setup] uses ArchitecturesInstallIn64BitMode=
; x64compatible, an identifier introduced there that replaced the bare `x64`.
;
; ## Why Inno and not electron-builder's NSIS target
;
; Everything hard about installing this product is in the parts NSIS would have
; to re-derive: downloading Npcap at install time (a licensing constraint, not a
; technical one), registering a LocalSystem service with a failure-recovery
; policy, stopping a service that can starve its own event loop and miss an SCM
; stop, and cleaning up two earlier products by name. That is the
; highest-risk rewrite available in this migration for no user-visible gain.
;
; The cost, accepted: electron-updater cannot drive an Inno installer, so
; updates are hand-rolled.
;
; ## Two payloads, two directories
;
;   {app}          the Electron app     (electron-builder --dir output)
;   {app}\agent    the capture agent    (PyInstaller --onedir output)
;
; Separate because they are replaced on different schedules and by different
; things: a UI release ships a new app and the same agent, and the agent's exe
; is held open by a running service while the app's is not. Keeping them apart
; is what lets an update touch one without the other.

#define MyAppName "Inwire"
#define MyAppExeName "Inwire.exe"
#define MyAppPublisher "Inwire"

; Two version numbers, because they are two different things.
;
; MyAppVersion is the PRODUCT, and is what Windows compares to decide whether
; an install is an upgrade. Locked to package.json by test_protocol.py.
;
; MyAgentVersion is a WIRE PROTOCOL version - the left-hand side of
; `isAgentOutdated`, so an ordering that only ever climbs. Locked to
; AGENT_VERSION in agent.py and REQUIRED_AGENT_VERSION in agentProtocol.ts.
; They stopped moving in step the moment one installer carried both.
#define MyAppVersion "1.0.0"
#define MyAgentVersion "3.8.0"

#define AgentExeName "inwire-agent-windows.exe"
#define ServiceName "InwireAgent"
#define NpcapUrl "https://npcap.com/dist/npcap-1.79.exe"
; The expected SHA256, and it is not decoration: this installer runs elevated
; and hands whatever arrives at that URL to the user's machine as a kernel
; driver. `DownloadPage.Add`'s third argument was an empty string, which means
; "do not check", so an install over a hostile network installed whatever it
; was given.
;
; Provenance: downloaded 2026-09-12 and verified to carry a VALID Authenticode
; signature from `CN=Nmap Software LLC, O=Nmap Software LLC` before the hash was
; taken. So this pins an artifact whose publisher was checked, rather than
; whichever bytes happened to arrive first.
;
; **This constant and NpcapUrl move together.** A version bump with a stale
; hash fails the download with an integrity error, which is the correct and
; visible failure - but the URL will eventually 404 as Npcap ages releases out,
; and the fix for that is a version+hash pair served from a feed we control
; rather than a literal here.
#define NpcapSha256 "a95577ebbc67fc45b319e2ef3a55f4e9b211fe82ed4cb9d8be6b1a9e2425ce53"

; Where the payloads come from, relative to this file.
#define AppSource "..\release\win-unpacked"
#define AgentSource "..\local-agent\dist\inwire-agent-windows"

; ## The two products this one replaces
;
; The standalone agent installer, whose AppId this one deliberately does NOT
; reuse: a product resetting to 1.0.0 under it would read as a downgrade on
; every machine that has agent 3.x. It is uninstalled instead - see
; RemoveStandaloneAgent, and note that it registers a service by the SAME name,
; so leaving it in place means its uninstaller would one day delete ours.
#define StandaloneAgentAppId "{4C2F8E1A-6B3D-4E9F-8A2C-1D5E7F9A3B6C}"
; And the product's name before that, whose service must be DELETED rather than
; stopped: it is registered auto-start, so a stopped one is back at next boot.
#define LegacyAppName "NetView Agent"
#define LegacyExeName "netview-agent-windows.exe"
#define LegacyServiceName "NetViewAgent"

[Setup]
AppId={{F384C012-C351-40DE-B9E9-62AC2B6ED001}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=output
OutputBaseFilename=Inwire-Setup
SetupIconFile=..\local-agent\icon.ico
VersionInfoVersion={#MyAppVersion}.0
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
; 64-bit only: the Electron payload is x64 and the agent links a 64-bit Npcap.
ArchitecturesAllowed=x64compatible

; Restart Manager, rather than the `taskkill /F /IM Inwire.exe` this would
; otherwise need. It asks the running app to close and reports which processes
; hold files open, so a person with an unsaved capture is told rather than
; having the window vanish. `AppMutex` is the older way to do this and is not
; used: it needs the app to create a named Win32 mutex, which Electron cannot
; do without a native module, and a mutex name that silently stops matching is
; worse than no check.
CloseApplications=yes
; The app is not relaunched by Restart Manager - [Run] below offers it instead,
; so the person decides.
RestartApplications=no

[Files]
; The Electron app. `electron-builder --dir` output, verbatim.
Source: "{#AppSource}\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; The capture agent, in its own directory. A DIRECTORY because the PyInstaller
; build is --onedir: a onefile build extracts its DLLs to %TEMP%\_MEI<random>
; and runs them from there, which Defender's prevalence ASR rule blocks and
; which no amount of signing the wrapper makes signed. See inwire_agent.spec.
Source: "{#AgentSource}\*"; DestDir: "{app}\agent"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
; Config and log live here, present before anyone logs in - which a LocalSystem
; service needs. Inherits ProgramData's default ACLs.
Name: "{commonappdata}\Inwire"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Run]
Filename: "{tmp}\npcap-installer.exe"; Parameters: "/S /winpcap_mode=no"; \
    StatusMsg: "Installing the Npcap capture driver..."; \
    Check: NeedsNpcap; Flags: waituntilterminated
; Service registration is NOT here. [Run] entries ignore exit codes, and a
; failed registration would leave a "successful" install with no service and
; nothing on screen to say so. RegisterAgentService checks the result.
Filename: "{app}\{#MyAppExeName}"; Description: "Start {#MyAppName}"; \
    Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\agent\{#AgentExeName}"; Parameters: "stop"; \
    Flags: runhidden waituntilterminated; RunOnceId: "StopInwireAgent"
Filename: "{app}\agent\{#AgentExeName}"; Parameters: "remove"; \
    Flags: runhidden waituntilterminated; RunOnceId: "RemoveInwireAgent"

[UninstallDelete]
; The rotating log and its backups are litter once the agent is gone. Any
; config.json from before 3.8.0 is left alone: the Windows agent no longer
; reads it, and an uninstall that removes more than it installed is the wrong
; kind of surprise.
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
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing),
                                     SetupMessage(msgPreparingDesc),
                                     @OnDownloadProgress);
end;

// Npcap is fetched at install time rather than bundled, and that is a
// LICENSING constraint rather than a technical one: redistributing and
// silently installing the Npcap installer inside a packaged product needs an
// Npcap OEM licence, and downloading it on the user's own machine is not
// redistribution.
//
// Aborts rather than continues on failure. Finishing would leave a registered
// service that can never capture anything, which presents to the user as an
// app that installed cleanly and does not work.
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = wpReady) and NeedsNpcap then
  begin
    DownloadPage.Clear;
    DownloadPage.Add('{#NpcapUrl}', 'npcap-installer.exe', '{#NpcapSha256}');
    DownloadPage.Show;
    try
      try
        DownloadPage.Download;
      except
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

// --- version comparison -------------------------------------------------------

// Returns <0, 0 or >0. Written out rather than compared as strings, because
// '1.10.0' sorts before '1.9.0' and the whole point of the guard below is to
// get exactly that case right.
// Takes the leading MAJOR.MINOR.PATCH and ignores anything after it, so a
// DisplayVersion carrying a build suffix still compares.
procedure SplitVersion(const V: String; var Major, Minor, Patch: Integer);
var
  Rest, Part: String;
  Dot, Field: Integer;
begin
  Major := 0; Minor := 0; Patch := 0;
  Rest := V;
  for Field := 0 to 2 do
  begin
    Dot := Pos('.', Rest);
    if Dot > 0 then
    begin
      Part := Copy(Rest, 1, Dot - 1);
      Rest := Copy(Rest, Dot + 1, Length(Rest));
    end
    else
    begin
      Part := Rest;
      Rest := '';
    end;
    case Field of
      0: Major := StrToIntDef(Part, 0);
      1: Minor := StrToIntDef(Part, 0);
      2: Patch := StrToIntDef(Part, 0);
    end;
  end;
end;

function CompareVersions(const A, B: String): Integer;
var
  MajA, MinA, PatA, MajB, MinB, PatB: Integer;
begin
  SplitVersion(A, MajA, MinA, PatA);
  SplitVersion(B, MajB, MinB, PatB);
  Result := 0;
  if MajA <> MajB then
  begin
    if MajA > MajB then Result := 1 else Result := -1;
    Exit;
  end;
  if MinA <> MinB then
  begin
    if MinA > MinB then Result := 1 else Result := -1;
    Exit;
  end;
  if PatA <> PatB then
  begin
    if PatA > PatB then Result := 1 else Result := -1;
  end;
end;

function InstalledProductVersion: String;
begin
  Result := '';
  if not RegQueryStringValue(HKLM,
      'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{F384C012-C351-40DE-B9E9-62AC2B6ED001}_is1',
      'DisplayVersion', Result) then
    Result := '';
end;

// Refuses to install over something newer.
//
// Inno does not do this on its own: it will happily replace 1.4.0 with 1.0.0,
// and the result is an install whose Add/Remove entry says 1.0.0 over files
// from 1.4.0 that the older uninstaller does not know about. The hand-rolled
// updater runs this installer with /VERYSILENT, so a stale feed entry or a
// retried download is a realistic way to arrive here.
function InitializeSetup: Boolean;
var
  Installed: String;
begin
  Result := True;
  Installed := InstalledProductVersion;
  if (Installed <> '') and (CompareVersions(Installed, '{#MyAppVersion}') > 0) then
  begin
    SuppressibleMsgBox(
      'Inwire ' + Installed + ' is already installed, which is newer than this '
      + 'installer (' + '{#MyAppVersion}' + ').' + #13#10#13#10
      + 'Uninstall it first if you really mean to go back to an older version.',
      mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

// --- stopping what is running -------------------------------------------------

// Waits for the service to actually stop, or gives up.
//
// The previous installer slept a blind five seconds here. This asks instead,
// and the trick is that the ANSWER is locale-independent even though `sc`'s
// output is not: `sc stop` exits 1062 ("the service has not been started")
// once it is stopped, and 1060 when there is no such service. Both are exit
// codes, so no output is parsed and no translated string is matched.
//
// Bounded at roughly eight seconds. A service that has not stopped by then is
// wedged, and step 3 below is what handles that.
function WaitForServiceStopped(const Name: String): Boolean;
var
  I, ResultCode: Integer;
begin
  Result := False;
  for I := 1 to 32 do
  begin
    if not Exec(ExpandConstant('{sys}\sc.exe'), 'stop ' + Name, '',
                SW_HIDE, ewWaitUntilTerminated, ResultCode) then Exit;
    // 1062: not started. 1060: not installed. Either way nothing is running.
    if (ResultCode = 1062) or (ResultCode = 1060) then
    begin
      Result := True;
      Exit;
    end;
    Sleep(250);
  end;
end;

// Uninstalls the standalone agent product, if this machine has one.
//
// It has to go, and not for tidiness: it registers a service by the same name
// as ours, so leaving its Add/Remove entry in place means that one day
// somebody uninstalls "Inwire Agent" and takes this product's service with it.
// Its files also sit in a different directory that nothing would ever clean up.
procedure RemoveStandaloneAgent;
var
  UninstallString: String;
  ResultCode: Integer;
begin
  if not RegQueryStringValue(HKLM,
      'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#StandaloneAgentAppId}_is1',
      'UninstallString', UninstallString) then Exit;
  if UninstallString = '' then Exit;

  // Inno's own uninstaller, so these switches are the documented ones.
  // /NORESTART because this installer decides about restarts, not that one.
  UninstallString := RemoveQuotes(UninstallString);
  Exec(UninstallString, '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Verified rather than assumed: if its uninstaller failed or was cancelled,
  // the service is still registered and pointing at files this install is
  // about to orphan. Deleting the registration is enough - ours is registered
  // fresh below, and a leftover directory is inert.
  if not WaitForServiceStopped('{#ServiceName}') then
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AgentExeName}', '',
         SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#ServiceName}', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';

  // A running service holds an open handle on its own executable, and Windows
  // refuses to replace a file that is in use. Without this, upgrading over an
  // existing install dies partway through extraction with "DeleteFile failed;
  // code 5. Access is denied." - leaving only bad choices: keep the OLD binary
  // under a NEW version's install, or abandon setup. [UninstallRun] stops the
  // service too, but only on uninstall; an upgrade-in-place never goes through
  // it.
  //
  // Asking politely is not enough on its own. The agent can be alive but unable
  // to service a stop request - a high-rate interface can starve its event loop
  // until the SCM's stop control is never processed. That is the state a
  // machine is most likely to be in when somebody has gone looking for an
  // update.

  // 0. The service under the product's name from two renames ago. Deleted, not
  //    stopped: it is auto-start, so a stopped one is back at the next boot.
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#LegacyServiceName}', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#LegacyExeName}', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#LegacyServiceName}', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 1. The standalone agent product, which owns the same service name.
  RemoveStandaloneAgent;

  // 2. Our own service, if this is an upgrade. Bounded, and it returns as soon
  //    as the service is actually down rather than after a fixed sleep.
  if not WaitForServiceStopped('{#ServiceName}') then
  begin
    // 3. Wedged. Force is warranted: the alternative is a failed upgrade, and
    //    the agent holds no unsaved state - its config and log are separate
    //    files it is not mid-write on.
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AgentExeName}', '',
         SW_HIDE, ewWaitUntilTerminated, ResultCode);
    // The kernel releases the exe's handle when the process object goes, which
    // lags the kill slightly. This is the one wait left that cannot be asked
    // about, and it is short.
    Sleep(1000);
  end;
end;

// --- the service --------------------------------------------------------------

// Lets whoever is sitting at this machine START the agent, and nothing else.
//
// The app runs unelevated on purpose - the dissector must never parse hostile
// bytes as an administrator - so it cannot start a LocalSystem service. Without
// this, an agent that has stopped can only be restarted from an elevated
// prompt, and Driver Info's "Start the agent" button would raise a UAC prompt
// every time.
//
// `IU` is the interactive-user SID, the same principal the agent's named pipe
// admits (see pipe_server.py). Not a specific account SID: under a
// SYSTEM-context install (Intune, SCCM) there is no installing user to name,
// and granting the account that answered a UAC prompt would be wrong on a
// shared machine anyway.
//
// Only `RP` (start) is added. `WP` (stop) is deliberately withheld - the app
// never stops the service, `restart_agent` covers the rest, and a capture
// service an unprivileged process can stop is a capture service an
// unprivileged process can silence. The rest of the descriptor is byte-for-byte
// what Windows created: SY and BA are written back exactly as found, which is
// what stops a botched grant from locking SYSTEM out of its own service.
procedure GrantServiceStartToInteractiveUsers;
var
  ResultCode: Integer;
  Sd, Readback: AnsiString;
  SdPath: String;
begin
  // The default, plus RP on the IU ace. Stated in full rather than edited into
  // whatever `sc sdshow` returns: string surgery on a security descriptor is
  // how somebody eventually writes one that parses and means something else.
  Sd := 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)'
      + '(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)';

  if not Exec(ExpandConstant('{sys}\sc.exe'), 'sdset {#ServiceName} ' + Sd, '',
              SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
  begin
    // Not fatal. The service still runs and still starts at boot; what is lost
    // is the app's ability to start it after somebody stops it, which degrades
    // to a UAC prompt rather than to a broken install.
    Log('sdset failed (' + IntToStr(ResultCode) + '); the app will need a UAC prompt to start the agent');
    Exit;
  end;

  // Read back, because a descriptor that did not take is indistinguishable
  // from one that did until somebody presses a button that then does nothing.
  SdPath := ExpandConstant('{tmp}\sdshow.txt');
  // Through cmd because sc writes the descriptor to stdout and Exec cannot
  // capture it; the doubled quotes are cmd's rule for a command line whose
  // first token is itself quoted.
  Exec(ExpandConstant('{cmd}'),
       '/C ""' + ExpandConstant('{sys}\sc.exe') + '" sdshow {#ServiceName} > "' + SdPath + '""',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if LoadStringFromFile(SdPath, Readback) then
  begin
    if Pos('(A;;CCLCSWRPLOCRRC;;;IU)', Readback) = 0 then
      Log('sdset reported success but the readback does not carry the grant');
  end;
  DeleteFile(SdPath);
end;

procedure RegisterAgentService;
var
  ExePath, LogPath: String;
  ResultCode: Integer;
begin
  ExePath := ExpandConstant('{app}\agent\{#AgentExeName}');
  LogPath := ExpandConstant('{commonappdata}\Inwire\agent.log');

  // Options MUST precede the command. pywin32's HandleCommandLine parses with
  // getopt, which stops at the first non-option token - so "install --startup
  // auto" never sees --startup: it prints its usage screen and exits 1 without
  // registering anything.
  if not Exec(ExePath, '--startup auto install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    SuppressibleMsgBox('Could not launch the Inwire agent service installer.' + #13#10#13#10 +
      SysErrorMessage(ResultCode), mbCriticalError, MB_OK, IDOK);
    Exit;
  end;
  if ResultCode <> 0 then
  begin
    SuppressibleMsgBox('Registering the Inwire agent service failed (exit code ' +
      IntToStr(ResultCode) + ').' + #13#10#13#10 +
      'Inwire was installed but cannot capture until the service is registered.' + #13#10#13#10 +
      'See ' + LogPath + ' for details.', mbCriticalError, MB_OK, IDOK);
    Exit;
  end;

  // Restart-on-failure actions, set between registering and starting.
  //
  // This is what makes Driver Info's "Restart Agent" possible at all: the agent
  // restarts by exiting, and without these the SCM would treat that exit as a
  // dead service and leave it stopped. The agent re-asserts the same policy at
  // startup and refuses to exit on request when it cannot confirm it, so a
  // failure here degrades to the button being unavailable rather than to an
  // agent that cannot come back.
  //
  // reset= 86400 means three failures inside a day stop the restarts, so a
  // genuine crash loop is left stopped instead of being retried forever - which
  // is the state `agentHealth.ts` reports as "the capture agent keeps stopping".
  Exec(ExpandConstant('{sys}\sc.exe'),
       'failure {#ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  GrantServiceStartToInteractiveUsers;

  if not Exec(ExePath, 'start', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    SuppressibleMsgBox('Could not launch the Inwire agent service.' + #13#10#13#10 +
      SysErrorMessage(ResultCode), mbCriticalError, MB_OK, IDOK);
    Exit;
  end;
  if ResultCode <> 0 then
    SuppressibleMsgBox('The Inwire agent service was registered but did not start (exit code ' +
      IntToStr(ResultCode) + ').' + #13#10#13#10 +
      'It is set to start automatically, so a reboot may resolve it.' + #13#10#13#10 +
      'See ' + LogPath + ' for details.', mbError, MB_OK, IDOK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    RegisterAgentService;
end;
