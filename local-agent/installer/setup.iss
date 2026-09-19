; Inwire Agent installer
; Build with Inno Setup 6.3.0 or newer:  iscc setup.iss
;
; 6.3.0 is the floor because [Setup] uses ArchitecturesInstallIn64BitMode=
; x64compatible, an identifier introduced in 6.3.0 that replaced the older
; bare `x64`.
;
; Installs the agent as a Windows service that starts at boot and shows no
; UI of any kind.
;
; ## Superseded, and no longer installs Npcap
;
; The product now ships as one installer at the repository root, which lays
; down the app and the agent together and uninstalls this one by AppId.
;
; What keeps this file, stated accurately because the two reasons it used to
; give were both wrong. It said it was kept "because that removal reads its
; AppId, and because macOS and Linux still install an agent on its own".
; Neither holds: installer/setup.iss carries its own copy of the GUID as
; `#define StandaloneAgentAppId` and never opens this file, and an Inno script
; installs nothing on macOS or Linux - that is the tarball from
; scripts/agent/package-unix.ts and unix/install.sh.
;
; It is kept because it is the SOURCE of the product an agent-3.x machine
; actually has installed, so the AppId and the version stamps below are a
; record of what is out there rather than a build input. One assertion script
; reads it and would have to change with it: scripts/agent/version.ts (its
; `LEGACY`), which asserts both stamps stay FROZEN rather than tracking the
; product. test_protocol.py used to read it too and no longer does - the agent
; has no version of its own to lock (ADR 0035). Nothing builds it -
; no npm script compiles it, and the release checklist runs
; `iscc installer/setup.iss` only.
;
; Its Npcap handling is gone. It was worse than the unified installer's: the
; same `/S` - Npcap's OEM silent-install switch, which the free licence does
; not grant - and `DownloadPage.Add`'s third argument was `''`, meaning **no
; integrity check at all**, so an elevated install over a hostile network ran
; whatever arrived as a kernel driver.
;
; Npcap is the app's business now: Settings -> Updates fetches it from
; npcap.com on a click, verifies a published hash, and runs Npcap's own
; installer visibly so its licence is shown. See docs/decisions/0032.

#define MyAppName "Inwire Agent"
; Two numbers, because they are two different things and only ever looked like
; one while this installer shipped the agent and nothing else.
;
; **These two numbers are FROZEN, and that is the point of this file now.**
;
; Nothing builds this installer. It is the record of what a machine with the
; agent-only install actually has on it - 3.9.0, under its own AppId - which is
; what the unified installer reads in order to uninstall it. A record that
; tracked the current version would describe an install that was never made.
;
; So they no longer move with the product, and `scripts/agent/version.ts`
; asserts they do not. Before ADR 0035 they were two of six stamps that had to
; be bumped together by hand; now the product has ONE version (package.json,
; agent_version.py, REQUIRED_AGENT_VERSION and the shipping installer's
; MyAppVersion), and these are history rather than configuration.
;
; If this file is ever built again - it should not be - both numbers are wrong
; and the AppId question in the paragraph below has to be re-answered first.
#define MyAgentVersion "3.9.0"
#define MyAppVersion "1.0.0"
#define MyAppExeName "inwire-agent-windows.exe"
#define MyAppPublisher "Inwire"

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
AppVersion={#MyAgentVersion}
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
VersionInfoVersion={#MyAgentVersion}.0
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAgentVersion}
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
; A DIRECTORY since 3.8.0, because the PyInstaller build is --onedir. A onefile
; build extracts its DLLs to %TEMP%\_MEI<random> and runs them from there,
; which Defender's prevalence ASR rule blocks outright and which no amount of
; signing the wrapper makes signed. See the reasoning in inwire_agent.spec.
;
; recursesubdirs and createallsubdirs are both required: PyInstaller puts
; almost everything under `_internal`, and without them the exe installs alone
; and fails to start with no message anywhere.
Source: "..\dist\inwire-agent-windows\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

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
; The rotating log and its backups are litter once the agent is gone. Any
; `config.json` left by an install before 3.8.0 is kept rather than removed:
; the Windows agent no longer reads it, so deleting it would be tidying up
; somebody's file for no benefit, and an uninstall that removes more than it
; installed is the wrong kind of surprise.
Type: files; Name: "{commonappdata}\Inwire\agent.log"
Type: files; Name: "{commonappdata}\Inwire\agent.log.*"

[Code]
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

// A token used to be minted here, and a `NewLine` helper existed to show it on
// the finished page. Both are gone with it (3.8.0).
//
// The agent's transport on Windows is a named pipe whose security descriptor
// says who may open it, so there is no secret to generate, no `--init-config`
// to run, and nothing for the person installing to copy down. `config.json` is
// no longer seeded at all: the Windows agent reads no origin allowlist and no
// token, and a file written only to be ignored is a file someone will later
// try to configure.

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
    RegisterAgentService;
end;
