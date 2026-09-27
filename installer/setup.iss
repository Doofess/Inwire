; Inwire — the whole product, app and agent, in one installer.
; Build with Inno Setup 6.3.0 or newer:  iscc installer\setup.iss
;
; 6.3.0 is the floor because [Setup] uses ArchitecturesInstallIn64BitMode=
; x64compatible, an identifier introduced there that replaced the bare `x64`.
;
; ## Why Inno and not electron-builder's NSIS target
;
; Everything hard about installing this product is in the parts NSIS would have
; to re-derive: registering a LocalSystem service with a failure-recovery
; policy, stopping a service that can starve its own event loop and miss an SCM
; stop, and cleaning up two earlier products by name. That is the
; highest-risk rewrite available in this migration for no user-visible gain.
;
; The cost, accepted: electron-updater cannot drive an Inno installer, so
; updates are hand-rolled.
;
; ## This installer does not install Npcap, and that is deliberate
;
; It used to. It downloaded npcap-1.79.exe at install time and ran it with
; `/S` - and `/S` is Npcap's **OEM silent-install feature**, used here against
; the free installer, whose licence does not grant it. That is gone, along with
; the download, the pinned SHA256, the DownloadPage and the three helpers that
; drove them.
;
; Two more things were wrong with it beyond the licence. The version was a
; compile-time `#define`, so correcting a stale pin meant shipping a new
; installer - the constant's own comment predicted the fix: "a version+hash
; pair served from a feed we control rather than a literal here". And `[Run]`
; ignores exit codes, so a failed driver install produced a "successful"
; product install with no capture capability and nothing on screen.
;
; Npcap is now the app's Update Center (Settings -> Updates), which reads the
; installed version, fetches from npcap.com on a click, verifies a hash from a
; feed that can be corrected without a release, and runs Npcap's own installer
; **visibly**, so its licence is shown to the person accepting it. A first
; launch with no driver lands on the "no capture interfaces" banner, which
; links there. See electron/updateCenter/ and docs/decisions/0032.
;
; What has not changed: uninstalling Inwire still leaves Npcap alone. Other
; tools on the machine may be using it, and it was never ours to remove.
;
; ## Two payloads, two directories
;
;   {app}          the Electron app     (electron-builder --dir output)
;   {app}\agent    the capture agent    (ONE file: the Rust agent, agent-rs/)
;
; Separate because they are replaced on different schedules and by different
; things: a UI release ships a new app and the same agent, and the agent's exe
; is held open by a running service while the app's is not. Keeping them apart
; is what lets an update touch one without the other.
;
; The agent is the Rust build (ADR 0037), not the PyInstaller one: one
; executable under a megabyte, where the Python agent was a 22 MB --onedir tree
; of .pyd and .dll files that signing the wrapper did not sign. It is installed
; under the Python agent's file name, so the service's ImagePath is the same
; string before and after an upgrade, and `install` over the existing
; registration updates it in place (agent-rs/src/main.rs). macOS and Linux
; keep the Python agent; this installer is Windows only.

#define MyAppName "Inwire"
#define MyAppExeName "Inwire.exe"
#define MyAppPublisher "Inwire"

; ONE version number, and it is the product's. ADR 0035.
;
; There were two. MyAgentVersion sat beside this line as a separate "wire
; protocol version", and it was defined here and **used nowhere in this file** -
; one of six stamps that had to be moved together by hand, held by two scripts
; covering different subsets of them. The agent had a number of its own because
; it used to be installed by its own installer against a web page of any age;
; this installer carries both halves and replaces them in one transaction, so
; two numbers could only ever disagree by mistake.
;
; It is 0.x because Inwire is in development (ADR 0051). The app compares the
; agent's number to its own for EQUALITY, so the number is free to go down; it
; was held at 4.x while that comparison was an ordering. What still orders is
; InitializeSetup below, which refuses to install over a newer Inwire - so a
; machine with 4.x on it uninstalls that once, and this installer after it.
;
; Locked to package.json, to agent_version.py, to agent-rs/Cargo.toml (which
; the Rust agent compiles in, and its VERSIONINFO is stamped from) and to
; REQUIRED_AGENT_VERSION by scripts/agent/version.ts, which runs on every
; `npm run check`.
#define MyAppVersion "0.4.1"

#define AgentExeName "inwire-agent-windows.exe"
#define ServiceName "InwireAgent"

; Where the payloads come from, relative to this file.
;
; AgentSource is NOT cargo's `target\release\`. `npm run build:agent` builds
; there, stamps a copy into agent-rs\dist - VERSIONINFO, the app's icon, an
; asInvoker manifest (scripts/agent/stamp-agent.ts) - under the name it is
; installed as, and then signs that copy in place (scripts/sign/sign.ps1).
; Stamp first, sign second, nothing after: any resource edit once it is signed
; is a signature that no longer verifies. Cargo's own output has no resources
; and no signature, and `scripts/agent/built-version.ts` reads this file's
; resources to catch a stale agent in a fresh installer.
#define AppSource "..\release\win-unpacked"
#define AgentSource "..\agent-rs\dist"

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

; ## Signing - off unless asked for
;
; A plain `iscc installer\setup.iss` compiles an UNSIGNED installer, as it always
; has. A signed one takes two switches:
;
;   iscc /DSIGN "/Sinwire=powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass $p" installer\setup.iss
;
; From PowerShell, single-quote the /S argument, or `$p` is expanded to nothing:
;
;   & $iscc /DSIGN '/Sinwire=powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass $p' installer\setup.iss
;
; /DSIGN turns on the directives below; /Sinwire= defines the Sign Tool they
; name, and it is deliberately ONLY the interpreter. Which script and which
; arguments is `$p`, written here from this file's own location, so the ISCC
; line carries no path and no certificate and works from any checkout. `inwire`
; is a name used by nothing else: Inno warns that a Sign Tool that is just `$p`
; runs whatever a `SignTool=` line says.
;
; Everything goes to scripts\sign\sign.ps1, the same script electron-builder's
; hook calls: it finds the certificate by thumbprint (INWIRE_SIGN_THUMBPRINT or
; the untracked .signing.json), signs SHA-256 and adds an RFC 3161 timestamp.
; -Require makes a missing certificate an error, because /DSIGN asked for a
; signed installer and an unsigned one is not a warning.
;
; What Inno signs: Inwire-Setup.exe, and - SignedUninstaller - the uninstaller
; and Setup's temporary self-copies. With a signed uninstaller Inno writes its
; messages to unins000.msg rather than into the exe, which would break the
; signature. Inno signs only what Inno makes.
;
; The PAYLOAD it only checks, and a signed build refuses one that fails. A
; signed Setup around an unsigned Inwire.exe is worse than an unsigned Setup:
; the outer signature is what a person looks at, and it would vouch for nothing
; inside - and a stale `release\win-unpacked`, or an agent built with no
; certificate configured, is exactly what an ordinary checkout contains. So
; under /DSIGN, before anything is compressed, the preprocessor runs
; scripts\sign\verify-payload.ps1 over what [Files] installs - every PE file
; under AppSource, found by content, and the agent - and anything but its
; INWIRE-PAYLOAD-OK line is a compile error that names the files. Inwire.exe
; and its DLLs are signed by `npm run pack`, and the agent by
; `npm run build:agent` after it stamps it (stamping rewrites the bytes a
; signature covers).
;
; The whole signed release, in order and with INWIRE_REQUIRE_SIGNING=1 so that
; no step can quietly skip signing, is one command:
;
;   npm run dist:signed          (scripts\sign\build-signed.ps1)
#ifdef SIGN
  #define SignScript SourcePath + "..\scripts\sign\sign.ps1"
  #define PayloadScript SourcePath + "..\scripts\sign\verify-payload.ps1"
  #define PayloadApp SourcePath + AppSource
  #define PayloadAgent SourcePath + AgentSource + "\" + AgentExeName
  #define PayloadVerdict ExecAndGetFirstLine(GetEnv("SystemRoot") + "\System32\WindowsPowerShell\v1.0\powershell.exe", '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + PayloadScript + '" "' + PayloadApp + '" "' + PayloadAgent + '"', SourcePath)
  #if Pos("INWIRE-PAYLOAD-OK ", PayloadVerdict) != 1
    #expr Error("Refusing a signed installer around an unsigned payload - " + PayloadVerdict + " - run scripts\sign\verify-payload.ps1 for the detail.")
  #endif
SignTool=inwire -File $q{#SignScript}$q -Require -Path $f
SignedUninstaller=yes
#endif

[InstallDelete]
; **Inno adds files and never removes them.** An upgrade copies the new payload
; over the old one and leaves behind anything the new build no longer ships, so
; a directory only ever grows.
;
; That is not hypothetical here: dropping `tkinter` from the agent's spec took
; the payload from 30 MB to 22 MB, and an upgrade over the previous build left
; all 7.2 MB of `_tk_data` sitting in `{app}\agent\_internal` where nothing
; would ever load it again. The install reported success, the version was
; right, and the saving was entirely undone.
;
; Both directories are build output and nothing else - PyInstaller's `_internal`
; and electron-builder's `resources` - so clearing them before the copy is
; recreating them, not discarding anything a user owns. `{app}` itself is
; deliberately NOT cleared: `{app}\agent` holds no config (that is
; `{commonappdata}\Inwire`), but the app directory is where an uninstaller and
; anything a future version writes would live.
;
; `_internal` is now ONLY a leftover: the Rust agent is one file and ships no
; such directory. That makes this line the whole of the Python agent's removal
; on upgrade - its exe is overwritten by the Rust one under the same name, and
; this takes the 22 MB beside it. Keep it for as long as an install from before
; the swap can exist.
Type: filesandordirs; Name: "{app}\agent\_internal"
Type: filesandordirs; Name: "{app}\resources"
; The same leftover problem one level up. Earlier builds shipped DirectX's
; shader compiler beside Inwire.exe and this one does not, so an upgrade left
; both behind - and dxcompiler.dll is unsigned, which made it the one file in a
; signed install that was not. Named rather than swept: {app} also holds the
; uninstaller and its log, which a wildcard here would take with it.
Type: files; Name: "{app}\dxcompiler.dll"
Type: files; Name: "{app}\dxil.dll"

[Files]
; The Electron app. `electron-builder --dir` output, verbatim.
Source: "{#AppSource}\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; The capture agent, in its own directory: one file, the Rust build, named
; exactly as the Python agent's exe was so the service's ImagePath does not
; move. Named rather than globbed, so a stray file in agent-rs\dist is not
; installed into a directory a LocalSystem service runs from.
;
; ignoreversion because both agents stamp the product version, so an upgrade
; from the Python agent at the same version would otherwise be skipped as "not
; newer" and leave the Python exe in place with its `_internal` deleted above.
Source: "{#AgentSource}\{#AgentExeName}"; DestDir: "{app}\agent"; \
    Flags: ignoreversion

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
  // Asking politely is not enough on its own. An agent can be alive but unable
  // to service a stop request: the Python agent's event loop could be starved
  // by a high-rate interface until the SCM's stop control was never processed,
  // and the upgrade that replaces it with the Rust agent is exactly when that
  // is the agent running. That is the state a machine is most likely to be in
  // when somebody has gone looking for an update.
  //
  // Both agents run as {#AgentExeName} from {app}\agent, so the one image name
  // below covers whichever this machine has.

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
// bytes as an administrator - so without a grant it cannot start a LocalSystem
// service at all, and an agent that has stopped could only be restarted from an
// elevated prompt.
//
// **Demand start leans on this grant every time the app opens.** `ensureRunning`
// in `electron/agentPipe.ts` runs an unelevated `sc start InwireAgent` at
// launch (ADR 0035), and `electron/serviceStart.ts` lets exactly one answer -
// ERROR_ACCESS_DENIED, which is what a missing grant produces - reach a UAC
// prompt, and only from a click. So this is what makes the agent come up with
// the window instead of behind a button and a prompt. (The comment here once
// said the app did not take the grant up; it did not then, and it does now.)
//
// `IU` is the interactive-user SID, the same principal the agent's named pipe
// admits (agent-rs/src/pipe.rs, as local-agent/pipe_server.py did before it).
// Not a specific account SID: under a SYSTEM-context install (Intune, SCCM)
// there is no installing user to name, and granting the account that answered
// a UAC prompt would be wrong on a shared machine anyway.
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
    // Not fatal, but it costs every launch rather than an edge case. The
    // service is demand-start, so without this grant the app's unelevated
    // start is refused each time Inwire opens, and the agent comes up only
    // after a click and a UAC prompt. That degrades the product rather than
    // breaking the install, so it is logged rather than raised.
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

  // Options first. The Rust agent accepts either order; the Python agent's
  // pywin32 HandleCommandLine parsed with getopt, which stops at the first
  // non-option token, so "install --startup manual" printed a usage screen and
  // exited 1 without registering anything. The line stays in the one order
  // both ever accepted - `switch-agent.ps1 -Python` still runs it against the
  // Python agent - and `--startup` takes a VALUE, which is the other way this
  // exact line has been misparsed (agent-rs/src/main.rs).
  //
  // **`install` over an existing InwireAgent updates it.** An upgrade always
  // finds one - the Python agent's, an earlier Rust build's, the standalone
  // agent's if its uninstaller failed - under the same name and, because the
  // file name did not change, the same image path. pywin32 fell through from
  // install to update on ERROR_SERVICE_EXISTS; the Rust agent does the same,
  // rewriting image path, start type, account (LocalSystem) and display name,
  // and leaving the npcap dependency to the step below. Before that, it failed
  // here with exit code 1 on every upgrade.
  //
  // **manual, not auto, and that is the whole of ADR 0035.** Auto meant a
  // LocalSystem capture service running from boot on a machine where Inwire
  // may never be opened - paying for itself in memory and attack surface for
  // an app nobody launched. Demand start means the app asks for it at
  // `whenReady()` (`electron/agentPipe.ts`) and the agent stops itself when the
  // last client goes away (the idle watchdog in agent-rs/src/runtime.rs), so
  // its lifetime is the app's. The right that makes the unelevated ask work is
  // granted below, by GrantServiceStartToInteractiveUsers.
  if not Exec(ExePath, '--startup manual install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
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
  // restarts by exiting with a failure code, and without these the SCM would
  // treat that exit as a dead service and leave it stopped. The agent
  // re-asserts the same policy at startup and refuses to exit on request when
  // it cannot confirm it, so a failure here degrades to the button being
  // unavailable rather than to an agent that cannot come back.
  //
  // **The re-assert only works since it asks for SERVICE_START.**
  // ChangeServiceConfig2 refuses a restart action from a handle without it,
  // and both agents opened the service with CHANGE_CONFIG and QUERY_CONFIG
  // alone and discarded the error - so until agent-rs/src/restart.rs added it,
  // this line was the only thing that ever set the policy, and the agent's
  // half was a read. The Rust agent logs the write's outcome now.
  //
  // **Which makes the idle self-stop's exit code load-bearing.** It must be 0,
  // and is (ADR 0037 measured it: STOPPED, exit code 0, 2.4 s after the last
  // client left). A non-zero one would have these actions restart a
  // demand-start service every five seconds for ever, with nobody asking.
  //
  // reset= 86400 means three failures inside a day stop the restarts, so a
  // genuine crash loop is left stopped instead of being retried forever - which
  // is the state `agentHealth.ts` reports as "the capture agent keeps stopping".
  Exec(ExpandConstant('{sys}\sc.exe'),
       'failure {#ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Start after Npcap's driver, but ONLY if Npcap is here to start after.
  //
  // What this fixed, when the service was auto-start: the agent could beat
  // Npcap's NDIS binding at boot and enumerate nothing. Observed on a
  // development machine - the log read "detected 1 network interface(s):
  // Loopback Pseudo-Interface 1" and stayed that way, because the list is only
  // re-read when a client connects and nothing could connect. Demand start
  // makes that race rare - the app asks after logon - but not impossible (an
  // Inwire in the Startup folder), and the ordering costs nothing.
  //
  // Why it is CONDITIONAL, and must stay so: a service whose dependency does
  // not exist does not start at all. Windows reports "the dependency service
  // does not exist", the agent never runs, and the app says "the capture agent
  // is not running" - a worse failure than the one this prevents, and one with
  // no visible cause. Npcap is no longer installed by this installer (0032), so
  // "not installed yet" is an ordinary first-run state rather than an error:
  // the Update Center fetches it later, on a click.
  //
  // The residual case is deliberate and small: install without Npcap, add it
  // from the Update Center, and no dependency is ever set. The boot race is
  // then still possible - and still covered in software, because the agent
  // re-reads the interface list on every client connection, which is why that
  // code exists in both agents. This only removes the race, it is not what
  // handles it.
  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npcap') then
  begin
    // Exit code ignored on purpose. Failing to order two services is not a
    // reason to fail an install that is otherwise complete and will work.
    Exec(ExpandConstant('{sys}\sc.exe'), 'config {#ServiceName} depend= npcap',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if ResultCode <> 0 then
      Log('could not set the npcap dependency (' + IntToStr(ResultCode) +
          '); the agent may enumerate nothing if it wins the boot race');
  end
  else
    Log('npcap is not installed; leaving the agent with no dependency, or it could never start');

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
      'It starts on demand, so opening Inwire will ask for it again, and ' +
      'Settings > Driver Info says why it is not running.' + #13#10#13#10 +
      'See ' + LogPath + ' for details.', mbError, MB_OK, IDOK);
end;

// Removes what pywin32 registered beside the Python agent's service.
//
// `install` over an existing registration rewrites the service's own values
// and nothing else under its key, and pywin32 left two things behind that
// nothing reads once the Rust agent has replaced it:
//
//   - Services\InwireAgent\PythonClass, the class its service host imported;
//   - an Application event-log source whose message file is
//     {app}\agent\_internal\win32\servicemanager.pyd - which [InstallDelete]
//     has just removed, so Event Viewer would render every entry the Python
//     agent ever wrote as "the description cannot be found".
//
// The source is deleted only when its message file is under `_internal`, i.e.
// when it is provably pywin32's: an event-log source name is machine-wide, and
// deleting one this installer cannot show it created is the wrong kind of
// cleanup. The Rust agent writes no event log - its log is agent.log.
procedure RemovePythonAgentRegistrations;
var
  MessageFile: String;
begin
  RegDeleteKeyIncludingSubkeys(HKLM, 'SYSTEM\CurrentControlSet\Services\{#ServiceName}\PythonClass');
  if RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\EventLog\Application\{#ServiceName}',
                         'EventMessageFile', MessageFile)
     and (Pos('\_internal\', Lowercase(MessageFile)) > 0) then
    RegDeleteKeyIncludingSubkeys(HKLM, 'SYSTEM\CurrentControlSet\Services\EventLog\Application\{#ServiceName}');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    RemovePythonAgentRegistrations;
    RegisterAgentService;
  end;
end;
