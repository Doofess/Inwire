; A throwaway Inno Setup script that exists only to run the Pascal in
; installer/path.iss under the real Inno compiler and runtime. It installs
; nothing: InitializeSetup runs the table below, writes PASS/FAIL lines to the
; file named by /RESULTS=<file> (default %TEMP%\inwire-path-tests.txt), and
; returns False so Setup exits before any wizard page.
;
; Run by scripts/distribution/launcher-tests.ps1:
;   ISCC.exe scripts\distribution\path-tests.iss
;   <OutputDir>\inwire-path-tests.exe /VERYSILENT /RESULTS=<file>
;
; The last line of the results file is `SUMMARY pass=<n> fail=<n>`.

[Setup]
AppName=InwirePathTests
AppVersion=1
CreateAppDir=no
Uninstallable=no
PrivilegesRequired=lowest
DisableWelcomePage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
DisableFinishedPage=yes
OutputDir={#GetEnv("TEMP")}\inwire-path-tests-out
OutputBaseFilename=inwire-path-tests

[Code]
#include "..\..\installer\path.iss"

const
  O = 'C:\Program Files\Inwire\bin';
  Mixed = '%SystemRoot%\system32;;"C:\q r";C:\Foo\';
  RegKey = 'Software\InwirePathTest';

var
  Report: String;
  Passes, Failures: Integer;

procedure Say(const Line: String);
begin
  Report := Report + Line + #13#10;
end;

procedure Eq(const Name, Got, Want: String);
begin
  if Got = Want then
  begin
    Passes := Passes + 1;
    Say('PASS  ' + Name);
  end
  else
  begin
    Failures := Failures + 1;
    Say('FAIL  ' + Name);
    Say('        expected [' + Want + ']');
    Say('        actual   [' + Got + ']');
  end;
end;

function B(Value: Boolean): String;
begin
  if Value then Result := 'true' else Result := 'false';
end;

procedure TestNormalize;
begin
  Eq('normalize: trim, quotes, trailing backslash, case',
    PathNormalizeEntry('  "C:\Inwire\Bin\"  '), 'c:\inwire\bin');
  Eq('normalize: several trailing backslashes', PathNormalizeEntry('C:\a\\'), 'c:\a');
  Eq('normalize: empty', PathNormalizeEntry(''), '');
  Eq('normalize: a lone quote is left alone', PathNormalizeEntry('"'), '"');
  Eq('normalize: unexpanded variables are not expanded',
    PathNormalizeEntry('%SystemRoot%\System32'), '%systemroot%\system32');
  Eq('normalize: non-ASCII case folds',
    PathNormalizeEntry('C:\Inw' + #$00CF + 're'), 'c:\inw' + #$00EF + 're');
end;

procedure TestSplit;
var
  Entry: String;
  Next, Count: Integer;
  Raw, Joined: String;
begin
  // Splitting and re-joining must reproduce the input byte for byte, for every
  // awkward shape: this is what lets the other functions promise they leave
  // foreign text alone.
  Raw := '%SystemRoot%\system32;;"C:\q;r";C:\x\;';
  Joined := '';
  Count := 0;
  Next := 1;
  repeat
    Next := PathNextEntry(Raw, Next, Entry);
    if Count > 0 then Joined := Joined + ';';
    Joined := Joined + Entry;
    Count := Count + 1;
  until Next > Length(Raw) + 1;
  Eq('split: rejoining reproduces the raw value', Joined, Raw);
  Eq('split: a quoted ; does not split, an empty and a trailing segment count',
    IntToStr(Count), '5');

  Count := 0;
  Next := 1;
  repeat
    Next := PathNextEntry('', Next, Entry);
    Count := Count + 1;
  until Next > 1;
  Eq('split: the empty value is one empty segment', IntToStr(Count), '1');
end;

procedure TestHas;
begin
  Eq('has: exact', B(PathHasOwned('C:\Windows;' + O, O)), 'true');
  Eq('has: different case, quotes, trailing backslash',
    B(PathHasOwned('C:\x;"c:\PROGRAM FILES\inwire\BIN\"', O)), 'true');
  Eq('has: surrounding spaces', B(PathHasOwned(' ' + O + ' ;C:\x', O)), 'true');
  Eq('has: first of several', B(PathHasOwned(O + ';C:\x;C:\y', O)), 'true');
  Eq('has: absent', B(PathHasOwned('C:\Windows;C:\x', O)), 'false');
  Eq('has: a longer sibling is not it', B(PathHasOwned(O + '2', O)), 'false');
  Eq('has: its parent is not it', B(PathHasOwned('C:\Program Files\Inwire', O)), 'false');
  Eq('has: empty owned never matches', B(PathHasOwned('C:\x;;C:\y', '')), 'false');
  Eq('has: empty value', B(PathHasOwned('', O)), 'false');
  Eq('has: an unexpanded spelling is not recognised',
    B(PathHasOwned('%ProgramFiles%\Inwire\bin', O)), 'false');
  Eq('has: a ; inside quotes is not a separator',
    B(PathHasOwned('"C:\a;' + O + '";C:\b', O)), 'false');
  Eq('has: non-ASCII, case-insensitive',
    B(PathHasOwned('C:\Inw' + #$00EF + 're\bin', 'C:\INW' + #$00CF + 'RE\BIN')), 'true');
end;

procedure TestAppend;
begin
  Eq('append: plain', PathAppendOwned('C:\A;C:\B', O), 'C:\A;C:\B;' + O);
  Eq('append: after a trailing ; no doubled ;', PathAppendOwned('C:\A;C:\B;', O), 'C:\A;C:\B;' + O);
  Eq('append: after ;; keeps both', PathAppendOwned('C:\A;;', O), 'C:\A;;' + O);
  Eq('append: to an empty value', PathAppendOwned('', O), O);
  Eq('append: already present is unchanged', PathAppendOwned('C:\A;' + O, O), 'C:\A;' + O);
  Eq('append: present in another spelling is unchanged',
    PathAppendOwned('C:\A;"' + Lowercase(O) + '\"', O), 'C:\A;"' + Lowercase(O) + '\"');
  Eq('append: present twice is unchanged',
    PathAppendOwned(O + ';C:\A;' + O + '\', O), O + ';C:\A;' + O + '\');
  Eq('append: foreign text is kept byte for byte', PathAppendOwned(Mixed, O), Mixed + ';' + O);
  Eq('append: idempotent', PathAppendOwned(PathAppendOwned(Mixed, O), O), Mixed + ';' + O);
  Eq('append: empty owned is a no-op', PathAppendOwned('C:\A', ''), 'C:\A');
end;

procedure TestRemove;
begin
  Eq('remove: from the middle', PathRemoveOwned('C:\A;' + O + ';C:\B', O), 'C:\A;C:\B');
  Eq('remove: the only entry', PathRemoveOwned(O, O), '');
  Eq('remove: the last entry', PathRemoveOwned('C:\A;' + O, O), 'C:\A');
  Eq('remove: the first entry', PathRemoveOwned(O + ';C:\A', O), 'C:\A');
  Eq('remove: other spellings of it', PathRemoveOwned('C:\A;"' + Uppercase(O) + '\";C:\B', O), 'C:\A;C:\B');
  Eq('remove: present twice, both go', PathRemoveOwned(O + ';C:\A;' + O + '\;C:\B;' + O, O), 'C:\A;C:\B');
  Eq('remove: foreign text byte-identical',
    PathRemoveOwned(Mixed + ';' + O + ';C:\Z', O), Mixed + ';C:\Z');
  Eq('remove: absent leaves every byte', PathRemoveOwned('C:\A;;C:\B;', O), 'C:\A;;C:\B;');
  Eq('remove: a trailing empty segment survives', PathRemoveOwned('C:\A;' + O + ';', O), 'C:\A;');
  Eq('remove: empty owned is a no-op', PathRemoveOwned('C:\A;;C:\B', ''), 'C:\A;;C:\B');
  Eq('remove: a longer sibling stays', PathRemoveOwned(O + '2;' + O, O), O + '2');
  Eq('remove: unexpanded entries stay unexpanded',
    PathRemoveOwned('%ProgramFiles%\Inwire\bin;' + O, O), '%ProgramFiles%\Inwire\bin');
  // Install then uninstall returns the value it started from.
  Eq('round trip: mixed value', PathRemoveOwned(PathAppendOwned(Mixed, O), O), Mixed);
  Eq('round trip: plain value', PathRemoveOwned(PathAppendOwned('C:\A;C:\B', O), O), 'C:\A;C:\B');
  Eq('round trip: empty value', PathRemoveOwned(PathAppendOwned('', O), O), '');
end;

procedure TestExpand;
begin
  Eq('expand: a set variable', PathExpandEnv('%SystemRoot%\system32'), GetEnv('SystemRoot') + '\system32');
  Eq('expand: an unset variable stays', PathExpandEnv('%INWIRE_NOPE_XYZ%\a'), '%INWIRE_NOPE_XYZ%\a');
  Eq('expand: a lone % stays', PathExpandEnv('50%off'), '50%off');
  Eq('expand: %% stays', PathExpandEnv('a%%b'), 'a%%b');
  Eq('expand: no variables', PathExpandEnv('C:\plain'), 'C:\plain');
end;

procedure TestFind;
var
  Root, Other, Mine, Empty: String;
begin
  Root := GetEnv('TEMP') + '\inwire-path-find-scratch';
  DelTree(Root, True, True, True);
  Other := Root + '\other dir';
  Mine := Root + '\mine';
  Empty := Root + '\empty';
  ForceDirectories(Other);
  ForceDirectories(Mine);
  ForceDirectories(Empty);
  SaveStringToFile(Other + '\inwire.cmd', '@echo hi', False);
  SaveStringToFile(Mine + '\inwire.exe', 'x', False);

  Eq('find: a .cmd shim elsewhere is found',
    PathFindOtherCommand(Empty + ';' + Other + ';' + Mine, Mine, 'inwire'), Other + '\inwire.cmd');
  Eq('find: our own directory is never a collision',
    PathFindOtherCommand(Empty + ';' + Mine, Mine, 'inwire'), '');
  Eq('find: our own directory in another spelling is skipped',
    PathFindOtherCommand('"' + Uppercase(Mine) + '\";' + Empty, Mine, 'inwire'), '');
  Eq('find: found through quotes and a trailing backslash',
    PathFindOtherCommand('"' + Other + '\"', Mine, 'inwire'), Other + '\inwire.cmd');
  Eq('find: nothing there', PathFindOtherCommand(Empty + ';;C:\no-such-dir-xyz', Mine, 'inwire'), '');
  Eq('find: relative entries are not looked in', PathFindOtherCommand('.;inwire-no', Mine, 'inwire'), '');
  Eq('find: other names do not count', PathFindOtherCommand(Other, Mine, 'inwire2'), '');
  DeleteFile(Other + '\inwire.cmd');
  SaveStringToFile(Other + '\inwire.ps1', 'x', False);
  Eq('find: a .ps1 counts', PathFindOtherCommand(Other, Mine, 'inwire'), Other + '\inwire.ps1');
  DelTree(Root, True, True, True);
end;

// What the install step relies on: RegQueryStringValue hands back a
// REG_EXPAND_SZ value WITHOUT expanding it, and RegWriteExpandStringValue
// writes one back as REG_EXPAND_SZ. Checked against a scratch key in HKCU.
procedure TestRegistry;
var
  Back: String;
begin
  RegDeleteKeyIncludingSubkeys(HKCU, RegKey);
  if not RegWriteExpandStringValue(HKCU, RegKey, 'Path', '%SystemRoot%\system32;C:\x') then
    Eq('registry: scratch value written', 'no', 'yes')
  else
  begin
    Back := '';
    RegQueryStringValue(HKCU, RegKey, 'Path', Back);
    Eq('registry: RegQueryStringValue returns REG_EXPAND_SZ unexpanded', Back, '%SystemRoot%\system32;C:\x');
  end;
  RegDeleteKeyIncludingSubkeys(HKCU, RegKey);
end;

function InitializeSetup: Boolean;
var
  Results: String;
begin
  Report := '';
  Passes := 0;
  Failures := 0;
  TestNormalize;
  TestSplit;
  TestHas;
  TestAppend;
  TestRemove;
  TestExpand;
  TestFind;
  TestRegistry;
  Say('SUMMARY pass=' + IntToStr(Passes) + ' fail=' + IntToStr(Failures));
  Results := ExpandConstant('{param:RESULTS|}');
  if Results = '' then Results := GetEnv('TEMP') + '\inwire-path-tests.txt';
  SaveStringToFile(Results, Report, False);
  Result := False;
end;
