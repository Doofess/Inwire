// The machine-PATH helpers behind the `inwire` command. #include'd into the
// [Code] section of setup.iss (and of scripts/distribution/path-tests.iss, which
// is what tests them); nothing here touches the registry, so it can be tested
// with strings.
//
// ## The rules these functions keep
//
// A PATH value is a list of segments joined by ';'. This installer is allowed to
// add ONE segment (its own bin directory) and later remove that one segment, and
// it must leave every other byte of the user's PATH exactly as it found it:
//
//   - entries that are still unexpanded (`%SystemRoot%\system32`) stay unexpanded;
//   - empty segments (`;;`, a trailing `;`), quotes, case, trailing backslashes
//     and the order of every other entry are untouched.
//
// So the value is split WITHOUT interpreting it (PathNextEntry returns each raw
// segment), and the only interpretation anywhere is PathNormalizeEntry, which is
// used to COMPARE and never to write. The split is quote-aware, because Windows'
// own search treats a ';' inside "quotes" as part of the entry; an unbalanced
// quote therefore swallows the rest of the value into one segment, exactly as
// the loader would read it.
//
// Joining the segments PathNextEntry yields with ';' reproduces the input byte
// for byte (for "a;b;" it yields 'a', 'b' and '' - the trailing empty segment is
// a segment).
//
// Not matched, deliberately: `%ProgramFiles%\Inwire\bin` is not the same string
// as `C:\Program Files\Inwire\bin` here, because expanding the user's entries to
// compare them would mean choosing an environment to expand in. A hand-added,
// differently spelled entry is therefore not recognised as ours - we add ours
// beside it, and uninstall removes only the one we recorded.
//
// Removal drops a segment together with one adjacent separator (it joins the
// kept segments), so install followed by uninstall returns the original value
// except for one trivial case: a value that ended in ';' loses that trailing
// empty segment when our entry, appended after it, is removed again.

// The segment that starts at 1-based index Start, and the index at which the NEXT
// segment starts. A caller loops until the returned index is past Length+1:
//
//   Next := 1;
//   repeat
//     Next := PathNextEntry(Raw, Next, Entry);
//     ...
//   until Next > Length(Raw) + 1;
function PathNextEntry(const Raw: String; Start: Integer; var Entry: String): Integer;
var
  I, Len: Integer;
  InQuote: Boolean;
begin
  Len := Length(Raw);
  InQuote := False;
  I := Start;
  while I <= Len do
  begin
    if Raw[I] = '"' then
      InQuote := not InQuote
    else if (Raw[I] = ';') and not InQuote then
      Break;
    I := I + 1;
  end;
  Entry := Copy(Raw, Start, I - Start);
  Result := I + 1;
end;

// For COMPARING only: trim, strip one pair of surrounding quotes, strip trailing
// backslashes, lower-case. Never used to produce text that is written back.
function PathNormalizeEntry(const Entry: String): String;
var
  Len: Integer;
begin
  Result := Trim(Entry);
  Len := Length(Result);
  if (Len >= 2) and (Result[1] = '"') and (Result[Len] = '"') then
    Result := Trim(Copy(Result, 2, Len - 2));
  Len := Length(Result);
  while (Len > 0) and (Result[Len] = '\') do
  begin
    Delete(Result, Len, 1);
    Len := Length(Result);
  end;
  // AnsiLowercase, not Lowercase: the latter folds ASCII only, and an install
  // directory can hold any letter.
  Result := AnsiLowercase(Result);
end;

function PathHasOwned(const Raw, Owned: String): Boolean;
var
  Want, Entry: String;
  Next: Integer;
begin
  Result := False;
  Want := PathNormalizeEntry(Owned);
  if Want = '' then Exit;
  Next := 1;
  repeat
    Next := PathNextEntry(Raw, Next, Entry);
    if PathNormalizeEntry(Entry) = Want then
    begin
      Result := True;
      Exit;
    end;
  until Next > Length(Raw) + 1;
end;

// Raw unchanged when Owned is already there; otherwise Raw with Owned after it,
// separated by ONE ';' (none when Raw is empty or already ends in one).
function PathAppendOwned(const Raw, Owned: String): String;
begin
  if (Trim(Owned) = '') or PathHasOwned(Raw, Owned) then
    Result := Raw
  else if Raw = '' then
    Result := Owned
  else if Raw[Length(Raw)] = ';' then
    Result := Raw + Owned
  else
    Result := Raw + ';' + Owned;
end;

// Raw without every segment that matches Owned; every other segment is carried
// over as the exact text it was.
function PathRemoveOwned(const Raw, Owned: String): String;
var
  Want, Entry: String;
  Next: Integer;
  Kept: Boolean;
begin
  Want := PathNormalizeEntry(Owned);
  if Want = '' then
  begin
    Result := Raw;
    Exit;
  end;
  Result := '';
  Kept := False;
  Next := 1;
  repeat
    Next := PathNextEntry(Raw, Next, Entry);
    if PathNormalizeEntry(Entry) <> Want then
    begin
      if Kept then Result := Result + ';';
      Result := Result + Entry;
      Kept := True;
    end;
  until Next > Length(Raw) + 1;
end;

// Whether an upgrade finds its own entry taken out by hand: the marker
// (Recorded) says this installer added exactly Owned once, and Raw no longer
// has it. That absence is the person's choice, so the install step leaves PATH
// alone and keeps the marker. A marker for another directory is a moved
// install, not a removal; no marker is a first install.
function PathOwnedRemovedByHand(const Raw, Owned, Recorded: String): Boolean;
begin
  Result := (Trim(Recorded) <> '')
    and (PathNormalizeEntry(Recorded) = PathNormalizeEntry(Owned))
    and not PathHasOwned(Raw, Owned);
end;

// --- finding a different `inwire` already on PATH ---------------------------

// %NAME% expanded from the environment of this process. For an existence test
// only: what is written to the registry is never expanded. An unset or
// unterminated %NAME% is left as it is.
function PathExpandEnv(const S: String): String;
var
  Rest, Name, Value: String;
  Open, Close: Integer;
begin
  Result := '';
  Rest := S;
  while Rest <> '' do
  begin
    Open := Pos('%', Rest);
    if Open = 0 then
    begin
      Result := Result + Rest;
      Exit;
    end;
    Result := Result + Copy(Rest, 1, Open - 1);
    Rest := Copy(Rest, Open + 1, Length(Rest));
    Close := Pos('%', Rest);
    if Close = 0 then
    begin
      Result := Result + '%' + Rest;
      Exit;
    end;
    Name := Copy(Rest, 1, Close - 1);
    Value := '';
    if Name <> '' then Value := GetEnv(Name);
    if Value <> '' then
      Result := Result + Value
    else
      Result := Result + '%' + Name + '%';
    Rest := Copy(Rest, Close + 1, Length(Rest));
  end;
end;

// The full path of the first file called Name.exe|.com|.bat|.cmd|.ps1 in a
// directory listed in Raw, skipping the segment that is Owned. '' when there is
// none. Only absolute entries are looked in: a relative one means "wherever the
// shell happens to be", which says nothing about what `inwire` would run from
// anywhere else.
function PathFindOtherCommand(const Raw, Owned, Name: String): String;
var
  Want, Entry, Dir, Candidate: String;
  Next, Ext: Integer;
  Extensions: array[0..4] of String;
begin
  Result := '';
  Extensions[0] := '.exe';
  Extensions[1] := '.com';
  Extensions[2] := '.bat';
  Extensions[3] := '.cmd';
  Extensions[4] := '.ps1';
  Want := PathNormalizeEntry(Owned);
  Next := 1;
  repeat
    Next := PathNextEntry(Raw, Next, Entry);
    if PathNormalizeEntry(Entry) <> Want then
    begin
      Dir := Trim(Entry);
      if (Length(Dir) >= 2) and (Dir[1] = '"') and (Dir[Length(Dir)] = '"') then
        Dir := Trim(Copy(Dir, 2, Length(Dir) - 2));
      Dir := PathExpandEnv(Dir);
      // Our own directory, spelled through a variable or with forward slashes,
      // holds our own launcher, which is not "another inwire". An 8.3 short
      // name or a junction is not recognised and is still reported.
      StringChangeEx(Dir, '/', '\', True);
      if PathNormalizeEntry(Dir) = Want then
        Dir := '';
      if ((Length(Dir) >= 3) and (Dir[2] = ':')) or (Copy(Dir, 1, 2) = '\\') then
      begin
        for Ext := 0 to 4 do
        begin
          Candidate := AddBackslash(Dir) + Name + Extensions[Ext];
          if FileExists(Candidate) then
          begin
            Result := Candidate;
            Exit;
          end;
        end;
      end;
    end;
  until Next > Length(Raw) + 1;
end;
