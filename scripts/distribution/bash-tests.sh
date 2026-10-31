#!/usr/bin/env bash
# The Git Bash bridge, distribution/install-inwire.sh, against a fake Windows
# PowerShell. Run: bash scripts/distribution/bash-tests.sh
#
# The fake is a shell script named powershell.exe under a temporary
# SYSTEMROOT, because the bridge runs PowerShell from SYSTEMROOT and never
# from PATH. It writes each argument it was given on its own line, so a test
# can see exactly where one argument ends and the next begins, and exits with
# FAKE_EXIT. `uname` is faked the same way, first on PATH, to stand in for
# Linux, macOS and WSL.
#
# Every hostile value below would create the file `pwned` in the work
# directory if anything evaluated it. The last check is that it never exists.

set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bridge="$here/../../distribution/install-inwire.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work" || exit 1

failures=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }

# --- fakes ---------------------------------------------------------------

fakeroot="$work/Windows"
mkdir -p "$fakeroot/System32/WindowsPowerShell/v1.0" "$work/fakebin"
cat > "$fakeroot/System32/WindowsPowerShell/v1.0/powershell.exe" <<'EOF'
#!/usr/bin/env bash
: > "$FAKE_LOG"
for a in "$@"; do printf '%s\n' "$a" >> "$FAKE_LOG"; done
exit "${FAKE_EXIT:-0}"
EOF
chmod +x "$fakeroot/System32/WindowsPowerShell/v1.0/powershell.exe"

cat > "$work/fakebin/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -r) printf '%s\n' "${FAKE_UNAME_R:-3.6.0}" ;;
  *) printf '%s\n' "${FAKE_UNAME_S:-MINGW64_NT-10.0-26300}" ;;
esac
EOF
chmod +x "$work/fakebin/uname"

# A bootstrap in a directory whose name is every metacharacter at once.
hostile_dir="$work/-Launch \$(touch pwned) \`touch pwned\` ; & ïnw ✓"
mkdir -p "$hostile_dir"
printf '# fake bootstrap\n' > "$hostile_dir/install-inwire.ps1"
plain_dir="$work/plain"
mkdir -p "$plain_dir"
printf '# fake bootstrap\n' > "$plain_dir/install-inwire.ps1"

export FAKE_LOG="$work/argv.txt"

# Runs the bridge with the fakes in place. Sets $code and $out.
run() {
  rm -f "$FAKE_LOG"
  out=$(PATH="$work/fakebin:$PATH" SYSTEMROOT="$fakeroot" bash "$bridge" "$@" 2>&1)
  code=$?
}

called() { [ -f "$FAKE_LOG" ]; }

# Expected argv for a bootstrap path, as the fake would write it.
expect_argv() {
  local file="$work/expected.txt"
  : > "$file"
  for a in "$@"; do printf '%s\n' "$a" >> "$file"; done
  cmp -s "$file" "$FAKE_LOG"
}

# --- syntax ----------------------------------------------------------------

if bash -n "$bridge" 2>/dev/null; then pass 'bash -n accepts the bridge'; else fail 'bash -n rejects the bridge'; fi

# --- argument boundaries -----------------------------------------------------

win_plain=$(cygpath -w "$plain_dir/install-inwire.ps1")
run --bootstrap "$plain_dir/install-inwire.ps1" --product Desktop --version 1.2.3 --launch
if [ "$code" = 0 ] && called && expect_argv -NoProfile -File "$win_plain" -Product Desktop -Version 1.2.3 -Launch; then
  pass 'product, version and launch arrive as separate arguments, the path as a Windows path'
else
  fail "argv for a plain call (exit $code): $(tr '\n' '|' < "$FAKE_LOG" 2>/dev/null)"
fi

run --bootstrap "$plain_dir/install-inwire.ps1"
if [ "$code" = 0 ] && expect_argv -NoProfile -File "$win_plain" -Product Desktop; then
  pass 'the default product is Desktop and nothing launches unless asked'
else
  fail "default argv (exit $code): $(tr '\n' '|' < "$FAKE_LOG" 2>/dev/null)"
fi

run --bootstrap "$plain_dir/install-inwire.ps1" --product EndpointAgent --repair
if [ "$code" = 0 ] && expect_argv -NoProfile -File "$win_plain" -Product EndpointAgent -Repair; then
  pass 'EndpointAgent and --repair pass through for the bootstrap to answer'
else
  fail "endpoint argv (exit $code): $(tr '\n' '|' < "$FAKE_LOG" 2>/dev/null)"
fi

win_hostile=$(cygpath -w "$hostile_dir/install-inwire.ps1")
run --bootstrap "$hostile_dir/install-inwire.ps1" --version 0.5.0
if [ "$code" = 0 ] && expect_argv -NoProfile -File "$win_hostile" -Product Desktop -Version 0.5.0; then
  pass 'a path of spaces, Unicode, ;, &, $(), backticks and a leading hyphen is one argument'
else
  fail "hostile path argv (exit $code): $(tr '\n' '|' < "$FAKE_LOG" 2>/dev/null)"
fi

if grep -q '^/' "$FAKE_LOG" 2>/dev/null; then
  fail 'an argument starting with / reached PowerShell (MSYS would rewrite it)'
else
  pass 'no slash switch crosses the bridge; Inno switches stay inside PowerShell'
fi

# --- values that must never reach PowerShell ---------------------------------

for bad in '1.2.3; touch pwned' '$(touch pwned)' '`touch pwned`' '-Launch' '1.2' '1.2.3 -Launch' ''; do
  run --bootstrap "$plain_dir/install-inwire.ps1" --version "$bad"
  if [ "$code" = 10 ] && ! called; then
    pass "version '$bad' is refused (10) before PowerShell runs"
  else
    fail "version '$bad': exit $code, PowerShell called: $(called && echo yes || echo no)"
  fi
done

for bad in 'Server' 'desktop; touch pwned' '-Launch' ''; do
  run --bootstrap "$plain_dir/install-inwire.ps1" --product "$bad"
  if [ "$code" = 10 ] && ! called; then
    pass "product '$bad' is refused (10) before PowerShell runs"
  else
    fail "product '$bad': exit $code, PowerShell called: $(called && echo yes || echo no)"
  fi
done

for args in '--frobnicate' 'extra' '--launch --launch-now'; do
  # shellcheck disable=SC2086 # split on purpose: each case is several words
  run --bootstrap "$plain_dir/install-inwire.ps1" $args
  if [ "$code" = 64 ] && ! called; then
    pass "'$args' is a usage error (64)"
  else
    fail "'$args': exit $code"
  fi
done

run --help
if [ "$code" = 0 ] && ! called && printf '%s' "$out" | grep -q 'install-inwire.sh'; then
  pass '--help prints usage and runs nothing'
else
  fail "--help: exit $code"
fi

# --- exit codes --------------------------------------------------------------

for c in 0 2 10 11 12 13 14 20; do
  FAKE_EXIT=$c run --bootstrap "$plain_dir/install-inwire.ps1"
  if [ "$code" = "$c" ]; then pass "bootstrap exit $c comes back as $c"; else fail "bootstrap exit $c came back as $code"; fi
done

# 3010 does not fit in a POSIX status: Cygwin hands bash 3010 & 255 = 194.
FAKE_EXIT=194 run --bootstrap "$plain_dir/install-inwire.ps1"
if [ "$code" = 194 ] && printf '%s' "$out" | grep -qi 'restart'; then
  pass 'reboot-required arrives as 194 (3010 mod 256) and the bridge says to restart'
else
  fail "reboot-required: exit $code, output: $out"
fi

# --- platforms ---------------------------------------------------------------

for s in Linux Darwin FreeBSD; do
  FAKE_UNAME_S=$s run --bootstrap "$plain_dir/install-inwire.ps1"
  if [ "$code" = 10 ] && ! called; then pass "$s is refused (10) before anything runs"; else fail "$s: exit $code"; fi
done

FAKE_UNAME_S=Linux FAKE_UNAME_R=5.15.167.4-microsoft-standard-WSL2 run --bootstrap "$plain_dir/install-inwire.ps1"
if [ "$code" = 10 ] && ! called && printf '%s' "$out" | grep -q 'WSL'; then
  pass 'WSL is refused (10) and named, not treated as Windows'
else
  fail "WSL: exit $code, output: $out"
fi

for s in MSYS_NT-10.0-26300 CYGWIN_NT-10.0-26300; do
  FAKE_UNAME_S=$s run --bootstrap "$plain_dir/install-inwire.ps1"
  if [ "$code" = 0 ] && called; then pass "$s is accepted"; else fail "$s: exit $code"; fi
done

# --- missing pieces ----------------------------------------------------------

rm -f "$FAKE_LOG"
out=$(PATH="$work/fakebin:$PATH" SYSTEMROOT="$work/nowhere" bash "$bridge" --bootstrap "$plain_dir/install-inwire.ps1" 2>&1)
code=$?
if [ "$code" = 10 ] && printf '%s' "$out" | grep -q 'PowerShell'; then
  pass 'no Windows PowerShell under SYSTEMROOT is refused (10), not looked up on PATH'
else
  fail "missing PowerShell: exit $code"
fi

run --bootstrap "$work/absent/install-inwire.ps1"
if [ "$code" = 10 ] && ! called; then pass 'a missing bootstrap is refused (10)'; else fail "missing bootstrap: exit $code"; fi

# A powershell.exe in the current directory is never the one that runs.
mkdir -p "$work/cwd"
cat > "$work/cwd/powershell.exe" <<'EOF'
#!/usr/bin/env bash
touch "$(dirname "$0")/pwned"
EOF
chmod +x "$work/cwd/powershell.exe"
(cd "$work/cwd" && rm -f "$FAKE_LOG" && PATH=".:$work/fakebin:$PATH" SYSTEMROOT="$fakeroot" bash "$bridge" --bootstrap "$plain_dir/install-inwire.ps1" >/dev/null 2>&1)
if [ ! -e "$work/cwd/pwned" ] && called; then
  pass 'a powershell.exe in the current directory, even with . on PATH, is not run'
else
  fail 'the current directory chose the PowerShell that ran'
fi

# --- nothing was ever evaluated ----------------------------------------------

if [ -z "$(find "$work" -name pwned -print -quit)" ]; then
  pass 'no hostile value was evaluated'
else
  fail 'a hostile value was evaluated: pwned exists'
fi

if [ "$failures" -eq 0 ]; then
  echo 'All Bash bridge checks passed'
  exit 0
fi
echo "$failures Bash bridge check(s) failed"
exit 1
