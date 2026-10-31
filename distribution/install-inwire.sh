#!/usr/bin/env bash
# Installs Inwire for Windows from Git Bash, by running the PowerShell
# bootstrap you have already downloaded and verified. It is a front end and
# nothing more: the bootstrap does the download, the checks, the UAC prompt
# and the install, and its exit code is this script's exit code.
#
#   bash install-inwire.sh [--product Desktop|EndpointAgent] [--version X.Y.Z]
#                          [--launch] [--repair] [--bootstrap PATH]
#
# What installs is the Windows desktop app. This is not a Linux or macOS
# installer and refuses to act as one; WSL is refused too, until Windows
# interop, the UAC prompt and the install location are tested from it.
#
# ## Why every value is checked here and nothing is built as a string
#
# The values become arguments to `powershell.exe -File`, which binds anything
# starting with `-` as a parameter name. A version of `-Launch` would launch,
# so the product is one of two words and the version is digits and dots,
# checked before PowerShell runs. The command is an array; there is no eval
# and no string that is later split.
#
# ## Why PowerShell comes from SYSTEMROOT
#
# Not from PATH, which can hold `.` or a directory someone else writes, and
# not as `pwsh`, which may be absent. Windows PowerShell 5.1 ships with every
# supported Windows. The bootstrap is run with -File, under whatever execution
# policy the machine has: this script never passes -ExecutionPolicy, because
# a bypass here would be the one place Inwire overrode the owner's policy.
#
# Not -NonInteractive. A bootstrap downloaded in a browser carries the mark
# of the web, and RemoteSigned then asks once whether to run software from a
# publisher the person has not trusted ("Run once" is the answer the docs
# give). -NonInteractive turns that question into a refusal for every
# first-time user.
#
# ## Exit codes
#
# The bootstrap's own (docs/distribution.md), except that 3010, reboot
# required, does not fit in a POSIX status: Git Bash receives 3010 mod 256,
# which is 194. Usage errors are 64, and an unsupported platform or a value
# refused here is 10, the bootstrap's code for the same thing.

set -u

usage() {
  cat <<'EOF'
Usage: bash install-inwire.sh [--product Desktop|EndpointAgent] [--version X.Y.Z]
                              [--launch] [--repair] [--bootstrap PATH]

Runs the Inwire PowerShell bootstrap (install-inwire.ps1, next to this script
unless --bootstrap names it) from Git Bash on Windows. It installs the Windows
desktop app, asking for administrator rights through UAC.

  --product   Desktop (default). EndpointAgent is not available yet.
  --version   install exactly this published version.
  --launch    open Inwire once it is installed.
  --repair    reinstall over an installation in an unknown state.

Exit codes are the bootstrap's; reboot-required (3010) arrives as 194.
EOF
}

die() {
  printf 'install-inwire.sh: %s\n' "$2" >&2
  exit "$1"
}

product=Desktop
version=
launch=0
repair=0
bootstrap="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install-inwire.ps1"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --help) usage; exit 0 ;;
    --product)
      [ "$#" -ge 2 ] || die 64 '--product needs a value'
      product=$2; shift 2 ;;
    --version)
      [ "$#" -ge 2 ] || die 64 '--version needs a value'
      version=$2
      [ -n "$version" ] || die 10 'the version is empty'
      shift 2 ;;
    --bootstrap)
      [ "$#" -ge 2 ] || die 64 '--bootstrap needs a value'
      bootstrap=$2; shift 2 ;;
    --launch) launch=1; shift ;;
    --repair) repair=1; shift ;;
    *) usage >&2; die 64 "unknown argument: $1" ;;
  esac
done

case "$product" in
  Desktop|EndpointAgent) ;;
  *) die 10 "unknown product '$product' (Desktop or EndpointAgent)" ;;
esac

# The bootstrap's own rule, so a value it would refuse never becomes a
# parameter it might bind instead.
if [ -n "$version" ] && ! [[ "$version" =~ ^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$ ]]; then
  die 10 "'$version' is not a version (expected digits like 0.5.0)"
fi

system=$(uname -s)
case "$system" in
  MINGW*|MSYS*|CYGWIN*) ;;
  Linux)
    if uname -r | grep -qi microsoft; then
      die 10 'WSL is not supported yet. Run this from Git Bash, or run install-inwire.ps1 from PowerShell.'
    fi
    die 10 'Inwire is a Windows desktop app; there is no Linux installer.' ;;
  Darwin) die 10 'Inwire is a Windows desktop app; there is no macOS installer.' ;;
  *) die 10 "unsupported platform: $system" ;;
esac

[ -n "${SYSTEMROOT:-}" ] || die 10 'SYSTEMROOT is not set, so Windows PowerShell cannot be found'
powershell="$(cygpath -u "$SYSTEMROOT")/System32/WindowsPowerShell/v1.0/powershell.exe"
[ -f "$powershell" ] || die 10 "Windows PowerShell was not found at $powershell"

[ -f "$bootstrap" ] || die 10 "the bootstrap was not found at $bootstrap (download it, verify it, and pass --bootstrap)"
bootstrap_win=$(cygpath -w "$bootstrap")

args=(-NoProfile -File "$bootstrap_win" -Product "$product")
[ -n "$version" ] && args+=(-Version "$version")
[ "$launch" = 1 ] && args+=(-Launch)
[ "$repair" = 1 ] && args+=(-Repair)

# MSYS rewrites an argument that looks like a POSIX path when it calls a
# Windows program. The path above is already a Windows path, and nothing else
# here starts with a slash, but say so rather than rely on it.
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "$powershell" "${args[@]}"
code=$?

if [ "$code" = 194 ]; then
  printf 'install-inwire.sh: Inwire is installed; restart Windows to finish (the bootstrap reported 3010).\n' >&2
fi
exit "$code"
