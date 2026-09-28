#!/usr/bin/env bash
# Regenerates the tshark ground truth the parity harness diffs against, for
# every fixture listed in test/fixtures/acceptance.json.
#
#   ./scripts/parity/regen-ground-truth.sh            # all fixtures
#   ./scripts/parity/regen-ground-truth.sh inwire     # one, by name
#
# Output: test/fixtures/<name>.psv and <name>-colors.psv - untracked, like the
# captures themselves (docs/decisions/0004-fixtures-and-privacy.md).
#
# Two things about the tshark invocation matter:
#
# 1. `-2` (two-pass). Single-pass tshark cannot know the future, so a ping
#    request never gets its "(reply in N)", a DNS query never gets its
#    "[Response In]", and the segments of a TLS record that completes later
#    show an EMPTY Info. The Wireshark GUI is two-pass, and it is the GUI
#    Inwire is matched against. On the inwire fixture 477 rows differ between
#    the two modes, all in the GUI's favour.
#
# 2. `tcp.reassembled_in` is exported as its own column, before Info. It is set
#    on every segment that is part of a PDU reassembled in a later frame -
#    exactly the rows whose Protocol/Info the GUI renders as plain TCP with a
#    "[TCP PDU reassembled in N]" suffix. Having the field separately lets the
#    harness bucket those rows on their own, because the fix for them (a
#    record cursor across segments, spec Phase 4) is unrelated to every other
#    TCP mismatch.
#
# The second pass with TLS disabled is kept for any row whose Info is still
# empty under -2: tshark labels a port-443 segment that is not a valid record
# with the stale conversation name "SSL" and no Info, while the GUI shows the
# TCP line underneath.
set -euo pipefail

TSHARK="${TSHARK:-tshark}"
if ! command -v "$TSHARK" >/dev/null 2>&1 && [ ! -x "$TSHARK" ]; then
  # The Windows installer does not add it to PATH; try the default location
  # before giving up, so the common case needs no environment variable.
  if [ -x "/c/Program Files/Wireshark/tshark.exe" ]; then
    TSHARK="/c/Program Files/Wireshark/tshark.exe"
  else
    echo "tshark not found. Set TSHARK to its full path." >&2
    exit 1
  fi
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The repository's Wireshark profile, not the personal one - see
# scripts/wiresharkProfile.ts. The ground truth is Wireshark's defaults, and a
# GUI left resolving IP addresses would otherwise write hostnames into the
# Source and Destination columns, one PTR query per address.
export WIRESHARK_CONFIG_DIR="$HERE/../wireshark-profile"
FIXTURES="$HERE/../../test/fixtures"
ACCEPT="$FIXTURES/acceptance.json"

# name<TAB>file for every fixture, or just the ones asked for.
list_fixtures() {
  node -e '
    const a = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    const want = process.argv.slice(2);
    for (const [name, f] of Object.entries(a.fixtures)) {
      if (want.length === 0 || want.includes(name)) console.log(name + "\t" + f.file);
    }' "$ACCEPT" "$@"
}

# JA3/JA3S/JA4 ride along as their own columns: tshark computes them from
# the same hello bytes the app parses, so a fingerprint mismatch pins down a
# parsing error in one extension or one GREASE rule without any guesswork.
FIELDS=(-e frame.number -e frame.time_relative -e _ws.col.Source -e _ws.col.Destination
        -e _ws.col.Protocol -e frame.len -e tcp.reassembled_in
        -e tls.handshake.ja3 -e tls.handshake.ja3s -e tls.handshake.ja4 -e _ws.col.Info)

list_fixtures "$@" | while IFS=$'\t' read -r name file; do
  capture="$FIXTURES/$file"
  if [ ! -f "$capture" ]; then
    echo "missing fixture $capture - see test/fixtures/README.md" >&2
    exit 1
  fi
  echo "$name: $file"

  "$TSHARK" -2 -r "$capture" -T fields "${FIELDS[@]}" -E separator='|' > "$FIXTURES/.pass1.psv"
  "$TSHARK" -2 -r "$capture" --disable-protocol tls -T fields "${FIELDS[@]}" -E separator='|' > "$FIXTURES/.pass2.psv"

  # Field 11 (Info) empty in pass 1 -> take that row's Protocol and Info from pass 2.
  awk -F'|' -v OFS='|' '
    NR==FNR { proto[$1]=$5; info[$1]=$11; next }
    { if ($11 == "") { $5 = proto[$1]; $11 = info[$1] } ; print }
  ' "$FIXTURES/.pass2.psv" "$FIXTURES/.pass1.psv" > "$FIXTURES/$name.psv"

  "$TSHARK" -2 -r "$capture" --color -T fields -e frame.number -e frame.coloring_rule.name \
    -E separator='|' > "$FIXTURES/$name-colors.psv"

  rm -f "$FIXTURES/.pass1.psv" "$FIXTURES/.pass2.psv"
  echo "  wrote $(wc -l < "$FIXTURES/$name.psv") frames"
done
