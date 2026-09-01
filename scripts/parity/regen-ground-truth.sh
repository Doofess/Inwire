#!/usr/bin/env bash
# Regenerates the tshark ground truth the parity harness diffs against.
#
#   ./scripts/parity/regen-ground-truth.sh [capture]
#
# Two passes, because tshark's Protocol/Info columns disagree with the
# reference analyzer's own GUI on one specific case: when a port-443 conversation carries a
# segment that is *not* a valid TLS record (a keep-alive's single byte, say),
# tshark labels the row with the stale conversation name "SSL" and emits an
# empty Info, even though `frame.protocols` proves TLS never dissected it. The
# GUI shows the underlying TCP line instead. Since the GUI is what NetView is
# being matched against, rows with an empty Info are taken from a second pass
# with the TLS dissector disabled, which yields exactly what the GUI displays.
#
# Frames TLS genuinely did dissect ("TLSv1.2 / Application Data") have a
# non-empty Info in the first pass and are left untouched.
set -euo pipefail

# Resolved from PATH by default. On Windows the installer does not add it, so
# point TSHARK at the binary yourself:
#   TSHARK="/c/Program Files/.../tshark.exe" ./scripts/parity/regen-ground-truth.sh
TSHARK="${TSHARK:-tshark}"
if ! command -v "$TSHARK" >/dev/null 2>&1 && [ ! -x "$TSHARK" ]; then
  echo "tshark not found. Set TSHARK to its full path." >&2
  exit 1
fi
CAPTURE="${1:-C:/Users/Rotem/Downloads/tmp.pcapng}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FIELDS=(-e frame.number -e frame.time_relative -e _ws.col.Source
        -e _ws.col.Destination -e _ws.col.Protocol -e frame.len -e _ws.col.Info)

"$TSHARK" -r "$CAPTURE" -T fields "${FIELDS[@]}" -E separator='|' > "$HERE/.pass1.psv"
"$TSHARK" -r "$CAPTURE" --disable-protocol tls -T fields "${FIELDS[@]}" -E separator='|' > "$HERE/.pass2.psv"

# Field 7 (Info) empty in pass 1 -> take that row's Protocol and Info from pass 2.
awk -F'|' -v OFS='|' '
  NR==FNR { proto[$1]=$5; info[$1]=$7; next }
  { if ($7 == "") { $5 = proto[$1]; $7 = info[$1] } ; print }
' "$HERE/.pass2.psv" "$HERE/.pass1.psv" > "$HERE/ground-truth.psv"

"$TSHARK" -r "$CAPTURE" --color -T fields -e frame.number -e frame.coloring_rule.name \
  -E separator='|' > "$HERE/ground-truth-colors.psv"

rm -f "$HERE/.pass1.psv" "$HERE/.pass2.psv"
echo "wrote $(wc -l < "$HERE/ground-truth.psv") frames to $HERE/ground-truth.psv"
