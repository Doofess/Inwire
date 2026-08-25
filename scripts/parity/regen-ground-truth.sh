#!/usr/bin/env bash
# Regenerates the Wireshark ground truth the parity harness diffs against.
#
#   ./scripts/parity/regen-ground-truth.sh [capture]
#
# Two passes, because tshark's Protocol/Info columns disagree with the
# Wireshark GUI on one specific case: when a port-443 conversation carries a
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

TSHARK="${TSHARK:-/c/Program Files/Wireshark/tshark.exe}"
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
' "$HERE/.pass2.psv" "$HERE/.pass1.psv" > "$HERE/wireshark.psv"

"$TSHARK" -r "$CAPTURE" --color -T fields -e frame.number -e frame.coloring_rule.name \
  -E separator='|' > "$HERE/wireshark_colors.psv"

rm -f "$HERE/.pass1.psv" "$HERE/.pass2.psv"
echo "wrote $(wc -l < "$HERE/wireshark.psv") frames to $HERE/wireshark.psv"
