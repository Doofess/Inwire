/**
 * Diffs NetView's own dissection of a capture file against Wireshark's, column
 * by column, so packet-list parity work has a hard pass/fail signal instead of
 * a side-by-side screenshot.
 *
 * Ground truth is produced by tshark and committed as a .psv next to this
 * script (see regenerate() below for the exact invocation). Running the real
 * `PcapService.parsePcapFile` here - rather than a reimplementation - means
 * this harness exercises the same code path the browser does.
 *
 *   npx tsx scripts/parity/parity-check.ts [path-to-capture]
 *
 * Exit code is non-zero when any compared column disagrees, so it can gate CI.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { PcapService } from '../../src/services/pcapParser';
import type { Packet } from '../../src/types/packet';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_CAPTURE = 'C:/Users/Rotem/Downloads/tmp.pcapng';

interface WiresharkRow {
  number: number;
  timeRelative: string;
  source: string;
  destination: string;
  protocol: string;
  frameLen: string;
  info: string;
}

function loadGroundTruth(): { rows: WiresharkRow[]; colors: Map<number, string> } {
  const rows = readFileSync(join(HERE, 'wireshark.psv'), 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map(line => {
      const [number, timeRelative, source, destination, protocol, frameLen, ...rest] = line.split('|');
      // Info legitimately contains '|' (QUIC frame lists do not, but display
      // filters and some dissectors can), so everything after the 6th field is
      // rejoined rather than treated as extra columns.
      return {
        number: Number(number),
        timeRelative,
        source,
        destination,
        protocol,
        frameLen,
        info: rest.join('|'),
      };
    });

  const colors = new Map<number, string>();
  for (const line of readFileSync(join(HERE, 'wireshark_colors.psv'), 'utf8').split(/\r?\n/)) {
    if (!line) continue;
    const [number, rule] = line.split('|');
    colors.set(Number(number), rule ?? '');
  }

  return { rows, colors };
}

/** The Protocol column NetView renders: the free-form label when a dissector
 *  set one, else the coarse ProtocolType. Mirrors what PacketList displays. */
function netviewProtocol(p: Packet): string {
  return (p as Packet & { protocolLabel?: string }).protocolLabel ?? p.protocol;
}

interface ColumnSpec {
  name: string;
  ours: (p: Packet) => string;
  theirs: (r: WiresharkRow) => string;
  /** Frames this column is knowingly not expected to match yet. */
  knownGap?: (r: WiresharkRow) => boolean;
}

const COLUMNS: ColumnSpec[] = [
  { name: 'Protocol', ours: netviewProtocol, theirs: r => r.protocol },
  { name: 'Source', ours: p => p.source, theirs: r => r.source },
  { name: 'Destination', ours: p => p.destination, theirs: r => r.destination },
  {
    name: 'Time',
    // tshark always prints 9 decimals; compare numerically so a capture stored
    // at microsecond resolution isn't failed for printing 6.
    ours: p => Number(p.relativeTime).toFixed(9),
    theirs: r => Number(r.timeRelative).toFixed(9),
  },
  { name: 'Length', ours: p => String(p.length), theirs: r => r.frameLen },
  { name: 'Info', ours: p => p.info, theirs: r => r.info },
];

async function main() {
  const capturePath = process.argv[2] ?? DEFAULT_CAPTURE;
  const { rows, colors } = loadGroundTruth();

  const bytes = readFileSync(capturePath);
  const file = new File([bytes], capturePath.split(/[\\/]/).pop() ?? 'capture.pcapng');
  const packets = await PcapService.parsePcapFile(file);

  console.log(`capture:   ${capturePath}`);
  console.log(`wireshark: ${rows.length} frames`);
  console.log(`netview:   ${packets.length} frames`);

  if (packets.length !== rows.length) {
    console.error(`\nFRAME COUNT MISMATCH - every other column is meaningless until this is fixed.`);
    process.exit(1);
  }

  let totalMismatches = 0;
  const summary: string[] = [];

  for (const column of COLUMNS) {
    const diffs: string[] = [];
    for (let i = 0; i < rows.length; i++) {
      const ours = column.ours(packets[i]);
      const theirs = column.theirs(rows[i]);
      if (ours !== theirs) {
        diffs.push(`  #${rows[i].number}\n    wireshark: ${theirs}\n    netview:   ${ours}`);
      }
    }

    const pass = rows.length - diffs.length;
    const mark = diffs.length === 0 ? 'PASS' : 'FAIL';
    summary.push(`${mark}  ${column.name.padEnd(12)} ${pass}/${rows.length}`);
    totalMismatches += diffs.length;

    if (diffs.length > 0) {
      console.log(`\n--- ${column.name}: ${diffs.length} mismatch(es) ---`);
      // Cap the dump so one badly-broken column doesn't bury the others;
      // PARITY_MAX_DIFFS=0 shows everything when working a specific column.
      const cap = process.env.PARITY_MAX_DIFFS === undefined ? 12 : Number(process.env.PARITY_MAX_DIFFS);
      const shown = cap === 0 ? diffs : diffs.slice(0, cap);
      console.log(shown.join('\n'));
      if (shown.length < diffs.length) console.log(`  ... and ${diffs.length - shown.length} more`);
    }
  }

  console.log('\n=== SUMMARY ===');
  summary.forEach(line => console.log(line));
  console.log(`\ncoloring-rule ground truth loaded for ${colors.size} frames (compared once colorRules matches Wireshark's ruleset)`);

  process.exit(totalMismatches === 0 ? 0 : 1);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
