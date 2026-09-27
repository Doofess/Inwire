/**
 * What a snaplen does to the dissection, against the reference on the same
 * cut capture.
 *
 *   npx tsx scripts/parity/snaplen.ts [--fixture inwire|bulk] [--write-floors]
 *
 * A capture started with a snaplen keeps the first N bytes of every frame
 * (ADR 0050), so every dissector meets frames that stop early. This cuts each
 * real fixture with `editcap -s N` - exactly what the driver would have kept -
 * and asks two questions of the result.
 *
 * **Is anything wrong that was right?** Truncation must not change what the
 * headers say. TCP's length and its analysis come from the headers alone, so
 * a frame's `tcp.len` and its analysis flags must be the same cut as whole;
 * before this existed, a cut segment read as a short one, the next as a hole
 * behind it, and a capture with no loss reported "previous segment not
 * captured" on most of its frames. And of the frames whose Protocol and Info
 * agree with tshark when whole, how many still agree when cut.
 *
 * **Does it say so?** `[Packet size limited during capture]` on the frames
 * the capture cut into, counted both ways: the frames tshark marks that this
 * build also marks is a floor, the ones it misses a ceiling. The frames only
 * this build marks are recorded and not enforced - the marker is a superset
 * on purpose (`dissect/captureShort.ts`).
 *
 * Counts, not ratios, for ADR 0039's reason: floors that only rise and
 * ceilings that only fall, in `test/fixtures/acceptance.json` beside the
 * column and tree floors, held there by `acceptance.ts`.
 *
 * Needs tshark, editcap and the untracked fixtures; skips cleanly without
 * them, so it runs under `npm run check`.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { PcapService } from '../../src/services/pcapParser';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import { SIZE_LIMITED } from '../../src/services/dissect/captureShort';
import type { Packet } from '../../src/types/packet';
import type { Acceptance, SnaplenAcceptance } from './acceptance-schema';
import { SNAPLENS } from './snaplens';
import { findWiresharkTool } from '../export/realCaptures';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURES = join(ROOT, 'test', 'fixtures');
const ACCEPTANCE = join(FIXTURES, 'acceptance.json');


let failures = 0;
function check(name: string, pass: boolean, detail = '') {
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? `  ${detail}` : ''}`);
}

const protocolOf = (p: Packet): string => p.protocolLabel ?? p.protocol;

async function dissect(path: string): Promise<Packet[]> {
  return (await PcapService.parseCaptureFile(new File([readFileSync(path)], 'capture.pcap'))).packets;
}

function reference(tshark: string, path: string): { protocol: string; info: string }[] {
  const text = execFileSync(tshark, ['-r', path, '-T', 'fields', '-E', 'separator=\t',
    '-e', '_ws.col.Protocol', '-e', '_ws.col.Info'], { maxBuffer: 1 << 29, encoding: 'utf8' });
  return text.replace(/\r/g, '').replace(/\n$/, '').split('\n').map((line) => {
    const [protocol, ...info] = line.split('\t');
    return { protocol, info: info.join('\t') };
  });
}

const flagsOf = (p: Packet): string => [...(p.analysisFlags ?? [])].sort().join(',');

/** One fixture at one snaplen, as the counts `acceptance.json` holds. */
function measure(
  whole: Packet[], wholeRef: { protocol: string; info: string }[],
  cut: Packet[], cutRef: { protocol: string; info: string }[],
): Record<string, number> {
  let tcpFrames = 0, tcpLenKept = 0, analysisKept = 0;
  let protocolEligible = 0, protocolKept = 0, infoEligible = 0, infoKept = 0;
  let limitedBoth = 0, limitedMissed = 0, limitedOnlyOurs = 0;
  for (let i = 0; i < cut.length; i++) {
    const w = whole[i], c = cut[i];
    const wLen = fieldValue(w, 'tcp.len');
    const cLen = fieldValue(c, 'tcp.len');
    // Only where the cut frame still has a whole TCP header: a sequence number
    // the capture did not keep cannot be analysed, whole or not.
    if (wLen !== undefined && cLen !== undefined) {
      tcpFrames++;
      if (wLen === cLen) tcpLenKept++;
      if (flagsOf(w) === flagsOf(c)) analysisKept++;
    }
    if (protocolOf(w) === wholeRef[i].protocol) {
      protocolEligible++;
      if (protocolOf(c) === cutRef[i].protocol) protocolKept++;
    }
    if (w.info === wholeRef[i].info) {
      infoEligible++;
      if (c.info === cutRef[i].info) infoKept++;
    }
    const theirs = cutRef[i].info.includes(SIZE_LIMITED);
    const ours = c.info.includes(SIZE_LIMITED);
    if (theirs && ours) limitedBoth++;
    else if (theirs) limitedMissed++;
    else if (ours) limitedOnlyOurs++;
  }
  return {
    tcpFrames, tcpLenKept, analysisKept, protocolEligible, protocolKept,
    infoEligible, infoKept, limitedBoth, limitedMissed, limitedOnlyOurs,
  };
}

/** What is enforced, and which way. The rest is recorded. */
const FLOORS = ['tcpLenKept', 'analysisKept', 'protocolKept', 'infoKept', 'limitedBoth'] as const;
const CEILINGS = ['limitedMissed'] as const;

async function main() {
  const argv = process.argv.slice(2);
  const only = argv.includes('--fixture') ? argv[argv.indexOf('--fixture') + 1] : undefined;
  const writeFloors = argv.includes('--write-floors');

  const tshark = findWiresharkTool('tshark');
  const editcap = findWiresharkTool('editcap');
  const tools = tshark !== null && editcap !== null ? { tshark, editcap } : null;
  if (tools === null) {
    console.log('SKIP  tshark or editcap not found - set TSHARK to its path to run this measurement.');
    return;
  }
  if (!existsSync(ACCEPTANCE)) {
    console.log('SKIP  test/fixtures/acceptance.json missing.');
    return;
  }
  const acceptance = JSON.parse(readFileSync(ACCEPTANCE, 'utf8')) as Acceptance;
  const scratch = mkdtempSync(join(tmpdir(), 'inwire-snaplen-'));
  try {
    for (const [name, spec] of Object.entries(acceptance.fixtures)) {
      if (only !== undefined && only !== name) continue;
      const capturePath = join(FIXTURES, spec.file);
      if (!existsSync(capturePath)) {
        console.log(`SKIP  ${name}: ${spec.file} not present (see test/fixtures/README.md)`);
        continue;
      }
      console.log(`\n=== ${name}: ${spec.file}`);
      const whole = await dissect(capturePath);
      const wholeRef = reference(tools.tshark, capturePath);
      const measured: SnaplenAcceptance = {};
      for (const snaplen of SNAPLENS) {
        const cutPath = join(scratch, `${name}_s${snaplen}.pcap`);
        // Classic pcap, as the fixtures are, so nothing but the cut differs.
        execFileSync(tools.editcap, ['-F', 'pcap', '-s', String(snaplen), capturePath, cutPath]);
        const counts = measure(whole, wholeRef, await dissect(cutPath), reference(tools.tshark, cutPath));
        measured[String(snaplen)] = counts;
        console.log(`--- snaplen ${snaplen}`);
        console.log(`      TCP with a whole header ${counts.tcpFrames}: tcp.len kept ${counts.tcpLenKept}, analysis kept ${counts.analysisKept}`);
        console.log(`      Protocol kept ${counts.protocolKept}/${counts.protocolEligible}, Info kept ${counts.infoKept}/${counts.infoEligible}`);
        console.log(`      marked by both ${counts.limitedBoth}, by tshark only ${counts.limitedMissed}, by this build only ${counts.limitedOnlyOurs}`);

        // Truncation changes nothing the headers say. Exact, not floored.
        check(`${name} @${snaplen}: every whole TCP header keeps its tcp.len`, counts.tcpLenKept === counts.tcpFrames,
          `${counts.tcpLenKept}/${counts.tcpFrames}`);
        const floors = spec.snaplen?.[String(snaplen)];
        if (floors === undefined) {
          console.log(`      (no floors recorded for ${name} @${snaplen} - run --write-floors)`);
          continue;
        }
        for (const key of FLOORS) {
          check(`${name} @${snaplen}: ${key} at or above its floor`, counts[key] >= floors[key],
            `${counts[key]} (floor ${floors[key]})`);
        }
        for (const key of CEILINGS) {
          check(`${name} @${snaplen}: ${key} at or below its ceiling`, counts[key] <= floors[key],
            `${counts[key]} (ceiling ${floors[key]})`);
        }
      }
      if (writeFloors) acceptance.fixtures[name].snaplen = measured;
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  if (writeFloors) {
    writeFileSync(ACCEPTANCE, `${JSON.stringify(acceptance, null, 2)}\n`);
    console.log('\nwrote the measured counts to test/fixtures/acceptance.json');
  }
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All snaplen checks passed.');
  process.exit(0);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
