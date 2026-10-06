/**
 * A new dissector against the reference, column for column and row for row.
 *
 * `synthetic.ts` compares the Protocol and Info columns, which is what a
 * packet list shows; a tree can be half missing behind a perfect Info line.
 * This compares both: each case's frames are written to one `.pcap`, read by
 * the real parser the way an import reads them, and every row of the protocol
 * under test - the abbrevs `rows` matches - is set against tshark's PDML for
 * the same file, in order, as `abbrev=value`.
 *
 * The value is what the reference shows after its row's first `: `, which is
 * the tree's own convention: a row's `name` is the label and its `value` the
 * rest. A row whose showname has no `: ` (a heading, a text line) compares on
 * its name. Rows the reference hides (`hide="yes"`) are not drawn by it, so
 * they are not asked for here.
 *
 * A helper, not a test: no `process.exit`, so `check.ts` does not run it.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { askTshark, pcapOf } from './synthetic';
import { findWiresharkTool } from '../export/realCaptures';
import { PcapService } from '../../src/services/pcapParser';
import type { Packet, ProtocolField } from '../../src/types/packet';

export interface OracleCase {
  label: string;
  frame: Uint8Array;
}

export interface OracleOptions {
  /** The abbrevs under test, e.g. `/^eapol\./`. */
  rows: RegExp;
  linktype?: number;
}

let failures = 0;
export function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}

/** Our rows under `rows`, in tree order, as `abbrev=value`. */
export function ourRows(packet: Packet, rows: RegExp): string[] {
  const out: string[] = [];
  const walk = (fields: readonly ProtocolField[]) => {
    for (const f of fields) {
      if (f.abbrev !== undefined && rows.test(f.abbrev)) {
        const value = typeof f.value === 'boolean' ? (f.value ? 'True' : 'False') : String(f.value);
        out.push(`${f.abbrev}=${value === '' ? f.name : value}`);
      }
      if (f.children) walk(f.children);
    }
  };
  for (const layer of packet.layers) walk(layer.fields);
  return out;
}

const unescape = (v: string) => v.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
  .replace(/&#x27;/g, "'").replace(/&#39;/g, "'").replace(/&amp;/g, '&');

/** The reference's rows under `rows` for each frame of a PDML document. */
export function referenceRows(pdml: string, rows: RegExp): string[][] {
  return pdml.split('<packet>').slice(1).map((packet) => {
    const out: string[] = [];
    for (const m of packet.matchAll(/<field ([^>]*?)\/?>/g)) {
      const attrs = Object.fromEntries([...m[1].matchAll(/([a-z_]+)="([^"]*)"/g)].map((a) => [a[1], unescape(a[2])]));
      if (!rows.test(attrs.name ?? '') || attrs.hide === 'yes') continue;
      const shown = attrs.showname ?? attrs.show ?? '';
      const at = shown.indexOf(': ');
      out.push(`${attrs.name}=${at >= 0 ? shown.slice(at + 2) : shown}`);
    }
    return out;
  });
}

/**
 * Two rows as the same row. Bytes are the one deliberate difference: this
 * tree writes them colon-separated (`hexColons`, which is the reference's
 * `show`), where its showname runs them together.
 */
function sameRow(mine: string, ref: string): boolean {
  if (mine === ref) return true;
  const [abbrev, ...rest] = mine.split('=');
  const value = rest.join('=');
  return /^[0-9a-f]{2}(:[0-9a-f]{2})+$/.test(value) && `${abbrev}=${value.replace(/:/g, '')}` === ref;
}

/**
 * Dissects `cases` as one capture and compares each frame's Protocol, Info and
 * rows with the reference's. Skips the comparison cleanly with no tshark.
 * Returns the packets, for a suite's own further assertions.
 */
export async function compareWithReference(cases: OracleCase[], options: OracleOptions): Promise<Packet[]> {
  const pcap = pcapOf(cases.map((c) => c.frame), options.linktype);
  const { packets } = await PcapService.parseCaptureFile(new File([pcap], 'oracle.pcap'), Number.POSITIVE_INFINITY, true);
  check(`every frame dissected (${cases.length})`, packets.length === cases.length);

  const tshark = findWiresharkTool('tshark');
  if (tshark === null) {
    console.log('SKIP  tshark not found - the frames were read; whether as the reference reads them was not checked');
    return packets;
  }
  const columns = askTshark(tshark, cases.map((c) => c.frame));
  const dir = mkdtempSync(join(tmpdir(), 'inwire-oracle-'));
  try {
    const file = join(dir, 'oracle.pcap');
    writeFileSync(file, pcap);
    const env = { ...process.env, WIRESHARK_CONFIG_DIR: join(process.cwd(), 'scripts', 'wireshark-profile') };
    const pdml = spawnSync(tshark, ['-n', '-r', file, '-T', 'pdml'], { encoding: 'utf8', env, maxBuffer: 1 << 28 }).stdout;
    const theirs = referenceRows(pdml, options.rows);
    check('the reference read every frame', theirs.length === cases.length && columns.length === cases.length);
    cases.forEach((c, i) => {
      const packet = packets[i];
      if (packet === undefined) return;
      const protocol = packet.protocolLabel ?? packet.protocol;
      check(`${c.label}: Protocol`, protocol === columns[i]?.protocol,
        `reference "${columns[i]?.protocol}", this build "${protocol}"`);
      check(`${c.label}: Info`, packet.info === columns[i]?.info,
        `reference "${columns[i]?.info}"\n        this build "${packet.info}"`);
      const mine = ourRows(packet, options.rows);
      const ref = theirs[i] ?? [];
      const differ = mine.length !== ref.length || mine.some((row, k) => !sameRow(row, ref[k]));
      check(`${c.label}: every row matches the reference (${ref.length})`, !differ,
        `reference:\n          ${ref.join('\n          ')}\n        this build:\n          ${mine.join('\n          ')}`);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return packets;
}

/** Ends a suite. */
export function finish(label: string): never {
  console.log();
  if (failures > 0) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log(`All ${label} checks passed.`);
  process.exit(0);
}
