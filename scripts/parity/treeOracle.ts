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
 * A helper, not a test: `check.ts` names it in NOT_TESTS, and runs every
 * script that imports it, since `finish()` is how those exit.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { pcapOf } from './synthetic';
import { findWiresharkTool } from '../export/realCaptures';
import { PcapService } from '../../src/services/pcapParser';
import { recordRefs } from '../../src/services/dissect/frameRecord';
import { arrive, firstDifference, render, revisit } from '../pipeline/arrival';
import type { Packet, ProtocolField } from '../../src/types/packet';

export interface OracleCase {
  label: string;
  frame: Uint8Array;
}

export interface OracleOptions {
  /** The abbrevs under test, e.g. `/^eapol\./`. */
  rows: RegExp;
  linktype?: number;
  /**
   * Ask the reference for its two-pass reading (`-2`), which is what the
   * fixture ground truth is and what this build's tree shows: a segment that
   * a later one completes says so (`[TCP PDU reassembled in N]`). Off for a
   * protocol whose single-pass reading is the one to match. `'columns'` takes
   * the two-pass columns and the single-pass tree: a protocol whose earlier
   * frames' Protocol column a later frame settles (TLS's and DTLS's version),
   * while each tree is what was known when its frame arrived.
   */
  twoPass?: boolean | 'columns';
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
        // An empty value is either a row that is only its name - a heading,
        // `Encrypted Static` - or a string that is empty. `\u0000` marks it,
        // and `sameRow` takes either reading.
        out.push(`${f.abbrev}=${value === '' ? `\u0000${f.name}` : value}`);
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
      // A long value is cut short in the label (`Client PQ KEM Public Key
      // [\u2026]: 0303...`); `show` holds all of it.
      const truncated = at >= 0 && shown.slice(0, at).endsWith('[\u2026]') && attrs.show !== undefined;
      // A label cut at the reference's 240 characters keeps both what it showed
      // and the field's own value (`show`); `sameRow` accepts either.
      out.push(`${attrs.name}=${truncated ? `\u0001${shown.slice(at + 2)}\u0002${attrs.show.replace(/:/g, '')}` : at >= 0 ? shown.slice(at + 2) : shown}`);
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
  if (value.startsWith('\u0000')) return ref === `${abbrev}=` || ref === `${abbrev}=${value.slice(1)}`;
  const refValue = ref.slice(abbrev.length + 1);
  // A truncated label: this build's value begins with what the reference
  // showed of it, or is the field's whole value.
  if (refValue.startsWith('\u0001')) {
    const [shown, show] = refValue.slice(1).split('\u0002');
    return value.startsWith(shown) || value.replace(/:/g, '') === show;
  }
  // A long label the reference stopped adding to before the limit - a flag
  // summary that lists the first few of the set flags.
  if (refValue.length >= 200 && value.startsWith(refValue)) return true;
  return /^[0-9a-f]{2}(:[0-9a-f]{2})+$/.test(value) && `${abbrev}=${value.replace(/:/g, '')}` === ref;
}

/**
 * Dissects `cases` as one capture and compares each frame's Protocol, Info and
 * rows with the reference's. Skips the comparison cleanly with no tshark.
 * Returns the packets, for a suite's own further assertions.
 */
export async function compareWithReference(cases: OracleCase[], options: OracleOptions): Promise<Packet[]> {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-oracle-'));
  try {
    const file = join(dir, 'oracle.pcap');
    writeFileSync(file, pcapOf(cases.map((c) => c.frame), options.linktype));
    return await compareCaptureFile(file, cases.map((c) => c.label), options);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * The same comparison over a capture file as it is - a real one, of any link
 * type - with one label per frame.
 */
export async function compareCaptureFile(file: string, labels: string[], options: OracleOptions): Promise<Packet[]> {
  const { packets } = await PcapService.parseCaptureFile(new File([readFileSync(file)], basename(file)), Number.POSITIVE_INFINITY, true);
  check(`every frame dissected (${labels.length})`, packets.length === labels.length);
  const tshark = findWiresharkTool('tshark');
  if (tshark === null) {
    console.log('SKIP  tshark not found - the frames were read; whether as the reference reads them was not checked');
    return packets;
  }
  const env = { ...process.env, WIRESHARK_CONFIG_DIR: join(process.cwd(), 'scripts', 'wireshark-profile') };
  const pass = (two: boolean) => (two ? ['-2'] : []);
  const pdml = spawnSync(tshark, [...pass(options.twoPass === true), '-n', '-r', file, '-T', 'pdml'], { encoding: 'utf8', env, maxBuffer: 1 << 28 }).stdout;
  const theirs = referenceRows(pdml, options.rows);
  const cols = spawnSync(tshark, [...pass(options.twoPass !== undefined && options.twoPass !== false), '-n', '-r', file, '-T', 'fields',
    '-e', '_ws.col.Protocol', '-e', '_ws.col.Info'], { encoding: 'utf8', env, maxBuffer: 1 << 28 }).stdout
    .split(/\r?\n/).slice(0, labels.length).map((line) => { const [protocol, info = ''] = line.split('\t'); return { protocol, info }; });
  check('the reference read every frame', theirs.length === labels.length && cols.length === labels.length);
  labels.forEach((label, i) => {
    const packet = packets[i];
    if (packet === undefined) return;
    const protocol = packet.protocolLabel ?? packet.protocol;
    check(`${label}: Protocol`, protocol === cols[i]?.protocol,
      `reference "${cols[i]?.protocol}", this build "${protocol}"`);
    check(`${label}: Info`, packet.info === cols[i]?.info,
      `reference "${cols[i]?.info}"\n        this build "${packet.info}"`);
    const mine = ourRows(packet, options.rows);
    const ref = theirs[i] ?? [];
    const differ = mine.length !== ref.length || mine.some((row, k) => !sameRow(row, ref[k]));
    // From the first row that differs, a few either side: a whole tree of a
    // hundred rows hides the one that moved.
    let at = mine.findIndex((row, k) => k >= ref.length || !sameRow(row, ref[k]));
    if (at < 0) at = Math.min(mine.length, ref.length);
    const around = (rows: string[]) => rows.slice(Math.max(0, at - 2), at + 6).map((r) => r.replace('\u0000', '')).join('\n          ');
    check(`${label}: every row matches the reference (${ref.length})`, !differ,
      `first difference at row ${at + 1} (this build has ${mine.length})\n        reference:\n          ${around(ref)}\n        this build:\n          ${around(mine)}`);
  });
  return packets;
}

/**
 * Every frame rebuilt from its bytes and its record alone, as the app rebuilds
 * a frame it opens later (ADR 0049), must draw the tree arrival drew. A
 * dissector with cross-frame state - a session number, a response link - is
 * exactly what this catches when a tracker question is not recorded.
 */
export async function checkRevisit(cases: OracleCase[], linktype?: number): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-oracle-revisit-'));
  try {
    const file = join(dir, 'revisit.pcap');
    writeFileSync(file, pcapOf(cases.map((c) => c.frame), linktype));
    await checkRevisitFile(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The same, over a capture file as it is. */
export async function checkRevisitFile(file: string): Promise<void> {
  const { arrived, patchesFor, host } = await arrive(file);
  const wrong: string[] = [];
  for (const { packet, record, input } of arrived) {
    const named = new Set(recordRefs(record));
    try {
      const layers = revisit(input, packet.id, record, host, patchesFor.get(packet.id) ?? [],
        (frame) => (named.has(frame) ? arrived[frame - 1]?.input.bytes : undefined));
      const want = render(packet.layers);
      const got = render(layers);
      if (want !== got) wrong.push(`frame ${packet.id}: ${firstDifference(want, got)}`);
    } catch (error) {
      wrong.push(`frame ${packet.id}: ${(error as Error).message}`);
    }
  }
  check(`every frame rebuilds from its record alone (${arrived.length})`, wrong.length === 0,
    wrong.slice(0, 4).join('\n        '));
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
