/**
 * Assertion tests for the pcapng writer, on the two real captures.
 *
 *   npx tsx scripts/export/pcapng.ts
 *
 * A writer is easy to test badly: feed its output to your own reader and
 * declare victory. That proves the two agree, which is exactly what a matched
 * pair of bugs also looks like. So this checks the file three ways:
 *
 *   * **the bytes**, against the format rather than this repo's reader -
 *     block types, the trailing length that lets a reader walk the file
 *     backwards, the option codes and the padding;
 *   * **Wireshark's own tools** - `tshark` must read every frame with the
 *     same length and timestamp it reads from the original capture, and
 *     `capinfos` must show the section's comment, application and OS;
 *   * **this repo's reader**, as a weaker check on top.
 *
 * Then the streaming property: the same frames written in pages of any size
 * are byte-identical to the one-shot file, because the IDBs are emitted by
 * first appearance and nothing depends on where a page ends.
 *
 * Driven by real traffic only. What no capture file can express is supplied
 * on a real frame and said so: a process attribution (the agent's socket
 * table, which no pcap carries), and a key log for the secrets block.
 * SKIPs cleanly without the fixtures (ADR 0004), and the tool checks without
 * Wireshark.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generatePcapNg } from '../../src/services/pcapngWriter';
import { PcapngWriter, sectionComment, type PcapngOptions } from '../../src/services/export/writers/pcapng';
import { concatChunks } from '../../src/services/export/writers/writer';
import { PcapService } from '../../src/services/pcapParser';
import { buildNameMap } from '../../src/services/nameResolution';
import { metaEntries, type CaptureMeta } from '../../src/services/export/captureMeta';
import { Direction, directionOf } from '../../src/services/direction';
import { findWiresharkTool, loadRealCaptures, runTool, type RealCapture } from './realCaptures';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  // BigInt is unavoidable here - a nanosecond tick count is past the exact
  // range of a double - and JSON.stringify refuses to serialise one.
  const show = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? `${x}n` : x));
  const pass = show(actual) === show(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${show(expected)?.slice(0, 400)}`);
    console.log(`        actual   ${show(actual)?.slice(0, 400)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

const SHB = 0x0a0d0d0a;
const IDB = 0x00000001;
const NRB = 0x00000004;
const ISB = 0x00000005;
const EPB = 0x00000006;
const DSB = 0x0000000a;

interface Block { type: number; length: number; body: Uint8Array }

/** Walks the file the way a reader does, and fails loudly if it cannot. */
function walk(bytes: Uint8Array): Block[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out: Block[] = [];
  let at = 0;
  while (at + 12 <= bytes.length) {
    const type = view.getUint32(at, true);
    const length = view.getUint32(at + 4, true);
    if (length < 12 || at + length > bytes.length) throw new Error(`block at ${at} claims ${length} bytes`);
    const trailing = view.getUint32(at + length - 4, true);
    if (trailing !== length) throw new Error(`block at ${at}: trailing length ${trailing} != ${length}`);
    if (length % 4 !== 0) throw new Error(`block at ${at} is not padded to four bytes`);
    out.push({ type, length, body: bytes.subarray(at + 8, at + length - 4) });
    at += length;
  }
  if (at !== bytes.length) throw new Error(`${bytes.length - at} bytes after the last block`);
  return out;
}

/** The options at the end of a block body, as code -> raw values. */
function options(body: Uint8Array, from: number): Map<number, Uint8Array[]> {
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const out = new Map<number, Uint8Array[]>();
  let at = from;
  while (at + 4 <= body.length) {
    const code = view.getUint16(at, true);
    const length = view.getUint16(at + 2, true);
    if (code === 0) break;
    if (at + 4 + length > body.length) throw new Error('option runs past the block');
    out.set(code, [...(out.get(code) ?? []), body.subarray(at + 4, at + 4 + length)]);
    at += 4 + length + ((4 - (length % 4)) % 4);
  }
  return out;
}

const text = (b: Uint8Array) => new TextDecoder().decode(b);
const u64 = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(0, true);
const u32 = (b: Uint8Array, at = 0) => new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(at, true);

/** An EPB's options start after its fixed header and its padded packet data. */
function epbOptions(b: Block): Map<number, Uint8Array[]> {
  return options(b.body, 20 + Math.ceil(u32(b.body, 12) / 4) * 4);
}

function metaFor(capture: RealCapture, drops: CaptureMeta['drops']): CaptureMeta {
  const p = capture.packets;
  return {
    app: 'Inwire', version: 'dev', os: 'Windows 11 Pro 10.0.26200', generatedAt: Date.UTC(2026, 8, 25, 12),
    source: { kind: 'import', fileName: capture.path.split(/[\\/]/).pop()! },
    firstUs: Math.min(...p.map((x) => x.tsUs)), lastUs: Math.max(...p.map((x) => x.tsUs)),
    frames: { exported: p.length, inCapture: p.length, unreadable: 0 },
    drops, scope: 'capture', filter: '',
    flags: { anonymised: false, rawBytes: true, fields: false, secrets: false },
  };
}

function writePaged(packets: readonly Packet[], options: PcapngOptions, page: number): Uint8Array {
  const writer = new PcapngWriter(options);
  const chunks: Uint8Array[] = [];
  for (let at = 0; at < packets.length; at += page) chunks.push(...writer.write(packets.slice(at, at + page)));
  chunks.push(...writer.finish());
  return concatChunks(chunks);
}

/** tshark's frame lengths and times for a file, one line per frame. */
function tsharkFrames(tshark: string, path: string): string[] {
  return runTool(tshark, ['-r', path, '-T', 'fields', '-e', 'frame.len', '-e', 'frame.cap_len', '-e', 'frame.time_epoch'])
    .split(/\r?\n/).filter((l) => l.length > 0);
}

async function captureChecks(capture: RealCapture, tools: Tools, dir: string): Promise<void> {
  const name = capture.name;
  const ordered = [...capture.packets].sort((a, b) => a.tsUs - b.tsUs);
  const meta = metaFor(capture, { kernel: 17, agent: 3, pipe: null });
  const names = buildNameMap(ordered).entries()
    .filter((e) => e.address.includes('.') || e.address.includes(':'))
    .map((e) => ({ address: e.address, names: [e.name] }));
  const writeOptions: PcapngOptions = {
    meta, os: 'Windows 11 Pro 10.0.26200', names,
    statistics: { received: null, drops: meta.drops },
    // A key log is not traffic; it is what the DSB carries, and a one-line log
    // is enough to find it in the file.
    secrets: 'CLIENT_RANDOM 001122 aabbccdd\n',
  };
  const bytes = new Uint8Array(await generatePcapNg(capture.packets, writeOptions).arrayBuffer());

  let blocks: Block[] = [];
  try {
    blocks = walk(bytes);
    checkTrue(`${name}: the file walks cleanly, forwards and by trailing length`, true);
  } catch (err) {
    check(`${name}: the file walks cleanly`, String(err), 'no error');
    return;
  }
  const types = blocks.map((b) => b.type);
  const adapters = [...new Set(ordered.map((p) => p.interfaceName || 'unknown'))];

  check(`${name}: it opens with a Section Header Block`, types[0], SHB);
  check(`${name}: ...then the secrets, ahead of every frame`, [types[1], types.indexOf(DSB) < types.indexOf(EPB)], [DSB, true]);
  check(`${name}: one IDB per adapter in the file`, types.filter((t) => t === IDB).length, adapters.length);
  checkTrue(`${name}: ...each ahead of the first frame that names it`, types.indexOf(IDB) < types.indexOf(EPB));
  check(`${name}: an EPB per frame`, types.filter((t) => t === EPB).length, ordered.length);
  check(`${name}: a Name Resolution Block, since the capture named hosts (${names.length})`, types.filter((t) => t === NRB).length, names.length > 0 ? 1 : 0);
  check(`${name}: a statistics block for the one adapter, last`, types[types.length - 1], ISB);

  // --- the section header ------------------------------------------------------------
  {
    const shb = blocks[0];
    const view = new DataView(shb.body.buffer, shb.body.byteOffset, shb.body.byteLength);
    check(`${name}: little-endian, version 1.0, section length unknown`,
      [view.getUint32(0, true), view.getUint16(4, true), view.getUint16(6, true), view.getBigUint64(8, true)],
      [0x1a2b3c4d, 1, 0, 0xffffffffffffffffn]);
    const opts = options(shb.body, 16);
    const comment = text(opts.get(1)![0]);
    check(`${name}: the section comment is the metadata, one line per entry`,
      comment.split('\n'), metaEntries(meta).map(([k, v]) => `${k}: ${v}`));
    checkTrue(`${name}: ...naming the drops that were reported and saying which were not`,
      comment.includes('Dropped by the driver: 17') && comment.includes('Dropped on the pipe: not available'));
    checkTrue(`${name}: shb_userappl is "Inwire <version>"`, /^Inwire \S+$/.test(text(opts.get(4)![0])));
    check(`${name}: shb_os is what the caller gave`, text(opts.get(3)![0]), 'Windows 11 Pro 10.0.26200');
    check(`${name}: shb_hardware is not claimed`, opts.has(2), false);
  }

  // --- the interface and its statistics ---------------------------------------------------
  {
    const idb = blocks.find((b) => b.type === IDB)!;
    const opts = options(idb.body, 8);
    check(`${name}: the IDB names the adapter and its resolution`,
      [new DataView(idb.body.buffer, idb.body.byteOffset).getUint16(0, true), text(opts.get(2)![0]), opts.get(9)![0][0]],
      [ordered[0].linkType ?? 1, adapters[0], ordered[0].tsPrecision ?? 6]);

    const isb = blocks[blocks.length - 1];
    const isbOpts = options(isb.body, 12);
    check(`${name}: isb_ifdrop is the driver's count`, isbOpts.has(5) ? u64(isbOpts.get(5)![0]) : null, 17n);
    // agent 3, pipe null: the sum has an unknown half, so it is not written -
    // and never written as a zero that claims nothing was lost.
    check(`${name}: isb_osdrop is absent when the pipe count is unknown`, isbOpts.has(7), false);
    check(`${name}: isb_ifrecv is absent when nobody reported it`, isbOpts.has(4), false);
    const start = isbOpts.get(2)![0];
    const startTicks = (BigInt(u32(start, 0)) << 32n) | BigInt(u32(start, 4));
    check(`${name}: isb_starttime is the adapter's first frame, in its own units`, startTicks, BigInt(ordered[0].tsUs));
  }

  // --- direction, in the format's own field -------------------------------------------------
  {
    const epbs = blocks.filter((b) => b.type === EPB);
    const flagOf = (b: Block) => { const v = epbOptions(b).get(2)?.[0]; return v === undefined ? null : u32(v) & 0b11; };
    const wrong = ordered.filter((p, i) => {
      const expected = directionOf(p.direction) === Direction.Out ? 0b10 : directionOf(p.direction) === Direction.In ? 0b01 : null;
      return flagOf(epbs[i]) !== expected;
    });
    const counted = ordered.filter((p) => directionOf(p.direction) !== Direction.Unknown && directionOf(p.direction) !== Direction.Transit).length;
    check(`${name}: epb_flags carries every sent/received frame's direction (${counted}), and nothing for the rest`,
      wrong.map((p) => p.id).slice(0, 5), []);
  }

  // --- paged output is the one-shot file, byte for byte --------------------------------------
  for (const page of [1, 777, 4096]) {
    const paged = writePaged(ordered, writeOptions, page);
    checkTrue(`${name}: written in pages of ${page}, byte-identical to the one-shot file`,
      paged.length === bytes.length && paged.every((b, i) => b === bytes[i]));
  }

  // --- this repo's reader ------------------------------------------------------------------------
  {
    const back = await PcapService.parseCaptureFile(new File([bytes], 'out.pcapng'), Number.POSITIVE_INFINITY);
    check(`${name}: every frame reads back`, back.packets.length, ordered.length);
    checkTrue(`${name}: ...with its bytes and timestamp`, back.packets.every((p, i) =>
      p.tsUs === ordered[i].tsUs && p.rawBytes.length === ordered[i].rawBytes.length
      && p.rawBytes.every((b, j) => b === ordered[i].rawBytes[j])));
  }

  // --- Wireshark's tools ---------------------------------------------------------------------------
  if (tools.tshark === null) {
    console.log(`SKIP  ${name}: tshark not found - the file was not opened with Wireshark's reader`);
    return;
  }
  const out = join(dir, `${name}.pcapng`);
  writeFileSync(out, bytes);
  const ours = tsharkFrames(tools.tshark, out);
  const reference = tsharkFrames(tools.tshark, capture.path);
  check(`${name}: tshark reads as many frames as the original holds`, ours.length, reference.length);
  // The original in time order, as the writer sorts it; a stable sort on the
  // epoch keeps frames sharing a timestamp in file order, as the writer does.
  const referenceOrdered = reference.map((line, i) => ({ line, i }))
    .sort((a, b) => Number(a.line.split('\t')[2]) - Number(b.line.split('\t')[2]) || a.i - b.i)
    .map((x) => x.line);
  check(`${name}: ...with every frame's length, captured length and time identical`,
    ours.filter((l, i) => l !== referenceOrdered[i]).slice(0, 3), []);
  if (tools.capinfos !== null) {
    const info = runTool(tools.capinfos, [out]);
    checkTrue(`${name}: capinfos shows the application`, /Capture application:\s+Inwire \S+/.test(info));
    checkTrue(`${name}: capinfos shows the OS`, info.includes('Capture oper-sys:    Windows 11 Pro 10.0.26200'));
    checkTrue(`${name}: capinfos shows the metadata comment`,
      info.includes(`Frames exported: ${ordered.length.toLocaleString('en-US')}`) && info.includes('Capture comment:'));
  } else {
    console.log(`SKIP  ${name}: capinfos not found`);
  }
}

interface Tools { tshark: string | null; capinfos: string | null; editcap: string | null }

async function main() {
  const captures = await loadRealCaptures();
  const tools: Tools = captures.length > 0
    ? { tshark: findWiresharkTool('tshark'), capinfos: findWiresharkTool('capinfos'), editcap: findWiresharkTool('editcap') }
    : { tshark: null, capinfos: null, editcap: null };
  const dir = mkdtempSync(join(tmpdir(), 'inwire-pcapng-'));
  try {
    for (const capture of captures) await captureChecks(capture, tools, dir);
    if (captures.length > 0) await edgeChecks(captures[0], captures, tools, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The cases a single capture file does not reach, each on real frames. */
async function edgeChecks(capture: RealCapture, allCaptures: RealCapture[], tools: Tools, dir: string): Promise<void> {
  const frames = [...capture.packets].sort((a, b) => a.tsUs - b.tsUs).slice(0, 200);

  // Drop counts: null is never a zero, and osdrop needs both halves.
  {
    const isbOf = (drops: CaptureMeta['drops'], received: number | null = null) => {
      const blocks = walk(concatChunks((() => {
        const w = new PcapngWriter({ statistics: { received, drops } });
        return [...w.write(frames), ...w.finish()];
      })()));
      const isb = blocks.find((b) => b.type === ISB);
      return isb ? options(isb.body, 12) : null;
    };
    check('no counts reported: no statistics block at all', isbOf({ kernel: null, agent: null, pipe: null }), null);
    const both = isbOf({ kernel: 0, agent: 4, pipe: 6 }, 1000)!;
    check('agent and pipe both reported: isb_osdrop is their sum, and a real 0 is written as 0',
      [u64(both.get(7)![0]), u64(both.get(5)![0]), u64(both.get(4)![0])], [10n, 0n, 1000n]);
    const kernelOnly = isbOf({ kernel: null, agent: 4, pipe: 6 })!;
    check('driver count unknown: isb_ifdrop absent, isb_osdrop present', [kernelOnly.has(5), kernelOnly.has(7)], [false, true]);
  }

  // Two adapters: the counters describe the whole capture, so no ISB.
  {
    const twoAdapters = frames.map((p, i) => ({ ...p, interfaceName: i % 2 === 0 ? 'Ethernet' : 'Wi-Fi' }));
    const w = new PcapngWriter({ statistics: { received: 10, drops: { kernel: 1, agent: 1, pipe: 1 } } });
    const blocks = walk(concatChunks([...w.write(twoAdapters), ...w.finish()]));
    check('two adapters: two IDBs, numbered by first appearance', blocks.filter((b) => b.type === IDB)
      .map((b) => text(options(b.body, 8).get(2)![0])), ['Ethernet', 'Wi-Fi']);
    check('...and the second adapter\'s frames name interface 1',
      u32(blocks.filter((b) => b.type === EPB)[1].body), 1);
    check('...and no statistics block, since one count cannot be split between two', blocks.some((b) => b.type === ISB), false);
  }

  // A process attribution: the agent's socket table, which no capture file
  // carries, supplied on a real frame.
  {
    const attributed = { ...frames[0], fields: { ...frames[0].fields, 'inwire.process.name': 'curl.exe', 'inwire.process.pid': 4242, 'inwire.process.path': 'C:/Windows/System32/curl.exe' } };
    const w = new PcapngWriter();
    const epbs = walk(concatChunks([...w.write([attributed, frames[1]]), ...w.finish()])).filter((b) => b.type === EPB);
    check('an attributed frame carries a comment naming the process, pid and path',
      text(epbOptions(epbs[0]).get(1)?.[0] ?? new Uint8Array()), 'Process: curl.exe (pid 4242) - C:/Windows/System32/curl.exe');
    check('an unattributed frame carries no comment at all', epbOptions(epbs[1]).get(1), undefined);
  }

  // The empty capture: a section and nothing else - and Wireshark reads it.
  {
    const empty = new Uint8Array(await generatePcapNg([]).arrayBuffer());
    check('an empty capture is a Section Header Block alone', walk(empty).map((b) => b.type), [SHB]);
    const named = walk(new Uint8Array(await generatePcapNg([], { interfaces: [{ name: 'Ethernet' }] }).arrayBuffer()));
    check('...or with the adapters the caller named, when it named some', named.map((b) => b.type), [SHB, IDB]);
    check('the one-shot comment is the caller\'s line alone when there is no metadata', sectionComment({ comment: 'x' }), 'x');
    if (tools.tshark !== null) {
      const path = join(dir, 'empty.pcapng');
      writeFileSync(path, empty);
      check('tshark opens the empty file and finds no frames', tsharkFrames(tools.tshark, path).length, 0);
    }
  }

  // Nanoseconds: the real capture, shifted by 123 ns and written as a
  // nanosecond pcap by Wireshark's own editcap, so every stamp has real
  // sub-microsecond digits. The writer must give it if_tsresol 9 and keep
  // every one of those digits - and also keep them in a MICROSECOND IDB's
  // neighbour: a ns frame written where the interface says µs is rounded
  // once, from the nanosecond stamp, not twice.
  if (tools.editcap === null || tools.tshark === null) {
    console.log('SKIP  nanosecond capture: editcap or tshark not found');
  } else {
    const nsPath = join(dir, 'ns.pcap');
    runTool(tools.editcap, ['-F', 'nsecpcap', '-t', '0.000000123', capture.path, nsPath]);
    const { packets } = await PcapService.parseCaptureFile(
      new File([new Uint8Array(readFileSync(nsPath))], 'ns.pcap'), Number.POSITIVE_INFINITY);
    const bytes = new Uint8Array(await generatePcapNg(packets).arrayBuffer());
    const idb = walk(bytes).find((b) => b.type === IDB)!;
    check('a nanosecond capture gets if_tsresol 9', options(idb.body, 8).get(9)![0][0], 9);
    const out = join(dir, 'ns.pcapng');
    writeFileSync(out, bytes);
    const times = (path: string) => runTool(tools.tshark!, ['-r', path, '-T', 'fields', '-e', 'frame.time_epoch'])
      .split(/\r?\n/).filter(Boolean).sort();
    const reference = times(nsPath);
    const ours = times(out);
    checkTrue('...the shifted pcap really has sub-microsecond digits (…123)', reference.every((t) => /\.\d{6}123$/.test(t)));
    check('...and tshark reads every nanosecond timestamp as the nanosecond pcap has it',
      [ours.length, ours.filter((t, i) => t !== reference[i]).slice(0, 3)], [reference.length, []]);

    // The same frames under a microsecond interface: the stamp comes from
    // tsNanos, so 123 ns rounds to 0 µs - one rounding, the right one.
    const micro = new Uint8Array(await generatePcapNg(packets, { interfaces: [{ name: packets[0].interfaceName, tsPrecision: 6 }] }).arrayBuffer());
    const epbs = walk(micro).filter((b) => b.type === EPB);
    const ticks = (b: Block) => (BigInt(u32(b.body, 4)) << 32n) | BigInt(u32(b.body, 8));
    const sorted = [...packets].sort((x, y) => x.tsUs - y.tsUs);
    check('...and under a microsecond interface each stamp is its nanoseconds, rounded down to µs once',
      epbs.filter((b, i) => ticks(b) !== sorted[i].tsNanos! / 1000n).length, 0);
  }

  // Two link types under one adapter label - which is every multi-interface
  // file an import reads, since every imported frame carries the same
  // `interfaceName`. Built from both real fixtures by Wireshark's own tools:
  // one re-labelled Raw IP (`editcap -T rawip`), then the two merged into one
  // pcapng. Written back, tshark must see each frame with the encapsulation it
  // had - and the second IDB lands after frames of the first, which is legal
  // and is what this checks tshark accepts.
  const mergecap = findWiresharkTool('mergecap');
  if (tools.editcap === null || tools.tshark === null || mergecap === null || allCaptures.length < 2) {
    console.log('SKIP  multi-link-type capture: editcap, mergecap, tshark or the second fixture not found');
  } else {
    const raw = join(dir, 'raw.pcap');
    const merged = join(dir, 'merged.pcapng');
    runTool(tools.editcap, ['-T', 'rawip', allCaptures[1].path, raw]);
    runTool(mergecap, ['-F', 'pcapng', '-w', merged, allCaptures[0].path, raw]);
    const { packets } = await PcapService.parseCaptureFile(
      new File([new Uint8Array(readFileSync(merged))], 'merged.pcapng'), Number.POSITIVE_INFINITY);
    const labels = new Set(packets.map((p) => p.interfaceName));
    const linkTypes = new Set(packets.map((p) => p.linkType ?? 1));
    check('the merged capture imports as one adapter label with two link types', [labels.size, linkTypes.size], [1, 2]);

    const bytes = new Uint8Array(await generatePcapNg(packets).arrayBuffer());
    const blocks = walk(bytes);
    const idbs = blocks.filter((b) => b.type === IDB);
    check('...and is written with one IDB per link type', idbs.map((b) => new DataView(b.body.buffer, b.body.byteOffset).getUint16(0, true)).sort((x, y) => x - y),
      [...linkTypes].sort((x, y) => x - y));
    const types = blocks.map((b) => b.type);
    checkTrue('...the second IDB after frames of the first', types.lastIndexOf(IDB) > types.indexOf(EPB));
    const out = join(dir, 'merged-out.pcapng');
    writeFileSync(out, bytes);
    const encap = (path: string) => runTool(tools.tshark!, ['-r', path, '-T', 'fields', '-e', 'frame.time_epoch', '-e', 'frame.encap_type', '-e', 'frame.len'])
      .split(/\r?\n/).filter(Boolean).sort();
    const reference = encap(merged);
    const ours = encap(out);
    check('...and tshark reads every frame with its original link type, time and length',
      [ours.length, ours.filter((l, i) => l !== reference[i]).slice(0, 3)], [reference.length, []]);
  }

  // Anonymised: the adapter is labelled as the metadata labels it, and a name
  // table or key log is refused rather than written.
  {
    const anonymisedMeta = { ...metaFor(capture, { kernel: null, agent: null, pipe: null }), flags: { anonymised: true, rawBytes: true, fields: false, secrets: false } };
    const w = new PcapngWriter({ meta: anonymisedMeta });
    const idb = walk(concatChunks([...w.write(frames.slice(0, 5)), ...w.finish()])).find((b) => b.type === IDB)!;
    check('an anonymised pcapng names the adapter "adapter 1" when there is no anonymiser to map it', text(options(idb.body, 8).get(2)![0]), 'adapter 1');
    let refusedNames = false;
    try { new PcapngWriter({ meta: anonymisedMeta, names: [{ address: frames[0].source, names: ['host'] }] }); } catch { refusedNames = true; }
    let refusedSecrets = false;
    try { new PcapngWriter({ meta: anonymisedMeta, secrets: 'CLIENT_RANDOM 00 11\n' }); } catch { refusedSecrets = true; }
    check('...and refuses a name table or a key log', [refusedNames, refusedSecrets], [true, true]);
  }
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All pcapng writer checks passed.');
  process.exit(0);
}).catch((err) => {
  console.log(`FAIL  the writer threw: ${err instanceof Error ? err.stack : String(err)}`);
  process.exit(1);
});
