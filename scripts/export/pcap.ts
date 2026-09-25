/**
 * Assertion tests for the classic pcap writer, on the two real captures.
 *
 *   npx tsx scripts/export/pcap.ts
 *
 * Classic pcap is a 24-byte header and a 16-byte header per record, so the
 * strongest check is also the simplest: the fixtures ARE little-endian
 * microsecond pcap files, so re-writing their frames must reproduce the
 * original's records byte for byte. Then tshark must read the written file
 * with every frame's length and time identical to the original's, and the
 * paged writer must match the one-shot file exactly.
 *
 * SKIPs cleanly without the fixtures (ADR 0004), and the tshark check
 * without tshark.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generatePcapBinary } from '../../src/services/export/oneShot';
import { PcapWriter } from '../../src/services/export/writers/pcap';
import { concatChunks, pipeToSink } from '../../src/services/export/writers/writer';
import { MemorySink } from '../../src/lib/saveSink';
import { LINKTYPE } from '../../src/services/dissect/types';
import { findWiresharkTool, loadRealCaptures, runTool } from './realCaptures';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)?.slice(0, 300)}`);
    console.log(`        actual   ${JSON.stringify(actual)?.slice(0, 300)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

async function main() {
  const captures = await loadRealCaptures();
  const tshark = captures.length > 0 ? findWiresharkTool('tshark') : null;
  const dir = mkdtempSync(join(tmpdir(), 'inwire-pcap-'));
  try {
    for (const capture of captures) {
      const name = capture.name;
      const original = new Uint8Array(readFileSync(capture.path));
      const bytes = new Uint8Array(await generatePcapBinary(capture.packets).arrayBuffer());

      const view = new DataView(bytes.buffer);
      check(`${name}: the header is little-endian microsecond pcap 2.4`,
        [view.getUint32(0, true), view.getUint16(4, true), view.getUint16(6, true)], [0xa1b2c3d4, 2, 4]);
      check(`${name}: ...declaring the frames' own link type`, view.getUint32(20, true), capture.packets[0].linkType ?? LINKTYPE.ETHERNET);

      // The original's records, in the order the writer puts frames: by time,
      // stably - one of the fixtures is not in time order on disk, which is
      // exactly why the writer sorts. Every record must be the original's.
      const records: { us: number; bytes: Uint8Array }[] = [];
      const ov = new DataView(original.buffer, original.byteOffset, original.byteLength);
      for (let at = 24; at + 16 <= original.length;) {
        const capLen = ov.getUint32(at + 8, true);
        records.push({ us: ov.getUint32(at, true) * 1_000_000 + ov.getUint32(at + 4, true), bytes: original.subarray(at, at + 16 + capLen) });
        at += 16 + capLen;
      }
      records.sort((x, y) => x.us - y.us);
      checkTrue(`${name}: every record is the original file's, byte for byte, in time order (${records.length} frames)`,
        same(bytes.subarray(24), concatChunks(records.map((r) => r.bytes))));

      const sorted = [...capture.packets].sort((a, b) => a.tsUs - b.tsUs);
      for (const page of [1, 1000]) {
        const writer = new PcapWriter();
        const chunks: Uint8Array[] = [];
        for (let at = 0; at < sorted.length; at += page) chunks.push(...writer.write(sorted.slice(at, at + page)));
        chunks.push(...writer.finish());
        checkTrue(`${name}: written in pages of ${page}, identical to the one-shot file`, same(concatChunks(chunks), bytes));
      }

      // Through a sink, the way a whole-capture export writes it.
      {
        const sink = new MemorySink();
        const pages = Array.from({ length: Math.ceil(sorted.length / 4096) }, (_, k) => ({ packets: sorted.slice(k * 4096, (k + 1) * 4096) }));
        const outcome = await pipeToSink(new PcapWriter(), pages, sink);
        check(`${name}: piped to a sink, the file is the one-shot file and the sink is closed`,
          [outcome.saved, same(sink.bytes(), bytes)], [true, true]);
        const failing = new MemorySink();
        async function* broken() { yield pages[0]; throw new Error('the store went away'); }
        let threw = false;
        try { await pipeToSink(new PcapWriter(), broken(), failing); } catch { threw = true; }
        check(`${name}: a failure mid-export aborts the sink rather than closing it`,
          [threw, failing.aborted, failing.closed], [true, true, false]);
      }

      if (tshark === null) {
        console.log(`SKIP  ${name}: tshark not found`);
        continue;
      }
      const out = join(dir, `${name}.pcap`);
      writeFileSync(out, bytes);
      const fields = (path: string) => runTool(tshark, ['-r', path, '-T', 'fields', '-e', 'frame.len', '-e', 'frame.cap_len', '-e', 'frame.time_epoch'])
        .split(/\r?\n/).filter(Boolean);
      const ours = fields(out);
      const theirs = fields(capture.path);
      check(`${name}: tshark reads every frame`, ours.length, theirs.length);
      const epoch = (line: string) => Number(line.split('\t')[2]);
      const theirsOrdered = theirs.map((line, i) => ({ line, i }))
        .sort((x, y) => epoch(x.line) - epoch(y.line) || x.i - y.i).map((x) => x.line);
      check(`${name}: ...with the original's length, captured length and time`,
        ours.filter((l, i) => l !== theirsOrdered[i]).slice(0, 3), []);
    }

    if (captures.length > 0) {
      const empty = new Uint8Array(await generatePcapBinary([]).arrayBuffer());
      check('an empty capture is a header alone, declaring Ethernet', [empty.length, new DataView(empty.buffer).getUint32(20, true)], [24, 1]);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All pcap writer checks passed.');
  process.exit(0);
}

main().catch((err) => {
  console.log(`FAIL  threw: ${err instanceof Error ? err.stack : String(err)}`);
  process.exit(1);
});
