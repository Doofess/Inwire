/**
 * The recovery rule, against real files that are really truncated.
 *
 *   npx tsx scripts/capture/recovery-on-disk.ts
 *
 * `blockFile.ts` has said since it was written that the format's hardest parts
 * - the recovery rule and the offset arithmetic - "cannot be tested through the
 * real backend, because **OPFS does not exist in Node**, and a browser cannot
 * be crashed on demand from a test", and that `scripts/` would supply a
 * `node:fs` implementation and "drive the format against a real file on the
 * local disk, killing and truncating it at chosen offsets".
 *
 * That has never been possible. Every capture script until now built its
 * `CaptureFiles` out of four `MemoryBlockFile`s, which is a faithful model of
 * the interface and no model at all of a filesystem: it cannot be truncated by
 * another process, reopened, or left half-written by a power cut.
 *
 * This is that test. What it adds over `scripts/capture/writer.ts`'s
 * in-memory version is not more cases - it is that the bytes survive the
 * process, so "reopen the capture and recover it" is a real sequence rather
 * than a method call on an object that never went away.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { CaptureWriter, type CaptureFiles } from '../../src/services/capture/captureWriter';
import { CaptureReader } from '../../src/services/capture/captureReader';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import { recoverIndex } from '../../src/services/capture/captureIndex';
import { CHUNK_FRAMES } from '../../src/services/capture/chunkCodec';
import { PcapService } from '../../src/services/pcapParser';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean): void { check(name, condition, true); }

const deflate = (b: Uint8Array): Uint8Array => new Uint8Array(deflateRawSync(b));
const inflate = (b: Uint8Array): Uint8Array => new Uint8Array(inflateRawSync(b));

const root = mkdtempSync(path.join(tmpdir(), 'inwire-recovery-'));

/** The four files a capture is, on disk, exactly as the store lays them out. */
function openCapture(id: string): CaptureFiles & { close(): void } {
  const dir = path.join(root, id);
  const files = {
    index: NodeBlockFile.open(path.join(dir, 'index.iwidx')),
    pfx: NodeBlockFile.open(path.join(dir, 'prefix.iwpfx')),
    sum: NodeBlockFile.open(path.join(dir, 'summary.iwsum')),
    byt: NodeBlockFile.open(path.join(dir, 'frames.iwbyt')),
  };
  return {
    ...files,
    close() {
      for (const file of Object.values(files)) file.close();
    },
  };
}

function frame(id: number, length = 120): Packet {
  const raw = new Uint8Array(length);
  for (let i = 0; i < length; i++) raw[i] = (id * 13 + i) & 0xff;
  return {
    id,
    source: '10.0.0.4',
    destination: '93.184.216.34',
    protocol: 'TCP',
    info: `frame ${id}`,
    status: 'ok',
    length,
    tsUs: 1_788_000_000_000_000 + id * 1000,
    relativeTime: id / 1000,
    timeDelta: 0.001,
    interfaceName: 'Ethernet 2',
    layers: [],
    rawBytes: raw,
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    fields: {},
  } as Packet;
}

try {
  console.log('--- a capture that outlives the process that wrote it ---\n');
  {
    const files = openCapture('healthy');
    const writer = new CaptureWriter(files, { deflate, horizonUs: 0 });
    const packets = Array.from({ length: CHUNK_FRAMES * 2 + 400 }, (_, i) => frame(i + 1));
    for (let i = 0; i < packets.length; i += 500) writer.append(packets.slice(i, i + 500));
    writer.finish();
    const chunks = writer.index.chunkCount;
    files.close();

    // Four real files, on a real disk, with the process's handles closed.
    for (const name of ['index.iwidx', 'prefix.iwpfx', 'summary.iwsum', 'frames.iwbyt']) {
      checkTrue(`${name} is on disk`, existsSync(path.join(root, 'healthy', name)));
    }

    const reopened = openCapture('healthy');
    const { records, plan } = recoverIndex(reopened.index, reopened.pfx, reopened.sum, reopened.byt);
    // The case that matters most and is easiest to get wrong: a clean capture
    // must recover to itself. A rule that truncated one chunk on every launch
    // would look like a rounding error and cost a chunk a time.
    check('a healthy capture loses nothing on reopen',
      [records.length, plan.keepRecords, plan.framesLost], [chunks, chunks, 0]);

    const reader = new CaptureReader(reopened, new CaptureWriter(reopened, {
      deflate, resumeFrom: records.slice(0, plan.keepRecords),
    }).index, inflate);
    const back = reader.readBytes([1, 4096, packets.length]);
    check('...and its frames still read back byte for byte',
      [1, 4096, packets.length].map((id) => {
        const want = frame(id).rawBytes;
        const got = back.get(id);
        return got !== undefined && got.length === want.length && got.every((b, i) => b === want[i]);
      }),
      [true, true, true]);
    reopened.close();
  }

  console.log('\n--- a torn tail, at every file in turn ---\n');
  {
    // The write order is data, flush, then the index record - so the only
    // inconsistency a crash can leave is data past the last record, or a
    // record whose extents run past a file that never landed.
    for (const victim of ['byt', 'sum', 'pfx'] as const) {
      const id = `torn-${victim}`;
      const files = openCapture(id);
      const writer = new CaptureWriter(files, { deflate, horizonUs: 0 });
      writer.append(Array.from({ length: CHUNK_FRAMES * 3 }, (_, i) => frame(i + 1)));
      writer.finish();
      const before = writer.index.chunkCount;
      files.close();

      // Cut one byte off the file the last chunk's record points into. On a
      // real disk this is what a power cut between the write and the fsync
      // looks like from the next launch's point of view.
      const reopened = openCapture(id);
      reopened[victim].truncate(reopened[victim].size() - 1);
      const { records, plan } = recoverIndex(
        reopened.index, reopened.pfx, reopened.sum, reopened.byt,
      );
      check(`a torn ${victim} costs exactly the last chunk`,
        [records.length, plan.keepRecords, plan.framesLost],
        [before, before - 1, CHUNK_FRAMES]);

      // Applying the plan and reopening must then be stable: recovery is not
      // allowed to keep eating a chunk every time the app starts.
      reopened.pfx.truncate(plan.pfxLength);
      reopened.sum.truncate(plan.sumLength);
      reopened.byt.truncate(plan.bytLength);
      reopened.index.truncate(plan.indexLength);
      const second = recoverIndex(reopened.index, reopened.pfx, reopened.sum, reopened.byt);
      check(`...and recovering again costs nothing more`,
        [second.plan.keepRecords, second.plan.framesLost], [before - 1, 0]);
      reopened.close();
    }
  }

  console.log('\n--- data past the last index record ---\n');
  {
    const id = 'orphan-bytes';
    const files = openCapture(id);
    const writer = new CaptureWriter(files, { deflate, horizonUs: 0 });
    writer.append(Array.from({ length: CHUNK_FRAMES }, (_, i) => frame(i + 1)));
    writer.finish();
    files.close();

    // Frame bytes are written the instant they arrive, so a crash mid-capture
    // routinely leaves bytes no record describes. They must be discarded, not
    // read: nothing can find them and leaving them makes every later offset
    // wrong.
    const reopened = openCapture(id);
    const bytBefore = reopened.byt.size();
    reopened.byt.write(bytBefore, new Uint8Array(5000).fill(0xcc));
    const { plan } = recoverIndex(reopened.index, reopened.pfx, reopened.sum, reopened.byt);
    check('bytes past the last record are discarded, and no chunk is lost',
      [plan.framesLost, plan.bytLength], [0, bytBefore]);
    reopened.close();
  }

  console.log('\n--- resuming, and then reopening again ---\n');
  {
    const id = 'resume';
    const files = openCapture(id);
    const first = new CaptureWriter(files, { deflate, horizonUs: 0 });
    first.append(Array.from({ length: CHUNK_FRAMES + 100 }, (_, i) => frame(i + 1)));
    first.finish();
    files.close();

    const again = openCapture(id);
    const { records, plan } = recoverIndex(again.index, again.pfx, again.sum, again.byt);
    const second = new CaptureWriter(again, {
      deflate, horizonUs: 0, resumeFrom: records.slice(0, plan.keepRecords),
    });
    check('a resumed writer counts what the last run left',
      second.stats.framesWritten, CHUNK_FRAMES + 100);
    second.append(Array.from({ length: 50 }, (_, i) => frame(CHUNK_FRAMES + 100 + i + 1)));
    second.finish();
    const total = second.index.frameCount;
    again.close();

    const third = openCapture(id);
    const final = recoverIndex(third.index, third.pfx, third.sum, third.byt);
    check('...and the capture that comes back is the sum of both runs',
      [final.records.reduce((n, r) => n + r.frameCount, 0), final.plan.framesLost],
      [total, 0]);
    third.close();
  }

  console.log('\n--- against a real capture ---\n');
  {
    const fixture = 'test/fixtures/bulk_capture_1788426090876.pcap';
    if (!existsSync(fixture)) {
      console.log(`SKIP  ${fixture} not present (test/fixtures/README.md)`);
    } else {
      const buf = readFileSync(fixture);
      const parsed = await PcapService.parseCaptureFile(
        new File([new Uint8Array(buf)], 'fixture.pcap'), Number.POSITIVE_INFINITY,
      );
      const packets = parsed.packets;

      const files = openCapture('bulk');
      const writer = new CaptureWriter(files, { deflate, horizonUs: 0 });
      for (let i = 0; i < packets.length; i += 500) writer.append(packets.slice(i, i + 500));
      writer.finish();
      files.close();

      const reopened = openCapture('bulk');
      const { records, plan } = recoverIndex(
        reopened.index, reopened.pfx, reopened.sum, reopened.byt,
      );
      const reader = new CaptureReader(reopened, new CaptureWriter(reopened, {
        deflate, resumeFrom: records.slice(0, plan.keepRecords),
      }).index, inflate);
      const back = reader.readBytes(packets.map((p) => p.id));

      let wrong = 0;
      for (const packet of packets) {
        if (packet.rawBytes.length === 0) continue;
        const got = back.get(packet.id);
        if (got === undefined || got.length !== packet.rawBytes.length) { wrong++; continue; }
        for (let i = 0; i < got.length; i++) {
          if (got[i] !== packet.rawBytes[i]) { wrong++; break; }
        }
      }
      check(`${packets.length.toLocaleString()} real frames survive a write, a close and a reopen`,
        [plan.framesLost, wrong], [0, 0]);
      const onDisk = reopened.index.size() + reopened.pfx.size()
        + reopened.sum.size() + reopened.byt.size();
      console.log(`      (${(onDisk / packets.length).toFixed(0)} B/frame across the four files)`);
      reopened.close();
    }
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

console.log(failures === 0
  ? '\nAll on-disk recovery checks passed.'
  : `\n${failures} on-disk recovery check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
