/**
 * Did live decryption keep up? Replays a stored capture against a key log.
 *
 *   npx tsx scripts/tls/replay-stored-capture.ts <capture dir> <key log>
 *
 * e.g. `%LOCALAPPDATA%\Inwire\captures\cap-...` and the file `SSLKEYLOGFILE`
 * names. A tool, not a test: it needs a person's own capture, so it is in
 * `check.ts`'s `NOT_TESTS`.
 *
 * It answers the question ADR 0045 could not answer from any driver - whether
 * a browser's secrets reach the Worker before the packets they open - without
 * starting a capture on a real adapter. The stored rows are what the live
 * Worker produced; re-dissecting the stored bytes with the whole key log is
 * what it would have produced had every secret been there in time. The
 * difference is the race, and the per-connection pattern says which kind:
 *
 * - `oooo...dddd` on every connection - the first burst lost, the rest
 *   decrypted - is **late keys**. That is what this found with a one-second
 *   poll: 180 of 326 opaque live, all 180 decrypting on replay.
 * - `oooo` for a whole connection that decrypts on replay is a secret that
 *   never arrived while it ran.
 * - opaque on replay too is not the race at all: no secret for that
 *   connection in the file, or a handshake the capture did not see.
 *
 * The capture directory is copied first. Opening it runs recovery, which can
 * truncate a torn tail, and a tool for looking must not change what it looks at.
 */
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { CaptureWriter } from '../../src/services/capture/captureWriter';
import { CaptureReader } from '../../src/services/capture/captureReader';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import { recoverIndex } from '../../src/services/capture/captureIndex';
import { PcapService } from '../../src/services/pcapParser';
import { keyLog } from '../../src/services/tls/keyLog';
import type { Packet } from '../../src/types/packet';

const [captureDir, keyLogFile] = process.argv.slice(2);
if (!captureDir || !keyLogFile) {
  console.log('usage: npx tsx scripts/tls/replay-stored-capture.ts <capture dir> <key log>');
  process.exit(2);
}

const isProtected = (p: Packet) => /QUIC|HTTP.?3/i.test(p.protocol) && /Protected Payload/.test(p.info);
/** A decrypted short-header packet's Info goes on past the type to its number. */
const isOpened = (p: Packet) => /PKN/.test(p.info);

async function main(): Promise<void> {
  const work = mkdtempSync(path.join(tmpdir(), 'inwire-replay-'));
  try {
    cpSync(captureDir, work, { recursive: true });
    const files = {
      index: NodeBlockFile.open(path.join(work, 'index.iwidx')),
      pfx: NodeBlockFile.open(path.join(work, 'prefix.iwpfx')),
      sum: NodeBlockFile.open(path.join(work, 'summary.iwsum')),
      byt: NodeBlockFile.open(path.join(work, 'frames.iwbyt')),
    };
    const inflate = (b: Uint8Array) => new Uint8Array(inflateRawSync(b));
    const deflate = (b: Uint8Array) => new Uint8Array(deflateRawSync(b));
    const { records, plan } = recoverIndex(files.index, files.pfx, files.sum, files.byt);
    const index = new CaptureWriter(files, { deflate, resumeFrom: records.slice(0, plan.keepRecords) }).index;
    const reader = new CaptureReader(files, index, inflate);

    const live: Packet[] = [];
    for (let chunk = 0; chunk < index.chunkCount; chunk++) live.push(...reader.readRows(chunk));
    const bytes = reader.readBytes(live.map((p) => p.id));
    const withBytes = live.map((p) => ({ ...p, rawBytes: bytes.get(p.id) ?? new Uint8Array(0) }) as Packet);
    for (const file of Object.values(files)) file.close();

    keyLog.add(readFileSync(keyLogFile, 'latin1'));
    const pcap = PcapService.generatePcapBinary(withBytes);
    const replayed = (await PcapService.parseCaptureFile(
      new File([await pcap.arrayBuffer()], 'replay.pcap'),
    )).packets;

    const liveProtected = live.filter(isProtected);
    const liveOpaque = liveProtected.filter((p) => !isOpened(p));
    const replayOpaque = replayed.filter((p) => isProtected(p) && !isOpened(p));
    console.log(`${live.length.toLocaleString()} frames, key log ${JSON.stringify(keyLog.stats())}`);
    console.log(`protected QUIC packets: ${liveProtected.length}`);
    console.log(`  opaque as the live capture dissected them: ${liveOpaque.length}`);
    console.log(`  opaque re-dissected with the whole key log: ${replayOpaque.length}`);
    console.log(`  => lost to timing, not to a missing secret: ${liveOpaque.length - replayOpaque.length}\n`);

    // Per connection, in arrival order: o = opaque live, d = decrypted live.
    const flows = new Map<string, Packet[]>();
    for (const p of liveProtected) {
      const ends = [
        `${p.source}:${p.fields?.['udp.srcport'] ?? '?'}`,
        `${p.destination}:${p.fields?.['udp.dstport'] ?? '?'}`,
      ].sort();
      const key = ends.join(' <> ');
      const list = flows.get(key);
      if (list === undefined) flows.set(key, [p]);
      else list.push(p);
    }
    for (const [key, list] of flows) {
      const pattern = list.map((p) => (isOpened(p) ? 'd' : 'o')).join('');
      const lastOpaque = [...list].reverse().find((p) => !isOpened(p));
      const burst = lastOpaque === undefined
        ? 'none opaque'
        : `opaque for ${((lastOpaque.relativeTime - list[0].relativeTime) * 1000).toFixed(0)} ms`;
      console.log(`${key}\n    ${pattern.length > 72 ? `${pattern.slice(0, 72)}...` : pattern}  (${burst})`);
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

main().then(() => process.exit(0), (error) => {
  console.error(error);
  process.exit(1);
});
