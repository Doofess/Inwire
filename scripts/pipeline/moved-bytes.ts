/**
 * A frame's bytes are MOVED once it is dissected, and nothing may notice.
 *
 *   npx tsx scripts/pipeline/moved-bytes.ts
 *
 * The live pipeline Worker transfers each flush's frame bytes to the renderer
 * (`flush()` in pipeline.worker.ts), which detaches them in the Worker. That is
 * safe only if no tracker kept a VIEW of an earlier frame's bytes - and a view
 * of a detached buffer does not throw when read: it reads as empty. So a
 * tracker that kept one does not fail, it quietly answers differently.
 *
 * One did. A TLS conversation kept its client and server randoms as views of
 * the hello frames, and the ServerHello's frame joins the client random
 * against the key log. On a live capture, every connection whose two hellos
 * fell in different flushes said "no key log entry for this connection" and
 * stayed encrypted. No import could show it, and no fixture test, because
 * nothing else ever detaches a frame. Found when recording those randoms into
 * a frame record threw on the detached buffer (ADR 0049).
 *
 * So every real capture is dissected twice, once with every frame's bytes
 * left alone and once with each frame's buffer detached the moment its
 * dissection ends - the key-log capture with its key log - and every tree
 * must render identically.
 *
 * Real captures only (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService, decodeRawEthernetPacket, type ExtractedFrame } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { keyLog } from '../../src/services/tls/keyLog';
import type { HostIdentity } from '../../src/services/direction';
import { FIXTURES, render } from './arrival';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 300));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 300));
  }
}

/** Every frame's tree, in order, each frame in a buffer of its own as the Worker holds it. */
function dissect(frames: ExtractedFrame[], host: HostIdentity | undefined, move: boolean): string[] {
  const tcp = new TcpStreamTracker();
  const icmp = new IcmpEchoTracker();
  const quic = new QuicFlowTracker();
  const dns = new DnsTracker();
  const l3 = new L3Tracker();
  const trees: string[] = [];
  let base: bigint | null = null;
  let previous: bigint | null = null;
  for (const [i, frame] of frames.entries()) {
    if (base === null) base = frame.tsNanos;
    const own = frame.rawBytes.slice();
    const { packet } = decodeRawEthernetPacket(own, i + 1, Number(frame.tsNanos / 1000n),
      Number(frame.tsNanos - base) / 1e9, previous === null ? 0 : Number(frame.tsNanos - previous) / 1e9,
      frame.origLen, tcp, icmp, quic, dns, undefined, frame.linktype, l3, host);
    previous = frame.tsNanos;
    trees.push(render(packet.layers));
    if (move) structuredClone(own.buffer, { transfer: [own.buffer] });
  }
  return trees;
}

async function main() {
  let ran = 0;
  for (const { name, path } of FIXTURES) {
    if (!existsSync(path)) {
      console.log(`SKIP  ${name}: ${path} is not present - see test/fixtures/README.md`);
      continue;
    }
    const keysPath = path.replace(/\.pcapng?$/, '.keys');
    const keys = keysPath !== path && existsSync(keysPath) ? readFileSync(keysPath, 'utf8') : null;
    const { frames } = await PcapService.extractFrames(new File([new Uint8Array(readFileSync(path))], 'f.pcap'),
      Number.POSITIVE_INFINITY);
    const host = PcapService.inferHostFromFrames(frames);
    keyLog.clear();
    if (keys !== null) keyLog.add(keys);
    const kept = dissect(frames, host, false);
    keyLog.clear();
    if (keys !== null) keyLog.add(keys);
    const moved = dissect(frames, host, true);
    keyLog.clear();
    const differ: string[] = [];
    for (let i = 0; i < kept.length; i++) {
      if (kept[i] === moved[i]) continue;
      const a = kept[i].split('\n');
      const b = moved[i].split('\n');
      let j = 0;
      while (j < a.length && a[j] === b[j]) j++;
      differ.push(`frame ${i + 1}: "${a[j]}" became "${b[j]}"`);
    }
    const label = keys !== null ? `${name} (with its key log)` : name;
    check(`${label}: no tree of ${frames.length.toLocaleString()} changes when earlier frames' bytes are moved`,
      differ.slice(0, 3), []);
    ran += 1;
  }
  if (ran === 0) console.log('\nAll moved-bytes checks passed (skipped).');
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All moved-bytes checks passed.');
  process.exit(0);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
