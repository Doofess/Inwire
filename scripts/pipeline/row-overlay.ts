/**
 * The overlay carries every write the coordinator's merge makes to a shard's
 * row (ADR 0053 phase 6, `src/services/pipeline/rowOverlay.ts`).
 *
 *   npx tsx scripts/pipeline/row-overlay.ts
 *
 * A shard's row reaches the window and the store as the shard packed it, plus
 * an overlay of what the merge wrote after: the settled `tls.stream`, the
 * process, a live gap, a fingerprint match, the clock precision. A step that
 * writes a key the overlay does not cover loses that write downstream with no
 * error anywhere, so this runs the real steps in `emitMerged`'s order and holds
 * "packed row + overlay" to the row the merge produced.
 */
import { isDeepStrictEqual } from 'node:util';
import { FlowAnnotationStore } from '../../src/services/flowAnnotations';
import { annotatePacket } from '../../src/services/dissect/processFields';
import { markLiveGap } from '../../src/services/dissect/liveGapFields';
import { ClientFingerprintStore, learnOrLabelFingerprint } from '../../src/services/dissect/clientFingerprints';
import { settleField } from '../../src/services/pipeline/coordinator';
import { applyOverlay, overlayMark, overlayOf } from '../../src/services/pipeline/rowOverlay';
import { PcapService } from '../../src/services/pcapParser';
import { Shard } from '../../src/services/pipeline/shard';
import { OpWriter, type FromShard } from '../../src/services/pipeline/shardProtocol';
import { unpackRows } from '../../src/services/pipeline/rowPack';
import type { Packet } from '../../src/types/packet';
import { evictionCapture } from './evictionCapture';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const T0 = 1_700_000_000 * 1_000_000;
const JA4 = 't13d1516h2_8daaf6152771_02713d6af862';

function row(id: number, sourcePort: number, fields: Record<string, string | number>): Packet {
  return {
    id, tsUs: T0 + id, relativeTime: 0, timeDelta: 0, length: 66,
    source: '10.0.0.4', destination: '93.184.216.34', sourcePort, destPort: 443,
    protocol: 'TLS', info: 'Client Hello', status: 'ok', rawBytes: new Uint8Array(0),
    layers: [{ name: 'Frame', summary: '', fields: [] }],
    frameProtocols: ['eth', 'ethertype', 'ip', 'tcp', 'tls'], fields,
  } as unknown as Packet;
}

/** Everything but the tree, which the overlay does not carry: trees stay on the shard. */
function bare(p: Packet): Packet {
  const copy = structuredClone({ ...p, layers: [] });
  return copy as Packet;
}

const flows = new FlowAnnotationStore();
flows.apply({
  full: true, procs: { 100: { name: 'chrome.exe', exe: 'C:/chrome.exe' } },
  add: [['tcp', '10.0.0.4', 54321, 100]], gone: [],
}, T0);
const fingerprints = new ClientFingerprintStore();

/** `emitMerged`'s writes, in its order, after `Coordinator.emit`'s settle. */
function merge(p: Packet, gap: number): void {
  settleField(p, () => 7);
  p.tsPrecision = 9;
  p.tsNanos = BigInt(p.tsUs) * 1000n + 123n;
  annotatePacket(p, flows);
  markLiveGap(p, gap);
  learnOrLabelFingerprint(p.fields, fingerprints, p.layers);
}

// An attributed ClientHello: settles, gains a process, a gap, and teaches its ja4.
const attributed = row(1, 54321, { 'tls.stream': -3, 'tls.handshake.ja4': JA4 });
// An unattributed one with the same ja4, after: labelled with the match.
const labelled = row(2, 50000, { 'tls.stream': -4, 'tls.handshake.ja4': JA4 });
// A row the merge changes nothing on but the clock.
const plain = row(3, 50001, {});

for (const [name, p, gap] of [['attributed', attributed, 12], ['labelled', labelled, 0], ['plain', plain, 0]] as const) {
  const before = bare(p);
  const mark = overlayMark(p);
  merge(p, gap);
  const overlay = overlayOf(p, mark);
  const rebuilt = bare(before);
  if (overlay !== null) applyOverlay(rebuilt, overlay);
  check(`${name}: the packed row plus its overlay is the merged row`, isDeepStrictEqual(rebuilt, bare(p)),
    `overlay ${JSON.stringify(overlay, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v))}`);
}
check('the attributed row was given its process, gap and settled stream',
  attributed.fields?.['inwire.process.name'] === 'chrome.exe' && attributed.fields?.['inwire.live.skipped'] === 12
  && attributed.fields?.['tls.stream'] === 7);
check('the labelled row was given the ja4 match', labelled.fields?.['inwire.process.ja4_match'] === 'chrome.exe');

// Nothing changed: no overlay at all.
{
  const p = row(4, 50002, {});
  p.tsPrecision = 9;
  const mark = overlayMark(p);
  check('a row the merge did not touch has no overlay', overlayOf(p, mark) === null);
}

// The guard can fail: a write outside what the overlay covers shows up as a difference.
{
  const p = row(5, 50003, {});
  const before = bare(p);
  const mark = overlayMark(p);
  p.info = 'rewritten';
  const rebuilt = bare(before);
  const overlay = overlayOf(p, mark);
  if (overlay !== null) applyOverlay(rebuilt, overlay);
  check('a write to an uncovered key is caught by the comparison', !isDeepStrictEqual(rebuilt, bare(p)));
}

// The overlay is a snapshot: a later write to the row does not reach it.
{
  const p = row(6, 54321, {});
  const mark = overlayMark(p);
  markLiveGap(p, 3);
  const overlay = overlayOf(p, mark)!;
  p.expert!.push({ category: 'CaptureGap', message: 'later' } as never);
  p.fields!['inwire.live.skipped'] = 99;
  check('...and does not alias the row it was taken from',
    overlay.expert!.length === 1 && overlay.fields!['inwire.live.skipped'] === 3);
}

// The merge writes the adapter's clock onto every row. A shard told the clock
// packs it, so that write changes nothing and costs no overlay per row - one
// would be an object on every row to the window and the store.
await (async () => {
  const { frames } = await PcapService.extractFrames(new File([evictionCapture()], 'e.pcap'), 1);
  const frame = frames[0];
  let posted: FromShard | null = null;
  const shard = new Shard((message) => { posted = message; }, { shards: 1, cacheFrames: 8 });
  shard.handle({ type: 'interfaces', interfaces: [[0, { name: 'eth', label: 'Ethernet', tsPrecision: 9 }]] });
  const writer = new OpWriter();
  const tsUs = Number(frame.tsNanos / 1000n);
  const none = { index: 0, pnum: 1, sinceFirst: 0, sincePrev: 0 };
  writer.tcp({
    id: 1, bytes: frame.rawBytes, tsUs, relativeTime: 0, timeDelta: 0, origLen: frame.origLen,
    linktype: frame.linktype, iface: 0, facts: { nanosRemainder: 123 },
  }, 'ip', { a: '00:00:5e:00:53:01', b: '00:00:5e:00:53:02', facts: none }, { a: '10.1.0.1', b: '10.2.0.1', facts: none }, '10.1.0.1:1024|10.2.0.1:443', 0);
  shard.handle({ type: 'batch', epoch: 0, ops: writer.seal() });
  const message = posted as FromShard | null;
  const pack = message?.type === 'results' ? message.pack : null;
  const row = pack === null ? undefined : unpackRows(pack)[0];
  check('a shard told the adapter\'s clock packs it', row?.tsPrecision === 9
    && row.tsNanos === BigInt(tsUs) * 1000n + 123n, `tsPrecision ${row?.tsPrecision}, tsNanos ${row?.tsNanos}`);
  if (row !== undefined) {
    const mark = overlayMark(row);
    row.tsPrecision = 9;
    row.tsNanos = BigInt(tsUs) * 1000n + 123n;
    check('...so the merge writing the same clock leaves no overlay', overlayOf(row, mark) === null);
  }
})();

console.log(failures === 0 ? '\nAll row-overlay checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
