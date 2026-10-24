/**
 * What does a dissected row cost to carry between threads, by codec?
 *
 *   npx tsx scripts/perf/row-codec.ts --pcap some.pcapng [--frames 300000] [--batch 384]
 *
 * ADR 0053 phase 6 gates on this. With shards, every TCP row crosses three
 * boundaries: shard -> coordinator, then coordinator -> window and
 * coordinator -> store. Profiled at 60,000 a second, the coordinator spends
 * ~47% of its time on that: deserializing the shards' answers (15.7%) and
 * cloning each row twice (18.8% + 12.2%). Packing a batch's rows into one
 * buffer the coordinator forwards is only worth building if some codec makes
 * the whole path cheaper, not just the coordinator's part of it - the window's
 * main thread decodes what it receives, and it was the limit before phase 3.
 *
 * So each codec is timed per hop, on the burst's own rows in shard-sized
 * batches, after one warm pass:
 *
 *  - **clone**: `v8.serialize` / `v8.deserialize`, the serializer a
 *    `postMessage` runs. Today: one deserialize and two serializes on the
 *    coordinator, one deserialize each in the window and the store.
 *  - **json**: `JSON.stringify` / `JSON.parse`. Needs no schema, and a string
 *    is forwarded by copy without a per-field walk.
 *  - **chunk**: the store's own disk codec (`chunkCodec.ts`), undeflated -
 *    interned strings, fixed slots, already lossless for a row.
 *
 * Each is also checked for being lossless against the rows as dissected, and
 * a codec that loses something says how many rows and which keys.
 *
 * "forward" is what the coordinator would pay to pass the encoded batch on:
 * the clone of a string or a byte copy, which is what a store-bound
 * `postMessage` makes (a transfer list into the store's utilityProcess drops
 * the message, so it copies; the window's could transfer).
 *
 * A measurement with no right answer, so not a test (`check.ts` NOT_TESTS).
 */
import { readFileSync } from 'node:fs';
import { deserialize, serialize } from 'node:v8';
import { isDeepStrictEqual } from 'node:util';
import { PcapService } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { FrameClock, Sequencer } from '../../src/services/dissect/sequencer';
import { FrameDissector } from '../../src/services/pipeline/frameDissector';
import { applyPrefixes, decodeChunk, encodeChunk, type EncodedChunk } from '../../src/services/capture/chunkCodec';
import type { Packet } from '../../src/types/packet';

function arg(name: string): string | undefined {
  const at = process.argv.indexOf(name);
  return at > 0 ? process.argv[at + 1] : undefined;
}

const pcap = arg('--pcap');
if (!pcap) {
  console.log('usage: npx tsx scripts/perf/row-codec.ts --pcap some.pcapng [--frames 300000] [--batch 384]');
  process.exit(2);
}
const maxFrames = Number(arg('--frames') ?? 300_000);
const BATCH = Number(arg('--batch') ?? 384);
const NO_BYTES = new Uint8Array(0);

interface Codec {
  name: string;
  encode(rows: Packet[], capLengths: number[]): unknown;
  decode(encoded: unknown): Packet[];
  /** What a `postMessage` of the encoded batch would copy, as a clone. */
  forward(encoded: unknown): void;
  size(encoded: unknown): number;
}

const CODECS: Codec[] = [
  {
    name: 'clone',
    encode: (rows) => serialize(rows),
    decode: (encoded) => deserialize(encoded as Buffer) as Packet[],
    forward: () => { /* a clone is re-made per hop: that is encode again */ },
    size: (encoded) => (encoded as Buffer).byteLength,
  },
  {
    name: 'json',
    encode: (rows) => JSON.stringify(rows),
    decode: (encoded) => JSON.parse(encoded as string) as Packet[],
    forward: (encoded) => { deserialize(serialize(encoded)); },
    size: (encoded) => (encoded as string).length * 2,
  },
  {
    name: 'chunk',
    encode: (rows, capLengths) => encodeChunk(rows, capLengths),
    decode: (encoded) => {
      // The timestamp, addresses and ports are in the fixed-width prefix.
      const { prefix, summary } = encoded as EncodedChunk;
      const rows = decodeChunk(summary);
      applyPrefixes(rows, prefix);
      return rows;
    },
    forward: (encoded) => { (encoded as EncodedChunk).prefix.slice(); (encoded as EncodedChunk).summary.slice(); },
    size: (encoded) => (encoded as EncodedChunk).prefix.byteLength + (encoded as EncodedChunk).summary.byteLength,
  },
];

/** Rows as a shard posts them: tree left behind, bytes riding beside, not inside. */
async function dissect(): Promise<{ rows: Packet[]; capLengths: number[] }> {
  const file = new File([new Uint8Array(readFileSync(pcap!))], 'capture.pcapng');
  const { frames } = await PcapService.extractFrames(file, maxFrames);
  const clock = new FrameClock();
  const sequencer = new Sequencer();
  const dissector = new FrameDissector({
    tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
    dns: new DnsTracker(), l3: new L3Tracker(sequencer),
  }, undefined, null);
  const rows: Packet[] = [];
  const capLengths: number[] = [];
  frames.forEach((frame, i) => {
    const { relativeTime, timeDelta } = clock.fromNanos(frame.tsNanos);
    try {
      const { packet } = dissector.dissect({
        id: i + 1, bytes: frame.rawBytes, tsUs: Number(frame.tsNanos / 1000n), relativeTime, timeDelta,
        origLen: frame.origLen, linktype: frame.linktype,
        facts: { nanosRemainder: frame.tsPrecision > 6 ? Number(frame.tsNanos % 1000n) : undefined },
      });
      capLengths.push(packet.rawBytes.byteLength);
      packet.layers = [];
      packet.rawBytes = NO_BYTES;
      rows.push(packet);
    } catch { /* a frame that fails to dissect sends no row */ }
  });
  return { rows, capLengths };
}

function batches<T>(items: T[]): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += BATCH) out.push(items.slice(i, i + BATCH));
  return out;
}

/** Every key that differs between a row and its decoded copy. */
function differences(a: Packet, b: Packet): string[] {
  const out: string[] = [];
  for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const x = (a as unknown as Record<string, unknown>)[key];
    const y = (b as unknown as Record<string, unknown>)[key];
    if (isDeepStrictEqual(x, y)) continue;
    if (key === 'fields' && x && y) {
      for (const f of new Set([...Object.keys(x), ...Object.keys(y)])) {
        if (!isDeepStrictEqual((x as Record<string, unknown>)[f], (y as Record<string, unknown>)[f])) out.push(`fields.${f}`);
      }
    } else {
      out.push(key);
    }
  }
  if (out.length > 0) return out;
  // Equal value for value: a key one side holds as `undefined` and the other
  // leaves out, which no reader of a row can tell apart with `=== undefined`.
  const holes = [...new Set([...Object.keys(a), ...Object.keys(b)])]
    .filter((key) => (key in a) !== (key in b));
  return holes.length > 0 ? holes.map((key) => `${key}?`) : ['(prototype)'];
}

function time(fn: () => void): number {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

async function main(): Promise<void> {
  const { rows, capLengths } = await dissect();
  const tcp = rows.flatMap((row, i) => (row.frameProtocols?.includes('tcp') ? [i] : []));
  console.log(`${rows.length.toLocaleString()} rows from ${pcap}, ${tcp.length.toLocaleString()} of them TCP (a shard's)`);
  console.log(`batches of ${BATCH}; us a row, second pass of each\n`);

  for (const [label, pick] of [['all rows', null], ['TCP rows', tcp]] as const) {
    const set = pick === null ? rows : pick.map((i) => rows[i]);
    const lens = pick === null ? capLengths : pick.map((i) => capLengths[i]);
    const rowBatches = batches(set);
    const lenBatches = batches(lens);
    console.log(label);
    console.log('  codec   encode  decode  forward  B/row   today-path  lossless');
    for (const codec of CODECS) {
      let enc = 0;
      let dec = 0;
      let fwd = 0;
      let bytes = 0;
      let encoded: unknown[] = [];
      for (let pass = 0; pass < 2; pass++) {
        encoded = [];
        enc = time(() => { rowBatches.forEach((b, i) => encoded.push(codec.encode(b, lenBatches[i]))); });
        dec = time(() => { for (const e of encoded) codec.decode(e); });
        fwd = time(() => { for (const e of encoded) codec.forward(e); });
      }
      bytes = encoded.reduce<number>((n, e) => n + codec.size(e), 0);
      const us = (ms: number) => (ms * 1000) / set.length;
      // One encode, one forward to each of two receivers, and three decodes
      // (coordinator, window, store) - or, for clone, today's three
      // serializes and three deserializes.
      const path = codec.name === 'clone' ? 3 * us(enc) + 3 * us(dec) : us(enc) + 2 * us(fwd) + 3 * us(dec);

      let lost = 0;
      const where = new Map<string, number>();
      encoded.forEach((e, b) => {
        codec.decode(e).forEach((back, i) => {
          const original = rowBatches[b][i];
          // Bytes never ride in the codec, and JSON has no Uint8Array.
          back.rawBytes = NO_BYTES;
          if (!isDeepStrictEqual(back, original)) {
            lost++;
            for (const key of differences(original, back)) where.set(key, (where.get(key) ?? 0) + 1);
          }
        });
      });
      const top = [...where].sort((x, y) => y[1] - x[1]).slice(0, 4).map(([k, n]) => `${k} ${n}`).join(', ');
      console.log(`  ${codec.name.padEnd(6)} ${us(enc).toFixed(2).padStart(7)} ${us(dec).toFixed(2).padStart(7)} `
        + `${us(fwd).toFixed(2).padStart(8)} ${(bytes / set.length).toFixed(0).padStart(6)} ${path.toFixed(2).padStart(11)}  `
        + `${lost === 0 ? 'yes' : `no: ${lost} rows (${top})`}`);
    }
    console.log('');
  }
}

void main();
