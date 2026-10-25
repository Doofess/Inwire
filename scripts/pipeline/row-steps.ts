/**
 * The shard's row steps and the coordinator's merge from a side record equal
 * what the single Worker's `ingest` does (ADR 0053 phase 6,
 * `src/services/pipeline/rowSteps.ts`).
 *
 *   npx tsx scripts/pipeline/row-steps.ts [--burst some.pcapng]
 *
 * Path A is the single Worker: `annotatePacket`, `markLiveGap`,
 * `learnOrLabelFingerprint`, then `networkFacts.observe`, on one row in order.
 * Path B is the split: `shardRowSteps` and `rowSide` on a shard's copy, the row
 * packed and its side record structured-cloned, then `mergeRowSide` in merged
 * order (or the old steps on the decoded row when the side says `needsRow`),
 * and the overlay applied. The two must agree on every row's fields and
 * findings, on the Frame layer's rows, and on the facts the collector ends up
 * with. A synthetic set runs always; the fixtures' TCP rows and `--burst` run
 * when their files are present, with a socket table built from the capture's
 * own first flows. Only counts are printed.
 */
import { existsSync, readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { deserialize, serialize } from 'node:v8';
import { FlowAnnotationStore } from '../../src/services/flowAnnotations';
import { annotatePacket } from '../../src/services/dissect/processFields';
import { markLiveGap } from '../../src/services/dissect/liveGapFields';
import { ClientFingerprintStore, learnOrLabelFingerprint } from '../../src/services/dissect/clientFingerprints';
import { NetworkFactsCollector } from '../../src/services/networkFacts';
import { applyOverlay } from '../../src/services/pipeline/rowOverlay';
import { packRows, unpackRows } from '../../src/services/pipeline/rowPack';
import { mergeRowSide, rowSide, shardRowSteps, type RowSide } from '../../src/services/pipeline/rowSteps';
import { FrameDissector } from '../../src/services/pipeline/frameDissector';
import { PcapService } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { FrameClock, Sequencer } from '../../src/services/dissect/sequencer';
import { NO_HOST, type HostIdentity } from '../../src/services/direction';
import type { Packet, ProtocolField, ProtocolLayer } from '../../src/types/packet';
import { FIXTURES } from './arrival';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

type Table = Parameters<FlowAnnotationStore['apply']>[0];

/** One row to run, with the hole the live stream had before it. */
interface Input { packet: Packet; holeBefore?: number }

const NO_BYTES = new Uint8Array(0);
const BATCH = 384;

/** Key-for-key, treating a key held as `undefined` and one left out as the same. */
function norm(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value ?? null, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v)));
}

function frameRowsOf(layers: ProtocolLayer[]): ProtocolField[] {
  return layers.find((layer) => layer.name === 'Frame')?.fields ?? [];
}

/** Both paths over the same rows, in order, with the state each one keeps. */
class Comparison {
  private readonly annotationsA = new FlowAnnotationStore();
  private readonly annotationsB = new FlowAnnotationStore();
  private readonly fingerprintsA = new ClientFingerprintStore();
  private readonly fingerprintsB = new ClientFingerprintStore();
  readonly factsA = new NetworkFactsCollector();
  readonly factsB = new NetworkFactsCollector();
  /** The first row that differed, and how. */
  wrong: string | null = null;
  rows = 0;
  sides = 0;
  needsRow = 0;
  /** Every side record, by row id, for the checks on what a side holds. */
  readonly sideById = new Map<number, RowSide | undefined>();

  constructor(table: Table | null, private readonly host: HostIdentity, private readonly keepSides = false) {
    if (table !== null) {
      this.annotationsA.apply(table, 0);
      this.annotationsB.apply(table, 0);
    }
  }

  /** Rows are fed in batches, as a shard packs them; ids ascend. */
  feed(inputs: Input[]): void {
    for (let at = 0; at < inputs.length; at += BATCH) this.batch(inputs.slice(at, at + BATCH));
  }

  private batch(inputs: Input[]): void {
    const { host } = this;
    // A: the single Worker, on its own copy.
    const a = inputs.map(({ packet, holeBefore }) => {
      const p = structuredClone(packet);
      annotatePacket(p, this.annotationsA);
      if (holeBefore !== undefined) markLiveGap(p, holeBefore);
      learnOrLabelFingerprint(p.fields, this.fingerprintsA, p.layers);
      this.factsA.observe(p, host);
      return p;
    });

    // B, the shard: the steps on the tree, then the row leaves without it.
    const sides: (RowSide | undefined)[] = [];
    const trees: ProtocolField[][] = [];
    const rows = inputs.map(({ packet, holeBefore }) => {
      const p = structuredClone(packet);
      shardRowSteps(p, this.annotationsB, holeBefore);
      sides.push(rowSide(p, host));
      trees.push(frameRowsOf(p.layers));
      p.layers = [];
      p.rawBytes = NO_BYTES;
      return p;
    });
    const pack = deserialize(serialize(packRows(0, rows, rows.map(() => 0))));
    const sent = structuredClone(sides);
    const back = unpackRows(pack);

    // B, the coordinator: in merged order, a side or the old steps on the row.
    back.forEach((row, i) => {
      const side = sent[i];
      let frameRows: ProtocolField[] = [];
      if (side?.needsRow) {
        this.needsRow++;
        const stub: ProtocolLayer = { name: 'Frame', summary: '', fields: [] };
        learnOrLabelFingerprint(row.fields, this.fingerprintsB, [stub]);
        this.factsB.observe(row, host);
        frameRows = stub.fields;
      } else {
        const merged = mergeRowSide(side, { fingerprints: this.fingerprintsB, facts: this.factsB, host }, null);
        if (merged.overlay !== null) applyOverlay(row, merged.overlay);
        frameRows = merged.frameRows;
      }
      if (side !== undefined) this.sides++;
      if (this.keepSides) this.sideById.set(row.id, side);
      this.rows++;
      if (this.wrong !== null) return;
      const want = a[i];
      if (!isDeepStrictEqual(norm(row.fields), norm(want.fields))) this.wrong = `row ${row.id}: fields differ`;
      else if (!isDeepStrictEqual(norm(row.expert), norm(want.expert))) this.wrong = `row ${row.id}: findings differ`;
      else if (!isDeepStrictEqual(norm([...trees[i], ...frameRows]), norm(frameRowsOf(want.layers)))) {
        this.wrong = `row ${row.id}: the Frame layer's rows differ`;
      }
    });
  }
}

// ---------------------------------------------------------------------------
// The synthetic set: needs no fixture.

const T0 = 1_700_000_000 * 1_000_000;
const HOST_MAC = '02:00:00:00:00:01';
const GATEWAY_MAC = '02:00:00:00:00:fe';
const OTHER_MAC = '02:00:00:00:00:77';
const JA4 = 't13d1516h2_8daaf6152771_02713d6af862';
const HOST: HostIdentity = {
  macs: new Set([HOST_MAC]), addresses: new Set(['10.0.0.4']), inferred: false, confidence: 1,
};
const TABLE: Table = {
  full: true,
  procs: { 100: { name: 'chrome.exe', exe: 'C:/chrome.exe' }, 101: { name: 'curl.exe', exe: '' } },
  add: [['tcp', '10.0.0.4', 54321, 100], ['tcp', '10.0.0.4', 54322, 101]],
  gone: [],
};

interface RowSpec {
  sport?: number; dport?: number; dst?: string; srcMac?: string; dstMac?: string;
  protocols?: string[]; fields?: Record<string, string | number>; hole?: number;
}

let nextId = 1;
function synth(spec: RowSpec): Input {
  const id = nextId++;
  const dport = spec.dport ?? 443;
  const dst = spec.dst ?? '93.184.216.34';
  const fields: Record<string, string | number> = {
    'eth.src': spec.srcMac ?? HOST_MAC, 'eth.dst': spec.dstMac ?? GATEWAY_MAC,
    'ip.src': '10.0.0.4', 'ip.dst': dst, 'tcp.srcport': spec.sport ?? 50000, 'tcp.dstport': dport,
    ...spec.fields,
  };
  const packet = {
    id, tsUs: T0 + id, relativeTime: 0, timeDelta: 0, length: 66, caplen: 66,
    source: '10.0.0.4', destination: dst, sourcePort: spec.sport ?? 50000, destPort: dport,
    protocol: 'TCP', info: 'x', status: 'ok', rawBytes: NO_BYTES,
    layers: [{ name: 'Frame', summary: '', fields: [] }],
    frameProtocols: spec.protocols ?? ['eth', 'ethertype', 'ip', 'tcp'], fields,
  } as unknown as Packet;
  return { packet, holeBefore: spec.hole };
}

const TLS = ['eth', 'ethertype', 'ip', 'tcp', 'tls'];
const set: Input[] = [];
// A ClientHello on an annotated flow learns; the same JA4 on an unannotated one matches.
const learnHello = synth({ sport: 54321, protocols: TLS, hole: 5, fields: { 'tls.handshake.ja4': JA4, 'tls.stream': -3 } });
const matchHello = synth({ sport: 50000, protocols: TLS, fields: { 'tls.handshake.ja4': JA4 } });
set.push(learnHello, matchHello);
// An ARP reply naming the gateway, before the frames that promote it.
set.push(synth({
  protocols: ['eth', 'ethertype', 'arp'], srcMac: GATEWAY_MAC, dstMac: HOST_MAC, dst: '10.0.0.4',
  fields: { 'arp.opcode': 2, 'arp.src.proto_ipv4': '10.0.0.1', 'arp.src.hw_mac': GATEWAY_MAC },
}));
// Nine frames to a public address through one MAC: promoted at the eighth.
for (let i = 0; i < 9; i++) set.push(synth({ sport: 50100 + i, hole: i === 3 ? 5 : undefined }));
// DoT by port, DoH by name.
set.push(synth({ dport: 853, dst: '1.1.1.1', protocols: TLS }));
set.push(synth({ protocols: TLS, dst: '8.8.4.4', fields: { 'tls.handshake.extensions_server_name': 'dns.google' } }));
// DNS over TCP: the one that needs the full row.
const dnsOverTcp = synth({ dport: 53, dst: '8.8.8.8', protocols: ['eth', 'ethertype', 'ip', 'tcp', 'dns'] });
set.push(dnsOverTcp);
// A plain data segment of a conversation between two other machines.
const plain = synth({ srcMac: OTHER_MAC, dstMac: HOST_MAC, dst: '10.0.0.9' });
set.push(plain);
// An annotated flow with no hello, and a TLS data row with nothing to observe.
set.push(synth({ sport: 54322, protocols: TLS, srcMac: OTHER_MAC, dst: '10.0.0.9' }));

{
  const run = new Comparison(TABLE, HOST, true);
  run.feed(set);
  check(`synthetic: every row's fields, findings and Frame rows equal the single Worker's (${run.rows} rows)`,
    run.wrong === null, run.wrong ?? '');
  check('synthetic: the facts equal the single Worker\'s',
    isDeepStrictEqual(norm(run.factsB.snapshot()), norm(run.factsA.snapshot())),
    `${JSON.stringify(run.factsB.snapshot())} vs ${JSON.stringify(run.factsA.snapshot())}`);
  const facts = run.factsA.snapshot();
  check('...and they are not empty: a gateway with its address, a DoT and a DoH endpoint, a resolver',
    facts.gatewayMac === GATEWAY_MAC && facts.gatewayAddresses.includes('10.0.0.1')
    && facts.encryptedDns.length === 2 && facts.dnsServers.length === 1, JSON.stringify(facts));
  check('rowSide is undefined for a plain data segment', run.sideById.get(plain.packet.id) === undefined);
  check('a DNS-over-TCP row says it needs the full row', run.sideById.get(dnsOverTcp.packet.id)?.needsRow === true);
  const learnSide = run.sideById.get(learnHello.packet.id);
  check('an attributed hello carries its ja4, process, a placeholder stream and its forwarding MAC',
    learnSide?.ja4 === JA4 && learnSide.process === 'chrome.exe' && learnSide.tlsStream === -3
    && learnSide.forwardTo === GATEWAY_MAC, JSON.stringify(learnSide));
  const matchSide = run.sideById.get(matchHello.packet.id);
  check('an unattributed hello carries its ja4 and no process', matchSide?.ja4 === JA4 && matchSide.process === undefined);
  check('a hello with nothing to observe in TLS carries no tls facts', matchSide?.tls === undefined);
  check('only the DNS-over-TCP and ARP rows of the set went through the full path', run.needsRow === 2, `${run.needsRow}`);
}

// A decoded row has had the shard's steps; the decoded merge path must not repeat them.
{
  const store = new FlowAnnotationStore();
  store.apply(TABLE, 0);
  const { packet } = synth({ sport: 54321, protocols: TLS, fields: { 'tls.handshake.ja4': JA4 } });
  shardRowSteps(packet, store, 5);
  // What `emitMerged` does with a decoded shard row: no annotate, no gap mark.
  learnOrLabelFingerprint(packet.fields, new ClientFingerprintStore(), packet.layers);
  new NetworkFactsCollector().observe(packet, HOST);
  const count = (abbrev: string) => frameRowsOf(packet.layers).filter((f) => f.abbrev === abbrev).length;
  check('a decoded row gets exactly one Process row and one gap row, and one finding',
    count('inwire.process.name') === 1 && count('inwire.live.skipped') === 1 && packet.expert?.length === 1,
    `${count('inwire.process.name')} process, ${count('inwire.live.skipped')} gap, ${packet.expert?.length} findings`);
  annotatePacket(packet, store);
  check('...and the count is a real guard: annotating again would give two',
    count('inwire.process.name') === 2);
}

// ---------------------------------------------------------------------------
// The fixtures' TCP rows, and the burst: when present.

const MAX_TABLE = 50;

/** Every TCP row of a capture as the single Worker dissects it, with a hole before every 500th. */
function* tcpRows(frames: Awaited<ReturnType<typeof PcapService.extractFrames>>['frames'], host: HostIdentity): Generator<Input> {
  const clock = new FrameClock();
  const sequencer = new Sequencer();
  const dissector = new FrameDissector({
    tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
    dns: new DnsTracker(), l3: new L3Tracker(sequencer),
  }, undefined, null);
  dissector.host = host;
  let n = 0;
  for (let i = 0; i < frames.length; i++) {
    const frame = frames[i];
    const { relativeTime, timeDelta } = clock.fromNanos(frame.tsNanos);
    let packet: Packet;
    try {
      packet = dissector.dissect({
        id: i + 1, bytes: frame.rawBytes.slice(), tsUs: Number(frame.tsNanos / 1000n), relativeTime, timeDelta,
        origLen: frame.origLen, linktype: frame.linktype,
      }).packet;
    } catch { continue; }
    if (!packet.frameProtocols?.includes('tcp')) continue;
    yield { packet, holeBefore: ++n % 500 === 0 ? 3 : undefined };
  }
}

async function capture(name: string, bytes: Uint8Array): Promise<void> {
  const { frames } = await PcapService.extractFrames(new File([bytes], 'capture.pcap'), Number.POSITIVE_INFINITY);
  const host = PcapService.inferHostFromFrames(frames) ?? NO_HOST;
  // A socket table from the capture's own first flows, so attribution has something to do.
  const endpoints = new Map<string, [string, string, number, number]>();
  for (const { packet } of tcpRows(frames.slice(0, 8192), host)) {
    if (endpoints.size >= MAX_TABLE || packet.sourcePort === undefined) continue;
    const key = `${packet.source}|${packet.sourcePort}`;
    if (!endpoints.has(key)) endpoints.set(key, ['tcp', packet.source, packet.sourcePort, 1000 + endpoints.size]);
  }
  const procs: Table['procs'] = {};
  for (const entry of endpoints.values()) procs[String(entry[3])] = { name: `proc${entry[3]}.exe`, exe: '' };
  const run = new Comparison({ full: true, procs, add: [...endpoints.values()], gone: [] }, host);
  let batch: Input[] = [];
  for (const input of tcpRows(frames, host)) {
    batch.push(input);
    if (batch.length === BATCH) { run.feed(batch); batch = []; }
    if (run.wrong !== null) break;
  }
  run.feed(batch);
  if (run.rows === 0 && run.wrong === null) {
    console.log(`SKIP  ${name}: no TCP rows`);
    return;
  }
  check(`${name}: ${run.rows.toLocaleString()} TCP rows equal the single Worker's, fields, findings and Frame rows`,
    run.wrong === null, run.wrong ?? '');
  check(`${name}: the facts equal the single Worker's`,
    isDeepStrictEqual(norm(run.factsB.snapshot()), norm(run.factsA.snapshot())));
  console.log(`        ${endpoints.size} flows annotated, ${run.sides.toLocaleString()} rows with a side record,`
    + ` ${run.needsRow.toLocaleString()} needing the full row`);
}

async function main(): Promise<void> {
  for (const fixture of FIXTURES) {
    if (!existsSync(fixture.path)) {
      if (!fixture.optional) console.log(`SKIP  ${fixture.name}: ${fixture.path} is not present - see test/fixtures/README.md`);
      continue;
    }
    await capture(fixture.name, new Uint8Array(readFileSync(fixture.path)));
  }
  const burstAt = process.argv.indexOf('--burst');
  const burst = burstAt > 0 ? process.argv[burstAt + 1] : undefined;
  if (burst !== undefined) await capture('burst', new Uint8Array(readFileSync(burst)));
}

main().then(() => {
  console.log(failures === 0 ? '\nAll row-steps checks passed.' : `\n${failures} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
