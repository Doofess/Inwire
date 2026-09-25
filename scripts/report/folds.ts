/**
 * The report's folds, held to an answer computed somewhere else, over real
 * captures.
 *
 *   npx tsx scripts/report/folds.ts
 *
 * An export reads a capture off disk in pages and never holds it whole, so
 * every aggregate it prints is a fold: one frame at a time, answer at the end.
 *
 * ## The oracle is tshark, not the array functions
 *
 * `conversations()`, `endpoints()` and `protocolHierarchy()` are now thin
 * wrappers over the same fold classes, so comparing the two would compare a
 * class to itself. The conversation and endpoint tables are instead held to
 * tshark's own `-z conv,<kind>` and `-z endpoints,<kind>` over the same file,
 * and the protocol hierarchy to `-z io,phs` - numbers computed by a different
 * program from a different dissection. Each fold is driven in pages, the way
 * an export drives it, and read part-way through once, because `result()` must
 * hand back a copy that later frames do not change.
 *
 * tshark prints a conversation's **bytes** rounded to its own units (`158 kB`),
 * so bytes are compared by formatting ours the way Wireshark's `format_size`
 * does - integer division by 1000 while the result is at least 10 - and the
 * frame counts, which it prints exactly, carry the precision.
 *
 * Driven by the two real fixtures (ADR 0004) and never by frames built here:
 * a fold's failure modes are about the traffic - a conversation first seen in
 * its reverse direction, a hierarchy node first met under another parent, a
 * quiet stretch in the middle of a capture - and hand-built frames contain only
 * the cases their author thought of. Skips cleanly without the fixtures, and
 * skips the tshark comparisons cleanly without tshark.
 */
import { spawnSync } from 'node:child_process';
import {
  ConversationTable, EndpointTable, HierarchyFold,
  type Conversation, type ConversationKind, type Endpoint, type HierarchyNode, type ProtocolHierarchy,
} from '../../src/services/statistics';
import { SIZE_BUCKETS, SizeFold } from '../../src/services/report/sizeBuckets';
import { NICE_WIDTHS, TimelineFold, rebin, timelineIndex } from '../../src/services/report/timeline';
import { categoryOfPacket, isFaultCategory } from '../../src/services/expertInfo';
import { isoMicros, metaEntries, type CaptureMeta } from '../../src/services/export/captureMeta';
import { appVersion } from '../../src/lib/appVersion';
import type { Packet } from '../../src/types/packet';
import { loadRealCaptures } from '../export/realCaptures';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  const pass = a === e;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${e.length > 600 ? `${e.slice(0, 600)}...` : e}`);
    console.log(`        actual   ${a.length > 600 ? `${a.slice(0, 600)}...` : a}`);
  }
}

interface Fold<T> { add(p: Packet): void; result(): T }

/**
 * Folds `packets` in pages of `size`, taking a `result()` part-way through, and
 * says whether that mid-fold answer was left alone by everything added after.
 *
 * The mid-fold read is the part with teeth: a `result()` that returned the live
 * rows (or sorted the live tree) would pass a fold read only once at the end.
 */
function paged<T>(fold: Fold<T>, packets: readonly Packet[], size: number): { end: T; midUntouched: boolean } {
  const half = Math.floor(packets.length / 2);
  let mid: T | null = null;
  let midText = '';
  for (let at = 0; at < packets.length; at += size) {
    const page = packets.slice(at, at + size);
    for (const p of page) fold.add(p);
    if (mid === null && at + page.length >= half) {
      mid = fold.result();
      midText = JSON.stringify(mid);
    }
  }
  return { end: fold.result(), midUntouched: JSON.stringify(mid) === midText };
}

// --- tshark ------------------------------------------------------------------

/** Where tshark is: the same list as `parity/tree-coverage.ts`. */
const TSHARK_CANDIDATES = [
  process.env.TSHARK,
  'tshark',
  'C:\\Program Files\\Wireshark\\tshark.exe',
  'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
  '/usr/bin/tshark',
  '/usr/local/bin/tshark',
  '/opt/homebrew/bin/tshark',
].filter((p): p is string => typeof p === 'string' && p.length > 0);

function findTshark(): string | null {
  for (const candidate of TSHARK_CANDIDATES) {
    const probe = spawnSync(candidate, ['-v'], { encoding: 'utf8', shell: false });
    if (probe.status === 0) return candidate;
  }
  return null;
}

/** tshark's name for each kind, in `-z conv,<name>` and `-z endpoints,<name>`. */
const TSHARK_KIND: Record<ConversationKind, { tap: string; title: string; ported: boolean }> = {
  eth: { tap: 'eth', title: 'Ethernet', ported: false },
  ipv4: { tap: 'ip', title: 'IPv4', ported: false },
  ipv6: { tap: 'ipv6', title: 'IPv6', ported: false },
  tcp: { tap: 'tcp', title: 'TCP', ported: true },
  udp: { tap: 'udp', title: 'UDP', ported: true },
};
const KINDS: readonly ConversationKind[] = ['eth', 'ipv4', 'ipv6', 'tcp', 'udp'];

/**
 * A byte count as Wireshark's `format_size` prints it in these tables: in the
 * largest SI unit whose quotient is at least 10, by integer division - so
 * truncated, not rounded - and exact below 10,000 bytes.
 */
function wiresharkSize(bytes: number): string {
  const units = ['kB', 'MB', 'GB', 'TB'];
  for (let i = units.length - 1; i >= 0; i--) {
    const q = Math.floor(bytes / 1000 ** (i + 1));
    if (q >= 10) return `${q} ${units[i]}`;
  }
  return `${bytes} bytes`;
}

const SIZE = String.raw`(\d+ (?:bytes|kB|MB|GB|TB))`;

interface TsharkConversation {
  a: string; b: string;
  /** "->" in tshark's table. */
  aToB: number; aToBBytes: string;
  /** "<-". */
  bToA: number; bToABytes: string;
  frames: number; bytes: string;
  start: number; duration: number;
}

interface TsharkEndpoint {
  key: string;
  packets: number; bytes: string;
  tx: number; txBytes: string;
  rx: number; rxBytes: string;
}

/** Every `-z` table tshark printed, by its title line ("IPv4 Conversations"). */
function sections(output: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  let current: string[] | null = null;
  for (const line of output.split(/\r?\n/)) {
    if (/^(.+ (Conversations|Endpoints)|Protocol Hierarchy Statistics)$/.test(line)) {
      current = [];
      out.set(line, current);
    } else if (line.startsWith('====')) {
      current = null;
    } else if (current !== null) {
      current.push(line);
    }
  }
  return out;
}

const CONVERSATION_LINE = new RegExp(
  String.raw`^(\S+)\s+<->\s+(\S+)\s+(\d+)\s+${SIZE}\s+(\d+)\s+${SIZE}\s+(\d+)\s+${SIZE}\s+([\d.]+)\s+([\d.]+)\s*$`,
);

function parseConversations(lines: readonly string[]): TsharkConversation[] {
  const rows: TsharkConversation[] = [];
  for (const line of lines) {
    const m = CONVERSATION_LINE.exec(line);
    if (m === null) continue;
    rows.push({
      a: m[1], b: m[2],
      bToA: Number(m[3]), bToABytes: m[4],
      aToB: Number(m[5]), aToBBytes: m[6],
      frames: Number(m[7]), bytes: m[8],
      start: Number(m[9]), duration: Number(m[10]),
    });
  }
  return rows;
}

function parseEndpoints(lines: readonly string[], ported: boolean): TsharkEndpoint[] {
  const pattern = new RegExp(
    String.raw`^(\S+)\s+${ported ? String.raw`(\d+)\s+` : ''}(\d+)\s+${SIZE}\s+(\d+)\s+${SIZE}\s+(\d+)\s+${SIZE}\s*$`,
  );
  const rows: TsharkEndpoint[] = [];
  for (const line of lines) {
    const m = pattern.exec(line);
    if (m === null) continue;
    const key = ported ? `${m[1]}:${m[2]}` : m[1];
    const [packets, bytes, tx, txBytes, rx, rxBytes] = m.slice(ported ? 3 : 2);
    rows.push({
      key,
      packets: Number(packets), bytes,
      tx: Number(tx), txBytes,
      rx: Number(rx), rxBytes,
    });
  }
  return rows;
}

interface PhsNode { token: string; packets: number; bytes: number; children: PhsNode[] }

/** `-z io,phs`, as a tree built from its two-space indentation. */
function parseHierarchy(lines: readonly string[]): PhsNode[] {
  const roots: PhsNode[] = [];
  const stack: { depth: number; children: PhsNode[] }[] = [{ depth: -1, children: roots }];
  for (const line of lines) {
    const m = /^( *)(\S+)\s+frames:(\d+) bytes:(\d+)\s*$/.exec(line);
    if (m === null) continue;
    const depth = m[1].length / 2;
    const node: PhsNode = { token: m[2], packets: Number(m[3]), bytes: Number(m[4]), children: [] };
    while (stack[stack.length - 1].depth >= depth) stack.pop();
    stack[stack.length - 1].children.push(node);
    stack.push({ depth, children: node.children });
  }
  return roots;
}

/** An address and port as tshark joins them - `addr:port`, IPv6 unbracketed. */
const endKey = (address: string, port: number | undefined) => (port === undefined ? address : `${address}:${port}`);
const pairKey = (x: string, y: string) => (x < y ? `${x} <-> ${y}` : `${y} <-> ${x}`);

/** The first few entries of a list of mismatches - enough to act on. */
const few = (list: readonly string[]) => (list.length > 6 ? [...list.slice(0, 6), `...and ${list.length - 6} more`] : list);

function compareConversations(
  label: string, ours: readonly Conversation[], theirs: readonly TsharkConversation[],
): void {
  const mine = new Map(ours.map((c) => [pairKey(endKey(c.addressA, c.portA), endKey(c.addressB, c.portB)), c]));
  const reference = new Map(theirs.map((t) => [pairKey(t.a, t.b), t]));
  check(`${label}: as many conversations as tshark (${theirs.length})`, ours.length, theirs.length);
  check(`${label}: ...the same pairs`,
    few([...reference.keys()].filter((k) => !mine.has(k)).map((k) => `missing ${k}`)
      .concat([...mine.keys()].filter((k) => !reference.has(k)).map((k) => `extra ${k}`))), []);

  const frames: string[] = [];
  const bytes: string[] = [];
  const sides: string[] = [];
  const times: string[] = [];
  for (const [key, t] of reference) {
    const c = mine.get(key);
    if (c === undefined) continue;
    const a = endKey(c.addressA, c.portA);
    // Both take A from the first frame seen; compared anyway, and oriented to
    // tshark's A so a disagreement about A cannot hide one about counts.
    const flipped = a !== t.a;
    if (flipped) sides.push(`${key}: tshark's A is ${t.a}, ours ${a}`);
    const aToB = flipped ? c.packetsBtoA : c.packetsAtoB;
    const bToA = flipped ? c.packetsAtoB : c.packetsBtoA;
    const aToBBytes = flipped ? c.bytesBtoA : c.bytesAtoB;
    const bToABytes = flipped ? c.bytesAtoB : c.bytesBtoA;
    if (aToB !== t.aToB || bToA !== t.bToA || c.packets !== t.frames) {
      frames.push(`${key}: ours ${aToB}/${bToA}/${c.packets}, tshark ${t.aToB}/${t.bToA}/${t.frames}`);
    }
    const ourBytes = [wiresharkSize(aToBBytes), wiresharkSize(bToABytes), wiresharkSize(c.bytes)];
    if (ourBytes.join() !== [t.aToBBytes, t.bToABytes, t.bytes].join()) {
      bytes.push(`${key}: ours ${ourBytes.join(' / ')}, tshark ${t.aToBBytes} / ${t.bToABytes} / ${t.bytes}`);
    }
    // tshark prints the start to 9 places and the duration to 4. Exact: the
    // start is the pair's EARLIEST timestamp, not its first frame in capture
    // order, and the inwire fixture has a QUIC frame 14.5 ms older than one
    // that arrived ahead of it - the case that makes the two differ.
    if (Math.abs(c.startRel - t.start) > 1e-6 || Math.abs(c.duration - t.duration) > 5.01e-5) {
      times.push(`${key}: ours ${c.startRel.toFixed(6)} + ${c.duration.toFixed(4)}, tshark ${t.start} + ${t.duration}`);
    }
  }
  check(`${label}: frames each way and in total, row by row`, few(frames), []);
  check(`${label}: bytes each way and in total, as tshark prints them`, few(bytes), []);
  check(`${label}: A is the same end - the sender of the first frame`, few(sides), []);
  check(`${label}: relative start and duration`, few(times), []);
}

function compareEndpoints(
  label: string, ours: readonly Endpoint[], theirs: readonly TsharkEndpoint[],
): void {
  const mine = new Map(ours.map((e) => [endKey(e.address, e.port), e]));
  const reference = new Map(theirs.map((t) => [t.key, t]));
  check(`${label}: as many endpoints as tshark (${theirs.length})`, ours.length, theirs.length);
  check(`${label}: ...the same endpoints`,
    few([...reference.keys()].filter((k) => !mine.has(k)).map((k) => `missing ${k}`)
      .concat([...mine.keys()].filter((k) => !reference.has(k)).map((k) => `extra ${k}`))), []);
  const counts: string[] = [];
  const bytes: string[] = [];
  for (const [key, t] of reference) {
    const e = mine.get(key);
    if (e === undefined) continue;
    if (e.packets !== t.packets || e.packetsTx !== t.tx || e.packetsRx !== t.rx) {
      counts.push(`${key}: ours ${e.packets}/${e.packetsTx}/${e.packetsRx}, tshark ${t.packets}/${t.tx}/${t.rx}`);
    }
    const ourBytes = [wiresharkSize(e.bytes), wiresharkSize(e.bytesTx), wiresharkSize(e.bytesRx)];
    if (ourBytes.join() !== [t.bytes, t.txBytes, t.rxBytes].join()) {
      bytes.push(`${key}: ours ${ourBytes.join(' / ')}, tshark ${t.bytes} / ${t.txBytes} / ${t.rxBytes}`);
    }
  }
  check(`${label}: packets, sent and received, row by row`, few(counts), []);
  check(`${label}: bytes, sent and received, as tshark prints them`, few(bytes), []);
}

/**
 * How deep the hierarchy is compared: frame, link, network, transport.
 *
 * Above transport the two vocabularies stop lining up, by design on both
 * sides, so a comparison there would be a list of naming differences rather
 * than of wrong counts:
 *
 * - tshark adds a node per PDU - `tls` under `tls` for a frame carrying a
 *   second record, `quic` under `quic` for coalesced packets - where a
 *   `frameProtocols` chain names each layer once;
 * - tshark files undissected payload under `data`, and mDNS and LLMNR under
 *   their own names where Inwire's token is `dns`;
 * - Inwire nests the TLS handshake inside QUIC's CRYPTO frames as `tls` under
 *   `quic`, which tshark does not make a hierarchy node of.
 */
const HIERARCHY_DEPTH = 4;

/**
 * Tshark's tree, cut at `HIERARCHY_DEPTH`, with `_ws.malformed` removed.
 *
 * tshark files a frame whose dissection threw under a `_ws.malformed` node at
 * the layer that threw. On these fixtures that is 200 IPv6 frames with a
 * payload length of 0 - segmentation-offload frames the NIC had not yet split
 * ("IPv6 payload length equals 0 (maybe because of TCP segmentation offload)").
 * Inwire stops the chain at `ipv6` for the same frames, so both count them in
 * `ipv6` and neither in anything below it; the node is tshark's way of saying
 * so, not a protocol.
 */
function theirTree(nodes: readonly PhsNode[], depth = 1): PhsNode[] {
  return nodes
    .filter((n) => n.token !== '_ws.malformed')
    .map((n) => ({
      token: n.token, packets: n.packets, bytes: n.bytes,
      children: depth >= HIERARCHY_DEPTH ? [] : theirTree(n.children, depth + 1),
    }))
    .sort((x, y) => x.token.localeCompare(y.token));
}

/**
 * Ours, cut the same way, with IPv6 extension headers folded into `ipv6`.
 *
 * `frameProtocols` names an extension header as a layer of its own
 * (`ipv6:ipv6.hopopts:icmpv6`, the MLD reports); tshark dissects it inside
 * the IPv6 layer and makes no node of it, so what is under it is under `ipv6`.
 */
function ourTree(nodes: readonly HierarchyNode[], depth = 1): PhsNode[] {
  const spliced: HierarchyNode[] = [];
  for (const n of nodes) {
    if (n.token.startsWith('ipv6.')) spliced.push(...n.children);
    else spliced.push(n);
  }
  const merged = new Map<string, HierarchyNode>();
  for (const n of spliced) {
    const seen = merged.get(n.token);
    if (seen === undefined) merged.set(n.token, { ...n, children: [...n.children] });
    else {
      seen.packets += n.packets;
      seen.bytes += n.bytes;
      seen.children.push(...n.children);
    }
  }
  return [...merged.values()]
    .map((n) => ({
      token: n.token, packets: n.packets, bytes: n.bytes,
      children: depth >= HIERARCHY_DEPTH ? [] : ourTree(n.children, depth + 1),
    }))
    .sort((x, y) => x.token.localeCompare(y.token));
}

function flatten(nodes: readonly PhsNode[], path = ''): string[] {
  return nodes.flatMap((n) => {
    const here = path ? `${path}:${n.token}` : n.token;
    return [`${here} ${n.packets} frames ${n.bytes} bytes`, ...flatten(n.children, here)];
  });
}

// --- Pure edge cases no real capture can express -----------------------------

console.log('--- empty input ---\n');
check('an empty timeline rebins to no bars', rebin(new TimelineFold()), { width: 1, bars: [], frames: 0, bytes: 0 });
check('an empty hierarchy', new HierarchyFold().result(), { roots: [], packets: 0, bytes: 0 });
check('appVersion() under tsx is "dev" - no define ran', appVersion(), 'dev');
check('isoMicros is total: a timestamp no Date can hold prints raw', isoMicros(9e21), '9e+21 µs since 1970 (out of range)');

const captures = await loadRealCaptures();
if (captures.length === 0) {
  console.log('\nSKIP  no real captures present; the fold checks need them');
  process.exit(failures ? 1 : 0);
}

const tshark = findTshark();
if (tshark === null) {
  console.log('\nSKIP  tshark not found - set TSHARK to its path; conversations, endpoints and the hierarchy go unchecked');
}

for (const { name, path, packets } of captures) {
  console.log(`\n=== ${name}: ${packets.length.toLocaleString('en-US')} frames ===\n`);

  // --- statistics.ts, against tshark -----------------------------------------

  const folded = new Map<ConversationKind, { conversations: Conversation[]; endpoints: Endpoint[] }>();
  for (const kind of KINDS) {
    const c = paged(new ConversationTable(kind), packets, 4096);
    const e = paged(new EndpointTable(kind), packets, 4096);
    check(`${name} ${kind}: a conversation read mid-fold is not changed by later frames`, c.midUntouched, true);
    check(`${name} ${kind}: an endpoint read mid-fold is not changed by later frames`, e.midUntouched, true);
    folded.set(kind, { conversations: c.end, endpoints: e.end });
  }
  const hierarchy = paged(new HierarchyFold(), packets, 4096);
  check(`${name}: a hierarchy read mid-fold is not changed by later frames`, hierarchy.midUntouched, true);
  const tree: ProtocolHierarchy = hierarchy.end;

  if (tshark !== null) {
    const args = ['-n', '-r', path, '-q'];
    for (const kind of KINDS) args.push('-z', `conv,${TSHARK_KIND[kind].tap}`, '-z', `endpoints,${TSHARK_KIND[kind].tap}`);
    args.push('-z', 'io,phs');
    const run = spawnSync(tshark, args, { encoding: 'utf8', maxBuffer: 1 << 28 });
    if (run.status !== 0) throw new Error(`tshark exited ${run.status}: ${run.stderr}`);
    const tables = sections(run.stdout);

    for (const kind of KINDS) {
      const { title, ported } = TSHARK_KIND[kind];
      const convLines = tables.get(`${title} Conversations`);
      const endLines = tables.get(`${title} Endpoints`);
      if (convLines === undefined || endLines === undefined) {
        check(`${name} ${kind}: tshark printed both tables`, false, true);
        continue;
      }
      const theirs = parseConversations(convLines);
      check(`${name} ${kind}: tshark's table parsed whole`,
        theirs.length, convLines.filter((l) => l.includes('<->')).length);
      const mine = folded.get(kind)!;
      compareConversations(`${name} ${kind} conversations`, mine.conversations, theirs);
      const theirEnds = parseEndpoints(endLines, ported);
      check(`${name} ${kind}: tshark's endpoint table parsed whole`,
        theirEnds.length, endLines.filter((l) => /\d+ (bytes|kB|MB|GB|TB)\s*$/.test(l)).length);
      compareEndpoints(`${name} ${kind} endpoints`, mine.endpoints, theirEnds);
    }

    const phs = tables.get('Protocol Hierarchy Statistics');
    if (phs === undefined) {
      check(`${name}: tshark printed the protocol hierarchy`, false, true);
    } else {
      const theirs = parseHierarchy(phs);
      const theirFrame = theirs.find((n) => n.token === 'frame');
      check(`${name}: the hierarchy's total is tshark's frame node`,
        [tree.packets, tree.bytes], [theirFrame?.packets, theirFrame?.bytes]);
      check(`${name}: the hierarchy to the transport layer is tshark's, node for node`,
        flatten(ourTree(tree.roots)), flatten(theirTree(theirs)));
    }
  }

  // --- sizeBuckets.ts --------------------------------------------------------

  // The old chart's inclusive-range loop, run directly over the capture.
  const direct = new Array<number>(SIZE_BUCKETS.length).fill(0);
  for (const p of packets) {
    for (let i = 0; i < SIZE_BUCKETS.length; i++) {
      if (p.length >= SIZE_BUCKETS[i].min && p.length <= SIZE_BUCKETS[i].max) { direct[i] += 1; break; }
    }
  }
  const sizes = paged(new SizeFold(), packets, 4096).end;
  check(`${name} size buckets equal a direct count`, sizes.counts, direct);
  check(`${name} size buckets hold every frame`, sizes.counts.reduce((a, b) => a + b, 0), packets.length);
  check(`${name} size fold total`, sizes.total, packets.length);
  check(`${name} uses more than one bucket (the check can see a boundary)`,
    sizes.counts.filter((n) => n > 0).length > 1, true);

  // --- timeline.ts -----------------------------------------------------------

  const timeline = new TimelineFold();
  for (const p of packets) timeline.add(p);
  const bytes = packets.reduce((a, p) => a + p.length, 0);
  const faults = packets.filter((p) => isFaultCategory(categoryOfPacket(p))).length;
  const firstSecond = Math.min(...timeline.seconds.keys());
  const lastSecond = Math.max(...timeline.seconds.keys());
  const span = lastSecond - firstSecond + 1;
  console.log(`        (${span} s spanned, ${timeline.seconds.size} seconds with traffic, ${faults} fault frames)`);

  for (const maxBars of [1, 2, 7, 30, 120, 600]) {
    const t = rebin(timeline, maxBars);
    check(`${name} rebin(${maxBars}): within maxBars`, t.bars.length <= maxBars, true);
    check(`${name} rebin(${maxBars}): conserves frames`, t.bars.reduce((a, b) => a + b.frames, 0), packets.length);
    check(`${name} rebin(${maxBars}): conserves bytes`, t.bars.reduce((a, b) => a + b.bytes, 0), bytes);
    check(`${name} rebin(${maxBars}): conserves fault frames`, t.bars.reduce((a, b) => a + b.faults, 0), faults);
    check(`${name} rebin(${maxBars}): bars are contiguous`,
      t.bars.every((b, i) => b.start === firstSecond + i * t.width), true);
    const nice = NICE_WIDTHS.includes(t.width) || t.width % 3600 === 0;
    check(`${name} rebin(${maxBars}): width ${t.width} s is a nice width`, nice, true);
    // The narrowest that fits: one step finer would have needed more bars.
    const i = NICE_WIDTHS.indexOf(t.width);
    const finer = i > 0 ? NICE_WIDTHS[i - 1] : i === -1 ? t.width - 3600 : 0;
    check(`${name} rebin(${maxBars}): the next finer width would not fit`,
      finer <= 0 || Math.ceil(span / finer) > maxBars, true);
  }
  check(`${name} the default rebin draws at most 120 bars`, rebin(timeline).bars.length <= 120, true);

  // The chart keys its map on `timelineIndex`; it must still be the floor it
  // replaced, at the chart's own interval choices.
  for (const width of [0.1, 1, 5, 60]) {
    check(`${name} timelineIndex at ${width} s is the chart's old floor`,
      packets.every((p) => timelineIndex(p.relativeTime, width) === Math.floor(p.relativeTime / width)), true);
  }

  // --- captureMeta.ts --------------------------------------------------------

  const meta: CaptureMeta = {
    app: 'Inwire', version: appVersion(), os: null, generatedAt: Date.UTC(2026, 8, 25, 12, 0, 0),
    source: { kind: 'import', fileName: `${name}.pcap` },
    firstUs: packets[0].tsUs, lastUs: packets[packets.length - 1].tsUs,
    frames: { exported: packets.length, inCapture: packets.length, unreadable: 0 },
    drops: { kernel: null, agent: null, pipe: null },
    scope: 'capture', filter: '',
    flags: { anonymised: false, rawBytes: true, fields: true, secrets: false },
  };
  const first = metaEntries(meta);
  const zone = process.env.TZ;
  process.env.TZ = 'Pacific/Chatham';
  const elsewhere = metaEntries(meta);
  process.env.TZ = zone;
  check(`${name} metaEntries is deterministic`, metaEntries(meta), first);
  check(`${name} metaEntries does not depend on the time zone`, elsewhere, first);
  const value = (key: string) => first.find(([k]) => k === key)?.[1];
  check(`${name} frames exported in en-US`, value('Frames exported'), packets.length.toLocaleString('en-US'));
  check(`${name} first frame is UTC with six digits`, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/.test(value('First frame') ?? ''), true);
  check(`${name} null drops read "not available", never 0`,
    ['Dropped by the driver', 'Dropped by the agent', 'Dropped on the pipe'].map(value),
    ['not available', 'not available', 'not available']);
  const known = metaEntries({ ...meta, drops: { kernel: 0, agent: 1234, pipe: null } });
  check(`${name} a real zero is still printed as 0, a real count in en-US`,
    ['Dropped by the driver', 'Dropped by the agent', 'Dropped on the pipe']
      .map((k) => known.find(([key]) => key === k)?.[1]),
    ['0', '1,234', 'not available']);
  const filtered = metaEntries({ ...meta, scope: 'filtered', filter: 'tcp.port == 443' });
  check(`${name} a filtered export names its filter`,
    filtered.find(([k]) => k === 'Display filter')?.[1], 'tcp.port == 443');
  check(`${name} a whole-capture export has no filter row`,
    first.some(([k]) => k === 'Display filter'), false);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All fold checks passed.');
process.exit(0);
