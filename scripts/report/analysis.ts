/**
 * The report's analysis, held to answers computed another way, over real
 * captures.
 *
 *   npx tsx scripts/report/analysis.ts
 *
 * `CaptureAnalyzer` is what every figure in the PDF comes from, so this is
 * where a wrong number would be caught before it is printed. Four things are
 * asserted, each against a second source rather than against the analyser
 * itself:
 *
 *   - **Paging changes nothing.** An export feeds the analyser pages read off
 *     disk. The analysis of both captures, folded at several page sizes, must
 *     be JSON-identical to one pass over the whole array - including the odd
 *     sizes that split a conversation's first frame from its second.
 *   - **The counts are the capture's.** Totals, first and last time, the
 *     busiest second, the host count and the expert counts are each recomputed
 *     here from the frames directly, not through the analyser's folds.
 *   - **The signals agree with tshark.** Resets, retransmissions and DNS
 *     responses and errors are compared with tshark's own answer over the same
 *     fixture file. Skips cleanly without tshark.
 *   - **The caller's frames are untouched.** The analyser colours frames with
 *     an engine of its own, and that engine caches on the object it is given;
 *     every `colorSlot` must read the same after the analysis as before.
 *
 * And the redaction: an anonymised analysis must contain none of the capture's
 * real addresses and none of its names.
 *
 * Driven by the two real fixtures (ADR 0004) and never by frames built here.
 * Skips cleanly without them.
 */
import { useRepositoryWiresharkProfile } from '../wiresharkProfile';
import { spawnSync } from 'node:child_process';
import { CaptureAnalyzer, analyseCapture, type CaptureAnalysis } from '../../src/services/report/analysis';
import { redactAnalysis } from '../../src/services/report/redact';
import { Anonymiser } from '../../src/services/anonymise';
import {
  CATEGORY_ORDER, CATEGORY_RANK, EXPERT_RULE_ID, ExpertLog, buildExpertLog, categoryOfPacket,
} from '../../src/services/expertInfo';
import { Direction, directionOf } from '../../src/services/direction';
import { DEFAULT_COLOR_RULES } from '../../src/services/colorRules';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
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
    console.log(`        expected ${e.length > 400 ? `${e.slice(0, 400)}...` : e}`);
    console.log(`        actual   ${a.length > 400 ? `${a.slice(0, 400)}...` : a}`);
  }
}

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
  useRepositoryWiresharkProfile();
  for (const candidate of TSHARK_CANDIDATES) {
    const probe = spawnSync(candidate, ['-v'], { encoding: 'utf8', shell: false });
    if (probe.status === 0) return candidate;
  }
  return null;
}

/** Several fields per selected frame, tab-separated, one row per frame. */
function tsharkRows(tshark: string, file: string, filter: string, fields: string[]): string[][] {
  const run = spawnSync(tshark, ['-n', '-r', file, '-Y', filter, '-T', 'fields', '-E', 'occurrence=f',
    ...fields.flatMap((f) => ['-e', f])], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (run.status !== 0) throw new Error(`tshark failed on ${filter}: ${run.stderr}`);
  return run.stdout.split(/\r?\n/).filter((l) => l.length > 0).map((l) => l.split('\t'));
}

/** The frame numbers tshark selects with a display filter, one per line. */
function tsharkFrames(tshark: string, file: string, filter: string, field = 'frame.number'): string[] {
  const run = spawnSync(tshark, ['-n', '-r', file, '-Y', filter, '-T', 'fields', '-e', field], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  if (run.status !== 0) throw new Error(`tshark failed on ${filter}: ${run.stderr}`);
  return run.stdout.split(/\r?\n/).filter((l) => l.length > 0);
}

function paged(packets: readonly Packet[], size: number): CaptureAnalysis {
  const analyzer = new CaptureAnalyzer();
  for (let at = 0; at < packets.length; at += size) analyzer.addPage(packets.slice(at, at + size));
  return analyzer.finish();
}

function num(p: Packet, abbrev: string): number | undefined {
  const v = fieldValue(p, abbrev);
  return typeof v === 'number' ? v : undefined;
}

async function main() {
  const captures = await loadRealCaptures();
  const tshark = findTshark();
  if (tshark === null) console.log('SKIP  tshark not found - the tshark cross-checks are skipped (set TSHARK to its path).');

  check('every expert category names a colour rule that exists',
    CATEGORY_ORDER.filter((c) => !DEFAULT_COLOR_RULES.some((r) => r.id === EXPERT_RULE_ID[c])), []);

  for (const { name, path, packets } of captures) {
    const slotsBefore = packets.map((p) => p.colorSlot ?? null);
    const whole = analyseCapture(packets);
    check(`${name}: the caller's frames keep their colorSlot`, packets.map((p) => p.colorSlot ?? null), slotsBefore);

    const text = JSON.stringify(whole);
    for (const size of [1, 7, 500, 4096]) {
      check(`${name}: folded in pages of ${size} equals one pass`, JSON.stringify(paged(packets, size)) === text, true);
    }
    const oneByOne = new CaptureAnalyzer();
    for (const p of packets) oneByOne.add(p);
    check(`${name}: add() frame by frame equals addPage()`, JSON.stringify(oneByOne.finish()) === text, true);
    check(`${name}: a second run is identical`, JSON.stringify(analyseCapture(packets)) === text, true);

    // --- totals, straight off the frames
    check(`${name}: frames`, whole.frames, packets.length);
    check(`${name}: bytes`, whole.bytes, packets.reduce((s, p) => s + p.length, 0));
    check(`${name}: first frame time`, whole.firstUs, Math.min(...packets.map((p) => p.tsUs)));
    check(`${name}: last frame time`, whole.lastUs, Math.max(...packets.map((p) => p.tsUs)));
    check(`${name}: duration`, whole.durationSeconds, (whole.lastUs! - whole.firstUs!) / 1e6);
    check(`${name}: timeline conserves frames`, whole.timeline.bars.reduce((s, b) => s + b.frames, 0), packets.length);
    check(`${name}: size buckets conserve frames`, whole.sizes.counts.reduce((s, n) => s + n, 0), packets.length);

    const perSecond = new Map<number, { frames: number; bytes: number }>();
    for (const p of packets) {
      const s = Math.floor(p.relativeTime);
      const cell = perSecond.get(s) ?? { frames: 0, bytes: 0 };
      cell.frames += 1;
      cell.bytes += p.length;
      perSecond.set(s, cell);
    }
    const cells = [...perSecond.values()];
    check(`${name}: peak frames in one second`, whole.rates.peakFramesPerSecond, Math.max(...cells.map((c) => c.frames)));
    check(`${name}: peak bits in one second`, whole.rates.peakBitsPerSecond, Math.max(...cells.map((c) => c.bytes)) * 8);

    // --- hosts: every distinct address in an IPv4 or IPv6 header
    const addresses = new Set<string>();
    for (const p of packets) {
      const layers = p.frameProtocols ?? [];
      for (const [layer, src, dst] of [['ip', 'ip.src', 'ip.dst'], ['ipv6', 'ipv6.src', 'ipv6.dst']] as const) {
        if (!layers.includes(layer)) continue;
        const s = fieldValue(p, src);
        const d = fieldValue(p, dst);
        if (typeof s === 'string' && typeof d === 'string') {
          addresses.add(`${layer}|${s}`);
          addresses.add(`${layer}|${d}`);
        }
      }
    }
    check(`${name}: hosts is the distinct IPv4 and IPv6 address count`, whole.hosts, addresses.size);
    check(`${name}: ...and splits into the two endpoint tables`,
      whole.endpoints.ipv4.distinct + whole.endpoints.ipv6.distinct, addresses.size);

    // --- ranking: bytes, then frames, then the key, and nothing out of order
    const ordered = <T>(rows: T[], bytes: (r: T) => number, frames: (r: T) => number, key: (r: T) => string) =>
      rows.every((r, i) => i === 0 || (() => {
        const q = rows[i - 1];
        return bytes(q) > bytes(r) || (bytes(q) === bytes(r) && (frames(q) > frames(r)
          || (frames(q) === frames(r) && key(q) < key(r))));
      })());
    for (const kind of ['ipv4', 'ipv6'] as const) {
      const rows = whole.endpoints[kind].rows;
      check(`${name}: ${kind} endpoints ranked by bytes, frames, address`,
        ordered(rows, (e) => e.bytes, (e) => e.packets, (e) => e.address), true);
      check(`${name}: ${kind} endpoints keep the top ${rows.length}`, rows.length, Math.min(10, whole.endpoints[kind].distinct));
    }
    for (const kind of ['ipv4', 'ipv6', 'tcp', 'udp'] as const) {
      const rows = whole.conversations[kind].rows;
      check(`${name}: ${kind} conversations ranked by bytes, frames, key`,
        ordered(rows, (c) => c.bytes, (c) => c.packets, (c) => c.key), true);
    }
    // The biggest IPv4 endpoint, found without the analyser: its bytes are the
    // frames it sent plus the frames it received.
    const v4Bytes = new Map<string, number>();
    for (const p of packets) {
      if (!(p.frameProtocols ?? []).includes('ip')) continue;
      for (const f of ['ip.src', 'ip.dst']) {
        const v = fieldValue(p, f);
        if (typeof v === 'string') v4Bytes.set(v, (v4Bytes.get(v) ?? 0) + p.length);
      }
    }
    const topV4 = Math.max(...v4Bytes.values());
    check(`${name}: the top IPv4 endpoint carries the most bytes`, whole.endpoints.ipv4.rows[0]?.bytes, topV4);

    // --- expert: the log over the whole array
    const log = buildExpertLog(packets);
    check(`${name}: expert counts equal ExpertLog over the array`, whole.expert.counts, log.counts());
    check(`${name}: expert total`, whole.expert.total, log.size);
    check(`${name}: expert groups in the log's order`,
      whole.expert.groups.map((g) => [g.key, g.count]), log.groups().map((g) => [g.key, g.count]));

    // --- colour rules: the expert bands lead the chain, so each band's frames
    // are exactly the frames whose strongest category is that band's.
    check(`${name}: colour rules account for every frame`,
      whole.colorRules.reduce((s, r) => s + r.frames, 0) + whole.uncoloured, packets.length);
    for (const c of CATEGORY_ORDER) {
      const expected = packets.filter((p) => categoryOfPacket(p) === c).length;
      const got = whole.colorRules.find((r) => r.id === EXPERT_RULE_ID[c])?.frames ?? 0;
      check(`${name}: frames painted by the ${c} band`, got, expected);
    }

    // --- signals, from the frames
    const resets = packets.filter((p) => num(p, 'tcp.flags.reset') === 1);
    check(`${name}: TCP resets`, whole.signals.tcp.resets, resets.length);
    const retrans = packets.filter((p) => (p.analysisFlags ?? [])
      .some((f) => f === 'retransmission' || f === 'fast_retransmission' || f === 'spurious_retransmission'));
    check(`${name}: TCP retransmissions`, whole.signals.tcp.retransmissions, retrans.length);
    const dnsResponses = packets.filter((p) => (p.frameProtocols ?? []).includes('dns') && num(p, 'dns.flags.response') === 1);
    check(`${name}: DNS responses`, whole.signals.dns.responses, dnsResponses.length);
    const dnsErrors = dnsResponses.filter((p) => (num(p, 'dns.flags.rcode') ?? 0) !== 0);
    check(`${name}: DNS errors`, whole.signals.dns.errors, dnsErrors.length);
    check(`${name}: DNS errors by code sum to the errors`,
      whole.signals.dns.byRcode.reduce((s, r) => s + r.count, 0), whole.signals.dns.errors);

    if (tshark !== null) {
      const theirResets = tsharkFrames(tshark, path, 'tcp.flags.reset == 1');
      check(`${name}: resets match tshark`, whole.signals.tcp.resets, theirResets.length);
      check(`${name}: reset frames are tshark's frames`, resets.map((p) => String(p.id)), theirResets);
      // Keyed as the conversation table keys: the unordered pair of ends.
      const theirResetPairs = new Set(tsharkRows(tshark, path, 'tcp.flags.reset == 1',
        ['ip.src', 'ipv6.src', 'tcp.srcport', 'ip.dst', 'ipv6.dst', 'tcp.dstport'])
        .map(([s4, s6, sp, d4, d6, dp]) => {
          const a = `${s4 || s6}|${sp}`;
          const b = `${d4 || d6}|${dp}`;
          return a < b ? `${a}|${b}` : `${b}|${a}`;
        }));
      check(`${name}: reset conversations match tshark's address and port pairs`, whole.signals.tcp.resetConversations, theirResetPairs.size);
      // The encrypted shares, summed by tshark: a frame is QUIC if it has
      // QUIC in it, and TLS only if it has TLS and no QUIC.
      const sum = (filter: string) => tsharkFrames(tshark, path, filter, 'frame.len').reduce((t, v) => t + Number(v), 0);
      check(`${name}: QUIC bytes match tshark`, whole.signals.encrypted.quicBytes, sum('quic'));
      // TLS over TCP is NOT held to tshark, and the difference is measured
      // rather than hidden: tshark files a TCP segment that carries the middle
      // of a TLS record under `tls`, where Inwire's dissector leaves it `tcp`
      // (frame 2 of either fixture). That is a dissection-parity gap, owned by
      // parity/tree-coverage.ts, not a counting question; the count itself is
      // held to the frames below.
      const theirTls = sum('tls && !quic');
      console.log(`NOTE  ${name}: TLS-over-TCP bytes ${whole.signals.encrypted.tlsBytes} here, ${theirTls} by tshark's wider idea of a TLS frame`);
      const theirRetrans = tsharkFrames(tshark, path,
        'tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission');
      check(`${name}: retransmissions match tshark`, retrans.map((p) => String(p.id)), theirRetrans);
      const theirResponses = tsharkFrames(tshark, path, 'dns.flags.response == 1');
      check(`${name}: DNS responses match tshark`, whole.signals.dns.responses, theirResponses.length);
      const theirErrors = tsharkFrames(tshark, path, 'dns.flags.response == 1 && dns.flags.rcode != 0');
      check(`${name}: DNS error frames are tshark's frames`, dnsErrors.map((p) => String(p.id)), theirErrors);
    }

    const layerBytes = (test: (layers: string[]) => boolean) => packets
      .filter((p) => test(p.frameProtocols ?? [])).reduce((t, p) => t + p.length, 0);
    check(`${name}: QUIC bytes are the frames with QUIC in them`,
      whole.signals.encrypted.quicBytes, layerBytes((l) => l.includes('quic')));
    check(`${name}: TLS bytes are the frames with TLS and no QUIC`,
      whole.signals.encrypted.tlsBytes, layerBytes((l) => l.includes('tls') && !l.includes('quic')));
    check(`${name}: reset conversations never exceed TCP conversations`,
      whole.signals.tcp.resetConversations <= whole.conversations.tcp.distinct, true);
    check(`${name}: the encrypted shares count each frame once`,
      whole.signals.encrypted.tlsBytes + whole.signals.encrypted.quicBytes
        <= packets.filter((p) => (p.frameProtocols ?? []).some((t) => t === 'tls' || t === 'quic')).reduce((t, p) => t + p.length, 0),
      true);

    // --- the busiest remote host, found without the analyser: this machine's
    // addresses are the sources of what it sent, and a group address is
    // nobody's.
    const ours = new Set<string>();
    const traffic = new Map<string, { bytes: number; frames: number }>();
    for (const p of packets) {
      const layers = p.frameProtocols ?? [];
      const v = layers.includes('ip') ? ['ip.src', 'ip.dst'] : layers.includes('ipv6') ? ['ipv6.src', 'ipv6.dst'] : null;
      if (!v) continue;
      if (directionOf(p.direction) === Direction.Out) ours.add(p.source);
      for (const f of v) {
        const addr = fieldValue(p, f);
        if (typeof addr !== 'string') continue;
        const t = traffic.get(addr) ?? { bytes: 0, frames: 0 };
        t.bytes += p.length;
        t.frames += 1;
        traffic.set(addr, t);
      }
    }
    const group = (a: string) => (a.includes(':') ? /^ff/i.test(a) : a === '255.255.255.255' || (Number(a.split('.')[0]) >= 224 && Number(a.split('.')[0]) <= 239));
    const busiest = [...traffic].filter(([addr]) => !ours.has(addr) && !group(addr))
      .sort((x, y) => y[1].bytes - x[1].bytes || y[1].frames - x[1].frames || (x[0] < y[0] ? -1 : 1))[0];
    check(`${name}: the busiest remote host is the capture's`, whole.topRemote?.address, busiest?.[0]);

    // --- expert groups in a total order, and a log without per-frame state
    // that says the same
    const groups = whole.expert.groups;
    check(`${name}: expert groups are totally ordered`, groups.every((g, i) => i === 0 || (() => {
      const q = groups[i - 1];
      const byRank = CATEGORY_RANK[q.category] - CATEGORY_RANK[g.category];
      if (byRank !== 0) return byRank < 0;
      if (q.count !== g.count) return q.count > g.count;
      if (q.summary !== g.summary) return q.summary < g.summary;
      return q.protocol < g.protocol;
    })()), true);
    const lean = new ExpertLog(false);
    for (const p of packets) lean.add(p);
    check(`${name}: a log without per-frame state groups the same`, [lean.counts(), lean.groups()], [log.counts(), log.groups()]);
    check(`${name}: ...and remembers no frame`, packets.some((p) => lean.categoryOf(p.id) !== undefined), false);
    check(`${name}: the app's log still answers per frame`, packets.some((p) => log.categoryOf(p.id) !== undefined), true);

    check(`${name}: the timeline ends after the last second with a frame`,
      whole.timeline.end, Math.max(...packets.map((p) => Math.floor(p.relativeTime))) + 1);

    // --- redaction
    const redacted = redactAnalysis(whole, new Anonymiser());
    const redactedText = JSON.stringify(redacted);
    const real = new Set<string>([
      ...whole.endpoints.ipv4.rows.map((e) => e.address),
      ...whole.endpoints.ipv6.rows.map((e) => e.address),
      ...Object.values(whole.conversations).flatMap((r) => r.rows.flatMap((c) => [c.addressA, c.addressB])),
      ...whole.localAddresses,
      ...whole.names.map((n) => n.address),
    ]);
    // Group addresses are nobody's and are deliberately left as they are.
    const probe = new Anonymiser();
    const personal = [...real].filter((a) => probe.text(a) !== a);
    check(`${name}: the capture has real addresses to hide`, personal.length > 0, true);
    check(`${name}: no real address survives redaction`,
      personal.filter((a) => redactedText.includes(`"${a}"`)), []);
    check(`${name}: no resolved name survives redaction`,
      whole.names.map((n) => n.name).filter((n) => redactedText.includes(n)), []);
    check(`${name}: names are dropped`, redacted.names, []);
    const mapper = new Anonymiser();
    const mapped = redactAnalysis(whole, mapper);
    check(`${name}: the busiest remote host is chosen before redaction and then mapped`,
      mapped.topRemote?.address,
      busiest ? (busiest[0].includes(':') ? mapper.ipv6Address(busiest[0]) : mapper.ipv4Address(busiest[0])) : undefined);
    check(`${name}: redaction keeps the counts`,
      [redacted.frames, redacted.hosts, redacted.expert.counts, redacted.signals.tcp],
      [whole.frames, whole.hosts, whole.expert.counts, whole.signals.tcp]);
    check(`${name}: the same host maps the same way in two tables`,
      redacted.endpoints.ipv4.rows[0]?.address === redacted.conversations.ipv4.rows
        .flatMap((c) => [c.addressA, c.addressB])
        .find((a) => a === redacted.endpoints.ipv4.rows[0]?.address),
      true);

    // --- Anonymiser.text over the capture's own prose and addresses. The
    // fixtures raise no finding that names an address, so the dissector's own
    // wording for one (pcapParser.ts, the ARP conflict) carries a real one.
    const anonymiser = new Anonymiser();
    const messages = [...new Set(packets.flatMap((p) => (p.expert ?? []).map((e) => e.message)))];
    check(`${name}: prose with no address in it is left alone`,
      messages.filter((m) => anonymiser.text(m) !== m), []);
    const sample = personal.slice(0, 20);
    check(`${name}: an address inside a finding is mapped like the tables map it`,
      sample.map((a) => anonymiser.text(`Duplicate IP address configured (${a})`)),
      sample.map((a) => `Duplicate IP address configured (${a.includes(':') ? anonymiser.ipv6Address(a) : anonymiser.ipv4Address(a)})`));
    // The capture's own MACs, in the dashed spelling Windows uses.
    const macs = [...new Set(packets.map((p) => fieldValue(p, 'eth.src')).filter((m): m is string => typeof m === 'string'))]
      .filter((m) => (parseInt(m.slice(0, 2), 16) & 1) === 0).slice(0, 10);
    check(`${name}: a dashed MAC maps like the colon form, vendor half kept`,
      macs.map((m) => anonymiser.text(`adapter ${m.replace(/:/g, '-').toUpperCase()} up`)),
      macs.map((m) => `adapter ${anonymiser.mac(m).replace(/:/g, '-')} up`));
    check(`${name}: ...and never comes back unchanged`,
      macs.filter((m) => anonymiser.text(m.replace(/:/g, '-')) === m.replace(/:/g, '-')), []);
    const withExpert = packets.filter((p) => p.expert && p.expert.length > 0).slice(0, 200);
    check(`${name}: Anonymiser.packet runs every finding through text()`,
      withExpert.map((p) => anonymiser.packet(p).expert!.map((e) => e.message)),
      withExpert.map((p) => p.expert!.map((e) => anonymiser.text(e.message))));
  }

  // The one case no real capture can be: nothing at all.
  const empty = new CaptureAnalyzer().finish();
  check('empty: no frames, no times', [empty.frames, empty.bytes, empty.firstUs, empty.lastUs], [0, 0, null, null]);
  check('empty: no rates and no peak', empty.rates, {
    avgFramesPerSecond: 0, avgBitsPerSecond: 0, peakFramesPerSecond: 0, peakBitsPerSecond: 0, peakFramesAt: null, peakBitsAt: null,
  });
  check('empty: no bars', empty.timeline.bars.length, 0);

  console.log();
  if (failures > 0) {
    console.log(`${failures} assertion(s) FAILED`);
    process.exit(1);
  }
  console.log('All analysis assertions passed.');
  process.exit(0);
}

main().catch((err) => {
  console.log(`FAIL  analysis threw: ${err instanceof Error ? err.stack : String(err)}`);
  process.exit(1);
});
