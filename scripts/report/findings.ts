/**
 * The report's findings: deterministic, and every number in them is the
 * analysis's own.
 *
 *   npx tsx scripts/report/findings.ts
 *
 * A finding is the sentence a reader acts on, so the thing to rule out is a
 * sentence whose number came from somewhere else - a stale variable, a share
 * of the wrong total, a count rounded into a different one. Each finding's
 * text is taken apart here: every figure the rule should print must be in it,
 * formatted from the analysis, and every figure in it must be one of those.
 * The headline counts are then recomputed from the frames themselves.
 *
 * Deterministic twice over: two runs agree, and so does a run in a child
 * process under a different time zone and locale, because a report written in
 * Kathmandu must say what the same report written in London says.
 *
 * Driven by the two real fixtures (ADR 0004). The empty capture and the drop
 * counters are the exceptions and are literal inputs, because no capture on
 * disk can be empty and a fixture file carries no drop counters at all.
 */
import { spawnSync } from 'node:child_process';
import { Anonymiser } from '../../src/services/anonymise';
import { redactAnalysis } from '../../src/services/report/redact';
import { Direction, directionOf } from '../../src/services/direction';
import { fileURLToPath } from 'node:url';
import { analyseCapture, type CaptureAnalysis } from '../../src/services/report/analysis';
import { findings, rcodeName, type Finding } from '../../src/services/report/findings';
import {
  bitRate, bytes, count, duration, frameRate, offset, percent, plural,
} from '../../src/services/report/format';
import type { CaptureMeta, DropCounts } from '../../src/services/export/captureMeta';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import { loadRealCaptures } from '../export/realCaptures';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  const pass = a === e;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${e.length > 500 ? `${e.slice(0, 500)}...` : e}`);
    console.log(`        actual   ${a.length > 500 ? `${a.slice(0, 500)}...` : a}`);
  }
}

function metaFor(a: CaptureAnalysis, drops: DropCounts, source: CaptureMeta['source']): CaptureMeta {
  return {
    app: 'Inwire', version: 'dev', os: null, generatedAt: 0, source,
    firstUs: a.firstUs, lastUs: a.lastUs,
    frames: { exported: a.frames, inCapture: a.frames, unreadable: 0 },
    drops, scope: 'capture', filter: '',
    flags: { anonymised: false, rawBytes: false, fields: false, secrets: false },
  };
}

const NO_DROPS: DropCounts = { kernel: null, agent: null, pipe: null };

/**
 * Every figure a finding should print, formatted from the analysis. The test
 * holds the text to this list in both directions.
 */
function expectedFigures(f: Finding, a: CaptureAnalysis): string[] | null {
  const s = a.signals;
  const c = a.expert.counts;
  switch (f.id) {
    case 'overview':
      return [plural(a.frames, 'frame'), bytes(a.bytes), duration(a.durationSeconds),
        frameRate(a.rates.avgFramesPerSecond), bitRate(a.rates.avgBitsPerSecond),
        plural(a.rates.peakFramesPerSecond, 'frame'), bitRate(a.rates.peakBitsPerSecond)];
    case 'drops':
      return [];
    case 'capture-gap':
      return [plural(c.CaptureGap, 'finding')];
    case 'broken':
      return [plural(c.Broken, 'finding')];
    case 'unverifiable':
      return [plural(c.Unverifiable, 'finding')];
    case 'resets':
      return [plural(s.tcp.resets, 'TCP reset'), plural(s.tcp.resetConversations, 'conversation'),
        percent(s.tcp.resetConversations, a.conversations.tcp.distinct), count(a.conversations.tcp.distinct)];
    case 'retransmissions':
      return s.tcp.retransmissions === 0
        ? [plural(s.tcp.frames, 'TCP frame')]
        : [plural(s.tcp.retransmissions, 'TCP retransmission'), percent(s.tcp.retransmissions, s.tcp.frames),
          ...(s.tcp.fastRetransmissions > 0 ? [`${count(s.tcp.fastRetransmissions)} fast`] : []),
          ...(s.tcp.spuriousRetransmissions > 0 ? [`${count(s.tcp.spuriousRetransmissions)} spurious`] : [])];
    case 'dns-errors':
      return s.dns.errors > 0
        ? [count(s.dns.errors), plural(s.dns.responses, 'DNS response'),
          ...s.dns.byRcode.map((r) => `${rcodeName(r.rcode)} ${count(r.count)}`)]
        : [plural(s.dns.responses, 'DNS response')];
    case 'top-host': {
      const host = a.topRemote;
      return host ? [` ${host.address}`, percent(host.bytes, a.ip.bytes), bytes(host.bytes)] : ['(no host named)'];
    }
    case 'top-conversation': {
      const conv = [...a.conversations.tcp.rows.slice(0, 1), ...a.conversations.udp.rows.slice(0, 1)]
        .sort((x, y) => y.bytes - x.bytes || y.packets - x.packets)[0];
      return [`${conv.addressA} port ${conv.portA}`, `${conv.addressB} port ${conv.portB}`,
        percent(conv.bytes, a.bytes), bytes(conv.bytes), duration(conv.duration)];
    }
    case 'encryption':
      return [
        ...(s.encrypted.tlsBytes > 0 ? [`${percent(s.encrypted.tlsBytes, a.bytes)} TLS over TCP`] : []),
        ...(s.encrypted.quicBytes > 0 ? [`${percent(s.encrypted.quicBytes, a.bytes)} QUIC`] : []),
      ];
    case 'dns-privacy':
      return [
        ...(s.dns.port53Frames > 0 ? [plural(s.dns.port53Frames, 'frame'), 'port 53'] : []),
        ...(s.encrypted.dotFrames > 0 ? [plural(s.encrypted.dotFrames, 'frame')] : []),
        ...s.encrypted.dohResolvers.map((n) => `"${n}"`),
      ];
    case 'broadcast':
      return [percent(s.broadcastFrames, a.frames), percent(s.multicastFrames, a.frames)];
    case 'cleartext':
      return s.cleartext.map((u) => `${u.label} (${plural(u.frames, 'frame')})`);
    case 'duplicates':
      return [plural(s.duplicateFrames, 'frame')];
    default:
      return null;
  }
}

/**
 * The numbers in a sentence, once the parts that are text rather than figures
 * are taken out: quoted names and summaries, and addresses.
 */
function figuresIn(text: string): string[] {
  const stripped = text
    .replace(/"[^"]*"/g, ' ')
    .replace(/\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b/gi, ' ')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, ' ')
    .replace(/\bport \d+\b/g, ' ')
    .replace(/\bTLSv1\.\d\b/g, ' ');
  return stripped.match(/\d[\d,]*(?:\.\d+)?/g) ?? [];
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
  for (const candidate of TSHARK_CANDIDATES) {
    if (spawnSync(candidate, ['-v'], { encoding: 'utf8', shell: false }).status === 0) return candidate;
  }
  return null;
}

/**
 * The largest TCP or UDP conversation by bytes, as tshark counts it: every
 * frame's length summed per stream, the stream named by its first frame's
 * ends. A different program's dissection and a different grouping from the
 * analyser's, which is what makes it a check.
 */
function tsharkLargestConversation(tshark: string, file: string): { a: string; pa: string; b: string; pb: string; bytes: number } {
  let best = { a: '', pa: '', b: '', pb: '', bytes: -1 };
  for (const proto of ['tcp', 'udp']) {
    const run = spawnSync(tshark, ['-n', '-r', file, '-Y', proto, '-T', 'fields', '-E', 'occurrence=f',
      '-e', `${proto}.stream`, '-e', 'frame.len', '-e', 'ip.src', '-e', 'ipv6.src', '-e', `${proto}.srcport`,
      '-e', 'ip.dst', '-e', 'ipv6.dst', '-e', `${proto}.dstport`], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    const streams = new Map<string, { a: string; pa: string; b: string; pb: string; bytes: number }>();
    for (const line of run.stdout.split(/\r?\n/)) {
      if (!line) continue;
      const [stream, len, s4, s6, sp, d4, d6, dp] = line.split('\t');
      const entry = streams.get(stream) ?? { a: s4 || s6, pa: sp, b: d4 || d6, pb: dp, bytes: 0 };
      entry.bytes += Number(len);
      streams.set(stream, entry);
    }
    for (const e of streams.values()) if (e.bytes > best.bytes) best = e;
  }
  return best;
}

async function emit(): Promise<void> {
  const out: Record<string, Finding[]> = {};
  for (const { name, packets } of await loadRealCaptures()) {
    const a = analyseCapture(packets);
    out[name] = findings(a, metaFor(a, NO_DROPS, { kind: 'import', fileName: name }));
  }
  process.stdout.write(`${JSON.stringify(out)}\n`);
}

async function main() {
  const captures = await loadRealCaptures();
  const mine: Record<string, Finding[]> = {};
  const tshark = findTshark();
  if (tshark === null) console.log('SKIP  tshark not found - the largest-conversation cross-check is skipped.');

  for (const { name, path, packets } of captures) {
    const a = analyseCapture(packets);
    const meta = metaFor(a, NO_DROPS, { kind: 'import', fileName: name });
    const list = findings(a, meta);
    mine[name] = list;
    check(`${name}: two runs agree`, findings(analyseCapture(packets), meta), list);
    check(`${name}: ids are unique`, new Set(list.map((f) => f.id)).size, list.length);
    check(`${name}: the overview leads`, list[0]?.id, 'overview');
    const tones = list.slice(1).map((f) => ({ fault: 0, notice: 1, info: 2 })[f.tone]);
    check(`${name}: then faults, notices, context`, tones.every((t, i) => i === 0 || tones[i - 1] <= t), true);

    for (const f of list) {
      const expected = expectedFigures(f, a);
      if (expected === null) {
        check(`${name}: finding "${f.id}" is one this test knows`, f.id, '(a known id)');
        continue;
      }
      check(`${name}: "${f.id}" prints every figure it should`, expected.filter((e) => !f.text.includes(e)), []);
      const allowed = expected.join(' ');
      check(`${name}: "${f.id}" prints no figure it should not`, figuresIn(f.text).filter((n) => !allowed.includes(n)), []);
    }

    // The headline counts, recomputed from the frames rather than read back.
    const resets = packets.filter((p) => fieldValue(p, 'tcp.flags.reset') === 1).length;
    const resetFinding = list.find((f) => f.id === 'resets');
    check(`${name}: the reset finding counts the capture's resets`,
      resets === 0 ? resetFinding === undefined : resetFinding?.text.startsWith(`${plural(resets, 'TCP reset')} `), true);
    const retrans = packets.filter((p) => (p.analysisFlags ?? []).some((x) => x.endsWith('retransmission'))).length;
    const tcpFrames = packets.filter((p) => (p.frameProtocols ?? []).includes('tcp')).length;
    const retransFinding = list.find((f) => f.id === 'retransmissions');
    check(`${name}: the retransmission finding counts the capture's retransmissions`,
      retransFinding?.text.startsWith(retrans === 0 ? 'No TCP retransmissions' : `${plural(retrans, 'TCP retransmission')}, ${percent(retrans, tcpFrames)} `), true);
    // The busiest host that is not this machine, found from the frames: this
    // machine's addresses are the sources of what it sent, a group address
    // is nobody's, and a host's bytes are what it sent plus what it received.
    const ours = new Set(packets.filter((p) => directionOf(p.direction) === Direction.Out).map((p) => p.source));
    const traffic = new Map<string, { bytes: number; frames: number }>();
    for (const p of packets) {
      const layers = p.frameProtocols ?? [];
      const fields = layers.includes('ip') ? ['ip.src', 'ip.dst'] : layers.includes('ipv6') ? ['ipv6.src', 'ipv6.dst'] : [];
      for (const f of fields) {
        const addr = fieldValue(p, f);
        if (typeof addr !== 'string') continue;
        const t = traffic.get(addr) ?? { bytes: 0, frames: 0 };
        t.bytes += p.length;
        t.frames += 1;
        traffic.set(addr, t);
      }
    }
    const isGroup = (x: string) => (x.includes(':') ? /^ff/i.test(x)
      : x === '255.255.255.255' || (Number(x.split('.')[0]) >= 224 && Number(x.split('.')[0]) <= 239));
    const [busiest] = [...traffic].filter(([x]) => !ours.has(x) && !isGroup(x))
      .sort((x, y) => y[1].bytes - x[1].bytes || y[1].frames - x[1].frames || (x[0] < y[0] ? -1 : 1))[0] ?? [];
    const hostText = list.find((f) => f.id === 'top-host')?.text ?? '';
    check(`${name}: the top-host finding names the busiest non-local host`,
      busiest !== undefined && (hostText.includes(` ${busiest},`) || hostText.includes(` ${busiest} (`)), true);
    const anonymiser = new Anonymiser();
    const redacted = findings(redactAnalysis(a, anonymiser), { ...meta, flags: { ...meta.flags, anonymised: true } });
    const pseudonym = busiest === undefined ? '' : busiest.includes(':') ? anonymiser.ipv6Address(busiest) : anonymiser.ipv4Address(busiest);
    check(`${name}: anonymised, it names the same host's pseudonym`,
      redacted.find((f) => f.id === 'top-host')?.text.startsWith(`The busiest remote host was ${pseudonym},`), true);

    if (tshark !== null) {
      const theirs = tsharkLargestConversation(tshark, path);
      const text = list.find((f) => f.id === 'top-conversation')?.text ?? '';
      const ends = [`${theirs.a} port ${theirs.pa}`, `${theirs.b} port ${theirs.pb}`];
      check(`${name}: the largest conversation is tshark's`, ends.every((e) => text.includes(e)), true);
      check(`${name}: ...with tshark's byte count`, text.includes(`(${bytes(theirs.bytes)})`), true);
    }

    const silence = list.find((f) => f.id === 'silence');
    if (silence) {
      const filteredSilence = findings(a, { ...meta, scope: 'filtered', filter: 'tcp' }).find((f) => f.id === 'silence');
      check(`${name}: on a filtered report a silence is "no matching frames"`, filteredSilence?.text.startsWith('No matching frames for '), true);
    } else {
      console.log(`SKIP  ${name}: no silence long enough to report, so its filtered wording is not exercised`);
    }

    const overview = list.find((f) => f.id === 'overview')!;
    check(`${name}: the overview counts the capture's frames`, overview.text.startsWith(`${plural(packets.length, 'frame')} (`), true);

    check(`${name}: an import with no counters says the file does not record drops`,
      list.find((f) => f.id === 'drops'),
      { id: 'drops', tone: 'notice', text: 'The file does not record whether frames were lost while it was captured: drop counters were not available.' });
    const live = (drops: DropCounts) => findings(a, metaFor(a, drops, { kind: 'live', adapters: ['Ethernet'] })).find((f) => f.id === 'drops');
    check(`${name}: live, no counters`, live(NO_DROPS),
      { id: 'drops', tone: 'notice', text: 'Drop counters were not available, so this report cannot say whether the capture is complete.' });
    check(`${name}: live, nothing dropped, one counter missing`, live({ kernel: 0, agent: 0, pipe: null }),
      { id: 'drops', tone: 'info', text: 'No frames were dropped by the driver and agent. The pipe counter was not available.' });
    check(`${name}: live, nothing dropped, every counter read`, live({ kernel: 0, agent: 0, pipe: 0 }),
      { id: 'drops', tone: 'info', text: 'No frames were dropped by the driver, agent and pipe.' });
    check(`${name}: live, frames dropped, a null stays "not available"`, live({ kernel: 1204, agent: 3, pipe: null }),
      { id: 'drops', tone: 'fault', text: 'The capture lost 1,207 frames before they reached Inwire (driver 1,204, agent 3, pipe not available). '
        + 'Everything below describes what arrived, not everything that was on the wire.' });
    check(`${name}: live, one frame dropped`, live({ kernel: null, agent: 1, pipe: 0 })?.text.startsWith('The capture lost 1 frame before'), true);

    const filtered = findings(a, { ...meta, scope: 'filtered', filter: 'tcp', frames: { ...meta.frames, inCapture: a.frames + 100 } });
    check(`${name}: a filtered report says so first`, filtered[0], {
      id: 'scope', tone: 'info',
      text: `This report covers only the ${plural(a.frames, 'frame')} matching the display filter "tcp", out of ${count(a.frames + 100)} in the capture.`,
    });
    const unreadable = findings(a, { ...meta, frames: { ...meta.frames, unreadable: 3 } }).find((f) => f.id === 'unreadable');
    check(`${name}: unreadable frames are a fault`, unreadable?.tone, 'fault');
  }

  // The same findings from a child process in another zone and locale.
  if (captures.length > 0) {
    const child = spawnSync(process.execPath, [...process.execArgv, fileURLToPath(import.meta.url), '--emit'], {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      env: { ...process.env, TZ: 'Asia/Kathmandu', LANG: 'de_DE.UTF-8', LC_ALL: 'de_DE.UTF-8' },
    });
    const line = child.stdout.split(/\r?\n/).find((l) => l.startsWith('{'));
    check('another time zone and locale produce the same findings', line ? JSON.parse(line) : child.stderr, mine);
  }

  // Nothing at all: a literal, since no capture file is empty.
  const empty = analyseCapture([]);
  check('empty: says there is nothing, and still reports drops',
    findings(empty, metaFor(empty, NO_DROPS, { kind: 'live', adapters: [] })), [
      { id: 'empty', tone: 'info', text: 'There are no frames to analyse.' },
      { id: 'drops', tone: 'notice', text: 'Drop counters were not available, so this report cannot say whether the capture is complete.' },
    ]);
  check('format: an offset is minutes and seconds', [offset(0), offset(212.3), offset(3725)], ['0:00', '3:32', '1:02:05']);

  console.log();
  if (failures > 0) {
    console.log(`${failures} assertion(s) FAILED`);
    process.exit(1);
  }
  console.log('All findings assertions passed.');
  process.exit(0);
}

if (process.argv.includes('--emit')) {
  emit().then(() => process.exit(0), (err) => { console.error(err); process.exit(1); });
} else {
  main().catch((err) => {
    console.log(`FAIL  findings threw: ${err instanceof Error ? err.stack : String(err)}`);
    process.exit(1);
  });
}
