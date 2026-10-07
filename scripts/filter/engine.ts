/**
 * Assertion tests for the display-filter language.
 *
 *   npx tsx scripts/filter/engine.ts
 *
 * The engine had no test of its own until now, which is how `==` came to mean
 * "equal or contains" without anyone noticing: `ip.src == 10.0.0.1` also
 * matched 110.0.0.10, and every shipped preset written with `==` was asking a
 * wider question than it looked like. So the first group below pins the
 * operators, and the last group pins the things that must NOT match - an
 * absent field, a protocol this build does not dissect, a network literal read
 * as a string.
 *
 * The packets here are hand-built rather than captured: the point is what the
 * engine does with a `fields` bag and a layer list, not how those were filled.
 */
import { FilterEngine } from '../../src/services/filterEngine';
import { compile } from '../../src/services/filter/compile';
import { tokenize } from '../../src/services/filter/lexer';
import { knownFieldNames, UNDISSECTED } from '../../src/services/filter/fields';
import { combineFilter, fieldTerm } from '../../src/services/filter/fromField';
import { MAX_CUSTOM_COLUMNS, normalizeCustomColumns } from '../../src/lib/packetColumns';
import { FIELD_BY_ABBREV, LAYERS } from '../../src/services/dissect/fieldRegistry';
import { DEFAULT_COLOR_RULES } from '../../src/services/colorRules';
import { DEFAULT_FILTER_PRESET_LIBRARY, allPresets } from '../../src/services/filterPresets';
import type { Packet, ProtocolType } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

// --- the frames every check below runs against ------------------------------

interface Spec {
  id: number;
  protocol: ProtocolType;
  protocolLabel?: string;
  source: string;
  destination: string;
  sourcePort?: number;
  destPort?: number;
  length?: number;
  info?: string;
  status?: Packet['status'];
  frameProtocols?: string[];
  fields?: Record<string, string | number>;
  analysisFlags?: string[];
  rawBytes?: number[];
}

function packet(s: Spec): Packet {
  return {
    id: s.id,
    tsUs: 1_700_000_000_000_000 + s.id * 1000,
    relativeTime: s.id / 100,
    timeDelta: 0.01,
    source: s.source,
    destination: s.destination,
    sourcePort: s.sourcePort,
    destPort: s.destPort,
    protocol: s.protocol,
    protocolLabel: s.protocolLabel,
    length: s.length ?? 100,
    info: s.info ?? '',
    status: s.status ?? 'ok',
    frameProtocols: s.frameProtocols,
    fields: s.fields,
    analysisFlags: s.analysisFlags,
    layers: [],
    rawBytes: Uint8Array.from(s.rawBytes ?? []),
    interfaceName: 'test',
  };
}

const PACKETS: Packet[] = [
  // 1: a plain TLS-over-TCP frame to a well-known port.
  packet({
    id: 1, protocol: 'TLS', protocolLabel: 'TLSv1.3',
    source: '10.0.0.1', destination: '93.184.216.34',
    sourcePort: 51000, destPort: 443, length: 1400,
    info: 'Client Hello (SNI=www.example.com)',
    frameProtocols: ['frame', 'eth', 'ip', 'tcp', 'tls'],
    fields: {
      'ip.src': '10.0.0.1', 'ip.dst': '93.184.216.34', 'ip.ttl': 64,
      'tcp.srcport': 51000, 'tcp.dstport': 443, 'tcp.flags': 0x018,
      'tcp.flags.syn': 0, 'tcp.checksum.status': 'Good',
      'tls.handshake.type': 1,
      'tls.handshake.extensions_server_name': 'www.example.com',
      'tls.handshake.ja4': 't13d1516h2_8daaf6152771_b186095e22b6',
    },
    rawBytes: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
  }),
  // 2: the SYN that opened it.
  packet({
    id: 2, protocol: 'TCP',
    source: '10.0.0.1', destination: '93.184.216.34',
    sourcePort: 51000, destPort: 443, length: 74,
    info: '51000 → 443 [SYN] Seq=0 Win=64240 Len=0',
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    fields: {
      'ip.src': '10.0.0.1', 'ip.dst': '93.184.216.34', 'ip.ttl': 64,
      'tcp.srcport': 51000, 'tcp.dstport': 443, 'tcp.flags': 0x002,
      'tcp.flags.syn': 1, 'tcp.flags.reset': 0,
    },
    rawBytes: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
  }),
  // 3: a retransmission, which the Bad TCP rule has to find.
  packet({
    id: 3, protocol: 'TCP',
    source: '93.184.216.34', destination: '10.0.0.1',
    sourcePort: 443, destPort: 51000, length: 1514,
    info: '[TCP Retransmission] 443 → 51000',
    status: 'retransmit',
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    fields: {
      'ip.src': '93.184.216.34', 'ip.dst': '10.0.0.1', 'ip.ttl': 52,
      'tcp.srcport': 443, 'tcp.dstport': 51000, 'tcp.flags': 0x010,
    },
    analysisFlags: ['retransmission'],
    rawBytes: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
  }),
  // 4: multicast DNS, on a low TTL, to a broadcast MAC.
  packet({
    id: 4, protocol: 'DNS', protocolLabel: 'MDNS',
    source: '10.0.0.7', destination: '224.0.0.251',
    sourcePort: 5353, destPort: 5353, length: 90,
    info: 'Standard query 0x0000 PTR _companion-link._tcp.local, "QM" question',
    frameProtocols: ['frame', 'eth', 'ip', 'udp', 'dns'],
    fields: {
      'ip.src': '10.0.0.7', 'ip.dst': '224.0.0.251', 'ip.ttl': 1,
      'udp.srcport': 5353, 'udp.dstport': 5353,
      'dns.qry.name': '_companion-link._tcp.local', 'dns.qry.type': 12, 'dns.flags.rcode': 0,
    },
    rawBytes: [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb],
  }),
  // 5: an ICMP destination-unreachable, for the set-membership rule.
  packet({
    id: 5, protocol: 'ICMP',
    source: '10.0.0.254', destination: '10.0.0.1', length: 110,
    info: 'Destination unreachable (Port unreachable)',
    status: 'warning',
    frameProtocols: ['frame', 'eth', 'ip', 'icmp'],
    fields: { 'ip.src': '10.0.0.254', 'ip.dst': '10.0.0.1', 'ip.ttl': 64, 'icmp.type': 3, 'icmp.code': 3 },
    rawBytes: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
  }),
  // 6: QUIC, whose only tree layer is the TLS handshake it carries - so its
  //    `quic` token has to come from the token list, not from a layer name.
  packet({
    id: 6, protocol: 'QUIC', protocolLabel: 'QUIC',
    source: '10.0.0.1', destination: '142.250.185.78',
    sourcePort: 52000, destPort: 443, length: 1252,
    info: 'Initial, DCID=0011223344556677, PKN: 1, CRYPTO, PADDING',
    frameProtocols: ['frame', 'eth', 'ipv6', 'udp', 'tls', 'quic'],
    fields: {
      'ipv6.src': '2001:db8::1', 'ipv6.dst': '2a00:1450:4001::200e', 'ipv6.hlim': 64,
      'udp.srcport': 52000, 'udp.dstport': 443,
      'tls.handshake.extensions_server_name': 'www.google.com',
      'tls.handshake.ja4': 'q13d0312h3_55b375c5d22e_cd85d2d88918',
    },
    rawBytes: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
  }),
];

const ids = (filter: string) => FilterEngine.filterPackets(PACKETS, filter).map(p => p.id);
const strict = (filter: string) => {
  const m = compile(filter);
  return PACKETS.filter(m).map(p => p.id);
};

// --- 1. the bug this phase exists for --------------------------------------

check('== is equality, not a substring match', strict('ip.src == 10.0.0.1'), [1, 2]);
check('...so a longer address that contains it does not match',
  PACKETS.concat(packet({ id: 99, protocol: 'TCP', source: '110.0.0.10', destination: '8.8.8.8' }))
    .filter(compile('ip.src == 10.0.0.1')).map(p => p.id), [1, 2]);
check('contains is the substring operator', strict('info contains "Retransmission"'), [3]);
check('...and is case-sensitive, as in the reference analyzer', strict('info contains "retransmission"'), []);
check('icontains is the case-insensitive one', strict('info icontains "retransmission"'), [3]);
check('matches is a regex', strict('info matches "^\\\\d+ . 443"'), [2]);
check('a bad regex is a syntax error',
  FilterEngine.validateFilter('info matches "("').isValid, false);

// --- 2. operators ----------------------------------------------------------

check('!= is "no occurrence equals"', strict('ip.src != 10.0.0.1'), [3, 4, 5]);
check('...and never matches a frame without the field', strict('icmp.type != 3'), []);
check('numeric >', strict('frame.len > 1000'), [1, 3, 6]);
check('numeric <=', strict('ip.ttl <= 1'), [4]);
check('worded operators', strict('tcp.flags.syn eq 1'), [2]);
check('hex literals', strict('tcp.flags == 0x02'), [2]);
check('bitmask on a field', strict('tcp.flags & 0x02'), [2]);
check('bitmask on a byte slice (the Broadcast rule)', strict('eth[0] & 1'), [4]);
check('a two-byte slice', strict('eth[0:2] == 0x0100'), [4]);
check('set membership with a range', strict('icmp.type in { 3..5, 11 }'), [5]);
check('negated set membership', strict('ip.ttl not in { 1, 64 }'), [3]);
check('and / or / not spelled as words', strict('tcp and not tls'), [2, 3]);
check('and / or / not spelled as symbols', strict('tcp && !tls'), [2, 3]);
check('parentheses bind', strict('(tcp || udp) && ip.ttl == 1'), [4]);
check('xor', strict('tcp xor tls'), [2, 3, 6]);

// --- 3. field resolution ---------------------------------------------------

check('a port alias reads both ends', strict('tcp.port == 443'), [1, 2, 3]);
check('the source-only alias does not', strict('tcp.srcport == 443'), [3]);
check('addr reads both ends', strict('ip.addr == 93.184.216.34'), [1, 2, 3]);
check('a CIDR compares networks', strict('ip.dst == 224.0.0.0/4'), [4]);
check('a negated CIDR excludes the network, not the literal',
  strict('ip && ip.dst != 224.0.0.0/4'), [1, 2, 3, 5]);
check('an IPv6 prefix', strict('ipv6.src == 2001:db8::/32'), [6]);
check('proto matches the coarse key', strict('proto == tls'), [1]);
check('...and the displayed label', strict('proto == tlsv1.3'), [1]);
check('addresses compare without regard to case', strict('ipv6.dst == 2A00:1450:4001::200E'), [6]);
check('a string field compares with regard to case',
  strict('tls.handshake.extensions_server_name == "WWW.Example.com"'), []);
check('generated analysis flags', strict('tcp.analysis.retransmission'), [3]);
check('the bare analysis-flags test', strict('tcp.analysis.flags'), [3]);
check('status', strict('status == warning'), [5]);
check('frame.number', strict('frame.number >= 5'), [5, 6]);
check('a registry field nothing in the frame carries', strict('dns.qry.type == 12'), [4]);

// --- 4. layer presence -----------------------------------------------------

check('a layer token reads the dissected layer list', strict('tcp'), [1, 2, 3]);
check('tls is a layer, so a TLS-over-QUIC frame satisfies it', strict('tls'), [1, 6]);
check('quic has no layer of its own and still resolves', strict('quic'), [6]);
check('dns', strict('dns'), [4]);
check('mdns is a label, not a layer', strict('mdns'), [4]);
check('a frame that dissected no such layer does not match', strict('udp'), [4, 6]);
check('a field name as a bareword tests presence', strict('tls.handshake.extensions_server_name'), [1, 6]);

// --- 5. what must NOT match ------------------------------------------------

check('a protocol this build does not dissect matches nothing', strict('dcerpc'), []);
check('...even when a frame mentions it', strict('netbios'), []);
check('an unknown field in a comparison matches nothing', strict('tpc.port == 443'), []);
check('...and is reported as a typo', FilterEngine.validateFilter('tpc.port == 443').isValid, false);
check('an undissected protocol is a warning, not an error', {
  valid: FilterEngine.validateFilter('dcerpc', { strict: true }).isValid,
  warnings: FilterEngine.validateFilter('dcerpc', { strict: true }).warnings?.length,
}, { valid: true, warnings: 1 });
// `ospf.msg` stood here until OSPF became a real layer token, and `bgp.type`
// until BGP became one - each time this quietly began asserting the opposite of
// what it means to, and each time the failure was the fix. The overlap check
// below is the structural version of this and needs no editing; what this adds
// is that a field UNDER an undissected name warns too, which that check cannot
// see.
//
// `dcerpc.opnum` should outlast the others, and for a measured reason rather
// than a guess. The reference's Protocol and Info columns for DCERPC are not
// the RPC layer at all: a bound context turns them into the INTERFACE's name
// and its OPERATION's name (`SRVSVC` / `NetShareEnumAll request`), from some
// hundred per-interface opnum tables and the NDR argument dissectors under
// them. A build that read the RPC header and stopped would be right on the
// interfaces nobody uses and wrong on every one they do.
check('...and so is a field belonging to one', {
  valid: FilterEngine.validateFilter('dcerpc.opnum != 1').isValid,
  warnings: FilterEngine.validateFilter('dcerpc.opnum != 1').warnings?.length,
}, { valid: true, warnings: 1 });
// --- the two lists of protocol names must not overlap ---------------------------
//
// `UNDISSECTED` names protocols this build recognises and cannot decode, so a
// colour rule written against one keeps its filter instead of reading as a
// typo. `LAYERS` names the ones it CAN decode. A name on both is a claim and
// its own denial, and the checks above could not catch it: they are hand-picked
// examples, and each one had to be hand-edited as its protocol landed - the
// comment above records `ospf.msg` standing here asserting the opposite of what
// it meant, and `fields.ts` records `rtcp` outstaying the others by a batch.
//
// Both had in fact happened again by the time this was written: `ldap` and
// `smb2` were still listed as undissected with working dissectors, real layer
// tokens and registered fields. Nothing broke visibly, which is the point - a
// bareword returns early from `layerPresence`, so `smb2` filtered correctly.
// Only a MISSPELT `smb2.*` field took the wrong branch, and was reported as
// "a protocol this build cannot decode" rather than as the typo it was: the
// exact failure the rtcp note describes, found the same way, by accident.
{
  const overlap = UNDISSECTED.filter((n) => (LAYERS as readonly string[]).includes(n));
  check('no protocol is both undissected and a layer token', overlap, []);
  // The other direction: a name here that Wireshark's default rules do not use
  // and no dissector is planned for is dead weight, but that is a judgement
  // call rather than a contradiction - so only the prefix form is asserted,
  // which is what makes the typo branch reachable at all.
  check('every undissected name is a bare protocol, not a field',
    UNDISSECTED.filter((n) => n.includes('.') && n !== 'eth.fcs'), []);
}

// --- every registered name is actually reachable -------------------------------
//
// The parser lower-cases a field name, which was harmless while every abbrev
// was lower case. Holding the registry to Wireshark's spelling made ten of
// them mixed-case (`sip.Method`, `radius.User_Name`, `ptp.v2.mm.managementId`)
// and every one became unreachable: the name looked up its own lower-cased
// form, found nothing, and was reported as a typo. Nothing caught it - the
// registry check saw a registered field with a writer and a row, and the
// parity harness never types a filter.
//
// So: every name the registry offers must resolve, as spelt AND lower-cased.
// The second half is the promise that matters - `sip.call-id` typed from
// memory must work, which is deliberately more forgiving than Wireshark.
const unreachable = knownFieldNames().filter((name) => {
  const asWritten = FilterEngine.validateFilter(`${name} == 1`);
  const lowered = FilterEngine.validateFilter(`${name.toLowerCase()} == 1`);
  return !asWritten.isValid || !lowered.isValid;
});
check('every name the registry offers resolves, in either case', unreachable, []);

// ...and the canonical spelling is what reads the bag, since that is the key
// the dissector wrote. Resolving the name is not enough on its own.
const mixedCase = packet({
  id: 200, protocol: 'UDP', protocolLabel: 'SIP',
  source: '192.0.2.1', destination: '192.0.2.2',
  frameProtocols: ['frame', 'eth', 'ip', 'udp', 'sip'],
  fields: { 'sip.Method': 'INVITE' },
});
check('a mixed-case field reads the bag under its registered spelling',
  [mixedCase].filter(compile('sip.Method == "INVITE"')).map(p => p.id), [200]);
check('...however the user typed it',
  [mixedCase].filter(compile('sip.method == "INVITE"')).map(p => p.id), [200]);

check('a typo is still an error, not a warning',
  FilterEngine.validateFilter('ospg.msg != 1').isValid, false);

// --- 6. the filter bar's free-text convenience -----------------------------

check('a bare word naming nothing searches the summary columns', ids('example'), [1]);
check('...but only on its own', ids('example && tcp'), []);
check('...and never through the strict path a colour rule uses',
  (() => { try { return strict('example'); } catch { return 'threw'; } })(), []);

// --- 7. syntax errors ------------------------------------------------------

const badSyntax = [
  'tcp &&',
  'ip.src ==',
  '(tcp',
  'tcp.port in { }',
  'icmp.type in { 5..3 }',
  'eth[x] & 1',
  'info contains "unterminated',
];
for (const expr of badSyntax) {
  check(`rejected: ${expr}`, FilterEngine.validateFilter(expr).isValid, false);
}
check('an error names where it gave up',
  /character \d+/.test(FilterEngine.validateFilter('tcp &&').errorMessage ?? ''), true);

// --- 8. the lexer's awkward literals ---------------------------------------

check('a CIDR is one token', tokenize('ip.dst == 224.0.0.0/4').filter(t => t.kind === 'word').map(t => t.text),
  ['ip.dst', '224.0.0.0/4']);
check('an IPv6 prefix is one token', tokenize('ipv6.dst == ff00::/8').filter(t => t.kind === 'word').map(t => t.text),
  ['ipv6.dst', 'ff00::/8']);
check('no spaces needed around an operator',
  tokenize('tcp.port==443').map(t => t.kind), ['word', 'op', 'word', 'eof']);
check('a quoted string keeps its spaces',
  tokenize('info contains "Client Hello"').filter(t => t.kind === 'string').map(t => t.text), ['Client Hello']);
check('a single = is read as ==', strict('tcp.dstport = 443'), [1, 2]);

// --- 9. everything shipped compiles ----------------------------------------

{
  const problems: string[] = [];
  for (const rule of DEFAULT_COLOR_RULES) {
    const result = FilterEngine.validateFilter(rule.filter);
    if (!result.isValid) problems.push(`${rule.name}: ${result.errorMessage}`);
  }
  check('every shipped colour rule compiles', problems, []);
}

{
  const problems: string[] = [];
  for (const preset of allPresets(DEFAULT_FILTER_PRESET_LIBRARY)) {
    if (!preset.filter.trim()) continue;
    const result = FilterEngine.validateFilter(preset.filter);
    if (!result.isValid) problems.push(`${preset.name}: ${result.errorMessage}`);
  }
  check('every shipped preset compiles', problems, []);
}

check('the known-name list comes from the registry',
  knownFieldNames().includes('tls.handshake.ja4') && knownFieldNames().includes('ip.addr'), true);

// --- 10. building a filter from a tree row ---------------------------------

{
  const tls = PACKETS[0];
  check('a numeric field goes in bare', fieldTerm(tls, 'tcp.dstport'), 'tcp.dstport == 443');
  check('a string field is quoted',
    fieldTerm(tls, 'tls.handshake.extensions_server_name'),
    'tls.handshake.extensions_server_name == "www.example.com"');
  check('a field the frame does not carry yields no term', fieldTerm(tls, 'dns.qry.name'), null);
  check('a row with no abbrev yields no term', fieldTerm(tls, undefined), null);

  // The term has to survive a round trip through the engine, or "apply as
  // filter" produces an expression that does not select the frame it was
  // built from - which looks like a dissection bug and is not one.
  const term = fieldTerm(tls, 'tls.handshake.extensions_server_name')!;
  check('the built term selects the frame it came from', strict(term), [1]);
  check('...and a numeric one does too', strict(fieldTerm(tls, 'tcp.dstport')!), [1, 2]);

  check('replace discards what was there', combineFilter('udp', 'tcp', 'replace'), 'tcp');
  check('not negates', combineFilter('udp', 'tcp', 'not'), '!(tcp)');
  check('and parenthesises both sides', combineFilter('tcp || udp', 'ip.ttl == 1', 'and'),
    '(tcp || udp) && (ip.ttl == 1)');
  check('...which is what keeps the precedence the user saw',
    strict(combineFilter('tcp || udp', 'ip.ttl == 1', 'and')), [4]);
  check('or, onto an empty bar, is just the term', combineFilter('', 'tcp', 'or'), 'tcp');

  // A value with a quote in it must not end the literal early.
  const awkward: Packet = packet({
    id: 7, protocol: 'DNS', source: '10.0.0.1', destination: '10.0.0.2',
    fields: { 'dns.txt': 'say "hi"\\now' },
  });
  const quoted = fieldTerm(awkward, 'dns.txt')!;
  check('a quote inside a value is escaped', quoted, 'dns.txt == "say \\"hi\\"\\\\now"');
  check('...and the escaped term still selects it', [awkward].filter(compile(quoted)).length, 1);
}

// --- 11. columns added from the tree ---------------------------------------

{
  const known = (abbrev: string) => FIELD_BY_ABBREV.has(abbrev);
  check('a registered field is kept', normalizeCustomColumns(['tls.handshake.ja4'], known), ['tls.handshake.ja4']);
  check('an unregistered one is dropped', normalizeCustomColumns(['nope.gone'], known), []);
  check('duplicates collapse',
    normalizeCustomColumns(['ip.ttl', 'ip.ttl'], known), ['ip.ttl']);
  check('non-strings are ignored', normalizeCustomColumns([1, null, 'ip.ttl'], known), ['ip.ttl']);
  check('a stored value of the wrong shape yields none', normalizeCustomColumns('ip.ttl', known), []);
  check('the list is capped',
    normalizeCustomColumns(
      [...FIELD_BY_ABBREV.keys()].slice(0, MAX_CUSTOM_COLUMNS + 4), known,
    ).length,
    MAX_CUSTOM_COLUMNS);
  check('every column the registry offers is a field the engine knows',
    [...FIELD_BY_ABBREV.values()].filter(f => f.column && !knownFieldNames().includes(f.abbrev)).map(f => f.abbrev),
    []);
}

// --- 12. the parse happens once, not per packet ----------------------------

{
  // 50,000 frames is the buffer cap; the phase's budget for a filter pass over
  // a full one is 50 ms. Run it on a copy large enough to be meaningful.
  const many: Packet[] = [];
  for (let i = 0; i < 50_000; i++) many.push(PACKETS[i % PACKETS.length]);
  const matcher = compile('tcp.port == 443 && !tcp.analysis.flags');
  const started = Date.now();
  let hits = 0;
  for (const p of many) if (matcher(p)) hits++;
  const elapsed = Date.now() - started;
  console.log(`        50,000 frames filtered in ${elapsed} ms (${hits} matched)`);
  check('a 50k pass stays inside the phase budget', elapsed < 50, true);

  // Reported rather than asserted, because it is a decision input rather than
  // a contract: whether a filter pass has to STREAM its results depends on
  // what one costs at the sizes the buffer is headed for. The expensive shape
  // is the one that decides it - a cheap filter is cheap at any size.
  //
  // The UX line drawn for this work is that a filter must return visible
  // results in under 100 ms whatever the cap, because a million frames where
  // filtering takes a second is not obviously better than a hundred thousand
  // where it is instant.
  // Deliberately a filter that CANNOT short-circuit: every term is false, so
  // all of them are evaluated for every frame, and the last is a regex over
  // the Info column - the most expensive operator the language has. A chain of
  // `||`s that matches early measured *faster* than the two-term filter above,
  // which makes it useless as a ceiling.
  const heavy = compile(
    'ip.src == 203.0.113.1 || udp.port == 9999 || tcp.port == 9998 '
    + '|| dns.qry.name == "nothing.invalid" || frame contains "zzzz" '
    + '|| _ws.col.info matches "^zzz[0-9]+"',
  );
  const t0 = performance.now();
  let heavyHits = 0;
  for (const p of many) if (heavy(p)) heavyHits++;
  const heavyMs = performance.now() - t0;
  const perFrame = (heavyMs * 1000) / many.length;
  console.log(`        ...and ${heavyMs.toFixed(1)} ms for a six-term filter that `
    + `cannot short-circuit (${heavyHits} matched, ${perFrame.toFixed(2)} us/frame)`);
  for (const size of [100_000, 1_000_000]) {
    console.log(`        which is ${((perFrame * size) / 1000).toFixed(0)} ms `
      + `at ${size.toLocaleString()} frames`);
  }
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All filter engine checks passed.');
process.exit(0);
