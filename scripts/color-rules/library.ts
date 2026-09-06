/**
 * Assertion tests for the editable colouring chain.
 *
 *   npx tsx scripts/color-rules/library.ts
 *
 * The chain used to be a constant with no editor, so nothing could go wrong
 * with it that was not a source change. Now it is stored, validated on load and
 * reordered by the user, which introduces three ways to break a packet list
 * silently: a stored value from an older build that no longer parses, an empty
 * chain, and a rule ordered behind one that already matches everything it would
 * have.
 *
 * The last group is the one that matters most: `WIRESHARK_DEFAULT_RULES` is
 * what the tshark parity harness compares against frame for frame, so it has to
 * stay exactly Wireshark's chain even as the app ships extra bands on top.
 */
import {
  DEFAULT_COLOR_RULES, INWIRE_EXTRA_RULES, WIRESHARK_DEFAULT_RULES,
  ColorRulesEngine, defaultColorRules, normalizeColorRules,
} from '../../src/services/colorRules';
import { FilterEngine } from '../../src/services/filterEngine';
import { REQUIRED_RULE_IDS, ROLE_BY_RULE_ID } from '../../src/services/packetThemes';
import { CATEGORY_ORDER } from '../../src/services/expertInfo';
import type { ExpertCategory } from '../../src/types/packet';
import type { Packet, ProtocolType } from '../../src/types/packet';

/** The rule-id spelling of each category. Stated, because a derived one would
 *  agree with whatever `colorRules.ts` typed. */
const KEBAB: Record<ExpertCategory, string> = {
  Broken: 'broken', Reset: 'reset', Security: 'security', Loss: 'loss',
  CaptureGap: 'capture-gap', FlowControl: 'flow-control',
  Unverifiable: 'unverifiable', Note: 'note',
};

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

// --- the two chains -----------------------------------------------------------

check('Wireshark\'s chain is exactly its twenty rules', WIRESHARK_DEFAULT_RULES.length, 20);
check('...and none of Inwire\'s additions leaked into it',
  WIRESHARK_DEFAULT_RULES.filter(r => INWIRE_EXTRA_RULES.some(e => e.id === r.id)).map(r => r.id), []);
check('the shipped chain is Wireshark\'s plus Inwire\'s',
  DEFAULT_COLOR_RULES.length, WIRESHARK_DEFAULT_RULES.length + INWIRE_EXTRA_RULES.length);
check('...keeping Wireshark\'s rules in Wireshark\'s order',
  DEFAULT_COLOR_RULES.map(r => r.id).filter(id => WIRESHARK_DEFAULT_RULES.some(w => w.id === id)),
  WIRESHARK_DEFAULT_RULES.map(r => r.id));

{
  const ids = DEFAULT_COLOR_RULES.map(r => r.id);
  const at = (id: string) => ids.indexOf(id);
  // First-match-wins is the whole design, so a band's POSITION is its meaning.
  //
  // The eight expert bands LEAD the chain - where Wireshark puts Bad TCP, and
  // for the same reason: a frame a dissector had something to say about is
  // more interesting than the fact that it is TCP. They are also the answer to
  // "this frame is both Broken and a Capture gap", so their order among
  // themselves is `CATEGORY_ORDER` and nothing else.
  const expertIds = CATEGORY_ORDER.map((c) => `color-expert-${KEBAB[c]}`);
  check('the expert bands lead the chain, in category order',
    ids.slice(0, expertIds.length), expertIds);
  check('...ahead of the broken-frame bands', at(expertIds[0]) < at('color-checksum-errors'), true);
  check('...and of the generic transport bands', at(expertIds[0]) < at('color-tcp'), true);
  check('TLS Handshake outranks plain TCP', at('color-tls-handshake') < at('color-tcp'), true);
  check('QUIC outranks plain UDP', at('color-quic') < at('color-udp'), true);
  check('every id is unique', new Set(ids).size, ids.length);
}

check('every rule in the shipped chain has a theme role',
  DEFAULT_COLOR_RULES.filter(r => !ROLE_BY_RULE_ID[r.id]).map(r => r.id), []);
check('the theme covers exactly the shipped chain', REQUIRED_RULE_IDS.length, DEFAULT_COLOR_RULES.length);

// --- every shipped rule is a filter the engine accepts --------------------------

{
  const broken = DEFAULT_COLOR_RULES
    .map(r => ({ r, v: FilterEngine.validateFilter(r.filter, { strict: true }) }))
    .filter(({ v }) => !v.isValid)
    .map(({ r, v }) => `${r.name}: ${v.errorMessage}`);
  check('every shipped rule compiles strictly', broken, []);
}

{
  // Inwire's three bands must actually be able to match something - unlike the
  // Wireshark rules they sit beside, they were written for this build and have
  // no excuse for naming a protocol it does not dissect.
  const dead = INWIRE_EXTRA_RULES
    .map(r => ({ r, v: FilterEngine.validateFilter(r.filter, { strict: true }) }))
    .filter(({ v }) => (v.warnings?.length ?? 0) > 0)
    .map(({ r }) => r.name);
  check('...and Inwire\'s own bands name nothing undissected', dead, []);
}

// --- what a stored chain may be ------------------------------------------------

check('a non-array is rejected', normalizeColorRules('nope'), null);
check('an empty array is rejected rather than emptying the list', normalizeColorRules([]), null);
check('a rule with no filter is dropped', normalizeColorRules([{ id: 'a', name: 'A' }]), null);
check('a valid rule survives',
  normalizeColorRules([{ id: 'a', name: 'A', filter: 'tcp', enabled: false }]),
  [{ id: 'a', name: 'A', filter: 'tcp', enabled: false }]);
check('enabled defaults to true when the stored value is not a boolean',
  normalizeColorRules([{ id: 'a', name: 'A', filter: 'tcp', enabled: 'yes' }])?.[0].enabled, true);
check('a duplicate id is dropped, not merged',
  normalizeColorRules([
    { id: 'a', name: 'A', filter: 'tcp' },
    { id: 'a', name: 'B', filter: 'udp' },
  ])?.map(r => r.name), ['A']);
check('colours survive the round trip',
  normalizeColorRules([{ id: 'a', name: 'A', filter: 'tcp', bgColor: '#123456', lightTextColor: '#abcdef' }])?.[0],
  { id: 'a', name: 'A', filter: 'tcp', enabled: true, bgColor: '#123456', lightTextColor: '#abcdef' });
check('the shipped chain survives its own validator',
  normalizeColorRules(defaultColorRules())?.length, DEFAULT_COLOR_RULES.length);
check('a reset hands out a copy, not the shared array',
  defaultColorRules()[0] === DEFAULT_COLOR_RULES[0], false);

/** A frame with just enough on it for the chain to have something to read. */
const packet = (over: Partial<Packet>): Packet => ({
  id: 1, tsUs: 0, relativeTime: 0, timeDelta: 0,
  source: '10.0.0.1', destination: '10.0.0.2',
  protocol: 'TCP' as ProtocolType, length: 100, info: '', status: 'ok',
  frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
  layers: [], rawBytes: Uint8Array.from([0x00, 0x11]), interfaceName: 'test',
  ...over,
});

// --- order is the feature --------------------------------------------------------

{
  const tlsHello = packet({
    protocolLabel: 'TLSv1.3',
    frameProtocols: ['frame', 'eth', 'ip', 'tcp', 'tls'],
    fields: { 'tls.handshake.type': 1, 'tcp.srcport': 51000, 'tcp.dstport': 443 },
  });

  check('a ClientHello is TLS Handshake, not plain TCP',
    new ColorRulesEngine().getMatchedRuleName(tlsHello), 'TLS Handshake');
  check('...but under Wireshark\'s own chain it is plain TCP',
    new ColorRulesEngine(WIRESHARK_DEFAULT_RULES).getMatchedRuleName(tlsHello), 'TCP');

  // Checksum Errors still ships DISABLED, exactly as it does in Wireshark. What
  // changed is that it is no longer the only thing standing between a bad
  // checksum and the list.
  //
  // The band it used to share that job with - "Expert Warnings", keyed on
  // `inwire.expert.severity` - shipped disabled too, because on the two parity
  // fixtures it would have painted 14 % and 22 % of the list, and **every one**
  // of those frames was outbound: 1,998 and 3,459 findings, 100 % of them on
  // frames this machine had sent, where the NIC had not filled the checksum in
  // yet. `checksumVerdict` reads `frame.direction` now, so those frames are
  // `Unverified` and raise nothing, which is what makes shipping the expert
  // bands ENABLED viable at all.
  const broken = packet({ fields: { 'tcp.checksum.status': 'Bad', 'inwire.expert.category': 'Broken' } });
  check('a frame with a Broken finding is painted by its category band',
    new ColorRulesEngine().getMatchedRuleName(broken), 'Expert: Broken');
  check('Checksum Errors still ships disabled',
    DEFAULT_COLOR_RULES.find(r => r.id === 'color-checksum-errors')!.enabled, false);
  check('...and enabling it does not take the frame back, because the bands lead',
    new ColorRulesEngine(
      DEFAULT_COLOR_RULES.map(r => (r.id === 'color-checksum-errors' ? { ...r, enabled: true } : r)),
    ).getMatchedRuleName(broken),
    'Expert: Broken');

  // The frame the old band painted 1,998 times: this machine sent it, so the
  // checksum on the wire was never the checksum in the buffer. No verdict, no
  // finding, no band - plain TCP.
  const offloaded = packet({ fields: { 'tcp.checksum.status': 'Unverified' } });
  check('an outbound frame whose checksum was not written yet is plain TCP',
    new ColorRulesEngine().getMatchedRuleName(offloaded), 'TCP');

  // Moving a rule up has to change the answer, or the arrows in the editor are
  // decoration.
  const reordered = [
    DEFAULT_COLOR_RULES.find(r => r.id === 'color-tcp')!,
    ...DEFAULT_COLOR_RULES.filter(r => r.id !== 'color-tcp'),
  ];
  check('moving TCP to the top makes it win', new ColorRulesEngine(reordered).getMatchedRuleName(tlsHello), 'TCP');

  const disabled = DEFAULT_COLOR_RULES.map(r => (r.id === 'color-tls-handshake' ? { ...r, enabled: false } : r));
  check('a disabled rule is skipped', new ColorRulesEngine(disabled).getMatchedRuleName(tlsHello), 'TCP');

  const nonsense = [{ id: 'x', name: 'Broken', filter: 'this is not a filter (', enabled: true }];
  check('a rule that does not compile matches nothing rather than throwing',
    new ColorRulesEngine(nonsense).getMatchedRuleName(tlsHello), undefined);

  // --- a frame's colour must not depend on bytes the buffer has released ----
  //
  // The buffer stops holding raw bytes past a window and reads them back from
  // the store on demand (docs/decisions/0013). Wireshark writes the Broadcast
  // rule as `eth[0] & 1`, straight out of the frame - and a byte read on a
  // frame whose bytes are gone returns nothing, which a filter cannot tell from
  // "this frame is not a broadcast". The row would quietly lose its colour on
  // the next re-match: a minimap repaint, or any edit to the rule chain.
  //
  // So the rule reads `eth.ig`, dissected once and kept. These two frames are
  // the same frame before and after eviction.
  // An ordinary STP hello, which the chain's own comment names as the case
  // that falls through to Broadcast - an ARP broadcast is coloured "ARP",
  // because the ARP rule comes first and first match wins.
  const stpHello = (rawBytes: Uint8Array): Packet => packet({
    protocol: 'STP' as ProtocolType,
    frameProtocols: ['frame', 'eth', 'llc', 'stp'],
    // Not 0x80: a topology-change BPDU has its own rule above this one.
    fields: { 'eth.dst': '01:80:c2:00:00:00', 'eth.ig': 1, 'stp.type': 0x00 },
    rawBytes,
  });
  const broadcastBytes = stpHello(Uint8Array.from([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]));
  const broadcastEvicted = stpHello(new Uint8Array(0));   // bytes released
  const engine = new ColorRulesEngine(DEFAULT_COLOR_RULES);
  check('a broadcast frame is coloured Broadcast',
    engine.getMatchedRuleName(broadcastBytes), 'Broadcast');
  check('...and still is once its bytes have been released',
    new ColorRulesEngine(DEFAULT_COLOR_RULES).getMatchedRuleName(broadcastEvicted), 'Broadcast');

  // The other direction: a unicast frame must not become a broadcast because
  // its group bit says 0 rather than being absent.
  const unicast = packet({
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    fields: { 'eth.dst': '44:15:24:aa:bb:cc', 'eth.ig': 0, 'tcp.srcport': 1, 'tcp.dstport': 2 },
    rawBytes: new Uint8Array(0),
  });
  check('a unicast frame with no bytes is not Broadcast',
    new ColorRulesEngine(DEFAULT_COLOR_RULES).getMatchedRuleName(unicast), 'TCP');
}

// --- The match cache, and the one way it could paint a frame wrongly ---------
//
// The matched rule is cached ON the packet - a number packing which engine
// decided it with which rule it decided (`Packet.colorSlot`). That is 15 B a
// frame against the 41 B the previous `WeakMap<Packet, ColorRule>` cost, and it
// takes a warm pass over a million frames from 103.8 ms to 22.7 ms
// (`scripts/perf/color-index-cost.ts`).
//
// It also puts a mutable cache on an object that outlives the thing that wrote
// it, which is exactly how a stale answer gets rendered as a current one. The
// generation is the defence, and these are what hold it.
{
  const tcp = packet({
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    fields: { 'tcp.srcport': 51000, 'tcp.dstport': 443 },
  });

  const first = new ColorRulesEngine(DEFAULT_COLOR_RULES);
  check('nothing is known before anything asks', first.matchedRuleIfKnown(tcp), undefined);
  check('a frame matches under the shipped chain', first.getMatchedRuleName(tcp), 'TCP');
  check('...and is known afterwards', first.matchedRuleIfKnown(tcp)?.name, 'TCP');
  check('...from the cache, without a second walk',
    first.matchedRuleIfKnown(tcp)?.name, 'TCP');

  // The whole point. A second engine over a DIFFERENT chain must not read the
  // first engine's answer off the packet - the frame is carrying a cached
  // 'TCP' and the correct answer here is 'UDP-ish', so a generation that did
  // not distinguish them would paint the old chain's decision for ever.
  const recoloured = DEFAULT_COLOR_RULES.map(r =>
    r.id === 'color-tcp' ? { ...r, name: 'TCP (edited)' } : r);
  const second = new ColorRulesEngine(recoloured);
  check("a new chain does not read the previous chain's answer",
    second.matchedRuleIfKnown(tcp), undefined);
  check('...and decides for itself', second.getMatchedRuleName(tcp), 'TCP (edited)');

  // ...and the first engine is not corrupted by the second having written over
  // the packet. It is a cache: a miss costs a walk, never a wrong answer.
  check('the earlier engine still answers correctly after being evicted',
    first.getMatchedRuleName(tcp), 'TCP');
}

// A frame matching NO rule caches that too - it is the expensive answer, being
// the only one that has run every matcher - and must come back as "decided,
// nothing matched" rather than as "not yet decided".
{
  const nothing = packet({ frameProtocols: ['frame', 'eth'], fields: {} });
  const engine = new ColorRulesEngine([
    { id: 'only', name: 'Only', filter: 'tcp', enabled: true },
  ]);
  check('a frame matching nothing has no rule name',
    engine.getMatchedRuleName(nothing), undefined);
  check('...and that is a decision, not an absence',
    engine.matchedRuleIfKnown(nothing), null);
}

// A chain longer than the slot can encode must stop caching rather than wrap.
// Wrapping would hand back a rule the frame did not match, which is the one
// failure mode worse than being slow.
{
  const many = Array.from({ length: 300 }, (_, i) => ({
    id: 'rule-' + i,
    name: 'Rule ' + i,
    // Only the last one can match, so the answer is unambiguous and is also
    // the deepest possible walk.
    filter: i === 299 ? 'tcp' : 'ip.src == 203.0.113.' + (i % 200),
    enabled: true,
  }));
  const engine = new ColorRulesEngine(many);
  const tcp = packet({
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    fields: { 'tcp.srcport': 1, 'tcp.dstport': 2 },
  });
  check('an over-long chain still matches correctly',
    engine.getMatchedRuleName(tcp), 'Rule 299');
  check('...twice, since nothing was cached to go stale',
    engine.getMatchedRuleName(tcp), 'Rule 299');
  check('...and it declines to cache rather than wrapping',
    engine.matchedRuleIfKnown(tcp), undefined);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All colour rule library checks passed.');
process.exit(0);
