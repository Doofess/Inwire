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
  check('Expert Warnings sits after the broken-frame bands', at('color-expert') > at('color-checksum-errors'), true);
  check('...and before the generic transport bands', at('color-expert') < at('color-tcp'), true);
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

// --- order is the feature --------------------------------------------------------

{
  const packet = (over: Partial<Packet>): Packet => ({
    id: 1, tsUs: 0, relativeTime: 0, timeDelta: 0,
    source: '10.0.0.1', destination: '10.0.0.2',
    protocol: 'TCP' as ProtocolType, length: 100, info: '', status: 'ok',
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    layers: [], rawBytes: Uint8Array.from([0x00, 0x11]), interfaceName: 'test',
    ...over,
  });

  const tlsHello = packet({
    protocolLabel: 'TLSv1.3',
    frameProtocols: ['frame', 'eth', 'ip', 'tcp', 'tls'],
    fields: { 'tls.handshake.type': 1, 'tcp.srcport': 51000, 'tcp.dstport': 443 },
  });

  check('a ClientHello is TLS Handshake, not plain TCP',
    new ColorRulesEngine().getMatchedRuleName(tlsHello), 'TLS Handshake');
  check('...but under Wireshark\'s own chain it is plain TCP',
    new ColorRulesEngine(WIRESHARK_DEFAULT_RULES).getMatchedRuleName(tlsHello), 'TCP');

  // Checksum Errors ships DISABLED, as it does in Wireshark - NIC offload means
  // a frame captured on the host that sent it has no checksum yet, and
  // validating those paints half the list red. So a bad checksum reaches the
  // list through Expert Warnings, which is exactly the gap that band was added
  // for; enable the rule and it takes precedence again.
  // Checksum Errors and Expert Warnings both ship DISABLED, and for the same
  // reason: NIC offload means a frame captured on the host that sent it has no
  // checksum yet, so on the two parity fixtures those two bands would have
  // painted 14 % and 22 % of the list over an artefact of where the capture
  // was taken. Both are one click away in the editor, which is what the editor
  // is for.
  const broken = packet({ fields: { 'tcp.checksum.status': 'Bad', 'inwire.expert.severity': 'error' } });
  check('a bad checksum is not painted by default', new ColorRulesEngine().getMatchedRuleName(broken), 'TCP');
  for (const id of ['color-checksum-errors', 'color-expert'] as const) {
    const enabled = DEFAULT_COLOR_RULES.map(r => (r.id === id ? { ...r, enabled: true } : r));
    check(`...and is once ${id} is enabled`,
      new ColorRulesEngine(enabled).getMatchedRuleName(broken),
      id === 'color-expert' ? 'Expert Warnings' : 'Checksum Errors');
  }

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
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All colour rule library checks passed.');
process.exit(0);
