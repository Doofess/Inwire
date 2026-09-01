/**
 * Assertion tests for ColorRulesEngine's per-packet rule cache.
 *
 *   npx tsx scripts/color-rules/cache.ts
 *
 * The cache exists because the packet-list minimap asks for every buffered
 * packet's color on every repaint, and walking the 19-rule chain per packet per
 * repaint was measured at 76% of all wall-clock time during a live capture.
 * These checks cover the ways a memo can be wrong: a stale or shared entry, a
 * negative result that is recomputed rather than remembered, and a theme change
 * being served the previous theme's colors.
 *
 * Frame-for-frame correctness of the chain itself is not this file's job -
 * scripts/parity/parity-check.ts already diffs every packet of a real pcap
 * against tshark's frame.coloring_rule.name, and it exercises the same cache.
 */
import { ColorRulesEngine, DEFAULT_COLOR_RULES, resolveRuleColors } from '../../src/services/colorRules';
import { getPacketThemeForApp } from '../../src/services/packetThemes';
import { THEME_OPTIONS } from '../../src/lib/themeOptions';
import type { Packet } from '../../src/types/packet';

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

let nextId = 1;
function makePacket(over: Partial<Packet> = {}): Packet {
  return {
    id: nextId++,
    timestamp: 1_700_000_000_000,
    relativeTime: 0,
    timeDelta: 0,
    source: '10.0.0.1',
    destination: '10.0.0.2',
    protocol: 'TCP',
    length: 74,
    info: 'test frame',
    status: 'ok',
    layers: [],
    rawBytes: new Uint8Array(0),
    ...over,
  } as Packet;
}

const engine = new ColorRulesEngine();

// --- The cache returns the same answer as an uncached walk -----------------
{
  // A second engine has never seen these packets, so its answer is by
  // definition uncached - any divergence is the cache lying.
  const fresh = new ColorRulesEngine();
  const packets = [
    makePacket({ protocol: 'TCP' }),
    makePacket({ protocol: 'UDP' }),
    makePacket({ protocol: 'ARP' }),
    makePacket({ protocol: 'ICMP' }),
    makePacket({ protocol: 'CUSTOM' }),
  ];
  const warmed = packets.map(p => engine.getMatchedRuleName(p));
  // Ask the warm engine a second time; this is the answer that comes from cache.
  const cached = packets.map(p => engine.getMatchedRuleName(p));
  const uncached = packets.map(p => fresh.getMatchedRuleName(p));
  check('a cached rule matches the first walk', cached, warmed);
  check('...and matches a never-warmed engine', cached, uncached);
}

// --- A no-match result is remembered, not re-walked ------------------------
{
  // "no rule matched" is the expensive answer: it is the only one that has run
  // every matcher in the chain. Caching it is the point, so prove it is cached
  // rather than merely returning undefined again.
  const engineWithProbe = new ColorRulesEngine();
  const anyEngine = engineWithProbe as unknown as {
    compiled: { rule: { name: string }; matcher: (p: Packet) => boolean }[];
  };
  let walks = 0;
  const realMatchers = anyEngine.compiled.map(c => c.matcher);
  anyEngine.compiled.forEach((c, i) => {
    c.matcher = (p: Packet) => {
      walks++;
      return realMatchers[i](p);
    };
  });

  // A packet nothing in the chain claims: CUSTOM is not one of the protocols
  // any rule names, it carries no ports for the port-based rules, and its
  // destination MAC is unicast so the Broadcast rule at the end misses too.
  const unmatched = makePacket({
    protocol: 'CUSTOM',
    layers: [{ name: 'Ethernet II', summary: '', fields: [{ name: 'Destination', value: '00:11:22:33:44:55' }] }],
    rawBytes: new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0, 0, 0, 0, 0, 0x08, 0x00]),
  });

  check('the probe packet really matches no rule', engineWithProbe.getMatchedRuleName(unmatched), undefined);
  const afterFirst = walks;
  engineWithProbe.getMatchedRuleName(unmatched);
  engineWithProbe.getMatchedRuleName(unmatched);
  check('a no-match walks the chain once, not per call', walks, afterFirst);
  check('...and the first call really did walk it', afterFirst > 0, true);
}

// --- One cached rule serves every theme ------------------------------------
{
  // The cache holds the matched *rule*, not a pair of colors, so switching
  // packet theme must not need invalidation and must not hand back the
  // previous theme's colors.
  const tcp = makePacket({ protocol: 'TCP' });
  const rule = DEFAULT_COLOR_RULES.find(r => r.name === 'TCP')!;
  const darkTheme = getPacketThemeForApp('dark');
  const lightTheme = getPacketThemeForApp('light');
  const dark = engine.getPacketStyle(tcp, darkTheme);
  const light = engine.getPacketStyle(tcp, lightTheme);
  check('dark colors come from the matched rule', dark.background, resolveRuleColors(rule, darkTheme).background);
  check('light colors come from the same rule', light.background, resolveRuleColors(rule, lightTheme).background);
  check('the two themes really differ', dark.background !== light.background, true);
  // Asking the first theme again after the second must not return the second.
  check('re-asking a theme is not poisoned by the other ask', engine.getPacketStyle(tcp, darkTheme).background, dark.background);

  // Every shipped theme must be reachable through the same cached rule - this
  // is what proves palettes are a lookup rather than a second match pass.
  // Now keyed by APP theme, since that is the only theme axis there is.
  const distinct = new Set(
    THEME_OPTIONS.map(t => engine.getPacketStyle(tcp, getPacketThemeForApp(t.value)).background),
  );
  check('every app theme paints TCP differently', distinct.size, THEME_OPTIONS.length);
}

// --- Entries are per packet, not shared ------------------------------------
{
  const tcp = makePacket({ protocol: 'TCP' });
  const arp = makePacket({ protocol: 'ARP' });
  check('first packet keeps its own rule', engine.getMatchedRuleName(tcp), 'TCP');
  check('a different packet is not served the first one\'s entry', engine.getMatchedRuleName(arp), 'ARP');
  check('...and the first is still itself afterwards', engine.getMatchedRuleName(tcp), 'TCP');
}

// --- Two packets that are equal by value are still separate keys -----------
{
  // WeakMap keys by identity. App.tsx replaces a packet with {...p, info} when
  // an ICMP reply patches it, so the copy must recompute rather than inherit -
  // which is correct, since no color rule reads `info`.
  const original = makePacket({ protocol: 'ICMP' });
  const patched = { ...original, info: `${original.info} (reply in 42)` } as Packet;
  check('an identity-copied packet resolves to the same rule', engine.getMatchedRuleName(patched), engine.getMatchedRuleName(original));
}

// --- getPacketStyle and getMatchedRuleName agree ---------------------------
{
  // Both go through matchRule now; a refactor that lets them drift would show
  // as a row whose color does not match the rule the parity check asserts.
  for (const proto of ['TCP', 'UDP', 'ARP', 'ICMP', 'CUSTOM'] as const) {
    const p = makePacket({ protocol: proto });
    const name = engine.getMatchedRuleName(p);
    const theme = getPacketThemeForApp('dark');
    const style = engine.getPacketStyle(p, theme);
    const expected = name === undefined ? undefined : resolveRuleColors(DEFAULT_COLOR_RULES.find(r => r.name === name)!, theme).background;
    check(`${proto}: style agrees with matched rule name`, style.background, expected);
  }
}

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
