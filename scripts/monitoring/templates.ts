/**
 * The collector's template store (ADRs 0064, 0065): isolation, redefinition,
 * withdrawals, restart detection, the two-condition lifetime, the bounds and
 * the gap flags.
 *
 *   npx tsx scripts/monitoring/templates.ts
 *
 * Plain tsx. The store is driven directly: `beginDatagram` once per datagram
 * of a scope, then `define`. The decoder-level cases (data before its
 * template, the same-datagram rule) are `flow-decode.ts`'s.
 *
 * Counting convention under test: a scope's message counter increments in
 * `beginDatagram`, before the expiry check, so the datagram that checks counts
 * itself. A template received in message m has been "unseen" for k messages at
 * message m + k.
 */
import assert from 'node:assert/strict';
import { CollectorTemplateStore, type TemplateScope } from '../../src/services/monitoring/templates';
import type { FlowTemplate } from '../../src/services/flow/flowExport';
import { LIMITS } from '../../src/services/monitoring/types';

let failures = 0;
let passes = 0;
function test(name: string, fn: () => void): void {
  try {
    fn();
    passes++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}`);
    console.log(`        ${String((e as Error).stack ?? e).split('\n').slice(0, 6).join('\n        ')}`.slice(0, 900));
  }
}

const T0 = 1_700_000_000_000;
const MIN = 60_000;
const A = '192.0.2.1';
const v9 = (domain: number): TemplateScope => ({ protocol: 'v9', exporter: A, exporterPort: null, domain });
const ipfix = (domain: number, port: number): TemplateScope => ({ protocol: 'ipfix', exporter: A, exporterPort: port, domain });
const flowTemplate = (...types: number[]): FlowTemplate => ({ scopeCount: 0, fields: types.map((type) => ({ type, length: 4 })) });

/** One datagram of the scope at `ms`: the message is counted, then the caller defines. */
const begin = (s: CollectorTemplateStore, scope: TemplateScope, ms: number, uptime: number | null = null) => s.beginDatagram(scope, ms, uptime);

test('isolation: a template in one scope is not in another', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  begin(s, a, T0);
  assert.equal(s.define(a, 256, flowTemplate(8, 12), 1, T0), 'defined');
  assert.notEqual(s.lookup(a, 256), null);
  assert.equal(s.lookup(v9(2), 256), null, 'another v9 Source ID');
  assert.equal(s.lookup(ipfix(1, 50_000), 256), null, 'IPFIX with the same domain');
  begin(s, ipfix(1, 50_000), T0);
  s.define(ipfix(1, 50_000), 300, flowTemplate(8), 2, T0);
  assert.equal(s.lookup(ipfix(1, 50_001), 300), null, 'another IPFIX source port');
  assert.equal(s.lookup(ipfix(2, 50_000), 300), null, 'another IPFIX domain');
  assert.equal(s.lookup(a, 300), null, 'IPFIX templates are not v9 templates');
  assert.equal(s.lookup({ ...a, exporter: '192.0.2.2' }, 256), null, 'another exporter address');
});

test('redefinition-replaces: other specifiers replace and restart the interval history', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  begin(s, a, T0);
  s.define(a, 256, flowTemplate(8, 12), 1, T0);
  begin(s, a, T0 + 1000);
  assert.equal(s.define(a, 256, flowTemplate(8, 12), 2, T0 + 1000), 'refreshed');
  assert.equal(s.lookup(a, 256)!.intervalMs, 1000);
  begin(s, a, T0 + 5000);
  assert.equal(s.define(a, 256, flowTemplate(8, 12, 7), 3, T0 + 5000), 'replaced');
  const t = s.lookup(a, 256)!;
  assert.deepEqual(t.fields.map((f) => f.type), [8, 12, 7]);
  assert.equal(t.definedEntryId, 3, 'defined at the entry that replaced it');
  assert.equal(t.intervalMs, 0, 'the interval history starts again');
  assert.equal(t.intervalMessages, 0);
});

test('refresh-keeps: the same specifiers keep the definition and widen the longest interval', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  begin(s, a, T0);
  s.define(a, 256, flowTemplate(8, 12), 1, T0);
  begin(s, a, T0 + 10_000);
  begin(s, a, T0 + 20_000);
  assert.equal(s.define(a, 256, flowTemplate(8, 12), 3, T0 + 20_000), 'refreshed');
  let t = s.lookup(a, 256)!;
  assert.equal(t.definedEntryId, 1, 'a refresh does not change the entry that defined it');
  assert.equal(t.intervalMs, 20_000);
  assert.equal(t.intervalMessages, 2);
  assert.equal(t.lastSeenMs, T0 + 20_000);
  begin(s, a, T0 + 25_000);
  s.define(a, 256, flowTemplate(8, 12), 4, T0 + 25_000);
  t = s.lookup(a, 256)!;
  assert.equal(t.intervalMs, 20_000, 'a shorter interval does not narrow the longest');
  assert.equal(t.intervalMessages, 2);
});

test('refused-redefinition-removes-old: the exporter said the old one is wrong', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  begin(s, a, T0);
  const big = (n: number): FlowTemplate => ({ scopeCount: 0, fields: Array.from({ length: n }, (_, i) => ({ type: (i % 100) + 1, length: 4 })) });
  // Eight templates of 96 KiB spend the 768 KiB budget exactly; a ninth template shares nothing.
  for (let i = 0; i < 8; i++) assert.equal(s.define(a, 256 + i, big(24_576), 1, T0), 'defined');
  // A redefinition that fits (the old specifiers are given back first) replaces.
  assert.equal(s.define(a, 257, big(24_576 - 1), 2, T0), 'replaced');
  // One that does not fit is refused, and takes the old definition with it.
  assert.notEqual(s.lookup(a, 256), null);
  assert.equal(s.define(a, 256, big(24_576 + 2), 3, T0), 'refused-bound');
  assert.equal(s.lookup(a, 256), null, 'the old definition is gone');
  assert.equal(s.counters(a).refused, 1);
  assert.notEqual(s.lookup(a, 258), null, 'nothing else was evicted');
});

test('withdrawal-ignored: counted per scope, nothing removed', () => {
  const s = new CollectorTemplateStore();
  const a = ipfix(1, 50_000);
  begin(s, a, T0);
  s.define(a, 256, flowTemplate(8), 1, T0);
  s.withdrawalIgnored(a);
  s.withdrawalIgnored(a);
  assert.notEqual(s.lookup(a, 256), null);
  assert.equal(s.counters(a).withdrawalsIgnored, 2);
  assert.equal(s.counters(ipfix(2, 50_000)).withdrawalsIgnored, 0, 'per scope');
});

test('restart-invalidates-scope: v9 uptime back by more than 10 s', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  assert.equal(begin(s, a, T0, 600_000), 'ok');
  s.define(a, 256, flowTemplate(8), 1, T0);
  assert.equal(begin(s, a, T0 + 1000, 400_000), 'restart');
  assert.equal(s.lookup(a, 256), null, 'the old layout is gone');
  assert.equal(s.counters(a).restarts, 1);
  // The exporter reuses 256 with a different layout: only the new one exists.
  s.define(a, 256, flowTemplate(12, 8), 2, T0 + 1000);
  assert.deepEqual(s.lookup(a, 256)!.fields.map((f) => f.type), [12, 8]);
});

test('restart-invalidates-scope: v9 uptime back by 5 s is a reordered datagram, not a restart', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  begin(s, a, T0, 600_000);
  s.define(a, 256, flowTemplate(8), 1, T0);
  assert.equal(begin(s, a, T0 + 1000, 595_000), 'ok');
  assert.notEqual(s.lookup(a, 256), null);
  assert.equal(s.counters(a).restarts, 0);
  // Ten seconds exactly is still within the tolerance; more is not.
  assert.equal(begin(s, a, T0 + 2000, 590_000), 'ok', 'exactly 10 s back, against the reference that stayed at 600000');
  assert.equal(begin(s, a, T0 + 3000, 560_000), 'restart');
});

test('restart-invalidates-scope: an uptime wrap is not a restart', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  const nearWrap = 2 ** 32 - 30 * MIN;
  begin(s, a, T0, nearWrap);
  s.define(a, 256, flowTemplate(8), 1, T0);
  assert.equal(begin(s, a, T0 + 1000, 5000), 'ok', 'previous within an hour of 2^32, new under an hour');
  assert.notEqual(s.lookup(a, 256), null);
  // From two hours up to two minutes is a restart.
  const b = v9(2);
  begin(s, b, T0, 2 * 60 * MIN);
  assert.equal(begin(s, b, T0 + 1000, 2 * MIN), 'restart');
});

test('restart-invalidates-scope: an IPFIX port change drops the old scope', () => {
  const s = new CollectorTemplateStore();
  const old = ipfix(7, 50_000);
  const moved = ipfix(7, 50_001);
  assert.equal(begin(s, old, T0), 'ok');
  s.define(old, 256, flowTemplate(8), 1, T0);
  assert.equal(begin(s, moved, T0 + 1000), 'restart');
  assert.equal(s.lookup(moved, 256), null, 'the new port is a new scope');
  assert.equal(s.lookup(old, 256), null, 'the old port\'s templates are not used');
  assert.equal(s.inventory().length, 0);
  s.define(moved, 256, flowTemplate(12), 2, T0 + 1000);
  assert.deepEqual(s.lookup(moved, 256)!.fields.map((f) => f.type), [12]);
  // A different domain on another port is another source, not a restart.
  assert.equal(begin(s, ipfix(8, 50_002), T0 + 2000), 'ok');
  assert.notEqual(s.lookup(moved, 256), null);
});

test('restart-invalidates-scope: an IE 160 jump keeps what the same datagram defined', () => {
  const s = new CollectorTemplateStore();
  const a = ipfix(1, 50_000);
  begin(s, a, T0);
  assert.equal(s.observeSystemInit(a, 1_699_990_000_000, 1), 'ok');
  s.define(a, 256, flowTemplate(8), 1, T0);
  // A later datagram: the template set comes first, then the options record states a new IE 160.
  begin(s, a, T0 + 1000);
  s.define(a, 257, flowTemplate(12), 5, T0 + 1000);
  assert.equal(s.observeSystemInit(a, 1_699_990_000_000 + 9_000, 5), 'ok', 'within 10 s is not a restart');
  assert.notEqual(s.lookup(a, 256), null);
  assert.equal(s.observeSystemInit(a, 1_699_990_000_000 + 60_000, 5), 'restart');
  assert.equal(s.lookup(a, 256), null, 'received in an earlier datagram');
  assert.notEqual(s.lookup(a, 257), null, 'defined earlier in this datagram');
  assert.equal(s.counters(a).restarts, 1);
});

// --- the lifetime -------------------------------------------------------------------------------------

/** A scope with template 256 defined in message 1 at T0, and a helper that sends one more datagram. */
function lifetimeRig() {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  begin(s, a, T0);
  s.define(a, 256, flowTemplate(8), 1, T0);
  let messages = 1;
  const send = (ms: number) => { messages++; begin(s, a, ms); return messages; };
  return { s, a, send, alive: () => s.lookup(a, 256) !== null };
}

test('lifetime-both-conditions: expired only when time and messages are both past', () => {
  const r = lifetimeRig();
  // Messages 2..49 are 1..48 messages after the definition: 48 is not "exceeds 48".
  for (let m = 2; m <= 49; m++) r.send(T0 + 31 * MIN);
  assert.equal(r.alive(), true, '48 messages since: not yet');
  r.send(T0 + 31 * MIN);
  assert.equal(r.alive(), false, '49 messages since and over 30 minutes');
});

test('lifetime-both-conditions: time past but messages not is kept', () => {
  const r = lifetimeRig();
  for (let m = 2; m <= 10; m++) r.send(T0 + 3 * 60 * MIN);
  assert.equal(r.alive(), true);
});

test('lifetime-both-conditions: messages past but time not is kept', () => {
  const r = lifetimeRig();
  for (let m = 2; m <= 200; m++) r.send(T0 + 29 * MIN);
  assert.equal(r.alive(), true, '199 messages in 29 minutes');
  r.send(T0 + 30 * MIN);
  assert.equal(r.alive(), true, 'exactly 30 minutes does not exceed 30 minutes');
  r.send(T0 + 30 * MIN + 1);
  assert.equal(r.alive(), false, 'a millisecond over, and long past the messages');
});

test('lifetime-both-conditions: the longest observed interval stretches both', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  begin(s, a, T0);
  s.define(a, 256, flowTemplate(8), 1, T0);
  // Refreshed 100 messages and 20 minutes later: the longest interval is now 100 messages / 20 minutes.
  for (let m = 2; m <= 100; m++) begin(s, a, T0 + 10 * MIN);
  begin(s, a, T0 + 20 * MIN);
  assert.equal(s.define(a, 256, flowTemplate(8), 101, T0 + 20 * MIN), 'refreshed');
  const t = s.lookup(a, 256)!;
  assert.equal(t.intervalMessages, 100);
  assert.equal(t.intervalMs, 20 * MIN);
  const seen = T0 + 20 * MIN;
  // Time bound is max(30 min, 60 min) = 60 min; message bound max(48, 300) = 300; message 101 is the last receipt.
  for (let m = 102; m <= 401; m++) begin(s, a, seen + 61 * MIN);
  assert.notEqual(s.lookup(a, 256), null, '300 messages since is not over 300');
  begin(s, a, seen + 61 * MIN);
  assert.equal(s.lookup(a, 256), null, '301 messages and 61 minutes');
  // And the time bound stretches too: a fresh template with a 20 minute interval is kept at 59 minutes of silence.
  begin(s, a, seen + 62 * MIN);
  s.define(a, 300, flowTemplate(8), 500, seen + 62 * MIN);
  begin(s, a, seen + 82 * MIN);
  s.define(a, 300, flowTemplate(8), 501, seen + 82 * MIN);
  for (let m = 0; m < 500; m++) begin(s, a, seen + 82 * MIN + 59 * MIN);
  assert.notEqual(s.lookup(a, 300), null, '59 minutes is under 3 x 20');
  begin(s, a, seen + 82 * MIN + 61 * MIN);
  assert.equal(s.lookup(a, 300), null, '61 minutes is over 3 x 20, and the messages are past');
});

test('lifetime-both-conditions: no interval is measured across gapEnded()', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  begin(s, a, T0);
  s.define(a, 256, flowTemplate(8), 1, T0);
  s.gapEnded();
  assert.equal(s.lookup(a, 256)!.previousSession, true);
  begin(s, a, T0 + 10 * MIN);
  assert.equal(s.define(a, 256, flowTemplate(8), 9, T0 + 10 * MIN), 'refreshed');
  const t = s.lookup(a, 256)!;
  assert.equal(t.intervalMs, 0, 'ten minutes across a gap is not a refresh interval');
  assert.equal(t.intervalMessages, 0);
  assert.equal(t.previousSession, false, 'the receipt clears the flag');
  begin(s, a, T0 + 10 * MIN + 1000);
  s.define(a, 256, flowTemplate(8), 10, T0 + 10 * MIN + 1000);
  assert.equal(s.lookup(a, 256)!.intervalMs, 1000, 'measured again within the session');
});

test('lifetime-both-conditions: after gapEnded() the message condition counts as met, once', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  const b = v9(2);
  begin(s, a, T0);
  s.define(a, 256, flowTemplate(8), 1, T0);
  begin(s, b, T0);
  s.define(b, 256, flowTemplate(8), 2, T0);
  s.gapEnded();
  // Scope a: one message after the gap, an hour later: time is past, messages are not, but the gap counts.
  begin(s, a, T0 + 60 * MIN);
  assert.equal(s.lookup(a, 256), null, 'expired by time, the message condition counting as met');
  // Scope b: the gap's first datagram arrives within the time bound: kept, and the flag is spent.
  begin(s, b, T0 + 10 * MIN);
  assert.notEqual(s.lookup(b, 256), null);
  begin(s, b, T0 + 60 * MIN);
  assert.notEqual(s.lookup(b, 256), null, 'the second datagram is back to counting messages');
});

// --- the bounds ---------------------------------------------------------------------------------------

test('bounds: the 257th template in a scope is refused, counted, and nothing is evicted', () => {
  const s = new CollectorTemplateStore();
  const a = ipfix(1, 50_000);
  begin(s, a, T0);
  for (let id = 256; id < 256 + LIMITS.templatesPerScope; id++) assert.equal(s.define(a, id, flowTemplate(8), 1, T0), 'defined');
  assert.equal(s.define(a, 9000, flowTemplate(8), 2, T0), 'refused-bound');
  assert.equal(s.lookup(a, 9000), null);
  assert.notEqual(s.lookup(a, 256), null, 'the oldest is still there');
  assert.equal(s.counters(a).refused, 1);
  // A refresh of an existing one is not a new template.
  assert.equal(s.define(a, 256, flowTemplate(8), 3, T0), 'refreshed');
  assert.equal(s.counters(a).refused, 1);
});

test('bounds: the 4,097th template in all is refused', () => {
  const s = new CollectorTemplateStore();
  // 16 scopes of 256 fill the store; the 17th scope is built directly because the store does not bound scopes.
  for (let d = 0; d < 16; d++) {
    const a = ipfix(d, 50_000 + d);
    begin(s, a, T0);
    for (let id = 256; id < 256 + 256; id++) assert.equal(s.define(a, id, flowTemplate(8), 1, T0), 'defined');
  }
  const extra = ipfix(99, 51_000);
  begin(s, extra, T0);
  assert.equal(s.define(extra, 256, flowTemplate(8), 2, T0), 'refused-bound');
  assert.equal(s.counters(extra).refused, 1);
  assert.equal(s.inventory().length, 4096);
});

test('bounds: the 768 KiB field budget', () => {
  const s = new CollectorTemplateStore();
  const a = ipfix(1, 50_000);
  begin(s, a, T0);
  // Each template: 24576 fields of 4 bytes = 96 KiB. Eight fill the budget exactly.
  const big = (): FlowTemplate => ({ scopeCount: 0, fields: Array.from({ length: 24_576 }, (_, i) => ({ type: (i % 100) + 1, length: 4 })) });
  for (let i = 0; i < 8; i++) assert.equal(s.define(a, 256 + i, big(), 1, T0), 'defined');
  assert.equal(s.define(a, 300, flowTemplate(8), 2, T0), 'refused-bound', 'one more field is over 768 KiB');
  // Enterprise fields cost 8 bytes.
  const s2 = new CollectorTemplateStore();
  begin(s2, a, T0);
  const enterprise: FlowTemplate = { scopeCount: 0, fields: Array.from({ length: 49_152 }, (_, i) => ({ type: (i % 100) + 1, length: 4, pen: 29305 })) };
  assert.equal(s2.define(a, 256, enterprise, 1, T0), 'defined', '49152 x 8 bytes = 384 KiB');
  assert.equal(s2.define(a, 257, enterprise, 1, T0), 'defined', 'two of them are exactly 768 KiB');
  assert.equal(s2.define(a, 258, flowTemplate(8), 1, T0), 'refused-bound');
});

test('gap flags: gapEnded() sets scope and template flags, the next datagram clears the scope\'s', () => {
  const s = new CollectorTemplateStore();
  const a = v9(1);
  begin(s, a, T0);
  s.define(a, 256, flowTemplate(8), 1, T0);
  assert.equal(s.lookup(a, 256)!.previousSession, false);
  s.gapEnded();
  assert.equal(s.lookup(a, 256)!.previousSession, true);
  begin(s, a, T0 + 1000);
  assert.equal(s.lookup(a, 256)!.previousSession, true, 'the template flag clears at its own receipt, not the scope\'s');
});

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
