/**
 * Three facts about the Monitoring sheet that no script can drive without a
 * window, held by reading the components' source (as `scripts/session/view.ts`
 * does for the shell): the final review's CR8, CR4 and M8.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  ESTIMATE_LABEL, MONITORING_FOLDER, clockText, engineLabel, notInterpretedText, readDraft, samplingEstimate, samplingText,
} from '../../src/components/monitoring/monitoringCopy';
import { ONBOARDING_SNIPPETS, SNIPPET_CAVEAT, fillSnippet } from '../../src/components/monitoring/onboardingSnippets';
import { test, runAll } from './queryRig';

const read = (name: string): string => readFileSync(new URL(`../../src/components/monitoring/${name}`, import.meta.url), 'utf8');

test('CR8: Start records the source as started only after client.start succeeded', () => {
  const src = read('SourceForm.tsx');
  const startAt = src.indexOf('await client.start(');
  assert.ok(startAt > 0, 'the form starts the listener');
  assert.equal(src.indexOf('startedThisSession.push'), src.lastIndexOf('startedThisSession.push'), 'one place records');
  const calls = [...src.matchAll(/\bremember\(config\)/g)].map((m) => m.index!);
  assert.ok(calls.length >= 1);
  for (const at of calls) assert.ok(at > startAt, 'remember(config) comes after the start call, never before it');
  assert.match(src, /if \(result\.ok\) remember\(config\)/);
});

test('CR4: Focus is a snapshot with a visible time and a Refresh, and does not poll', () => {
  const src = read('Focus.tsx');
  assert.match(src, /as of \{localTime\(asOfMs\)\}/);
  assert.match(src, /Refresh/);
  assert.doesNotMatch(src, /setInterval/, 'Focus does not re-query on a timer');
});

test('M8: a damaged history says how to start a new one, with the real folder', () => {
  const src = read('SourceStatus.tsx');
  const at = src.indexOf("intake.storage === 'refused-corrupt'");
  assert.ok(at > 0);
  const block = src.slice(at, at + 500);
  assert.match(block, /MONITORING_FOLDER/);
  assert.match(block, /Inwire does not delete it/);
  assert.equal(MONITORING_FOLDER, '%LOCALAPPDATA%\\Inwire\\monitoring');
});

test('limit: a storage limit too large is told apart from one too small', () => {
  const base = { exporterIPv4: '192.0.2.1', bindIPv4: '192.0.2.20', port: '2055', unit: 'GiB' as const };
  const err = (limit: string, unit: 'MiB' | 'GiB' = 'GiB') => readDraft({ ...base, limit, unit }).errors.limit;
  assert.equal(err('8'), undefined, 'a sensible limit has no error');
  assert.equal(err('65536'), undefined, '64 TiB itself is accepted');
  assert.match(err('65537') ?? '', /at most 64 TiB/, 'one GiB past the cap says too large');
  assert.match(err('1e12') ?? '', /at most 64 TiB/);
  assert.match(err('1', 'MiB') ?? '', /at least 16 MiB/, 'too small keeps its own words');
  assert.match(err('0') ?? '', /at least 16 MiB/);
  assert.match(err('-5') ?? '', /at least 16 MiB/);
  assert.match(err('') ?? '', /at least 16 MiB/);
  assert.match(err('abc') ?? '', /at least 16 MiB/);
});

const COPY_CONSTANTS = [
  'Evidence expired',
  'Not available: this minute exceeded the key budget, and its evidence has expired.',
  'Nothing expires unless you turn this on',
  'Totals come from retained minute rollups.',
  'under the retention policy',
  'was discarded before',
];

test('Task 6: the storage block carries its fields and adds no confirm of its own', () => {
  const src = read('StorageBlock.tsx');
  for (const label of ['Kept in', 'Change…', 'Keep up to', 'Keep raw evidence for', 'At the storage limit', 'Discard…']) {
    assert.ok(src.includes(label), `StorageBlock says "${label}"`);
  }
  const form = read('SourceForm.tsx');
  assert.ok(!form.includes('Keep up to'), 'the limit field moved out of SourceForm');
  // Discard acts at once: it renders after Start and Save, not among the drafts they save.
  assert.ok(form.indexOf('<DiscardControl') > form.indexOf("'Start'"), 'Discard renders below Start');
  assert.match(form, /firstStart && busy !== 'load' && !readOnly/, 'no firewall note while Start is off for a read-only folder');
  assert.doesNotMatch(src, /uppercase/, 'section titles are sentence case');
  assert.doesNotMatch(src, /confirm\(/);
  assert.doesNotMatch(src, /role="dialog"/);
  assert.doesNotMatch(src, /alertdialog/);
});

test('Task 6: the expiry copy is held verbatim in monitoringCopy', () => {
  const src = read('monitoringCopy.ts');
  for (const text of COPY_CONSTANTS) assert.ok(src.includes(text), `monitoringCopy holds "${text}"`);
});

test('Task 6: Export evidence bundle sits in the same button row as Export CSV', () => {
  const src = read('History.tsx');
  const csv = src.indexOf('Export CSV');
  const bundle = src.indexOf('Export evidence bundle');
  assert.ok(csv > 0 && bundle > 0);
  assert.ok(Math.abs(bundle - csv) < 900, 'the two buttons are neighbours');
  assert.ok(!src.slice(Math.min(csv, bundle), Math.max(csv, bundle)).includes('</div>'), 'no row closes between them');
});

test('Task 6: the chart marks aggregate-only apart from observed-records and has the legend entry', () => {
  const src = read('HistoryChart.tsx');
  assert.match(src, /EVIDENCE_EXPIRED_LEGEND/);
  assert.match(src, /b\.coverage === 'aggregate-only'/);
});

test('Task 6: Focus words an expired range from the copy function, not the reply message', () => {
  const src = read('Focus.tsx');
  assert.match(src, /'evidence-expired'/);
  assert.match(src, /evidenceExpiredText\(/);
});

test('Final: an expired or failed Focus drops the old list and can still be refreshed; a stale journal is asked again a bounded number of times', () => {
  const src = read('Focus.tsx');
  const failures = src.slice(src.indexOf("reply.code === 'cancelled'"), src.indexOf('setError(reply.message)'));
  assert.match(failures, /'evidence-expired'/);
  assert.match(failures, /setResult\(null\)[\s\S]*'evidence-expired'/, 'the expired note and the error do not sit under an older list');
  const staleBranch = src.slice(src.indexOf("reply.code === 'stale-generation'"));
  assert.match(staleBranch.slice(0, 300), /MAX_STALE/, 'a journal that keeps reopening ends in a message, not an endless re-ask');
  const resultBlock = src.indexOf('{result && (');
  assert.ok(resultBlock > 0);
  const refreshUses = [...src.matchAll(/onClick=\{onRefresh\}/g)].map((m) => m.index ?? 0);
  assert.ok(refreshUses.length === 1 && refreshUses[0] < resultBlock, 'Refresh is defined once, outside the result block, so the expired and error states reach it');
});

// --- Task 10: the exporter's state and onboarding (ADRs 0064-0066) -----------------------------------------

test('Task 10: a template lists what it does not interpret as "not interpreted: PEN n / IE m"', () => {
  assert.equal(notInterpretedText([]), null, 'nothing to say when every element is interpreted');
  assert.equal(notInterpretedText([{ pen: 29305, ie: 1 }, { pen: null, ie: 82 }]), 'not interpreted: PEN 29305 / IE 1, IE 82');
  const src = read('ExporterDetail.tsx');
  assert.match(src, /notInterpretedText\(/);
  assert.match(src, /awaitingSets/, 'the awaiting-template count is on screen');
  assert.match(src, /lastAwaitingTemplateId/);
});

test('Task 10: the sampling status reads its four states, and absence is never 1:1', () => {
  const known = samplingText({ kind: 'known', interval: 100 });
  assert.match(known.text, /1 in 100/);
  const absent = samplingText({ kind: 'absent' });
  assert.match(absent.text, /not stated/i);
  assert.match(absent.text, /never assumed 1:1/);
  assert.match(samplingText({ kind: 'unsupported', reason: 'random sampling without an interval' }).text, /random sampling without an interval/);
  assert.match(samplingText({ kind: 'unsupported' }).text, /unsupported/i);
  const mixed = samplingText({ kind: 'mixed' });
  assert.match(mixed.text, /changed/i);
  assert.equal(new Set([known, absent, samplingText({ kind: 'unsupported' }), mixed].map((s) => s.text)).size, 4, 'four different sentences');
  // The live status says since when.
  assert.match(samplingText({ kind: 'known', interval: 100, sinceEntryId: 42 }).text, /since entry 42/);
});

test('Task 10: an estimate exists only when the rate is known and constant over the range, and says so', () => {
  assert.deepEqual(samplingEstimate({ kind: 'known', interval: 100 }, true, 1_500n, 3n), { interval: 100, octets: 150_000n, packets: 300n });
  for (const s of [{ kind: 'absent' }, { kind: 'mixed' }, { kind: 'unsupported' }] as const) {
    assert.equal(samplingEstimate(s, true, 1_500n, 3n), null, `no estimate when sampling is ${s.kind}`);
  }
  assert.equal(samplingEstimate({ kind: 'known', interval: 1 }, true, 1_500n, 3n), null, '1 in 1 is not sampled: the reported figure is the figure');
  // Some records of the range with no known rate: the range's interval may be known, the estimate is not.
  assert.equal(samplingEstimate({ kind: 'known', interval: 10 }, false, 1_500n, 3n), null, 'no estimate when some records have unknown sampling');
  assert.deepEqual(samplingEstimate({ kind: 'known', interval: 10 }, true, 1_500n, 3n), { interval: 10, octets: 15_000n, packets: 30n });
  assert.equal(ESTIMATE_LABEL, 'estimate');
  const src = read('History.tsx');
  assert.match(src, /samplingEstimate\(/);
  assert.match(src, /ESTIMATE_LABEL/);
  assert.match(src, /samplingText\(result\.sampling\)/, 'the rate is stated beside the values it qualifies');
});

test('Task 10: the clock status shows its offset and is flagged past the threshold', () => {
  assert.match(clockText({ latestSkewMs: null, minSkewMs: null, maxSkewMs: null, flagged: false }).text, /no export time/i);
  const ahead = clockText({ latestSkewMs: 1_200, minSkewMs: -300, maxSkewMs: 1_200, flagged: false });
  assert.match(ahead.text, /1\.2 s ahead/);
  assert.match(ahead.text, /0\.3 s behind/);
  assert.equal(ahead.tone, 'good');
  const flagged = clockText({ latestSkewMs: -95_000, minSkewMs: -95_000, maxSkewMs: -95_000, flagged: true });
  assert.match(flagged.text, /behind/);
  assert.equal(flagged.tone, 'warn');
  assert.match(flagged.text, /past the 10 s threshold/);
});

test('Task 10: a v9 or IPFIX source is labelled by what it calls itself', () => {
  assert.equal(engineLabel('192.0.2.1/0/5'), 'engine 0/5');
  assert.equal(engineLabel('v9:192.0.2.1/7'), 'NetFlow v9, source ID 7');
  assert.equal(engineLabel('ipfix:192.0.2.1/300'), 'IPFIX, domain 300');
});

// The survey's rows that send v9 or IPFIX (`docs/monitoring-v5-measurements.md`, *Exporter survey*), and Sophos, which
// sends v5 only. Juniper EX is sFlow only and has no row here.
const SURVEYED = ['Cisco', 'Fortinet', 'Palo Alto Networks', 'Juniper', 'Cisco Meraki', 'Sophos', 'MikroTik', 'OPNsense', 'Netgate', 'Ubiquiti', 'HPE Aruba'];

test('Task 10: one onboarding snippet per surveyed v9/IPFIX vendor plus Sophos, each cited and filled with the listener', () => {
  for (const vendor of SURVEYED) assert.ok(ONBOARDING_SNIPPETS.some((s) => s.vendor === vendor), `a snippet for ${vendor}`);
  assert.equal(ONBOARDING_SNIPPETS.find((s) => s.vendor === 'Sophos')?.protocol, 'NetFlow v5', 'Sophos sends v5 only');
  assert.equal(new Set(ONBOARDING_SNIPPETS.map((s) => s.id)).size, ONBOARDING_SNIPPETS.length, 'ids are unique');
  for (const s of ONBOARDING_SNIPPETS) {
    assert.ok(s.sources.length > 0 && s.sources.every((x) => x.url.startsWith('https://')), `${s.id} cites its page`);
    assert.match(s.readOn, /^\d{4}-\d{2}-\d{2}$/);
    if (s.lines.length === 0) continue;
    const text = fillSnippet(s, '192.0.2.20', 2056);
    assert.ok(text.includes('192.0.2.20') && text.includes('2056'), `${s.id} carries the configured address and port`);
    assert.doesNotMatch(text, /\{[A-Z_]+\}/,`${s.id} leaves no placeholder unfilled`);
  }
  assert.equal(SNIPPET_CAVEAT, 'From vendor documentation; not tested on this hardware.');
  const src = read('Onboarding.tsx');
  // Every snippet with lines is verified (the Aruba test below), so the caveat is on every one shown.
  assert.ok(src.includes('{snippet.verified ? SNIPPET_CAVEAT : UNVERIFIED_CAVEAT}'), 'every snippet shows the caveat');
  assert.match(read('History.tsx'), /<Onboarding /, 'the empty history offers it');
  assert.match(read('MonitoringSheet.tsx'), /<Onboarding /, 'and so does the sheet once there is a history');
});

test('Task 10: Aruba is marked unverified and gives no lines, its page having refused to be read', () => {
  const aruba = ONBOARDING_SNIPPETS.filter((s) => s.vendor === 'HPE Aruba');
  assert.equal(aruba.length, 1);
  assert.equal(aruba[0].verified, false);
  assert.deepEqual(aruba[0].lines, [], 'an unreadable page gives no guessed lines');
  for (const s of ONBOARDING_SNIPPETS) if (s.vendor !== 'HPE Aruba') assert.equal(s.verified, true, `${s.id} was read`);
  assert.match(read('Onboarding.tsx'), /UNVERIFIED_CAVEAT/);
});

process.exit((await runAll()) === 0 ? 0 : 1);
