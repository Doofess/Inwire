/**
 * Three facts about the Monitoring sheet that no script can drive without a
 * window, held by reading the components' source (as `scripts/session/view.ts`
 * does for the shell): the final review's CR8, CR4 and M8.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { MONITORING_FOLDER, readDraft } from '../../src/components/monitoring/monitoringCopy';
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

process.exit((await runAll()) === 0 ? 0 : 1);
