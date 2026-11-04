/**
 * Assertion tests for the key log store, as a thing fed repeatedly.
 *
 *   npx tsx scripts/tls/key-log.ts
 *
 * `keyLog.add` was written for a file loaded once a session. It is now fed
 * every line Chrome appends (`electron/keyLogFollower.ts`), and the whole file
 * again whenever a renderer attaches - which turned two harmless habits into
 * costs:
 *
 * - **It stored and counted every line every time.** Loading the same file
 *   twice doubled `secrets` and doubled the lines an export writes back, and
 *   the panel's "added no new secrets - every line was already loaded" could
 *   never be shown, because the count always moved.
 * - **It bumped `generation` on every call**, and a bump tells every live TLS
 *   and QUIC conversation to re-derive its keys on its next packet. A chunk
 *   that taught nothing must not cost that.
 *
 * And one that was simply wrong: Clear cleared this store and not the
 * Worker's, which is the one live capture decrypts with.
 */
import { readFileSync } from 'node:fs';
import { keyLog, KeyLogStore, type KeyLogShared } from '../../src/services/tls/keyLog';

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
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/** A syntactically real line. The values mean nothing; the shape is the test. */
const line = (label: string, random: string, secret: string) =>
  `${label} ${random.repeat(64 / random.length)} ${secret.repeat(64 / secret.length)}`;

const A = line('CLIENT_TRAFFIC_SECRET_0', 'a1', 'c3');
const B = line('SERVER_TRAFFIC_SECRET_0', 'a1', 'd4');
const C = line('CLIENT_TRAFFIC_SECRET_0', 'b2', 'e5');

console.log('\n--- the same line twice is one secret ---\n');

keyLog.clear();
keyLog.add(`${A}\n${B}\n`);
const once = keyLog.stats();
keyLog.add(`${A}\n${B}\n`);
const twice = keyLog.stats();
check('loading a file twice does not double the count', twice.secrets, once.secrets);
check('...or the lines an export would write back',
  new TextDecoder('latin1').decode(keyLog.serialise()).split('\n').filter(Boolean).length, 2);
check('...and the connection count is unchanged', twice.connections, once.connections);

console.log('\n--- generation moves only when something was learned ---\n');

const g0 = keyLog.generation;
keyLog.add(`${A}\n`);
check('a chunk of lines already held does not bump the generation', keyLog.generation, g0);
keyLog.add('# a comment, and nothing else\n\n');
check('...nor does a chunk with no key log lines in it', keyLog.generation, g0);
keyLog.add(`${C}\n`);
checkTrue('a chunk with a new secret does', keyLog.generation > g0);

console.log('\n--- a later line for the same label still wins ---\n');

// The store's own documented rule, which dedupe must not break: a key log is
// append-only, and a repeated label with a DIFFERENT secret means the
// connection was resumed. Only identical lines are the same secret.
const g1 = keyLog.generation;
const resumed = line('CLIENT_TRAFFIC_SECRET_0', 'a1', 'f6');
keyLog.add(`${resumed}\n`);
checkTrue('a new secret for a held label is taken', keyLog.generation > g1);
check('...and it is what the store answers with now',
  [...(keyLog.secretsFor(new Uint8Array(32).fill(0xa1))?.get('CLIENT_TRAFFIC_SECRET_0') ?? [])].slice(0, 2),
  [0xf6, 0xf6]);

console.log('\n--- Clear reaches the copy live capture uses ---\n');

// Source text, because the Worker is not reachable from plain `tsx`. The
// failure these catch is silent in the worst direction: a panel that says the
// secrets are gone while the Worker goes on decrypting with them.
const panel = readFileSync('src/components/common/DecryptionSettingsPanel.tsx', 'utf8');
const worker = readFileSync('src/workers/pipeline.worker.ts', 'utf8');
const clearBody = panel.slice(panel.indexOf('const clear = ()'), panel.indexOf('const following ='));
checkTrue('the panel\'s Clear clears the page\'s store', clearBody.includes('keyLog.clear()'));
checkTrue('...and stops following, or the next appended line would decrypt again',
  clearBody.includes('forgetKeyLog()'));
checkTrue('...and no longer sends text to the Worker',
  !panel.includes('pipeline.addKeyLog') && !panel.includes('pipeline.clearKeyLog'));
const sharedCase = worker.slice(worker.indexOf("case 'keylog-shared':"), worker.indexOf("case 'detail':"));
checkTrue('the Worker adopts the page\'s buffer', sharedCase.includes('keyLog.adopt(command.snapshot)'));
checkTrue('...and on a cleared one drops its cached trees and derived answers',
  sharedCase.includes('treeCache.clear()') && sharedCase.includes('derivedStore.clear()'));
checkTrue('...and hands every shard the same buffer',
  sharedCase.includes("broadcast({ type: 'keylogShared', snapshot: command.snapshot })"));
checkTrue('a shard started later is given it too',
  /startParallel[\s\S]*keylogShared[\s\S]*keyLogSnapshot/.test(worker));
checkTrue('no copy of the key log text is kept in the Worker', !worker.includes('keyLogTexts'));
// Each TCP shard adopts the same buffer (ADR 0053 phase 3), and keeps no trees (ADR 0072).
const shard = readFileSync('src/services/pipeline/shard.ts', 'utf8');
const shardCase = shard.slice(shard.indexOf("case 'keylogShared':"), shard.indexOf("case 'flows':"));
checkTrue('the shard adopts it', shardCase.includes('keyLog.adopt(message.snapshot)'));
checkTrue('...and keeps no cached tree for plaintext to outlive it in', !/this\.trees\b/.test(shard));

console.log('\n--- a reader follows the writer\'s Clear ---\n');

{
  // The writer is the page; the reader is a Worker. Clear replaces the buffer and
  // sends a cleared snapshot, which is all the reader is told.
  const writer = new KeyLogStore();
  const reader = new KeyLogStore();
  const seen: KeyLogShared[] = [];
  writer.onSnapshot((s) => seen.push(s));
  writer.add(`${A}\n`);
  reader.adopt(writer.share());
  const random = new Uint8Array(32).fill(0xa1);
  checkTrue('the reader finds what the writer added', reader.secretsFor(random) !== undefined);
  writer.add(`${C}\n`);
  checkTrue('...and a later append with no message', reader.secretsFor(new Uint8Array(32).fill(0xb2)) !== undefined);
  writer.clear();
  const last = seen[seen.length - 1];
  checkTrue('the writer announces its Clear with a cleared snapshot', last !== undefined && last.cleared === true);
  reader.adopt(last!);
  checkTrue('adopting it leaves the reader empty', reader.isEmpty === true);
  check('...and the old secrets are not found', reader.secretsFor(random), undefined);
}

keyLog.clear();
console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All key log store checks passed.');
process.exit(0);
