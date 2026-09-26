/**
 * The capture store has two ports, and only one of them is where replies go.
 *
 *   npx tsx scripts/electron/store-ports.ts
 *
 * ## The failure this exists to prevent
 *
 * `entry.ts` used to take `event.ports[0]` from **any** parent message and
 * assign it to its single `port`. That was correct while there was one channel
 * and silently wrong the moment there were two: the second port replaced the
 * first, the store kept working - kept writing frames, kept reading them - and
 * answered every request down a port nothing was listening on. A hung hex
 * viewer, a restore that never completes, and no error anywhere.
 *
 * It is exactly the shape of the bug `§8` records shipping invisibly, and it is
 * a **source-level** check because the alternative needs two `MessagePortMain`s
 * and a `utilityProcess`, which is Electron and therefore not `tsx`. What it
 * can hold is the decisions: that a role travels with every port, that the
 * ingest port never becomes the one replies go to, and that the renderer only
 * ferries it.
 *
 * The ingest port answers exactly one thing, on itself: a revisit kit the
 * Worker asked for there (ADR 0049). That answer travels with its request as a
 * callback, so the port is still never `port`, and a failure is still
 * reported on the client port the app watches.
 *
 * ADR 0038.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (rel: string) => readFileSync(join(root, rel), 'utf8');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = actual === expected;
  if (!pass) failures += 1;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${String(expected)}`);
    console.log(`        actual   ${String(actual)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

const entry = read('electron/store/entry.ts');
const host = read('electron/store/host.ts');
const worker = read('src/workers/pipeline.worker.ts');
const client = read('src/services/pipelineClient.ts');

console.log('--- the role travels with the port ---\n');

checkTrue('host.ts sends a role with every port it hands over',
  /postMessage\(\{\s*role\s*\}/.test(host));
// Both roles exist and are distinct, or the tag says nothing.
checkTrue("...and there are exactly the two: 'client' and 'ingest'",
  /'client' \| 'ingest'/.test(host));
checkTrue('host.ts hands ports over in one place',
  (host.match(/new MessageChannelMain\(\)/g) ?? []).length === 1);

checkTrue('entry.ts reads the role off the message', /role\s*[=:]/.test(entry));

console.log('\n--- and only the client port is the reply port ---\n');

// The load-bearing one. `port` is what `CaptureHost`'s reply callback posts to;
// if the ingest branch ever assigns it, every reply goes down a one-way channel.
const ingestBranch = /if \(role === 'ingest'\) \{([\s\S]*?)\n  \}/.exec(entry)?.[1] ?? '';
checkTrue('the ingest branch exists', ingestBranch.length > 0);
checkTrue('...and never assigns `port`', !/\bport\s*=/.test(ingestBranch));
checkTrue('...but does start its own port, or it delivers nothing',
  /\.start\(\)/.test(ingestBranch));
checkTrue('...and feeds the same host', /host\.receive/.test(ingestBranch));

// The reply path is unchanged and still singular.
checkTrue('replies go to the client port alone',
  /port\?\.postMessage\(message\)/.test(entry));

// ADR 0049's one exception, held to exactly one: the host answers down a
// message's own callback for a revisit kit and for nothing else, so no reply
// meant for the renderer can ever leave on the Worker's port.
const captureHost = read('src/services/capture/captureHost.ts');
checkTrue('the host answers down a message\'s own port only with a revisit kit',
  JSON.stringify([...captureHost.matchAll(/\breply\(\{ type: '([a-zA-Z]+)'/g)].map((m) => m[1])) === '["revisitKit"]'
  && (captureHost.match(/\breply\(/g) ?? []).length === 1);

console.log('\n--- the renderer only ferries it ---\n');

// ADR 0007: no captured frame crosses the renderer's main thread. The ingest
// port's destination is the Worker, which is the only place holding a frame's
// bytes and its id at once - so the main thread must transfer it and not use it.
checkTrue('pipelineClient transfers the port into the Worker',
  /this\.send\(\{ type: 'storePort' \}, \[port\]\)/.test(client));
checkTrue('...and never posts a frame on it itself',
  !/appendBytes/.test(client));
checkTrue('the Worker is what posts frames to the store',
  /storePort\.postMessage\(\{[\s\S]{0,80}appendBytes/.test(worker));

console.log('\n--- bytes go before dissection, not after ---\n');

// The whole point: ids are assigned and bytes posted for the WHOLE released
// group before any of it is dissected. Per frame inside the loop would put each
// write behind the previous frame's dissection, which is the coupling removed.
const flushBody = /function flush\(\): void \{([\s\S]*?)\n\}/.exec(worker)?.[1] ?? '';
checkTrue('flush() was found', flushBody.length > 0);
const postAt = flushBody.indexOf('appendBytes');
const ingestAt = flushBody.indexOf('ingest(frame, id)');
checkTrue('...and posts the bytes before it dissects',
  postAt !== -1 && ingestAt !== -1 && postAt < ingestAt);
// `ingest` must not assign ids any more, or the bytes would carry different
// ones than the rows and nothing would ever match.
checkTrue('ids are assigned once, outside ingest',
  /function ingest\(frame: LiveFrame, id: number\)/.test(worker));

console.log('\n--- a missing port is degraded, never broken ---\n');

// A build whose preload predates the ingest port, or a failed request, must
// keep working: the writer notices it has no slot and writes bytes and rows
// together exactly as it always did.
checkTrue('the Worker checks the port before posting',
  /storePort !== null/.test(worker));
checkTrue('the client treats a missing ingest port as a warning, not a failure',
  /console\.warn\([\s\S]{0,120}ahead of dissection/.test(client));

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All store-port checks passed.');
process.exit(0);
