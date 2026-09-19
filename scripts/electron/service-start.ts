/**
 * The agent is demand-start, and this holds the three decisions that makes.
 *
 * What it covers, and why each one is here rather than trusted:
 *
 *   - **`classifyStart`**, because the whole module exists to avoid reading
 *     `sc.exe`'s localised output, and a wrong number is exactly as confident
 *     and exactly as wrong as a wrong parse. The case that matters most is
 *     `SC_ACCESS_DENIED`: it is the ONLY code that may reach a UAC prompt, and
 *     a bug that widened it would raise prompts a person cannot act on.
 *   - **`worthStarting`**, because it decides whether a process is spawned at
 *     all on a 20-second cadence for the life of a window.
 *   - **the backoff table**, read out of `pipeTransport.ts` itself, because the
 *     numbers are the difference between a connection landing while the window
 *     paints and one landing three seconds later.
 *
 * Plain `tsx`, no Electron: `serviceStart.ts` imports nothing, which is why it
 * is a module beside `agentPipe.ts` rather than a method inside it.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  classifyStart,
  MAX_AUTO_START_ATTEMPTS,
  SC_ACCESS_DENIED,
  SC_ALREADY_RUNNING,
  SC_DEPENDENCY_FAILED,
  SC_DISABLED,
  SC_NO_SUCH_SERVICE,
  SC_OK,
  SC_REQUEST_TIMEOUT,
  worthStarting,
  type StartOutcome,
} from '../../electron/serviceStart';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const read = (rel: string) => readFileSync(path.join(root, rel), 'utf8');

let failures = 0;
function check(ok: boolean, what: string, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}${detail && !ok ? ` - ${detail}` : ''}`);
  if (!ok) failures += 1;
}

console.log('--- what sc.exe said ---\n');

const cases: Array<[number | null, StartOutcome, string]> = [
  [SC_OK, 'running', 'started'],
  [SC_ALREADY_RUNNING, 'running', 'already running'],
  [SC_ACCESS_DENIED, 'needsElevation', 'the only code a prompt can fix'],
  [SC_REQUEST_TIMEOUT, 'retry', 'slow, not broken'],
  [SC_DISABLED, 'hopeless', 'an administrator turned it off'],
  [SC_NO_SUCH_SERVICE, 'hopeless', 'not installed'],
  [SC_DEPENDENCY_FAILED, 'hopeless', 'a dependency failed'],
  [null, 'retry', 'could not run sc.exe at all'],
];

for (const [code, expected, what] of cases) {
  const got = classifyStart(code).outcome;
  check(got === expected, `${String(code)} -> ${expected} (${what})`, `got ${got}`);
}

// The invariant with a UAC prompt behind it. Every other code must reach some
// other verdict, or a person gets a prompt that cannot help them - and on a
// machine where the service is uninstalled, one they have no way to evaluate.
const elevating = [...cases.map(([code]) => code), 1, 2, 87, 1072, 1077]
  .filter((code) => classifyStart(code).outcome === 'needsElevation');
check(
  elevating.length === 1 && elevating[0] === SC_ACCESS_DENIED,
  'ACCESS_DENIED is the only code that escalates',
  `also escalated on ${elevating.filter((c) => c !== SC_ACCESS_DENIED).join(', ')}`,
);

// An unknown number proves nothing about the service, so it must not be read
// as a permanent failure. The attempt budget is what stops it retrying for
// ever - which is asserted below rather than assumed.
check(classifyStart(4242).outcome === 'retry', 'an unrecognised code is retryable, not hopeless');
check(MAX_AUTO_START_ATTEMPTS > 0 && MAX_AUTO_START_ATTEMPTS <= 5,
  'the automatic attempt budget is small and non-zero',
  `it is ${MAX_AUTO_START_ATTEMPTS}`);

console.log('\n--- whether to ask at all ---\n');

check(worthStarting({ installed: true, startType: 'manual' }),
  'manual is the shipped configuration and gets an attempt');
check(worthStarting({ installed: true, startType: 'auto' }),
  'auto still gets one - an upgrade from before ADR 0035 is still auto');
check(!worthStarting({ installed: true, startType: 'disabled' }),
  'disabled does not: the SCM will refuse, and the registry already said so');
check(!worthStarting({ installed: false, startType: 'unknown' }),
  'not installed does not');
// The rule this codebase keeps repeating, and the one a rewrite of
// `worthStarting` would most easily lose: `provesAbsent` exists precisely so
// that failing to ask is never turned into an answer.
check(worthStarting({ installed: true, startType: 'unknown' }),
  'unknown DOES get an attempt - not knowing how it starts is not knowing it cannot');

console.log('\n--- the backoff, read out of the transport ---\n');

const transport = read('electron/pipeTransport.ts');
const table = /const FAST_RETRY_MS = \[([^\]]+)\]/.exec(transport);
check(table !== null, 'pipeTransport.ts declares FAST_RETRY_MS');
if (table) {
  const steps = table[1].split(',').map((n) => Number(n.trim())).filter((n) => !Number.isNaN(n));
  check(steps.length >= 3, 'there are enough fast steps to cover a service start',
    `found ${steps.length}`);
  check(steps.every((n, i) => i === 0 || n > steps[i - 1]),
    'the steps increase',
    steps.join(', '));
  check(steps[0] <= 200,
    'the first retry is fast enough to catch a warm start',
    `it is ${steps[0]}ms`);
  const total = steps.reduce((a, b) => a + b, 0);
  check(total <= 3000,
    'the fast steps settle within the old flat cadence',
    `they sum to ${total}ms`);
}

// The reset rule, which is the half that is easy to drop in an edit. A backoff
// that is only ever reset by `open()` would stay backed off across the agent's
// own idle stop and restart - which is now the ordinary case, not an error.
check(/this\.attempt = 0;/.test(transport.slice(transport.indexOf("socket.once('close'"))),
  'a connection that lasted re-arms the fast steps');

console.log('\n--- the installed service is demand-start ---\n');

const iss = read('installer/setup.iss');
check(/--startup manual install/.test(iss),
  'the installer registers the service as manual');
check(!/--startup auto install/.test(iss),
  'and no auto-start registration survives');

// The app has to actually ask, or demand start is just a service that never
// runs. `ensureRunning` before `createWindow` is what makes the link land
// while the window is still painting.
const main = read('electron/main.ts');
check(/agent\.ensureRunning\(\);/.test(main), 'main asks for the agent at startup');
check(main.indexOf('agent.ensureRunning()') < main.indexOf('await createWindow()'),
  'and it asks before the window, so a slow SCM delays the agent and not the UI');

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All service-start checks passed.');
process.exit(0);
