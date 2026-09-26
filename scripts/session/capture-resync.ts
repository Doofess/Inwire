/**
 * A reconnect mid-capture must not be undone by the agent's answer to it.
 *
 *   npx tsx scripts/session/capture-resync.ts
 *
 * After a pipe break mid-capture the app's `hello` handler resends the
 * selection and then `start_capture`. Both agents answer `set_interfaces` with a
 * `state` broadcast (agent.py:1385; the Rust agent's `control.rs`), and it says
 * **idle**, because the start behind it has not been processed yet. The state
 * handler treated every idle-while-capturing as the agent's verdict and called
 * `onCaptureStopped()` - so the capture the start then began ran on the agent
 * while the window said it had stopped.
 *
 * `services/captureResync.ts` is the decision, lifted out of the hook so it can
 * be driven here without React. The sequences below are what each agent
 * actually sends, in order, on one connection.
 */
import { readFileSync } from 'node:fs';
import {
  NO_RESYNC, planResync, readReply, type AgentReply, type Resync,
} from '../../src/services/captureResync';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

/** Folds a reply sequence; answers whether the window ended up stopped. */
function run(resync: Resync, replies: AgentReply[], capturing = true): boolean {
  let stopped = false;
  let state = resync;
  for (const reply of replies) {
    const read = readReply(state, reply, capturing && !stopped);
    state = read.resync;
    if (read.stopped) stopped = true;
  }
  return stopped;
}

/** What the handler did before: every idle while capturing stopped it. */
function runOld(replies: AgentReply[]): boolean {
  return replies.some((r) => r.type === 'state' && r.state === 'idle');
}

const idle: AgentReply = { type: 'state', state: 'idle' };
const sniffing: AgentReply = { type: 'state', state: 'sniffing' };
const error: AgentReply = { type: 'error' };

console.log('--- what hello sends ---');
const resuming = planResync({ ownedElsewhere: false, selected: ['\\Device\\NPF_{A}'], capturing: true });
check('a capture is resumed: the selection, then the start',
  resuming.commands.map((c) => c.type), ['set_interfaces', 'start_capture']);
check('...and the selection\'s own answer is expected', resuming.resync.awaitingSelectionReply, true);
check('the selection travels as it was',
  resuming.commands[0], { type: 'set_interfaces', interfaces: ['\\Device\\NPF_{A}'] });
check('not capturing: the selection alone, and nothing to lose to its answer',
  planResync({ ownedElsewhere: false, selected: ['a'], capturing: false }),
  { commands: [{ type: 'set_interfaces', interfaces: ['a'] }], resync: NO_RESYNC });
check('another window owns the capture: nothing is sent',
  planResync({ ownedElsewhere: true, selected: ['a'], capturing: true }),
  { commands: [], resync: NO_RESYNC });
check('no selection: only the start, with no selection answer to wait for',
  planResync({ ownedElsewhere: false, selected: [], capturing: true }),
  { commands: [{ type: 'start_capture' }], resync: NO_RESYNC });

console.log();
console.log('--- the replies, as the agents send them ---');
// Python and Rust alike: set_interfaces while idle -> state idle; start -> state sniffing.
const resumed = [idle, sniffing];
check('THE BUG: the old handler stopped a resumed capture on the selection\'s idle', runOld(resumed), true);
check('a resumed capture keeps capturing', run(resuming.resync, resumed), false);

// Rust, when nothing opens: capture_failed per adapter, then idle.
check('a resume whose start fails still stops - on the START\'s idle',
  run(resuming.resync, [idle, error, error, idle]), true);
// Rust with no adapters at all: no_interfaces, then idle.
check('...and on a no_interfaces refusal', run(resuming.resync, [idle, error, idle]), true);
// Python, when nothing opens: sniffing first, the failures, then idle.
check('...and on Python\'s sniffing-then-idle', run(resuming.resync, [idle, sniffing, error, idle]), true);
// A refused selection answers with an error and no state.
check('a refused selection ends the wait, so a failed start still stops',
  run(resuming.resync, [error, idle]), true);
check('...and a working start after a refused selection keeps capturing',
  run(resuming.resync, [error, sniffing]), false);

console.log();
console.log('--- outside a resync, idle is still the agent\'s verdict ---');
check('every adapter died mid-capture: stopped', run(NO_RESYNC, [idle]), true);
check('not capturing: an idle stops nothing', run(NO_RESYNC, [idle], false), false);
check('only the FIRST state after the resync is consumed',
  run(resuming.resync, [idle, sniffing, idle]), true);

console.log();
console.log('--- the hook uses it ---');
const hook = readFileSync('src/hooks/useAgentConnection.ts', 'utf8');
check('the hello handler plans with planResync', /planResync\(/.test(hook), true);
check('the state handler reads with readReply', /readReply\(resync, message/.test(hook), true);
check('the inline idle rule that caused it is gone',
  /message\.state === 'idle' && isCapturingRef\.current/.test(hook), false);

console.log();
if (failures) {
  console.log(`${failures} capture-resync check(s) FAILED`);
  process.exit(1);
}
console.log('All capture-resync checks passed.');
