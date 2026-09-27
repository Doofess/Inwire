/**
 * Assertion tests for agentProtocol.ts's version comparison and command
 * encoding.
 *
 *   npx tsx scripts/agent-protocol/version-and-commands.ts
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeAgentCommand, isAgentMismatched, REQUIRED_AGENT_VERSION } from '../../src/services/agentProtocol';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${expected}`);
    console.log(`        actual   ${actual}`);
  }
}

// Equality, not order (ADR 0051): an agent from any other build is one a
// different install left behind, whichever way the number moved.
check('exact match is this build', isAgentMismatched('0.4.1', '0.4.1'), false);
check('lower patch is mismatched', isAgentMismatched('0.4.0', '0.4.1'), true);
check('lower minor is mismatched', isAgentMismatched('0.3.9', '0.4.1'), true);
check('higher patch is mismatched too', isAgentMismatched('0.4.2', '0.4.1'), true);
check('an agent from before the 0.x reset is mismatched', isAgentMismatched('4.1.0', '0.4.1'), true);
check('...and so is the 4.0.0 one', isAgentMismatched('4.0.0', '0.4.1'), true);
check('segments are numbers: 0.4.01 is 0.4.1', isAgentMismatched('0.4.01', '0.4.1'), false);
check('segments are numbers: 0.10.0 is not 0.1.0', isAgentMismatched('0.10.0', '0.1.0'), true);
check('a missing patch segment is 0: 0.4 is 0.4.0', isAgentMismatched('0.4', '0.4.0'), false);
check('a missing patch segment is 0: 0.4 is not 0.4.1', isAgentMismatched('0.4', '0.4.1'), true);

check('start_capture encodes', encodeAgentCommand({ type: 'start_capture' }), '{"type":"start_capture"}');
check('stop_capture encodes', encodeAgentCommand({ type: 'stop_capture' }), '{"type":"stop_capture"}');
check('set_interfaces encodes', encodeAgentCommand({ type: 'set_interfaces', interfaces: ['eth0', 'eth1'] }), '{"type":"set_interfaces","interfaces":["eth0","eth1"]}');

// **Read from package.json rather than pinned to a literal**, which is the
// change ADR 0035 made here. A hardcoded `'3.9.0'` was one of six stamps that
// had to move together by hand, and the only thing it actually asserted was
// that somebody had edited this line too - it could not catch drift, because it
// WAS the drift. The agent's version is the product's now, so the real
// assertion is that this constant equals the one place a version is authored.
//
// The rest of the lock - the generated `agent_version.py`, the installer, and
// the stamps' shape - is `scripts/agent/version.ts`.
const productVersion = (
  JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../../package.json'), 'utf8')) as
    { version: string }
).version;
check('REQUIRED_AGENT_VERSION is the product version', REQUIRED_AGENT_VERSION, productVersion);

// `authenticate` was here, and is gone with the pairing token. The kernel
// answers the question it was asked to answer: on Windows the agent's only
// transport is a named pipe whose security descriptor names who may open it,
// so there is nothing to present and nothing to paste.

check('this build\'s own agent is not mismatched',
  isAgentMismatched(REQUIRED_AGENT_VERSION, REQUIRED_AGENT_VERSION), false);

// 3.6.0: how this machine's adapters are configured. Subscribed for the same
// reason the socket table is - reading it spawns PowerShell on Windows when
// the address list has moved, and a client that never opens the Network panel
// should not pay for that.
check('subscribe_adapters encodes', encodeAgentCommand({ type: 'subscribe_adapters' }), '{"type":"subscribe_adapters"}');
check('unsubscribe_adapters encodes', encodeAgentCommand({ type: 'unsubscribe_adapters' }), '{"type":"unsubscribe_adapters"}');
// Distinct from subscribing, and it has to be: subscribing is answered from
// whatever the agent has, while this drops the cache first. A Refresh that
// replied with a reading taken before the user changed something would be
// the one answer guaranteed to be wrong.
check('refresh_adapters encodes', encodeAgentCommand({ type: 'refresh_adapters' }), '{"type":"refresh_adapters"}');

check('subscribe_logs encodes', encodeAgentCommand({ type: 'subscribe_logs' }), '{"type":"subscribe_logs"}');
check('unsubscribe_logs encodes', encodeAgentCommand({ type: 'unsubscribe_logs' }), '{"type":"unsubscribe_logs"}');

// 3.4.0: which process owns which socket. Subscribed rather than always-on, so
// a client that never asks never causes the table to be read at all.
check('subscribe_sockets encodes', encodeAgentCommand({ type: 'subscribe_sockets' }), '{"type":"subscribe_sockets"}');
check('unsubscribe_sockets encodes', encodeAgentCommand({ type: 'unsubscribe_sockets' }), '{"type":"unsubscribe_sockets"}');

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
