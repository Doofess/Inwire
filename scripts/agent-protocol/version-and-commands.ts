/**
 * Assertion tests for agentProtocol.ts's version comparison and command
 * encoding.
 *
 *   npx tsx scripts/agent-protocol/version-and-commands.ts
 */
import { encodeAgentCommand, isAgentOutdated, REQUIRED_AGENT_VERSION } from '../../src/services/agentProtocol';

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

check('exact match is not outdated', isAgentOutdated('1.1.0', '1.1.0'), false);
check('lower patch is outdated', isAgentOutdated('1.1.0', '1.1.1'), true);
check('lower minor is outdated', isAgentOutdated('1.1.0', '1.2.0'), true);
check('lower major is outdated', isAgentOutdated('1.1.0', '2.0.0'), true);
check('higher patch is not outdated', isAgentOutdated('1.1.5', '1.1.0'), false);
check('minor beats patch: 1.9.9 vs 1.10.0 is outdated', isAgentOutdated('1.9.9', '1.10.0'), true);
check('minor beats patch: 1.10.0 vs 1.9.9 is not outdated', isAgentOutdated('1.10.0', '1.9.9'), false);
check('missing patch segment treated as 0: 1.0 vs 1.0.5 is outdated', isAgentOutdated('1.0', '1.0.5'), true);
check('missing patch segment treated as 0: 1.0.5 vs 1.0 is not outdated', isAgentOutdated('1.0.5', '1.0'), false);
check('missing minor and patch: 1 vs 1.0.1 is outdated', isAgentOutdated('1', '1.0.1'), true);

check('start_capture encodes', encodeAgentCommand({ type: 'start_capture' }), '{"type":"start_capture"}');
check('stop_capture encodes', encodeAgentCommand({ type: 'stop_capture' }), '{"type":"stop_capture"}');
check('set_interfaces encodes', encodeAgentCommand({ type: 'set_interfaces', interfaces: ['eth0', 'eth1'] }), '{"type":"set_interfaces","interfaces":["eth0","eth1"]}');

// 3.0.0 is the rename: the service, its data directory and its URI scheme all
// changed name, so an older agent is not merely missing a command - it is a
// different install. Major, not minor. This constant has to move with
// AGENT_VERSION in agent.py and MyAppVersion in setup.iss;
// local-agent/test_protocol.py is what enforces that all three agree.
check('required agent version is 3.6.0', REQUIRED_AGENT_VERSION, '3.6.0');

// Pairing. The token goes on the wire as an ordinary command rather than in
// the handshake, because a handshake this agent refuses reaches the browser as
// an opaque error indistinguishable from "the agent is not running".
check('authenticate encodes', encodeAgentCommand({ type: 'authenticate', token: 'abc' }),
  '{"type":"authenticate","token":"abc"}');

// The command exists so Driver Info can ask the agent to restart itself. The
// agent refuses it unless it can prove something would start it again - see
// decide_restart_allowed in agent.py.
check('restart_agent encodes', encodeAgentCommand({ type: 'restart_agent' }), '{"type":"restart_agent"}');
check('a 1.1.0 agent is outdated against 2.4.0', isAgentOutdated('1.1.0', '2.4.0'), true);
check('a 2.3.0 agent is outdated against 2.4.0', isAgentOutdated('2.3.0', '2.4.0'), true);
check('a 2.4.0 agent is current', isAgentOutdated('2.4.0', '2.4.0'), false);
check('a 2.5.0 agent is not outdated', isAgentOutdated('2.5.0', '2.4.0'), false);

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
