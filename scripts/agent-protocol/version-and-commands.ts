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

check('required agent version is 2.1.0', REQUIRED_AGENT_VERSION, '2.1.0');
check('a 1.1.0 agent is outdated against 2.1.0', isAgentOutdated('1.1.0', '2.1.0'), true);
check('a 2.0.0 agent is outdated against 2.1.0', isAgentOutdated('2.0.0', '2.1.0'), true);
check('a 2.1.0 agent is current', isAgentOutdated('2.1.0', '2.1.0'), false);
check('a 2.2.0 agent is not outdated', isAgentOutdated('2.2.0', '2.1.0'), false);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
