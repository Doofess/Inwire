/**
 * Assertion tests for agentProtocol.ts's pure message parsing.
 *
 *   npx tsx scripts/agent-protocol/message-parsing.ts
 */
import { parseAgentMessage } from '../../src/services/agentProtocol';

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

check('malformed JSON returns null', parseAgentMessage('{not json'), null);
check('non-object JSON returns null', parseAgentMessage('42'), null);
check('unknown type returns null', parseAgentMessage('{"type":"mystery"}'), null);
check('missing type returns null (legacy untyped packet is dropped, per spec)', parseAgentMessage('{"source":"1.2.3.4"}'), null);

const hello = parseAgentMessage('{"type":"hello","version":"1.1.0","state":"idle","authRequired":true,"interfaces":[{"name":"eth0","label":"Ethernet"}]}');
check('valid hello parses', hello, { type: 'hello', version: '1.1.0', state: 'idle', authRequired: true, interfaces: [{ name: 'eth0', label: 'Ethernet' }] });
check('hello missing version returns null', parseAgentMessage('{"type":"hello","state":"idle","interfaces":[]}'), null);
check('hello missing interfaces returns null', parseAgentMessage('{"type":"hello","version":"1.0.0"}'), null);

const state = parseAgentMessage('{"type":"state","state":"sniffing","interfaces":[]}');
check('valid state parses', state, { type: 'state', state: 'sniffing', interfaces: [] });
check('state missing state field returns null', parseAgentMessage('{"type":"state","interfaces":[]}'), null);

const err = parseAgentMessage('{"type":"error","message":"nope"}');
check('valid error parses', err, { type: 'error', message: 'nope' });
check('error missing message returns null', parseAgentMessage('{"type":"error"}'), null);

const pkt = parseAgentMessage('{"type":"packet","source":"1.2.3.4","destination":"5.6.7.8"}');
check('packet passes through with all its fields', pkt, { type: 'packet', source: '1.2.3.4', destination: '5.6.7.8' });

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
