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

const hello = parseAgentMessage('{"type":"hello","version":"1.1.0","state":"idle","interfaces":[{"name":"eth0","label":"Ethernet"}]}');
check('valid hello parses', hello, { type: 'hello', version: '1.1.0', state: 'idle', interfaces: [{ name: 'eth0', label: 'Ethernet' }] });
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

check('hello with invalid state enum value returns null', parseAgentMessage('{"type":"hello","version":"1.0.0","state":"exploded","interfaces":[]}'), null);
check('state with invalid enum value returns null', parseAgentMessage('{"type":"state","state":"exploded","interfaces":[]}'), null);
check('state with malformed interface entries returns null', parseAgentMessage('{"type":"state","state":"idle","interfaces":["oops"]}'), null);
check('state with interface entry missing label returns null', parseAgentMessage('{"type":"state","state":"idle","interfaces":[{"name":"eth0"}]}'), null);

// A hello with no authRequired field must still parse - the field is gone
// from the 2.0.0 protocol entirely.
check(
  'hello parses without authRequired',
  parseAgentMessage(JSON.stringify({
    type: 'hello', version: '2.0.0', state: 'idle',
    interfaces: [{ name: 'eth0', label: 'Ethernet' }],
  }))?.type,
  'hello',
);

// A stray authRequired from an older agent is ignored, not rejected.
check(
  'hello tolerates a leftover authRequired field',
  parseAgentMessage(JSON.stringify({
    type: 'hello', version: '1.1.0', state: 'idle', authRequired: true,
    interfaces: [],
  }))?.type,
  'hello',
);

const logMsg = parseAgentMessage('{"type":"log","lines":[{"time":"2026-08-26 22:14:02,123","level":"INFO","message":"client connected"}]}');
check('valid log message parses', logMsg, {
  type: 'log',
  lines: [{ time: '2026-08-26 22:14:02,123', level: 'INFO', message: 'client connected' }],
});
check('log with an empty lines array parses', parseAgentMessage('{"type":"log","lines":[]}'), { type: 'log', lines: [] });
check(
  'log entry with null time and level parses (unparseable backlog line)',
  parseAgentMessage('{"type":"log","lines":[{"time":null,"level":null,"message":"  File \\"agent.py\\", line 42"}]}'),
  { type: 'log', lines: [{ time: null, level: null, message: '  File "agent.py", line 42' }] },
);
check('log missing lines returns null', parseAgentMessage('{"type":"log"}'), null);
check('log with lines not an array returns null', parseAgentMessage('{"type":"log","lines":"nope"}'), null);
check('log with a non-object entry returns null', parseAgentMessage('{"type":"log","lines":["nope"]}'), null);
check('log with an entry missing message returns null', parseAgentMessage('{"type":"log","lines":[{"time":null,"level":"INFO"}]}'), null);
check('log with a non-string message returns null', parseAgentMessage('{"type":"log","lines":[{"time":null,"level":null,"message":42}]}'), null);
check('log with a non-string level returns null', parseAgentMessage('{"type":"log","lines":[{"time":null,"level":7,"message":"x"}]}'), null);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
