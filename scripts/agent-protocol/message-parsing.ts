/**
 * Assertion tests for agentProtocol.ts's pure message parsing.
 *
 *   npx tsx scripts/agent-protocol/message-parsing.ts
 */
import { parseAgentMessage, summarizeCaptureStats } from '../../src/services/agentProtocol';
import type { AgentCaptureStatsMessage } from '../../src/services/agentProtocol';

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

// --- 3.1.0: interface ids, capture_stats, error codes -------------------------

check('interface entries may carry an id',
  parseAgentMessage('{"type":"state","state":"idle","interfaces":[{"id":0,"name":"eth0","label":"Ethernet"}]}'),
  { type: 'state', state: 'idle', interfaces: [{ id: 0, name: 'eth0', label: 'Ethernet' }] });
check('...but a non-integer id is rejected',
  parseAgentMessage('{"type":"state","state":"idle","interfaces":[{"id":"zero","name":"eth0","label":"Ethernet"}]}'), null);

const stats = parseAgentMessage(JSON.stringify({
  type: 'capture_stats', intervalMs: 1000, seqHigh: 42, droppedAgent: 3,
  interfaces: [{ iface: 0, received: 42, kernelReceived: 45, droppedKernel: 3 }],
}));
check('valid capture_stats parses', stats?.type, 'capture_stats');
check('capture_stats: null kernel counters mean unknown and are allowed',
  parseAgentMessage(JSON.stringify({
    type: 'capture_stats', intervalMs: 1000, seqHigh: 0, droppedAgent: 0,
    interfaces: [{ iface: 0, received: 0, kernelReceived: null, droppedKernel: null }],
  }))?.type,
  'capture_stats');
check('capture_stats missing droppedAgent returns null',
  parseAgentMessage('{"type":"capture_stats","intervalMs":1000,"seqHigh":0,"interfaces":[]}'), null);
check('capture_stats with a negative count returns null',
  parseAgentMessage('{"type":"capture_stats","intervalMs":1000,"seqHigh":0,"droppedAgent":-1,"interfaces":[]}'), null);
check('capture_stats with a malformed interface entry returns null',
  parseAgentMessage('{"type":"capture_stats","intervalMs":1000,"seqHigh":0,"droppedAgent":0,"interfaces":[{"iface":0}]}'), null);

// --- droppedPipe: the third loss site, added without breaking the second ---------
//
// Frames shed from the outbound pipe queue when the client is not reading fast
// enough. It had no counter at all - `write()` discarded them and set a flag
// `send()` did not test - so every one of them was invisible.
//
// Additive and OPTIONAL, which is the whole compatibility story: an agent that
// predates it omits the field, and an omitted field is `null` downstream, never
// 0. "None were lost here" and "nobody counted" are different facts, and this
// repo has the `agentSilentLabel` post-mortem for what happens when a missing
// value is given a confident default.
check('capture_stats without droppedPipe still parses',
  parseAgentMessage('{"type":"capture_stats","intervalMs":1000,"seqHigh":0,"droppedAgent":0,"interfaces":[]}')?.type,
  'capture_stats');
check('...and summarises as unknown rather than none',
  summarizeCaptureStats(parseAgentMessage(
    '{"type":"capture_stats","intervalMs":1000,"seqHigh":0,"droppedAgent":0,"interfaces":[]}',
  ) as AgentCaptureStatsMessage).droppedPipe, null);
check('capture_stats with droppedPipe carries the number',
  summarizeCaptureStats(parseAgentMessage(
    '{"type":"capture_stats","intervalMs":1000,"seqHigh":0,"droppedAgent":0,"droppedPipe":7,"interfaces":[]}',
  ) as AgentCaptureStatsMessage).droppedPipe, 7);
check('...and zero is reported as zero, not as unknown',
  summarizeCaptureStats(parseAgentMessage(
    '{"type":"capture_stats","intervalMs":1000,"seqHigh":0,"droppedAgent":0,"droppedPipe":0,"interfaces":[]}',
  ) as AgentCaptureStatsMessage).droppedPipe, 0);
// A field that is present and wrong is a malformed message, not a missing one.
// Accepting it would put a negative into a figure the status bar adds up.
check('a negative droppedPipe returns null',
  parseAgentMessage('{"type":"capture_stats","intervalMs":1000,"seqHigh":0,"droppedAgent":0,"droppedPipe":-1,"interfaces":[]}'), null);
check('a non-numeric droppedPipe returns null',
  parseAgentMessage('{"type":"capture_stats","intervalMs":1000,"seqHigh":0,"droppedAgent":0,"droppedPipe":"lots","interfaces":[]}'), null);

// --- adapter_config (3.6.0) ---------------------------------------------------
//
// The validator here is deliberately permissive about every field but `id`,
// and these assertions are what hold it to that. A provider that could not
// read a lease time reports null - that is the contract - so a message full of
// nulls has to survive, or the app would discard the half the OS did know.
const adapter = {
  id: '\Device\NPF_{ABC}', name: 'Ethernet 2', description: 'Intel I225-V',
  mac: '04:7c:16:52:db:17', status: 'up', speedMbps: 2500, mtu: 1500,
  dhcpEnabled: true, dhcpServer: '10.0.0.138',
  leaseObtained: 1788655468, leaseExpires: 1788659068,
  ipv4: [{ address: '10.0.0.4', prefixLength: 24, broadcast: '10.0.0.255' }],
  ipv6: [{ address: 'fe80::1', prefixLength: 64, scope: 'link-local', temporary: false }],
  gatewayV4: '10.0.0.138', gatewayV6: null, gatewayMac: '44:15:24:5d:cc:62',
  dnsServers: ['10.0.0.138'], dnsSuffix: 'home', source: { dhcp: 'registry' },
};
check('valid adapter_config parses',
  parseAgentMessage(JSON.stringify({ type: 'adapter_config', adapters: [adapter] }))?.type,
  'adapter_config');
check('an adapter the OS could answer almost nothing about still parses',
  parseAgentMessage(JSON.stringify({
    type: 'adapter_config',
    adapters: [{
      id: 'eth0', name: 'eth0', description: null, mac: null, status: null,
      speedMbps: null, mtu: null, dhcpEnabled: null, dhcpServer: null,
      leaseObtained: null, leaseExpires: null, ipv4: [], ipv6: [],
      gatewayV4: null, gatewayV6: null, gatewayMac: null,
      dnsServers: [], dnsSuffix: null, source: {},
    }],
  }))?.type,
  'adapter_config');
// `id` is the join key to a capture interface. An entry without one has
// nowhere to attach, so it is the single field that is not optional.
check('an adapter with no id returns null',
  parseAgentMessage(JSON.stringify({ type: 'adapter_config', adapters: [{ ...adapter, id: '' }] })), null);
check('adapter_config with a non-array adapters returns null',
  parseAgentMessage('{"type":"adapter_config","adapters":{}}'), null);
check('an empty adapter list is legitimate - a machine may have none we can read',
  parseAgentMessage('{"type":"adapter_config","adapters":[]}')?.type, 'adapter_config');

check('error carries its code and interface through',
  parseAgentMessage('{"type":"error","code":"capture_failed","iface":1,"message":"no"}'),
  { type: 'error', code: 'capture_failed', iface: 1, message: 'no' });

check('a 3.1 packet keeps seq, iface and tsUs',
  parseAgentMessage('{"type":"packet","seq":7,"iface":1,"tsUs":1788477971653284,"raw":""}'),
  { type: 'packet', seq: 7, iface: 1, tsUs: 1788477971653284, raw: '' });

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
