/**
 * The commands the app sends, as bytes, checked against the app's own encoder.
 *
 * ## Why this exists, which is a bug that shipped
 *
 * `control-vectors.json` covers the messages the agent **emits**, checked
 * against the app's parser. Nothing covered the other direction, and the gap
 * cost a working capture:
 *
 * `set_interfaces` carries device **names** - `AgentCommand` declares
 * `interfaces: string[]`, and `local-agent/agent.py` spawns one sniffer per
 * entry by name. The Rust agent parsed the field with `as_u64` and treated the
 * entries as **indices into its own list**. The app's message therefore did not
 * parse at all; the selection stayed unset; and `start_capture` fell back to
 * adapter 0, which on the machine this was found on is a dead
 * `WAN Miniport (Network Monitor)`. The agent opened it, reported `sniffing`
 * perfectly truthfully, and delivered zero frames for ever.
 *
 * **Both ends agreed and both were wrong**, which is the part worth designing
 * against. `agent-interop.ts` - the harness whose whole purpose is to be "the
 * app's own client" - sent `interfaces: [wanted.id]`, a number, because it was
 * written while reading the Rust implementation. Its capture worked perfectly.
 * The Rust unit test asserted `[0,2]` parsed to `vec![0, 2]`. Every test passed
 * for as long as the bug existed, because each end was checked against itself.
 *
 * So the fixture is the authority here, exactly as `wire-vectors.json` is for
 * the frame format: this script holds it to what the app's own
 * `encodeAgentCommand` produces, and `agent-rs`'s `command_vectors` test holds
 * the Rust parser to the same file. Neither implementation can move without the
 * other noticing.
 *
 * ## Exhaustiveness is the type checker's job
 *
 * `SAMPLES` is a `Record<AgentCommand['type'], AgentCommand>`, so a command
 * added to the union does not compile until it has a sample here - and the
 * sample then has to be added to the JSON, which the Rust side then has to
 * parse. That chain is the point: a new command cannot reach the agent without
 * the agent being asked whether it understands it.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { encodeAgentCommand, type AgentCommand } from '../../src/services/agentProtocol';

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
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/**
 * One sample per command. A `Record` keyed on the union's own `type` field, so
 * this fails to compile the day a command is added.
 *
 * The `set_interfaces` sample carries a real device path, backslashes and
 * braces included, because that is the shape that actually travels - a sample
 * reading `"eth0"` would have passed against a parser that accepted any string
 * and taught nobody anything.
 */
const SAMPLES: Record<AgentCommand['type'], AgentCommand> = {
  start_capture: { type: 'start_capture' },
  stop_capture: { type: 'stop_capture' },
  set_interfaces: { type: 'set_interfaces', interfaces: ['\\Device\\NPF_{A}'] },
  subscribe_logs: { type: 'subscribe_logs' },
  unsubscribe_logs: { type: 'unsubscribe_logs' },
  subscribe_interface_stats: { type: 'subscribe_interface_stats' },
  unsubscribe_interface_stats: { type: 'unsubscribe_interface_stats' },
  subscribe_sockets: { type: 'subscribe_sockets' },
  unsubscribe_sockets: { type: 'unsubscribe_sockets' },
  subscribe_adapters: { type: 'subscribe_adapters' },
  unsubscribe_adapters: { type: 'unsubscribe_adapters' },
  refresh_adapters: { type: 'refresh_adapters' },
  restart_agent: { type: 'restart_agent' },
};

const VECTORS = path.join('scripts', 'agent', 'command-vectors.json');

console.log('--- the app\'s commands, as they go on the wire ---\n');

const encoded = Object.values(SAMPLES).map(encodeAgentCommand);
const file = JSON.parse(readFileSync(VECTORS, 'utf8')) as { commands: string[]; note?: string };

check('every command in the union has a vector', file.commands.length, encoded.length);
check('...and each is byte-for-byte what encodeAgentCommand produces', file.commands, encoded);

// The one that was wrong, named on its own so a regression reports itself as
// the thing it is rather than as a diff of thirteen strings.
const setInterfaces = JSON.parse(
  file.commands.find((c) => c.includes('set_interfaces')) ?? '{}',
) as { interfaces?: unknown[] };
checkTrue('set_interfaces carries strings, not numbers',
  Array.isArray(setInterfaces.interfaces)
  && setInterfaces.interfaces.length > 0
  && setInterfaces.interfaces.every((i) => typeof i === 'string'));

// A device path is the thing that travels, and it is the case an implementation
// is most likely to mangle - backslashes survive JSON and braces are not a
// format string.
checkTrue('...and a real device path survives encoding',
  setInterfaces.interfaces?.[0] === '\\Device\\NPF_{A}');

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  console.log(`\nIf the union changed on purpose, the vectors are:\n`);
  console.log(JSON.stringify({ commands: encoded }, null, 2));
  process.exit(1);
}
console.log('All command-vector checks passed.');
process.exit(0);
