/**
 * Every message the app can read, and whether the Rust agent can send it.
 *
 *   npx tsx scripts/agent/message-coverage.ts
 *
 * ## What this is for
 *
 * ADR 0037's "not ported" list was written from what was **consciously
 * skipped** rather than from the protocol, and the ADR says so. That is how
 * `interface_stats` was missed: the Rust agent parsed `subscribe_interface_stats`
 * and answered with a generic `state`, so the app subscribed successfully and
 * then waited for rates that never arrived - a flat sparkline rather than an
 * absent feature, with nothing erroring anywhere. `adapter_config` was missed
 * the same way, and that one cost every frame its direction and painted a
 * third of a capture as broken checksums.
 *
 * Neither had a symptom a test could see, because **both ends were internally
 * consistent**: the app's parser accepted what it was sent and the agent sent
 * nothing. The only thing that can catch the shape is a list of what the app
 * can read, checked against what the agent can write - which is what this is.
 *
 * ## Why it reads source text rather than importing
 *
 * `agent-rs` is Rust and this is a `tsx` script, so there is nothing to
 * import. The app's half IS imported - the `type: '...'` literals come out of
 * `agentProtocol.ts`'s own source - so a message added to the union is in this
 * check on the commit that adds it, whether or not anybody remembered to.
 *
 * A grep for the wire string in `agent-rs/src/` is a weak proof and is
 * deliberately weak in the safe direction: it can pass on a string that only
 * appears in a comment, and it cannot pass on a message nobody has written
 * down at all. The failures this exists to catch are of the second kind.
 *
 * ## The allow-list is the point
 *
 * A message the Rust agent deliberately does not serve is fine and must say so
 * here, with the reason. That turns "not ported" from a memory into a list
 * that a commit has to edit - which is the difference between the ADR's list
 * and this one.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

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

function text(relative: string): string {
  try {
    return readFileSync(join(root, relative), 'utf8');
  } catch {
    failures++;
    console.log(`FAIL  ${relative} could not be read`);
    return '';
  }
}

/**
 * Messages the Rust agent does not send, and why.
 *
 * **Each entry is a decision with a date on it, not a shrug.** Deleting an
 * entry is how a port is declared done; adding one is a statement that the app
 * will go without. A message in neither this list nor the agent's source is
 * the failure this script exists for.
 */
const UNSERVED: Record<string, string> = {
  // Only the app sends these; the agent never does. They are in
  // `AgentMessage` because the union is what `parseAgentMessage` answers with,
  // and `packet` is the binary path's JSON shadow - a real frame arrives as
  // `FRAME_BINARY` and is decoded by `agentBinary.ts`, never as this.
  packet: 'the binary frame path, which has no JSON form on the wire '
    + '(src/services/agentBinary.ts)',
};

// --- what the app can read ---------------------------------------------------

const protocol = text('src/services/agentProtocol.ts');

/**
 * The `type: '...'` literals of the message interfaces.
 *
 * Read from the source rather than from a list kept here, so a message added
 * to `AgentMessage` is checked by this script without anybody adding it twice.
 * The command union in the same file uses `| { type: 'x' }` rather than a
 * `type: 'x';` property, so this pattern separates the two without needing to
 * know either list.
 */
const appReads = [...protocol.matchAll(/^\s{2}type: '([a-z_]+)';$/gm)]
  .map((m) => m[1])
  .sort();

check('the app declares the messages this build expects', appReads, [
  'adapter_config', 'capture_filter_check', 'capture_stats', 'error', 'hello',
  'interface_stats', 'log', 'packet', 'socket_table', 'state',
]);

// --- what the Rust agent can write -------------------------------------------

function rustSources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(join(root, dir))) {
    const full = join(dir, entry);
    if (statSync(join(root, full)).isDirectory()) out.push(...rustSources(full));
    else if (entry.endsWith('.rs')) out.push(full);
  }
  return out;
}

/**
 * The agent's source, minus its own test fixtures and assertions.
 *
 * `protocol.rs`'s tests hold whole messages as Rust raw strings
 * (`r#"{"type":"set_interfaces",...}"#`) and assert on decoded ones
 * (`assert_eq!(h["type"], "hello")`). Both put a wire string on the same line
 * as `"type"`, so a message that existed only in a test would read as one the
 * agent can send. Dropping those lines is what keeps the proof about the
 * emitters rather than about the tests.
 */
const agentSource = rustSources('agent-rs/src')
  .map(text)
  .join('\n')
  .split('\n')
  .filter((line) => !line.includes('r#"') && !line.trimStart().startsWith('assert'))
  .join('\n');

/**
 * Whether the agent writes this wire string as a message type.
 *
 * The key and the value on one line, in either of the two shapes this agent
 * writes: `"type": "x"` inside a `json!` literal, and
 * `insert("type".into(), json!("x"))` where a field is conditional. Matching
 * the bare word instead would find `interface_stats` inside
 * `subscribe_interface_stats` - a `Command` variant that only *parses* one,
 * which is precisely the shape that produced the flat sparkline.
 *
 * The leading quote in the pattern is what keeps those apart: in
 * `"subscribe_interface_stats"` the character before `interface_stats` is an
 * underscore rather than a quote.
 */
function agentEmits(wire: string): boolean {
  return new RegExp(`"type"[^\\n]*"${wire}"`).test(agentSource);
}

for (const wire of appReads) {
  const reason = UNSERVED[wire];
  if (reason !== undefined) {
    // An allow-listed message the agent HAS learned to send is a stale
    // entry, and it fails: the list is only worth reading if it is true.
    check(`${wire} is on the unserved list (${reason})`, agentEmits(wire), false);
    continue;
  }
  check(`the Rust agent emits ${wire}`, agentEmits(wire), true);
}

// --- and the commands, from the other side -----------------------------------

/**
 * The app's commands, likewise read from its own source.
 *
 * The agent must *understand* every one. Answering a command it cannot serve
 * with `unknown_command` is a legal answer and a different failure from
 * dropping it, so this checks the parser's table rather than a behaviour.
 */
const appSends = [...protocol.matchAll(/^\s{2}\|\s*\{\s*type: '([a-z_]+)'/gm)]
  .map((m) => m[1])
  .sort();

check('the app declares the commands this build expects', appSends, [
  'check_capture_filter', 'refresh_adapters', 'set_interfaces', 'start_capture',
  'stop_capture', 'subscribe_adapters', 'subscribe_interface_stats',
  'subscribe_logs', 'subscribe_sockets', 'unsubscribe_adapters',
  'unsubscribe_interface_stats', 'unsubscribe_logs', 'unsubscribe_sockets',
]);

const parser = text('agent-rs/src/protocol.rs');
for (const wire of appSends) {
  check(`the Rust agent parses ${wire}`, parser.includes(`"${wire}"`), true);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All agent message coverage checks passed.');
process.exit(0);
