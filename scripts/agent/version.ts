/**
 * Inwire has one version number, and this is what holds it to one.
 *
 *   npx tsx scripts/agent/version.ts
 *
 * ## What this replaced
 *
 * Six stamps: `AGENT_VERSION` in `agent.py`, `REQUIRED_AGENT_VERSION` in
 * `agentProtocol.ts`, `MyAgentVersion` in **both** `.iss` files, a literal in
 * `scripts/agent-protocol/version-and-commands.ts`, and a CI step that read
 * `agent.AGENT_VERSION` by name. Two scripts covered them, each covering a
 * different subset: `test_protocol.py` read the LEGACY installer and is Python,
 * so `scripts/check.ts` never discovered it; `installer-versions.ts` read both
 * `.iss` files and ran unprompted. Between them the shipping installer's stamps
 * went unread by anything at all for months.
 *
 * ADR 0035 collapsed the agent's version into the product's, which deletes the
 * question rather than checking it more carefully: `package.json` is the only
 * place a version is authored, and everything below either derives from it or
 * is a literal this file holds to it.
 *
 * ## Why there is no floor any more
 *
 * There was one, at 3.9.0, because `REQUIRED_AGENT_VERSION` was the left-hand
 * side of an ORDERING: an agent left behind by a higher-numbered build read as
 * newer than required and passed. That is what jumped the product to 4.0.0 when
 * the two numbers were collapsed. The app now asks for equality instead
 * (`isAgentMismatched`, ADR 0051) - an agent the same installer did not put
 * down is from another build whichever way its number moved - so the number is
 * free to say what it means: 0.x, because Inwire is in development.
 *
 * The one ordering left is the installer's refusal to install over a newer
 * Inwire, which a reset trips exactly once per machine; 0051 says how.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { REQUIRED_AGENT_VERSION } from '../../src/services/agentProtocol';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${String(expected)}`);
    console.log(`        actual   ${String(actual)}`);
  }
}

/**
 * Reads a file, and counts a failure rather than throwing if it is not there.
 *
 * A missing file must not read as "nothing to check". `node-safe.ts` makes the
 * same argument about its import walk: an assertion that passes because it
 * found nothing is worse than no assertion, because it prints PASS.
 */
function text(relative: string): string {
  try {
    return readFileSync(join(root, relative), 'utf8');
  } catch {
    failures++;
    console.log(`FAIL  ${relative} could not be read`);
    return '';
  }
}

const lines = (source: string) => source.split('\n').map((line) => line.trim());

/**
 * The value of an Inno `#define`.
 *
 * Scanned rather than pattern-matched, because the `#define` prefix is doing
 * real work: these names also appear in the prose comments above their own
 * definitions, and a looser match reads the sentence instead.
 */
function define(source: string, name: string): string | null {
  for (const line of lines(source)) {
    if (!line.startsWith('#define')) continue;
    const rest = line.slice('#define'.length).trim();
    if (!rest.startsWith(name)) continue;
    const after = rest.slice(name.length).trim();
    if (!after.startsWith('"')) continue;
    return after.slice(1, after.indexOf('"', 1));
  }
  return null;
}

/** `NAME = "x.y.z"` out of a Python source file. */
function pythonConstant(source: string, name: string): string | null {
  for (const line of lines(source)) {
    if (!line.startsWith(name)) continue;
    const after = line.slice(line.indexOf('=') + 1).trim();
    if (!after.startsWith('"')) continue;
    return after.slice(1, after.indexOf('"', 1));
  }
  return null;
}

const SHIPPING = 'installer/setup.iss';
const LEGACY = 'local-agent/installer/setup.iss';

const shipping = text(SHIPPING);
const legacy = text(LEGACY);

// The read is itself an assertion: with both of these empty, every check below
// would compare null to null and pass.
check(`${SHIPPING} was read`, shipping.length > 0, true);
check(`${LEGACY} was read`, legacy.length > 0, true);

console.log('\n--- one number, authored in package.json ---\n');

const pkg = JSON.parse(text('package.json') || '{}') as { version?: string };
const version = pkg.version ?? null;

check('package.json declares a version', version !== null, true);
check('...and it is MAJOR.MINOR.PATCH',
  version !== null && /^\d+\.\d+\.\d+$/.test(version), true);

// The generated file. Its whole hazard is being committed and going stale, so
// it is checked rather than trusted - `npm run sync:version` rewrites it.
const generated = pythonConstant(text('local-agent/agent_version.py'), 'AGENT_VERSION');
check('agent_version.py matches package.json (run `npm run sync:version`)',
  generated, version);

check('agentProtocol.ts REQUIRED_AGENT_VERSION matches package.json',
  REQUIRED_AGENT_VERSION, version);

check(`${SHIPPING} MyAppVersion matches package.json`,
  define(shipping, 'MyAppVersion'), version);

// The Rust agent's crate version, which `lib.rs` re-exports as `VERSION` via
// `env!("CARGO_PKG_VERSION")` - so this is what its `hello` carries, what
// `--version` prints, and what `stamp-agent.ts` insists the VERSIONINFO agrees
// with. It was deliberately `0.0.0` while the agent still had a version of its
// own; it joined the lock when the collapse landed, and `npm run sync:version`
// has written it since the Rust agent became what the installer ships.
const cargo = text('agent-rs/Cargo.toml');
check('agent-rs/Cargo.toml was read', cargo.length > 0, true);
const crateVersion = /^version = "([^"]+)"$/m.exec(cargo)?.[1] ?? null;
check('agent-rs/Cargo.toml version matches package.json (run `npm run sync:version`)',
  crateVersion, version);

// And the crate's own entry in the lock, because `npm run build:agent` builds
// `--locked`: a lock naming the previous version fails the release build
// rather than being rewritten by it, which is the right failure but a late one.
const lock = text('agent-rs/Cargo.lock');
const lockVersion = /^name = "inwire-agent"\r?\nversion = "([^"]+)"$/m.exec(lock)?.[1] ?? null;
check('agent-rs/Cargo.lock inwire-agent entry matches package.json', lockVersion, version);

console.log('\n--- and no second number beside it ---\n');

// The deletion is the decision, so it is asserted rather than assumed. A
// session re-adding `MyAgentVersion` "for clarity" reintroduces the whole
// six-stamp problem with one line.
check(`${SHIPPING} declares no MyAgentVersion`, define(shipping, 'MyAgentVersion'), null);

// agent.py must not re-declare what it now imports. A literal here would shadow
// the generated module and every check above would keep passing while the agent
// reported a different version than the product.
const agentSource = text('local-agent/agent.py');
check('agent.py declares no AGENT_VERSION literal of its own',
  pythonConstant(agentSource, 'AGENT_VERSION'), null);
check('...and imports it from agent_version instead',
  /from agent_version import AGENT_VERSION/.test(agentSource), true);

console.log('\n--- the legacy installer is a record, and is frozen ---\n');

// Nothing builds it. It describes what an agent-only install actually put on a
// machine, which is what the unified installer reads in order to remove it - so
// a version that tracked the product would describe an install never made.
check(`${LEGACY} MyAgentVersion stays at the last agent-only release`,
  define(legacy, 'MyAgentVersion'), '3.9.0');
check(`${LEGACY} MyAppVersion stays where it was`,
  define(legacy, 'MyAppVersion'), '1.0.0');

console.log('\n--- the installer finds what an install registered ---\n');

/**
 * The key Inno registers an `AppId` under: `{{` is an escaped brace and a lone
 * `}` is itself, so `{{GUID}}` registers as `{GUID}}`.
 *
 * Asserted because the reads got it wrong and nothing could tell: the upgrade
 * guard looked up `{GUID}_is1`, found no install, and so refused none - never
 * noticed until 0.4.1 was the first installer to go below what was installed
 * (ADR 0051). A read that finds nothing is indistinguishable from a machine
 * with nothing on it.
 */
function registeredKey(source: string): string | null {
  const line = lines(source).find((l) => l.startsWith('AppId='));
  if (line === undefined) return null;
  return `${line.slice('AppId='.length).replace(/\{\{/g, '{')}_is1`;
}

const ownKey = registeredKey(shipping);
check(`${SHIPPING} has an AppId`, ownKey !== null, true);
check('...and the upgrade guard reads the key that AppId registers',
  ownKey !== null && shipping.includes(`CurrentVersion\\Uninstall\\${ownKey}'`), true);

const standaloneKey = registeredKey(legacy);
const standaloneRead = `CurrentVersion\\Uninstall\\${define(shipping, 'StandaloneAgentAppId')}}_is1`;
check(`${LEGACY} has an AppId`, standaloneKey !== null, true);
check('the standalone agent is looked up under the key its AppId registered',
  standaloneKey !== null && standaloneRead.endsWith(`\\${standaloneKey}`)
    && shipping.includes(`CurrentVersion\\Uninstall\\{#StandaloneAgentAppId}}_is1'`), true);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All version checks passed.');
process.exit(0);
