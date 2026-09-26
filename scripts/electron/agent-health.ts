/**
 * Why the agent is not answering — the whole decision table.
 *
 *   npx tsx scripts/electron/agent-health.ts
 *
 * This exists because the states it distinguishes are exactly the ones nobody
 * can reproduce on demand. Uninstalling the service, disabling it in
 * `services.msc`, and making it crash-loop are three deliberate acts on a real
 * machine, so in practice the branches would each be exercised once by hand,
 * by whoever wrote them, and never again. `diagnoseAgent` is pure precisely so
 * that they can be exercised every commit instead.
 *
 * The registry parser is held to **real `reg query` output**, captured from a
 * live machine rather than composed here, because a parser tested against a
 * string its own author also wrote tests the author's idea of the format.
 */
import { parseStartType, provesAbsent, readAgentService } from '../../electron/agentService';
import {
  CRASH_LOOP_CONNECTIONS, agentNeedsAttention, agentStatusLabel, diagnoseAgent,
  type AgentHealth, type AgentHealthInput, type AgentServiceFacts,
} from '../../src/services/agentHealth';

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

const RUNNING: AgentServiceFacts = { installed: true, startType: 'auto' };

function diagnose(over: Partial<AgentHealthInput>): AgentHealth {
  return diagnoseAgent({
    status: 'disconnected', service: RUNNING, shortConnections: 0, ...over,
  });
}

console.log('--- what the registry says ---\n');

{
  // Captured from `reg query HKLM\SYSTEM\CurrentControlSet\Services\<name> /v
  // Start` on a real Windows 11 machine. Note the leading blank line and the
  // four-space indent: both are the tool's, not this file's.
  const real = '\r\n'
    + 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\InwireAgent\r\n'
    + '    Start    REG_DWORD    0x2\r\n\r\n';
  check('auto-start reads as auto', parseStartType(real), 'auto');
  check('3 is manual', parseStartType(real.replace('0x2', '0x3')), 'manual');
  check('4 is disabled', parseStartType(real.replace('0x2', '0x4')), 'disabled');

  // 0 and 1 are driver load states and cannot occur for a user-mode service.
  // Naming them would claim an understanding this code does not have.
  check('a boot/system value is not given a name', parseStartType(real.replace('0x2', '0x0')), 'unknown');
  check('nothing found is unknown, never a default', parseStartType(''), 'unknown');
  check('...and so is output that does not contain the value',
    parseStartType('HKEY_LOCAL_MACHINE\\SYSTEM\\...\\InwireAgent\r\n'), 'unknown');

  // Tabs on some builds, spaces on others; and `reg` has been seen to pad
  // differently under redirection.
  check('whitespace between the columns does not matter',
    parseStartType('\tStart\tREG_DWORD\t0x4\t'), 'disabled');

  // The one thing that must never happen: a localised error page parsed as a
  // start type. `reg` prints its error to stderr and exits non-zero, so the
  // parser never sees it - but if it ever did, it must decline.
  check('a localised error message yields nothing',
    parseStartType('FEHLER: Der angegebene Registrierungsschlüssel...'), 'unknown');
}

console.log('\n--- proving absence, which is not the same as failing to ask ---\n');

{
  // These three shapes are what Node's `execFile` actually hands back,
  // captured from real `reg` runs on this machine. The first version of
  // `provesAbsent` tested `error.code === undefined` - which is the shape of
  // SUCCESS - so a missing service read as unknown and a failure to ask read
  // as missing. Both backwards, and invisible without running it for real.
  const missing = Object.assign(new Error('Command failed'), { code: 1 });
  checkTrue('exit 1 with no output proves the key is absent', provesAbsent(missing, ''));

  // `reg` not on PATH. A string code, and it says nothing about the service.
  const noTool = Object.assign(new Error('spawn reg ENOENT'), { code: 'ENOENT' });
  check('a spawn failure proves nothing', provesAbsent(noTool, ''), false);

  // Timed out. `execFile` kills the child, so there is a signal and `killed`.
  const timedOut = Object.assign(new Error('timeout'),
    { killed: true, signal: 'SIGTERM', code: null });
  check('a timeout proves nothing', provesAbsent(timedOut, ''), false);

  // A non-zero exit that still printed something is not a shape `reg`
  // produces, and not one to read as absence either.
  check('a non-zero exit that still printed something proves nothing',
    provesAbsent(missing, 'Start REG_DWORD 0x2'), false);
  check('no error at all is not an absence', provesAbsent(null, ''), false);
}

console.log('\n--- against this machine\'s real registry ---\n');

{
  // The end-to-end read. Off Windows there is no registry, and the function
  // says so by construction rather than by failing.
  const facts = await readAgentService();
  console.log(`      this machine says: ${JSON.stringify(facts)}`);
  if (process.platform !== 'win32') {
    checkTrue('off Windows it answers "unknown" rather than inventing one',
      facts.installed === true && facts.startType === 'unknown');
  } else {
    // Deliberately not asserting WHICH answer: whether the agent is installed
    // here is a property of this machine, not of the code. What must hold is
    // that a real read produces a value the type allows, and never throws.
    checkTrue('a real read answers with a known start type',
      ['auto', 'manual', 'disabled', 'unknown'].includes(facts.startType));
  }
}

console.log('\n--- the diagnosis ---\n');

check('a live link needs no diagnosis',
  diagnose({ status: 'connected' }).kind, 'connected');
check('...and neither does one still trying',
  diagnose({ status: 'connecting' }).kind, 'connecting');

// The ordinary case, and the only one the app can act on.
{
  const stopped = diagnose({});
  check('installed and enabled but silent means stopped', stopped.kind, 'stopped');
  checkTrue('...and only this state offers to start it',
    'canStart' in stopped && stopped.canStart);
}

{
  const disabled = diagnose({ service: { installed: true, startType: 'disabled' } });
  check('a disabled service is named as such', disabled.kind, 'disabled');
  // The important half: pressing Start on a disabled service fails, and an
  // offer that cannot work is worse than no offer.
  checkTrue('...and does NOT offer a start that would fail',
    'canStart' in disabled && disabled.canStart === false);
  checkTrue('...and says an administrator is needed',
    'detail' in disabled && disabled.detail.includes('administrator'));
}

{
  const missing = diagnose({ service: { installed: false, startType: 'unknown' } });
  check('a service that is not there is not "stopped"', missing.kind, 'missing');
  checkTrue('...and points at reinstalling rather than at Services',
    'canStart' in missing && missing.canStart === false);
}

// `unknown` start type is not a reason to withhold the offer: not knowing how
// a service starts does not stop it starting.
check('an unreadable start type still allows a start',
  diagnose({ service: { installed: true, startType: 'unknown' } }).kind, 'stopped');

console.log('\n--- the crash loop ---\n');

{
  // Two is a service restarting once - an upgrade, or the SCM bringing it back
  // after one failure. Calling that a crash loop would accuse the agent of the
  // one restart its policy exists to make.
  check('one short connection is not a loop',
    diagnose({ shortConnections: 1 }).kind, 'stopped');
  check('two is still not a loop',
    diagnose({ shortConnections: CRASH_LOOP_CONNECTIONS - 1 }).kind, 'stopped');
  const crashing = diagnose({ shortConnections: CRASH_LOOP_CONNECTIONS });
  check('three is', crashing.kind, 'crashing');

  // The ordering that matters. A crash-looping service has every registry
  // value exactly right, so the registry branch would call it "stopped" and
  // offer a Start that the machine has already tried three times by itself.
  check('a crash loop outranks a perfectly healthy registry key',
    diagnose({ shortConnections: 5, service: RUNNING }).kind, 'crashing');
  checkTrue('...and sends the reader to the log, not to a button',
    'detail' in crashing && crashing.detail.includes('log'));
  checkTrue('...offering no start', 'canStart' in crashing && crashing.canStart === false);
}

console.log('\n--- before anything is known ---\n');

{
  // The window between the link failing and main answering. Naming a cause
  // here would mean guessing, and the guess would be "not installed", which
  // sends somebody to reinstall over a working install.
  const early = diagnose({ service: null });
  check('no answer yet is not a cause', early.kind, 'unknown');
  checkTrue('...and says so plainly',
    'detail' in early && early.detail.toLowerCase().includes('checking'));
  checkTrue('...offering nothing to press',
    'canStart' in early && early.canStart === false);
}

// Every state that is not connected/connecting must carry text for the panel,
// or the banner renders empty and reads as a rendering bug.
{
  const states: AgentHealth[] = [
    diagnose({}),
    diagnose({ service: { installed: true, startType: 'disabled' } }),
    diagnose({ service: { installed: false, startType: 'unknown' } }),
    diagnose({ shortConnections: CRASH_LOOP_CONNECTIONS }),
    diagnose({ service: null }),
  ];
  checkTrue('every diagnosis has a summary and a detail',
    states.every((s) => 'summary' in s && s.summary.length > 0
      && 'detail' in s && s.detail.length > 0));
  checkTrue('...and no two of them say the same thing',
    new Set(states.map((s) => ('summary' in s ? s.summary : ''))).size === states.length);
}

// **The labels, which nothing here checked until one of them shipped wrong.**
//
// `agentSilentLabel` was a `Partial<Record<...>>` of the five silent kinds with
// `?? 'Agent not reachable'` behind it. Its two callers at the time only asked
// while the agent WAS silent, so the missing `connected` entry was unreachable
// - until the status bar's link item asked unconditionally, and a healthy agent
// read "Agent not reachable" in the bar while capture ran perfectly.
//
// The record is total now and the fallback is gone, so a new kind cannot
// compile without a label. These hold the part a type cannot: that the healthy
// states do not READ as faults, and that the text agrees with the glyph.
{
  const kinds: AgentHealth[] = [
    { kind: 'connected' },
    { kind: 'connecting' },
    diagnose({}),
    diagnose({ service: { installed: true, startType: 'disabled' } }),
    diagnose({ service: { installed: false, startType: 'unknown' } }),
    diagnose({ shortConnections: CRASH_LOOP_CONNECTIONS }),
    diagnose({ service: null }),
  ];
  const labels = kinds.map(agentStatusLabel);

  checkTrue('every state has a label', labels.every((l) => l.length > 0));
  check('...and no two states share one', new Set(labels).size, labels.length);

  // The bug, named. A healthy agent must not be described in the vocabulary of
  // a broken one.
  check('connected does not read as a fault',
    agentStatusLabel({ kind: 'connected' }), 'Agent connected');

  // The pair that has to agree: `agentNeedsAttention` decides whether a warning
  // glyph is drawn and the label decides what is written beside it. A label
  // announcing a fault with no glyph, or a glyph with reassuring text, is the
  // state this file exists to keep straight.
  const faultWord = /\bnot\b|missing|disabled|crash/i;
  const disagree = kinds
    .filter((k) => agentNeedsAttention(k) !== faultWord.test(agentStatusLabel(k)))
    .map((k) => k.kind);
  check('the label and the warning glyph agree on every state', disagree, []);
}

console.log(failures === 0
  ? '\nAll agent health checks passed.'
  : `\n${failures} agent health check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
