/**
 * What `sc.exe start InwireAgent` said, as a decision rather than a number.
 *
 * The agent is demand-start (`installer/setup.iss` installs it
 * `--startup manual`), so something has to start it, and that something is the
 * app at `whenReady()`. This module is the half that decides what a failed
 * attempt MEANS, split out from `agentPipe.ts` for the reason every decision in
 * `electron/` is split out: so a script can drive it under plain `tsx` on a
 * machine with no SCM.
 *
 * ## Why exit codes and not output
 *
 * The same argument `agentService.ts` makes about `reg` over `sc query`, one
 * layer down. `sc.exe` prints **localised** text - the failure line on a German
 * Windows is German - and it also prints the error NUMBER, which is not. The
 * number is what `sc` returns as its own process exit code, so nothing has to
 * be parsed at all.
 *
 * This is the same doctrine `updateCenter/elevate.ts` follows for a declined
 * UAC prompt, and for the same reason: a parser written against an English
 * machine reports a confident wrong answer everywhere else.
 *
 * ## Why there is no automatic escalation
 *
 * `needsElevation` is a fact this module reports; it is not a trigger. A UAC
 * prompt nobody asked for, raised by an app the person has just launched, is
 * indistinguishable from malware to the one audience that should be most
 * suspicious of it. So `AgentPipeLink` escalates only from an explicit click -
 * the existing `startAgentService` path - and the automatic attempt at startup
 * is unelevated or nothing.
 *
 * The installer already grants the right that makes the unelevated attempt
 * work: `GrantServiceStartToInteractiveUsers` runs `sc sdset` to add `RP`
 * (SERVICE_START) to the `IU` ACE. `WP` (SERVICE_STOP) is deliberately NOT
 * granted and this module never wants it - the agent stops **itself** when its
 * last client goes away (ADR 0035), so nothing here needs the right to stop a
 * service a second Windows user may be capturing through.
 */

/**
 * Win32 error codes `sc.exe start` returns as its exit code.
 *
 * Named rather than inlined because the whole point is that these are the
 * stable half of what the tool reports; a bare `1060` in a condition is a
 * number somebody will eventually have to look up, and looking it up is how
 * the localised-text mistake gets made again.
 */
export const SC_OK = 0;
/** ERROR_ACCESS_DENIED - the unelevated attempt was refused. */
export const SC_ACCESS_DENIED = 5;
/** ERROR_SERVICE_ALREADY_RUNNING - somebody else already started it. */
export const SC_ALREADY_RUNNING = 1056;
/** ERROR_SERVICE_REQUEST_TIMEOUT - it is starting, just not quickly. */
export const SC_REQUEST_TIMEOUT = 1053;
/** ERROR_SERVICE_DISABLED - an administrator turned it off. */
export const SC_DISABLED = 1058;
/** ERROR_SERVICE_DOES_NOT_EXIST - removed, or never installed. */
export const SC_NO_SUCH_SERVICE = 1060;
/** ERROR_SERVICE_DEPENDENCY_FAIL - something it needs did not start. */
export const SC_DEPENDENCY_FAILED = 1068;

/**
 * What to do next.
 *
 * `running` covers both "we started it" and "it was already up", because the
 * caller wants the pipe either way and the difference is not a state the UI
 * describes. `retry` is the only verdict that says trying again unchanged
 * could work.
 */
export type StartOutcome = 'running' | 'needsElevation' | 'hopeless' | 'retry';

export interface StartVerdict {
  outcome: StartOutcome;
  /** For the log. Never shown: the UI's wording comes from `agentHealth.ts`. */
  reason: string;
}

/**
 * Classifies one attempt.
 *
 * `code` is the process exit code, or `null` when the process could not be run
 * at all (`sc.exe` missing from PATH, a spawn failure, a timeout). That case is
 * `retry` rather than `hopeless` on purpose: it says nothing about the service,
 * and a machine that cannot spawn `sc.exe` right now may be able to in three
 * seconds.
 */
export function classifyStart(code: number | null): StartVerdict {
  switch (code) {
    case SC_OK:
      return { outcome: 'running', reason: 'started' };
    case SC_ALREADY_RUNNING:
      return { outcome: 'running', reason: 'already running' };
    case SC_ACCESS_DENIED:
      // The one code where a prompt helps. Everything else below would raise
      // one that could not fix anything, which is the worst kind of prompt.
      return { outcome: 'needsElevation', reason: 'access denied' };
    case SC_REQUEST_TIMEOUT:
      return { outcome: 'retry', reason: 'the service is slow to start' };
    case SC_DISABLED:
      return { outcome: 'hopeless', reason: 'the service is disabled' };
    case SC_NO_SUCH_SERVICE:
      return { outcome: 'hopeless', reason: 'the service is not installed' };
    case SC_DEPENDENCY_FAILED:
      return { outcome: 'hopeless', reason: 'a service it depends on failed' };
    case null:
      return { outcome: 'retry', reason: 'sc.exe could not be run' };
    default:
      // An unrecognised code is not a licence to keep trying for ever: the
      // caller stops after a few attempts whatever this says, and `retry`
      // here means only that this particular number proved nothing.
      return { outcome: 'retry', reason: `sc.exe exited ${code}` };
  }
}

/**
 * Whether an automatic attempt is worth making at all.
 *
 * Read from what `agentService.ts` already knows, so a machine where the
 * service was removed or disabled is never asked - `sc start` there costs a
 * process to be told something the registry said for free.
 *
 * `unknown` gets an attempt. The registry read failing is not evidence about
 * the service, and the whole reason `provesAbsent` exists is that this
 * codebase refuses to turn "we could not ask" into "it is not there".
 */
export function worthStarting(
  facts: { installed: boolean; startType: 'auto' | 'manual' | 'disabled' | 'unknown' },
): boolean {
  if (!facts.installed) return false;
  return facts.startType !== 'disabled';
}

/**
 * How many automatic attempts before the app stops asking.
 *
 * Bounded because the retry that drives it runs for as long as the window is
 * open, and a machine where the start genuinely cannot succeed would otherwise
 * spawn `sc.exe` every twenty seconds for ever. Three is enough to cover a
 * service that is mid-stop when the first attempt lands (`sc start` fails with
 * ERROR_SERVICE_MARKED_FOR_DELETE or a stop still pending) without turning a
 * permanent failure into a permanent process spawner.
 *
 * The count is reset by anything that changes the answer: a successful
 * connection, or the person clicking the button that escalates.
 */
export const MAX_AUTO_START_ATTEMPTS = 3;
