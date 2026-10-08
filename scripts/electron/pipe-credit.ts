/**
 * Main's credit with the pipeline Worker (ADR 0053), driven without Electron.
 *
 *   npx tsx scripts/electron/pipe-credit.ts
 *
 * What it must never do: shed a batch while nothing is owed (a lone batch
 * bigger than the budget would be shed for ever), flap at the line (every
 * flap is another hole in every TCP stream crossing it), or keep counting a
 * batch the Worker answered for.
 */
import { PipeCredit, RESUME_FRACTION } from '../../electron/pipeCredit';
import { batchFrameCount } from '../../src/services/agentBinary';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

let clock = 1000;
const now = () => clock;

// --- admitting, answering, and the oldest -----------------------------------
{
  const credit = new PipeCredit(1000, now);
  const a = credit.admit(300, 30);
  clock += 50;
  const b = credit.admit(300, 30);
  check('batches under the budget are admitted with ids', a === 1 && b === 2);
  let lag = credit.backlog();
  check('the backlog counts what is owed', lag.frames === 60 && lag.bytes === 600);
  check('...and its age is the oldest batch\'s', lag.oldestMs === 50);
  credit.drained([a!]);
  lag = credit.backlog();
  check('an answered batch leaves the backlog, and the next is the oldest', lag.frames === 30 && lag.oldestMs === 0);
  credit.drained([a!, 99]);
  check('answering twice, or an id never issued, changes nothing', credit.backlog().frames === 30);
}

// --- shedding, with hysteresis -----------------------------------------------
{
  const credit = new PipeCredit(1000, now);
  const ids: number[] = [];
  for (let i = 0; i < 3; i++) ids.push(credit.admit(300, 10)!);
  check('the batch that would cross the budget is shed', credit.admit(300, 10) === null);
  check('...and counted, in frames', credit.backlog().shedFrames === 10 && credit.backlog().shedding);
  credit.drained([ids[0]]);
  check('freeing a little does not stop the shedding (no flapping at the line)', credit.admit(100, 5) === null);
  credit.drained([ids[1]]);
  check(`under ${RESUME_FRACTION * 100}% of the budget it admits again`, credit.admit(100, 5) !== null && !credit.backlog().shedding);
  check('the shed count is every frame shed', credit.backlog().shedFrames === 15);
}

// --- a lone batch bigger than the budget --------------------------------------
{
  const credit = new PipeCredit(1000, now);
  check('a batch larger than the budget is admitted while nothing is owed', credit.admit(5000, 500) !== null);
  check('...and the next is shed until it is answered', credit.admit(10, 1) === null);
}

// --- a reconnect owes nothing --------------------------------------------------
{
  const credit = new PipeCredit(1000, now);
  credit.admit(600, 6);
  credit.admit(600, 6);
  credit.reset();
  const lag = credit.backlog();
  check('reset clears the backlog, the shedding and the count', lag.frames === 0 && !lag.shedding && lag.shedFrames === 0);
}

// --- reading a batch's frame count without decoding it -------------------------
{
  const batch = new Uint8Array(8 + 22);
  const view = new DataView(batch.buffer);
  view.setUint32(0, 0x31_50_57_49, true);
  view.setUint8(4, 4);
  view.setUint16(6, 7, true);
  check('a batch header says how many frames it carries', batchFrameCount(batch) === 7);
  check('...read through a view into a larger buffer too', batchFrameCount(new Uint8Array(new Uint8Array([0, 0, ...batch]).buffer, 2)) === 7);
  check('a message that is not a batch has no count', batchFrameCount(new TextEncoder().encode('{"type":"hello"}')) === null);
}

console.log(failures === 0 ? '\nAll pipe-credit checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
