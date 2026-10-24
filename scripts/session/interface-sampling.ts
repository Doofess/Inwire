/**
 * Adapter sampling is counted, not switched.
 *
 *   npx tsx scripts/session/interface-sampling.ts
 *
 * Two surfaces draw the adapters' sparklines: the Interfaces panel in the side
 * bar and the welcome on an empty Packets view. Each turns sampling on when it
 * mounts and off when it unmounts. While the flag was a boolean, the second
 * surface to close turned sampling off under the first, and the survivor kept
 * drawing its last thirty samples - which reads as a quiet adapter, not as a
 * dropped subscription. `createSamplingCount` answers "tell the agent now?"
 * only on the 0 -> 1 and 1 -> 0 edges.
 */
import { readFileSync } from 'node:fs';
import { createSamplingCount } from '../../src/lib/samplingCount';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const count = createSamplingCount();
check('the first acquire is the edge that subscribes', count.acquire() === true && count.active);
check('a second acquire tells the agent nothing', count.acquire() === false && count.active);
check('the first release keeps sampling on for the surface still open', count.release() === false && count.active);
check('the last release is the edge that unsubscribes', count.release() === true && !count.active);
check('a release at zero is a no-op', count.release() === false && !count.active);
check('and leaves the count at zero, so one acquire turns it back on', count.acquire() === true && count.active);

const hook = readFileSync('src/hooks/useAgentConnection.ts', 'utf8');
check('useAgentConnection no longer stores the flag as a boolean',
  !hook.includes('interfaceStatsSubscribedRef.current = on'));
check('useAgentConnection uses createSamplingCount', hook.includes('createSamplingCount('));

if (failures > 0) {
  console.log(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
