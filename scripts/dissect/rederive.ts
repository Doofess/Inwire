/**
 * Assertion tests for re-deciding direction over a whole buffer.
 *
 *   npx tsx scripts/dissect/rederive.ts
 *
 * `services/redirect.ts` is the second pass an **import** and a **restored
 * session** both take: neither goes through the Worker, so no frame in either
 * has a direction until this runs.
 *
 * The property worth a test is not the arithmetic - `scripts/dissect/direction.ts`
 * holds that - but that the pass **finishes at all**.
 *
 * It did not, and the way it failed is the reason this file exists. The work
 * was sliced with `requestAnimationFrame`, which does not fire *at all* in a
 * background tab: measured at zero callbacks over 3.8 seconds in a hidden one.
 * So a restore that completed while the tab was in the background left every
 * frame without a direction, and left it that way until somebody looked at the
 * tab - which is precisely when nobody is watching to notice. On a real
 * 101,907-frame session it showed as a column of dots.
 *
 * Node has no `requestAnimationFrame`, so **this file runs in exactly the
 * condition that broke it**. If the scheduler ever goes back to animation
 * frames, nothing here will complete and every check below fails.
 */
import { rederiveDirections, countDirections } from '../../src/services/redirect';
import { Direction, packDirection, withDuplicate, isDuplicate, signalOf, DirectionSignal,
  type HostIdentity } from '../../src/services/direction';
import type { Packet } from '../../src/types/packet';

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
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

const OURS = '04:7c:16:52:db:17';
const GATEWAY = '44:15:24:5d:cc:62';
const host: HostIdentity = {
  macs: new Set([OURS]), addresses: new Set(['10.0.0.4']),
  inferred: false, confidence: 1,
};

function frame(id: number, src: string, dst: string, direction?: number): Packet {
  return {
    id, source: '', destination: '', direction,
    fields: { 'eth.src': src, 'eth.dst': dst },
  } as unknown as Packet;
}

const done = (packets: Packet[], id: HostIdentity, onFrame?: (p: Packet) => void) =>
  new Promise<number>((resolve) => {
    rederiveDirections(packets, id, resolve, onFrame ? (p) => onFrame(p) : undefined);
  });

// There is no requestAnimationFrame here, which is the point.
checkTrue('this runs without requestAnimationFrame, as a hidden tab does',
  typeof (globalThis as { requestAnimationFrame?: unknown }).requestAnimationFrame === 'undefined');

// --- It finishes, and it decides every frame --------------------------------------
{
  // More than one slice's worth, so the scheduler actually has to come back.
  const packets = [
    ...Array.from({ length: 25_000 }, (_, i) => frame(i + 1, OURS, GATEWAY)),
    ...Array.from({ length: 25_000 }, (_, i) => frame(100_000 + i, GATEWAY, OURS)),
  ];
  const changed = await done(packets, host);
  check('every frame was decided', changed, packets.length);

  const counts = countDirections(packets);
  check('...half outbound', counts[Direction.Out], 25_000);
  check('...half inbound', counts[Direction.In], 25_000);
  check('...and none left unknown', counts[Direction.Unknown], 0);
}

// --- The per-frame visitor sees every frame, once ------------------------------------
//
// This is how an imported or restored capture collects its network facts: the
// collector rides this pass rather than taking one of its own.
{
  const packets = Array.from({ length: 30_000 }, (_, i) => frame(i + 1, OURS, GATEWAY));
  const seen = new Set<number>();
  let visits = 0;
  await done(packets, host, (p) => { seen.add(p.id); visits++; });
  check('the visitor saw every frame', seen.size, packets.length);
  check('...exactly once each', visits, packets.length);
}

// --- Cancelling stops it ---------------------------------------------------------------
//
// A second import, or an override while the first pass is still running, must
// not leave two of them writing different identities into the same frames.
{
  const packets = Array.from({ length: 60_000 }, (_, i) => frame(i + 1, OURS, GATEWAY));
  let finished = false;
  const cancel = rederiveDirections(packets, host, () => { finished = true; });
  cancel();
  await new Promise((r) => setTimeout(r, 60));
  checkTrue('a cancelled pass never reports done', !finished);
  checkTrue('...and leaves the rest of the buffer alone',
    countDirections(packets)[Direction.Unknown] > 0);
}

// --- Re-deciding preserves what belongs to another question ------------------------------
{
  const marked = frame(1, OURS, GATEWAY,
    withDuplicate(packDirection(Direction.In, DirectionSignal.InferredHost)));
  await done([marked], host);
  check('the direction is re-decided', countDirections([marked])[Direction.Out], 1);
  checkTrue('...and the duplicate mark survives it', isDuplicate(marked.direction));
}

// --- An answer this pass cannot reproduce is kept, not erased ---------------------------
//
// Both offload signals are read out of the raw bytes and the frame's own link
// type at dissection - a frame past the MTU, a required checksum still zero -
// and neither is in reach here. Clearing them was harmless while imports had
// no direction at all; the moment the dissector started deciding for them, this
// pass ran straight over the top and set them back to nothing.
{
  // A frame off a link with no Ethernet header - a TUN-style VPN, a raw-IP
  // adapter - and addresses that are not the host's. Nothing here for either
  // of this pass's two tests to bite on, which is the only situation where the
  // dissector's answer is the better one.
  const linkless = (direction: number): Packet => ({
    id: 1, source: '198.51.100.7', destination: '203.0.113.9', direction, fields: {},
  } as unknown as Packet);

  for (const [name, signal] of [
    ['segmentation offload', DirectionSignal.Offload],
    ['an unfilled checksum', DirectionSignal.ChecksumOffload],
  ] as const) {
    const offloaded = linkless(packDirection(Direction.Out, signal));
    await done([offloaded], host);
    check(`a frame decided by ${name} keeps its direction`,
      countDirections([offloaded])[Direction.Out], 1);
    check('...and the signal that decided it', signalOf(offloaded.direction), signal);
  }

  // The other half of the same rule. `InferredHost` is a signal this pass DOES
  // produce, so an answer carrying it is the previous host's answer and must
  // give way - otherwise an override could never take a frame back.
  const weak = linkless(packDirection(Direction.Out, DirectionSignal.InferredHost));
  await done([weak], host);
  check('an answer this pass can produce is replaced, not kept',
    countDirections([weak])[Direction.Unknown], 1);
}

// --- An empty buffer still reports done ----------------------------------------------------
{
  check('an empty buffer completes rather than hanging', await done([], host), 0);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All rederive checks passed.');
process.exit(0);
