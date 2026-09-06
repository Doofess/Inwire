/**
 * Assertion tests for which way a frame went.
 *
 *   npx tsx scripts/dissect/direction.ts
 *
 * `services/direction.ts` decides whether a frame was sent by the capturing
 * machine, received by it, or merely overheard. It is a small amount of code
 * standing behind a claim the user reads as fact - an arrow in a column - so
 * what is held here is the ladder itself: which signal wins, what each one is
 * allowed to conclude, and the several cases where the obvious implementation
 * is wrong.
 *
 * Three of those are worth naming, because each was a real trap:
 *
 *   - **The source MAC has to be tested before the destination.** A DHCP
 *     Discover this machine sends goes to ff:ff:ff:ff:ff:ff, and a
 *     destination-first reading calls the machine's own broadcast inbound.
 *   - **Offload can only ever say "out".** A frame larger than the link can
 *     carry was handed to the sniffer above segmentation offload, so it is
 *     leaving; but a frame of ordinary size proves nothing at all, and a
 *     tiebreaker that concluded "in" from its absence would be inventing.
 *   - **Both ends local is not a direction.** Loopback, and a machine with two
 *     adapters, are cases where neither answer is more true than the other.
 *
 * And the packing: three facts share one number, so a test that only checked
 * the direction would pass while the tooltip named the wrong signal.
 */
import {
  Direction, DirectionSignal, DIRECTION_NAMES, directionFromAddresses,
  directionFromMacs, directionFromOffload, directionOf, isDuplicate,
  packDirection, signalOf, withDuplicate, type HostIdentity,
} from '../../src/services/direction';

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
const STRANGER = '74:56:3c:c5:e3:7d';

const host = (over: Partial<HostIdentity> = {}): HostIdentity => ({
  macs: new Set([OURS]), addresses: new Set(['10.0.0.4']),
  inferred: false, confidence: 1, ...over,
});

// --- The packing holds three facts and they do not collide ---------------------
{
  for (const direction of [Direction.Unknown, Direction.Out, Direction.In, Direction.Transit]) {
    for (const signal of [DirectionSignal.None, DirectionSignal.InterfaceMac,
      DirectionSignal.SocketTable, DirectionSignal.ChecksumOffload]) {
      const slot = packDirection(direction, signal);
      if (directionOf(slot) !== direction || signalOf(slot) !== signal) {
        check(`packing ${direction}/${signal} round-trips`,
          [directionOf(slot), signalOf(slot)], [direction, signal]);
      }
    }
  }
  check('every direction and signal pair round-trips', failures, 0);

  // The duplicate bit is set later, by a pass that has no business changing
  // what the frame decided about its own direction.
  const decided = packDirection(Direction.Out, DirectionSignal.InterfaceMac);
  const marked = withDuplicate(decided);
  check('marking a duplicate leaves the direction alone', directionOf(marked), Direction.Out);
  check('...and the signal alone', signalOf(marked), DirectionSignal.InterfaceMac);
  checkTrue('...and the frame reads as a duplicate', isDuplicate(marked));
  checkTrue('a frame nobody marked is not a duplicate', !isDuplicate(decided));

  // Absent is the common case - a frame nothing could answer for - and it must
  // not throw or read as some other direction.
  check('an undefined slot is Unknown', directionOf(undefined), Direction.Unknown);
  check('...with no signal', signalOf(undefined), DirectionSignal.None);
  checkTrue('...and is not a duplicate', !isDuplicate(undefined));
}

// --- The MAC test, which answers for almost every frame -------------------------
{
  const out = directionFromMacs(OURS, GATEWAY, host());
  check('a frame from our MAC is outbound', directionOf(out), Direction.Out);
  check('...decided by the interface MAC', signalOf(out), DirectionSignal.InterfaceMac);

  check('a frame to our MAC is inbound',
    directionOf(directionFromMacs(GATEWAY, OURS, host())), Direction.In);

  // The whole point of the column: a capture in promiscuous mode carries other
  // people's conversations, and calling those "received" would be wrong in the
  // way that matters - it would put them in the Received filter.
  check('a frame between two other machines is transit',
    directionOf(directionFromMacs(GATEWAY, STRANGER, host())), Direction.Transit);

  // This is the ordering trap. Our own broadcasts and multicasts go to a group
  // address, and reading the destination first calls every DHCP Discover,
  // every ARP request and every mDNS query this machine sends "received".
  check('our own broadcast is outbound, not inbound',
    directionOf(directionFromMacs(OURS, 'ff:ff:ff:ff:ff:ff', host())), Direction.Out);
  check('our own IPv4 multicast is outbound',
    directionOf(directionFromMacs(OURS, '01:00:5e:00:00:fb', host())), Direction.Out);
  check('our own IPv6 multicast is outbound',
    directionOf(directionFromMacs(OURS, '33:33:00:00:00:01', host())), Direction.Out);

  // Group traffic we did not send, we did receive - it was addressed to a
  // group this machine is in, which is what "in" means here.
  check('somebody else\'s broadcast is inbound',
    directionOf(directionFromMacs(GATEWAY, 'ff:ff:ff:ff:ff:ff', host())), Direction.In);
  check('a neighbour\'s multicast is inbound',
    directionOf(directionFromMacs(STRANGER, '33:33:00:00:00:01', host())), Direction.In);

  // No identity, no answer. This is the imported-capture case before inference
  // has run, and it must produce nothing rather than a default.
  check('with no host known, the MACs decide nothing',
    directionFromMacs(OURS, GATEWAY, { ...host(), macs: new Set() }), 0);
  check('a link with no MACs at all decides nothing here',
    directionFromMacs(undefined, undefined, host()), 0);

  // An inferred host answers the same question, but the frame has to remember
  // that it was inferred, because the column marks those.
  check('an inferred host is recorded as inferred, not as an adapter',
    signalOf(directionFromMacs(OURS, GATEWAY, host({ inferred: true }))),
    DirectionSignal.InferredHost);
}

// --- The address test, for links with no MACs ------------------------------------
{
  // A TUN-style VPN adapter has no Ethernet header, so this is not a fallback
  // for it - it is the only signal that can ever fire.
  check('our address as the source is outbound',
    directionOf(directionFromAddresses('10.0.0.4', '1.1.1.1', host())), Direction.Out);
  check('our address as the destination is inbound',
    directionOf(directionFromAddresses('1.1.1.1', '10.0.0.4', host())), Direction.In);
  check('neither address ours decides nothing',
    directionFromAddresses('1.1.1.1', '8.8.8.8', host()), 0);

  // The socket table is the weaker claim and is consulted second: it says this
  // machine holds a socket on an address, which is true of every address on a
  // multi-homed machine.
  const local = (a: string) => a === '10.0.0.4' || a === '192.168.1.5';
  const noHost = { ...host(), macs: new Set<string>(), addresses: new Set<string>() };
  check('the socket table can decide outbound',
    directionOf(directionFromAddresses('192.168.1.5', '1.1.1.1', noHost, local)), Direction.Out);
  check('...and is recorded as the socket table',
    signalOf(directionFromAddresses('192.168.1.5', '1.1.1.1', noHost, local)),
    DirectionSignal.SocketTable);
  check('the socket table can decide inbound',
    directionOf(directionFromAddresses('1.1.1.1', '192.168.1.5', noHost, local)), Direction.In);

  // Loopback, and a frame between two of this machine's own adapters. Neither
  // direction is more true than the other, so neither is claimed.
  check('both ends local is not a direction',
    directionFromAddresses('10.0.0.4', '192.168.1.5', noHost, local), 0);

  // The adapter's own addresses outrank the socket table when both could
  // answer, because one is what the adapter is configured with and the other
  // is what some process happens to be bound to.
  check('the adapter outranks the socket table',
    signalOf(directionFromAddresses('10.0.0.4', '1.1.1.1', host(), local)),
    DirectionSignal.InterfaceAddress);
}

// --- Offload, which can only ever say "out" ---------------------------------------
{
  check('a frame larger than the link can carry is outbound',
    directionOf(directionFromOffload(2800, true, false)), Direction.Out);
  check('...and says so was the reason', signalOf(directionFromOffload(2800, true, false)),
    DirectionSignal.Offload);

  // A frame of ordinary size is not thereby inbound. The absence of an offload
  // artefact is not evidence of anything.
  check('an ordinary frame decides nothing', directionFromOffload(1500, true, false), 0);
  check('a frame exactly at the Ethernet maximum decides nothing',
    directionFromOffload(1514, true, false), 0);

  // Only on a link whose maximum we know. A large frame on a loopback or TUN
  // interface, whose MTU is routinely 65535, says nothing at all.
  check('a large frame on a link with no Ethernet header decides nothing',
    directionFromOffload(2800, false, false), 0);

  // A required checksum the NIC has not filled in yet: an artefact only a
  // transmitting stack leaves.
  check('an unfilled checksum is outbound',
    directionOf(directionFromOffload(200, true, true)), Direction.Out);
  check('...recorded as checksum offload', signalOf(directionFromOffload(200, true, true)),
    DirectionSignal.ChecksumOffload);
}

// --- The names a filter matches ----------------------------------------------------
{
  // Both spellings, so `frame.direction == out` and `== sent` find the same
  // frames. The engine already supports several values per read - it is how
  // `proto == tls` and `proto == tlsv1.2` both match - so this needs no new
  // machinery, but it does need the two lists to actually contain both.
  check('outbound answers to out and to sent', DIRECTION_NAMES[Direction.Out], ['out', 'sent']);
  check('inbound answers to in and to received', DIRECTION_NAMES[Direction.In], ['in', 'received']);
  check('transit answers to transit', DIRECTION_NAMES[Direction.Transit], ['transit']);
  check('unknown answers to unknown', DIRECTION_NAMES[Direction.Unknown], ['unknown']);

  // No two directions may share a name, or a filter would be ambiguous.
  const all = Object.values(DIRECTION_NAMES).flat();
  check('no name belongs to two directions', all.length, new Set(all).size);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All direction checks passed.');
process.exit(0);
