/**
 * Assertion tests for the packet detail window's pure parts.
 *
 *   npx tsx scripts/packet-detail/model.ts
 *
 * The frame-number box is the reason most of this exists. Its lookup has edge
 * cases that are tedious to reach through the UI and easy to get subtly wrong:
 * a buffer whose numbering no longer starts at 1 because it has been trimmed,
 * a number just outside either end, and input that is not a number at all.
 */
import {
  buildFrameSummary,
  collectRelatedFrames,
  findPacketIndexById,
  frameJumpRefusal,
  lookupFrame,
} from '../../src/components/packet-details/packetDetailModel';
import type { Packet, ProtocolField, ProtocolLayer } from '../../src/types/packet';

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

function makePacket(id: number, over: Partial<Packet> = {}): Packet {
  return {
    id,
    tsUs: 1_700_000_000_000_000 + id * 1000,
    relativeTime: id / 100,
    timeDelta: 0.01,
    source: '10.0.0.1',
    destination: '10.0.0.2',
    protocol: 'TCP',
    length: 74,
    info: `frame ${id}`,
    status: 'ok',
    layers: [],
    rawBytes: new Uint8Array(74),
    interfaceName: 'Ethernet 2',
    ...over,
  };
}

// --- Lookup by frame number -------------------------------------------------
{
  const buffer = Array.from({ length: 500 }, (_, i) => makePacket(i + 1));

  check('finds the first frame', findPacketIndexById(buffer, 1), 0);
  check('finds the last frame', findPacketIndexById(buffer, 500), 499);
  check('finds one in the middle', findPacketIndexById(buffer, 250), 249);
  check('rejects one past the end', findPacketIndexById(buffer, 501), -1);
  check('rejects one before the start', findPacketIndexById(buffer, 0), -1);
  check('rejects a negative', findPacketIndexById(buffer, -5), -1);
  check('an empty buffer finds nothing', findPacketIndexById([], 1), -1);

  // The binary search must agree with a linear scan for every id in range,
  // including the ones either side of every midpoint it could pick.
  let mismatches = 0;
  for (let id = 0; id <= 502; id++) {
    if (findPacketIndexById(buffer, id) !== buffer.findIndex(p => p.id === id)) mismatches++;
  }
  check('binary search agrees with a linear scan across the whole range', mismatches, 0);
}

// --- A trimmed buffer: numbering no longer starts at 1 ----------------------
{
  // This is the case that catches an index computed as `id - packets[0].id`.
  const trimmed = Array.from({ length: 300 }, (_, i) => makePacket(i + 4001));

  check('finds a frame in a trimmed buffer', findPacketIndexById(trimmed, 4001), 0);
  check('...and one at the far end', findPacketIndexById(trimmed, 4300), 299);
  check('...and one in the middle', findPacketIndexById(trimmed, 4150), 149);
  check('a frame trimmed away is gone', findPacketIndexById(trimmed, 4000), -1);
  check('a frame not yet captured is absent', findPacketIndexById(trimmed, 4301), -1);

  let mismatches = 0;
  for (let id = 3995; id <= 4305; id++) {
    if (findPacketIndexById(trimmed, id) !== trimmed.findIndex(p => p.id === id)) mismatches++;
  }
  check('agrees with a linear scan on a trimmed buffer too', mismatches, 0);
}

// --- What the user typed ----------------------------------------------------
{
  const buffer = Array.from({ length: 100 }, (_, i) => makePacket(i + 201));

  check('an empty box is not an error', lookupFrame(buffer, '').kind, 'empty');
  check('whitespace only is also empty', lookupFrame(buffer, '   ').kind, 'empty');
  check('a typo is reported as invalid', lookupFrame(buffer, '12x').kind, 'invalid');
  check('a negative sign is not a frame number', lookupFrame(buffer, '-4').kind, 'invalid');
  check('a decimal is not a frame number', lookupFrame(buffer, '20.5').kind, 'invalid');

  const found = lookupFrame(buffer, '250');
  check('a frame in the buffer is found', found.kind, 'found');
  check('...at the right index', found.kind === 'found' ? found.index : null, 49);
  check('...and hands back that packet', found.kind === 'found' ? found.packet.id : null, 250);
  check('surrounding whitespace is tolerated', lookupFrame(buffer, '  250  ').kind, 'found');

  const out = lookupFrame(buffer, '9999');
  check('a real number outside the buffer is out of range', out.kind, 'outOfRange');
  check('...and reports what the buffer does hold', out.kind === 'outOfRange' ? [out.first, out.last] : null, [201, 300]);

  const empty = lookupFrame([], '5');
  check('an empty buffer reports no range rather than crashing', empty.kind === 'outOfRange' ? [empty.first, empty.last] : null, [null, null]);
}

// --- Refusing a jump, rather than ignoring it -------------------------------
//
// Every cross-reference between frames - `[Response In: N]`, `(request in N)`,
// a Statistics row's first frame - is a number written while its target was in
// the buffer, and the buffer trims its oldest. Clicking one after that used to
// do nothing at all, which is indistinguishable from a broken link. These hold
// the refusal to being specific about WHY, because "no" without a reason is
// barely better than silence.
{
  // 201..300, the same trimmed buffer as above: numbering that no longer
  // starts at 1 is the whole situation this exists for.
  const buffer = Array.from({ length: 100 }, (_, i) => makePacket(201 + i));

  check('a frame that is present is not refused', frameJumpRefusal(buffer, 250), null);
  check('...including the first', frameJumpRefusal(buffer, 201), null);
  check('...and the last', frameJumpRefusal(buffer, 300), null);

  // The two ends mean different things, and only one of them is permanent.
  const trimmed = frameJumpRefusal(buffer, 12);
  checkTrue('a frame below the buffer says it is gone',
    trimmed !== null && trimmed.includes('no longer'));
  checkTrue('...and says what is held instead',
    trimmed !== null && trimmed.includes('201') && trimmed.includes('300'));

  const ahead = frameJumpRefusal(buffer, 9999);
  checkTrue('a frame above the buffer says it has not arrived',
    ahead !== null && ahead.includes('not yet'));

  const none = frameJumpRefusal([], 5);
  checkTrue('an empty buffer refuses without inventing a range',
    none !== null && none.includes('empty'));
}

// --- Frame summary ----------------------------------------------------------
{
  // Wire length and captured length are the same in the ordinary case, and
  // saying so twice would be noise - so the second is only reported when it
  // genuinely differs.
  const whole = makePacket(1, { length: 74, rawBytes: new Uint8Array(74) });
  check('a fully captured frame reports one length', buildFrameSummary(whole).captureLength, null);

  const truncated = makePacket(2, { length: 1514, rawBytes: new Uint8Array(96) });
  const tSummary = buildFrameSummary(truncated);
  check('a truncated frame reports the wire length', tSummary.frameLength, 1514);
  check('...and separately the captured length', tSummary.captureLength, 96);

  const byteless = makePacket(3, { length: 120, rawBytes: new Uint8Array(0) });
  check('a frame with no bytes at all does not claim a capture length of 0', buildFrameSummary(byteless).captureLength, null);

  // Precision follows the capture's own resolution, the way the Time column
  // does - printing more digits than the capture carries invents precision.
  const micro = makePacket(4, { relativeTime: 1.5, timeDelta: 0.25, tsPrecision: 6 });
  check('microsecond capture prints 6 decimals', buildFrameSummary(micro).relativeTime, '1.500000');
  const nano = makePacket(5, { relativeTime: 1.5, timeDelta: 0.25, tsPrecision: 9 });
  check('nanosecond capture prints 9 decimals', buildFrameSummary(nano).relativeTime, '1.500000000');
  check('...and the delta matches that resolution', buildFrameSummary(nano).timeDelta, '0.250000000');
  check('missing precision defaults to 6', buildFrameSummary(makePacket(6, { relativeTime: 2 })).relativeTime, '2.000000');

  const rich = makePacket(7, {
    frameProtocols: ['eth', 'ip', 'udp', 'dns'],
    analysisFlags: ['retransmission'],
    interfaceName: 'Wi-Fi',
    status: 'warning',
  });
  const rSummary = buildFrameSummary(rich);
  check('the protocol chain comes through in order', rSummary.protocolChain, ['eth', 'ip', 'udp', 'dns']);
  check('analysis flags come through', rSummary.analysisFlags, ['retransmission']);
  check('the interface comes through', rSummary.interfaceName, 'Wi-Fi');
  check('the status comes through', rSummary.status, 'warning');

  const bare = buildFrameSummary(makePacket(8));
  check('a frame with no protocol chain gets an empty list, not undefined', bare.protocolChain, []);
  check('...and no analysis flags likewise', bare.analysisFlags, []);

  // A nonsense timestamp must not render "Invalid Date" into the header.
  const broken = buildFrameSummary(makePacket(9, { tsUs: Number.NaN }));
  check('an unusable timestamp degrades to a word, not Invalid Date', [broken.localTime, broken.utcTime], ['unknown', 'unknown']);
}

// --- Related frames ---------------------------------------------------------
{
  const field = (name: string, over: Partial<ProtocolField> = {}): ProtocolField => ({
    name, value: '', ...over,
  });
  const layer = (name: string, fields: ProtocolField[]): ProtocolLayer => ({ name, summary: name, fields });

  const packet = makePacket(10, {
    streamId: 3,
    layers: [
      layer('Frame', [field('Frame Number', { value: 10 })]),
      layer('ICMP', [
        field('Type', { value: 8 }),
        // Nested under a generated grouping node, which is where dissectors
        // usually put these - a top-level-only walk would miss it.
        field('[Timestamps]', {
          children: [field('[Response In]', { value: 11, linkToFrame: 11 })],
        }),
      ]),
      layer('TCP', [field('[Request In]', { value: 4, linkToFrame: 4 })]),
    ],
  });

  const related = collectRelatedFrames(packet);
  check('finds a reference nested inside a grouping node', related.some(r => r.frameNumber === 11), true);
  check('finds a top-level reference too', related.some(r => r.frameNumber === 4), true);
  check('carries the field name that made the reference', related.find(r => r.frameNumber === 11)?.label, '[Response In]');
  check('finds exactly the two references present', related.length, 2);

  const dup = makePacket(11, {
    layers: [layer('X', [
      field('[Response In]', { value: 11, linkToFrame: 11 }),
      field('[Also]', { value: 11, linkToFrame: 11 }),
    ])],
  });
  check('the same frame referenced twice is listed once', collectRelatedFrames(dup).length, 1);

  check('a frame with no references yields none', collectRelatedFrames(makePacket(12)), []);
  check('a layer with no fields does not crash', collectRelatedFrames(makePacket(13, {
    layers: [{ name: 'Empty', summary: 'Empty', fields: [] }],
  })), []);
}

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
