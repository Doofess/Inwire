/**
 * Assertion tests for the TCP sequence analysis - the flags a person reads
 * first when a connection misbehaves, held to Wireshark's conditions.
 *
 *   npx tsx scripts/tcp/analysis.ts
 *
 * Each block is a tiny synthetic conversation driven straight through the
 * analyser. The parity harness holds the aggregate counts to tshark on real
 * captures; these pin the individual rules and their thresholds so a change
 * to one cannot hide inside a count that happens to still add up.
 */
import { analyzeTcpSegment, freshConnection, type TcpSegment } from '../../src/services/dissect/tcpAnalysis';

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

let frame = 0;
function seg(over: Partial<TcpSegment> & { timeUs: number }): TcpSegment {
  frame++;
  return { frame, seq: 0, ack: 0, window: 65535, segLen: 0, syn: false, ack_: true, fin: false, rst: false, ...over };
}

// --- a clean handshake raises nothing ------------------------------------------

{
  const c = freshConnection();
  const syn = analyzeTcpSegment(c, 'a', seg({ timeUs: 0, seq: 1000, ack_: false, syn: true, windowScaleOption: 8 }));
  const synAck = analyzeTcpSegment(c, 'b', seg({ timeUs: 1_000, seq: 5000, ack: 1001, syn: true, windowScaleOption: 7 }));
  const ackOf = analyzeTcpSegment(c, 'a', seg({ timeUs: 1_900, seq: 1001, ack: 5001 }));
  check('SYN raises nothing', syn.flags, []);
  check('SYN-ACK raises nothing - the SYN consumed a sequence number', synAck.flags, []);
  check('the handshake ACK raises nothing', ackOf.flags, []);
  check('...and measures the initial RTT', ackOf.initialRttUs, 1_900);
  check('the SYN advanced the sequence by one', c.a.nextSeq, 1001);
}

// --- retransmission vs out-of-order is a timing call --------------------------

{
  const c = freshConnection();
  analyzeTcpSegment(c, 'a', seg({ timeUs: 0, seq: 1, segLen: 100 }));
  analyzeTcpSegment(c, 'a', seg({ timeUs: 1_000, seq: 101, segLen: 100 }));
  const late = analyzeTcpSegment(c, 'a', seg({ timeUs: 500_000, seq: 1, segLen: 100 }));
  check('data already seen, resent half a second later, is a retransmission', late.flags, ['retransmission']);
  check('...with the Info tag', late.tags, ['[TCP Retransmission]']);
}

{
  const c = freshConnection();
  analyzeTcpSegment(c, 'a', seg({ timeUs: 0, seq: 1, segLen: 100 }));
  analyzeTcpSegment(c, 'a', seg({ timeUs: 1_000, seq: 301, segLen: 100 }));   // 101..300 missing
  const gap = analyzeTcpSegment(c, 'a', seg({ timeUs: 2_000, seq: 101, segLen: 100 }));
  check('the missing piece arriving 1 ms later is out-of-order, not a retransmission', gap.flags, ['out_of_order']);
}

{
  const c = freshConnection();
  analyzeTcpSegment(c, 'a', seg({ timeUs: 0, seq: 1, segLen: 100 }));
  analyzeTcpSegment(c, 'b', seg({ timeUs: 500, seq: 1, ack: 101 }));            // b acks 1..100
  const spurious = analyzeTcpSegment(c, 'a', seg({ timeUs: 400_000, seq: 1, segLen: 100 }));
  check('resending data the peer already acknowledged is a spurious retransmission', spurious.flags, ['spurious_retransmission']);
}

// --- duplicate ACKs carry the original frame and a counter --------------------

{
  const c = freshConnection();
  analyzeTcpSegment(c, 'a', seg({ timeUs: 0, seq: 1, segLen: 100 }));
  const first = analyzeTcpSegment(c, 'b', seg({ timeUs: 100, seq: 1, ack: 101 }));
  const firstFrame = frame;
  const d1 = analyzeTcpSegment(c, 'b', seg({ timeUs: 200, seq: 1, ack: 101 }));
  const d2 = analyzeTcpSegment(c, 'b', seg({ timeUs: 300, seq: 1, ack: 101 }));
  check('the first ACK is not a duplicate', first.flags, []);
  check('the second is Dup ACK #1 of the first frame', [d1.flags, d1.dupAckNum, d1.dupAckFrame], [['duplicate_ack'], 1, firstFrame]);
  check('...and its tag names that frame', d1.tags, [`[TCP Dup ACK ${firstFrame}#1]`]);
  check('the third is #2', d2.dupAckNum, 2);
  // A fast retransmission follows within 20 ms.
  const fast = analyzeTcpSegment(c, 'a', seg({ timeUs: 5_000, seq: 101, segLen: 100 }));
  analyzeTcpSegment(c, 'a', seg({ timeUs: 6_000, seq: 201, segLen: 100 }));
  const fr = analyzeTcpSegment(c, 'a', seg({ timeUs: 15_000, seq: 101, segLen: 100 }));
  check('new data after the dup ACKs raises nothing', fast.flags, []);
  check('resending the dup-ACKed sequence within 20 ms is a fast retransmission', fr.flags, ['fast_retransmission']);
}

// --- window updates and zero windows -----------------------------------------------

{
  const c = freshConnection();
  analyzeTcpSegment(c, 'a', seg({ timeUs: 0, seq: 1, segLen: 100 }));
  analyzeTcpSegment(c, 'b', seg({ timeUs: 100, seq: 1, ack: 101, window: 1000 }));
  const wu = analyzeTcpSegment(c, 'b', seg({ timeUs: 200, seq: 1, ack: 101, window: 2000 }));
  check('same seq/ack, new window, no data: a window update', wu.flags, ['window_update']);
  check('...tagged', wu.tags, ['[TCP Window Update]']);
  const zw = analyzeTcpSegment(c, 'b', seg({ timeUs: 300, seq: 1, ack: 101, window: 0 }));
  check('a zero window is flagged', zw.flags.includes('zero_window'), true);
  const probe = analyzeTcpSegment(c, 'a', seg({ timeUs: 400, seq: 101, segLen: 1 }));
  check('one byte into a zero window is a probe', probe.flags, ['zero_window_probe']);
  const probeAck = analyzeTcpSegment(c, 'b', seg({ timeUs: 500, seq: 1, ack: 101, window: 0 }));
  check('the answer with the window still closed is a probe ACK', probeAck.flags.includes('zero_window_probe_ack'), true);
}

// --- keep-alives ---------------------------------------------------------------------

{
  const c = freshConnection();
  analyzeTcpSegment(c, 'a', seg({ timeUs: 0, seq: 1, segLen: 100 }));
  analyzeTcpSegment(c, 'b', seg({ timeUs: 100, seq: 1, ack: 101 }));
  const ka = analyzeTcpSegment(c, 'a', seg({ timeUs: 60_000_000, seq: 100, segLen: 1 }));
  check('one byte one behind the expected sequence is a keep-alive', ka.flags, ['keep_alive']);
  const kaa = analyzeTcpSegment(c, 'b', seg({ timeUs: 60_000_100, seq: 1, ack: 101 }));
  check('the ACK repeating the last ACK right after it is a keep-alive ACK, not a dup ACK', kaa.flags, ['keep_alive_ack']);
}

// --- lost segments and acknowledgments of unseen data ----------------------------

{
  const c = freshConnection();
  analyzeTcpSegment(c, 'a', seg({ timeUs: 0, seq: 1, segLen: 100 }));
  const lost = analyzeTcpSegment(c, 'a', seg({ timeUs: 1_000, seq: 1001, segLen: 100 }));
  check('a jump ahead in sequence means a previous segment was not captured', lost.flags, ['lost_segment']);
  const ackBeyond = analyzeTcpSegment(c, 'b', seg({ timeUs: 2_000, seq: 1, ack: 1101 }));
  check('acknowledging past the gap is flagged once', ackBeyond.flags, ['ack_lost_segment']);
  const ackAgain = analyzeTcpSegment(c, 'b', seg({ timeUs: 3_000, seq: 1, ack: 1101, window: 70000 }));
  check('...and not again by the next ACK', ackAgain.flags.includes('ack_lost_segment'), false);
}

// --- tag order is Wireshark's ---------------------------------------------------------

{
  const c = freshConnection();
  analyzeTcpSegment(c, 'a', seg({ timeUs: 0, seq: 1, segLen: 100 }));
  analyzeTcpSegment(c, 'b', seg({ timeUs: 100, seq: 1, ack: 101 }));
  analyzeTcpSegment(c, 'a', seg({ timeUs: 200, seq: 101, segLen: 100 }));
  // b acknowledges beyond what a was seen to send AND a's data jumps.
  const both = analyzeTcpSegment(c, 'b', seg({ timeUs: 300, seq: 1, ack: 501 }));
  check('an ACK beyond the seen data is flagged', both.flags, ['ack_lost_segment']);
  const a2 = analyzeTcpSegment(c, 'a', seg({ timeUs: 400, seq: 901, segLen: 50 }));
  const b2 = analyzeTcpSegment(c, 'b', seg({ timeUs: 500, seq: 1, ack: 1201 }));
  check('a gap is flagged on the data segment', a2.flags, ['lost_segment']);
  check('an ACK past a gap is again flagged', b2.flags, ['ack_lost_segment']);
}

// --- a SACK block settles dup-ACK vs window-update ------------------------------
//
// These four expectations are tshark's, taken by building the frames and asking
// it, not read off the C. Two segments identical but for the option read
// `[TCP Window Update]` without a SACK block and `[TCP Dup ACK]` with one, on a
// segment whose advertised window had changed.
//
// It is the rule that closed the last mismatched analysis count in either
// fixture. A keep-alive DOES update the remembered window - the first block
// below pins that, because it is the half that surprises - so a direction that
// sends one at a smaller window makes its next ordinary ACK look like a change.
// inwire frame 9379 read as a window update 1,332 frames after two keep-alives
// at 131072 pulled the remembered window down from 131584, and the SACK block
// it carried is what says it was never a window update at all: a receiver
// reporting a hole is the definition of a duplicate ACK.

/** a sends 100 bytes, b acknowledges them, and b is the direction under test. */
function primed(): ReturnType<typeof freshConnection> {
  const c = freshConnection();
  analyzeTcpSegment(c, 'a', seg({ timeUs: 0, seq: 1, segLen: 100, window: 8192 }));
  analyzeTcpSegment(c, 'b', seg({ timeUs: 100, seq: 1, ack: 101, window: 8192 }));
  return c;
}

{
  const c = primed();
  const again = analyzeTcpSegment(c, 'b', seg({ timeUs: 200, seq: 1, ack: 101, window: 8192 }));
  check('the same ACK twice, same window, is a duplicate', again.flags, ['duplicate_ack']);
  check('...and counts itself', again.dupAckNum, 1);
}

{
  const c = primed();
  const wider = analyzeTcpSegment(c, 'b', seg({ timeUs: 200, seq: 1, ack: 101, window: 4096 }));
  check('the same ACK with a different window is a window update', wider.flags, ['window_update']);
}

{
  const c = primed();
  // seq = nextSeq - 1 is the keep-alive signature, and it carries a smaller
  // window. The window it advertises IS remembered - measured, and the reason
  // the fixture frame went wrong 1,332 frames later.
  const ka = analyzeTcpSegment(c, 'b', seg({ timeUs: 200, seq: 0, ack: 101, window: 4096 }));
  check('a keep-alive is recognised', ka.flags, ['keep_alive']);
  const after = analyzeTcpSegment(c, 'b', seg({ timeUs: 300, seq: 1, ack: 101, window: 8192 }));
  check('...and it moved the remembered window, so the next ACK reads as an update',
    after.flags, ['window_update']);
}

{
  const c = primed();
  analyzeTcpSegment(c, 'b', seg({ timeUs: 200, seq: 0, ack: 101, window: 4096 }));
  // The same frame as above, plus a SACK block. The receiver is reporting a
  // hole, so the window it advertises cannot make this a window update.
  const sacked = analyzeTcpSegment(c, 'b', seg({
    timeUs: 300, seq: 1, ack: 101, window: 8192,
    sackBlocks: [{ left: 200, right: 300 }],
  }));
  check('a SACK block makes it a duplicate ACK despite the changed window',
    sacked.flags, ['duplicate_ack']);
  check('...and never both at once', sacked.flags.includes('window_update'), false);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All TCP analysis checks passed.');
process.exit(0);
