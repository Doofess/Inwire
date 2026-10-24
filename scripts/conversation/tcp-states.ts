/**
 * RFC 793 states inferred from one vantage point (ADR 0055).
 *
 *   npx tsx scripts/conversation/tcp-states.ts
 *
 * Every case is a sequence of segments as the wire showed them, and the
 * assertion is the whole list of transitions, not only the final states. A
 * machine that reaches the right end by the wrong path draws the wrong map.
 */
import {
  TcpStateMachine, outcomeOf, type TcpSegment, type TcpTransition,
} from '../../src/services/conversation/tcpStates';

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

const seg = (
  from: 'client' | 'server', flags: string,
  n: { seq?: number; len?: number; ack?: number; raw?: number; reused?: boolean } = {},
): TcpSegment => ({
  from,
  syn: flags.includes('S'), ack: flags.includes('A'), fin: flags.includes('F'), rst: flags.includes('R'),
  ...(n.seq !== undefined ? { seq: n.seq } : {}),
  ...(n.len !== undefined ? { len: n.len } : {}),
  ...(n.ack !== undefined ? { ackNo: n.ack } : {}),
  ...(n.raw !== undefined ? { rawSeq: n.raw } : {}),
  ...(n.reused ? { reused: true } : {}),
});
const short = (t: TcpTransition) => `${t.side}:${t.from}>${t.to}:${t.evidence}`;
function run(segments: TcpSegment[]) {
  const m = new TcpStateMachine();
  const steps = segments.flatMap((s) => m.apply(s).map(short));
  return { steps, state: { client: m.state.client, server: m.state.server }, outcome: outcomeOf(m.state), joined: m.state.joined };
}

const handshake = [seg('client', 'S', { seq: 0 }), seg('server', 'SA', { seq: 0, ack: 1 }), seg('client', 'A', { seq: 1, ack: 1 })];

{
  const r = run([
    ...handshake,
    seg('client', 'A', { seq: 1, len: 99, ack: 1 }),
    seg('server', 'A', { seq: 1, len: 499, ack: 100 }),
    seg('client', 'FA', { seq: 100, len: 0, ack: 500 }),
    seg('server', 'A', { seq: 500, ack: 101 }),
    seg('server', 'FA', { seq: 500, ack: 101 }),
    seg('client', 'A', { seq: 101, ack: 501 }),
  ]);
  check('active close by client: every step', r.steps, [
    'client:UNKNOWN>SYN_SENT:sent', 'server:UNKNOWN>LISTEN:inferred',
    'server:LISTEN>SYN_RCVD:sent',
    'client:SYN_SENT>ESTABLISHED:sent', 'server:SYN_RCVD>ESTABLISHED:received',
    'client:ESTABLISHED>FIN_WAIT_1:sent', 'server:ESTABLISHED>CLOSE_WAIT:received',
    'client:FIN_WAIT_1>FIN_WAIT_2:received',
    'server:CLOSE_WAIT>LAST_ACK:sent',
    'server:LAST_ACK>CLOSED:received', 'client:FIN_WAIT_2>TIME_WAIT:sent',
  ]);
  check('active close by client: outcome', r.outcome, 'closed cleanly');
}

check('refused', run([seg('client', 'S'), seg('server', 'RA')]).outcome, 'refused');
check('no reply, SYN retransmitted once', run([seg('client', 'S'), seg('client', 'S')]).steps,
  ['client:UNKNOWN>SYN_SENT:sent', 'server:UNKNOWN>LISTEN:inferred']);
check('no reply outcome', run([seg('client', 'S'), seg('client', 'S')]).outcome, 'no reply');
check('handshake unfinished', run([seg('client', 'S'), seg('server', 'SA')]).outcome, 'handshake unfinished');

{
  const r = run([seg('server', 'A', { seq: 9, len: 10, ack: 4 }), seg('client', 'A', { seq: 4, ack: 19 })]);
  check('joined mid-stream: steps', r.steps,
    ['server:UNKNOWN>ESTABLISHED:inferred', 'client:UNKNOWN>ESTABLISHED:inferred']);
  check('joined mid-stream: flag and outcome', [r.joined, r.outcome], [true, 'open']);
}

check('reset by client after handshake', run([...handshake, seg('client', 'RA')]).outcome, 'reset by client');
check('a stray RST after a clean close stays clean', run([
  ...handshake, seg('client', 'FA', { seq: 1, ack: 1 }), seg('server', 'FA', { seq: 1, ack: 2 }),
  seg('client', 'A', { seq: 2, ack: 2 }), seg('client', 'R', { seq: 2 }),
]).outcome, 'closed cleanly');

{
  // FINs cross: the server's FIN does not yet acknowledge the client's.
  const r = run([
    ...handshake,
    seg('client', 'FA', { seq: 1, ack: 1 }),
    seg('server', 'FA', { seq: 1, ack: 1 }),
    seg('client', 'A', { seq: 2, ack: 2 }),
    seg('server', 'A', { seq: 2, ack: 2 }),
  ]);
  check('crossing FINs end clean', [r.state, r.outcome],
    [{ client: 'TIME_WAIT', server: 'CLOSED' }, 'closed cleanly']);
}

{
  const r = run([...handshake, seg('client', 'FA', { seq: 1, ack: 1 }), seg('server', 'A', { seq: 1, ack: 2 }),
    seg('server', 'A', { seq: 1, len: 100, ack: 2 })]);
  check('half-closed by client', [r.state, r.outcome],
    [{ client: 'FIN_WAIT_2', server: 'CLOSE_WAIT' }, 'half-closed by client']);
}

check('SYN not captured, SYN+ACK first', run([seg('server', 'SA')]).steps,
  ['server:UNKNOWN>LISTEN:inferred', 'server:LISTEN>SYN_RCVD:sent', 'client:UNKNOWN>SYN_SENT:inferred']);

check('no sequence numbers: the next ACK acknowledges the FIN',
  run([...handshake, seg('client', 'FA'), seg('server', 'A')]).state,
  { client: 'FIN_WAIT_2', server: 'CLOSE_WAIT' });

{
  const r = run([...handshake, seg('client', 'RA'), seg('client', 'S'), seg('server', 'SA'), seg('client', 'A')]);
  check('port reuse: a new SYN after CLOSED reopens', r.state, { client: 'ESTABLISHED', server: 'ESTABLISHED' });
}

// A reused five-tuple is a new connection: the old one's outcome must not leak.
check('reused port pair, refused: outcome is refused', run([
  ...handshake, seg('client', 'RA'), seg('client', 'S'), seg('server', 'RA'),
]).outcome, 'refused');
check('reused port pair, no answer: outcome is no reply', run([
  ...handshake, seg('client', 'RA'), seg('client', 'S'),
]).outcome, 'no reply');

// FIN at the top of the 32-bit range ends at 0 once the sequence wraps.
check('FIN at the wrap point is acknowledged by ackNo 0', run([
  ...handshake, seg('client', 'FA', { seq: 4294967295, ack: 1 }), seg('server', 'A', { seq: 1, ack: 0 }),
]).state, { client: 'FIN_WAIT_2', server: 'CLOSE_WAIT' });
check('an ACK just below the wrapped FIN end is not taken as acknowledging', run([
  ...handshake, seg('client', 'FA', { seq: 4294967295, ack: 1 }), seg('server', 'A', { seq: 1, ack: 4294967295 }),
]).state, { client: 'FIN_WAIT_1', server: 'CLOSE_WAIT' });

// Port reuse that the old connection's end state does not announce (I1). Every
// SYN reads relative sequence 0, so the raw sequence number (`tcp.seq_raw`) is
// what tells two incarnations apart; tshark's reused-ports flag is the other.
const rawHandshake = (c: number, s: number) => [
  seg('client', 'S', { seq: 0, raw: c }),
  seg('server', 'SA', { seq: 0, ack: 1, raw: s }),
  seg('client', 'A', { seq: 1, ack: 1 }),
];
const firstConnection = rawHandshake(1000, 2000);
const secondConnection = rawHandshake(5000, 6000);
const secondSteps = [
  'client:CLOSED>SYN_SENT:sent', 'server:CLOSED>LISTEN:inferred', 'server:LISTEN>SYN_RCVD:sent',
  'client:SYN_SENT>ESTABLISHED:sent', 'server:SYN_RCVD>ESTABLISHED:received',
];
/** What `rest` did on top of `before`: its own steps and the final picture. */
function after(before: TcpSegment[], rest: TcpSegment[]) {
  const m = new TcpStateMachine();
  for (const s of before) m.apply(s);
  const steps = rest.flatMap((s) => m.apply(s).map(short));
  return {
    steps, state: { client: m.state.client, server: m.state.server }, outcome: outcomeOf(m.state),
    finAcked: m.state.finAcked, machine: m,
  };
}
const open = { client: 'ESTABLISHED', server: 'ESTABLISHED' };

{
  // (a) The close was never captured: the new handshake met two ESTABLISHED sides.
  const before = [...firstConnection, seg('client', 'A', { seq: 1, len: 10, ack: 1 })];
  const r = after(before, secondConnection);
  check('reuse (a): the old close unseen, the new handshake is folded', r.steps, secondSteps);
  check('reuse (a): state and outcome belong to the new connection', [r.state, r.outcome], [open, 'open']);
}
{
  // (b) The server closed first and the last ACK was missed: LAST_ACK / FIN_WAIT_2.
  const before = [
    ...firstConnection,
    seg('server', 'FA', { seq: 1, ack: 1 }),
    seg('client', 'FA', { seq: 1, ack: 2 }),
  ];
  const stuck = after(before, []);
  check('reuse (b): the old side really is mid-close', stuck.state, { client: 'LAST_ACK', server: 'FIN_WAIT_2' });
  const r = after(before, secondConnection);
  check('reuse (b): the server-first close with a missed ACK, then reuse', r.steps, secondSteps);
  check('reuse (b): not reported as closing', [r.state, r.outcome], [open, 'open']);
}
{
  // (c) The last ACK was missed, and the new handshake's ACK must not stand in for it.
  const before = [
    ...firstConnection,
    seg('client', 'FA', { seq: 1, ack: 1 }),
    seg('server', 'A', { seq: 1, ack: 2 }),
    seg('server', 'FA', { seq: 1, ack: 2 }),
  ];
  const r = after(before, secondConnection);
  check('reuse (c): final ACK missed, then reuse', r.steps, secondSteps);
  check('reuse (c): the old FIN is not acknowledged by the new handshake',
    [r.state, r.outcome, r.finAcked], [open, 'open', { client: false, server: false }]);

  // Without sequence numbers, any next ACK would acknowledge the old FIN.
  const bare = (c: number, s: number) => [
    seg('client', 'S', { raw: c }), seg('server', 'SA', { raw: s }), seg('client', 'A'),
  ];
  const nb = after(
    [...bare(1000, 2000), seg('client', 'FA'), seg('server', 'A'), seg('server', 'FA')],
    bare(5000, 6000),
  );
  check('reuse (c) with no numbers: the new ACK does not acknowledge the old FIN',
    [nb.steps, nb.outcome, nb.finAcked], [secondSteps, 'open', { client: false, server: false }]);
}
{
  // The tshark flag alone: no raw numbers, and a client still in SYN_SENT, which
  // would otherwise read as a SYN retransmission.
  const r = after([seg('client', 'S'), seg('server', 'SA')], [seg('client', 'S', { reused: true })]);
  check('reuse by flag: a reused-ports SYN starts over', [r.steps, r.outcome],
    [['client:CLOSED>SYN_SENT:sent', 'server:CLOSED>LISTEN:inferred'], 'no reply']);
}
{
  // A different ISN while still in SYN_SENT is a new connection, too.
  const r = after([seg('client', 'S', { raw: 1000 })], [seg('client', 'S', { raw: 5000 })]);
  check('reuse by ISN while SYN_SENT: a different ISN starts over', r.steps,
    ['client:CLOSED>SYN_SENT:sent', 'server:CLOSED>LISTEN:inferred']);
}
{
  // The same ISN is the same connection, however far along it is.
  const dup = seg('client', 'S', { seq: 0, raw: 1000 });
  const retransmit = after([seg('client', 'S', { seq: 0, raw: 1000 })], [dup]);
  check('same ISN in SYN_SENT: a retransmission changes nothing', retransmit.steps, []);

  const established = after(firstConnection, [dup]);
  check('same ISN after ESTABLISHED: a duplicate SYN does not split the connection',
    [established.steps, established.state, established.outcome], [[], open, 'open']);

  const closed = [
    ...firstConnection,
    seg('client', 'FA', { seq: 1, ack: 1 }), seg('server', 'A', { seq: 1, ack: 2 }),
    seg('server', 'FA', { seq: 1, ack: 2 }), seg('client', 'A', { seq: 2, ack: 2 }),
  ];
  const late = after(closed, [dup]);
  check('same ISN after a clean close: a late duplicate SYN does not reopen it',
    [late.steps, late.state, late.outcome], [[], { client: 'TIME_WAIT', server: 'CLOSED' }, 'closed cleanly']);

  const next = after(firstConnection, [dup, seg('client', 'FA', { seq: 1, ack: 1 })]);
  check('same ISN: the connection carries on from where it was', next.steps,
    ['client:ESTABLISHED>FIN_WAIT_1:sent', 'server:ESTABLISHED>CLOSE_WAIT:received']);
}
{
  // A state restored from before `isn` existed reads as "unknown", not a crash.
  const m = new TcpStateMachine();
  for (const s of firstConnection) m.apply(s);
  const old = JSON.parse(JSON.stringify(m.state));
  delete old.isn;
  const back = new TcpStateMachine(old);
  const steps = secondConnection.flatMap((s) => back.apply(s).map(short));
  check('a snapshot without isn: a bare SYN past SYN_SENT still starts over', steps, secondSteps);
}

check('state round-trips through JSON', (() => {
  const m = new TcpStateMachine();
  for (const s of handshake) m.apply(s);
  const back = new TcpStateMachine(JSON.parse(JSON.stringify(m.state)));
  return back.apply(seg('client', 'FA')).map(short);
})(), ['client:ESTABLISHED>FIN_WAIT_1:sent', 'server:ESTABLISHED>CLOSE_WAIT:received']);

console.log(failures === 0 ? '\nall passed' : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
