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

const seg = (from: 'client' | 'server', flags: string, n: { seq?: number; len?: number; ack?: number } = {}): TcpSegment => ({
  from,
  syn: flags.includes('S'), ack: flags.includes('A'), fin: flags.includes('F'), rst: flags.includes('R'),
  ...(n.seq !== undefined ? { seq: n.seq } : {}),
  ...(n.len !== undefined ? { len: n.len } : {}),
  ...(n.ack !== undefined ? { ackNo: n.ack } : {}),
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

check('state round-trips through JSON', (() => {
  const m = new TcpStateMachine();
  for (const s of handshake) m.apply(s);
  const back = new TcpStateMachine(JSON.parse(JSON.stringify(m.state)));
  return back.apply(seg('client', 'FA')).map(short);
})(), ['client:ESTABLISHED>FIN_WAIT_1:sent', 'server:ESTABLISHED>CLOSE_WAIT:received']);

console.log(failures === 0 ? '\nall passed' : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
