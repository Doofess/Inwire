/**
 * The ladder's DNS marks: an unanswered query and a failed answer (ADR 0055, stage 3).
 *
 *   npx tsx scripts/conversation/dns-marks.ts
 */
import { dnsMarks } from '../../src/services/conversation/dnsMarks';
import type { Packet } from '../../src/types/packet';

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

function row(id: number, time: number, dnsId: number, response: boolean, rcode?: number): Packet {
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: time,
    source: '10.0.0.2', destination: '10.0.0.1', sourcePort: 50000, destPort: 53,
    protocol: 'DNS', frameProtocols: ['eth', 'ip', 'udp', 'dns'],
    fields: { 'dns.id': dnsId, 'dns.flags.response': response ? 1 : 0, ...(rcode === undefined ? {} : { 'dns.flags.rcode': rcode }) },
    length: 80, info: '', status: 'ok',
  } as unknown as Packet;
}
const entries = (m: Map<number, string>) => [...m.entries()];

check('an unanswered query is marked no answer',
  entries(dnsMarks([row(1, 10, 5, false), row(2, 10.1, 6, false), row(3, 10.2, 6, true, 0)], 15)), [[1, 'no answer']]);
check('an error answer is marked with its rcode name',
  entries(dnsMarks([row(1, 10, 5, false), row(2, 10.1, 5, true, 3), row(3, 11, 6, true, 99)], 11)),
  [[2, 'No such name'], [3, 'error']]);
check('a waiting query is not marked', entries(dnsMarks([row(1, 10, 5, false)], 14.9)), []);
check('a repeated query marks only its last copy',
  entries(dnsMarks([row(1, 10, 5, false), row(2, 11, 5, false)], 30)), [[2, 'no answer']]);
check('a retried query answered is not marked',
  entries(dnsMarks([row(1, 10, 5, false), row(2, 11, 5, false), row(3, 11.1, 5, true, 0)], 30)), []);
// A finished capture (a file, or a stopped or paused capture) gains no answers,
// so a query still inside the wait window will never be answered.
check('finished: a query inside the wait window is marked no answer',
  entries(dnsMarks([row(1, 10, 5, false)], 14.9, true)), [[1, 'no answer']]);
check('finished: an answered query is still not marked',
  entries(dnsMarks([row(1, 10, 5, false), row(2, 10.1, 5, true, 0)], 14.9, true)), []);
check('not finished is the default', entries(dnsMarks([row(1, 10, 5, false)], 14.9, false)), []);

console.log(failures === 0 ? '\nall passed' : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
