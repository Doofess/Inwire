/**
 * Assertion tests for the expert-information log.
 *
 *   npx tsx scripts/expert/log.ts
 *
 * The point of this module is that two vocabularies became one: dissectors
 * wrote `chat/note/warn/error` onto tree rows while the anomaly detector wrote
 * `low/medium/high/critical`, and nothing related them - so the same frame
 * could be a "warning" in the tree and a "high" in the alerts panel, and no
 * view could rank one against the other. The checks below are mostly about
 * that translation and about the aggregation on top of it: four hundred
 * retransmissions are one problem with a count, not four hundred rows.
 */
import { ExpertLog, buildExpertLog, expertItemsFor, SEVERITY_ORDER } from '../../src/services/expertInfo';
import type { AnomalyInfo, Packet, ProtocolField } from '../../src/types/packet';

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

let nextId = 1;
function packet(fields: ProtocolField[], anomalies?: AnomalyInfo[], label = 'TCP'): Packet {
  return {
    id: nextId++,
    tsUs: 0, relativeTime: 0, timeDelta: 0,
    source: '10.0.0.1', destination: '10.0.0.2',
    protocol: 'TCP', protocolLabel: label,
    length: 100, info: '', status: 'ok',
    layers: [{ name: 'L', summary: '', fields }],
    rawBytes: new Uint8Array(0),
    anomalies,
    interfaceName: 'test',
  };
}

const anomaly = (severity: AnomalyInfo['severity'], title: string): AnomalyInfo => ({
  type: 't', severity, title, description: '', recommendation: '',
});

// --- what a frame contributes -------------------------------------------------

{
  nextId = 1;
  const p = packet([
    { name: 'Checksum', value: 0, expertInfo: { severity: 'error', group: 'Checksum', message: 'Bad checksum' } },
    {
      name: '[SEQ/ACK analysis]', value: '',
      children: [
        { name: 'x', value: '', expertInfo: { severity: 'note', group: 'Sequence', message: '[TCP Retransmission]' } },
      ],
    },
    { name: 'plain', value: 1 },
  ]);
  const items = expertItemsFor(p);
  check('findings are collected from anywhere in the tree', items.length, 2);
  check('...including nested ones', items.map(i => i.summary).sort(),
    ['Bad checksum', '[TCP Retransmission]']);
  check('a row with no expert info contributes nothing',
    expertItemsFor(packet([{ name: 'plain', value: 1 }])).length, 0);
  check('a finding without a group falls back to Protocol',
    expertItemsFor(packet([{ name: 'x', value: 1, expertInfo: { severity: 'note', message: 'm' } }]))[0].group,
    'Protocol');
}

// --- the two vocabularies become one ------------------------------------------

{
  nextId = 1;
  const items = expertItemsFor(packet([], [
    anomaly('critical', 'c'), anomaly('high', 'h'), anomaly('medium', 'm'), anomaly('low', 'l'),
  ]));
  check('anomaly severities map onto the shared four',
    items.map(i => `${i.summary}=${i.severity}`),
    ['c=error', 'h=error', 'm=warn', 'l=note']);
  check('an anomaly is a Security finding', items[0].group, 'Security');
}

// --- aggregation ----------------------------------------------------------------

{
  nextId = 1;
  const log = new ExpertLog();
  for (let i = 0; i < 400; i++) {
    log.add(packet([{ name: 'x', value: '', expertInfo: { severity: 'note', group: 'Sequence', message: '[TCP Retransmission]' } }]));
  }
  log.add(packet([{ name: 'x', value: 0, expertInfo: { severity: 'error', group: 'Checksum', message: 'Bad checksum' } }]));

  const groups = log.groups();
  check('identical findings collapse to one row', groups.length, 2);
  check('...with the count', groups.find(g => g.group === 'Sequence')?.count, 400);
  check('the worst is listed first', groups[0].severity, 'error');
  check('the counts strip counts findings, not rows', log.counts(), { error: 1, warn: 0, note: 400, chat: 0 });
  check('the total is every finding', log.size, 401);
  // The frame list is for jumping to the evidence, not for exporting the
  // capture, so it stops well short of four hundred entries.
  check('a group remembers a bounded number of frames',
    groups.find(g => g.group === 'Sequence')!.frames.length, 200);
  check('...starting with the first', groups.find(g => g.group === 'Sequence')!.frames[0], 1);
}

// --- the per-frame severity the list draws ---------------------------------------

{
  nextId = 1;
  const log = new ExpertLog();
  log.add(packet([
    { name: 'a', value: '', expertInfo: { severity: 'note', group: 'Sequence', message: 'n' } },
    { name: 'b', value: '', expertInfo: { severity: 'error', group: 'Checksum', message: 'e' } },
    { name: 'c', value: '', expertInfo: { severity: 'chat', group: 'Protocol', message: 'c' } },
  ]));
  check('a frame is marked at its WORST severity', log.severityOf(1), 'error');
  check('a frame with no finding has none', log.severityOf(99), undefined);
}

{
  nextId = 1;
  // Order of arrival must not change the answer.
  const log = new ExpertLog();
  log.add(packet([
    { name: 'b', value: '', expertInfo: { severity: 'error', group: 'Checksum', message: 'e' } },
    { name: 'a', value: '', expertInfo: { severity: 'note', group: 'Sequence', message: 'n' } },
  ]));
  check('...whichever order the findings arrive in', log.severityOf(1), 'error');
}

// --- built from a buffer, and empty ---------------------------------------------

{
  nextId = 1;
  const log = buildExpertLog([
    packet([{ name: 'x', value: '', expertInfo: { severity: 'warn', group: 'Security', message: 'Certificate expired' } }], undefined, 'TLSv1.2'),
    packet([]),
  ]);
  check('a whole buffer folds in one pass', log.size, 1);
  check('the row keeps the protocol it was raised on', log.groups()[0].protocol, 'TLSv1.2');
}

{
  const log = new ExpertLog();
  check('an empty log has no rows', log.groups(), []);
  check('...and zero at every level', log.counts(), { error: 0, warn: 0, note: 0, chat: 0 });
  check('severities are ordered worst first', [...SEVERITY_ORDER], ['error', 'warn', 'note', 'chat']);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All expert information checks passed.');
process.exit(0);
