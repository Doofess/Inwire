/**
 * Assertion tests for the expert-information log.
 *
 *   npx tsx scripts/expert/log.ts
 *
 * The log used to translate between two vocabularies - dissectors wrote
 * `chat/note/warn/error` onto tree rows while the anomaly detector wrote
 * `low/medium/high/critical` - and most of these checks were about that
 * translation. Severity is gone (see the header of `services/expertInfo.ts`:
 * every single `error/Checksum` finding in both fixtures was on a frame this
 * machine sent, so the scale could not tell damaged from not-yet-written), and
 * with it the anomaly list that was the other half of the translation.
 *
 * What is left to assert is the part that always mattered: where a finding is
 * read from, that it is read from exactly one place, how identical findings
 * collapse, and which single category a frame is painted by.
 */
import {
  CATEGORY_ORDER, ExpertLog, buildExpertLog, expertItemsFor, isFaultCategory,
} from '../../src/services/expertInfo';
import { withDuplicate } from '../../src/services/direction';
import type { ExpertCategory, ExpertInfo, Packet, ProtocolField } from '../../src/types/packet';

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
function packet(
  fields: ProtocolField[],
  opts: { expert?: ExpertInfo[]; label?: string; direction?: number } = {},
): Packet {
  return {
    id: nextId++,
    tsUs: 0, relativeTime: 0, timeDelta: 0,
    source: '10.0.0.1', destination: '10.0.0.2',
    protocol: 'TCP', protocolLabel: opts.label ?? 'TCP',
    length: 100, info: '', status: 'ok',
    layers: [{ name: 'L', summary: '', fields }],
    rawBytes: new Uint8Array(0),
    expert: opts.expert,
    direction: opts.direction,
    interfaceName: 'test',
  };
}

const finding = (category: ExpertCategory, message: string): ExpertInfo => ({ category, message });

// --- where a finding is read from ---------------------------------------------

{
  nextId = 1;
  // The flat list is the normal path: the tree is dissected on demand
  // (docs/decisions/0007), so a frame nobody has clicked on has no tree to walk.
  const items = expertItemsFor(packet([], {
    expert: [finding('Broken', 'Bad checksum'), finding('Loss', '[TCP Retransmission]')],
  }));
  check('the flat list the dissector published is the answer', items.length, 2);
  check('...carrying its category', items.map((i) => `${i.category}|${i.summary}`),
    ['Broken|Bad checksum', 'Loss|[TCP Retransmission]']);
}

{
  nextId = 1;
  // The fallback, for a frame from an older build or a custom dissector: the
  // tree, walked to any depth.
  const p = packet([
    { name: 'Checksum', value: 0, expertInfo: finding('Broken', 'Bad checksum') },
    {
      name: '[SEQ/ACK analysis]', value: '',
      children: [
        { name: 'x', value: '', expertInfo: finding('Loss', '[TCP Retransmission]') },
      ],
    },
    { name: 'plain', value: 1 },
  ]);
  const items = expertItemsFor(p);
  check('with no flat list the tree is walked instead', items.length, 2);
  check('...including nested rows', items.map((i) => i.summary).sort(),
    ['Bad checksum', '[TCP Retransmission]']);
  check('a row with no expert info contributes nothing',
    expertItemsFor(packet([{ name: 'plain', value: 1 }])).length, 0);
  check('a finding with no category reads as a Note',
    expertItemsFor(packet([{ name: 'x', value: 1, expertInfo: { message: 'm' } }]))[0].category,
    'Note');
}

{
  nextId = 1;
  // The guard that was documented and missing. A frame carrying both - which
  // is every live-captured frame the moment someone selects it and the tree
  // arrives - counted each finding twice, and the comment above the walk said
  // it could not happen. It only looked correct because `layers` is emptied on
  // restore, which made the branch unreachable rather than right.
  const both = packet(
    [{ name: 'x', value: 0, expertInfo: finding('Broken', 'Bad checksum') }],
    { expert: [finding('Broken', 'Bad checksum')] },
  );
  check('a frame carrying BOTH counts each finding once', expertItemsFor(both).length, 1);
}

// --- the duplicate note is not a fault -----------------------------------------

{
  nextId = 1;
  const items = expertItemsFor(packet([], { direction: withDuplicate(0) }));
  check('a frame captured on two adapters says so', items.length, 1);
  check('...as a Note, because nothing is wrong with the network', items[0].category, 'Note');
  check('...and a Note is not a fault', isFaultCategory('Note'), false);
  check('a Broken frame is', isFaultCategory('Broken'), true);
  check('nothing at all is not', isFaultCategory(undefined), false);
}

// --- aggregation ----------------------------------------------------------------

{
  nextId = 1;
  const log = new ExpertLog();
  for (let i = 0; i < 400; i++) {
    log.add(packet([], { expert: [finding('Loss', '[TCP Retransmission]')] }));
  }
  log.add(packet([], { expert: [finding('Broken', 'Bad checksum')] }));

  const groups = log.groups();
  check('identical findings collapse to one row', groups.length, 2);
  check('...with the count', groups.find((g) => g.category === 'Loss')?.count, 400);
  check('the row highest in chain order is listed first', groups[0].category, 'Broken');
  check('the counts strip counts findings, not rows', log.counts(), {
    Broken: 1, Reset: 0, Security: 0, Loss: 400,
    CaptureGap: 0, FlowControl: 0, Unverifiable: 0, Note: 0,
  });
  check('the total is every finding', log.size, 401);
  // The frame list is for jumping to the evidence, not for exporting the
  // capture, so it stops well short of four hundred entries.
  check('a group remembers a bounded number of frames',
    groups.find((g) => g.category === 'Loss')!.frames.length, 200);
  check('...starting with the first', groups.find((g) => g.category === 'Loss')!.frames[0], 1);
}

{
  nextId = 1;
  // Wireshark's Dup ACK summary names the frame it duplicates and how many
  // times, which is right in the Info column and wrong as an aggregation key:
  // every Dup ACK became its own row, so the one table that exists to collapse
  // repeats did not collapse the finding that repeats most.
  const log = new ExpertLog();
  for (let i = 0; i < 50; i++) {
    log.add(packet([], { expert: [finding('Loss', `[TCP Dup ACK ${3515 + i}#${(i % 3) + 1}]`)] }));
  }
  check('Dup ACKs collapse to one row', log.groups().length, 1);
  check('...under the summary with the numbers taken out', log.groups()[0].summary, '[TCP Dup ACK]');
  check('...counting every one of them', log.groups()[0].count, 50);
  // The frame numbers are the thing the embedded ids were being kept for, and
  // they are still here per row.
  check('...and the frames are still recoverable', log.groups()[0].frames.slice(0, 3), [1, 2, 3]);
}

{
  nextId = 1;
  // The same problem in the other message that names a per-frame number. A
  // browsing capture offloads at dozens of distinct sizes, so this was one row
  // per size: 91 distinct findings over the inwire fixture, against 14 once
  // both are collapsed.
  const log = new ExpertLog();
  for (const size of [2709, 2267, 6229, 2709]) {
    log.add(packet([], {
      expert: [finding('Unverifiable',
        `Frame is ${size} bytes, past the 1514-byte Ethernet MTU - segmentation offload`)],
    }));
  }
  check('offload findings collapse however many sizes there were', log.groups().length, 1);
  check('...under a summary with the size taken out', log.groups()[0].summary,
    'Frame is past the 1514-byte Ethernet MTU - segmentation offload');
  check('...counting every one', log.groups()[0].count, 4);
}

// --- the one category a frame is painted by --------------------------------------

{
  nextId = 1;
  const log = new ExpertLog();
  log.add(packet([], {
    expert: [finding('FlowControl', 'w'), finding('Broken', 'e'), finding('Note', 'n')],
  }));
  check('a frame reads as the first of its findings in chain order', log.categoryOf(1), 'Broken');
  check('a frame with no finding has none', log.categoryOf(99), undefined);
}

{
  nextId = 1;
  // Order of arrival must not change the answer.
  const log = new ExpertLog();
  log.add(packet([], { expert: [finding('Broken', 'e'), finding('FlowControl', 'w')] }));
  check('...whichever order the findings arrive in', log.categoryOf(1), 'Broken');
}

// --- built from a buffer, and empty ---------------------------------------------

{
  nextId = 1;
  const log = buildExpertLog([
    packet([], { expert: [finding('Security', 'Certificate expired')], label: 'TLSv1.2' }),
    packet([]),
  ]);
  check('a whole buffer folds in one pass', log.size, 1);
  check('the row keeps the protocol it was raised on', log.groups()[0].protocol, 'TLSv1.2');
}

{
  const log = new ExpertLog();
  check('an empty log has no rows', log.groups(), []);
  check('...and zero in every category', log.counts(), {
    Broken: 0, Reset: 0, Security: 0, Loss: 0,
    CaptureGap: 0, FlowControl: 0, Unverifiable: 0, Note: 0,
  });
  // The order is the shipped colour chain's, and it is what decides which
  // category paints a frame carrying several. Stated here rather than derived
  // so that reordering the chain has to be a deliberate edit in two places.
  check('the chain order is damage, then network, then vantage point, then noise',
    [...CATEGORY_ORDER],
    ['Broken', 'Reset', 'Security', 'Loss', 'CaptureGap', 'FlowControl', 'Unverifiable', 'Note']);
  check('the fault categories are the first four',
    CATEGORY_ORDER.map(isFaultCategory),
    [true, true, true, true, false, false, false, false]);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All expert information checks passed.');
process.exit(0);
