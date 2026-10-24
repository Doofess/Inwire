/**
 * The Schedule panel shows the calendar only when it can set something, and
 * its Start and Stop controls fit the side bar's column.
 *
 *   npx tsx scripts/session/schedule-panel.ts
 *
 * The calendar was always open, greyed out under a note saying how to make it
 * work: on a Manual/Manual schedule - the default - a third of the panel was a
 * control that did nothing. It appears now when Start or Stop is "At a time".
 * Stop's four modes overflowed their card at 1024; `Segmented`'s `fill` shares
 * the column between the segments instead of sizing each to its label.
 */
import { readFileSync } from 'node:fs';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const panel = readFileSync('src/components/sidebar/CaptureSchedulePanel.tsx', 'utf8');
const segmented = readFileSync('src/components/ui/segmented.tsx', 'utf8');

check('the Calendar section renders only when an end is timed',
  /\{calendarLive && \(\s*<Section\s+title="Calendar"/.test(panel));
check('the "how to make it work" note is gone', !panel.includes('to pick a day'));
check('the calendar is never drawn disabled', !panel.includes('disabled={!calendarLive}'));

check('Segmented takes fill', /fill\?: boolean/.test(segmented));
check('a filled group spans the column', /fill && "flex w-full"/.test(segmented));
// `flex-auto`, not `flex-1`: equal thirds clipped "At a time" at 192px while
// "After" had room to spare. Sized from the label, shrinking only when short.
check('a filled segment grows from its label and can shrink below it',
  /fill \? "flex-auto min-w-0 px-1 text-center\b/.test(segmented));

const uses = [...panel.matchAll(/<Segmented[\s\S]*?\/>/g)].map((m) => m[0]);
check('the panel has the Start and Stop segmented controls', uses.length === 2, `found ${uses.length}`);
check('both pass fill', uses.length === 2 && uses.every((u) => /\bfill\b/.test(u)));

if (failures > 0) {
  console.log(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('\nAll schedule panel checks passed.');
process.exit(0);
