/**
 * Assertion tests for the Sent/Received control's effect on the expression.
 *
 *   npx tsx scripts/filter/direction-bar.ts
 *
 * The control writes into the filter the user can see, rather than keeping a
 * second filter of its own - so the thing that can go wrong is not a wrong
 * checkbox, it is a wrong expression the user is then shown as their own.
 *
 * The case that matters most is precedence. `frame.direction == out && dns ||
 * tcp` parses as `(direction && dns) || tcp`, so pressing "Sent" over a filter
 * containing `||` would show inbound frames under a button that says Sent -
 * wrong, and wrong in a way that looks like the feature working.
 */
import {
  directionModeOf, withDirection, withoutDirection,
} from '../../src/lib/directionFilter';

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

// --- Composing over an empty field ---------------------------------------------
check('Sent on an empty filter is the clause alone',
  withDirection('', 'out'), 'frame.direction == out');
check('Received likewise', withDirection('', 'in'), 'frame.direction == in');
check('All on an empty filter stays empty', withDirection('', 'all'), '');

// --- The precedence trap ---------------------------------------------------------
//
// Without the parentheses this reads as (direction && dns) || tcp, and every
// inbound TCP frame appears under a button labelled Sent.
check('the existing expression is parenthesised',
  withDirection('dns || tcp', 'out'), 'frame.direction == out && (dns || tcp)');
check('...even when it looks safe, because consistency is what makes it removable',
  withDirection('dns', 'in'), 'frame.direction == in && (dns)');

// --- Switching replaces rather than accumulates ------------------------------------
{
  const sent = withDirection('dns', 'out');
  const received = withDirection(sent, 'in');
  check('switching Sent to Received replaces the clause',
    received, 'frame.direction == in && (dns)');
  check('...and switching back to All restores what was typed',
    withDirection(received, 'all'), 'dns');
  check('pressing the same one twice changes nothing',
    withDirection(sent, 'out'), sent);
}

// --- The control reads its own position out of the text -----------------------------
//
// Which is what keeps the two from disagreeing: a user who edits the field by
// hand moves the control, rather than leaving it pointing at a filter that is
// no longer there.
check('an empty filter reads as All', directionModeOf(''), 'all');
check('the bare clause reads as Sent', directionModeOf('frame.direction == out'), 'out');
check('a composed clause reads as Received',
  directionModeOf('frame.direction == in && (dns)'), 'in');
check('an ordinary filter reads as All', directionModeOf('tcp.port == 443'), 'all');
// A clause the user wrote themselves somewhere else in the expression is NOT
// this control's clause. Claiming it would mean the next press rewrote a part
// of an expression somebody wrote by hand.
check('a direction test buried mid-expression is not claimed',
  directionModeOf('dns && frame.direction == out'), 'all');
check('...and stripping leaves it alone',
  withoutDirection('dns && frame.direction == out'), 'dns && frame.direction == out');

// --- Round trips -----------------------------------------------------------------
for (const filter of ['', 'dns', 'dns || tcp', 'ip.addr == 10.0.0.4 && tcp.port == 443']) {
  for (const mode of ['out', 'in'] as const) {
    const composed = withDirection(filter, mode);
    if (directionModeOf(composed) !== mode || withoutDirection(composed) !== filter.trim()) {
      check(`round trip of ${JSON.stringify(filter)} as ${mode}`,
        [directionModeOf(composed), withoutDirection(composed)], [mode, filter.trim()]);
    }
  }
}
check('every filter round-trips through both directions', failures, 0);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All direction-bar checks passed.');
process.exit(0);
