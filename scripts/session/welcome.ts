/**
 * The welcome on an empty Packets view, and the start gate it shares with the rail.
 *
 *   npx tsx scripts/session/welcome.ts
 *
 * The rail asks "Delete the previous capture?" before Start would discard it.
 * The welcome has a Start of its own and must ask the same question, so the
 * decision is `startGate` in `src/lib/startGate.ts`, pure, and both read it.
 * The source checks hold the wiring a type cannot: the panes are gone while the
 * welcome is up without `layout.panes` being written, Start goes through the
 * gate, and sampling follows the welcome's mount.
 */
import { readFileSync } from 'node:fs';
import { startGate, type StartGateInput } from '../../src/lib/startGate';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const ready: StartGateInput = {
  isCapturing: false, canCapture: true, canClearBuffer: true, hasSelection: true,
  ownedElsewhere: false, blockedReason: null, bufferedPackets: 0, previousCapture: null,
};
const gate = (patch: Partial<StartGateInput>) => startGate({ ...ready, ...patch });

check('no selection blocks with the rail\'s text',
  gate({ hasSelection: false }).blocked === 'Choose an interface first');
check('no capture permission blocks', gate({ canCapture: false }).blocked !== null);
check('a blocked reason is shown as given', gate({ blockedReason: 'X' }).blocked === 'X');
check('another window capturing blocks', gate({ ownedElsewhere: true }).blocked !== null);
check('a previous capture with an empty buffer is discarded by Start',
  gate({ previousCapture: 'the capture from 10:42', bufferedPackets: 0 }).discards === 'previous');
check('frames in the buffer are discarded by Start',
  gate({ bufferedPackets: 5 }).discards === 'buffer');
check('frames in the buffer win over a previous capture',
  gate({ bufferedPackets: 5, previousCapture: 'x' }).discards === 'buffer');
check('while capturing nothing is discarded',
  gate({ isCapturing: true, bufferedPackets: 5, previousCapture: 'x' }).discards === null);
const plain = gate({});
check('ready with nothing on disk: not blocked, nothing discarded',
  plain.blocked === null && plain.discards === null);

const app = readFileSync('src/App.tsx', 'utf8');
const rail = readFileSync('src/components/common/ActivityRail.tsx', 'utf8');
const welcome = readFileSync('src/components/packet-list/Welcome.tsx', 'utf8');
const transfer = readFileSync('src/components/sidebar/TransferPanel.tsx', 'utf8');

check('(a) App defines showWelcome', app.includes(
  'const showWelcome = packets.length === 0 && !isCapturing && !reopening;'));
check('(a) and renders <Welcome', /<Welcome\b/.test(app));
check('(b) both detail-pane sites are gated by showPanes && !showWelcome',
  (app.match(/\{showPanes && !showWelcome && \(/g) ?? []).length === 2
  && !/\{showPanes && \(/.test(app));
const welcomeJsx = app.slice(app.indexOf('<Welcome'), app.indexOf('<Welcome') + 1500);
check('(c) App passes onStart and onClearPackets to Welcome',
  welcomeJsx.includes('onStart={handleStartCapture}')
  && welcomeJsx.includes('onClearPackets={handleClearPackets}'));
check('(d) ActivityRail imports startGate', /import \{[^}]*\bstartGate\b[^}]*\} from/.test(rail));
check('(e) Welcome has no font-mono', !welcome.includes('font-mono'));
check('(e) and uses TITLE and MICRO_LABEL',
  /\bTITLE\b/.test(welcome) && /\bMICRO_LABEL\b/.test(welcome));
check('(f) Welcome turns sampling on in an effect and off in its cleanup',
  /notify\.current\(true\);\s*return \(\) => \{\s*notify\.current\(false\);/.test(welcome));
check('(g) Welcome disables Start from gate.blocked',
  /disabled=\{gate\.blocked !== null\}/.test(welcome));
check('(h) TransferPanel reads pickRequest', /\bpickRequest\b/.test(transfer));
check('(i) Welcome calls useEscapeLayer', /useEscapeLayer\(/.test(welcome));
// The welcome's adapters sit right above its Start, so with none picked it
// points at them rather than repeating the rail's "Choose an interface first".
check('(j) with adapters listed and none picked, Start points up at them',
  welcome.includes("'Pick an adapter above.'")
  && /selectedInterfaces\.length === 0 && interfaces\.length > 0/.test(welcome));
check('the welcome keeps data-tour="list"', /data-tour="list"/.test(app)
  && (app.match(/data-tour="list"/g) ?? []).length === 2);

if (failures > 0) {
  console.log(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
