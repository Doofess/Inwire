/**
 * One Escape closes one surface, the newest first.
 *
 *   npx tsx scripts/commands/escape-stack.ts
 *
 * Every popover used to claim Escape with its own capture-phase listener on
 * `window` and `stopPropagation` - which stops the event travelling on, and
 * does nothing to a SIBLING listener on the same target. So the palette open
 * over the presets list, the rail's restart confirm, the import refusal or the
 * frame view's meta overlay closed both on one key. `escapeStack.ts` is the one
 * listener; a surface pushes a layer while it is up and the top one answers.
 */
import { readFileSync } from 'node:fs';
import { createEscapeStack } from '../../src/lib/escapeStack';

let failures = 0;
function checkTrue(name: string, ok: boolean): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
}

const key = (k: string, isComposing = false) => ({ key: k, isComposing });

{
  const stack = createEscapeStack();
  const closed: string[] = [];
  stack.push(() => closed.push('presets'));
  const dropPalette = stack.push(() => closed.push('palette'));
  checkTrue('the newest layer answers', stack.handle(key('Escape')) && closed.join() === 'palette');
  dropPalette();
  checkTrue('a removed layer hands the key down', stack.handle(key('Escape')) && closed.join() === 'palette,presets');
}
{
  const stack = createEscapeStack();
  let calls = 0;
  stack.push(() => { calls++; });
  checkTrue('another key is not claimed', !stack.handle(key('Enter')) && calls === 0);
  checkTrue('an IME composition keeps its Escape', !stack.handle(key('Escape', true)) && calls === 0);
}
{
  const stack = createEscapeStack();
  checkTrue('with no layer the key goes on to the view', !stack.handle(key('Escape')));
  const drop = stack.push(() => {});
  drop();
  drop();
  checkTrue('removing a layer twice is harmless', !stack.handle(key('Escape')));
}
{
  // A layer removed out of order must not take a newer one with it.
  const stack = createEscapeStack();
  const closed: string[] = [];
  const dropA = stack.push(() => closed.push('a'));
  stack.push(() => closed.push('b'));
  dropA();
  stack.handle(key('Escape'));
  checkTrue('removing an older layer leaves the newer on top', closed.join() === 'b');
}

// Every surface that claimed Escape on window goes through the stack now.
const SURFACES = [
  'src/components/common/CommandPalette.tsx',
  'src/components/common/FilterBar.tsx',
  'src/components/common/ActivityRail.tsx',
  'src/components/export/ImportErrorDialog.tsx',
  'src/components/packet-details/PacketDetailPane.tsx',
];
for (const file of SURFACES) {
  const src = readFileSync(file, 'utf8');
  checkTrue(`${file} pushes an Escape layer`, src.includes('useEscapeLayer('));
  // A file may still read Escape in a React handler on its own element (the
  // filter field's completions do); what it may not do is listen on the window.
  checkTrue(`${file} has no Escape listener of its own on window`,
    !(src.includes("addEventListener('keydown'") && src.includes("'Escape'")));
}
{
  // The presets layer is up only while the list can be seen: a hidden list
  // that took Escape would eat the key the completions above it wanted.
  const src = readFileSync('src/components/common/FilterBar.tsx', 'utf8');
  checkTrue('the presets layer follows the VISIBLE list', /useEscapeLayer\(presetsVisible,/.test(src));
}
{
  // Likewise the frame view's meta overlay: `railOverlay` outlives the strip
  // that draws it (the pane widens, the frame has no summary), and a layer
  // with nothing on screen eats an Escape meant for the view.
  const src = readFileSync('src/components/packet-details/PacketDetailPane.tsx', 'utf8');
  checkTrue('the meta overlay layer follows the DRAWN overlay', /useEscapeLayer\(overlayShown,/.test(src));
}
{
  // An Escape during IME composition is the IME's: the stack declines it, so
  // App's bubble-phase listener sees it next and must decline it too, or it
  // closes the view under a half-typed word.
  const src = readFileSync('src/App.tsx', 'utf8');
  checkTrue("App's Escape listener ignores a composing key",
    /if \(e\.key !== 'Escape' \|\| e\.isComposing\) return;/.test(src));
}

console.log(failures === 0 ? '\nAll escape-stack checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
