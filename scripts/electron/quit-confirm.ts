/**
 * The quit confirm's decision, driven without Electron.
 *
 *   npx tsx scripts/electron/quit-confirm.ts
 *
 * The confirm is the renderer's own dialog now, so it can follow Day and Night
 * (Windows paints `showMessageBox` light whatever the app's theme). That moved
 * the one thing standing between a click and a discarded capture into the
 * process most likely to be hung. What this holds `electron/quitConfirm.ts` to
 * are the two failures that move invites, both silent:
 *
 *  - **a close that does nothing** - a hung or absent renderer swallowing the
 *    request, so the window cannot be closed at all
 *  - **a close that quits without asking** - an answer from a confirm nobody
 *    is looking at any more, or a box that failed to open read as a yes
 *
 * plus the rule that a second close never stacks a second confirm. The clock is
 * a fake one, so "a second later" is exact rather than slept for.
 */
import { readFileSync } from 'node:fs';
import { QuitConfirm, RENDERER_ACK_MS, type QuitConfirmHost } from '../../electron/quitConfirm';
import {
  QUIT_CONFIRM_TEXT, readQuitConfirmReply, readQuitConfirmRequest,
  type QuitConfirmRequest,
} from '../../src/lib/quitConfirm';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

/** A host with a fake clock, a renderer that may or may not be there, and a native box the test answers. */
function harness(options: { rendererAlive?: boolean } = {}) {
  let now = 0;
  let nextHandle = 1;
  const timers = new Map<number, { at: number; fn: () => void }>();
  const sent: QuitConfirmRequest[] = [];
  let nativeShown = 0;
  let quits = 0;
  let answerNative: ((quit: boolean) => void) | null = null;
  let failNative: (() => void) | null = null;
  const state = { rendererAlive: options.rendererAlive ?? true };

  const host: QuitConfirmHost = {
    send: (request) => {
      if (!state.rendererAlive) return false;
      sent.push(request);
      return true;
    },
    showNative: () => {
      nativeShown++;
      return new Promise<boolean>((resolve, reject) => {
        answerNative = resolve;
        failNative = () => reject(new Error('window gone'));
      });
    },
    quit: () => { quits++; },
    setTimer: (fn, ms) => {
      const handle = nextHandle++;
      timers.set(handle, { at: now + ms, fn });
      return handle;
    },
    clearTimer: (handle) => { timers.delete(handle as number); },
  };
  const confirm = new QuitConfirm(host);

  return {
    confirm,
    state,
    sent,
    get nativeShown() { return nativeShown; },
    get quits() { return quits; },
    get liveTimers() { return timers.size; },
    /** Moves the clock and fires whatever came due, in order. */
    advance(ms: number): void {
      now += ms;
      for (const [handle, timer] of [...timers].sort((a, b) => a[1].at - b[1].at)) {
        if (timer.at > now) continue;
        timers.delete(handle);
        timer.fn();
      }
    },
    /** Answers the native box and lets its promise settle. */
    async native(quit: boolean): Promise<void> {
      answerNative?.(quit);
      await Promise.resolve();
      await Promise.resolve();
    },
    async nativeFails(): Promise<void> {
      failNative?.();
      await Promise.resolve();
      await Promise.resolve();
    },
  };
}

// --- the renderer asks, and the reader decides --------------------------------
{
  const h = harness();
  h.confirm.requested();
  check('a close asks the renderer, and only the renderer',
    h.sent.length === 1 && h.sent[0].open && h.nativeShown === 0);
  const id = h.sent[0].id;
  h.confirm.replied({ id, answer: 'shown' });
  check('"shown" disarms the fallback', h.liveTimers === 0);
  h.advance(60_000);
  check('...so the reader can take a minute and the OS never steps in',
    h.nativeShown === 0 && h.confirm.pending);
  h.confirm.replied({ id, answer: 'quit' });
  check('Quit quits, once', h.quits === 1 && !h.confirm.pending);
  h.confirm.replied({ id, answer: 'quit' });
  check('...and a repeated answer does not quit twice', h.quits === 1);
}

{
  const h = harness();
  h.confirm.requested();
  const first = h.sent[0].id;
  h.confirm.replied({ id: first, answer: 'shown' });
  h.confirm.replied({ id: first, answer: 'keep' });
  check('Keep capturing keeps the window', h.quits === 0 && !h.confirm.pending);
  h.confirm.requested();
  const second = h.sent[1].id;
  check('the next close asks again, as a new confirm', second !== first && h.sent[1].open);
  h.confirm.replied({ id: first, answer: 'quit' });
  check('...and an answer to the old one is not an answer to it', h.quits === 0 && h.confirm.pending);
}

{
  const h = harness();
  h.confirm.requested();
  const id = h.sent[0].id;
  h.confirm.replied({ id, answer: 'quit' });
  check('a decision without a "shown" first still counts', h.quits === 1 && h.liveTimers === 0);
}

// --- the renderer does not answer ---------------------------------------------
{
  const h = harness();
  h.confirm.requested();
  const id = h.sent[0].id;
  h.advance(RENDERER_ACK_MS - 1);
  check('a renderer still inside its second is waited for', h.nativeShown === 0);
  h.advance(1);
  check(`after ${RENDERER_ACK_MS} ms with no "shown", the OS asks`, h.nativeShown === 1);
  check('...and the renderer\'s confirm is withdrawn, by the same id',
    h.sent.length === 2 && h.sent[1].id === id && !h.sent[1].open);
  h.confirm.replied({ id, answer: 'shown' });
  h.confirm.replied({ id, answer: 'quit' });
  check('a slow renderer answering late does not decide anything', h.quits === 0);
  await h.native(true);
  check('Quit in the OS\'s box quits', h.quits === 1 && !h.confirm.pending);
}

{
  const h = harness();
  h.confirm.requested();
  h.advance(RENDERER_ACK_MS);
  await h.native(false);
  check('Keep capturing in the OS\'s box keeps the window', h.quits === 0 && !h.confirm.pending);
  h.confirm.requested();
  check('...and the next close goes back to the renderer first',
    h.sent.at(-1)!.open && h.nativeShown === 1);
}

{
  const h = harness();
  h.confirm.requested();
  h.advance(RENDERER_ACK_MS);
  await h.nativeFails();
  check('a box that could not be shown is a Keep, never a Quit', h.quits === 0 && !h.confirm.pending);
}

{
  const h = harness({ rendererAlive: false });
  h.confirm.requested();
  check('with no renderer to ask, the OS asks at once, not a second later',
    h.nativeShown === 1 && h.liveTimers === 0);
}

{
  const h = harness();
  h.confirm.requested();
  h.confirm.replied({ id: h.sent[0].id, answer: 'shown' });
  h.confirm.rendererGone();
  check('a renderer that crashes holding the question hands it to the OS', h.nativeShown === 1);
}

{
  const h = harness();
  h.confirm.rendererGone();
  check('a renderer crash with nothing asked shows nothing', h.nativeShown === 0 && !h.confirm.pending);
}

// --- a second close never stacks a second confirm ------------------------------
{
  const h = harness();
  h.confirm.requested();
  h.advance(600);
  h.confirm.requested();
  check('a second close re-asks the SAME confirm', h.sent.length === 2 && h.sent[1].id === h.sent[0].id);
  check('...with one fallback timer live, not two', h.liveTimers === 1);
  h.advance(600);
  check('...re-armed from the second close', h.nativeShown === 0);
  h.advance(400);
  check('...and it still falls back if nobody answers', h.nativeShown === 1);
  h.confirm.requested();
  h.confirm.requested();
  check('while the OS\'s box is up, more closes show nothing more',
    h.nativeShown === 1 && h.sent.length === 3);
}

{
  // The trap this re-ask exists for: the renderer put the dialog up, said so,
  // and then hung. Ignoring the second close would leave Alt+F4 doing nothing
  // for as long as the hang lasts.
  const h = harness();
  h.confirm.requested();
  h.confirm.replied({ id: h.sent[0].id, answer: 'shown' });
  h.confirm.requested();
  check('a close after "shown" asks the renderer to prove it is still there',
    h.sent.length === 2 && h.liveTimers === 1);
  h.advance(RENDERER_ACK_MS);
  check('...and a renderer that hung after showing it loses the question to the OS',
    h.nativeShown === 1);
}

{
  const h = harness();
  h.confirm.requested();
  h.confirm.replied({ id: h.sent[0].id, answer: 'shown' });
  h.confirm.requested();
  h.confirm.replied({ id: h.sent[0].id, answer: 'shown' });
  h.advance(RENDERER_ACK_MS * 5);
  check('...while a live one answers again and keeps it', h.nativeShown === 0 && h.confirm.pending);
}

// --- what crosses the boundary --------------------------------------------------
{
  check('a request reads back', JSON.stringify(readQuitConfirmRequest({ id: 3, open: true })) === '{"id":3,"open":true}');
  check('a request with no id is refused', readQuitConfirmRequest({ open: true }) === null);
  check('...and one whose open is not a boolean', readQuitConfirmRequest({ id: 1, open: 'yes' }) === null);
  check('a reply reads back', JSON.stringify(readQuitConfirmReply({ id: 2, answer: 'keep' })) === '{"id":2,"answer":"keep"}');
  check('a reply with an answer nobody sends is refused', readQuitConfirmReply({ id: 2, answer: 'yes' }) === null);
  check('...and one with a fractional id', readQuitConfirmReply({ id: 1.5, answer: 'quit' }) === null);
  check('...and a non-object', readQuitConfirmReply('quit') === null && readQuitConfirmReply(null) === null);
}

// --- both boxes say the same thing, and Keep is the default in both -----------
{
  const main = readFileSync('electron/main.ts', 'utf8');
  const dialog = readFileSync('src/components/common/QuitConfirmDialog.tsx', 'utf8');
  check('the OS\'s box takes its words from the shared text',
    main.includes('QUIT_CONFIRM_TEXT.title') && main.includes('QUIT_CONFIRM_TEXT.detail'));
  check('...with Keep capturing as default and cancel',
    /buttons: \[QUIT_CONFIRM_TEXT\.quit, QUIT_CONFIRM_TEXT\.keep\]/.test(main)
    && main.includes('defaultId: 1') && main.includes('cancelId: 1'));
  check('the app\'s dialog takes its words from the same text',
    dialog.includes('QUIT_CONFIRM_TEXT.title') && dialog.includes('QUIT_CONFIRM_TEXT.keep'));
  check('...and focuses Keep capturing, so Enter keeps',
    /autoFocus/.test(dialog));
  check('the wording is what it was', QUIT_CONFIRM_TEXT.title === 'Quit Inwire?'
    && QUIT_CONFIRM_TEXT.message === 'Quit while a capture is in the buffer?');
}

console.log(failures === 0 ? '\nAll quit-confirm checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
