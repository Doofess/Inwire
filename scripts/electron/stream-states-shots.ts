/**
 * The ladder and the state map over real streams, photographed - for looking
 * at, not asserting (ADR 0055).
 *
 *   npx tsx scripts/electron/stream-states-shots.ts <out-dir> [--widths 1024,1600] [--themes dark,light]
 *
 * Imports the `inwire` fixture into the built app and opens a stream that
 * closed cleanly and one that was reset, then the `bulk` fixture for one
 * joined mid-stream - found by folding each fixture through the digest here,
 * which is the same fold the store runs. For each theme and width: the ladder
 * with the map docked, the map after hovering a frame that moved the chosen
 * side, the ladder after clicking a state, the server's side, and the packet
 * list filtered to the stream so the chips can be held against their rows.
 *
 * Launches through `launchApp`, so the window stays off-screen and unfocused;
 * the stub agent stands in for the service so nothing asks the SCM. In
 * `check.ts`'s NOT_TESTS: it has no right answer, only pictures, and a run
 * takes a few minutes. What it does print is whether the hover lit an edge
 * and whether the click brought the frame in, which is the pass the brief
 * asks for and the eye cannot do from a still.
 */
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Page } from 'playwright';
import { arrive, FIXTURES } from '../pipeline/arrival';
import { StreamDigest, type StreamSummary } from '../../src/services/conversation/streamDigest';
import { startStubAgent } from './stubAgent';
import { launchApp } from './launchApp';

const OUT = process.argv[2];
if (!OUT) { console.log('usage: stream-states-shots.ts <out-dir> [--widths 1024,1600] [--themes dark,light]'); process.exit(2); }
const arg = (name: string, fallback: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const WIDTHS = arg('widths', '1024,1600').split(',').map(Number);
const THEMES = arg('themes', 'dark,light').split(',');
mkdirSync(OUT, { recursive: true });

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

if (process.platform !== 'win32') { console.log('SKIP  the desktop app is Windows-only'); process.exit(0); }
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'main.cjs'))) {
  console.log('SKIP  no build to launch - run `npm run build` first'); process.exit(0);
}
const inwire = FIXTURES.find((f) => f.name === 'inwire')!;
const bulk = FIXTURES.find((f) => f.name === 'bulk')!;
for (const f of [inwire, bulk]) {
  if (!existsSync(f.path)) { console.log(`SKIP  ${f.path} is not present - see test/fixtures/README.md`); process.exit(0); }
}

/** A stream worth photographing: how to find it, and what to hover and click once it is open. */
interface Case {
  name: string;
  fixture: { path: string; frames: number };
  summary: StreamSummary;
}

/** The fixture's streams as the digest folds them, which is the fold the store runs. */
async function digestOf(fixturePath: string): Promise<{ summaries: StreamSummary[]; frames: number }> {
  const { arrived } = await arrive(fixturePath);
  const digest = new StreamDigest();
  for (const a of arrived) digest.feed(a.packet);
  // Every summary: each has a version above zero once a row has been folded.
  return { summaries: digest.changedSince(0), frames: arrived.length };
}

console.log('folding the fixtures through the digest...');
const inwireDigest = await digestOf(inwire.path);
const bulkDigest = await digestOf(bulk.path);
const total = (s: StreamSummary) => s.toServer.packets + s.toClient.packets;
// A stream with a few dozen frames reads on one ladder; thousands fold into bands.
const pick = (list: StreamSummary[], want: (s: StreamSummary) => boolean) =>
  [...list].filter(want).sort((a, b) => Math.abs(total(a) - 40) - Math.abs(total(b) - 40))[0];
const cases: Case[] = [];
const closed = pick(inwireDigest.summaries, (s) => s.outcome === 'closed cleanly' && !s.joinedMidStream && total(s) >= 8);
const reset = pick(inwireDigest.summaries, (s) => s.outcome.startsWith('reset by') && !s.joinedMidStream && total(s) >= 6);
const joined = pick(bulkDigest.summaries, (s) => s.joinedMidStream && total(s) >= 8);
if (closed) cases.push({ name: 'closed-cleanly', fixture: { path: inwire.path, frames: inwireDigest.frames }, summary: closed });
if (reset) cases.push({ name: 'reset', fixture: { path: inwire.path, frames: inwireDigest.frames }, summary: reset });
if (joined) cases.push({ name: 'joined-mid-stream', fixture: { path: bulk.path, frames: bulkDigest.frames }, summary: joined });
for (const c of cases) {
  console.log(`  ${c.name}: stream #${c.summary.streamId}, frames #${c.summary.firstId}..#${c.summary.lastId}, `
    + `${total(c.summary)} frames, ${c.summary.outcome}${c.summary.joinedMidStream ? ' (joined mid-stream)' : ''}, `
    + `${c.summary.steps.length} steps`);
}
if (cases.length === 0) { console.log('no streams to photograph'); process.exit(1); }

const PIPE = String.raw`\\.\pipe\inwire-stream-shots-` + process.pid;
const agent = await startStubAgent(PIPE, 5);

async function importFixture(page: Page, fixture: Case['fixture']): Promise<boolean> {
  await page.getByLabel('Export or import a capture').click();
  await sleep(500);
  await page.getByRole('button', { name: /^import$/i }).click().catch(() => { /* already there */ });
  await sleep(300);
  await page.locator('input[type="file"]').first().setInputFiles(path.resolve(fixture.path));
  const counts = () => page.evaluate(() => {
    const text = document.querySelector('[data-packet-counts]')?.textContent ?? '';
    const m = text.match(/([\d,]+)\s*\/\s*([\d,]+)/);
    return m ? Number(m[2].replace(/,/g, '')) : 0;
  });
  const deadline = Date.now() + 180_000;
  let seen = 0;
  while (Date.now() < deadline) {
    seen = await counts();
    if (seen >= fixture.frames) break;
    await sleep(1000);
  }
  await page.keyboard.press('Escape');
  await sleep(2000);
  return seen >= fixture.frames;
}

// The stub agent is closed however the shots end: a locator that times out
// must not leave its pipe open and the process with it.
try {
  for (const theme of THEMES) {
    for (const width of WIDTHS) {
      const height = width <= 1024 ? 700 : 1000;
      const tag = `${theme}-${width}`;
      const profile = mkdtempSync(path.join(tmpdir(), 'inwire-stream-shots-'));
      const app = await launchApp({
        args: ['.'],
        env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE } as Record<string, string>,
      });
      try {
        const p = await app.firstWindow();
        p.setDefaultTimeout(30_000);
        await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
        await p.evaluate((t) => {
          localStorage.setItem('theme', t);
          localStorage.setItem('inwire.tour', JSON.stringify({ completed: true }));
        }, theme);
        await p.reload();
        await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
        await app.evaluate(({ BrowserWindow }, [w, h]) => {
          const win = BrowserWindow.getAllWindows()[0];
          win.unmaximize();
          win.setSize(w, h);
        }, [width, height] as [number, number]);
        await sleep(800);
        await p.getByRole('button', { name: 'Skip' }).click({ timeout: 2000 }).catch(() => {});
        const shot = async (name: string) => {
          await p.screenshot({ path: path.join(OUT, `${tag}-${name}.png`) });
          console.log(`  ${tag}-${name}`);
        };

        let imported: string | null = null;
        for (const c of cases) {
          if (imported !== c.fixture.path) {
            console.log(`${tag}: importing ${path.basename(c.fixture.path)}`);
            const ok = await importFixture(p, c.fixture);
            console.log(`  imported: ${ok}`);
            imported = c.fixture.path;
          }
          const { summary } = c;
          // Open the stream from its first frame: the filter finds the row, the
          // row is selected, and the rail's Follow Stream follows the selection.
          const filter = p.getByPlaceholder('e.g. tcp.port == 443');
          await filter.fill(`frame.number == ${summary.firstId}`);
          await filter.press('Enter');
          const row = p.locator(`#packet-row-${summary.firstId}`);
          await row.waitFor({ timeout: 30_000 });
          await row.click();
          await sleep(300);
          await p.getByRole('button', { name: 'Follow Stream' }).click();
          await sleep(500);
          await p.getByRole('radio', { name: 'Ladder' }).click();
          const map = p.locator('[data-state-map]');
          await map.waitFor({ timeout: 30_000 });
          // The whole stream read through the digest, not the buffer's slice.
          await p.waitForFunction(() => !/reading \d/.test(document.body.innerText), undefined, { timeout: 60_000 }).catch(() => {});
          await sleep(800);
          await shot(`${c.name}-1-ladder`);

          // Hover: a frame that moved the client - its last step's frame, which
          // is on screen when the stream fits; the ladder opens at its start,
          // so the first client step is the safer choice.
          const clientSteps = summary.steps.filter((s) => s.side === 'client');
          const hoverStep = clientSteps[0];
          if (hoverStep !== undefined) {
            const arrow = p.locator(`[data-frame="${hoverStep.frameId}"]`).first();
            const present = await arrow.count();
            if (present > 0) {
              await arrow.hover();
              await sleep(400);
              const lit = await p.locator('[data-state-map] path[data-lit]').getAttribute('data-edge').catch(() => null);
              console.log(`  hover frame #${hoverStep.frameId} (${hoverStep.from} -> ${hoverStep.to}): lit edge ${lit ?? 'NONE'}`);
              await shot(`${c.name}-2-hover`);
              await p.mouse.move(5, 5);
            } else {
              console.log(`  hover: frame #${hoverStep.frameId} has no arrow on screen (inside a band or out of the window)`);
            }
          }

          // Click: the client's last state, whose frame is at the stream's end -
          // out of the opening window on any stream longer than a screen.
          const lastStep = clientSteps[clientSteps.length - 1];
          if (lastStep !== undefined) {
            const to = lastStep.to === 'CLOSED' ? 'CLOSED_END' : lastStep.to;
            const before = await p.locator(`[data-frame="${lastStep.frameId}"]`).count();
            await p.locator(`[data-state-map] [data-state-node="${to}"]`).click();
            await sleep(800);
            const after = await p.locator(`[data-frame="${lastStep.frameId}"]`).count();
            console.log(`  click ${to} (frame #${lastStep.frameId}): arrow on screen before ${before}, after ${after}`);
            await shot(`${c.name}-3-picked`);
          }

          // Keyboard: Tab from the side switch lands on the first state the
          // side visited, which draws the ring a mouse click must not.
          await p.mouse.move(5, 5);
          await p.locator('[data-state-map] [role="radio"][aria-checked="true"]').focus();
          // Below 1180px the map's collapse button is the first stop.
          const stateFocused = () => p.evaluate(() => document.activeElement?.getAttribute('data-state-node') ?? null);
          for (let i = 0; i < 3 && (await stateFocused()) === null; i++) await p.keyboard.press('Tab');
          await sleep(300);
          const focused = await stateFocused();
          console.log(`  keyboard focus on ${focused ?? 'NO STATE'}`);
          await shot(`${c.name}-3b-keyboard`);

          await p.getByRole('radio', { name: 'Server' }).click();
          await sleep(400);
          await shot(`${c.name}-4-server`);

          // The packet list over the same stream, for the chips.
          await p.keyboard.press('Escape');
          await sleep(400);
          await filter.fill(`tcp.stream == ${summary.streamId}`);
          await filter.press('Enter');
          await p.locator(`#packet-row-${summary.firstId}`).waitFor({ timeout: 30_000 }).catch(() => {});
          await sleep(800);
          await shot(`${c.name}-5-list`);

          // Statistics, once, over the `inwire` fixture: the TCP level read
          // from the digest - its scope note, the outcome column, sorting by
          // it, the row's filter button hovered and keyboard-focused - then a
          // row's click, which must land on the stream, not on Packets.
          if (c === cases.filter((x) => x.fixture.path === inwire.path).at(-1)) {
            await filter.fill('');
            await filter.press('Enter');
            await p.getByRole('button', { name: /^Statistics/ }).click();
            await p.getByRole('button', { name: 'Conversations' }).click();
            await p.getByRole('button', { name: 'TCP', exact: true }).click();
            const note = await p.getByText(/^(Whole capture|Rebuilding the stream digest)/).first().textContent({ timeout: 30_000 }).catch(() => null);
            console.log(`  statistics scope note: ${note ?? 'NONE'}`);
            await sleep(500);
            await shot('stats-1-tcp');
            await p.getByRole('button', { name: 'Outcome', exact: true }).click();
            await sleep(300);
            await shot('stats-2-by-outcome');
            const button = p.getByRole('button', { name: 'Filter to this conversation' }).first();
            await button.hover();
            await sleep(300);
            await shot('stats-3-filter-hover');
            await button.focus();
            await p.keyboard.press('Shift+Tab');
            await p.keyboard.press('Tab');
            await sleep(300);
            await shot('stats-4-filter-focus');
            await p.mouse.move(5, 5);
            await p.locator('tbody tr').first().locator('td').first().click();
            const opened = await p.locator('[data-state-map]').waitFor({ timeout: 10_000 }).then(() => true, () => false);
            console.log(`  row click opened the stream: ${opened}`);
            await shot('stats-5-row-opened');
          }
        }
      } finally {
        const page = app.windows()[0];
        if (page !== undefined) await page.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
        const pid = app.process().pid;
        await app.close().catch(() => {});
        for (let i = 0; i < 50; i++) {
          try { process.kill(pid!, 0); await sleep(200); } catch { break; }
        }
        rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
      }
    }
  }
} finally {
  await agent.close();
}
console.log(`shots in ${OUT}`);
process.exit(0);
