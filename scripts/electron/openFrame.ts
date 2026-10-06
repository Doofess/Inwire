/**
 * Opening one frame in the running app and proving which tree came back - the
 * half of `revisit-drive.ts` and `live-revisit-drive.ts` that is the same.
 *
 * It was two copies, and each had to learn the same lessons twice:
 * - **The frame's own row is clicked, not the list's first.** A filter is
 *   answered by a scan in the store; until it lands, the first row is the last
 *   frame opened, already selected, and clicking it asks for nothing.
 * - **The pane must name the frame before its rows count.** The tree pane
 *   heads itself `#Frame N` from the same packet it draws, so one snapshot of
 *   the header and the rows is one frame's. Matching rows alone passed on the
 *   previous frame's tree whenever the two shared them.
 * - **The Worker must be asked for THIS frame.** The spy keeps each command's
 *   id as well as its type; a `detail` for any frame used to count.
 * - **A row that never appears fails its case, not the drive**, so the cases
 *   after it still run and the summary still prints.
 *
 * A helper, not a test: no `process.exit`, so `check.ts` does not run it.
 */
import type { Page } from 'playwright';

/** A frame to open, and the rows its tree must show, as `[abbrev, name:value]` with no whitespace. */
export interface FrameCase {
  label: string;
  id: number;
  expect: [string, string][];
}

type CheckTrue = (name: string, condition: boolean) => void;

/** A command the renderer posted to a Worker: its type, and the frame it names if any. */
interface Sent { type: string; id?: number }

/**
 * Wraps `Worker.prototype.postMessage` to keep every command's type and id,
 * and listens to each Worker for the failures it posts. An init script, so it
 * must be added before the app creates its pipeline Worker - before a reload.
 * One list for every Worker: MapLibre starts Workers of its own, and a list per
 * Worker let the last one started hide the pipeline's.
 */
export async function installWorkerSpy(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const shared = window as unknown as { __sentToWorker: Sent[]; __workerFailures: string[] };
    shared.__sentToWorker = [];
    shared.__workerFailures = [];
    const original = Worker.prototype.postMessage;
    Worker.prototype.postMessage = function (this: Worker, message: unknown, ...rest: never[]) {
      const { type, id } = (message ?? {}) as { type?: unknown; id?: unknown };
      if (typeof type === 'string') shared.__sentToWorker.push({ type, ...(typeof id === 'number' ? { id } : {}) });
      const self = this as Worker & { __heard?: boolean };
      if (!self.__heard) {
        self.__heard = true;
        self.addEventListener('message', (event) => {
          const data = (event as MessageEvent).data as { type?: string; message?: string } | null;
          if (data?.type === 'failure') shared.__workerFailures.push(String(data.message));
        });
      }
      return (original as (...args: unknown[]) => void).call(this, message, ...rest);
    } as Worker['postMessage'];
  });
}

export const sentToWorker = (page: Page) =>
  page.evaluate(() => [...(window as unknown as { __sentToWorker?: Sent[] }).__sentToWorker ?? []]);

export const workerFailures = (page: Page) =>
  page.evaluate(() => [...(window as unknown as { __workerFailures?: string[] }).__workerFailures ?? []]);

/** The tree pane as it stands: the frame its header names, and its rows' text. */
const paneSnapshot = (page: Page) => page.evaluate(() => {
  const header = [...document.querySelectorAll('span')].find((s) => /^#Frame \d+$/.test(s.textContent ?? ''));
  if (header === undefined) return { frame: null, tree: '' };
  let pane: Element | null = header;
  while (pane !== null && pane.querySelector('.custom-scrollbar') === null) pane = pane.parentElement;
  const tree = pane?.querySelector('.custom-scrollbar') as HTMLElement | null;
  return { frame: Number((header.textContent ?? '').slice('#Frame '.length)), tree: tree?.innerText ?? '' };
});

/**
 * Selects each case's frame through the display filter, clicks its row, and
 * checks the tree on screen is that frame's, built from its record - a
 * `detail` for this id and no `replay` - and not from part of its
 * conversation. Every check goes through `checkTrue`; nothing here throws for
 * one frame.
 */
export async function openFrames(page: Page, cases: FrameCase[], checkTrue: CheckTrue, of = ''): Promise<void> {
  checkTrue('every case opens a different frame', new Set(cases.map((c) => c.id)).size === cases.length);
  const filter = page.getByPlaceholder('e.g. tcp.port == 443');
  for (const { label, id, expect } of cases) {
    // Taken before the filter: the list may select its one row itself.
    const before = (await sentToWorker(page)).length;
    await filter.fill(`frame.number == ${id}`);
    await filter.press('Enter');
    const row = page.locator(`#packet-row-${id}`);
    const appeared = await row.waitFor({ timeout: 30_000 }).then(() => true, () => false);
    checkTrue(`frame ${id}'s row is listed under frame.number == ${id}`, appeared);
    if (!appeared) continue;

    const t0 = Date.now();
    await row.click();
    let pane = { frame: null as number | null, tree: '' };
    const shows = () => pane.frame === id && expect.every(([, line]) => pane.tree.replace(/\s+/g, '').includes(line));
    while (Date.now() - t0 < 15_000) {
      pane = await paneSnapshot(page);
      if (shows()) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    console.log(`\n      frame ${id}${of}: ${label} - tree on screen in ${Date.now() - t0} ms`);
    const flat = pane.tree.replace(/\s+/g, '');
    checkTrue(`frame ${id}: the tree pane is showing frame ${id}`, pane.frame === id);
    for (const [abbrev, line] of expect) {
      checkTrue(`frame ${id} shows its ${abbrev} row: ${line}`, pane.frame === id && flat.includes(line));
    }
    const sent = (await sentToWorker(page)).slice(before);
    const fromRecord = sent.some((s) => s.type === 'detail' && s.id === id) && !sent.some((s) => s.type === 'replay');
    checkTrue(`frame ${id}'s tree was asked for, and came from its record rather than a replay`, fromRecord);
    checkTrue(`frame ${id}'s tree was not rebuilt from part of its conversation`,
      !pane.tree.includes('[Reassembly context]') && !pane.tree.includes('Rebuilt from part of the conversation'));
    if (!shows() || !fromRecord) {
      console.log(`        sent to the Worker: ${JSON.stringify(sent)}`);
      console.log(`        the pane (frame ${pane.frame}): ${JSON.stringify(pane.tree.slice(0, 600))}`);
    }
  }
}
