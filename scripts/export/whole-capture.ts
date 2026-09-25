/**
 * The whole-capture export iterator, over a real store holding a real capture.
 *
 *   npx tsx scripts/export/whole-capture.ts
 *
 * Every frame of each fixture is written through a real `CaptureHost` over a
 * `MemoryVolume`, each append crossing `v8.serialize` the way it crosses the
 * store's `MessagePort` - the clone that once made the whole disk path inert
 * (`storePacket.ts`). The newest fifth is kept as the "window" and everything
 * older is read back off the store, so the seam between the two halves is
 * exercised on traffic nobody chose to make it pass.
 *
 * What it holds `exportFrames` to, each against an answer computed another way:
 * every frame exactly once and in capture order; every frame's bytes equal to
 * the file's; a filtered export equal to `FilterEngine` over the whole capture;
 * chunks with no match never read; `linkType` put back on disk rows; the
 * window placed by the store rather than by a caller's stale number; one
 * unreadable chunk in the middle costing that chunk and nothing after it; a
 * store that stops answering ending in a count rather than a hang; an abort
 * that stops it; and `orderByTime` sorting what a bounded skew disordered.
 *
 * Driven by the untracked fixtures (ADR 0004) and skips cleanly without them.
 */
import { serialize, deserialize } from 'node:v8';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PcapService } from '../../src/services/pcapParser';
import { CaptureHost } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { MatchSet } from '../../src/services/capture/matchSet';
import { plainForStore } from '../../src/services/capture/storePacket';
import { FilterEngine } from '../../src/services/filterEngine';
import { LINKTYPE } from '../../src/services/dissect/types';
import { NO_BYTES } from '../../src/services/packetBytes';
import {
  exportFrames, exportTotal, linkTypeTable,
  type CaptureRowReader, type ExportFramesOptions, type ExportPage, type FrameScope,
} from '../../src/services/export/exportFrames';
import { orderByTime } from '../../src/services/export/orderByTime';
import { findWiresharkTool, loadRealCaptures, runTool } from './realCaptures';
import type { RowBlock } from '../../src/services/capture/captureClient';
import type { FromCapture } from '../../src/services/capture/captureProtocol';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 300));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 300));
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/** A copy, by the serialiser a `postMessage` across processes uses. */
const crossed = <T>(value: T): T => deserialize(serialize(value)) as T;

/**
 * A store holding `packets`, and a reader over it shaped like `captureStore`.
 *
 * Answers cross `v8` too: what comes back from the store is a clone in the
 * app, and a reader handed the host's own objects could pass by sharing them.
 */
async function storeOf(packets: readonly Packet[]) {
  const volume = new MemoryVolume();
  const waiting = new Map<number, (message: FromCapture) => void>();
  const failuresSaid: string[] = [];
  const store = new CaptureHost(volume, (message) => {
    const copy = crossed(message);
    if (copy.type === 'failure') failuresSaid.push(copy.message);
    const id = (copy as { requestId?: number }).requestId;
    // A scan's progress carries its id too; only the final answer settles.
    if (id === undefined || copy.type === 'scanProgress') return;
    const settle = waiting.get(id);
    if (settle === undefined) return;
    waiting.delete(id);
    settle(copy);
  });

  let nextId = 1;
  const ask = (build: (requestId: number) => Parameters<CaptureHost['receive']>[0]) =>
    new Promise<FromCapture>((resolve) => {
      const requestId = nextId++;
      waiting.set(requestId, resolve);
      store.receive(build(requestId));
    });

  store.receive({ type: 'open', captureId: 'cap-20260925-120000-expt' });
  for (let i = 0; i < packets.length; i += 1000) {
    store.receive({ type: 'append', packets: crossed(packets.slice(i, i + 1000).map(plainForStore)) });
  }
  store.receive({ type: 'finish' });
  await store.drain();

  const reader: CaptureRowReader = {
    async readRowsAt(from, to) {
      const answer = await ask((requestId) => ({ type: 'rowsAt', requestId, from, to }));
      return answer.type === 'blocks' ? answer.blocks : [];
    },
    async readBytes(ids) {
      const answer = await ask((requestId) => ({ type: 'read', requestId, ids: [...ids] }));
      return new Map(answer.type === 'bytes' ? answer.frames : []);
    },
    async ordinalOf(id) {
      const answer = await ask((requestId) => ({ type: 'locate', requestId, id }));
      return answer.type === 'located' ? answer.ordinal : -1;
    },
  };

  return {
    reader,
    failuresSaid,
    locate: (id: number): Promise<number> => reader.ordinalOf(id),
    async scan(filter: string): Promise<MatchSet | null> {
      const answer = await ask((requestId) => ({ type: 'scan', requestId, filter }));
      if (answer.type !== 'scanDone' || answer.bits === null) return null;
      return MatchSet.fromBytes(answer.frameCount, answer.bits);
    },
    close: () => store.close(),
  };
}

/** Every page, or a named failure if it takes longer than a hang should. */
async function collect(
  pages: AsyncIterable<ExportPage>, ms = 30_000,
): Promise<{ pages: ExportPage[]; packets: Packet[] }> {
  const run = (async () => {
    const out: ExportPage[] = [];
    for await (const page of pages) out.push(page);
    return out;
  })();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`no end after ${ms} ms - a hang`)), ms);
  });
  try {
    const out = await Promise.race([run, timeout]);
    return { pages: out, packets: out.flatMap((p) => p.packets) };
  } finally {
    clearTimeout(timer);
  }
}

const ids = (packets: readonly Packet[]) => packets.map((p) => p.id);
const last = <T>(list: readonly T[]): T | undefined => list[list.length - 1];

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** A reader that records every range it was asked for. */
function counting(reader: CaptureRowReader) {
  const asked: { from: number; to: number; blocks: RowBlock[] }[] = [];
  const wrapped: CaptureRowReader = {
    async readRowsAt(from, to) {
      const blocks = await reader.readRowsAt(from, to);
      asked.push({ from, to, blocks });
      return blocks;
    },
    readBytes: (list) => reader.readBytes(list),
    ordinalOf: (id) => reader.ordinalOf(id),
  };
  return { reader: wrapped, asked };
}

async function main() {
  const captures = await loadRealCaptures();
  if (captures.length === 0) {
    console.log('SKIP  no fixtures present - nothing to export');
    process.exit(0);
  }

  const noLinkTypes = new Map<string, number>();
  const plain = (extra: Partial<ExportFramesOptions> = {}): ExportFramesOptions =>
    ({ hydrateBytes: true, linkTypes: noLinkTypes, ...extra });

  for (const { name, packets } of captures) {
    console.log(`\n--- ${name}: ${packets.length} frames ---\n`);
    const store = await storeOf(packets);
    check(`${name}: the store took every frame without complaint`, store.failuresSaid, []);

    // The newest fifth is the window, and `below` comes from the store, the
    // way `useWindowOrdinal` gets it - never from arithmetic on ids.
    const split = Math.floor(packets.length * 0.8);
    const tail = packets.slice(split);
    const below = await store.locate(tail[0].id);
    check(`${name}: the store places the window's first frame`, below, split);

    // The older half of the window has had its bytes evicted, as
    // `evictOldBytes` leaves a real buffer - copies, so the fixture itself
    // keeps its bytes to compare against.
    const evicted = Math.floor(tail.length / 2);
    const window = tail.map((p, i) => (i < evicted ? { ...p, rawBytes: NO_BYTES } : p));
    const windowBefore = window.map((p) => ({ bytes: p.rawBytes, keys: Object.keys(p).length }));

    // ---- the whole capture ----
    const whole: FrameScope = { window, filter: null };
    const full = await collect(exportFrames(whole, store.reader, plain()));
    check(`${name}: exportTotal is the whole capture`, await exportTotal(whole, store.reader), packets.length);
    check(`${name}: ...and every page says where the store placed the window`,
      full.pages.every((p) => p.below === below), true);
    check(`${name}: every frame, once, in capture order`, ids(full.packets), ids(packets));
    check(`${name}: ...and the last page says so`,
      [last(full.pages)?.done, last(full.pages)?.total, last(full.pages)?.unreadable],
      [packets.length, packets.length, 0]);
    const byteMismatch = full.packets.findIndex((p, i) => !sameBytes(p.rawBytes, packets[i].rawBytes));
    check(`${name}: every frame's bytes are the file's`, byteMismatch, -1);
    check(`${name}: no frame came back without bytes`, last(full.pages)?.bytesMissing, 0);
    checkTrue(`${name}: disk rows carry what the writers read`,
      full.packets.slice(0, below).every((p, i) =>
        p.tsUs === packets[i].tsUs && p.length === packets[i].length && p.info === packets[i].info));
    checkTrue(`${name}: no window packet is handed out as itself`,
      full.packets.slice(below).every((p, i) => p !== window[i]));
    checkTrue(`${name}: ...nor changed by being exported`,
      window.every((p, i) => p.rawBytes === windowBefore[i].bytes
        && Object.keys(p).length === windowBefore[i].keys));

    // ---- linkType ----
    // The store records each row's link type (chunk version 2), so a table
    // that disagrees is not consulted: these rows are Ethernet, recorded as
    // such, and stay so.
    const adapter = packets[0].interfaceName;
    const loopback = new Map([[adapter, LINKTYPE.NULL]]);
    checkTrue(`${name}: the fixture really is Ethernet, so a restored type is ours`,
      packets.every((p) => p.linkType === undefined));
    const recorded = await collect(exportFrames(whole, store.reader, plain({ hydrateBytes: false, linkTypes: loopback })));
    checkTrue(`${name}: a disk row keeps the link type its chunk recorded, whatever the table says`,
      recorded.packets.slice(0, below).every((p) => p.linkType === undefined));
    // A chunk written before link types were stored answers without the flag,
    // and only then does the table speak. The reader is the real one; the
    // wrapper answers the way the store answers for an old chunk.
    const oldChunks: CaptureRowReader = {
      readRowsAt: async (from, to) => (await store.reader.readRowsAt(from, to))
        .map((b) => ({ firstOrdinal: b.firstOrdinal, packets: b.packets })),
      readBytes: (list) => store.reader.readBytes(list),
      ordinalOf: (id) => store.reader.ordinalOf(id),
    };
    const relabelled = await collect(exportFrames(whole, oldChunks, plain({ hydrateBytes: false, linkTypes: loopback })));
    checkTrue(`${name}: an old chunk's rows get their adapter's link type from the table`,
      relabelled.packets.slice(0, below).every((p) => p.linkType === LINKTYPE.NULL));
    checkTrue(`${name}: ...and a window frame keeps the one it was dissected with`,
      relabelled.packets.slice(below).every((p) => p.linkType === undefined));
    checkTrue(`${name}: without bytes asked for, disk rows carry none`,
      relabelled.packets.slice(0, below).every((p) => p.rawBytes.byteLength === 0));

    // ---- filtered ----
    const candidates = ['tcp', 'udp', 'dns', 'tls.handshake', 'tcp.flags.syn == 1', 'udp.port == 443', 'arp'];
    let sparsest: { expression: string; matches: MatchSet; chunksHit: number } | null = null;
    const chunksBelow = Math.ceil(below / 4096);
    for (const expression of candidates) {
      const matches = await store.scan(expression);
      if (matches === null) {
        check(`${name}: the scan of '${expression}' finished`, false, true);
        continue;
      }
      const scope: FrameScope = { window, filter: { expression, matches } };
      const expected = ids(FilterEngine.filterPackets(packets, expression));
      const got = await collect(exportFrames(scope, store.reader, plain()));
      check(`${name}: '${expression}' exports what FilterEngine finds over everything (${expected.length})`,
        ids(got.packets), expected);
      check(`${name}: ...and exportTotal says as much`, await exportTotal(scope, store.reader), expected.length);
      const originals = new Map(packets.map((p) => [p.id, p]));
      checkTrue(`${name}: ...with every frame's bytes`,
        got.packets.every((p) => sameBytes(p.rawBytes, originals.get(p.id)!.rawBytes)));

      let chunksHit = 0;
      for (let c = 0; c < chunksBelow; c++) {
        const lo = c * 4096, hi = Math.min(below, lo + 4096);
        if (matches.rank(hi) > matches.rank(lo)) chunksHit++;
      }
      if (chunksHit > 0 && chunksHit < chunksBelow
        && (sparsest === null || chunksHit < sparsest.chunksHit)) {
        sparsest = { expression, matches, chunksHit };
      }
    }

    // ---- a chunk with no match is never read ----
    if (sparsest === null) {
      check(`${name}: some filter leaves a chunk below the window unmatched`, false, true);
    } else {
      const { expression, matches, chunksHit } = sparsest;
      const { reader, asked } = counting(store.reader);
      await collect(exportFrames(
        { window, filter: { expression, matches } }, reader, plain({ hydrateBytes: false })));
      const read = asked.flatMap((a) => a.blocks);
      console.log(`        '${expression}' matches in ${chunksHit} of ${chunksBelow} chunks below the window`);
      checkTrue(`${name}: '${expression}': every chunk read holds a match`,
        read.every((b) => matches.rank(b.firstOrdinal + b.packets.length) > matches.rank(b.firstOrdinal)));
      check(`${name}: ...and each matching chunk is read once`, read.length, chunksHit);
    }

    // ---- a filter with no scan yet ----
    let refused = '';
    try {
      await exportTotal({ window, filter: { expression: 'tcp', matches: null } }, store.reader);
    } catch (error) { refused = (error as Error).message; }
    checkTrue(`${name}: a filter whose scan has not finished is refused, saying so`,
      refused.includes('scan'));
    let refusedToo = false;
    try {
      await collect(exportFrames({ window, filter: { expression: 'tcp', matches: null } }, store.reader, plain()));
    } catch { refusedToo = true; }
    checkTrue(`${name}: ...by the iterator as well`, refusedToo);

    // ---- the window is placed by the store, never by the caller ----
    if (window.length > 500) {
      // The list's `below` answers an async question about an earlier window.
      // Here a trim has moved the window up 500 frames since it last asked.
      // With that number handed in - the old API - the 500 between were in
      // neither half, and done === total said nothing was missing, because the
      // total was counted from the same stale number.
      const staleBelow = below;
      const trimmed = window.slice(500);
      check(`${name}: (the case: a stale below plus the trimmed window falls 500 short)`,
        staleBelow + trimmed.length, packets.length - 500);
      const trimmedScope: FrameScope = { window: trimmed, filter: null };
      const got = await collect(exportFrames(trimmedScope, store.reader, plain({ hydrateBytes: false })));
      check(`${name}: after a trim the list has not caught up with, every frame once, in order`,
        ids(got.packets), ids(packets));
      check(`${name}: ...the store placing the window past the stale number`,
        last(got.pages)?.below, staleBelow + 500);
      check(`${name}: ...and exportTotal agreeing`,
        await exportTotal(trimmedScope, store.reader), packets.length);
    }
    {
      // The window's first frame not placed yet (staged behind the patch
      // horizon) while older frames are on disk: asked again, not read as 0.
      let asks = 0;
      const late: CaptureRowReader = {
        ...store.reader,
        ordinalOf: async (id) => (++asks <= 2 ? -1 : store.reader.ordinalOf(id)),
      };
      const got = await collect(exportFrames(whole, late,
        plain({ hydrateBytes: false, locate: { attempts: 5, delayMs: 1 } })));
      check(`${name}: a window not placed yet is waited for, and the disk half still exported`,
        [ids(got.packets).length, asks], [packets.length, 3]);

      const never: CaptureRowReader = { ...store.reader, ordinalOf: async () => -1 };
      let said = '';
      try {
        await collect(exportFrames(whole, never, plain({ locate: { attempts: 3, delayMs: 1 } })));
      } catch (error) { said = (error as Error).message; }
      checkTrue(`${name}: ...and one never placed is refused, saying why, rather than exported as the window alone`,
        said.includes('not yet placed'));

      // Nothing sealed at all: a short capture still wholly staged. The window
      // is the capture, and that is exported rather than refused.
      const unsealed: CaptureRowReader = {
        ...store.reader, ordinalOf: async () => -1, readRowsAt: async () => [],
      };
      const alone = await collect(exportFrames(whole, unsealed, plain({ hydrateBytes: false })));
      check(`${name}: with nothing on disk, the window is the whole export`,
        [ids(alone.packets), last(alone.pages)?.below, last(alone.pages)?.total],
        [ids(tail), 0, tail.length]);
    }

    // ---- one unreadable chunk in the middle ----
    {
      const [bad] = await store.reader.readRowsAt(Math.floor(below / 2), Math.floor(below / 2) + 1);
      const badStart = bad?.firstOrdinal ?? 0;
      const badEnd = badStart + (bad?.packets.length ?? 0);
      if (bad === undefined || badStart === 0 || badEnd >= below) {
        console.log(`        (${below} frames below the window has no chunk with neighbours on both sides)`);
      } else {
        const lost = new Set(ids(packets.slice(badStart, badEnd)));
        const tcp = await store.scan('tcp');
        // Both ways the store answers a chunk it cannot read: a block with no
        // rows (`CaptureReader.readRows` on a short read), and nothing at all
        // for the request (`CaptureHost.onRowsAt` when decoding throws).
        for (const shape of ['an empty block', 'no answer'] as const) {
          let reads = 0;
          const failing: CaptureRowReader = {
            ...store.reader,
            async readRowsAt(from, to) {
              reads++;
              const blocks = await store.reader.readRowsAt(from, to);
              if (!blocks.some((b) => b.firstOrdinal === badStart)) return blocks;
              if (shape === 'no answer') return [];
              return blocks.map((b) => (b.firstOrdinal === badStart ? { firstOrdinal: badStart, packets: [] } : b));
            },
          };
          const got = await collect(exportFrames(whole, failing, plain({ hydrateBytes: false })));
          const end = last(got.pages);
          check(`${name}: chunk [${badStart}, ${badEnd}) unreadable as ${shape}: exactly its frames are counted`,
            end?.unreadable, badEnd - badStart);
          check(`${name}: ...every frame after it still arrives`,
            ids(got.packets), ids(packets).filter((id) => !lost.has(id)));
          check(`${name}: ...done reaches total`, end?.done, end?.total);
          checkTrue(`${name}: ...in a bounded number of reads (${reads})`, reads < Math.ceil(below / 4096) + 10);

          if (tcp !== null) {
            const expected = ids(FilterEngine.filterPackets(packets, 'tcp'));
            const filtered = await collect(exportFrames(
              { window, filter: { expression: 'tcp', matches: tcp } }, failing, plain({ hydrateBytes: false })));
            check(`${name}: ...filtered to 'tcp', the chunk's matches are counted`,
              last(filtered.pages)?.unreadable, expected.filter((id) => lost.has(id)).length);
            check(`${name}: ...and every other match arrives`,
              ids(filtered.packets), expected.filter((id) => !lost.has(id)));
          }
        }
      }
    }

    // ---- a store that stops answering ----
    {
      // Answers empty from the third call on - a macrotask later, as a port
      // would, so `collect`'s timer can fire - and gives up loudly past a
      // hundred, because an iterator that retries an empty answer in
      // microtasks alone would starve the timer and hang the suite silently.
      let calls = 0;
      const torn: CaptureRowReader = {
        async readRowsAt(from, to) {
          if (++calls <= 2) return store.reader.readRowsAt(from, to);
          if (calls > 100) throw new Error('asked 100 times for rows that are not there - a loop');
          await new Promise((resolve) => setImmediate(resolve));
          return [];
        },
        readBytes: (list) => store.reader.readBytes(list),
        ordinalOf: (id) => store.reader.ordinalOf(id),
      };
      const got = await collect(exportFrames(whole, torn, plain({ hydrateBytes: false })));
      const fromDisk = got.packets.length - window.length;
      const end = last(got.pages);
      check(`${name}: a store that stops answering ends, counting what it lost`,
        end?.unreadable, below - fromDisk);
      // The empty answer, then at most two reads stepping over it - see
      // "A chunk that cannot be read is stepped over" - and then no more.
      checkTrue(`${name}: ...having asked at most twice more (${calls - 3})`, calls >= 4 && calls <= 5);
      check(`${name}: ...with what it did read correct`, ids(got.packets.slice(0, fromDisk)), ids(packets.slice(0, fromDisk)));
      check(`${name}: ...and the window after it whole`, ids(got.packets.slice(fromDisk)), ids(tail));
      check(`${name}: ...so done still reaches total`, end?.done, end?.total);
    }

    // ---- a chunk the store skipped over ----
    {
      // Two chunks an answer, the first thrown away: the frames between must
      // be counted, and the frames after them must still arrive.
      let dropped = 0;
      const holed: CaptureRowReader = {
        async readRowsAt(from, to) {
          const blocks = await store.reader.readRowsAt(from, to);
          if (dropped === 0 && blocks.length >= 2) {
            dropped = blocks[0].packets.length;
            return blocks.slice(1);
          }
          return blocks;
        },
        readBytes: (list) => store.reader.readBytes(list),
        ordinalOf: (id) => store.reader.ordinalOf(id),
      };
      const got = await collect(exportFrames(whole, holed, plain({ hydrateBytes: false, pageSize: 8192 })));
      if (dropped === 0) {
        console.log(`        (${below} frames below the window is under two chunks; no hole to make)`);
      } else {
        check(`${name}: a chunk missing from an answer is counted`, last(got.pages)?.unreadable, dropped);
        check(`${name}: ...and everything after it still arrives`,
          ids(got.packets), ids(packets.slice(dropped)));
      }
    }

    // ---- abort ----
    {
      const controller = new AbortController();
      let seen = 0;
      let caught: unknown = null;
      try {
        for await (const _page of exportFrames(whole, store.reader, plain({ signal: controller.signal }))) {
          seen++;
          controller.abort();
        }
      } catch (error) { caught = error; }
      check(`${name}: an abort stops the export after the page in hand`, seen, 1);
      check(`${name}: ...by throwing, so no writer commits a short file`,
        (caught as { name?: string } | null)?.name, 'AbortError');
    }

    // ---- orderByTime ----
    {
      // The real export, through the orderer: already in capture order, and
      // a capture's order is its time order bar driver skew - so the output
      // must be sorted and, where the input already was, unchanged.
      const ordered = await collect(orderByTime(exportFrames(whole, store.reader, plain({ hydrateBytes: false }))));
      const sortedInput = [...packets].sort((a, b) => a.tsUs - b.tsUs);
      check(`${name}: orderByTime over the export is the capture stably sorted by time`,
        ids(ordered.packets), ids(sortedInput));

      // Disordered on purpose, by a bounded skew: the capture's frames, each
      // run of 64 reversed, in pages of 1,000 - so no frame is more than a
      // page out of place.
      const skewed: Packet[] = [];
      for (let i = 0; i < sortedInput.length; i += 64) skewed.push(...sortedInput.slice(i, i + 64).reverse());
      async function* pagesOf(list: Packet[]): AsyncGenerator<ExportPage> {
        for (let i = 0; i < list.length; i += 1000) {
          yield { packets: list.slice(i, i + 1000), done: i, total: list.length, below: 0, unreadable: 0, bytesMissing: 0 };
        }
      }
      const out = (await collect(orderByTime(pagesOf(skewed)))).packets;
      checkTrue(`${name}: a bounded skew comes out sorted`,
        out.every((p, i) => i === 0 || out[i - 1].tsUs <= p.tsUs));
      check(`${name}: ...with every frame exactly once`,
        ids(out).sort((a, b) => a - b), ids(packets).sort((a, b) => a - b));
      // Ties: frames sharing a timestamp leave in the order they arrived.
      const arrival = new Map(skewed.map((p, i) => [p.id, i]));
      checkTrue(`${name}: ...and ties keep their arrival order`,
        out.every((p, i) => i === 0 || out[i - 1].tsUs !== p.tsUs
          || arrival.get(out[i - 1].id)! < arrival.get(p.id)!));
    }

    store.close();
  }

  // ---- two link types under one adapter label ----
  //
  // Every frame of an import carries the same `interfaceName`, so a
  // multi-interface file is one label and several link types - and a table
  // keyed by label can hold only one of them. Built from both real fixtures by
  // Wireshark's own tools, as `pcapng.ts` builds it: one re-labelled Raw IP
  // (`editcap -T rawip`), then the two merged into one pcapng.
  await mergedCapture(captures, plain);

  // ---- linkTypeTable over real Ethernet frames ----
  // The adapter list is the agent's descriptors, not frames; the window is a
  // fixture's own. An Ethernet frame teaches the table nothing, and an
  // Ethernet adapter is left out - absent already means Ethernet.
  {
    const window = captures[0].packets.slice(0, 2);
    const table = linkTypeTable([
      { label: 'Npcap Loopback Adapter', linkType: LINKTYPE.NULL },
      { label: 'Wi-Fi', linkType: LINKTYPE.ETHERNET },
      { label: 'Ethernet 2' },
    ], window);
    check('linkTypeTable: the loopback adapter, and nothing for Ethernet frames or adapters',
      [...table].sort(), [['Npcap Loopback Adapter', LINKTYPE.NULL]]);
  }

  console.log();
  if (failures > 0) {
    console.log(`${failures} assertion(s) FAILED`);
    process.exit(1);
  }
  console.log('All assertions passed.');
  process.exit(0);
}

async function mergedCapture(
  captures: Awaited<ReturnType<typeof loadRealCaptures>>,
  plain: (extra?: Partial<ExportFramesOptions>) => ExportFramesOptions,
): Promise<void> {
  console.log('\n--- one label, two link types ---\n');
  const editcap = findWiresharkTool('editcap');
  const mergecap = findWiresharkTool('mergecap');
  if (editcap === null || mergecap === null || captures.length < 2) {
    console.log('SKIP  multi-link-type capture: editcap, mergecap or the second fixture not found');
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), 'inwire-whole-capture-'));
  try {
    const raw = join(dir, 'raw.pcap');
    const merged = join(dir, 'merged.pcapng');
    runTool(editcap, ['-T', 'rawip', captures[1].path, raw]);
    runTool(mergecap, ['-F', 'pcapng', '-w', merged, captures[0].path, raw]);
    const { packets } = await PcapService.parseCaptureFile(
      new File([new Uint8Array(readFileSync(merged))], 'merged.pcapng'), Number.POSITIVE_INFINITY);
    const label = new Set(packets.map((p) => p.interfaceName));
    const kinds = new Set(packets.map((p) => p.linkType ?? LINKTYPE.ETHERNET));
    check('merged: one adapter label, two link types', [label.size, kinds.size], [1, 2]);

    const store = await storeOf(packets);
    const split = Math.floor(packets.length * 0.8);
    const window = packets.slice(split);
    const below = await store.locate(window[0].id);
    check('merged: the store places the window', below, split);
    const own = (p: Packet) => p.linkType ?? LINKTYPE.ETHERNET;
    const disk = packets.slice(0, below);
    checkTrue('merged: both link types are on disk, below the window',
      new Set(disk.map(own)).size === 2);

    // Whatever the table says - the window's own answer, or each of the two
    // types forced onto the label - every disk row comes back as it was.
    const tableFromWindow = linkTypeTable([], window);
    // A frame that is not Ethernet does teach it: real frames of both kinds,
    // under one label, and the table keeps the one that says something.
    const rawFrame = packets.find((p) => p.linkType === LINKTYPE.RAW_IP)!;
    const etherFrame = packets.find((p) => p.linkType === undefined)!;
    check('merged: linkTypeTable learns Raw IP from a real frame, and nothing from Ethernet',
      [...linkTypeTable([], [rawFrame, etherFrame])], [[rawFrame.interfaceName, LINKTYPE.RAW_IP]]);
    for (const [why, table] of [
      ['the table built from the window', tableFromWindow],
      ['a table saying Raw IP', new Map([[packets[0].interfaceName, LINKTYPE.RAW_IP]])],
      ['a table saying loopback', new Map([[packets[0].interfaceName, LINKTYPE.NULL]])],
    ] as const) {
      const out = await collect(exportFrames({ window, filter: null }, store.reader,
        plain({ hydrateBytes: false, linkTypes: table })));
      check(`merged: every disk row keeps its own link type, under ${why}`,
        out.packets.slice(0, below).filter((p, i) => own(p) !== own(disk[i])).length, 0);
    }
    // And the table alone - what an old chunk falls back to - could not have
    // said it, which is what makes the check above one that can fail.
    const tableOnly = (p: Packet) => tableFromWindow.get(p.interfaceName) ?? LINKTYPE.ETHERNET;
    checkTrue('merged: a label-keyed table would have mislabelled some of them',
      disk.some((p) => tableOnly(p) !== own(p)));
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
