/**
 * The ladder and the state map over real streams, photographed - for looking
 * at, not asserting (ADR 0055).
 *
 *   npx tsx scripts/electron/stream-states-shots.ts <out-dir> [--widths 1024,1600] [--themes dark,light] [--kinds tcp,udp,quic,tls,dns,dhcp] [--dhcp-pcap <file>]
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
 *
 * Stage 2's kinds ride the same import: a two-way UDP flow, an established
 * QUIC connection and one joined mid-stream, each opened on the ladder (no
 * state map; QUIC's phase line, then a click on its last phase), the packet
 * list filtered to it, and Statistics' UDP and QUIC levels with a row's click.
 * `--kinds` picks which of the three to shoot.
 *
 * `--kinds dhcp` needs no fixture: the fixtures hold no DHCP, so the script
 * writes a synthetic capture (documentation addresses only) with one acked
 * DORA exchange, one Discover and Offer with no Request, and one unicast
 * renewal Request with no reply, imports it, and shoots Statistics' DHCP level
 * and Follow Stream on each exchange. `--dhcp-pcap <file>` keeps the capture
 * at that path; otherwise it lives in a temp directory and is removed.
 */
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Page } from 'playwright';
import { arrive, FIXTURES } from '../pipeline/arrival';
import { StreamDigest, type StreamSummary } from '../../src/services/conversation/streamDigest';
import { inFlow, type QuicSummary, type UdpSummary } from '../../src/services/conversation/flowSummary';
import { Bytes, pcapOf, udpFrameTo } from '../parity/synthetic';
import type { DhcpSummary } from '../../src/services/conversation/dhcpSummary';
import { dnsMarks } from '../../src/services/conversation/dnsMarks';
import type { Packet } from '../../src/types/packet';
import { dnsOutcomeText } from '../../src/services/conversation/digestRows';
import type { TlsSummary } from '../../src/services/conversation/tlsSummary';
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
const KINDS = arg('kinds', 'tcp,udp,quic').split(',');
mkdirSync(OUT, { recursive: true });

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

if (process.platform !== 'win32') { console.log('SKIP  the desktop app is Windows-only'); process.exit(0); }
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'main.cjs'))) {
  console.log('SKIP  no build to launch - run `npm run build` first'); process.exit(0);
}
const inwire = FIXTURES.find((f) => f.name === 'inwire')!;
const bulk = FIXTURES.find((f) => f.name === 'bulk')!;
// DHCP writes its own capture; every other kind reads the private fixtures.
const NEED_FIXTURES = KINDS.some((k) => k !== 'dhcp');
if (NEED_FIXTURES) {
  for (const f of [inwire, bulk]) {
    if (!existsSync(f.path)) { console.log(`SKIP  ${f.path} is not present - see test/fixtures/README.md`); process.exit(0); }
  }
}

/** A stream worth photographing: how to find it, and what to hover and click once it is open. */
interface Case {
  name: string;
  fixture: { path: string; frames: number };
  summary: StreamSummary;
}

/** A UDP flow or QUIC connection: opened the same way, with no state map to drive. */
interface FlowCase {
  name: string;
  fixture: { path: string; frames: number };
  summary: UdpSummary | QuicSummary;
}

/** The fixture's streams as the digest folds them, which is the fold the store runs. */
async function digestOf(fixturePath: string): Promise<{
  summaries: StreamSummary[]; udp: UdpSummary[]; quic: QuicSummary[]; tls: TlsSummary[]; dhcp: DhcpSummary[];
  frames: number; rows: Packet[];
}> {
  const { arrived } = await arrive(fixturePath);
  const digest = new StreamDigest();
  for (const a of arrived) digest.feed(a.packet);
  // Every summary: each has a version above zero once a row has been folded.
  const changes = digest.changedSince(0);
  return { summaries: changes.tcp, udp: changes.udp, quic: changes.quic, tls: changes.tls, dhcp: changes.dhcp, frames: arrived.length, rows: arrived.map((a) => a.packet) };
}

console.log('folding the fixtures through the digest...');
const NO_DIGEST: Awaited<ReturnType<typeof digestOf>> = { summaries: [], udp: [], quic: [], tls: [], dhcp: [], frames: 0, rows: [] };
const inwireDigest = NEED_FIXTURES ? await digestOf(inwire.path) : NO_DIGEST;
const bulkDigest = NEED_FIXTURES ? await digestOf(bulk.path) : NO_DIGEST;
const total = (s: { toServer: { packets: number }; toClient: { packets: number } }) => s.toServer.packets + s.toClient.packets;
// A stream with a few dozen frames reads on one ladder; thousands fold into bands.
const pick = (list: StreamSummary[], want: (s: StreamSummary) => boolean) =>
  [...list].filter(want).sort((a, b) => Math.abs(total(a) - 40) - Math.abs(total(b) - 40))[0];
const cases: Case[] = [];
const closed = pick(inwireDigest.summaries, (s) => s.outcome === 'closed cleanly' && !s.joinedMidStream && total(s) >= 8);
const reset = pick(inwireDigest.summaries, (s) => s.outcome.startsWith('reset by') && !s.joinedMidStream && total(s) >= 6);
const joined = pick(bulkDigest.summaries, (s) => s.joinedMidStream && total(s) >= 8);
if (KINDS.includes('tcp') && closed) cases.push({ name: 'closed-cleanly', fixture: { path: inwire.path, frames: inwireDigest.frames }, summary: closed });
if (KINDS.includes('tcp') && reset) cases.push({ name: 'reset', fixture: { path: inwire.path, frames: inwireDigest.frames }, summary: reset });
if (KINDS.includes('tcp') && joined) cases.push({ name: 'joined-mid-stream', fixture: { path: bulk.path, frames: bulkDigest.frames }, summary: joined });

const near40 = <T extends UdpSummary | QuicSummary>(list: T[], want: (s: T) => boolean): T | undefined =>
  [...list].filter(want).sort((a, b) => Math.abs(total(a) - 40) - Math.abs(total(b) - 40))[0];
const inwireFixture = { path: inwire.path, frames: inwireDigest.frames };
const flowCases: FlowCase[] = [];
const udpFlow = near40(inwireDigest.udp, (s) => s.outcome === 'two-way' && total(s) >= 8);
const quicConn = near40(inwireDigest.quic, (s) => s.outcome === 'established' && !s.joinedMidStream && total(s) >= 8);
const quicJoined = near40(inwireDigest.quic, (s) => s.joinedMidStream);
if (KINDS.includes('udp') && udpFlow) flowCases.push({ name: 'udp-two-way', fixture: inwireFixture, summary: udpFlow });
if (KINDS.includes('quic') && quicConn) flowCases.push({ name: 'quic-established', fixture: inwireFixture, summary: quicConn });
if (KINDS.includes('quic') && quicJoined) flowCases.push({ name: 'quic-joined', fixture: inwireFixture, summary: quicJoined });
for (const c of flowCases) {
  console.log(`  ${c.name}: ${c.summary.kind} #${c.summary.key}, frames #${c.summary.firstId}..#${c.summary.lastId}, `
    + `${total(c.summary)} frames, ${c.summary.outcome}${c.summary.kind === 'quic' ? `, ${c.summary.phases.length} phases` : ''}`);
}
for (const c of cases) {
  console.log(`  ${c.name}: stream #${c.summary.streamId}, frames #${c.summary.firstId}..#${c.summary.lastId}, `
    + `${total(c.summary)} frames, ${c.summary.outcome}${c.summary.joinedMidStream ? ' (joined mid-stream)' : ''}, `
    + `${c.summary.steps.length} steps`);
}
// Stage 3: the first TCP stream whose TLS summary has a ServerHello step.
let tlsCase: { summary: StreamSummary; tls: TlsSummary } | undefined;
if (KINDS.includes('tls')) {
  for (const t of inwireDigest.tls) {
    if (!t.phases.some((p) => p.phase === 'ServerHello')) continue;
    const s = inwireDigest.summaries.find((x) => x.streamId === t.key);
    if (s !== undefined) { tlsCase = { summary: s, tls: t }; break; }
  }
  console.log(tlsCase === undefined
    ? '  tls: no stream with a ServerHello'
    : `  tls: stream #${tlsCase.summary.streamId}, phases ${tlsCase.tls.phases.map((p) => `${p.phase === 'alert' ? `alert: ${p.alertName}` : p.phase} (${p.side})`).join(' -> ')}`);
}
// Stage 3: the UDP flow with a DNS tally and the most queries.
let dnsCase: UdpSummary | undefined;
// The frame the ladder is opened on: a marked one when the flow has any, so the shot shows a mark.
let dnsFrame = 0;
if (KINDS.includes('dns')) {
  const queries = (u: UdpSummary) => (u.dns === undefined ? -1 : u.dns.answered + u.dns.errors + u.dns.evictedUnanswered + u.dns.open.length);
  dnsCase = [...inwireDigest.udp].filter((u) => u.dns !== undefined).sort((a, b) => queries(b) - queries(a))[0];
  console.log(dnsCase === undefined
    ? '  dns: no UDP flow with a tally'
    : `  dns: udp #${dnsCase.key}, ${dnsOutcomeText(dnsCase.dns!, Math.max(...inwireDigest.udp.map((u) => u.end)))}`);
  if (dnsCase !== undefined) {
    const key = dnsCase.key;
    const marks = dnsMarks(inwireDigest.rows.filter((r) => inFlow(r, 'udp', key)), Math.max(...inwireDigest.rows.map((r) => r.relativeTime)));
    dnsFrame = [...marks.keys()][0] ?? dnsCase.firstId;
    console.log(`  dns: opened on frame #${dnsFrame}${marks.has(dnsFrame) ? `, marked "${marks.get(dnsFrame)}"` : ''}`);
  }
}

// Stage 3: DHCP, from a capture written here because the fixtures hold none.
const MAC_A = '02:00:00:00:00:01';
const MAC_B = '02:00:00:00:00:02';
const MAC_C = '02:00:00:00:00:03';
const SERVER = '192.0.2.1';

/** A BOOTP message (RFC 2131) with option 53 and the given options, as UDP payload. */
function bootp(
  op: 1 | 2, xid: number, mac: string, type: number,
  opts: { ciaddr?: string; yiaddr?: string; hostname?: string; requested?: string; server?: string } = {},
): Uint8Array {
  const b = new Bytes()
    .u8(op, 1, 6, 0).u32(xid).u16(0, 0x8000)
    .ipv4(opts.ciaddr ?? '0.0.0.0').ipv4(opts.yiaddr ?? '0.0.0.0').ipv4('0.0.0.0').ipv4('0.0.0.0')
    .mac(mac).zeros(10).zeros(64).zeros(128)
    .u32(0x63825363)
    .u8(53, 1, type);
  if (opts.hostname !== undefined) b.u8(12, opts.hostname.length).ascii(opts.hostname);
  if (opts.requested !== undefined) b.u8(50, 4).ipv4(opts.requested);
  if (opts.server !== undefined) b.u8(54, 4).ipv4(opts.server);
  if (op === 2 && type !== 6) b.u8(51, 4).u32(3600);
  return b.u8(255).build();
}

/** The synthetic capture: frames in order, and what each exchange should read as. */
function dhcpFrames(): { frames: Uint8Array[]; expect: Record<string, string> } {
  const bc = '255.255.255.255';
  const A = 0x1a2b3c4d, B = 0x5e6f7081, C = 0x8badf00d;
  const frames = [
    // A: acked, with a hostname and a server identifier.
    udpFrameTo('0.0.0.0', bc, 68, 67, bootp(1, A, MAC_A, 1, { hostname: 'synth-laptop' })),
    udpFrameTo(SERVER, '192.0.2.50', 67, 68, bootp(2, A, MAC_A, 2, { yiaddr: '192.0.2.50', server: SERVER })),
    udpFrameTo('0.0.0.0', bc, 68, 67, bootp(1, A, MAC_A, 3, { hostname: 'synth-laptop', requested: '192.0.2.50', server: SERVER })),
    udpFrameTo(SERVER, '192.0.2.50', 67, 68, bootp(2, A, MAC_A, 5, { yiaddr: '192.0.2.50', server: SERVER })),
    // B: an offer nobody took.
    udpFrameTo('0.0.0.0', bc, 68, 67, bootp(1, B, MAC_B, 1)),
    udpFrameTo(SERVER, '192.0.2.51', 67, 68, bootp(2, B, MAC_B, 2, { yiaddr: '192.0.2.51', server: SERVER })),
    // C: a unicast renewal Request that nothing answered.
    udpFrameTo('198.51.100.20', '198.51.100.1', 68, 67, bootp(1, C, MAC_C, 3, { ciaddr: '198.51.100.20' })),
  ];
  return { frames, expect: { [String(A)]: 'acked', [String(B)]: 'offer not taken', [String(C)]: 'no reply' } };
}

interface DhcpCase { name: string; summary: DhcpSummary }
const dhcpCases: DhcpCase[] = [];
let dhcpFixture: { path: string; frames: number } | undefined;
let dhcpDir: string | undefined;
if (KINDS.includes('dhcp')) {
  const { frames, expect } = dhcpFrames();
  const keep = arg('dhcp-pcap', '');
  dhcpDir = keep === '' ? mkdtempSync(path.join(tmpdir(), 'inwire-dhcp-shots-')) : undefined;
  const file = keep === '' ? path.join(dhcpDir!, 'dhcp-synthetic.pcap') : keep;
  writeFileSync(file, pcapOf(frames));
  dhcpFixture = { path: file, frames: frames.length };
  const tsharkArgs = ['-r', file, '-Y', 'dhcp', '-T', 'fields', '-e', 'dhcp.option.dhcp'];
  const probe = [spawnSync('tshark', tsharkArgs, { encoding: 'utf8' }),
    spawnSync('C:/Program Files/Wireshark/tshark.exe', tsharkArgs, { encoding: 'utf8' })]
    .find((r) => r.status === 0) ?? { status: 1, stdout: '' };
  const types = (probe.stdout ?? '').split('\n').filter((l) => l !== '');
  console.log(probe.status === 0
    ? `  dhcp: tshark reads ${types.length} DHCP frames of ${frames.length}, option 53 values ${types.join(',')}`
    : '  dhcp: tshark not on PATH, frame layout not cross-checked');
  const folded = await digestOf(file);
  const names: Record<string, string> = { acked: 'ladder', 'offer not taken': 'offer', 'no reply': 'renewal' };
  for (const d of folded.dhcp) {
    const want = expect[String(d.key)];
    console.log(`  dhcp: 0x${d.key.toString(16).padStart(8, '0')} ${d.outcome} (expected ${want}), ${d.phases.map((p) => p.message).join(' -> ')}, frames #${d.firstId}..#${d.lastId}`);
    dhcpCases.push({ name: names[want] ?? `x${d.key}`, summary: d });
  }
  dhcpCases.sort((a, b) => a.summary.firstId - b.summary.firstId);
}
if (cases.length === 0 && flowCases.length === 0 && tlsCase === undefined && dnsCase === undefined && dhcpCases.length === 0) { console.log('no streams to photograph'); process.exit(1); }

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
            // A row with the filter button, not the virtual list's spacer row.
            await p.locator('tbody tr').filter({ has: p.getByRole('button', { name: 'Filter to this conversation' }) })
              .first().locator('td').first().click();
            const opened = await p.locator('[data-state-map]').waitFor({ timeout: 10_000 }).then(() => true, () => false);
            console.log(`  row click opened the stream: ${opened}`);
            await shot('stats-5-row-opened');
          }
        }

        for (const c of flowCases) {
          if (imported !== c.fixture.path) {
            console.log(`${tag}: importing ${path.basename(c.fixture.path)}`);
            const ok = await importFixture(p, c.fixture);
            console.log(`  imported: ${ok}`);
            imported = c.fixture.path;
          }
          const { summary } = c;
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
          await p.waitForFunction(() => !/reading \d/i.test(document.body.innerText), undefined, { timeout: 60_000 }).catch(() => {});
          await sleep(800);
          const title = await p.getByText(/^Follow (UDP|QUIC) (Stream|Connection)/).first().textContent({ timeout: 30_000 }).catch(() => null);
          const mapShown = await p.locator('[data-state-map]').count();
          console.log(`  title: ${title ?? 'NONE'}; state map present: ${mapShown}`);
          await shot(`${c.name}-1-ladder`);

          if (summary.kind === 'quic') {
            const phases = p.locator('[aria-label="QUIC phases"]');
            const shown = await phases.waitFor({ timeout: 30_000 }).then(() => true, () => false);
            const buttons = await phases.getByRole('button').count();
            console.log(`  phase line: ${shown}, ${buttons} buttons (summary has ${summary.phases.length})`);
            const last = summary.phases[summary.phases.length - 1];
            if (shown && last !== undefined) {
              const before = await p.locator(`[data-frame="${last.frameId}"]`).count();
              await phases.getByRole('button').last().click();
              await sleep(800);
              const after = await p.locator(`[data-frame="${last.frameId}"]`).count();
              console.log(`  click ${last.phase}/${last.side} (frame #${last.frameId}): arrow on screen before ${before}, after ${after}`);
              await shot(`${c.name}-2-picked`);
              await phases.getByRole('button').first().hover();
              await sleep(600);
              await shot(`${c.name}-3-phase-hover`);
              await phases.getByRole('button').first().focus();
              await p.keyboard.press('Tab');
              await sleep(300);
              await shot(`${c.name}-4-phase-focus`);
              await p.mouse.move(5, 5);
            }
          }

          await p.keyboard.press('Escape');
          await sleep(400);
          await filter.fill(summary.kind === 'quic' ? `quic.connection.number == ${summary.key}` : `udp.stream == ${summary.key}`);
          await filter.press('Enter');
          await p.locator(`#packet-row-${summary.firstId}`).waitFor({ timeout: 30_000 }).catch(() => {});
          await sleep(800);
          await shot(`${c.name}-5-list`);
        }

        // Stage 3: a TCP stream with a ServerHello, opened on the ladder with
        // its TLS line, then Statistics' TCP level sorted by Outcome.
        if (tlsCase !== undefined) {
          if (imported !== inwire.path) {
            console.log(`${tag}: importing ${path.basename(inwire.path)}`);
            console.log(`  imported: ${await importFixture(p, inwireFixture)}`);
            imported = inwire.path;
          }
          const { summary } = tlsCase;
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
          await p.waitForFunction(() => !/reading \d/i.test(document.body.innerText), undefined, { timeout: 60_000 }).catch(() => {});
          await sleep(800);
          const line = p.locator('[aria-label="TLS phases"]');
          const shown = await line.waitFor({ timeout: 30_000 }).then(() => true, () => false);
          console.log(`  TLS line: ${shown}, ${shown ? await line.getByRole('button').count() : 0} buttons (summary has ${tlsCase.tls.phases.length})`);
          await shot('tls-1-ladder');

          await p.keyboard.press('Escape');
          await sleep(400);
          await filter.fill('');
          await filter.press('Enter');
          await p.getByRole('button', { name: /^Statistics/ }).click();
          await p.getByRole('button', { name: 'Conversations' }).click();
          await p.getByRole('button', { name: 'TCP', exact: true }).click();
          await sleep(500);
          await p.getByRole('button', { name: 'Outcome', exact: true }).click();
          await sleep(300);
          const notes = await p.locator('tbody tr').filter({ hasText: /TLS (alert|unanswered)/ }).count();
          console.log(`  TCP rows with a TLS note: ${notes}`);
          await shot('stats-tcp-tls');
        }

        // Stage 3: Follow Stream on the DNS flow, then Statistics' UDP level by Outcome.
        if (dnsCase !== undefined) {
          if (imported !== inwire.path) {
            console.log(`${tag}: importing ${path.basename(inwire.path)}`);
            console.log(`  imported: ${await importFixture(p, inwireFixture)}`);
            imported = inwire.path;
          }
          const filter = p.getByPlaceholder('e.g. tcp.port == 443');
          await filter.fill(`frame.number == ${dnsFrame}`);
          await filter.press('Enter');
          const row = p.locator(`#packet-row-${dnsFrame}`);
          await row.waitFor({ timeout: 30_000 });
          await row.click();
          await sleep(300);
          await p.getByRole('button', { name: 'Follow Stream' }).click();
          await sleep(500);
          await p.getByRole('radio', { name: 'Ladder' }).click();
          await p.waitForFunction(() => !/reading \d/i.test(document.body.innerText), undefined, { timeout: 60_000 }).catch(() => {});
          await sleep(800);
          await shot('dns-1-ladder');

          await p.keyboard.press('Escape');
          await sleep(400);
          await filter.fill('');
          await filter.press('Enter');
          await p.getByRole('button', { name: /^Statistics/ }).click();
          await p.getByRole('button', { name: 'Conversations' }).click();
          await p.getByRole('button', { name: 'UDP', exact: true }).click();
          await sleep(500);
          await p.getByRole('button', { name: 'Outcome', exact: true }).click();
          await sleep(300);
          await shot('stats-udp-dns');
        }

        // Stage 3: the synthetic DHCP capture. Statistics' DHCP level first,
        // then Follow Stream on each exchange, opened from its first frame.
        if (dhcpFixture !== undefined && dhcpCases.length > 0) {
          console.log(`${tag}: importing ${path.basename(dhcpFixture.path)}`);
          console.log(`  imported: ${await importFixture(p, dhcpFixture)}`);
          imported = dhcpFixture.path;
          const filter = p.getByPlaceholder('e.g. tcp.port == 443');
          await p.getByRole('button', { name: /^Statistics/ }).click();
          await p.getByRole('button', { name: 'Conversations' }).click();
          await p.getByRole('button', { name: 'DHCP', exact: true }).click();
          const note = await p.getByText(/^(Whole capture|Rebuilding the stream digest)/).first().textContent({ timeout: 30_000 }).catch(() => null);
          const rows = await p.locator('tbody tr').filter({ has: p.getByRole('button', { name: 'Filter to this conversation' }) }).count();
          console.log(`  statistics DHCP scope note: ${note ?? 'NONE'}; ${rows} rows (expected ${dhcpCases.length})`);
          await sleep(500);
          await shot('stats-dhcp');
          await p.keyboard.press('Escape');
          await sleep(400);
          for (const [i, c] of dhcpCases.entries()) {
            await filter.fill(`frame.number == ${c.summary.firstId}`);
            await filter.press('Enter');
            const row = p.locator(`#packet-row-${c.summary.firstId}`);
            await row.waitFor({ timeout: 30_000 });
            await row.click();
            await sleep(300);
            await p.getByRole('button', { name: 'Follow Stream' }).click();
            await sleep(500);
            await p.getByRole('radio', { name: 'Ladder' }).click();
            await p.waitForFunction(() => !/reading \d/i.test(document.body.innerText), undefined, { timeout: 60_000 }).catch(() => {});
            await sleep(800);
            const title = await p.getByText(/^Follow DHCP Exchange/).first().textContent({ timeout: 30_000 }).catch(() => null);
            const line = p.locator('[aria-label="DHCP phases"]');
            const shown = await line.waitFor({ timeout: 30_000 }).then(() => true, () => false);
            console.log(`  dhcp ${c.name}: title ${title ?? 'NONE'}; phase line ${shown}, ${shown ? await line.getByRole('button').count() : 0} buttons (summary has ${c.summary.phases.length})`);
            await shot(`dhcp-${i + 1}-${c.name}`);
            await p.keyboard.press('Escape');
            await sleep(400);
          }
          await filter.fill('');
          await filter.press('Enter');
        }

        // Statistics' UDP and QUIC levels, read from the digest, and a row's
        // click, which must land on Follow Stream for both.
        if (flowCases.length > 0) {
          const filter = p.getByPlaceholder('e.g. tcp.port == 443');
          await filter.fill('');
          await filter.press('Enter');
          for (const level of ['UDP', 'QUIC'].filter((l) => KINDS.includes(l.toLowerCase()))) {
            await p.getByRole('button', { name: /^Statistics/ }).click();
            await p.getByRole('button', { name: 'Conversations' }).click();
            await p.getByRole('button', { name: level, exact: true }).click();
            const note = await p.getByText(/^(Whole capture|Rebuilding the stream digest)/).first().textContent({ timeout: 30_000 }).catch(() => null);
            console.log(`  statistics ${level} scope note: ${note ?? 'NONE'}`);
            await sleep(500);
            await shot(`stats-${level.toLowerCase()}-1-level`);
            await p.getByRole('button', { name: 'Outcome', exact: true }).click();
            await sleep(300);
            await shot(`stats-${level.toLowerCase()}-2-by-outcome`);
            await p.locator('tbody tr').filter({ has: p.getByRole('button', { name: 'Filter to this conversation' }) })
              .first().locator('td').first().click();
            const opened = await p.getByText(/^Follow (UDP|QUIC) (Stream|Connection)/).first()
              .waitFor({ timeout: 10_000 }).then(() => true, () => false);
            await p.waitForFunction(() => !/reading \d/i.test(document.body.innerText), undefined, { timeout: 60_000 }).catch(() => {});
            await sleep(800);
            console.log(`  ${level} row click opened Follow Stream: ${opened}`);
            await shot(`stats-${level.toLowerCase()}-3-row-opened`);
            await p.keyboard.press('Escape');
            await sleep(400);
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
  if (dhcpDir !== undefined) rmSync(dhcpDir, { recursive: true, force: true });
}
console.log(`shots in ${OUT}`);
process.exit(0);
