/**
 * Runs every assertion script in this directory.
 *
 *   npm run check
 *
 * The repo has two dozen assertion scripts and, until this existed, nothing
 * that ran them as a set - so each was only as useful as whoever remembered it.
 * Adding one more to an unrun pile is not coverage.
 *
 * Discovery is by directory walk rather than a hand-maintained list, because a
 * list is the thing that silently stops including the newest script. A file
 * counts as an assertion script if it calls `process.exit`, which is how every
 * one of them signals failure - or if it imports `parity/treeOracle.ts`, whose
 * `finish()` makes that call for it. The second rule was missing while the
 * oracle's first seventeen callers were written, so sixteen of them never ran
 * here: a test that exits through a helper has no `process.exit` of its own.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..');

/**
 * Scripts that are not assertions and cannot pass on an arbitrary machine.
 *
 * Both are legitimate tools; neither is a test. Keeping them out by name - with
 * the reason attached - is better than a heuristic that might one day exclude a
 * real test for looking unusual.
 */
const NOT_TESTS: Record<string, string> = {
  'gen-oui.ts': 'generator; downloads ~5MB from IEEE',
  'electron/launchApp.ts':
    'helper; the one way a script starts the app, in the background (INWIRE_BACKGROUND_WINDOW); '
    + 'every script that launches Electron imports it',
  'parity/treeOracle.ts': 'helper; every script that imports it is run instead',
  'agent/sync-version.ts':
    'generator; WRITES local-agent/agent_version.py, agent-rs/Cargo.toml and Cargo.lock '
    + 'from package.json. A check suite that rewrites its own inputs cannot fail - '
    + '`scripts/agent/version.ts` is the half that asserts',
  'agent/stamp-agent.ts':
    'build step; WRITES agent-rs/dist/inwire-agent-windows.exe from cargo\'s output. '
    + 'Run by `npm run build:agent`; `scripts/agent/built-version.ts` is the half that asserts',
  'distribution/generate.ts':
    'generator; WRITES a release.json from a final signed installer - run by the release, '
    + '`scripts/distribution/contracts.ts` is the half that asserts',
  'electron/disk-drive.ts':'drives a 180,000-frame capture to reach the disk path; ~2 minutes, run by hand',
  'agent/two-client-drive.ts':
    'two real connections to the installed agent, one capture on a real adapter: the second is refused '
    + 'the first\'s capture and leaving ends neither; needs the service, Npcap and traffic, run by hand',
  'electron/agent-live-drive.ts':
    'drives the app against the REAL installed agent service and reads the SCM; '
    + 'needs dist/, the InwireAgent service, and Windows - run by hand',
  'electron/update-center-drive.ts':
    'drives the Update Center against a loopback feed in the real app; needs dist/ and ~1 minute, run by hand',
  'electron/import-drive.ts': 'imports a 400,000-frame file to reach the disk path; ~1 minute, run by hand',
  'electron/import-heap-drive.ts': 'driver; imports a large capture file into the built app and fails if the renderer dies or the heap ends past the buffer budget (#19) - needs a big file, minutes per run',
  'electron/revisit-drive.ts':
    'launches the built app, imports the real inwire fixture and opens frames whose trees '
    + 'are rebuilt from their records (ADR 0049); needs a build and the fixture, run by hand',
  'electron/live-revisit-drive.ts':
    'captures live traffic through the installed agent and opens old frames rebuilt from '
    + 'their records (ADR 0049); needs a build, the agent, Npcap and an Ethernet adapter, run by hand',
  'electron/capture-options-drive.ts':
    'captures through the installed agent with a capture filter and a snaplen, and checks '
    + 'every frame on disk against both (ADR 0050); needs a build, the 0.5.0 agent, Npcap and '
    + 'an Ethernet adapter, run by hand',
  'electron/capture-file-drive.ts':
    'captures through the installed agent until its autostop and checks the file it wrote as '
    + 'this user against the store, and that a folder this user cannot write is refused (ADR 0052); '
    + 'needs a build, the 0.5.0 agent, Npcap and an Ethernet adapter, run by hand',
  'electron/gpu-restore-drive.ts':
    'loses and restores a real WebGL context in the running app; needs dist/ and a GPU, run by hand',
  'electron/serveStub.ts': 'tool; serves the stub agent until Ctrl+C, for driving the app by hand',
  'electron/stream-states-shots.ts':
    'photographs the ladder and the state map over real streams in both themes, for looking at '
    + 'rather than asserting; needs dist/, the fixtures and a few minutes, run by hand',
  'tls/replay-stored-capture.ts':
    'tool; replays a person\'s own stored capture against their key log (ADR 0045), run by hand',
  'parity/cluster-diff.ts':
    'tool; diffs ONE abbrev prefix against the reference by frame and by value, '
    + 'which is what proves a new cluster is correct rather than merely present. '
    + 'Takes a pcap and a prefix, has no pass mark of its own, and needs tshark '
    + 'and a fixture - run by hand',
  'agent/pipe-interop.ts':
    "drives the Rust agent's named pipe with the app's own client; needs "
    + '`cargo run --example pipe_serve` running beside it, and Windows',
  'agent/agent-interop.ts':
    "drives the Rust agent's whole capture path with the app's own client; "
    + 'needs `cargo run --example agent_serve` running beside it, a real '
    + 'capture device, and Windows',
  'agent/agent-compare.ts':
    'runs BOTH agents against one adapter at the same moment and diffs what '
    + 'they captured; needs the Python agent registered as the service and the '
    + 'Rust one running on INWIRE_AGENT_PIPE beside it, and Windows',
  'parity/parity-check.ts': 'needs the untracked fixture captures and tshark ground truth (test/fixtures/README.md)',
  'tcp/reassembly.ts': 'diagnostic; needs the fixtures, and reports rather than asserts (docs/decisions/0020)',
  'perf/clone-cost.ts': 'measurement; there is no right answer to hold it to (docs/decisions/0007)',
  'perf/throughput.ts': 'measurement; needs the untracked fixture captures (test/fixtures/README.md)',
  'perf/tree-cost.ts': 'measurement; needs the untracked fixture captures (test/fixtures/README.md)',
  'perf/buffer-cost.ts': 'measurement; needs the untracked fixture captures (test/fixtures/README.md)',
  'perf/fields-cost.ts': 'measurement; needs the fixtures and --expose-gc (test/fixtures/README.md)',
  'perf/tracker-cost.ts': 'measurement; needs --expose-gc, and there is no right answer to hold it to (docs/decisions/0014)',
  'perf/color-index-cost.ts': 'measurement; needs the fixtures and --expose-gc (docs/decisions/0015)',
  'perf/record-cost.ts': 'measurement; needs the fixtures and --expose-gc (docs/decisions/0016)',
  'perf/fields-split-cost.ts': 'measurement; needs the fixtures and --expose-gc (docs/decisions/0017)',
  'perf/store-boundary.ts': 'measurement; there is no right answer to hold it to (the ADR 0028 number)',
  'perf/ui-burst-drive.ts': 'measurement and driver; launches the built app against a replay of a real burst and prints fps, long tasks and profiles, with no pass mark',
  'electron/readme-shots.ts': 'photographs the capture view against the stub agent for the README; pictures have no right answer and it launches the built app',
  'electron/palette-shots.ts': 'photographs the command palette, the filter recents and match chip, and settings search and Reset in all four themes, for looking at; its one assertion (Escape closes only the palette) needs the built app launched',
  'electron/speed-test-shots.ts': 'photographs every state of the speed test against a local speed server, for looking at; a few minutes and no pass mark',
  'electron/monitoring-shots.ts': 'photographs every state of NetFlow monitoring against datagrams it sends itself, for looking at; a few minutes and no pass mark',
  'electron/speed-test-drive.ts': 'runs one real speed test against Cloudflare in the built app and prints the numbers - an outbound test by design, and the network decides the answer',
  'speed-test/gen-colos.ts': 'generator; fetches Cloudflare\'s data-centre list and WRITES src/services/speedTest/colos.ts - run by hand, committed with its output',
  'perf/parallel-threads.ts': 'measurement; dissects a capture on worker_threads shards and prints frames a second against one core, with no pass mark (ADR 0053 phase 3)',
  'perf/row-codec.ts': 'measurement; times structured clone, JSON and the chunk codec carrying dissected rows between threads, with no pass mark (ADR 0053 phase 6)',
  'perf/record-transport.ts': 'measurement; times frame records as one buffer per frame against one slab per batch on the shard -> coordinator and coordinator -> store hops, with no pass mark',
  'monitoring/measurement.ts':
    'measurement and human step (ADRs 0058-0059); the journal mode writes ~2.7 GB to temp, socket, journal and rollup print '
    + 'machine properties with no pass mark, and the firewall mode needs the installed agent, WSL and a person to answer the Windows Security prompt',
  'electron/monitoring-drive.ts':
    'driver; launches the built app a dozen times against its own loopback exporter and kills its Worker, utility and renderer '
    + 'to prove recovery, quit drain and sidecar rebuild, then v9 restarts and retention expiry - about six minutes, and every launch needs a build',
  'monitoring/interop.ts':
    'driver; replays softflowd\'s v5 and softflowd\'s and pmacct\'s v9 and IPFIX exports into the built app and compares with '
    + 'tshark and nfdump - needs WSL, Ubuntu, softflowd, pmacct, nfdump and tshark, and says NOT RUN without them, which is never a pass',
  'monitoring/load.ts': 'measurement; stepped NetFlow load against the built app for up to ten minutes, with no pass mark',
  'monitoring/exporter-lab.ts':
    'measurement; records what softflowd and pmacct send as v9 and IPFIX and cross-checks tshark and nfdump - needs WSL, Ubuntu, '
    + 'softflowd, pmacct, nfdump and tshark, and says NOT RUN without them, which is never a pass',
  'electron/monitoringSeed.ts': 'helper, not a test; builds real monitoring datasets on disk (expired, incomplete, read-only, foreign, empty) for monitoring-ui.ts and monitoring-shots.ts, each proved by the collector’s own inspect',
  'monitoring/fixtures.ts': 'helper, not a test; builds the generated NetFlow v5 payloads and evidence the monitoring scripts assert against',
  'monitoring/queryRig.ts': 'helper, not a test; the in-memory journal, sidecar, runtime and Worker host that rollup.ts and queries.ts drive',
  'perf/xlsx-cost.ts':
    'measurement; sizes the Excel export budget (XLSX_BYTES_PER_CELL) on the real captures, '
    + 'needs the fixtures and --expose-gc, and has no pass mark',
  'perf/wire-size.ts': 'measurement; there is no right answer to hold it to (docs/decisions/0005)',
  'perf/summary-codec.ts': 'measurement; needs the fixtures, and sizes a format rather than asserting one (the disk-backed buffer plan)',
  'perf/profile.ts':
    'measurement; re-executes itself under `node --cpu-prof` and prints self time '
    + 'by function. Needs the fixtures, takes ~30s, and a profile has no pass mark - '
    + 'but nothing else can answer "where did the milliseconds go", which is the '
    + 'question ADR 0011 got wrong by an order of magnitude before it measured',
};

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (entry.endsWith('.ts')) out.push(full);
  }
  return out;
}

const candidates = walk(here)
  // Posix separators so the printed names match how the repo talks about
  // them, on Windows as well as elsewhere.
  .map((f) => relative(here, f).split(sep).join('/'))
  .filter((f) => f !== 'check.ts')
  .filter((f) => !(f in NOT_TESTS))
  .filter((f) => {
    const text = readFileSync(join(here, f), 'utf8');
    return text.includes('process.exit') || /from '\.\.\/parity\/treeOracle'/.test(text);
  })
  .sort();

const skipped = Object.entries(NOT_TESTS);

console.log(`Running ${candidates.length} assertion script(s)\n`);

const failed: string[] = [];
for (const script of candidates) {
  // `shell: true` because on Windows the npx entry point is a .cmd shim, which
  // CreateProcess cannot execute directly - without it every script "fails"
  // with no output at all, which looks like a broken test rather than a broken
  // runner.
  const result = spawnSync(`npx tsx ${join('scripts', script)}`, {
    cwd: repoRoot,
    encoding: 'utf8',
    shell: true,
  });
  const ok = result.error === undefined && result.status === 0;
  if (!ok) failed.push(script);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${script}`);
  if (!ok) {
    // Only the failing script's output, and only the tail of it - the point is
    // to name what broke, not to reprint two dozen passing assertions.
    const output = result.error
      ? `could not run it: ${result.error.message}`
      : `${result.stdout ?? ''}${result.stderr ?? ''}`.trimEnd();
    for (const line of output.split('\n').slice(-25)) console.log(`      ${line}`);
  }
}

console.log();
for (const [script, why] of skipped) console.log(`SKIP  ${script}  (${why})`);

console.log();
if (failed.length > 0) {
  console.log(`${failed.length} script(s) FAILED: ${failed.join(', ')}`);
  process.exit(1);
}
console.log(`All ${candidates.length} assertion scripts passed.`);
