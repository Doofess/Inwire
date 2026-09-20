/**
 * Does the protocol tree hold what the reference analyzer's holds?
 *
 *   npx tsx scripts/parity/tree-coverage.ts [--fixture inwire|bulk] [--frames N] [--top N]
 *
 * ## Why this exists
 *
 * `parity-check.ts` compares six summary columns, the colour rule, and three
 * named fingerprint fields. `synthetic.ts` compares Protocol and Info. Between
 * them they are the whole tshark-backed gate, and **neither looks at a field**
 * beyond those three - there is no `-V` and no `-T pdml` anywhere else under
 * `scripts/`.
 *
 * So the depth of the detail pane has never been measured against anything. A
 * dissector that stopped emitting half its rows would pass every check in this
 * repository, because the Info column would be unchanged. And the reverse
 * question - *which rows does the reference have that we do not* - had no
 * answer at all, which makes "add more depth" a matter of taste.
 *
 * This asks `tshark -T pdml` for every field of every frame and diffs the
 * **names** against ours, then the values where both sides have one. The
 * output is a ranked list of what is missing, which is the thing that was
 * missing.
 *
 * ## What it is not
 *
 * **A pass/fail gate, yet.** There is no right answer to hold this to: the
 * reference emits fields that are meaningless here, and a long tail nobody
 * wants. So it is a measurement, and `check.ts` skips it by name like
 * `throughput.ts` and `tree-cost.ts`. Choosing floors out of its output is a
 * separate decision, taken once there is an output to read.
 *
 * Needs tshark and the untracked fixtures (test/fixtures/README.md). Skips
 * cleanly without either - a machine that cannot run a measurement has not
 * failed anything.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { PcapService } from '../../src/services/pcapParser';
import { knownFieldNames, protocolNames } from '../../src/services/filter/fields';
import type { Packet, ProtocolField } from '../../src/types/packet';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', '..', 'test', 'fixtures');
const ACCEPTANCE = join(FIXTURES, 'acceptance.json');

/**
 * Where tshark is. The same list as `synthetic.ts`, which includes the bare
 * name so a PATH install is found - `wireshark-abbrevs.ts` omits it and so
 * skips silently on a Linux box with tshark anywhere but the two paths it
 * names.
 */
const TSHARK_CANDIDATES = [
  process.env.TSHARK,
  'tshark',
  'C:\\Program Files\\Wireshark\\tshark.exe',
  'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
  '/usr/bin/tshark',
  '/usr/local/bin/tshark',
  '/opt/homebrew/bin/tshark',
].filter((p): p is string => typeof p === 'string' && p.length > 0);

function findTshark(): string | null {
  for (const candidate of TSHARK_CANDIDATES) {
    const probe = spawnSync(candidate, ['-v'], { encoding: 'utf8', shell: false });
    if (probe.status === 0) return candidate;
  }
  return null;
}

/**
 * Names the reference emits that this build has no business emitting, so they
 * do not sit at the top of the gap list for ever.
 *
 * Each is a fact about the *file* or about tshark's own bookkeeping rather
 * than about the packet: `geninfo` is a proto PDML invents, `frame.*` is the
 * pcap record header (answered here by the synthetic readers in
 * `filter/fields.ts` rather than by a dissector), and `_ws.*` is the
 * reference's internal namespace.
 *
 * Deliberately short. Anything else added here needs the kind of argument
 * `wireshark-abbrevs.ts`'s exemption list demands.
 */
const NOT_OURS = [
  /^frame(\.|$)/,
  /^_ws\./,
  /^fake-field-wrapper$/,
  // `data` is not a protocol. It is the reference's marker for *the absence of
  // dissection* - `data.data`, `data.len`, `data.text` on a payload nothing
  // claimed - and this build represents that state by emitting no rows at all.
  // Counting it as a gap would ask us to add three fields whose meaning is
  // "there is nothing here".
  /^data(\.|$)/,
];
const ignored = (abbrev: string): boolean => NOT_OURS.some((pattern) => pattern.test(abbrev));

/**
 * Rows the reference derives from a field we already emit.
 *
 * `eth.dst.oui`, `eth.dst.lg`, `eth.dst.ig` and `eth.dst_resolved` sit at
 * **100% of frames** at the top of the gap list, and every one of them is the
 * reference re-presenting bits of an address it has already shown - the OUI
 * half, the locally-administered bit, the group bit, the name resolution.
 *
 * **The exemption is conditional on the parent, and that is what makes it
 * unable to rot.** `eth.dst.oui` is exempt *because* `eth.dst` is present; the
 * claim is "we emit the address, this is a decomposition of it". The day a
 * regression stops us emitting `eth.dst`, the exemption evaporates on its own
 * and four rows reappear at the top of ABSENT - which is the loud behaviour,
 * arrived at without a rot check. `wireshark-abbrevs.ts` needs its `stale`
 * check because its exemptions are bare names; these are not.
 */
const DECOMPOSITION: { suffix: RegExp; why: string }[] = [
  { suffix: /\.(lg|ig)$/, why: "a bit of an address we emit whole" },
  { suffix: /\.oui(_resolved)?$/, why: "the vendor half of an address we emit whole" },
  { suffix: /_resolved$/, why: 'name resolution of an address we emit whole' },
];

/** `eth.dst.oui` -> `eth.dst`; `eth.dst_resolved` -> `eth.dst`. */
function parentOf(abbrev: string, suffix: RegExp): string {
  const cut = abbrev.replace(suffix, '');
  return cut.endsWith('.') ? cut.slice(0, -1) : cut;
}

/**
 * Fields the reference files under **another protocol's** registry.
 *
 * SSDP is the case that forced this, and it is not what it first looks like.
 * `http.request.method` reads ABSENT on 53 inwire frames; the frames are
 * `eth:ethertype:ip:udp:ssdp` on *both* sides. The reference's SSDP dissector
 * simply reuses HTTP's field names for the start line and headers, because
 * SSDP is HTTP-shaped over UDP.
 *
 * **These are re-attributed, not exempted, and the difference is the whole
 * point.** This build registers `ssdp` as a layer token with *zero* fields, so
 * those 53 frames really do show nothing where the reference shows a method, a
 * URI and headers. Dropping them would hide a genuine gap; counting them under
 * `http` blames the HTTP dissector for a hole in SSDP and hides the real state
 * of both. So the abbrev keeps its name and the per-layer table counts it
 * under the protocol the frame actually is.
 *
 * Applied per frame, on the reference's own proto chain - never by prefix, or
 * a genuinely missing HTTP field on port 80 would be re-attributed too.
 */
const REATTRIBUTE: { proto: string; family: string; why: string }[] = [
  {
    proto: 'ssdp',
    family: 'http',
    why: "the reference's SSDP dissector reuses HTTP's field names",
  },
];

/**
 * `geninfo` has to be dropped by its **proto**, not by its field names.
 *
 * It is a synthetic proto PDML invents to carry the frame's metadata, and its
 * four fields are named `num`, `len`, `caplen` and `timestamp` - bare words
 * with no prefix. Matched by name they would need four entries in `NOT_OURS`
 * that would also swallow any real protocol field called `len`, and they sat
 * at the top of the gap list at 100% of frames on the first run.
 */
const SYNTHETIC_PROTO = 'geninfo';

// --- reading the reference's tree ---------------------------------------------

/** One frame's fields, as `abbrev -> first displayed value`. */
type FrameFields = Map<string, string>;

function attribute(line: string, name: string): string | undefined {
  const at = line.indexOf(` ${name}="`);
  if (at === -1) return undefined;
  const from = at + name.length + 3;
  const to = line.indexOf('"', from);
  return to === -1 ? undefined : line.slice(from, to);
}

/** PDML escapes its attribute values; `show` comes back through these. */
function unescapeXml(value: string): string {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#(\d+);/g, (_, code: string) => String.fromCodePoint(Number(code)))
    .replace(/&amp;/g, '&');
}

/**
 * Streams `tshark -T pdml` and calls back once per frame.
 *
 * Streamed rather than buffered because PDML for a 15,000-frame capture runs
 * to hundreds of megabytes, and every frame is finished with by the time the
 * next one begins - an `execFileSync` with a `maxBuffer` big enough would hold
 * all of it at once for no reason.
 */
async function eachReferenceFrame(
  tshark: string,
  capturePath: string,
  maxFrames: number,
  onFrame: (index: number, fields: FrameFields, protos: Set<string>) => void,
): Promise<number> {
  const args = ['-T', 'pdml', '-r', capturePath];
  if (Number.isFinite(maxFrames)) args.push('-c', String(maxFrames));
  const child = spawn(tshark, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => { stderr += chunk; });

  let index = -1;
  let fields: FrameFields = new Map();
  let protos = new Set<string>();
  let currentProto = '';

  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  for await (const raw of lines) {
    const line = raw.trimStart();
    if (line.startsWith('<packet>')) {
      index++;
      fields = new Map();
      protos = new Set();
      currentProto = '';
      continue;
    }
    if (line.startsWith('</packet>')) {
      onFrame(index, fields, protos);
      continue;
    }
    if (line.startsWith('<proto ')) {
      const name = attribute(line, 'name');
      currentProto = name ?? '';
      if (name !== undefined && name !== '' && name !== SYNTHETIC_PROTO && !ignored(name)) protos.add(name);
      continue;
    }
    if (!line.startsWith('<field ')) continue;
    if (currentProto === SYNTHETIC_PROTO) continue;
    const name = attribute(line, 'name');
    if (name === undefined || name === '' || ignored(name)) continue;
    // First occurrence wins. A field repeated inside one frame - every TCP
    // option, every DNS answer - is one row as far as "do we have this field"
    // is concerned.
    if (fields.has(name)) continue;
    const show = attribute(line, 'show');
    fields.set(name, show === undefined ? '' : unescapeXml(show));
  }

  const status: number = await new Promise((resolve) => { child.on('close', resolve); });
  if (status !== 0) {
    const detail = stderr.trim().split('\n').slice(0, 3).join(' / ');
    throw new Error(`tshark exited ${status}: ${detail}`);
  }
  return index + 1;
}

// --- reading ours --------------------------------------------------------------

/**
 * Every abbrev this build publishes for a frame, from **both** surfaces.
 *
 * A field reaches a person two ways here and they are not the same set: a tree
 * row (`ProtocolField.abbrev`, what the detail pane draws) and the flat bag
 * (`Packet.fields`, what a filter reads). 36 registered fields are `treeOnly`
 * and appear only in the first; some derived values appear only in the second.
 * The union is what the build *knows*, and the reference's PDML is likewise
 * the union of everything its dissectors put in the tree - so the union is the
 * comparable thing.
 */
function ourFrameFields(packet: Packet): FrameFields {
  const out: FrameFields = new Map();
  const walk = (fields: readonly ProtocolField[]): void => {
    for (const field of fields) {
      if (field.abbrev !== undefined && !out.has(field.abbrev)) {
        out.set(field.abbrev, String(field.value));
      }
      if (field.children !== undefined) walk(field.children);
    }
  };
  for (const layer of packet.layers ?? []) walk(layer.fields);
  for (const [abbrev, value] of Object.entries(packet.fields ?? {})) {
    if (!out.has(abbrev)) out.set(abbrev, String(value));
  }
  return out;
}

// --- the diff -------------------------------------------------------------------

interface Tally {
  /** Frames in which the reference emitted this abbrev. */
  theirs: number;
  /** Frames in which this build emitted it. */
  ours: number;
  /** Frames where both emitted it and the displayed values differ. */
  differ: number;
  samples: string[];
}

function layerOf(abbrev: string): string {
  const dot = abbrev.indexOf('.');
  return dot === -1 ? abbrev : abbrev.slice(0, dot);
}

const num = (value: number): string => value.toLocaleString('en-US');
const pct = (part: number, whole: number): string =>
  whole === 0 ? '   n/a' : `${((part / whole) * 100).toFixed(1).padStart(5)}%`;

async function run(): Promise<void> {
  const argv = process.argv.slice(2);
  const arg = (flag: string): string | undefined => {
    const at = argv.indexOf(flag);
    return at === -1 ? undefined : argv[at + 1];
  };
  const only = arg('--fixture');
  const maxFrames = Number(arg('--frames') ?? Number.POSITIVE_INFINITY);
  const top = Number(arg('--top') ?? 40);
  // Off by default: `show` is the reference's *display* string, so most
  // differences are formatting it chose and we did not ("0x0800" against
  // "0x0800 (IPv4)"). Useful when reading one protocol, noise in a summary.
  const showValues = argv.includes('--values');

  /**
   * Names a filter here accepts, whether or not a tree row carries them.
   *
   * A third surface exists beside the tree and the bag: the synthetic readers
   * in `filter/fields.ts` answer `eth.addr`, `ip.addr`, `tcp.port` and
   * `tcp.stream` from the packet directly. Counting those as missing would be
   * wrong - a user can filter on them today - but they are genuinely absent
   * from the *tree*, which is a real and separate gap. They get their own
   * list rather than being folded into either answer.
   */
  const filterable = new Set(knownFieldNames());

  const tshark = findTshark();
  if (tshark === null) {
    console.log('SKIP  tshark not found - set TSHARK to its path to run this measurement.');
    console.log(`      (Tried: ${TSHARK_CANDIDATES.join(', ')})`);
    return;
  }
  if (!existsSync(ACCEPTANCE)) {
    console.log('SKIP  test/fixtures/acceptance.json missing.');
    return;
  }

  const acceptance = JSON.parse(readFileSync(ACCEPTANCE, 'utf8')) as {
    fixtures: Record<string, { file: string }>;
  };

  for (const [name, spec] of Object.entries(acceptance.fixtures)) {
    if (only !== undefined && only !== name) continue;
    const capturePath = join(FIXTURES, spec.file);
    if (!existsSync(capturePath)) {
      console.log(`SKIP  ${name}: ${spec.file} not present (see test/fixtures/README.md)`);
      continue;
    }

    const bytes = readFileSync(capturePath);
    const built = await PcapService.parseCaptureFile(new File([bytes], spec.file), maxFrames, true);
    const packets = built.packets;

    const tally = new Map<string, Tally>();
    const bump = (abbrev: string): Tally => {
      let entry = tally.get(abbrev);
      if (entry === undefined) {
        entry = { theirs: 0, ours: 0, differ: 0, samples: [] };
        tally.set(abbrev, entry);
      }
      return entry;
    };

    const theirProtos = new Map<string, number>();
    /**
     * Every protocol name this build can answer to, which is **not** just the
     * tokens the fixture happened to produce.
     *
     * `frameProtocols` alone put `mdns` and `llmnr` on the unnamed list, and
     * both are wrong: `filter/fields.ts` answers those barewords through
     * `PROTOCOL_PREDICATES`, so a user can filter on them today. Subtracting
     * `protocolNames()` - which is already exactly
     * `[...LAYER_TOKENS, ...Object.keys(PROTOCOL_PREDICATES)]` - removes them
     * with **no exemption entry at all**, which beats writing two reasons down.
     * The same move `REFERENCE_COUNTERS` makes in `parity-check.ts`: derive it
     * rather than keep a second copy by hand.
     */
    const ourProtoTokens = new Set<string>(protocolNames());
    for (const packet of packets) {
      for (const token of packet.frameProtocols ?? []) ourProtoTokens.add(token);
    }
    // Which exemptions actually applied. An exemption nobody observes is a
    // claim about traffic that is not in these captures - and the captures are
    // pinned by sha256, so it means the reason is wrong rather than that the
    // traffic moved. `wireshark-abbrevs.ts` calls this an orphaned entry.
    const decompositionFired = new Set<string>();
    const reattributeFired = new Set<string>();
    /** Abbrev -> the layer it is counted under, where that is not its prefix. */
    const layerOverride = new Map<string, string>();

    let compared = 0;
    const referenceFrames = await eachReferenceFrame(tshark, capturePath, maxFrames, (index, theirFields, protos) => {
      const packet = packets[index];
      if (packet === undefined) return;
      compared++;
      for (const proto of protos) theirProtos.set(proto, (theirProtos.get(proto) ?? 0) + 1);

      const ourFields = ourFrameFields(packet);
      // Families this frame's own protocol borrows from another's registry.
      const borrowed = REATTRIBUTE.filter((r) => protos.has(r.proto));

      for (const [abbrev, theirValue] of theirFields) {
        // Counted under the protocol the frame IS, not the one whose field
        // names it borrowed. The gap stays visible; only its address changes.
        const borrow = borrowed.find(
          (r) => abbrev === r.family || abbrev.startsWith(`${r.family}.`),
        );
        if (borrow !== undefined) {
          reattributeFired.add(borrow.proto);
          layerOverride.set(abbrev, borrow.proto);
        }
        // A row derived from one we already emit - and only while we do.
        const derived = DECOMPOSITION.find(
          (rule) => rule.suffix.test(abbrev) && ourFields.has(parentOf(abbrev, rule.suffix)),
        );
        if (derived !== undefined) {
          decompositionFired.add(derived.why);
          continue;
        }
        const entry = bump(abbrev);
        entry.theirs++;
        const ourValue = ourFields.get(abbrev);
        if (ourValue === undefined || ourValue === theirValue) continue;
        entry.differ++;
        if (entry.samples.length < 3) {
          entry.samples.push(`#${packet.id}  reference: ${theirValue}   inwire: ${ourValue}`);
        }
      }
      for (const abbrev of ourFields.keys()) {
        if (ignored(abbrev)) continue;
        bump(abbrev).ours++;
      }
    });

    console.log(`\n${'='.repeat(78)}`);
    console.log(`${name}: ${spec.file}`);
    console.log('='.repeat(78));
    console.log(`frames: reference ${num(referenceFrames)}, inwire ${num(packets.length)}, compared ${num(compared)}`);
    if (referenceFrames !== packets.length) {
      console.log('WARN  frame counts differ - alignment here is by index, so the diff below is suspect.');
    }

    const entries = [...tally.entries()];
    const missing = entries.filter(([, t]) => t.ours === 0 && t.theirs > 0).sort((a, b) => b[1].theirs - a[1].theirs);
    const extra = entries.filter(([, t]) => t.theirs === 0 && t.ours > 0).sort((a, b) => b[1].ours - a[1].ours);
    const differing = entries.filter(([, t]) => t.differ > 0).sort((a, b) => b[1].differ - a[1].differ);

    const absent = missing.filter(([abbrev]) => !filterable.has(abbrev));
    const filterOnly = missing.filter(([abbrev]) => filterable.has(abbrev));

    console.log(`\n--- ABSENT: the reference emits it, this build has it nowhere (${num(absent.length)} distinct) ---`);
    console.log('      frames  of ref  abbrev');
    for (const [abbrev, entry] of absent.slice(0, top)) {
      console.log(`  ${num(entry.theirs).padStart(10)}  ${pct(entry.theirs, compared)}  ${abbrev}`);
    }
    if (absent.length > top) console.log(`  ... and ${num(absent.length - top)} more`);

    console.log(`\n--- FILTERABLE BUT NOT IN THE TREE: a filter answers, the detail pane does not (${num(filterOnly.length)}) ---`);
    for (const [abbrev, entry] of filterOnly.slice(0, Math.min(top, 20))) {
      console.log(`  ${num(entry.theirs).padStart(10)}  ${pct(entry.theirs, compared)}  ${abbrev}`);
    }
    if (filterOnly.length === 0) console.log('  (none)');

    const byLayer = new Map<string, { ours: Set<string>; theirs: Set<string> }>();
    for (const [abbrev, entry] of entries) {
      const layer = layerOverride.get(abbrev) ?? layerOf(abbrev);
      let seen = byLayer.get(layer);
      if (seen === undefined) {
        seen = { ours: new Set(), theirs: new Set() };
        byLayer.set(layer, seen);
      }
      if (entry.ours > 0) seen.ours.add(abbrev);
      if (entry.theirs > 0) seen.theirs.add(abbrev);
    }
    const layers = [...byLayer.entries()]
      .filter(([, seen]) => seen.theirs.size > 0)
      .sort((a, b) => (b[1].theirs.size - b[1].ours.size) - (a[1].theirs.size - a[1].ours.size));

    console.log('\n--- per-layer coverage: distinct abbrevs ---');
    console.log('    layer              ours  theirs  covered');
    for (const [layer, seen] of layers.slice(0, top)) {
      const ours = String(seen.ours.size).padStart(5);
      const theirs = String(seen.theirs.size).padStart(6);
      console.log(`  ${layer.padEnd(18)} ${ours}  ${theirs}  ${pct(seen.ours.size, seen.theirs.size)}`);
    }

    if (showValues) {
      console.log(`\n--- VALUE MISMATCHES: both emit the abbrev, the shown value differs (${num(differing.length)} distinct) ---`);
      console.log('    advisory - the reference formats plenty of values differently by design');
      for (const [abbrev, entry] of differing.slice(0, Math.min(top, 20))) {
        console.log(`  ${num(entry.differ).padStart(10)} frames  ${abbrev}`);
        for (const sample of entry.samples) console.log(`               ${sample}`);
      }
    } else {
      console.log(`\n--- VALUE MISMATCHES: ${num(differing.length)} abbrevs differ in their shown value; pass --values to list them ---`);
    }

    console.log(`\n--- INWIRE-ONLY: this build emits it, the reference does not (${num(extra.length)} distinct) ---`);
    for (const [abbrev, entry] of extra.slice(0, Math.min(top, 25))) {
      console.log(`  ${num(entry.ours).padStart(10)}  ${abbrev}`);
    }

    console.log('\n--- PROTOCOLS the reference names that this build cannot name at all ---');
    const unlabelled = [...theirProtos.entries()]
      .filter(([proto]) => !ourProtoTokens.has(proto))
      .sort((a, b) => b[1] - a[1]);
    if (unlabelled.length === 0) console.log('  (none)');
    for (const [proto, frames] of unlabelled.slice(0, top)) {
      console.log(`  ${num(frames).padStart(10)}  ${proto}`);
    }
    const protosNamed = theirProtos.size - unlabelled.length;
    console.log(`  named ${num(protosNamed)} of the ${num(theirProtos.size)} the reference used here`);

    // An exemption nobody observed is a claim about traffic that is not in
    // these captures - and they are pinned by sha256, so it means the reason
    // is wrong rather than that the traffic moved.
    console.log('\n--- EXEMPTIONS that applied on this fixture ---');
    for (const rule of DECOMPOSITION) {
      console.log(`  ${decompositionFired.has(rule.why) ? 'fired ' : 'UNUSED'}  ${rule.suffix.source}  (${rule.why})`);
    }
    for (const rule of REATTRIBUTE) {
      const fired = reattributeFired.has(rule.proto) ? 'fired ' : 'UNUSED';
      console.log(`  ${fired}  ${rule.family}.* counted under ${rule.proto}  (${rule.why})`);
    }
  }
}

run().catch((error: unknown) => {
  console.error(`FAIL  ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
