/**
 * Does the protocol tree hold what the reference analyzer's holds?
 *
 *   npx tsx scripts/parity/tree-coverage.ts [--fixture inwire|bulk] [--frames N] [--top N] [--values] [--write-floors]
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
 * ## What it is held to
 *
 * This file used to say *"a pass/fail gate, yet… choosing floors out of its
 * output is a separate decision, taken once there is an output to read."*
 * There is an output to read, and ADR 0039 is that decision. Four numbers per
 * fixture, in `acceptance.json`'s `tree` block:
 *
 * - **`layers[layer]` — a floor, and a COUNT, never a ratio.** The number of
 *   distinct abbrevs *both* sides emit in that layer. The denominator of a
 *   coverage percentage is the **reference's** vocabulary, which grows when
 *   Wireshark ships - so a ratio floor would fail a build that changed nothing,
 *   on the very upgrade `test/fixtures/README.md` tells you to perform. A gate
 *   that fails on its own prescribed maintenance is a gate people delete.
 *   `wireshark-abbrevs.ts` won the same argument by checking `ours ⊆ theirs`,
 *   which is immune to the reference growing and fails only on a rename.
 *   The intersection, not our raw count, because a floor on our own output
 *   would pass just as happily on an abbrev we invented.
 * - **`protosNamed` — a floor.** How many of the protocols the reference names
 *   here this build can name, through `frameProtocols` or a filter predicate.
 * - **`ceilings.filterableNotInTree` — a number that may only FALL.** It is
 *   the one place where every entry is a defect with no judgement call: the
 *   app accepts a filter for a row the detail pane refuses to draw. Bounded by
 *   *our* vocabulary, so the reference cannot grow it, and it falls whenever a
 *   registered name gains the row it was always promising.
 * - **`counts` — recorded and NEVER enforced.** `absentDistinct` because a
 *   ceiling on it would turn a ranked measurement into a 600-item backlog,
 *   which is exactly what ADR 0021 ended: *a bucket is a defect only until it
 *   is measured*.
 *
 *   **`valueMismatches` is here and was briefly a ceiling, which was wrong.**
 *   `ourFrameFields` stringifies with `String(...)` against the reference's
 *   *display* string, so it counts formatting divergences and not defects -
 *   our `Not set` against its `False`, our `20 bytes (5)` against its `20`.
 *   It therefore **rises when a field is added**, which is the direction this
 *   whole gate exists to encourage: naming the five TCP flag bits took it up
 *   by five without a single value being wrong. A ceiling that punishes the
 *   improvement it was built to reward is a ceiling people route around. The
 *   series is still worth having, so it is recorded.
 *
 * `--write-floors` records what it measured. `--frames N` is a prefix, so it
 * turns the assertions off loudly rather than checking whole-file floors
 * against a tenth of the evidence.
 *
 * Needs tshark and the untracked fixtures (test/fixtures/README.md). Skips
 * cleanly without either - a machine that cannot run a measurement has not
 * failed anything, which is also the reason this can be in `npm run check`
 * where `parity-check.ts` cannot: that one fails on a missing fixture, by
 * design (ADR 0004).
 */
import { useRepositoryWiresharkProfile } from '../wiresharkProfile';
import { spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { PcapService } from '../../src/services/pcapParser';
import { knownFieldNames, protocolNames } from '../../src/services/filter/fields';
import type { Packet, ProtocolField } from '../../src/types/packet';
import type { Acceptance, TreeAcceptance } from './acceptance-schema';

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
  useRepositoryWiresharkProfile();
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
  // `data` used to be exempt here, on the argument that it marks *the absence
  // of dissection* and that this build "represents that state by emitting no
  // rows at all". **That premise stopped being true and the exemption went
  // with it.** The rows exist now - `dissectors/mediaType.ts` raises the
  // reference's `Data` layer for any payload that reaches the end of its
  // dissector chain unclaimed, on 1,902 frames of `inwire` and 187 of `bulk`.
  //
  // Keeping it would have been the exact failure `wireshark-abbrevs.ts` calls
  // a stale exemption: a claim that stays in the file after the thing it
  // claims has changed. The bare `data` protocol name is the one piece still
  // absent, and it is counted rather than excused.
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
  // `-2`, for the reason `regen-ground-truth.sh` gives for the columns: the
  // Wireshark GUI is two-pass, and it is the GUI this build is matched against.
  // This gate was single-pass while the column gate was not, so the two halves
  // of one measurement were comparing against two different references.
  //
  // It costs nothing and buys seven names. Measured on `inwire`: the
  // single-pass vocabulary is a strict subset of the two-pass one - 802 abbrevs
  // against 809 - and every one of the seven is a fact a first pass cannot
  // know. `dns.response_in`, `dns.response_missing`, `icmp.resp_in`,
  // `icmp.no_resp`, `icmp.resp_not_found`, `quic.reassembled_in` and
  // `tls.handshake.reassembled_in`. This build already emits the first of them,
  // so it was being counted as inwire-only against a reference that simply had
  // not been asked the question.
  //
  // `-c` is a first-pass limit, so `--frames N` still means the first N.
  const args = ['-2', '-T', 'pdml', '-r', capturePath];
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

let failures = 0;
/** One held expectation, in the PASS/FAIL shape every script here prints. */
function report(name: string, pass: boolean, detail: string): void {
  if (!pass) failures++;
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${name}${pass ? '' : ` - ${detail}`}`);
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
  const writeFloors = argv.includes('--write-floors');
  /**
   * **A prefix cannot be checked against whole-file floors.**
   *
   * The floors are measured over every frame of a fixture. Holding a
   * 500-frame prefix to them would fail on every layer the prefix happens not
   * to contain, so the only honest answer is to stop asserting - loudly, not
   * by quietly passing, because a gate that says PASS on a tenth of the
   * evidence is worse than one that says nothing.
   */
  const wholeFile = !Number.isFinite(maxFrames);
  const assertFloors = wholeFile && !writeFloors;

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

  const acceptance = JSON.parse(readFileSync(ACCEPTANCE, 'utf8')) as Acceptance;
  /** What `--write-floors` will put back, per fixture. */
  const written: Record<string, TreeAcceptance> = {};

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
      // **A failure, not a warning.** Alignment is by index, so a count
      // mismatch makes every number below it meaningless - the floors would be
      // checked against a diff of frames that are not the same frames.
      // `parity-check.ts` treats its own row-count mismatch the same way.
      console.log('FAIL  frame counts differ - alignment here is by index, so nothing below is '
        + 'comparable. Re-generate the ground truth, or check the capture.');
      failures++;
      continue;
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

    // --- what this fixture is held to ------------------------------------------

    /**
     * The floorable number per layer: abbrevs **both** sides emit.
     *
     * Not our raw count, which would pass on a name we invented, and not a
     * ratio - see this file's header and ADR 0039. `entry.ours > 0` alone is
     * what the table above prints, and the difference between the two is the
     * INWIRE-ONLY list.
     */
    const shared = new Map<string, number>();
    for (const [abbrev, entry] of entries) {
      if (entry.ours === 0 || entry.theirs === 0) continue;
      const layer = layerOverride.get(abbrev) ?? layerOf(abbrev);
      shared.set(layer, (shared.get(layer) ?? 0) + 1);
    }
    const measured: TreeAcceptance = {
      layers: Object.fromEntries([...shared.entries()].sort(([a], [b]) => a.localeCompare(b))),
      protosNamed,
      ceilings: { filterableNotInTree: filterOnly.length },
      counts: { absentDistinct: absent.length, valueMismatches: differing.length },
      unimplemented: spec.tree?.unimplemented ?? {},
    };

    if (writeFloors) {
      written[name] = measured;
      console.log('\n--- MEASURED (--write-floors) ---');
      console.log(JSON.stringify(measured, null, 2).split('\n').map((l) => `  ${l}`).join('\n'));
      continue;
    }
    if (!assertFloors) {
      console.log(`\nSKIP  assertions: --frames ${num(maxFrames)} is a prefix and the floors are `
        + 'whole-file. Run without --frames to check them.');
      continue;
    }

    const held = spec.tree;
    if (held === undefined) {
      console.log(`\nFAIL  ${name}: no "tree" block in acceptance.json. `
        + 'Run with --write-floors to record one.');
      failures++;
      continue;
    }

    console.log('\n--- HELD TO ---');
    for (const [layer, floor] of Object.entries(held.layers)) {
      const now = shared.get(layer) ?? 0;
      report(`${name}: ${layer} keeps at least ${floor} shared abbrevs`, now >= floor,
        `has ${now}`);
    }
    report(`${name}: names at least ${held.protosNamed} of the reference's protocols`,
      protosNamed >= held.protosNamed, `names ${protosNamed}`);
    for (const [what, ceiling] of Object.entries(held.ceilings)) {
      const now = measured.ceilings[what] ?? 0;
      report(`${name}: ${what} stays at or below ${ceiling}`, now <= ceiling, `is ${now}`);
    }
    // A layer declared unimplemented that has started emitting is not a
    // failure here - it is a floor waiting to be written, and `acceptance.ts`
    // is where that becomes one. Said out loud so it is not missed.
    for (const layer of Object.keys(held.unimplemented)) {
      if ((shared.get(layer) ?? 0) > 0) {
        console.log(`  NOTE  ${name}: ${layer} is declared unimplemented and now emits `
          + `${shared.get(layer)} shared abbrevs - run --write-floors and move it into layers.`);
      }
    }
  }

  if (writeFloors) {
    for (const [name, tree] of Object.entries(written)) {
      if (acceptance.fixtures[name] !== undefined) acceptance.fixtures[name].tree = tree;
    }
    writeFileSync(ACCEPTANCE, `${JSON.stringify(acceptance, null, 2)}\n`);
    console.log(`\nwrote tree floors for ${Object.keys(written).join(', ')} to acceptance.json`);
    console.log('Hand-add `unimplemented` reasons for any layer at zero before committing.');
    return;
  }

  console.log();
  if (failures > 0) {
    console.log(`${failures} tree check(s) FAILED`);
    process.exit(1);
  }
  console.log('All tree coverage checks passed.');
  process.exit(0);
}

run().catch((error: unknown) => {
  console.error(`FAIL  ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
