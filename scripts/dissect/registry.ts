/**
 * Assertion tests for the field registry (docs/decisions/0002) and the
 * dissection directory's isolation (docs/decisions/0003).
 *
 *   npx tsx scripts/dissect/registry.ts
 *
 * The registry is only worth having if it is complete, and it only stays
 * complete if something fails when it is not. Both directions are checked:
 * a key a dissector writes that the registry lacks (the field exists, but
 * filters call it a typo and "apply as column" cannot offer it), and a key the
 * registry lists that nothing writes any more (a filter that validates, matches
 * nothing, and never says why - the shipped colour preset had seven of these).
 *
 * The scan is textual: every quoted `word.word[.word]` literal in the dissection
 * sources is taken to be a field name. That is deliberately broad, because the
 * failure this guards against is a dissector author inventing a name in a
 * string and never registering it; a false positive here is a one-line
 * exclusion below, a false negative is a silent gap.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FIELDS, FIELD_ABBREVS, LAYERS } from '../../src/services/dissect/fieldRegistry';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (/\.tsx?$/.test(entry)) out.push(full);
  }
  return out;
}

// --- where dissectors live ----------------------------------------------------

const DISSECTION_SOURCES = [
  join(root, 'src', 'services', 'pcapParser.ts'),
  ...walk(join(root, 'src', 'services', 'dissectors')),
  ...walk(join(root, 'src', 'services', 'dissect')).filter((f) => !f.endsWith('fieldRegistry.ts')),
];

/**
 * Dotted literals in the dissection sources that are not field names.
 * Keep this list short; a growing one means names are being written in
 * places that should use the registry's constants instead.
 */
const NOT_FIELDS = new Set<string>([]);

const written = new Set<string>();
const writersByKey = new Map<string, string[]>();
for (const file of DISSECTION_SOURCES) {
  const text = readFileSync(file, 'utf8');
  // The tail allows upper case for the same reason the identifier check below
  // does: `ptp.v2.mm.managementId` is the reference analyzer's own spelling.
  for (const m of text.matchAll(/'([a-z][a-z0-9_]*\.[A-Za-z0-9_.-]+)'/g)) {
    const key = m[1];
    if (NOT_FIELDS.has(key)) continue;
    // Something like 'e.g.' or a file name is not a field: require the last
    // segment to be a plausible identifier and the first to be a layer token.
    //
    // Upper case and hyphens are both allowed, because the reference analyzer
    // uses both: `sip.Call-ID`, `sip.Method`, `radius.User_Name` and
    // `ptp.v2.mm.managementId` are all real field names. An abbrev has to match
    // Wireshark's spelling rather than a convention of ours, so this cannot be
    // narrowed to what looks tidy. What still excludes `e.g.` and a file name
    // is the layer-token check immediately below - `e` and `packet` are not
    // layer tokens - which is a stronger filter than the shape of the tail.
    if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(key.split('.').at(-1) ?? '')) continue;
    // `inwire.` is the prefix for a field with no Wireshark equivalent, and it
    // is not a layer token - the registry's own naming rule already allows it,
    // so the scanner has to as well or such a field reads as "registered with
    // no writer".
    const first = key.split('.')[0];
    if (first !== 'inwire' && !(LAYERS as readonly string[]).includes(first)) continue;
    // Layer tokens are names of layers, not fields: `ipv6.fragment` is what
    // `frameProtocols` calls the header, and a filter tests it for presence.
    if ((LAYERS as readonly string[]).includes(key)) continue;
    written.add(key);
    const rel = relative(root, file).split(sep).join('/');
    const list = writersByKey.get(key) ?? [];
    if (!list.includes(rel)) list.push(rel);
    writersByKey.set(key, list);
  }
}

// --- both directions ----------------------------------------------------------

check('every field a dissector writes is registered',
  [...written].filter((k) => !FIELD_ABBREVS.has(k)).sort(), []);

check('...and every registered field has a writer',
  FIELDS.map((f) => f.abbrev).filter((k) => !written.has(k)).sort(), []);

check('abbrevs are unique', FIELDS.length, FIELD_ABBREVS.size);

check('every field belongs to a known layer',
  FIELDS.filter((f) => !(LAYERS as readonly string[]).includes(f.layer)).map((f) => f.abbrev), []);

check('an abbrev starts with its own layer token',
  FIELDS.filter((f) => !f.abbrev.startsWith(`${f.layer.split('.')[0]}.`) && !f.abbrev.startsWith('inwire.')).map((f) => f.abbrev), []);

check('every field has a label', FIELDS.filter((f) => !f.label.trim()).map((f) => f.abbrev), []);

// --- the filter engine derives from the registry rather than repeating it ----

const engine = readFileSync(join(root, 'src', 'services', 'filterEngine.ts'), 'utf8');
const fieldResolution = readFileSync(join(root, 'src', 'services', 'filter', 'fields.ts'), 'utf8');
check('the filter engine resolves its field names through the registry',
  /from '\.\.\/dissect\/fieldRegistry'/.test(fieldResolution)
  && /from '\.\/dissect\/fieldRegistry'/.test(engine), true);

// A handful of registered names legitimately appear in the resolution table,
// because the engine's own aliases are BUILT from them: `tcp.port` reads
// `tcp.srcport` and `tcp.dstport`, `ipv6.addr` reads the two IPv6 addresses.
// Everything else a dissector publishes must not be spelled out anywhere in
// the engine - it should arrive through the registry or not at all.
const ENGINE_ALIASES = new Set([
  'ipv6.src', 'ipv6.dst', 'eth.src', 'eth.dst',
  'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport',
]);
check('...and no longer hand-lists a dissector field',
  [...FIELD_ABBREVS]
    .filter((k) => !ENGINE_ALIASES.has(k))
    .filter((k) => new RegExp(`'${k.replace(/\./g, '\\.')}'`).test(engine + fieldResolution))
    .sort(),
  []);

// --- a published field is reachable from the tree ----------------------------

/**
 * A field is only half-registered until the tree row that shows it carries the
 * same `abbrev`: without one the row is display-only, and "Apply as Filter"
 * and "Apply as Column" are greyed out on precisely the rows people reach for
 * first. Every name below was published into `Packet.fields` - and so
 * filterable if you already knew what to type - while its row offered nothing.
 */
const CORE_TREE_ABBREVS = [
  'ip.src', 'ip.dst', 'ip.ttl', 'ip.proto', 'ip.checksum', 'ip.checksum.status',
  'tcp.srcport', 'tcp.dstport', 'tcp.seq', 'tcp.seq_raw', 'tcp.ack', 'tcp.ack_raw',
  'tcp.flags', 'tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.fin', 'tcp.flags.push',
  'tcp.flags.reset', 'tcp.window_size', 'tcp.len', 'tcp.checksum', 'tcp.checksum.status',
];

{
  const { decodeRawEthernetPacket } = await import('../../src/services/pcapParser');
  // A minimal TCP/IPv4 frame over Ethernet: 14 + 20 + 20 bytes, SYN set.
  const frame = new Uint8Array(54);
  frame.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00], 0);
  frame.set([0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
             10, 0, 0, 1, 93, 184, 216, 34], 14);
  frame.set([0xc7, 0x38, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
             0x50, 0x02, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00], 34);

  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);

  const seen = new Set<string>();
  const visit = (rows: { abbrev?: string; children?: unknown[] }[]) => {
    for (const row of rows) {
      if (row.abbrev) seen.add(row.abbrev);
      if (row.children) visit(row.children as typeof rows);
    }
  };
  for (const layer of packet.layers) visit(layer.fields);

  check('every core field is published', CORE_TREE_ABBREVS.filter((a) => packet.fields?.[a] === undefined), []);
  check('...and its tree row carries the filter name', CORE_TREE_ABBREVS.filter((a) => !seen.has(a)), []);
  check('no tree row names a field the registry does not have',
    [...seen].filter((a) => !FIELD_ABBREVS.has(a)).sort(), []);
}

// --- the dissection directory is Worker-safe (docs/decisions/0003) -----------

const forbidden = /^\s*import .* from ['"](react|react-dom|next-themes|motion\/react)['"]|\b(document|window|localStorage|navigator)\.[A-Za-z]/m;
check('nothing under src/services/dissect touches React or the DOM',
  walk(join(root, 'src', 'services', 'dissect'))
    .filter((f) => forbidden.test(readFileSync(f, 'utf8')))
    .map((f) => relative(root, f).split(sep).join('/')),
  []);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All registry checks passed.');
process.exit(0);
