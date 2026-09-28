/**
 * Regenerates the vendor tables in src/services/macVendors.ts from IEEE's
 * published registries.
 *
 *   npx tsx scripts/gen-oui.ts
 *
 * IEEE assigns MAC blocks at three sizes, and publishes each as its own CSV:
 *
 *   MA-L  24-bit prefix  oui/oui.csv       ~40,000 blocks, the familiar OUI
 *   MA-M  28-bit prefix  oui28/mam.csv     ~6,600
 *   MA-S  36-bit prefix  oui36/oui36.csv   ~7,200, and the older IAB
 *                        iab/iab.csv       registry of the same size, ~4,600
 *   CID   24-bit prefix  cid/cid.csv       ~200 Company IDs, for addresses
 *                                          with the locally-administered bit
 *
 * A 28- or 36-bit block is carved out of a 24-bit one IEEE holds itself
 * ("IEEE Registration Authority"), so without the smaller registries a device
 * in one resolves to IEEE rather than to its maker. Lookup is longest prefix
 * first (`macVendors.ts`).
 *
 * Nothing fetches these at build or run time: this project has no build-time
 * network step, and the app makes no request it was not asked to (CLAUDE.md,
 * "Offline by default"). Run this by hand, then commit the regenerated file.
 * `scripts/dissect/mac-vendors.ts` holds the result to Wireshark's own table.
 *
 * Short names: see shortName() below. They are derived from the registry's
 * legal names by this project's own rule, not copied from any analyzer's
 * curated list, so they agree with other tools usually rather than always.
 * Entries already present in the checked-in tables are preserved, so
 * hand-corrected names are never clobbered by a regeneration.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const IEEE = 'https://standards-oui.ieee.org';
const MA_L = `${IEEE}/oui/oui.csv`;
const MA_M = `${IEEE}/oui28/mam.csv`;
const MA_S = `${IEEE}/oui36/oui36.csv`;
const IAB = `${IEEE}/iab/iab.csv`;
const CID = `${IEEE}/cid/cid.csv`;
const MACVENDORS = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'services', 'macVendors.ts');

/**
 * IEEE publishes only the full legal name ("Intel Corporate", "GIGA-BYTE
 * TECHNOLOGY CO.,LTD."). The column wants something a person recognises in
 * twelve characters, so the legal-form words every registry entry carries are
 * dropped first and what remains is packed and truncated: "Intel Corporate"
 * -> "Intel", "Sagemcom Broadband SAS" -> "SagemcomBroa".
 *
 * Derived here from the public registry rather than taken from any analyzer's
 * curated list - those files are separately licensed, and this project ships
 * under MIT. Names therefore agree with other tools usually, not always.
 */
const LEGAL_FORM_WORDS = new Set([
  'corporate', 'corporation', 'corp', 'inc', 'incorporated', 'ltd', 'limited', 'llc', 'lp', 'plc',
  'co', 'company', 'gmbh', 'ag', 'kg', 'sas', 'sa', 'srl', 'spa', 'bv', 'nv', 'ab', 'as', 'oy',
  'pty', 'pte', 'sdn', 'bhd', 'kk', 'aps', 'sl', 'the', 'and', 'of',
]);

function shortName(organization: string): string {
  const words = organization
    .replace(/[.,]/g, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .filter((w) => !LEGAL_FORM_WORDS.has(w.toLowerCase().replace(/[^a-z]/g, '')));
  // Letters and digits of any script: a registry name written only in Chinese
  // is the maker's name, and an ASCII-only rule reduced it to nothing - an
  // entry that resolved no address. Twelve characters, not twelve UTF-16 units.
  const packed = (words.length > 0 ? words : [organization]).join('').replace(/[^\p{L}\p{N}]/gu, '');
  return Array.from(packed).slice(0, 12).join('');
}

/**
 * RFC 4180 over the whole text. IEEE quotes any field with a comma, and some
 * organisation addresses carry a line break inside their quotes - so a split
 * on newlines first would cut those rows in two and read an address line as
 * an assignment.
 */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (ch === '"') inQuotes = false;
      else cell += ch;
    } else if (ch === '"') inQuotes = true;
    else if (ch === ',') { row.push(cell); cell = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); cell = '';
      rows.push(row); row = [];
    } else cell += ch;
  }
  if (cell !== '' || row.length > 0) { row.push(cell); rows.push(row); }
  return rows;
}

/** Assignment (hex digits) to short name, for every row of one registry. */
async function registry(url: string, digits: number): Promise<Map<string, string>> {
  console.log(`fetching ${url} ...`);
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url} returned ${response.status} ${response.statusText}`);
  const [header, ...rows] = parseCsv(await response.text());
  if (header?.[1] !== 'Assignment' || header[2] !== 'Organization Name') {
    throw new Error(`${url} no longer has the columns this script reads: ${header?.join(',')}`);
  }
  const out = new Map<string, string>();
  for (const [, assignment, organization] of rows) {
    if (!assignment || !organization) continue;
    const hex = assignment.trim().toUpperCase();
    if (hex.length !== digits || !/^[0-9A-F]+$/.test(hex)) {
      throw new Error(`${url}: "${assignment}" is not ${digits} hex digits`);
    }
    out.set(hex, shortName(organization.trim()));
  }
  if (out.size === 0) throw new Error(`${url} held no assignments`);
  return out;
}

/**
 * Existing entries win over generated ones - a hand-corrected name survives a
 * regeneration - unless they have no name, which corrects nothing. Sorted.
 */
function merge(generated: Map<string, string>, existing: Map<string, string>): [string, string][] {
  const kept = [...existing].filter(([, name]) => name !== '');
  return [...new Map([...generated, ...kept])].filter(([, name]) => name !== '')
    .sort(([a], [b]) => a.localeCompare(b));
}

/** The source text of one `const NAME = ...;` declaration, and its body. */
function declaration(source: string, pattern: RegExp, name: string): RegExpMatchArray {
  const match = source.match(pattern);
  if (!match) throw new Error(`Could not locate ${name} in macVendors.ts - has it been renamed?`);
  return match;
}

const OUI24 = /const OUI_VENDOR_MAP: Record<string, string> = \{\n([\s\S]*?)\n\};/;
const blocksPattern = (name: string) => new RegExp(`const ${name} = \`\\n([\\s\\S]*?)\`;`);

/** "hex name" lines, as the packed tables hold them. */
function readLines(body: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of body.split('\n')) {
    const at = line.indexOf(' ');
    if (at > 0) out.set(line.slice(0, at), line.slice(at + 1));
  }
  return out;
}

async function main() {
  const [large, cid, medium, small, iab] = await Promise.all([
    registry(MA_L, 6), registry(CID, 6), registry(MA_M, 7), registry(MA_S, 9), registry(IAB, 9),
  ]);

  let source = readFileSync(MACVENDORS, 'utf8');

  // 24-bit: an object literal, keyed "AA:BB:CC", as it always was.
  const table = declaration(source, OUI24, 'OUI_VENDOR_MAP');
  const existing24 = new Map<string, string>();
  for (const entry of table[1].matchAll(/'([0-9A-F:]{8})':\s*'([^']+)'/g)) existing24.set(entry[1], entry[2]);
  const generated24 = new Map([...cid, ...large].map(([hex, name]) => [hex.match(/.{2}/g)!.join(':'), name]));
  const merged24 = merge(generated24, existing24);
  const body24 = merged24.map(([oui, name]) => `  '${oui}': '${name.replace(/'/g, "\\'")}',`).join('\n');
  source = source.replace(table[0], `const OUI_VENDOR_MAP: Record<string, string> = {\n${body24}\n};`);

  // 28- and 36-bit: packed text, one "HEX Name" line a block. shortName()
  // leaves only letters and digits, so nothing in a line can end the template.
  const counts: string[] = [];
  for (const [name, generated] of [
    ['OUI28_BLOCKS', medium],
    ['OUI36_BLOCKS', new Map([...iab, ...small])],
  ] as const) {
    const decl = declaration(source, blocksPattern(name), name);
    const merged = merge(generated, readLines(decl[1]));
    source = source.replace(decl[0], `const ${name} = \`\n${merged.map(([hex, n]) => `${hex} ${n}`).join('\n')}\n\`;`);
    counts.push(`${merged.length} ${name}`);
  }

  writeFileSync(MACVENDORS, source);
  console.log(`wrote ${merged24.length} 24-bit OUIs, ${counts.join(', ')} to ${MACVENDORS}`);
}

main().catch(err => {
  console.error(err.message ?? err);
  process.exit(1);
});
