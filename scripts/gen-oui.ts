/**
 * Regenerates the OUI_VENDOR_MAP in src/services/macVendors.ts from IEEE's
 * published MA-L registry.
 *
 *   npx tsx scripts/gen-oui.ts
 *
 * Why the checked-in table is partial: IEEE's registry is the authoritative
 * source and is freely redistributable, but it is ~5 MB and this project has
 * no build-time network step. Rather than make every `npm install` depend on
 * a live fetch, the table ships hand-curated and this script exists to widen
 * it on demand. Run it whenever a capture shows raw MACs where a vendor name
 * is expected, then commit the regenerated file.
 *
 * Note on short names: IEEE publishes only the full legal organization name
 * ("GIGA-BYTE TECHNOLOGY CO.,LTD."). The <=12-character abbreviations used in
 * the column are derived here by stripping non-alphanumerics and truncating,
 * which is close to - but not always identical to - the curated abbreviation
 * other analyzers show. Entries already present in the checked-in table are
 * preserved, so hand-corrected names are never clobbered by a regeneration.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const IEEE_MAL_CSV = 'https://standards-oui.ieee.org/oui/oui.csv';
const MACVENDORS = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'services', 'macVendors.ts');

/** Strips punctuation and truncates, e.g. "Sagemcom Broadband SAS" -> "SagemcomBroa". */
function shortName(organization: string): string {
  return organization.replace(/[^A-Za-z0-9]/g, '').slice(0, 12);
}

/** Minimal RFC 4180 row splitter - IEEE quotes organization names containing commas. */
function parseCsvRow(line: string): string[] {
  const cells: string[] = [];
  let cell = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') { cell += '"'; i++; }
      else if (ch === '"') inQuotes = false;
      else cell += ch;
    } else if (ch === '"') inQuotes = true;
    else if (ch === ',') { cells.push(cell); cell = ''; }
    else cell += ch;
  }
  cells.push(cell);
  return cells;
}

async function main() {
  console.log(`fetching ${IEEE_MAL_CSV} ...`);
  const response = await fetch(IEEE_MAL_CSV);
  if (!response.ok) throw new Error(`IEEE registry returned ${response.status} ${response.statusText}`);
  const csv = await response.text();

  const source = readFileSync(MACVENDORS, 'utf8');
  const tableMatch = source.match(/const OUI_VENDOR_MAP: Record<string, string> = \{\n([\s\S]*?)\n\};/);
  if (!tableMatch) throw new Error('Could not locate OUI_VENDOR_MAP in macVendors.ts - has it been renamed?');

  // Existing hand-curated entries win over generated ones.
  const curated = new Map<string, string>();
  for (const entry of tableMatch[1].matchAll(/'([0-9A-F:]{8})':\s*'([^']+)'/g)) {
    curated.set(entry[1], entry[2]);
  }

  const rows = csv.split(/\r?\n/).slice(1).filter(Boolean);
  const generated = new Map<string, string>();
  for (const row of rows) {
    const [, assignment, organization] = parseCsvRow(row);
    if (!assignment || assignment.length !== 6 || !organization) continue;
    const oui = assignment.toUpperCase().match(/.{2}/g)!.join(':');
    generated.set(oui, shortName(organization));
  }

  const merged = [...new Map([...generated, ...curated])].sort(([a], [b]) => a.localeCompare(b));
  const body = merged.map(([oui, name]) => `  '${oui}': '${name.replace(/'/g, "\\'")}',`).join('\n');

  writeFileSync(MACVENDORS, source.replace(tableMatch[0], `const OUI_VENDOR_MAP: Record<string, string> = {\n${body}\n};`));
  console.log(`wrote ${merged.length} OUIs (${curated.size} hand-curated preserved) to ${MACVENDORS}`);
}

main().catch(err => {
  console.error(err.message ?? err);
  process.exit(1);
});
