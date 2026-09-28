/**
 * Every registered abbrev is a field the reference analyzer also has.
 *
 *   npx tsx scripts/dissect/wireshark-abbrevs.ts
 *
 * `fieldRegistry.ts` requires each field to carry "its Wireshark abbreviation",
 * and until now nothing checked that claim - `scripts/dissect/registry.ts`
 * verifies a field has a writer and a tree row, both of which are true of a
 * name that is simply wrong. So a typo'd abbrev shipped silently, and did:
 * `ptp.v2.an.stepsremoved` was registered for a field Wireshark calls
 * `ptp.v2.an.localstepsremoved`.
 *
 * That is worse than an ordinary typo. The abbrev is what a user types, and
 * the promise of the whole registry is that a filter learnt in Wireshark works
 * here. A name that exists in this build and nowhere else silently breaks that
 * promise in the direction nobody tests: the filter *works*, so there is no
 * error to notice - it is just spelled differently from every reference,
 * tutorial and saved filter in existence.
 *
 * `tshark -G fields` dumps the reference's entire dictionary, which makes this
 * a complete check rather than a sample. Fields Inwire publishes and Wireshark
 * has no equivalent for are exempt by prefix, and that list is deliberately
 * explicit: an exemption is a claim that no reference name exists, and it
 * should be as visible as the fields it covers.
 */
import { useRepositoryWiresharkProfile } from '../wiresharkProfile';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { FIELDS } from '../../src/services/dissect/fieldRegistry';

const TSHARK_CANDIDATES = [
  process.env.TSHARK,
  // On PATH. Absent from this list until now, which is why a Linux box with
  // tshark anywhere but the two absolute paths below printed SKIP here while
  // `synthetic.ts` - whose list has always had it - ran its whole suite. A
  // check that skips silently on a machine that could run it is worse than one
  // that is simply missing.
  'tshark',
  'C:/Program Files/Wireshark/tshark.exe',
  'C:/Program Files (x86)/Wireshark/tshark.exe',
  '/usr/bin/tshark',
  '/usr/local/bin/tshark',
  '/opt/homebrew/bin/tshark',
].filter((p): p is string => typeof p === 'string' && p.length > 0);

function findTshark(): string | null {
  useRepositoryWiresharkProfile();
  for (const candidate of TSHARK_CANDIDATES) {
    if (existsSync(candidate)) return candidate;
    try {
      execFileSync(candidate, ['-v'], { stdio: 'ignore' });
      return candidate;
    } catch { /* not here */ }
  }
  return null;
}

/**
 * Prefixes with no Wireshark counterpart, and why.
 *
 * A claim that the reference analyzer cannot answer the question at all - not
 * that its name is inconvenient.
 */
const NO_REFERENCE_EQUIVALENT: [string, string][] = [
  ['inwire.', 'facts from the captured machine, which no passive analyzer has '
    + '(process attribution, heuristic provenance, expert category)'],
];

/**
 * Individual fields Wireshark has no equivalent for, each with its reason.
 *
 * The bar is high and deliberately so: **an exemption is a claim that no
 * reference name exists**, and every one of these was checked against
 * `tshark -G fields` rather than assumed. When this check was first written it
 * failed on 40 fields, and 27 of those were not exemptions at all - they were
 * names this build had invented where Wireshark already had one
 * (`sip.method` for `sip.Method`, `radius.username` for `radius.User_Name`,
 * `rtcp.ssrc.sender` for `rtcp.senderssrc`, and so on). They were renamed. The
 * list below is what genuinely remained.
 *
 * Adding to it should feel like it needs an argument, because it does.
 */
const DERIVED: [string, string][] = [
  // Counts and flags this build computes. Wireshark shows the same information
  // by listing the items; there is no field to filter on.
  ['ospf.hello.neighbor_count', 'a count derived from the neighbour list'],
  ['rip.route_count', 'a count derived from the route entries'],
  ['tftp.data_length', 'the payload size; Wireshark has `tftp.data`, the bytes'],
  ['tftp.last_block', 'derived from the block size - TFTP has no end-of-transfer flag'],
  ['syslog.priority', 'the byte on the wire, which Wireshark only ever splits '
    + 'into `syslog.facility` and `syslog.level` (both of which are registered too)'],

  // Presence markers. Wireshark's `*_in` fields hold the frame number that
  // completed the reassembly, which is a different question from "was this
  // frame reassembled".
  ['ip.reassembled', 'presence of reassembly; `ip.reassembled_in` is a frame number'],
  ['ipv6.reassembled', 'presence of reassembly; `ipv6.reassembled.in` is a frame number'],
  ['tls.reassembled', 'presence of reassembly; `tls.reassembled_in` is a frame number'],

  // Fields where Wireshark models the same data differently rather than
  // naming it differently.
  ['snmp.value', 'one generic value; Wireshark splits by ASN.1 type '
    + '(`snmp.value.int`, `.octets`, `.oid`, ...)'],
  ['tcp.options.sack_perm', 'the option\'s presence; Wireshark has '
    + '`.present`/`.absent` as separate booleans'],
  ['tcp.options.nop', 'the option\'s presence; Wireshark registers this name as '
    + 'a sub-PROTOCOL rather than a field, so it is absent from `-G fields` '
    + 'while still being a name a user can type'],
  // The same argument as `tcp.options.nop` directly above, and checked the
  // same way: `tshark -G protocols` lists all four - "TCP Option - Maximum
  // segment size", "TCP Option - Window Scale", "TCP Option - SACK", "TCP
  // Option - End of Option List (EOL)" - so each is a name a user can type
  // and a name `-G fields` will never contain. They name the OPTION; the
  // numbers inside them (`tcp.options.mss_val`, `tcp.options.wscale.shift`,
  // `tcp.options.sack_le`) are ordinary fields and are not exempted.
  ['tcp.options.mss', 'the option itself; a sub-PROTOCOL in Wireshark, as `tcp.options.nop` is'],
  ['tcp.options.wscale', 'the option itself; a sub-PROTOCOL in Wireshark, as `tcp.options.nop` is'],
  ['tcp.options.sack', 'the option itself; a sub-PROTOCOL in Wireshark, as `tcp.options.nop` is'],
  ['tcp.options.eol', 'the option itself; a sub-PROTOCOL in Wireshark, as `tcp.options.nop` is'],
  ['tls.handshake.extensions_ech', 'the ECH extension\'s presence; Wireshark '
    + 'names only its inner parts'],
  ['tls.x509.subject_cn', 'read from the certificate inline; Wireshark reaches '
    + 'these through its own x509 dissector tree (`x509sat.*`)'],
  ['tls.x509.issuer_cn', 'as above'],
];

const tshark = findTshark();
if (tshark === null) {
  console.log('SKIP  tshark not found - set TSHARK to its path to run this check.');
  console.log('      (Tried: ' + TSHARK_CANDIDATES.join(', ') + ')');
  process.exit(0);
}
console.log(`Oracle: ${tshark}\n`);

// `-G fields` writes one tab-separated record per field; column 3 is the
// abbreviation, which is the only one this cares about.
const dump = execFileSync(tshark, ['-G', 'fields'], {
  encoding: 'utf8', maxBuffer: 256 * 1024 * 1024,
});
const reference = new Set<string>();
for (const line of dump.split('\n')) {
  const columns = line.split('\t');
  if (columns[0] !== 'F') continue;
  if (columns[2]) reference.add(columns[2]);
}
console.log(`The reference analyzer defines ${reference.size} fields.\n`);

const DERIVED_SET = new Map(DERIVED);

let failures = 0;
const exempt: string[] = [];
const missing: string[] = [];
for (const field of FIELDS) {
  const excuse = NO_REFERENCE_EQUIVALENT.find(([prefix]) => field.abbrev.startsWith(prefix));
  if (excuse || DERIVED_SET.has(field.abbrev)) { exempt.push(field.abbrev); continue; }
  if (!reference.has(field.abbrev)) missing.push(field.abbrev);
}

// An exemption for a field that IS in Wireshark's dictionary is stale - either
// the field was renamed or Wireshark gained a name for it. Either way the
// exemption is now a lie, and lying exemptions are how this list rots.
const stale = [...DERIVED_SET.keys()].filter((abbrev) => reference.has(abbrev));
if (stale.length > 0) {
  failures++;
  console.log('FAIL  exemption(s) claiming no reference name, for fields Wireshark has:');
  for (const abbrev of stale) console.log(`        ${abbrev}`);
}
// An exemption for a field nobody registers any more is dead weight.
const registered = new Set(FIELDS.map((f) => f.abbrev));
const orphaned = [...DERIVED_SET.keys()].filter((abbrev) => !registered.has(abbrev));
if (orphaned.length > 0) {
  failures++;
  console.log('FAIL  exemption(s) for fields that are no longer registered:');
  for (const abbrev of orphaned) console.log(`        ${abbrev}`);
}

if (missing.length === 0) {
  console.log(`PASS  all ${FIELDS.length - exempt.length} registered abbrevs exist in Wireshark`);
} else {
  failures++;
  console.log(`FAIL  ${missing.length} registered abbrev(s) are not Wireshark field names`);
  for (const abbrev of missing) {
    // A near miss is far more useful than the bare name: the bug is nearly
    // always a word missing or a separator differing, not an invented field.
    const stem = abbrev.split('.').slice(0, -1).join('.');
    const tail = abbrev.split('.').at(-1) ?? '';
    const near = [...reference].filter((r) => r.startsWith(stem + '.')
      && (r.includes(tail) || tail.includes(r.split('.').at(-1) ?? '\u0000')));
    console.log(`        ${abbrev}`);
    if (near.length > 0) console.log(`          did you mean: ${near.slice(0, 4).join(', ')}`);
  }
}

console.log(`\n${exempt.length} field(s) exempt as having no reference equivalent:`);
for (const [prefix, why] of NO_REFERENCE_EQUIVALENT) {
  console.log(`  ${prefix}*  - ${why}`);
}
for (const [abbrev, why] of DERIVED) {
  console.log(`  ${abbrev}  - ${why}`);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All Wireshark abbrev checks passed.');
process.exit(0);
