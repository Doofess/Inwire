/**
 * A tree rebuilt from its record stays what arrival would show (ADR 0072).
 *
 * Since shards keep no tree, every shard frame's tree is rebuilt from its
 * record and kept in the Worker's small cache of rebuilt trees. Two things the
 * shard's own cache used to give it must survive that:
 *
 * - links a LATER frame writes into it (`tcp.reassembled_in`, a response's
 *   frame) - a kept tree a link has since landed on is dropped, and so is one
 *   whose rebuild was under way when the link landed, so the next click
 *   rebuilds from a store that has the link;
 * - the "Matches process" row a JA4 match puts on the Frame layer, which the
 *   stored row carries as `inwire.process.ja4_match`.
 *
 *   npx tsx scripts/pipeline/rebuilt-trees.ts
 */
import { readFileSync } from 'node:fs';
import { RebuiltTrees } from '../../src/services/pipeline/rebuiltTrees';
import { addMatchRow, ClientFingerprintStore } from '../../src/services/dissect/clientFingerprints';
import type { ProtocolLayer } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}
const tree = (): ProtocolLayer[] => [{ name: 'Frame', summary: '', fields: [] }];

// --- the cache of rebuilt trees -------------------------------------------------
{
  const trees = new RebuiltTrees(3);
  const a = tree();
  trees.begin(10);
  trees.keep(10, a);
  check('a rebuilt tree is kept for the next click', trees.get(10) === a);
  trees.patched(10);
  check('...and dropped once a later frame links into it', trees.get(10) === undefined);

  trees.begin(11);
  trees.patched(11); // the link lands while the store is answering
  trees.keep(11, tree());
  check('a rebuild a link landed during is not kept', trees.get(11) === undefined);
  trees.begin(11);
  const b = tree();
  trees.keep(11, b);
  check('...and the next rebuild, after the link, is', trees.get(11) === b);

  trees.patched(99);
  trees.begin(12);
  trees.keep(12, tree());
  check('a link into a frame nobody rebuilt marks nothing', trees.get(12) !== undefined);

  trees.begin(13);
  trees.keep(13, null);
  trees.begin(13);
  const c = tree();
  trees.keep(13, c);
  check('a failed rebuild leaves no mark on the next one', trees.get(13) === c);

  for (const id of [20, 21, 22, 23]) { trees.begin(id); trees.keep(id, tree()); }
  check('it keeps only the newest few', trees.get(20) === undefined && trees.get(23) !== undefined);
  trees.clear();
  check('...and clears', trees.get(23) === undefined);

  // A key-log clear while a rebuild waits on the store: its tree read the old
  // keys, and keeping it would show plaintext the panel said was gone.
  trees.begin(30);
  trees.clear();
  trees.keep(30, tree());
  check('a rebuild under way when the cache is cleared is not kept', trees.get(30) === undefined);
}

// --- the fingerprint row -------------------------------------------------------------
{
  const store = new ClientFingerprintStore();
  store.learn('t13d_fp', 'chrome.exe');
  store.learn('t13d_fp', 'chrome.exe');
  const layers = tree();
  addMatchRow(layers, { 'tls.handshake.ja4': 't13d_fp', 'inwire.process.ja4_match': 'chrome.exe' }, store);
  const row = layers[0].fields[0];
  check('a rebuilt tree gets the row a JA4 match put on its Frame layer',
    row?.name === 'Matches process' && row.value === 'chrome.exe' && row.abbrev === 'inwire.process.ja4_match',
    JSON.stringify(row));
  check('...with its basis, from what the store has seen',
    /chrome\.exe/.test(String(row?.children?.[0]?.value)) && /2 attributed frames/.test(String(row?.children?.[0]?.value)),
    String(row?.children?.[0]?.value));

  store.learn('t13d_fp', 'edge.exe'); // now ambiguous: the arrival-time match still stands, without a count
  const later = tree();
  addMatchRow(later, { 'tls.handshake.ja4': 't13d_fp', 'inwire.process.ja4_match': 'chrome.exe' }, store);
  const basis = String(later[0].fields[0]?.children?.[0]?.value);
  check('a match the store no longer holds keeps the arrival name, and claims no count',
    later[0].fields[0]?.value === 'chrome.exe' && !/attributed frame/.test(basis), basis);

  const none = tree();
  addMatchRow(none, { 'tls.handshake.ja4': 't13d_fp' }, store);
  check('a row with no match gets no row', none[0].fields.length === 0);
}

// --- the Worker uses both -------------------------------------------------------------
{
  const worker = readFileSync('src/workers/pipeline.worker.ts', 'utf8');
  const patchedCalls = worker.match(/rebuiltTrees\.patched\(/g)?.length ?? 0;
  check('both of the Worker\'s link-patch loops drop a rebuilt tree', patchedCalls >= 2, `${patchedCalls} call(s)`);
  check('the Worker brackets its rebuild with begin and keep',
    /rebuiltTrees\.begin\(/.test(worker) && /rebuiltTrees\.keep\(/.test(worker));
  check('the Worker\'s rebuild adds the fingerprint row', /addMatchRow\(/.test(worker));
  check('...and keeps no rebuilt-tree map of its own', !/revisitedTrees/.test(worker));
}

console.log(failures === 0 ? '\nAll rebuilt-trees checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
