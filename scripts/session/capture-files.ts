/**
 * The capture's own pcapng files as the app records them (ADR 0052).
 *
 *   npx tsx scripts/session/capture-files.ts
 *
 * The agent writes each capture's files and reports every one it opens,
 * closes and - in a ring - deletes. `services/captureFiles.ts` folds those
 * reports into one entry per file; these are its rules, held to the reports
 * the Rust agent actually emits (`scripts/agent/control-vectors.json`, which
 * `agent-rs`'s own example generates) rather than to hand-written ones.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseAgentMessage, type AgentCaptureFileMessage } from '../../src/services/agentProtocol';
import { applyCaptureFile, keptFiles, stopReasonText, type CaptureFile } from '../../src/services/captureFiles';

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

// The agent's own reports, as the app parses them.
const vectors = JSON.parse(readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'agent', 'control-vectors.json'), 'utf8',
)) as { cases: { message: unknown }[] };
const reports = vectors.cases
  .map((c) => parseAgentMessage(JSON.stringify(c.message)))
  .filter((m): m is AgentCaptureFileMessage => m !== null && m.type === 'capture_file');
check('the agent emits a report for each of open, closed and deleted',
  reports.map((r) => r.state).sort(), ['closed', 'deleted', 'open']);

const report = (index: number, state: AgentCaptureFileMessage['state'], first: number | null, last: number | null):
  AgentCaptureFileMessage => ({
  type: 'capture_file', index, name: `capture_${String(index).padStart(5, '0')}_20260928120000.pcapng`,
  state, firstSeq: first, lastSeq: last, frames: first === null || last === null ? 0 : last - first + 1, bytes: 0,
});

console.log('\n--- one entry per file, the latest report winning ---\n');

let files: CaptureFile[] = [];
files = applyCaptureFile(files, report(1, 'open', null, null));
files = applyCaptureFile(files, report(1, 'closed', 0, 999));
files = applyCaptureFile(files, report(2, 'open', null, null));
check('a file opened then closed is one entry, closed',
  files.map((f) => [f.index, f.state, f.firstSeq, f.lastSeq]), [[1, 'closed', 0, 999], [2, 'open', null, null]]);

files = applyCaptureFile(files, report(1, 'deleted', 0, 999));
check('a ring deleting its oldest file marks it rather than forgetting it',
  files.map((f) => [f.index, f.state]), [[1, 'deleted'], [2, 'open']]);
check('...and the files kept are the ones on disk', keptFiles(files).map((f) => f.index), [2]);

files = applyCaptureFile(files, report(1, 'closed', 0, 999));
check('a late report cannot bring a deleted file back', files.find((f) => f.index === 1)?.state, 'deleted');

const shuffled = [report(3, 'open', null, null), report(1, 'open', null, null), report(2, 'open', null, null)]
  .reduce<CaptureFile[]>(applyCaptureFile, []);
check('entries are kept in file order, however they arrive', shuffled.map((f) => f.index), [1, 2, 3]);

console.log('\n--- why a capture stopped itself ---\n');

check('each reason reads as the end of a sentence',
  (['packets', 'bytes', 'seconds', 'files'] as const).map(stopReasonText),
  ['it reached its packet limit', 'it reached its size limit', 'it reached its time limit', 'it reached its file limit']);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All capture-file checks passed.');
process.exit(0);
