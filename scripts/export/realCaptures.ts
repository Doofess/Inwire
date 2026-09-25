/**
 * The two real captures in `test/fixtures/`, dissected the way an import
 * dissects them, for export assertions that must be driven by real traffic
 * rather than frames a test author built to pass.
 *
 * Not a test itself - no `process.exit`, so `scripts/check.ts` does not run it.
 * Untracked by design (ADR 0004): a caller gets back only the fixtures that are
 * present and is expected to SKIP cleanly when that is none, the way
 * `parity/tree-coverage.ts` does, so `npm run check` stays runnable on CI.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PcapService } from '../../src/services/pcapParser';
import type { Packet } from '../../src/types/packet';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'test', 'fixtures');

export const REAL_CAPTURES: Record<string, string> = {
  inwire: 'inwire_capture_1788478187989.pcap',
  bulk: 'bulk_capture_1788426090876.pcap',
};

export interface RealCapture { name: string; path: string; packets: Packet[] }

/** Every fixture that is present, dissected in full. Prints a SKIP line for each one that is not. */
export async function loadRealCaptures(): Promise<RealCapture[]> {
  const found: RealCapture[] = [];
  for (const [name, file] of Object.entries(REAL_CAPTURES)) {
    const path = join(FIXTURES, file);
    if (!existsSync(path)) {
      console.log(`SKIP  ${name}: ${file} not present (test/fixtures/README.md)`);
      continue;
    }
    const { packets } = await PcapService.parseCaptureFile(
      new File([new Uint8Array(readFileSync(path))], file), Number.POSITIVE_INFINITY,
    );
    found.push({ name, path, packets });
  }
  return found;
}
