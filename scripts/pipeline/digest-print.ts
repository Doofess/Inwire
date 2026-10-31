/**
 * One hash per capture, so two builds can be compared by eye or by diff.
 *
 *   npx tsx scripts/pipeline/digest-print.ts
 *
 * Prints `<name> <frames> <sha256 of the per-frame digests joined by \n>` for
 * every fixture that is present, then the synthetic `quic`, `eviction` (the
 * TCP order's 20,000 connections) and `fragments` captures. A measurement, not
 * an assertion: it asserts nothing and never exits non-zero for a difference.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FIXTURES } from './arrival';
import { digestCapture } from './frameDigest';
import { evictionCapture } from './evictionCapture';
import { fragmentCapture } from './fragmentCapture';
import { quicCapture } from './quicCapture';

function print(name: string, digests: string[]): void {
  console.log(`${name} ${digests.length} ${createHash('sha256').update(digests.join('\n')).digest('hex')}`);
}

async function main(): Promise<void> {
  for (const fixture of FIXTURES) {
    if (!existsSync(fixture.path)) continue;
    print(fixture.name, await digestCapture(fixture.path));
  }
  const dir = mkdtempSync(join(tmpdir(), 'inwire-digest-'));
  try {
    const synthetic: [string, Uint8Array][] = [
      ['quic', quicCapture()], ['eviction', evictionCapture()], ['fragments', fragmentCapture()],
    ];
    for (const [name, bytes] of synthetic) {
      const path = join(dir, `${name}.pcap`);
      writeFileSync(path, bytes);
      print(name, await digestCapture(path));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error); throw error; });
