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
import { useRepositoryWiresharkProfile } from '../wiresharkProfile';
import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PcapService } from '../../src/services/pcapParser';
import type { Packet } from '../../src/types/packet';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'test', 'fixtures');

export const REAL_CAPTURES: Record<string, string> = {
  inwire: 'inwire_capture_1788478187989.pcap',
  bulk: 'bulk_capture_1788426090876.pcap',
};

/**
 * Real captures a caller asks for by name, for what the two general ones do
 * not contain. Not in `REAL_CAPTURES`, because every script that loads those
 * asserts things only a general capture has (a DNS query on both sides of the
 * disk seam, say), and a 66-frame capture of traceroutes has none of them.
 *
 *   - `icmpErrors`: taken on this machine's Ethernet adapter with dumpcap
 *     (`-f "icmp or icmp6 or igmp"`) during `tracert` to 1.1.1.1 and
 *     2606:4700:4700::1111 - ICMPv4 and ICMPv6 Time Exceeded, each quoting
 *     the echo that expired, plus Neighbor Discovery and a Router
 *     Advertisement. Neither general capture holds a single ICMP error.
 *   - `keyLog`: 75 seconds of this machine's Ethernet adapter while a
 *     throwaway headless Chrome profile browsed eight sites with
 *     `SSLKEYLOGFILE` set - TLS 1.3, HTTP/2 and QUIC/HTTP/3 - with the key log
 *     beside it under the same name, `.keys`. The only capture here that
 *     decrypts; the other processes' TLS in it does not, which is realistic.
 */
export const OPTIONAL_CAPTURES: Record<string, string> = {
  icmpErrors: 'icmp_errors_capture_1790359378632.pcapng',
  keyLog: 'keylog_capture_1790455330535.pcapng',
};

export interface RealCapture { name: string; path: string; packets: Packet[] }

/**
 * Every fixture that is present, dissected in full. Prints a SKIP line for each
 * one that is not. `optional` names entries of `OPTIONAL_CAPTURES` to load too.
 */
export async function loadRealCaptures(optional: readonly string[] = []): Promise<RealCapture[]> {
  const found: RealCapture[] = [];
  const wanted: [string, string][] = [
    ...Object.entries(REAL_CAPTURES),
    ...optional.map((name): [string, string] => [name, OPTIONAL_CAPTURES[name]]),
  ];
  for (const [name, file] of wanted) {
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

/**
 * A Wireshark command-line tool - `tshark`, `capinfos`, `editcap` - or null.
 *
 * The same search `parity/tree-coverage.ts` makes for tshark: `TSHARK`'s
 * directory when set, the bare name on PATH, then the install paths. A caller
 * that gets null prints SKIP for the cross-check and runs the rest.
 */
export function findWiresharkTool(tool: 'tshark' | 'capinfos' | 'editcap' | 'mergecap'): string | null {
  useRepositoryWiresharkProfile();
  const exe = process.platform === 'win32' ? `${tool}.exe` : tool;
  const candidates = [
    process.env.TSHARK ? join(dirname(process.env.TSHARK), exe) : undefined,
    tool,
    `C:\\Program Files\\Wireshark\\${exe}`,
    `C:\\Program Files (x86)\\Wireshark\\${exe}`,
    `/usr/bin/${tool}`,
    `/usr/local/bin/${tool}`,
    `/opt/homebrew/bin/${tool}`,
  ].filter((p): p is string => typeof p === 'string' && p.length > 0);
  for (const candidate of candidates) {
    const probe = spawnSync(candidate, ['-v'], { encoding: 'utf8', shell: false });
    if (probe.status === 0) return candidate;
  }
  return null;
}

/** Runs a Wireshark tool and returns its stdout; throws with its stderr on failure. */
export function runTool(tool: string, args: string[]): string {
  const result = spawnSync(tool, args, { encoding: 'utf8', shell: false, maxBuffer: 512 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(`${tool} ${args.join(' ')} exited ${result.status}: ${result.stderr}`);
  return result.stdout;
}
