/**
 * Runs tshark, and every other Wireshark tool a script starts, under the
 * repository's own profile rather than the personal one.
 *
 * tshark reads the same preferences file as the Wireshark GUI, so the
 * reference the gates compare against was whatever the GUI on this machine was
 * last set to. One setting made that concrete: "Resolve network (IP)
 * addresses" turned on in the GUI made every tshark pass over a fixture send a
 * DNS PTR query per address in it, through the machine's resolver - the
 * untracked fixtures' personal contents, visible in the next live capture as a
 * burst of reverse lookups that looked like the app's own.
 *
 * `WIRESHARK_CONFIG_DIR` moves the personal configuration folder, and every
 * `spawnSync` inherits `process.env`, so setting it once in the process covers
 * every tool it starts. Called by each script's tshark finder, so a script
 * that can find tshark has already switched profiles.
 */
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const WIRESHARK_PROFILE = join(dirname(fileURLToPath(import.meta.url)), 'wireshark-profile');

export function useRepositoryWiresharkProfile(): void {
  process.env.WIRESHARK_CONFIG_DIR = WIRESHARK_PROFILE;
}
