/**
 * The packed executable has Node's own entry points shut off.
 *
 *   npx tsx scripts/electron/fuses.ts
 *
 * ## What a fuse is, and what it was worth here
 *
 * A byte in the Electron binary that turns a capability off permanently.
 * Until `electron/afterPack.cjs` started flipping them, this was true of the
 * packed app, and it is quoted from the build that shipped it rather than
 * described:
 *
 *     ELECTRON_RUN_AS_NODE=1 Inwire.exe -e "console.log(process.version)"
 *     v24.20.0
 *
 * Arbitrary JavaScript, executing as the user, out of the application's own
 * executable. **Signing does not help**: the file is unmodified, so every
 * signature check passes - the capability belongs to the binary, which is why
 * the root `CLAUDE.md` records that the fuses must land *before* signing
 * rather than alongside it.
 *
 * ## Why this reads the wire instead of running the exploit
 *
 * Running it is the better evidence and the worse test. With `RunAsNode` off,
 * `Inwire.exe -e "..."` does not refuse - it stops treating the arguments as
 * Node's and **launches the application**, so a suite that checked this by
 * execution would open a window on every `npm run check`, and would have to
 * find and kill it again. `getCurrentFuseWire` answers the same question from
 * the bytes.
 *
 * The exploit is still the right thing to run by hand after changing this,
 * and `docs/verification.md` is where that belongs.
 *
 * ## Why it SKIPs when nothing is packed
 *
 * `npm run check` does not pack, and CI on ubuntu never will. A missing
 * artifact has not failed anything; a packed one with a fuse open has, which
 * is the distinction `agent/built-version.ts` draws beside it.
 */
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getCurrentFuseWire, FuseVersion, FuseV1Options } from '@electron/fuses';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PACKED = join(root, 'release', 'win-unpacked', 'Inwire.exe');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

/**
 * What each fuse must read, and what it costs to leave open.
 *
 * The reason is in the table rather than in a comment above it, because a
 * future session weakening one should have to delete the sentence saying what
 * that buys an attacker.
 */
const REQUIRED: { fuse: FuseV1Options; name: string; want: boolean; why: string }[] = [
  {
    fuse: FuseV1Options.RunAsNode, name: 'RunAsNode', want: false,
    why: 'ELECTRON_RUN_AS_NODE=1 turns the signed app into a Node interpreter',
  },
  {
    fuse: FuseV1Options.EnableNodeCliInspectArguments, name: 'EnableNodeCliInspectArguments', want: false,
    why: '--inspect opens a debugger port into the main process',
  },
  {
    fuse: FuseV1Options.EnableNodeOptionsEnvironmentVariable, name: 'EnableNodeOptionsEnvironmentVariable', want: false,
    why: 'NODE_OPTIONS=--require injects a module without touching the app',
  },
  {
    fuse: FuseV1Options.OnlyLoadAppFromAsar, name: 'OnlyLoadAppFromAsar', want: true,
    why: 'without it, a directory dropped beside the exe replaces the application',
  },
];

async function main(): Promise<void> {
  if (!existsSync(PACKED)) {
    console.log('SKIP  nothing packed - `npm run pack` produces what this reads.');
    return;
  }

  const wire = await getCurrentFuseWire(PACKED);
  check('the packed binary carries a v1 fuse wire', wire.version, FuseVersion.V1);

  for (const { fuse, name, want, why } of REQUIRED) {
    const raw = (wire as unknown as Record<number, number | undefined>)[fuse];
    // **The wire holds ASCII digits, not booleans and not 0/1.** A set fuse
    // reads 49 and a cleared one reads 48 - `'1'` and `'0'` as character
    // codes - so `Boolean(raw)` is true for BOTH, and the first version of
    // this check failed all three `want: false` rows against a binary whose
    // fuses were correctly off. It was wrong in the safe direction by luck
    // rather than design: the same coercion would have passed a `want: true`
    // row against a cleared fuse, which is the direction that matters.
    check(`${name} is present in the wire`, raw !== undefined, true);
    if (raw === undefined) continue;
    check(`${name} is ${want} (${why})`, String.fromCharCode(raw) === '1', want);
  }

  console.log();
  if (failures > 0) {
    console.log(`${failures} check(s) FAILED - repack; `
      + '`electron/afterPack.cjs` is what flips these.');
    process.exit(1);
  }
  console.log('Every required fuse is set on the packed binary.');
}

await main();
process.exit(0);
