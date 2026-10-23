/**
 * The repo's Claude Code hooks decide what `.claude/README.md` says they do.
 *
 *   npx tsx scripts/claude/hooks.ts
 *
 * Each hook is a plain Node script that Claude Code runs with the tool call as
 * JSON on stdin. These rows run them the same way, as a child process, so what
 * is tested is the file Claude Code runs and not a function lifted out of it.
 *
 * `guard-shell.mjs` stops two mistakes that cost real time here: Windows-side
 * Python (the Store stub hangs the shell) and an `npm run check` held in the
 * foreground past the tool's limit. It reads only the command word of each
 * real segment, so text that merely mentions either - a commit message, a
 * heredoc, a grep pattern - goes through. A hook that cannot read its input
 * lets the call through: it is a guard against slips, not a security boundary.
 */
import { spawnSync } from 'node:child_process';
import path from 'node:path';

let failures = 0;
function check(name: string, pass: boolean, detail = ''): void {
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${pass || !detail ? '' : ` - ${detail}`}`);
  if (!pass) failures++;
}

const HOOKS = path.resolve('.claude/hooks');

/** Runs a hook the way Claude Code does; `input` is sent as JSON unless it is a string. */
function run(hook: string, input: unknown): { code: number; decision: string | null; reason: string; stdout: string } {
  const result = spawnSync(process.execPath, [path.join(HOOKS, hook)], {
    input: typeof input === 'string' ? input : JSON.stringify(input),
    encoding: 'utf8',
    timeout: 20_000,
  });
  const stdout = result.stdout ?? '';
  let decision: string | null = null;
  let reason = '';
  try {
    const out = JSON.parse(stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
    decision = out.hookSpecificOutput?.permissionDecision ?? null;
    reason = out.hookSpecificOutput?.permissionDecisionReason ?? '';
  } catch { /* no output is the allow case */ }
  return { code: result.status ?? -1, decision, reason, stdout };
}

type Shell = 'Bash' | 'PowerShell';
interface Row { command: string; shell?: Shell; timeout?: number; background?: boolean }

function shellCall({ command, shell = 'Bash', timeout, background }: Row) {
  return {
    hook_event_name: 'PreToolUse',
    tool_name: shell,
    tool_input: { command, ...(timeout === undefined ? {} : { timeout }), ...(background ? { run_in_background: true } : {}) },
  };
}

// ---- guard-shell: Windows-side Python ---------------------------------------

const PYTHON_DENY = [
  'python --version',
  'python3 -c "print(1)"',
  'python3.12 x.py',
  'pythonw x.pyw',
  'cd agent && python x.py',
  'py -3 x.py',
  'ls | python3 -',
  'C:/Python314/python.exe x.py',
  'C:\\Python314\\python.exe x.py',
  '& "C:\\Program Files\\Python314\\python.exe" x.py',
  'FOO=1 python x.py',
  'wsl -l && python x.py',
];
for (const shell of ['Bash', 'PowerShell'] as const) {
  for (const command of PYTHON_DENY) {
    const r = run('guard-shell.mjs', shellCall({ command, shell }));
    check(`guard-shell denies ${shell}: ${command}`, r.code === 0 && r.decision === 'deny' && /wsl/i.test(r.reason), r.stdout || `exit ${r.code}`);
  }
}

// ---- guard-shell: npm run check held in the foreground ----------------------

const CHECK_DENY: Row[] = [
  { command: 'npm run check' },
  { command: 'npm run check > a.log 2>&1; echo $?', timeout: 300_000 },
  { command: 'npx tsx scripts/check.ts' },
  { command: 'npx tsx scripts\\check.ts', shell: 'PowerShell' },
];
for (const row of CHECK_DENY) {
  const r = run('guard-shell.mjs', shellCall(row));
  check(`guard-shell denies a foreground check: ${row.command} (timeout ${row.timeout ?? 'default'})`,
    r.code === 0 && r.decision === 'deny' && /run_in_background/.test(r.reason), r.stdout || `exit ${r.code}`);
}

// ---- guard-shell: everything that only mentions them ------------------------

const ALLOW: Row[] = [
  { command: 'wsl -u root -- python3 -c 1' },
  { command: 'wsl -e bash -lc "python3 x.py; python3 y.py"' },
  { command: 'grep -n python file.md' },
  { command: 'echo "it\'s python"' },
  { command: 'git commit -m "python guard"' },
  { command: 'git commit -m "speed up npm run check"' },
  { command: 'grep "npm run check" CLAUDE.md' },
  { command: 'echo "see scripts/check.ts"' },
  { command: "cat > a.md <<'EOF'\npython foo\nnpm run check\nEOF" },
  { command: 'cat <<-EOF > a.md\n\tpython foo\n\tEOF' },
  { command: "cat << 'EOF' > a.md\npython foo\nEOF" },
  { command: "git commit -m \"$(cat <<'EOF'\npython fix\nEOF\n)\"" },
  { command: "git commit -m @'\npython fix\n'@", shell: 'PowerShell' },
  { command: 'npx tsx scripts/capture/reader.ts' },
  { command: 'npm run check', timeout: 600_000 },
  { command: 'npm run check', background: true },
  { command: 'npm run checkout' },
  { command: 'npm run check:x' },
];
for (const row of ALLOW) {
  const r = run('guard-shell.mjs', shellCall(row));
  check(`guard-shell allows ${row.shell ?? 'Bash'}: ${JSON.stringify(row.command)}${row.timeout ? ` (timeout ${row.timeout})` : ''}${row.background ? ' (background)' : ''}`,
    r.code === 0 && r.decision === null, r.stdout || `exit ${r.code}`);
}

// ---- guard-shell fails open --------------------------------------------------

const FAIL_OPEN: Array<[string, unknown]> = [
  ['empty stdin', ''],
  ['input that is not JSON', 'not json'],
  ['a tool it does not guard', { hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: 'python' } }],
  ['unbalanced quotes', shellCall({ command: 'echo "python' })],
];
for (const [name, input] of FAIL_OPEN) {
  const r = run('guard-shell.mjs', input);
  check(`guard-shell lets the call through on ${name}`, r.code === 0 && r.decision === null, r.stdout || `exit ${r.code}`);
}

if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('Claude Code hooks hold.');
process.exit(0);
