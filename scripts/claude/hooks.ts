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
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
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

// ---- ensure-modules: node_modules in new worktrees ---------------------------

// A real repository in a temp directory, because the hook asks git which
// worktrees exist. Main's node_modules holds a marker, so a link is seen to
// lead to main's copy, and removing a worktree is seen not to empty it.
{
  const root = realpathSync.native(mkdtempSync(path.join(tmpdir(), 'inwire-hooks-')));
  const main = path.join(root, 'main');
  const git = (cwd: string, ...args: string[]) => execFileSync('git', args, { cwd, stdio: 'pipe' });
  const inside = (name: string) => path.join(main, '.claude', 'worktrees', name);
  const outside = path.join(root, 'outside');
  const linked = (wt: string) => {
    try { return lstatSync(path.join(wt, 'node_modules')).isSymbolicLink() && existsSync(path.join(wt, 'node_modules', 'marker.txt')); } catch { return false; }
  };
  const worktrees: string[] = [];
  try {
    mkdirSync(main);
    git(main, 'init', '-q');
    writeFileSync(path.join(main, 'package-lock.json'), '{}\n');
    git(main, 'add', '.');
    git(main, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'init');
    mkdirSync(path.join(main, 'node_modules'));
    writeFileSync(path.join(main, 'node_modules', 'marker.txt'), 'main');
    for (const [wt, branch] of [[inside('wt'), 'wt'], [outside, 'outside']]) {
      git(main, 'worktree', 'add', '-q', '-b', branch, wt);
      worktrees.push(wt);
    }

    const added = run('ensure-modules.mjs', { hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'git worktree add .claude/worktrees/wt' }, cwd: main });
    check('ensure-modules links main\'s node_modules into a new worktree', added.code === 0 && linked(inside('wt')), added.stdout || `exit ${added.code}`);
    check('ensure-modules tells Claude what it linked', added.stdout.includes('Linked node_modules into:') && added.stdout.includes('"hookEventName":"PostToolUse"'), added.stdout);
    // The worktree's lockfile is the committed one, checked out with CRLF under autocrlf.
    check('ensure-modules does not warn about a lockfile that differs only in line endings', !added.stdout.includes('differs'), added.stdout);
    check('ensure-modules does not link a worktree outside .claude/worktrees', !existsSync(path.join(outside, 'node_modules')));

    const again = run('ensure-modules.mjs', { hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'git worktree add .claude/worktrees/wt' }, cwd: main });
    check('ensure-modules run twice changes nothing and says nothing', again.code === 0 && again.stdout === '' && linked(inside('wt')), again.stdout);

    for (const name of ['wt2', 'wt3']) {
      git(main, 'worktree', 'add', '-q', '-b', name, inside(name));
      worktrees.push(inside(name));
    }
    // npm ci empties node_modules' entries, and through a junction those are main's.
    writeFileSync(path.join(inside('wt3'), 'package-lock.json'), '{"changed":true}\n');
    const ls = run('ensure-modules.mjs', { hook_event_name: 'PostToolUse', tool_name: 'PowerShell', tool_input: { command: 'ls' }, cwd: main });
    check('ensure-modules ignores a shell command that adds no worktree', ls.code === 0 && ls.stdout === '' && !existsSync(path.join(inside('wt2'), 'node_modules')), ls.stdout);

    const subagent = run('ensure-modules.mjs', { hook_event_name: 'SubagentStart', cwd: main });
    check('ensure-modules links at SubagentStart, for isolation: worktree agents', subagent.code === 0 && linked(inside('wt2')), subagent.stdout || `exit ${subagent.code}`);
    check('ensure-modules never links a worktree whose lockfile differs from main\'s', !existsSync(path.join(inside('wt3'), 'node_modules')));
    check('ensure-modules says why it left that worktree alone', subagent.stdout.includes('not linked') && subagent.stdout.includes('package-lock.json differs'), subagent.stdout);
    check('ensure-modules tells Claude never to run npm through the junction', subagent.stdout.includes('rewrite main\'s packages'), subagent.stdout);
    check('ensure-modules still never links the outside worktree', !existsSync(path.join(outside, 'node_modules')));

    // guard-shell: npm that rewrites packages, aimed at a linked node_modules.
    const msys = (p: string) => p.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_, d: string) => `/${d.toLowerCase()}`);
    const NPM_DENY: Array<[string, Shell, string]> = [
      ['npm ci', 'Bash', inside('wt')],
      ['npm install', 'PowerShell', inside('wt')],
      ['npm i -D tsx', 'Bash', inside('wt')],
      ['npm uninstall tsx', 'Bash', inside('wt')],
      ['npm --prefix .claude/worktrees/wt ci', 'Bash', main],
      [`npm install --prefix="${inside('wt').replace(/\\/g, '/')}"`, 'Bash', main],
      ['cd .claude/worktrees/wt && npm ci', 'Bash', main],
      [`cd "${msys(inside('wt'))}" && npm install`, 'Bash', main],
      ['Set-Location .claude/worktrees/wt; npm ci', 'PowerShell', main],
    ];
    for (const [command, shell, cwd] of NPM_DENY) {
      const r = run('guard-shell.mjs', { ...shellCall({ command, shell }), cwd });
      check(`guard-shell denies ${shell} ${JSON.stringify(command)} through a node_modules link`, r.decision === 'deny' && r.reason.includes('rewrite main'), r.stdout || `exit ${r.code}`);
    }
    const NPM_ALLOW: Array<[string, string]> = [
      ['npm ci', main],
      ['npm run build', inside('wt')],
      ['npx tsx scripts/x.ts', inside('wt')],
      ['cd .claude/worktrees/wt3 && npm ci', main],
      ['cd .claude/worktrees/wt && cd ../../.. && npm ci', main],
    ];
    for (const [command, cwd] of NPM_ALLOW) {
      const r = run('guard-shell.mjs', { ...shellCall({ command }), cwd });
      check(`guard-shell allows ${JSON.stringify(command)} where node_modules is not a link`, r.code === 0 && r.decision === null, r.stdout || `exit ${r.code}`);
    }

    git(main, 'worktree', 'remove', '--force', inside('wt'));
    worktrees.splice(worktrees.indexOf(inside('wt')), 1);
    check('removing a linked worktree leaves main\'s node_modules alone', existsSync(path.join(main, 'node_modules', 'marker.txt')));

    for (const [name, input] of [['empty stdin', ''], ['input that is not JSON', 'not json'], ['a cwd that is not a repository', { hook_event_name: 'SubagentStart', cwd: root }]] as Array<[string, unknown]>) {
      const r = run('ensure-modules.mjs', input);
      check(`ensure-modules exits cleanly on ${name}`, r.code === 0 && r.stdout === '', r.stdout || `exit ${r.code}`);
    }
  } catch (error) {
    check('ensure-modules test repository', false, String(error));
  } finally {
    for (const wt of worktrees) {
      try { git(main, 'worktree', 'remove', '--force', wt); } catch { /* reported by the rows */ }
    }
    // A missing marker means a removal reached through a link: keep the evidence.
    if (existsSync(path.join(main, 'node_modules', 'marker.txt'))) rmSync(root, { recursive: true, force: true });
  }
}

if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('Claude Code hooks hold.');
process.exit(0);
