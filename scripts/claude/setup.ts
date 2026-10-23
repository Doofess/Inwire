/**
 * The repo's Claude Code setup is what `.claude/README.md` says it is.
 *
 *   npx tsx scripts/claude/setup.ts
 *
 * Everything here is project scope on purpose: the owner's rule is that this
 * repo's Claude Code setup changes nothing outside it. So the plugin and
 * connector switches live in the committed `.claude/settings.json` rather than
 * in user settings, and this file holds them to their values - a key that
 * silently drops out puts every connector's instructions back into every turn.
 *
 * The repo is public, so nothing committed under `.claude/` or in `.mcp.json`
 * may carry a personal path or an email address. It reads only tracked files
 * and the ones it names, so it passes the same on CI's clean clone.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

let failures = 0;
function check(name: string, pass: boolean, detail = ''): void {
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${pass || !detail ? '' : ` - ${detail}`}`);
  if (!pass) failures++;
}

function readJson(file: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

const settings = readJson('.claude/settings.json');
check('.claude/settings.json parses', settings !== null);

check('plugins unused here are off for this project only', JSON.stringify(settings?.enabledPlugins) === JSON.stringify({
  'playwright@anthropic-plugin-directory': false,
  'design@synced': false,
  'engineering@synced': false,
}), JSON.stringify(settings?.enabledPlugins));
check('claude.ai connectors are off for this project', settings?.disableClaudeAiConnectors === true);
check('the project MCP server is pre-approved', JSON.stringify(settings?.enabledMcpjsonServers) === '["microsoft-learn"]');

// Hook wiring: each hook runs from the project root's copy, and a command
// naming a script that is not there would fail on every tool call.
interface HookEntry { matcher?: string; hooks?: Array<{ type?: string; command?: string; if?: string; timeout?: number }> }
const hooks = (settings?.hooks ?? {}) as Record<string, HookEntry[]>;
const wired = (event: string, matcher: string | undefined, script: string, condition?: string) =>
  (hooks[event] ?? []).some((e) => e.matcher === matcher && (e.hooks ?? []).some((h) =>
    h.type === 'command' && h.command === `node "$CLAUDE_PROJECT_DIR/.claude/hooks/${script}"` && h.if === condition));
check('guard-shell runs before every Bash and PowerShell call', wired('PreToolUse', 'Bash|PowerShell', 'guard-shell.mjs'));
// The `if` only saves a node spawn per shell call; the script's own regex is the filter.
check('ensure-modules runs after a Bash worktree add', wired('PostToolUse', 'Bash', 'ensure-modules.mjs', 'Bash(*worktree add*)'));
check('ensure-modules runs after a PowerShell worktree add', wired('PostToolUse', 'PowerShell', 'ensure-modules.mjs', 'PowerShell(*worktree add*)'));
check('ensure-modules runs after EnterWorktree', wired('PostToolUse', 'EnterWorktree', 'ensure-modules.mjs'));
check('ensure-modules runs as each subagent starts', wired('SubagentStart', undefined, 'ensure-modules.mjs'));
const timeouts = Object.values(hooks).flat().flatMap((e) => e.hooks ?? []).filter((h) => h.command?.includes('ensure-modules.mjs')).map((h) => h.timeout);
check('ensure-modules has 30 seconds wherever it runs', timeouts.length === 4 && timeouts.every((t) => t === 30), JSON.stringify(timeouts));
for (const entry of Object.values(hooks).flat()) {
  for (const h of entry.hooks ?? []) {
    const script = h.command?.match(/\.claude\/hooks\/([\w.-]+\.mjs)/)?.[1];
    check(`hook command ${h.command} names a script that exists`, script !== undefined && existsSync(`.claude/hooks/${script}`));
  }
}

const mcp = readJson('.mcp.json');
check('.mcp.json holds exactly Microsoft Learn over HTTP', JSON.stringify(mcp?.mcpServers) === JSON.stringify({
  'microsoft-learn': { type: 'http', url: 'https://learn.microsoft.com/api/mcp' },
}), JSON.stringify(mcp?.mcpServers));

const ignored = readFileSync('.gitignore', 'utf8').split(/\r?\n/);
check('.gitignore keeps per-machine settings out', ignored.includes('.claude/settings.local.json'));
check('.gitignore keeps worktrees out', ignored.includes('.claude/worktrees/'));

/** The frontmatter of a Markdown file as flat `key: value` strings. */
function frontmatter(file: string): Record<string, string> {
  const m = readFileSync(file, 'utf8').match(/^---\r?\n([\s\S]*?)\r?\n---/);
  const fields: Record<string, string> = {};
  for (const line of m?.[1].split(/\r?\n/) ?? []) {
    const kv = line.match(/^([\w-]+):\s*(.*)$/);
    if (kv) fields[kv[1]] = kv[2].trim();
  }
  return fields;
}

// The repo's own worker replaces the user's for this repo: same model and
// effort, plus the command shapes that kept tripping the worktree guard.
const WORKER = '.claude/agents/worker.md';
if (existsSync(WORKER)) {
  const fm = frontmatter(WORKER);
  check('the worker keeps its name, model and effort', fm.name === 'worker' && fm.model === 'sonnet' && fm.effort === 'medium', JSON.stringify(fm));
  const body = readFileSync(WORKER, 'utf8');
  for (const rule of ['$VAR', 'sed -i', 'python', 'npx tsx scripts/', 'launchApp.ts', 'npm run check', 'start:app', 'test/']) {
    check(`the worker carries the rule naming ${rule}`, body.includes(rule));
  }
} else {
  check(`${WORKER} exists`, false);
}

/** Exact globs, never a walk of `.claude/`: its worktrees hold whole checkouts. */
function inDir(dir: string, pick: (name: string) => string | null): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .map((e) => pick(e.isDirectory() ? `${e.name}/` : e.name))
    .filter((f): f is string => f !== null && existsSync(path.join(dir, f)))
    .map((f) => `${dir}/${f}`);
}
const agentFiles = inDir('.claude/agents', (n) => (n.endsWith('.md') ? n : null));
const skillFiles = inDir('.claude/skills', (n) => (n.endsWith('/') ? `${n}SKILL.md` : null));
const hookFiles = inDir('.claude/hooks', (n) => (n.endsWith('.mjs') ? n : null));

// Skills: each is listed in full so Claude can pick it, and a `paths:` scope
// that matches no file would quietly never load it.
const tracked = execFileSync('git', ['ls-files'], { encoding: 'utf8' }).split('\n').filter(Boolean);
function globToRegExp(glob: string): RegExp {
  const body = glob.split('**').map((part) => part.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*')).join('.*');
  return new RegExp(`^${body}$`);
}
for (const skill of ['inwire-verify', 'inwire-launch', 'inwire-visual-design']) {
  check(`skill ${skill} exists`, skillFiles.includes(`.claude/skills/${skill}/SKILL.md`));
}
for (const file of skillFiles) {
  const fm = frontmatter(file);
  const folder = path.basename(path.dirname(file));
  check(`${folder}: frontmatter name matches its folder`, fm.name === folder, fm.name);
  const length = (fm.description ?? '').length;
  check(`${folder}: description is listed in full (50-1024 chars)`, length >= 50 && length <= 1024, `${length} chars`);
  if (fm.paths !== undefined) {
    let globs: string[] = [];
    try { globs = JSON.parse(fm.paths) as string[]; } catch { /* reported below */ }
    check(`${folder}: paths is a one-line list`, Array.isArray(globs) && globs.length > 0, fm.paths);
    for (const glob of globs) {
      const re = globToRegExp(glob);
      check(`${folder}: paths ${glob} matches a tracked file`, tracked.some((f) => re.test(f)));
    }
  }
}
if (skillFiles.includes('.claude/skills/inwire-visual-design/SKILL.md')) {
  check('inwire-visual-design is scoped to the files it governs', frontmatter('.claude/skills/inwire-visual-design/SKILL.md').paths !== undefined);
}
// Per machine and gitignored, so absent on CI: checked only where it exists.
const local = readJson('.claude/settings.local.json');
if (local) check('no local override hides a project skill', !('skillOverrides' in local));

// tsc never sees `.claude/`, so a syntax error in a hook would only show as a
// hook that silently allows everything.
for (const hook of hookFiles) {
  const result = spawnSync(process.execPath, ['--check', hook], { encoding: 'utf8' });
  check(`${hook} parses`, result.status === 0, result.stderr.split('\n')[0]);
}

/** A personal path or an email address in a public file. */
const PERSONAL = /[A-Z]:[\\/](Users|dev)[\\/]|Home Office|claude-setup|[\w.+-]+@[\w-]+\.[\w.]+/i;
const committed = ['.mcp.json', '.claude/settings.json', '.claude/README.md', ...agentFiles, ...skillFiles, ...hookFiles];
for (const file of committed.filter((f) => existsSync(f))) {
  const hit = readFileSync(file, 'utf8').match(PERSONAL);
  check(`${file} carries nothing personal`, hit === null, hit?.[0]);
}

if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('Claude Code project setup holds.');
process.exit(0);
