// PostToolUse (Bash, PowerShell, EnterWorktree) and SubagentStart hook. A new
// worktree has no node_modules, so tsx, tsc and every npm script fail in it
// until `npm ci` runs there. This junctions main's node_modules into each
// worktree under <main>/.claude/worktrees/ that has none. A junction needs no
// privilege (Developer Mode is off), and `git worktree remove` unlinks it
// without entering it. Worktrees anywhere else are never touched.
// It fails open: any error or bad input exits 0 with no output.
import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync, realpathSync, symlinkSync } from 'node:fs';
import path from 'node:path';

/** A path for comparison: real, forward slashes, lower case (Windows paths ignore case). */
function key(p) {
  return realpathSync.native(p).replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
}

function hasEntry(p) {
  try { lstatSync(p); return true; } catch { return false; } // a dangling junction counts
}

/** A lockfile's text with LF endings: a checkout under autocrlf differs from main's only in CRs. */
function readLock(dir) {
  try { return readFileSync(path.join(dir, 'package-lock.json'), 'utf8').replace(/\r\n/g, '\n'); } catch { return null; }
}

/** `git worktree list --porcelain` as entries; the first is main. */
function worktrees(cwd) {
  const out = execFileSync('git', ['worktree', 'list', '--porcelain'], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  return out.split(/\r?\n\r?\n/).map((block) => {
    const lines = block.split(/\r?\n/);
    const head = lines.find((l) => l.startsWith('worktree '));
    return head ? { path: head.slice('worktree '.length), prunable: lines.some((l) => l.startsWith('prunable')) } : null;
  }).filter(Boolean);
}

function shouldRun(input) {
  if (input.hook_event_name === 'SubagentStart' || input.tool_name === 'EnterWorktree') return true;
  if (input.tool_name !== 'Bash' && input.tool_name !== 'PowerShell') return false;
  const command = input.tool_input?.command;
  return typeof command === 'string' && /\bworktree\s+add\b/.test(command);
}

function link(input) {
  const [main, ...others] = worktrees(input.cwd || process.cwd());
  if (!main) return [];
  const modules = path.join(main.path, 'node_modules');
  if (!existsSync(modules)) return [];
  const under = `${key(main.path)}/.claude/worktrees/`;
  const mainLock = readLock(main.path);
  const notes = [];
  for (const wt of others) {
    try {
      if (wt.prunable || !existsSync(wt.path) || !key(wt.path).startsWith(under)) continue;
      const target = path.join(wt.path, 'node_modules');
      if (hasEntry(target)) continue;
      symlinkSync(modules, target, 'junction');
      const differs = readLock(wt.path) !== mainLock;
      notes.push(differs
        ? `${wt.path} (its package-lock.json differs from main's; run npm ci there if its dependencies changed)`
        : wt.path);
    } catch {
      // one worktree failing leaves the others to be linked
    }
  }
  return notes;
}

try {
  const input = JSON.parse(readFileSync(0, 'utf8'));
  if (shouldRun(input)) {
    const notes = link(input);
    if (notes.length) {
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: input.hook_event_name ?? 'PostToolUse',
          additionalContext: `Linked node_modules into: ${notes.join('; ')}`,
        },
      }));
    }
  }
} catch {
  // fail open
}
