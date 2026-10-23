// PreToolUse hook for the Bash and PowerShell tools. It denies three slips:
//   - Windows-side Python (the Microsoft Store stub hangs the shell);
//   - `npm run check` / `npx tsx scripts/check.ts` held in the foreground;
//   - npm that writes node_modules where node_modules is a link. ensure-modules
//     junctions main's copy into worktrees, and npm ci there would empty it.
// Only the command word of each real segment is read, so text that merely
// mentions any of them (a commit message, a heredoc, a grep pattern) goes
// through. A `cd` or `Set-Location` segment moves where npm is taken to run.
// It fails open: any error, bad input or unbalanced quote lets the call run.
// Allow = exit 0 with no output; deny = exit 0 with one JSON object on stdout.
import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';

const LINK_REASON =
  "node_modules here is a junction to main's copy, so this npm command would rewrite main's packages. " +
  'Delete the junction first, (Get-Item -Force node_modules).Delete() in PowerShell, then run it.';

/** npm subcommands and aliases that write node_modules. */
const NPM_WRITES = new Set(['ci', 'install', 'i', 'in', 'add', 'isntall', 'uninstall', 'remove', 'rm', 'r', 'un',
  'unlink', 'update', 'up', 'upgrade', 'udpate', 'dedupe', 'ddp', 'prune', 'link', 'ln', 'rebuild', 'rb']);
const CD = new Set(['cd', 'pushd', 'chdir', 'set-location', 'sl', 'push-location']);

/** A shell path as Node reads it: Git Bash's /c/... is C:/... on Windows. */
function nativePath(p) {
  return process.platform === 'win32' ? p.replace(/^\/([A-Za-z])(?=\/|$)/, '$1:') : p;
}

function isLink(p) {
  try { return lstatSync(p).isSymbolicLink(); } catch { return false; }
}

/** The directory an npm segment that writes node_modules acts on; null for any other segment. */
function npmTarget(w, dir) {
  if (!/^npm(\.cmd)?$/i.test(w[0])) return null;
  let target = dir;
  let sub = null;
  for (let k = 1; k < w.length; k++) {
    const prefix = /^--prefix=(.+)$/.exec(w[k]);
    if (prefix) target = path.resolve(dir, nativePath(prefix[1]));
    else if ((w[k] === '--prefix' || w[k] === '-C') && w[k + 1]) target = path.resolve(dir, nativePath(w[++k]));
    else if (sub === null && !w[k].startsWith('-')) sub = w[k].toLowerCase();
  }
  return NPM_WRITES.has(sub) ? target : null;
}

const PYTHON_REASON =
  'Windows-side Python is blocked in Inwire (the Microsoft Store stub hangs the shell). ' +
  'Run it inside WSL instead: wsl -e python3 …';
const CHECK_REASON =
  'npm run check takes over 10 minutes. Run it with run_in_background: true ' +
  '(then wait for the notification), or with timeout: 600000 so it moves itself to the background.';

const HEREDOC = /(?<!<)<<(?!<)(-?)\s*(?:'([^'\n]+)'|"([^"\n]+)"|([A-Za-z_]\w*))/g;

/** Drops heredoc bodies (and their terminator) line by line; an unterminated marker is left alone. */
function stripHeredocs(text) {
  const lines = text.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    out.push(lines[i]);
    for (const m of lines[i].matchAll(HEREDOC)) {
      const word = m[2] ?? m[3] ?? m[4];
      let end = -1;
      for (let j = i + 1; j < lines.length; j++) {
        if ((m[1] ? lines[j].replace(/^\t+/, '') : lines[j]) === word) { end = j; break; }
      }
      if (end < 0) break;
      i = end;
    }
  }
  return out.join('\n');
}

/** Drops PowerShell here-strings: `@'` / `@"` ending a line, through a line starting `'@` / `"@`. */
function stripHereStrings(text) {
  const lines = text.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const open = /@['"]\s*$/.exec(lines[i]);
    if (open) {
      let end = -1;
      for (let j = i + 1; j < lines.length; j++) {
        if (/^['"]@/.test(lines[j])) { end = j; break; }
      }
      if (end >= 0) {
        out.push(lines[i].slice(0, open.index));
        i = end;
        continue;
      }
    }
    out.push(lines[i]);
  }
  return out.join('\n');
}

/** Splits on && || ; | and newline outside quotes. Throws on an unclosed quote. */
function segments(text) {
  const out = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      cur += c;
      if (quote === '"' && c === '\\' && text[i + 1] === '"') cur += text[++i];
      else if (c === quote) quote = null;
    } else if (c === "'" || c === '"') {
      quote = c;
      cur += c;
    } else if (c === '&' && text[i + 1] === '&' || c === '|' && text[i + 1] === '|') {
      out.push(cur); cur = ''; i++;
    } else if (c === ';' || c === '|' || c === '\n') {
      out.push(cur); cur = '';
    } else {
      cur += c;
    }
  }
  if (quote) throw new Error('unbalanced quotes');
  out.push(cur);
  return out;
}

/** Whitespace-separated words, keeping quoted runs together (quotes stay in the word). */
function words(segment) {
  const out = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i];
    if (quote) {
      cur += c;
      if (quote === '"' && c === '\\' && segment[i + 1] === '"') cur += segment[++i];
      else if (c === quote) quote = null;
    } else if (c === "'" || c === '"') {
      quote = c;
      cur += c;
    } else if (/\s/.test(c)) {
      if (cur) out.push(cur);
      cur = '';
    } else {
      cur += c;
    }
  }
  if (cur) out.push(cur);
  return out;
}

const unquote = (w) => w.replace(/["']/g, '');

/** Leading words of a segment with `VAR=value`, `&` and `(` prefixes removed and quotes stripped. */
function leading(segment) {
  const ws = words(segment);
  let i = 0;
  while (i < ws.length) {
    const w = ws[i].replace(/^[&(]+/, '');
    if (w === '' || /^[A-Za-z_]\w*=/.test(w)) { i++; continue; }
    break;
  }
  return ws.slice(i).map((w, k) => unquote(k === 0 ? w.replace(/^[&(]+/, '') : w));
}

function decide(input) {
  if (input.tool_name !== 'Bash' && input.tool_name !== 'PowerShell') return null;
  const ti = input.tool_input ?? {};
  if (typeof ti.command !== 'string') return null;
  const exempt = ti.run_in_background === true || Number(ti.timeout) >= 600000;
  const text = stripHereStrings(stripHeredocs(ti.command.replace(/\r\n/g, '\n')));
  let dir = input.cwd || process.cwd();
  for (const seg of segments(text)) {
    const w = leading(seg);
    if (!w.length) continue;
    const last = w[0].split(/[\\/]/).pop().toLowerCase();
    if (/^(python[\d.]*w?|py)(\.exe)?$/.test(last)) return PYTHON_REASON;
    if (CD.has(w[0].toLowerCase()) && w[1] && !w[1].startsWith('-')) dir = path.resolve(dir, nativePath(w[1]));
    const target = npmTarget(w, dir);
    if (target && isLink(path.join(target, 'node_modules'))) return LINK_REASON;
    if (exempt) continue;
    const npmCheck = w[0] === 'npm' && w[1] === 'run' && /^check(?:[<>&]|$)/.test(w[2] ?? '');
    const tsxCheck = w[0] === 'npx' && w[1] === 'tsx' && /scripts[\\/]check\.ts$/.test(w[2] ?? '');
    if (npmCheck || tsxCheck) return CHECK_REASON;
  }
  return null;
}

try {
  const reason = decide(JSON.parse(readFileSync(0, 'utf8')));
  if (reason) {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason },
    }));
  }
} catch {
  // fail open
}
