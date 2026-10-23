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
import { existsSync, readFileSync } from 'node:fs';

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

const mcp = readJson('.mcp.json');
check('.mcp.json holds exactly Microsoft Learn over HTTP', JSON.stringify(mcp?.mcpServers) === JSON.stringify({
  'microsoft-learn': { type: 'http', url: 'https://learn.microsoft.com/api/mcp' },
}), JSON.stringify(mcp?.mcpServers));

const ignored = readFileSync('.gitignore', 'utf8').split(/\r?\n/);
check('.gitignore keeps per-machine settings out', ignored.includes('.claude/settings.local.json'));
check('.gitignore keeps worktrees out', ignored.includes('.claude/worktrees/'));

/** A personal path or an email address in a public file. */
const PERSONAL = /[A-Z]:[\\/](Users|dev)[\\/]|Home Office|claude-setup|[\w.+-]+@[\w-]+\.[\w.]+/i;
const committed = ['.mcp.json', '.claude/settings.json', '.claude/README.md'];
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
