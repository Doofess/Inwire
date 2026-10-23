# Claude Code in this repo

Everything here is **project scope**. It shapes Claude Code sessions in Inwire
and nothing else, and it is committed so every machine gets the same setup.
Per-machine choices go in settings.local.json beside it, which is gitignored.

## What is here

| File | What it does |
|---|---|
| `.claude/settings.json` | Turns off, for this repo only, the claude.ai connectors and the plugins sessions here never used (Playwright's browser MCP and the synced design and engineering skills). Pre-approves the project MCP server and wires the hooks |
| `.mcp.json` | One MCP server, Microsoft Learn (HTTP, no login), for Win32, named-pipe, service, ACL and signing documentation. Only search text leaves the machine. Never paste capture data into a query |
| `.claude/hooks/guard-shell.mjs` | Before every Bash and PowerShell call: blocks Windows-side Python (the Store stub hangs the shell; WSL is fine), an `npm run check` held in the foreground without `run_in_background` or a 600000 ms timeout, and npm that writes `node_modules` where `node_modules` is a link |
| `.claude/hooks/ensure-modules.mjs` | After a shell `worktree add`, after EnterWorktree, and as each subagent starts: junctions main's `node_modules` into every worktree under the repo's worktree folder that has none, so `tsx` and `tsc` work there at once. A worktree whose lockfile differs from main's is left for its own `npm ci`, because npm run through the junction would empty and rewrite main's copy. Removing the worktree unlinks the junction and leaves main's copy alone |
| `.claude/agents/worker.md` | This repo's `worker` subagent. It replaces the user-level worker here and adds the repo's command shapes and verification rules |
| `.claude/skills/inwire-verify/SKILL.md` | Picks checks from the changed paths, then runs the full gate in the background and quotes the output |
| `.claude/skills/inwire-launch/SKILL.md` | Launches the real app in the background with a throwaway profile, then screenshots every state in both themes |
| `.claude/skills/inwire-visual-design/SKILL.md` | Typography, themes and the brand mark. Loads when UI files are touched |

## Rules for changing it

- **Change files here, never user scope.** Plugin switches go in
  `enabledPlugins` in `.claude/settings.json`. Never run
  `claude plugin enable` or `claude plugin disable` without `--scope`, nor
  `claude plugin marketplace add`, `claude mcp add`, the `/mcp` toggle or
  the claude.ai sync switches. Each of those writes to user scope and would
  change every other project.
- **This repo is public.** No personal paths, user names or email addresses
  in anything committed here. `scripts/claude/setup.ts` fails on them.
- **Hooks are plain Node with no dependencies, and they fail open.** A hook
  that cannot read its input allows the call. They are a guard against
  slips, not a security boundary: native Windows has no sandbox.
- **The worker is a copy.** Edits to the user-level worker do not reach this
  repo. Copy them across by hand when they matter here.

## Testing it

- `npx tsx scripts/claude/setup.ts` checks the settings values, the hook
  wiring, the skills' frontmatter and `paths:` globs, and the privacy rule.
- `npx tsx scripts/claude/hooks.ts` runs each hook as a child process
  against every allow and deny row.
- Both scripts run in `npm run check`, and so on CI. A settings change takes
  effect in the next session, so try it with `claude -p` from the repo root.
