# local-agent/CLAUDE.md

Build and packaging mechanics for the Windows agent service. Loaded only when
working under `local-agent/`; the rules that must never be got wrong (the
three-place version lock, and `dist/`/`public/downloads/` being untracked)
stay in the root CLAUDE.md so they are always in context.

- `pyinstaller local-agent/netview_agent.spec` builds `local-agent/dist/netview-agent-windows.exe` — the service host, entry point `service_windows.py`, built with `console=False`. It accepts `install` / `remove` / `start` / `stop` / `debug`; `debug` requires the service to already be `install`ed first (pywin32's `debug` verb checks the SCM registry before running any agent code), so the practical loop is `install` once, then `debug` to run the service body in the foreground for iteration. Note `debug` is a **log-file** diagnostic, not a console one: the exe is built `console=False`, so `sys.stderr` is `None` and nothing appears on screen — watch `%ProgramData%\NetView\agent.log` instead. `debug` also only takes effect on the frozen exe; run from source, pywin32 spawns a separate `pythonservice.exe` process, so use `python local-agent/agent.py` for source-level iteration.
- `iscc local-agent/installer/setup.iss` (Inno Setup 6.3.0+ — `setup.iss` uses `ArchitecturesInstallIn64BitMode=x64compatible`, which older Inno Setup releases don't support) wraps that into `local-agent/installer/output/NetView-Agent-Setup.exe`, which downloads Npcap if missing, registers the `NetViewAgent` service as LocalSystem/auto-start, and seeds the config. Copy that installer into `public/downloads/` for the web app to serve.
- macOS and Linux keep the manual-launch bootstrap scripts (`bootstrap_macos.command`, `bootstrap_linux.sh`); the service model is Windows-only.
