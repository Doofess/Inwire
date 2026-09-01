# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

NetView (internally referred to in some strings as "WirePulse") is a browser-based network packet analyzer with a desktop-analyzer-style UI, built with React + Vite. It has no backend of its own for capture: live packets come from a separate local Python agent (`local-agent/agent.py`) that the user downloads and runs with elevated privileges, which streams captured packets over a local WebSocket (`ws://localhost:8999`) to the web app running in the browser. Everything else — protocol dissection, filtering, dissector rules, color rules, anomaly detection, PCAP export/import — happens client-side in TypeScript.

## Commands

- `npm run lint` — type-check only (`tsc --noEmit`); there is no separate lint tool configured
- `npm run start` — run the built app behind the Express server (`server.ts`) via `tsx`; expects `npm run build` to have produced `dist/` first
- There is no test suite/runner configured in this repo.

### Local capture agent (`local-agent/`)

This is a separate Python project, not built by the npm scripts:
- `pip install -r local-agent/requirements.txt` (scapy, websockets, psutil, pyinstaller, pywin32 on Windows)
- `python local-agent/agent.py` (run as Administrator/root — raw packet capture requires elevation on every OS). On Windows this development path needs Npcap installed already; the installer normally handles that, so install it from https://npcap.com/#download if you haven't run the installer.
- The agent speaks a typed WebSocket protocol (`hello`/`state`/`error`/`log`/`packet`/`interface_stats` from the agent; `start_capture`/`stop_capture`/`set_interfaces`/`subscribe_logs`/`unsubscribe_logs`/`subscribe_interface_stats`/`unsubscribe_interface_stats` to it) and starts **idle** — it only sniffs once a client sends `start_capture`, and stops again when the last client disconnects.
- `subscribe_logs` streams the agent's own log to that one client: a backlog of up to 200 lines read from the tail of `agent.log`, then each new line live via a `logging.Handler` on the `netview` logger (`local-agent/agent_log.py`). Nothing is sent to clients that have not subscribed, and the subscription dies with the socket. The web app surfaces this in Settings → Driver Info.
- Browsers are authenticated by **origin**, not a token: a connection whose `Origin` header isn't listed in `%ProgramData%\NetView\config.json` is rejected with a 403 during the handshake. Defaults cover localhost:3000 and localhost:4173. The file is re-read per connection, so adding an origin needs no restart.
- Logs go to `%ProgramData%\NetView\agent.log` (rotating). When the agent runs as a service there is no console, so this is the only place to look.
- Any change to the agent's wire protocol or behavior must bump the version, which appears in three places that must move together: `AGENT_VERSION` in `local-agent/agent.py`, `REQUIRED_AGENT_VERSION` in `src/services/agentProtocol.ts`, and `MyAppVersion` in `local-agent/installer/setup.iss`. `python local-agent/test_protocol.py` enforces that all three agree and are a valid `MAJOR.MINOR.PATCH`.

**Windows distribution** — the agent ships as a Windows service, installed once and thereafter invisible (no console, no tray icon, no UAC prompt). The PyInstaller/Inno Setup build steps live in `local-agent/CLAUDE.md`, which loads when working in that directory.
- Neither `local-agent/dist/` nor `public/downloads/` is tracked in git (rebuild rather than editing binaries).

## Architecture

### Data flow
`local-agent/agent.py` (Scapy sniff → JSON over WebSocket, idle until told to start) → `App.tsx`'s always-on WebSocket client (auto-reconnects every 3s, tracks `agentStatus` independent of whether capture is active) → when a raw base64 frame is present, `services/pcapParser.ts` (`decodeRawEthernetPacket`) dissects it into a `Packet` the same way an imported `.pcap` file would be; when the agent sends metadata-only (no raw bytes), a minimal fallback `Packet` is built without fabricating payload data. The packet buffer is capped at `PACKET_BUFFER_CAP` (50000) entries, oldest dropped first, and capture auto-pauses at 99% of it.

Imported PCAP files go through the same `pcapParser.ts` path via `ExportImportModal`, so live capture and file import produce identical `Packet` shapes.

### Core domain types
`src/types/packet.ts` is the single source of truth for the domain model — every dissection, filter, and color rule is typed against it.

### Services (`src/services/`) — all pure client-side engines, no backend calls except geo/DNS lookups
- `rbacService.ts` — defines `ROLE_PERMISSIONS` for four roles (ADMIN/SOC_ANALYST/NETWORK_ENGINEER/AUDITOR_GUEST); currently `App.tsx` hardcodes the ADMIN permission set (`// RBAC Role (Simplified: Always Admin)`) rather than wiring up real auth — role-gating in components still reads from `permissions` props, so restoring per-user roles is a matter of feeding a real role into that object

### Theming
Theming is **four themes**, not a light/dark pair: `light` (Day), `paper`, `dark` (Graphite) and `midnight`, declared once in `src/lib/themeOptions.ts` and driven by `next-themes` (`attribute="class"`, `defaultTheme="dark"`, `enableSystem={false}`). Each has a complete 32-token block in `src/index.css` - `:root` IS the `light` block - and a matching entry in `src/services/themePalettes.ts` giving the nine **data** hues the packet list, map and charts derive from. `scripts/themes/*.ts` enforce the whole contract (token completeness, contrast, how far apart two row fills may be, CSS-vs-palette drift); run `npm run check` after any colour edit, and regenerate the status tokens with `npx tsx scripts/themes/status-css.ts`. Dark themes must be listed in the `@custom-variant dark` list at the top of `index.css`. `--chrome`/`--chrome-foreground` paint the header bar and the left drawer in every theme. Retired theme ids are migrated on load by `migrateStoredTheme` in `src/main.tsx` - next-themes does not validate a stored value against its own list. Most components branch on Tailwind's `dark:` classes; a few (`PacketList`'s color engine, `TrafficTimelineChart`'s D3 code, `GeoMap`, `ExportImportModal`) need a plain boolean and read `isDark` from `isDarkTheme(resolvedTheme)` in `App.tsx`, passed down as a prop.

### Vite config quirks (`vite.config.ts`) — read the inline comments before touching this file
- `maplibre-gl` is excluded from `optimizeDeps` because Vite's dependency pre-bundler breaks its web worker asset resolution, silently killing map tile rendering.
- File watching/HMR is fully disabled when the `DISABLE_HMR` env var is set. Useful when a tool is rewriting many files at once: each save would otherwise trigger a reload, and they accumulate until the tab stalls.
- `local-agent/**` is excluded from the file watcher so that rebuilding the Python agent doesn't trigger a full page reload (which would tear down the live agent WebSocket and look like a connect/disconnect loop). `public/downloads/**` is deliberately **not** excluded, even though it belongs to the same build chain - read the inline comment before "fixing" that, because an excluded path falls through to the SPA fallback and the browser silently downloads `index.html` renamed to `NetView-Agent-Setup.exe`.

### Env vars
The app itself needs none. `server.ts` reads `PORT`, and `vite.config.ts` reads `DISABLE_HMR`; both have working defaults.
- `.env.local.example` — `VITE_FIREBASE_*` vars for a "Standalone NetView" Firebase config. `security_spec.md` describes the corresponding Firestore rules/threat model (roles, admin bootstrap email, shared-capture ownership invariants) for that Firebase backend, but no `firebase.ts`/Firestore integration currently exists under `src/` — treat `security_spec.md` as a spec for not-yet-implemented (or removed) backend auth/sharing, not a description of current code.
