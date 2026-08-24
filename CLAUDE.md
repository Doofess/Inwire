# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

NetView (internally referred to in some strings as "WirePulse") is a browser-based network packet analyzer — a Wireshark-like UI built with React + Vite. It has no backend of its own for capture: live packets come from a separate local Python agent (`local-agent/agent.py`) that the user downloads and runs with elevated privileges, which streams captured packets over a local WebSocket (`ws://localhost:8999`) to the web app running in the browser. Everything else — protocol dissection, filtering, dissector rules, color rules, anomaly detection, PCAP export/import — happens client-side in TypeScript.

The project originated in Google AI Studio (see README.md); `vite.config.ts` still has AI-Studio-specific accommodations (see Architecture notes below).

## Commands

- `npm run dev` — start the Vite dev server on port 3000 (`--host=0.0.0.0`)
- `npm run build` — production build to `dist/`
- `npm run lint` — type-check only (`tsc --noEmit`); there is no separate lint tool configured
- `npm run start` — run the built app behind the Express server (`server.ts`) via `tsx`; expects `npm run build` to have produced `dist/` first
- `npm run preview` — Vite's own preview of the production build
- There is no test suite/runner configured in this repo.

### Local capture agent (`local-agent/`)

This is a separate Python project, not built by the npm scripts:
- `pip install -r local-agent/requirements.txt` (scapy, websockets, pyinstaller)
- `python local-agent/agent.py` (run as Administrator/root — raw packet capture requires elevation on every OS)
- Platform installers (`bootstrap_windows.py`, `bootstrap_macos.command`, `bootstrap_linux.sh`) are one-click wrappers that install OS capture drivers (Npcap on Windows) and then launch the agent; they're compiled into the executables under `local-agent/dist/` via `pyinstaller netview_agent.spec`, and the compiled installers get copied into `public/downloads/` for the web app to serve. Neither `local-agent/dist/` nor `public/downloads/` is tracked in git (rebuild via PyInstaller rather than editing binaries).

## Architecture

### Data flow
`local-agent/agent.py` (Scapy sniff → JSON over WebSocket) → `App.tsx`'s always-on WebSocket client (auto-reconnects every 3s, tracks `agentStatus` independent of whether capture is active) → when a raw base64 frame is present, `services/pcapParser.ts` (`decodeRawEthernetPacket`) dissects it into a `Packet` the same way an imported `.pcap` file would be; when the agent sends metadata-only (no raw bytes), a minimal fallback `Packet` is built without fabricating payload data. The packet buffer is capped at 4000 entries (oldest dropped first).

Imported PCAP files go through the same `pcapParser.ts` path via `ExportImportModal`, so live capture and file import produce identical `Packet` shapes.

### Core domain types
`src/types/packet.ts` is the single source of truth for the domain model: `Packet`, `ProtocolLayer`/`ProtocolField` (the dissected protocol tree), `AnomalyInfo`, `CustomDissectorRule`, `ColorRule`, `FilterPreset`, `UserRole`/`UserRolePermissions`.

### Services (`src/services/`) — all pure client-side engines, no backend calls except geo/DNS lookups
- `pcapParser.ts` — Ethernet/IP/TCP/UDP/DNS/TLS/etc. dissection into `ProtocolLayer[]`, byte-range-annotated for hex-viewer highlighting
- `filterEngine.ts` — parses/evaluates the Wireshark-style display filter DSL (e.g. `http || tcp.port == 443`) used by `FilterBar` and `DEFAULT_FILTER_PRESETS`
- `customDissectorEngine.ts` — user-defined protocol dissectors (magic-header/port matching, optional custom JS parsing snippet), editable via `CustomDissectorModal`
- `colorRules.ts` — Wireshark-style row coloring rules, editable via `ColorRulesModal`
- `packetGenerator.ts` — synthetic packet generation (demo/offline mode) plus packet ID sequencing shared with the live-agent path
- `geoIpService.ts` — client-side IP geolocation + reverse-DNS (via Cloudflare DoH, no API key) for `GeoMap`, with in-memory caching to avoid redundant lookups
- `rbacService.ts` — defines `ROLE_PERMISSIONS` for four roles (ADMIN/SOC_ANALYST/NETWORK_ENGINEER/AUDITOR_GUEST); currently `App.tsx` hardcodes the ADMIN permission set (`// RBAC Role (Simplified: Always Admin)`) rather than wiring up real auth — role-gating in components still reads from `permissions` props, so restoring per-user roles is a matter of feeding a real role into that object
- `platformDetect.ts` — OS sniffing to pick which agent installer (`AGENT_DOWNLOADS`) to offer for download

### Component layout (`src/components/`)
Organized by feature area, all consumed from `App.tsx`: `analytics/` (GeoMap, traffic timeline, protocol donut, network matrix, anomaly alerts, live I/O graph), `packet-list/`, `packet-details/` (protocol tree + hex viewer, linked via `activeByteRange` hover-sync), `common/` (Header, FilterBar, FloatingToolbar, ColorRulesModal), `dissectors/`, `export/`, `isp/`, `stream-follower/`, and `ui/` (shadcn/radix-ui primitives — see `components.json` for the shadcn config: New York style, no RSC, `@/src/components/ui` aliasing).

### Theming
Light/dark theming uses `next-themes` (`attribute="class"`, `defaultTheme="system"`) driving Tailwind v4's class-based dark variant (`@custom-variant dark` in `src/index.css`, since Tailwind v4 has no JS config file). CSS custom properties (`--background`, `--primary`, etc.) are defined once under `:root` and overridden under `.dark`. Most components branch on Tailwind's `dark:` classes; a few (`PacketList`'s color engine, `TrafficTimelineChart`'s D3 code, `GeoMap`, `ExportImportModal`) need a plain boolean and read `isDark` derived from `useTheme().resolvedTheme` in `App.tsx`, passed down as a prop — don't reintroduce a separate hardcoded-dark default without checking the flash-of-light-theme tradeoff noted in `App.tsx`'s comment.

### Vite config quirks (`vite.config.ts`) — read the inline comments before touching this file
- `maplibre-gl` is excluded from `optimizeDeps` because Vite's dependency pre-bundler breaks its web worker asset resolution, silently killing map tile rendering.
- File watching/HMR is fully disabled when the `DISABLE_HMR` env var is set (used by AI Studio to prevent flicker during agent edits).
- `local-agent/**` and `public/downloads/**` are excluded from the file watcher so that rebuilding the Python agent or dropping a new installer binary doesn't trigger a full page reload (which would tear down the live agent WebSocket and look like a connect/disconnect loop).

### Env vars
Two separate `.env*` setups exist, from different points in the project's history:
- `.env.example` — `GEMINI_API_KEY`, `APP_URL` (legacy AI-Studio-injected values; `@google/genai` is still a dependency but not obviously wired into the current UI — check before assuming it's live)
- `.env.local.example` — `VITE_FIREBASE_*` vars for a "Standalone NetView" Firebase config. `security_spec.md` describes the corresponding Firestore rules/threat model (roles, admin bootstrap email, shared-capture ownership invariants) for that Firebase backend, but no `firebase.ts`/Firestore integration currently exists under `src/` — treat `security_spec.md` as a spec for not-yet-implemented (or removed) backend auth/sharing, not a description of current code.
