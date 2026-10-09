# A pairing token, origin allowlist or WebSocket port on Windows

**Rejected:** `authenticate`, `authRequired`, `auth_required` / `auth_failed`, `is_origin_allowed`, and `ws://localhost:8999` in the app or the Windows agent.

**Why:** on Windows the app and the agent talk over a named pipe whose security descriptor is the authentication: the interactive user gets read and write, SYSTEM and administrators everything, and nobody else anything. Nothing to pair, no secret to paste, no port open. A token on top would be theatre, and `scripts/agent/control-vectors.ts` fails on any `auth*` key to keep it out.

**Rests on:** ADR 0029. The Python agent for macOS and Linux keeps its token for its WebSocket until those platforms get a desktop app and a socket-file permission design of their own.
