# MSIX, Electron Forge, V8 startup snapshots

**Rejected:** packaging as MSIX, migrating the build to Electron Forge, and V8 startup snapshots.

**Why:** MSIX cannot install a kernel driver or a LocalSystem service cleanly, and the installer has to do both (one installer, two destinations, ADR 0030). Forge has no Inno Setup maker, and the update channel is the trap: installed fleets only move forward on the updater they shipped with. Startup snapshots are VS Code-scale complexity for tens of milliseconds.

**Rests on:** ADRs 0030, 0032, 0047; `CLAUDE.md` §10 "Not to do".
