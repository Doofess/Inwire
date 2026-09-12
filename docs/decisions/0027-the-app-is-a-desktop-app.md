# 0027 — The app is a desktop app

**Status:** accepted. **Supersedes `0025` Decision 1's mechanism** — the four
files are the same four files, and they are not in OPFS. Dissolves the
constraint `0026` reasoned from, and makes `0029` possible at all.

## Context

Almost every hard decision in this repository was hard because of the browser,
and it is worth listing them together, because separately each looked like an
engineering problem and together they were one:

- **OPFS**, not files, because a web page has no filesystem — which forced a
  storage-only Worker for `createSyncAccessHandle()` and made `BlockFile` a
  seam rather than a convenience.
- **A 10.8 GB quota**, measured, which is a share of the disk rather than the
  disk, and which `0026`'s central argument is arithmetic about. Not a promise
  either: `navigator.storage.persist()` returned **false**.
- **A ~2 GB import**, because `file.arrayBuffer()` is how a page reads a file
  and an `ArrayBuffer` has a ceiling.
- **Exports that must fit a `Blob`**, and download through an anchor element.
- **A 256-bit token pasted in by hand**, because the page could not read
  `%ProgramData%` — which was the reason the token was put there.
- **An origin allowlist** that `0005` itself described as keeping an ordinary
  web page out and stopping nothing that can set a header.
- **A loopback port** for the agent, reachable by every process on the machine,
  and three phases of scaffolding defending it.

None of these is a browser bug. They are what a browser is: a sandbox that a
packet analyzer is on the wrong side of. The app needs a privileged capture
service, real files at real sizes, and a channel between the two that the
operating system can police. A web page is entitled to none of that, and every
workaround above is the shape of asking anyway.

## Decision

**Inwire is an Electron desktop application for Windows, and the capture agent
ships inside it.** There is no browser build, no `server.ts`, no hosted
deployment.

The renderer is the same React app, served from a custom `app://inwire` scheme
rather than from a dev server or a file URL. The main process owns what only a
privileged process can hold — the window, the menu, the agent's pipe, the
native dialogs, the capture store's lifetime — and holds no logic worth
testing: every decision beside it lives in a module that does not import
Electron.

## What this dissolved, rather than solved

The distinction matters, because a decision that removes a problem is worth
more than one that manages it, and because a reader of the older ADRs needs to
know which of their arguments have stopped applying.

| Was | Now |
|---|---|
| OPFS, and a Worker for the sync handles | `node:fs`, in a process (`0028`) |
| A 10.8 GB quota; `persist()` false | Free space on the volume; nothing evicts a file |
| A pairing token, pasted by hand | Deleted. The pipe's ACL is the authentication (`0029`) |
| An origin allowlist | Deleted. There is no origin |
| `ws://localhost:8999` | Not opened on Windows at all |
| A `Blob` and an anchor | A native save dialog |

**`0026`'s conclusion survives its reasoning.** That ADR argued for one capture
on disk from arithmetic about a 10.8 GB quota, and on a real disk the
arithmetic evaporates. One capture is still what ships, for the reason `0026`
gives second rather than first — a 5 GB capture makes the previous one worth
less — but the quota paragraph is void and should be read as history.

## What it cost, stated plainly

**A 246 MB executable**, against a URL. That is Chromium, and no amount of
pruning changes the order of magnitude. What pruning did change, measured:
Electron ships 49 locale `.pak` files and the app is English-only, which is
**50.1 MB freed** by an `afterPack` hook; `files:` in electron-builder does not
exclude `node_modules`, and saying so took **app.asar from 273 MB to 10.1 MB**;
and a stale installer left under `public/` was two thirds of a 30 MB renderer
bundle, now **9.7 MB**.

**A support window.** Electron carries security fixes for three majors. This is
on 44, so a bump every other release is maintenance the browser was doing for
us.

**Distribution becomes ours.** A web app updates by being reloaded. A desktop
app needs an installer, a signature and an update channel — `0030` for the
first, and the other two are deliberately unfinished.

**The store had to become a process.** Not a consequence anyone wanted, and
`0028` is the argument for it.

## Why Windows first, and why that is not a placeholder

The agent needs Administrator on every operating system, because raw capture
does. What differs is the channel between an unprivileged app and a privileged
service, and Windows has an answer with a name — a named pipe with a security
descriptor naming the interactive user. A Unix socket is not the same object
with a different name (`0029`), so macOS and Linux keep the tarball agent and
the WebSocket until that is designed rather than approximated.

## Consequences

- Every ADR before this one that reasons from a quota, an origin, a token or a
  `Blob` should be read as describing a constraint that no longer exists. The
  conclusions mostly stand; several of the arguments do not.
- The assertion suite must keep running under plain `tsx` with no Electron and
  no browser. That is what `scripts/capture/node-safe.ts` and
  `scripts/electron/tsconfigs.ts` now hold it to, and it is why anything
  needing Electron is split into a module that does not import it.
- Three bugs in the migration type-checked, bundled and failed silently at
  runtime — the maplibre worker URL, `node:os` in a sandboxed preload, and COEP
  blocking a same-origin worker. None was reachable from a script. That is what
  `scripts/electron/smoke.ts` exists for, and its own header is the list.
- A fourth was worse and is the standing warning: the capture store wrote **no
  rows at all** for the whole migration, because a `FieldBlock` class instance
  does not survive a structured clone and nothing in the suite crossed a
  process boundary. A desktop app has boundaries a web page did not, and a test
  that does not cross them is testing a different program.
