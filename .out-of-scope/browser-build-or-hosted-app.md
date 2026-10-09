# A browser build, a hosted app, a service worker, a phone layout

**Rejected:** building the renderer for a browser, hosting it, an SPA fallback, a service worker, anything under `public/` that is not a static asset the app loads, and a phone or narrow layout (the window minimum is 1024 px; `md:` is 768).

**Why:** the app is a desktop app (ADR 0027). The renderer is served to Electron from the `app://inwire` scheme and talks to a privileged local agent over a named pipe; none of that exists in a browser. A hosted build would also break the offline invariant. A phone layout optimises for a surface the product does not run on.

**Rests on:** ADRs 0027, 0029; `CLAUDE.md` "must not come back".
