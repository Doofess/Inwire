# Companion browser extension — spec

**Status:** proposed. Sub-project 3 of `docs/decisions/0009-off-wire-enrichment.md`.
Nothing is built yet; this exists to be argued with first.

## What it is for

Inwire can now say *which program* sent a frame. It cannot say **what that
program asked for**, because for anything over TLS the request is encrypted and
the app has no key. A browser knows its own requests in the clear, and this is
the only way to get them.

The result would be: a TLS or QUIC flow in the packet list annotated with the
URLs it actually carried, the status codes that came back, and whether the
response came from cache.

## Why the obvious approach does not work

`PerformanceObserver` on `resource` entries is the answer a web app reaches for,
and it fails on scope. It reports only the requests **the Inwire page itself
made**, and for cross-origin entries without `Timing-Allow-Origin` - which is
all of them - it returns URL, start time and duration and zeroes everything
else. It can never see another tab. Measured against the actual need, it is not
a smaller version of this feature; it is a different one.

An extension is the only mechanism that sees the whole browser.

## What the extension can actually observe

Manifest V3, permission `webRequest` (observation only - `webRequestBlocking` is
restricted to policy-installed extensions now, and this needs to block nothing)
plus host permissions.

| Event | Carries |
|---|---|
| `onBeforeRequest` | url, method, type, tabId, frameId, requestId, timeStamp |
| `onResponseStarted` | statusCode, **ip**, fromCache |
| `onCompleted` | statusCode, **ip**, fromCache, responseHeaders |

`details.ip` is the load-bearing field: the server address the browser actually
connected to. Without it there is no way to tie a request to a flow.

## The join

The extension never sees the local port, so the key cannot be a five-tuple.
Three signals together:

1. **Remote address** — `details.ip` against the frame's remote endpoint.
2. **Time window** — the request's `timeStamp` against the flow's frames.
3. **Hostname against SNI** — the URL's host against the server name the capture
   already extracted from the ClientHello.

The third is what makes this trustworthy rather than plausible. One CDN address
serves thousands of names, so address plus time alone would mis-attach requests
between sites sharing an IP; the SNI is an independent string the capture read
off the wire, and requiring it to match the URL's host turns a correlation into
a corroboration.

**Where the three do not agree, attach nothing.** Same rule as everywhere else
in this seam.

## Where it plugs in

`services/flowAnnotations.ts`, unchanged. This is the reason it exists: an
external source that knows about a flow, keyed by endpoints, arriving after the
frames. Process attribution proved the seam; this is its second source.

New fields on the `frame` layer, registered as `inwire.request.*`:
`inwire.request.url`, `inwire.request.method`, `inwire.request.status`,
`inwire.request.type`, `inwire.request.cached`.

## Transport, and why not the obvious one

`externally_connectable` lets the page call `chrome.runtime.sendMessage`
directly, and is cleaner - on Chrome. Firefox's support is partial and its
history uneven.

**Decision: a content script that `window.postMessage`s to the page**, with an
origin check on both ends. It costs one more moving part and works the same on
both browsers. The alternative is Chrome-only, and Firefox is a browser people
run packet analyzers in.

## The part that needs to be said plainly

The permission prompt will read **"Read your browsing history"**, because that
is precisely what this does. That is not a wording problem to be worked around,
and any design that tries to make it sound smaller is the wrong design.

So:

- The extension is **entirely optional**. Inwire works without it, and nothing
  in the UI nags for it.
- It sends only to `localhost`, only while a capture is running, and only for
  requests whose remote address appears in that capture.
- URLs are **stripped of query strings by default**, because that is where
  session tokens and search terms live and the path alone answers the question
  the feature exists for. A switch can turn the full URL on.
- Requests are held **in memory only**, never in the stored session, and are
  stripped by Anonymise exactly as process names are.
- Exports carry them only with the same explicit opt-in the Decryption Secrets
  Block already uses (`docs/decisions/0008`).

## Distribution

Its own artifact, not part of the app bundle:

- `extension/` in this repo, built to `public/downloads/inwire-extension.zip`.
- Unpacked install with developer mode for now. A store listing is a separate
  decision with its own review latency and is not a prerequisite.
- The extension declares the Inwire versions it speaks to, and the app says so
  when they disagree - the same three-place version lock the agent already has,
  and for the same reason: two implementations of one protocol drift.

## What would need to be proven before this is worth shipping

1. **The join actually joins.** On a real capture with a real browsing session,
   what fraction of TLS flows get a URL, and are any of them wrong? A
   deliberately adversarial case: two sites on one CDN address, loaded seconds
   apart. If the SNI check does not separate them, the design is wrong.
2. **The cost is bounded.** A busy page makes hundreds of requests; the message
   rate must not compete with packet delivery, and the same delta discipline the
   socket table uses probably applies.
3. **Firefox works.** If the content-script transport does not carry there, the
   portability argument that chose it collapses and the decision should be
   revisited rather than quietly kept.

## Open questions

- Should the extension report requests for tabs other than the ones the user is
  looking at? Everything says yes for completeness and no for privacy. Leaning
  yes-with-the-switch-visible.
- HTTP/3 over QUIC: the capture cannot always tell where a QUIC flow's requests
  begin. The join may only be reliable per-connection rather than per-request
  there, and the annotation should say which it is.
