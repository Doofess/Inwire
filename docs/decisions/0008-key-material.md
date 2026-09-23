# 0008 — Where TLS key material lives, and where it does not

> **Weakened by [0027](0027-the-app-is-a-desktop-app.md), and the question is
> reopened rather than answered.** The decision below stands - key material is
> still memory-only, still never written to a preference or a stored session,
> still out of an export unless a switch that counts the connections is turned
> on. What no longer holds is the *bound* the argument rests on: this file says
> the exposure "is exactly as old as the tab", and there is no tab. A desktop
> window stays open for days, so "the life of the page" below should be read as
> the life of the process, which is unbounded in a way a browser tab was not.
>
> **`crashReporter` stays off for the same reason.** A renderer minidump is a
> copy of `KeyLogStore`, so the usual advice - enable it with
> `uploadToServer: false` for local dumps - conflicts with this ADR and is
> declined until the key-lifetime question is reopened properly. Reopening it is
> what a successor ADR would do; this banner only records that the premise moved.

**Status:** accepted, Phase 13. **Weakened by 0027** — see the banner above.
**Amended by [0045](0045-the-key-log-is-followed-not-loaded.md):** key material now enters memory at
launch when the person has chosen to follow a key log file, rather than only by an action in that
session. Only the file's path is persisted; the rest of this decision stands.
**Supersedes nothing. Related: 0004 (fixtures and privacy), 0001 (two-phase dissection).**

## The decision

A TLS key log is held **in memory only**, for the life of the page, in a
`KeyLogStore` per JavaScript context (`src/services/tls/keyLog.ts`). It is:

- never written to the stored session, so reloading the app loses it;
- never written to `localStorage`, `IndexedDB` or a preference;
- never included in an export unless the user turns on a switch that says, in
  the same sentence, how many connections the file would then open;
- never sent anywhere.

A capture and its key log together are the traffic in the clear. Separately
they are two useless halves. Every rule above exists to keep them separate by
default, and to make joining them an act rather than a side effect.

## Why it is not persisted with the session

The session store already keeps frames across a reload, and it would have been
one line to keep the secrets with them. Two reasons not to.

The first is that the secrets are not the user's to leave lying around: a key
log covers whatever the browser was doing while it was set, which is every site
that browser visited, not the one being analysed. A capture is a record of what
was on the wire; a key log is a key to everything the machine did.

The second is that persistence would have made the sensitive state invisible.
Nothing in the UI would say the app was holding the keys to last week's
browsing, because it would have been true since last week. In memory, the state
is exactly as old as the tab.

The cost is real and accepted: a key log has to be loaded again after a reload,
and frames dissected before it was loaded keep what they showed. Settings says
so rather than pretending otherwise.

## Why decryption happens in the summary pass

Docs/decisions/0001 divides dissection into a summary pass that runs for every
frame and a tree built on demand. Decryption is in the *summary* pass, which
looks like the expensive choice and is the only correct one.

TLS records, HTTP/2 frames and HPACK tables are all cross-frame state. A
decoder that ran only for frames the user selected would see a stream with
holes in it: the HPACK dynamic table would index entries it never saw inserted,
and the HTTP/2 framing would resynchronise on whatever byte it happened to
start at. The Protocol and Info columns would also be wrong for every frame
until it was clicked, which is worse than being wrong consistently.

Measured (a real 1,051-frame Cloudflare session, 1.3 MB of HTTP/2 inside TLS
1.3): 173 ms without a key log, 305 ms with one - so decryption costs about 130
ms per 1.3 MB, and it only costs anything at all on conversations the key log
actually covers.

## Why the AEAD tag is the oracle

Nothing here guesses which keys or which sequence number a record belongs to
and then renders the result. Every decryption is authenticated, and a failure
is returned as a failure.

That is what makes it safe to *try*: a direction's epoch transition happens
when its Finished message goes out, which is itself encrypted, so there is no
signal on the wire that says a record has moved from the handshake keys to the
application keys. The decoder tries the current epoch at the current sequence
number and then the next epoch from zero, and the tag decides. A wrong guess
cannot succeed by accident, so a wrong guess cannot be shown.

The same rule covers the cipher suites this build does not implement. A CBC
suite is reported as "not decrypted" with the reason, rather than attempted and
quietly abandoned - the user supplied a key log and is entitled to know why it
did not help.

## What a pcapng Decryption Secrets Block changes

A pcapng file may carry its own key log (block type 0x0000000A). Reading it is
unambiguously right: the secrets are already in the file, and refusing to use
them would only mean the user has to extract them by hand.

Writing one is the reverse, and is off by default. A capture with its secrets
attached has no confidentiality left, and - this is the part worth stating -
that is invisible from the outside: it is the same file, the same size, with
one more block in it. The export panel says how many connections would travel
in the clear, and refuses to combine the option with Anonymise, where the two
would contradict each other outright.
