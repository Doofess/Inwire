# 0009 — Facts that did not come off the wire

**Status:** accepted, sub-project 1 (process attribution) implemented.
**Related: 0001 (two-phase dissection), 0002 (field registry), 0004 (fixtures and privacy).**

## The decision

Inwire may publish facts about a flow that are **not derivable from the frame**,
provided they come from the machine the capture was taken on, and provided every
one of them travels through a single seam: `src/services/flowAnnotations.ts`.

The first such fact is **which process opened the socket**.

## Why this is allowed at all

Everything else in this analyzer is dissected from bytes. `nameResolution.ts` is
emphatic that nothing is looked up, and that is the right default: a name that
came from somewhere other than the capture is a claim the capture cannot
support.

Process attribution is a different case, and the difference is not a matter of
degree. Inwire runs **on the endpoint whose traffic it is capturing**. The
operating system of that machine knows that local port 54321 belonged to
`chrome.exe`; a passive observer anywhere else on the network cannot know it and
never could. This is not a fact the frame failed to carry - it is a fact no
frame has ever carried. Wireshark cannot answer "what is talking to that
address" for the same reason, and it is the question users ask of a capture more
than any other.

So the rule is not "never enrich". It is: **enrich only from the captured
machine, and never from a third party.** Process attribution travels agent →
loopback WebSocket → browser and leaves the machine only if the user exports it.
That is what distinguishes it from `geoIp` and `reverseDns`, which are gated
behind consent because they *send an address to somebody*.

## One seam, not one feature

A companion browser extension reporting request URLs would be the same shape as
this: something that knows about a **flow**, keyed by its endpoints, arriving
**after** the frames it describes. Two bespoke enrichment paths for one shape
would be the mistake, so the store is general and process attribution is its
first source.

## Consequences, and the rules that fall out

**Keyed by the local endpoint, not by a five-tuple.** Forced, not chosen:
Windows' `GetExtendedUdpTable` has no remote column, so every UDP socket reports
an empty remote address - measured, 63 of 63 on a real machine. A five-tuple key
would attribute no QUIC and no DNS, which is most of what a browser does.

**A wildcard fallback is mandatory.** 34 of 59 UDP sockets were bound to
`0.0.0.0` or `::`, Chrome's QUIC sockets among them. An exact-bind-only lookup
would miss exactly the traffic worth attributing.

**Which end is local is decided by address, never by port.** Otherwise a frame
sent *to* a server on 443 gets attributed to whatever local process happens to
listen on 443. The set of local addresses is learned from the socket table
itself, since every key in it is one by construction.

**Deltas, not snapshots.** The table is ~890 sockets and ~52 KB of JSON, and
changes by one or two a second - 50 to 250 bytes of churn, measured. A resend
every second would compete with packet delivery for the same socket.

**Absent, never guessed.** Three different situations all render as nothing: the
endpoint was never seen, the OS would not name its owner, and two lives of a
reused port both cover the instant. A plausible wrong process name is worse than
a blank column, and this is the same rule the driver's drop counter follows -
an unknown is not a zero.

**Time is part of the key.** A local port freed by one process and taken by
another must re-attribute, or every frame the second process sends is labelled
with the first one's name. Each socket carries the window it was observed open,
widened by one polling interval at each edge because that is the resolution the
claim can honestly have; an overlap inside that window answers with nothing.

**It is `Packet.fields`, not a property of its own.** That is what makes it
filterable, offered by "Apply as Column", and - the reason that matters most -
**stripped by Anonymise for free**, because the anonymiser drops the whole field
bag. A bespoke property would have needed remembering, and "chrome.exe, pid
8412, `C:/Users/<name>/AppData/...`" identifies a person far more precisely than
the address beside it. `scripts/export/anonymise.ts` asserts it rather than
trusting it.

**The fields sit on the `frame` layer.** They describe the capture rather than
the packet - the same category as the interface a frame arrived on - and giving
a process its own `frameProtocols` token would place it in the protocol
hierarchy as a child of whatever layer it happened to follow.

**It travels in the file as an `opt_comment`, not a private option.** The point
of writing it is that somebody else can read it, and `opt_comment` is the one
per-packet option every pcapng reader already shows. Verified by handing a file
to **tshark**, which reports
`Process: curl.exe (pid 4242) - C:/Windows/System32/curl.exe` in `frame.comment`
without being told anything. A private option would have made the one fact the
file could not otherwise contain readable only by the app that wrote it.

**The Processes table is keyed on the pid, not the name.** Two processes with
one name are two programs - a browser runs a dozen renderer children, and
folding them into one row hides which is talking. Unattributed frames get no
"unknown" row: there is no single thing they belong to.

**A replay is handed the answer rather than asked to re-derive it.** The store
is a moving picture of open sockets; a frame scrolled back to may belong to one
that closed long ago. The same treatment `[Response In: N]` already gets.

## Verified live, 2026-09-05

Against agent 3.4.0 installed as a service, capturing on a real adapter:

- A `curl.exe` run produced **196 attributed frames**, and the detail pane named
  it `C:\Program Files\Git\mingw64\bin\curl.exe` - Git Bash's bundled curl,
  which is the one actually invoked, not `C:\Windows\System32\curl.exe`. A
  coincidence would not have picked the right one of two.
- A PowerShell connection reported opening from local port 54977.
  `tcp.port == 54977` selects 37 frames; `inwire.process.name ==
  "powershell.exe"` selects the same 37. A fact the process stated directly and
  an attribution derived independently agree exactly.
- 231-276 of ~2,000 frames attributed per run, which is the honest figure: an
  Ethernet segment carries broadcast, other hosts, and sockets that live and
  die inside one poll.
- **The limitation, demonstrated rather than asserted.** An earlier run's quick
  `Invoke-WebRequest` calls attributed *nothing* - each opened and closed inside
  a single one-second poll, so the table never saw them. The same process on a
  connection held open across several polls attributed perfectly. Absent, not
  guessed, is what that looks like in practice.

**One bug this found.** The subscription was first sent from the WebSocket's
`connected` handler, which fires before the pairing token has been accepted - so
the agent answered `auth_required` and no table ever arrived, while capture
itself worked because Start happens later. It is sent from the `hello` handler
now, queued behind the `authenticate` on the same connection, which delivers in
order.

## What the seam has carried since

**JA4 → process, learned locally** (`dissect/clientFingerprints.ts`). Every
analyzer can compute a TLS fingerprint; none can say whose it is from a capture
alone, and the usual answer is a downloaded corpus somebody else labelled. With
process attribution, a hello from a socket the OS named is a *labelled example*
about software actually installed here - and once enough are gathered, the
hellos it could not attribute become readable, including ones from other
machines on the segment. It reports a **match**, never an identification: a
fingerprint seen from two programs is ambiguous for ever after, because shared
TLS libraries are the norm rather than the exception. A frame teaches or is
labelled, never both, so a label can never become its own evidence.

**Link context** (`services/linkContext.ts`). `navigator.connection`, for one
reason: its `change` event. A machine moving between networks is what a gap with
no frames, a burst of ARP and DHCP, or a stream that stops dead all look like
from inside a capture. The numbers alongside are the browser's estimates and are
labelled as such; `effectiveType` renders as "4g-class" because the spec defines
it as a performance bucket rather than a technology, and a wired gigabit link
reports "4g". Chromium-only, and where it is absent nothing is shown rather than
a number derived from timings.

## What this does not do

It does not change what a frame **is**. `Packet.source` stays the address on
every path, so display filters, exports and the tshark parity harness are
untouched - the same rule passive name resolution follows.

It does not attribute a capture taken anywhere but here. A mirror port, a hub,
or an imported `.pcap` has no socket table and gets no annotation, which is
correct: for those, nobody knows.
