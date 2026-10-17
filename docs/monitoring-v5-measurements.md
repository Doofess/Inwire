# NetFlow v5 monitoring: measurements and exporter survey

What a NetFlow v5 collector costs on this machine before any of it is built,
measured for ADRs [0058](decisions/0058-monitoring-intake-and-lifetime.md),
[0059](decisions/0059-monitoring-evidence-journal-and-rollups.md) and
[0060](decisions/0060-monitoring-workspace-sheet.md). Every number is a
property of the machine it ran on; `scripts/monitoring/measurement.ts`
reproduces each one, and is in `check.ts`'s `NOT_TESTS` for that reason.

**Not run is not passed.** Three things this report would like to say are not
measured, and are listed under **Not run** rather than left out.

## The machine

| | |
|---|---|
| OS | Windows 11 Pro 10.0.26300, not elevated |
| Node | 26.8.1 (what `tsx` ran the socket, journal and rollup modes on) |
| Electron | 44.3.0, the repository's dev copy (`node_modules/electron/dist`) |
| Capture | the installed Inwire agent 0.5.0 (Rust), on `NPF_Loopback`, the WSL adapter and Ethernet |
| WSL | WSL 2, kernel 6.18.54.1, Ubuntu in NAT mode, Python 3.14.4 |
| Exporter | softflowd 1.1.1 in WSL, installed by the owner for the interop run; no nfdump |

Datagrams are generated, except in the softflowd section: `TrafficModel` in the script builds v5 records for
twelve hosts talking to a pool of 2,000 remote addresses, with a heavy tail of
ports, at 2, 7 and 50 datagrams a second; a *high-cardinality* variant gives
every record a new address pair. The 7 a second profile is the planning point:
a busy small office with 30 records to a full datagram.

## The Windows path

### Bind behaviour (`socket`, loopback only)

Loopback and an unassigned address raise no firewall prompt, so these ran with
no person present.

| Case | Result |
|---|---|
| bind `127.0.0.1:47055` | ok; default receive buffer **64 KiB** |
| a second bind, same address and port | `EADDRINUSE` |
| the same with `reuseAddr` | `EACCES` |
| an address not on this machine (`192.0.2.1`) | `EADDRNOTAVAIL` |
| port 514, below 1024 | ok - no privilege is needed on Windows |

### A wildcard bind beside a specific one (`bindpair`)

Binding `0.0.0.0` from `node.exe` would raise the firewall prompt for
`node.exe`, so this ran under the copy of Electron whose rules run 2 below had
already turned to Allow. `bind-pair-probe.cjs` bound each socket in its own
order, one `utilityProcess` per process in the plan, and a sender in WSL sent
20 datagrams to the WSL adapter's address. 2026-10-17:

| Binds, in order | Both bind? | Who received the 20 |
|---|---|---|
| wildcard, then specific (one process, or two; with or without `reuseAddr` on either) | yes | the specific socket, all 20 |
| specific, then wildcard (the same six variations) | yes | the specific socket, all 20 |
| specific, then the same specific address, neither `reuseAddr` | `EADDRINUSE` | the first |
| specific, then the same specific address, both `reuseAddr` | yes | the first, all 20; the second none |
| specific without `reuseAddr`, then the same with it | `EACCES` | the first |

- **A wildcard listener never makes a specific bind fail, in either order.**
  The more specific socket takes every datagram to its address, and the
  wildcard socket goes silent for that address with no error. If another
  program is collecting on `0.0.0.0:2055`, a specific bind here succeeds and
  takes its datagrams; if Inwire is bound first, the other program's
  wildcard bind succeeds and receives nothing on this address.
- **`EADDRINUSE` means the same address and port**, held by a socket without
  `reuseAddr`. A socket bound without `reuseAddr` cannot be shared, by a later
  bind with or without the option.

### Delivery against passive capture (`socket`)

Full 1,464 B datagrams sent in bursts of 50 every 10 ms, the agent capturing
on `NPF_Loopback` throughout:

| | Delivered to the socket | Seen by the capture | ICMP port unreachable | Sender errors |
|---|---|---|---|---|
| bound listener, default 64 KiB buffer | 900 of 1,000 | 2,000 of 2,000 over both runs | 0 | none |
| bound listener, 8 MiB buffer | 1,000 of 1,000 | (counted with the row above) | 0 | none |
| listener stalled for 2 s, default buffer | 45 of 5,000 | not counted | - | none |
| listener stalled for 2 s, 8 MiB buffer | 5,000 of 5,000 | not counted | - | none |
| no listener, unconnected sender, two runs | - | 2,000 of 2,000 | **300 of 2,000** | none |
| no listener, connected sender | - | - | - | none |

- **The default receive buffer loses a burst.** An exporter's datagrams come
  in bursts when its cache expires, and 64 KiB is 44 full datagrams. 8 MiB
  took a 2-second stall without loss.
- **The sender learns nothing either way.** No error reached it for a full
  buffer or for a port with no listener, even from a connected socket.
- **Passive capture sees every datagram, and that is not a collector.** With
  no listener it saw all 2,000, while Windows answered only 300 of them (15%)
  with ICMP port unreachable. It reports what reached the adapter, not what a
  socket accepted, and the exporter gets no reliable sign that nothing is
  listening.

### The firewall prompt (`firewall`, a human step)

Run three times, 2026-10-17. Each time a fresh copy of the dev `electron.exe`
(a program with no rule yet) forked `firewall-probe.cjs`'s `utilityProcess`.
The probe bound the WSL adapter's IPv4 address, port 47058. A Python sender in
WSL sent one 64 B datagram every 0.2 s while the agent captured the adapter.
The owner answered the prompt.

**What Windows shows.** It is a *Windows Security* dialog, not the older Defender
Firewall one:

> **Do you want to allow public and private networks to access this app?**
>
> Windows Firewall has blocked some features of Electron on all public and
> private networks.

Below the text are the program's name ("Electron") and publisher
("GitHub, Inc."), and a "Show more" link. The buttons are **Allow** and
**Cancel**. There is no checkbox for choosing a profile. Both the name and the
publisher are read from the executable; the packaged `Inwire.exe`'s own prompt
is below.

**What happens at bind, before anyone clicks.** The firewall service adds
inbound **Block** rules for the program at once: one for TCP and one for UDP,
on the **Public** profile only. They are named after the executable. The
firewall log records them as event 2097, with action Block and profiles = 4.
The bind itself succeeds and the socket reports `listening`.

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| owner's answer | Allow, ~28 s in | Allow, ~4 s in | Cancel |
| sent from WSL | 550 | 550 | 550 |
| reached the adapter | 550 | 550 | 550 |
| delivered to the socket | 431 | 548 | **0** |
| ICMP unreachable sent back | 0 | 0 | 0 |

- **While the prompt is open**, datagrams that reach the adapter are dropped
  silently. They are not queued for later, and no ICMP reply is sent.
- **Allow** changes the same rules to Allow (event 2099, six rules, still
  Public only), and delivery starts at once. The change is made by
  `dllhost.exe`, and the owner saw **no UAC prompt**. The dialog says "public
  and private networks", but the rules it leaves are Public-only. The WSL
  adapter is on the Public profile, and so is this machine's Ethernet.
- **Cancel** leaves the Block rules in place. Nothing is delivered, nothing
  arrives at the sender, and the socket stays `listening`. This is the state
  the spec describes as listening with nothing arriving. Windows does not ask
  again for a program it already has a rule for. Undoing a Cancel means
  editing or removing the rule in *Windows Defender Firewall with Advanced
  Security* (`wf.msc`), which needs an administrator.
- **No rule** is the state before the first bind. It does not survive the
  first bind, because the bind is what creates the Block rules.
- The firewall log (`Microsoft-Windows-Windows Firewall With Advanced
  Security/Firewall`) can be read without elevation. An app could see that a
  rule exists for its own executable without changing it, but no design here
  depends on that.

### The packaged `Inwire.exe`'s prompt

Run once, 2026-10-17, the owner answering Allow. `npm run pack` built and
signed `release/win-unpacked` from `main` at 674364c, fuses flipped, and the
folder was copied to a scratch path with no firewall rule. A fused `Inwire.exe`
loads only `resources/app.asar`, so the copy's asar was replaced by one holding
`firewall-probe.cjs` as its main. That works because
`enableEmbeddedAsarIntegrityValidation` is still off (CLAUDE.md §5), and it
changed no source file and no signed byte. The probe bound the WSL adapter's
address on port 2055, as in the runs above.

> **Do you want to allow public and private networks to access this app?**
>
> Windows Firewall has blocked some features of Inwire on all public and
> private networks.

- **The wording is the dev prompt's word for word**, with *Inwire* for
  *Electron*. ADR 0060's sheet text holds for the packaged app.
- **Name "Inwire", publisher "Rotem Grinhut".** These are the executable's
  VERSIONINFO, `FileDescription` and `CompanyName`, which electron-builder
  takes from `package.json`'s `productName` and `author`. They are not the
  certificate's subject, which is *Inwire Code Signing (this PC)*. The dev
  `electron.exe` showed "GitHub, Inc.", its own `CompanyName`.
- **The rules are the same shape**: two inbound rules named `inwire.exe`,
  Public only, created as Block at the bind (event 2097, twice) and turned to
  Allow by the click (event 2099, six times), with no UAC prompt.
- **Delivery: 361 of 400.** All 400 reached the adapter. The 39 lost are about the
  first 8 seconds of sending, while the prompt was open, and no ICMP was sent.

Cancel was not run against the packaged build. Windows' refusal to ask again
is a property of the rule already existing, which run 3 showed for the dev
copy.

### An exporter across the LAN (`firewall --nic Ethernet --listen-only`)

A laptop on the same LAN ran softflowd 1.1.1 in WSL, replaying a short
`tcpdump` of its own traffic (`-r <pcap> -v 5`) to this machine's Ethernet
address on port 2055. The receiver was the packaged `Inwire.exe` copy above,
whose rules already said Allow, bound to the Ethernet address. The
Ethernet network is on the **Public** profile. The agent captured the same
port beside it.

| On the adapter | Delivered | ICMP unreachable |
|---|---|---|
| 2 | **2** | 0 |

Every datagram that reached the wire reached the socket. The path is a real
NIC, a real switch and another machine's stack, which the WSL adapter does not
cover. The exporter was softflowd on a laptop, not a router.

## softflowd against the app's decoder (`softflowd`)

softflowd 1.1.1 (Ubuntu's package, in WSL) replayed each fixture with
`-r <capture> -v 5 -d`, exporting to a receiver inside WSL that kept every
datagram. The script wrapped those datagrams in a pcap, and tshark's `cflow`
dissector and the app's own `normalizeFlows`
(`src/services/flow/flowExport.ts`) each read them. Fourteen fields were compared
per record: addresses, next hop, interfaces, packets, octets, ports, TCP
flags, protocol, ToS and both AS numbers.

| Fixture | Datagrams | Records | Field mismatches | Packets: flows / capture IPv4 |
|---|---|---|---|---|
| `inwire` | 7 | 188 | **0** | 4,226 / 4,226 |
| `bulk` | 2 | 33 | **0** | 170 / 170 |

- **The decoder agrees with tshark on every field of every record**, with no
  sequence breaks and at most 29 records in a datagram.
- **softflowd's octets are not IP lengths.** They count every byte past the
  Ethernet header, so a short frame's padding is included: 5,311,697 against
  5,300,353 by `ip.len` for `inwire`, and exactly 5,311,697 past the
  Ethernet header. The 11,344 bytes are the padding on 1,890 frames. A
  collector shows an exporter's octets as the exporter counted them, and
  this exporter counts a few bytes more than the IP headers say.
- v5 carries IPv4 only, so a fixture's IPv6 traffic exports nothing.

## The journal (`journal`, ~2.7 GB written to temp and deleted)

The prototype framing is the one ADR 0059 pins: a 64-byte file header, then
entries made of a 24-byte header and a body, with CRC-32 over each.
`NodeBlockFile` holds the file, and nothing is batched.

Figures from the second full run. The first agreed within 10% everywhere it
finished; where it stopped is described below.

| | |
|---|---|
| CRC-32 over 64 MiB | 639 MiB/s in a JS table, **7,596 MiB/s** in `zlib.crc32`; they agree |
| append, realistic 1,464 B datagram | **6.94 µs** an entry (144,052 a second); 48 B of framing, 3.17% |
| append, maximum 65,507 B datagram | 172 µs an entry (5,815 a second) |
| `fsync` after every append | 249 µs (1,464 B), 456 µs (65,507 B) |
| one-second flush timer at 7 a second | 0.24 ms a flush, mean |

Two generated datasets, written at full speed:

| | day at 7/s | week at 2/s |
|---|---|---|
| datagrams | 622,570 | 1,435,907 |
| journal | 842 MiB, 1,419 B a datagram | 1,701 MiB, 1,242 B a datagram |
| per day | 0.82 GiB | 0.24 GiB |
| **1 GiB of journal lasts** | **29.2 h** | **101 h** |
| open scan, headers only | 159 ms | 354 ms |
| open scan, every CRC checked | 1,493 ms | 3,448 ms |
| entries recovered / bad | all / 0 | all / 0 |
| raw scan of the last 100,000 datagrams | 1,703 ms, 2.8 M records | 1,494 ms, 2.4 M records |
| …its distinct 5-tuple keys | over 50,000: refused | over 50,000: refused |
| raw drill-down, last 10 minutes, 5-tuple | 108 ms, 118,082 records, over 50,000 keys | 38 ms, 29,272 records, 21,870 keys |
| **streaming rollup rebuild** (address pair, budget 16,384) | **18.0 s**, 1,441 minutes, 158 MiB sidecar, peak heap **159 MiB** | **38.0 s**, 10,081 minutes, 442 MiB sidecar, peak heap **189 MiB** |

- **Ports are answerable from raw only when the scan is narrowed.** Ten
  minutes at 7 a second already passes 50,000 distinct 5-tuple keys, so a
  port drill-down has to be scoped to one host or to a few minutes.
- **Rebuild memory does not grow with the range.** Seven times the minutes
  cost 30 MiB more heap than the day did.

**The first full run ran out of memory, and that is a finding.** It kept
every minute's rollup maps until the end of the week, about 10,080 minutes ×
2,700 keys, and node aborted at 3.5 GB. The day survived only because, at
budget 5,000 with service-port keys, every minute overflowed and cleared its
maps. Rebuild now **streams**: it holds the open minute, encodes it when the
minute changes and drops it. The table above is that rebuild, and ADR 0059
makes it a rule.

## Rollup sizing (`rollup`)

Per-minute cardinality, averaged over 30 minutes after a 15-minute warm-up,
with no budget:

| Profile | Records/min | Endpoints | 5-tuple | Service port | Address pair | Bytes/min (5-tuple / service / pair) |
|---|---|---|---|---|---|---|
| realistic, 2/s | 3,374 | 415 | 3,329 | 2,041 | 1,546 | 105k / 63k / 45k |
| realistic, 7/s | 11,841 | 873 | 11,691 | 5,843 | 3,974 | 357k / 175k / 113k |
| realistic, 50/s | 84,624 | 1,838 | 83,139 | 30,019 | 15,208 | 2.4M / 847k / 402k |
| high-cardinality, 2/s | 3,601 | 3,613 | 3,601 | 3,601 | 3,601 | 177k / 170k / 159k |
| high-cardinality, 7/s | 12,597 | 12,609 | 12,597 | 12,597 | 12,597 | 618k / 592k / 555k |

A 5-tuple key is nearly one per record. A minute keyed that way is the raw
journal again, so a 5-tuple rollup would cost about as much as the journal
and save nothing. *Service port* is the conversation without the ephemeral
port. *Address pair* is the directional pair of addresses.

24 hours generated per profile; the week is generated at 2/s:

| Rate | Key | Budget | Peak keys a minute | Incomplete minutes | Sidecar a day, raw (deflated) | Distinct over the day | 24 h query | 7-day query |
|---|---|---|---|---|---|---|---|---|
| 2/s | address pair | 5,000 | 2,167 | 0 / 1,440 | 63 MiB (23) | 49,955 | 638 ms | 4,164 ms, over 50k |
| 2/s | address pair | 16,384 | 2,263 | 0 / 10,080 | 63 MiB (23) | 49,955 | 585 ms | 1,076 ms, over 50k |
| 2/s | service port | 16,384 | 2,819 | 0 / 10,080 | 88 MiB (33) | 551,795 | over 50k | over 50k |
| 7/s | address pair | 5,000 | over 5,000 | **385 / 1,440** | 115 MiB (51) | 50,037 | over 50k | over 50k |
| 7/s | address pair | 16,384 | 5,218 | 0 / 1,440 | 158 MiB (59) | 50,037 | 741 ms, over 50k | 1,882 ms, over 50k |
| 7/s | service port | 5,000 | over 5,000 | **1,440 / 1,440** | - | - | - | - |
| 7/s | service port | 16,384 | 7,285 | 0 / 1,440 | 248 MiB (94) | 1,718,961 | over 50k | over 50k |

- **5,000 keys a minute is too few at the planning rate.** With address
  pairs, 7 a second left 385 of 1,440 minutes incomplete. With service ports,
  every minute was incomplete. 16,384 left none incomplete in either case.
- **The 50,000-key range bound is exceeded by a day.** The day's distinct
  address pairs, about 50,000, are a ceiling set by the model's own universe:
  12 hosts × 2,000 remotes × 2 directions, plus endpoints. A real network can
  exceed it, so a day or week view of conversations does not fit the plan's
  bound as it stands. ADR 0059 takes that up.
- The sidecar at 7 a second with address pairs is 158 MiB a day, raw. That is
  19% of the journal it is derived from, or 7% deflated. Raw sidecar plus
  journal is about 1 GiB a day at that rate.

## Not run

- **A router or firewall as the exporter.** The Ethernet path is measured
  with softflowd on a laptop. No hardware exporter has sent to this machine,
  so a device's own timeouts, sequence handling and source address are
  known only from the survey.
- **Cancel under the packaged `Inwire.exe`.** Its Allow is measured above;
  its Cancel was not run.
- **The installed build's prompt.** The packaged run used a scratch copy of
  `release/win-unpacked`. An installed `Inwire.exe` under `Program Files`
  carries the same VERSIONINFO, so it should show the same name and
  publisher. That is expected, not measured.

## Exporter survey

Vendor and open-source primary documentation, read on the cited page,
2026-10-17. "-" means the page says nothing on it. Aruba's site refuses
automated clients, so its row comes from search summaries of the cited pages
and is **unverified**.

| Vendor | v5 | v9 | IPFIX | sFlow | Sampling | Active / inactive | Port |
|---|---|---|---|---|---|---|---|
| Cisco IOS / IOS-XE Flexible NetFlow | yes | **default** | yes | - | `random 1 out-of N`, sent in a v9 options template | 1800 s / 15 s | 9995 |
| Cisco classic NetFlow | yes | yes | - | - | v9 `sampler` option; the v5 header's bytes 22-23 are reserved | 30 min / 15 s | - |
| Fortinet FortiGate (7.6) | - | yes | "v10" on NP7 only | yes, v5 | per interface, default 1; sent in template 256 | 1800 s / 15 s | 2055; sFlow 6343 |
| Palo Alto PAN-OS | - | **only** | - | - | "do not support sampled NetFlow" | 5 min / - | 2055 |
| Juniper SRX | v5, v8 | J-Flow v9 | yes ("version 10") | - | - | 1800 s (forwarding-options); 60 / 60 s (inline IPFIX) | - |
| Juniper EX | - | - | - | yes, v5 | separate ingress / egress rates | - | 6343 |
| Cisco Meraki MX | - | **only** | - | - | - | - (3 s maximum update) | set in Dashboard |
| Sophos Firewall (SFOS 21.5) | **only** | - | - | - | - | - | 2055 |
| MikroTik RouterOS 7 | yes (and v1) | yes | yes | - | `packet-sampling` default no | 30 min / 15 s | 2055 |
| OPNsense (ng_netflow) | yes | yes | - | - | none | 1800 s / 15 s | - |
| pfSense CE (softflowd) | yes, default | yes | yes (`-v 10`) | - | `-s` denominator | - | - |
| pfSense Plus 24.03+ (pflow) | yes | - | yes | - | - | - | 2055 |
| Ubiquiti UniFi | - | - | "NetFlow (IPFIX)", sampled | - | rate not stated | - | - |
| HPE Aruba AOS-CX *(unverified)* | - | - | yes | yes | sFlow 1 in 4096 | 1800 s / 30 s (10.15) | 4739; 6343 |

What it changes:

- **v5 is what the small end exports.** Sophos exports only v5, contrary to
  the spec's working assumption that it sends v9. MikroTik, OPNsense and both
  pfSense exporters offer v5, and softflowd defaults to it. Cisco, Juniper SRX
  and MikroTik can be configured for it.
- **The enterprise end is v9 or IPFIX.** PAN-OS and Meraki export only v9,
  Cisco Flexible NetFlow defaults to it, and FortiGate's NetFlow is v9. The
  spec's v9/IPFIX release gate stands.
- **Only Cisco and FortiGate say what the sampling rate is**, and only in a v9
  options template. A v5 record never says. That is the reason for the
  spec's rule that unknown sampling is never assumed to be 1:1.
- **30 minutes active, 15 seconds inactive is the common default.** A
  long-lived flow is therefore reported every 30 minutes. Receipt-time
  history will show it as a spike every half hour, and that is why the
  history is labelled *received traffic records* rather than bandwidth.
- **2055 is the common port**, but Cisco's documentation names 9995. The
  port field has to be free text, not a fixed value.

Sources:

- Cisco: [FNF command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fnetflow/command/fnf-cr-book.pdf), [IOS XE 17 FNF guide](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ntw-servs/b-network-services/m_fnf-fnetflow.html), [classic NetFlow export](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_pi/configuration/15-s/nf-15-s-book/cfg-nflow-data-expt.html), [classic command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/netflow/command/nf-cr-book.pdf)
- Fortinet: [`config system netflow` 7.6.0](https://docs.fortinet.com/document/fortigate/7.6.0/cli-reference/105185180/config-system-netflow), [sampling](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/667577/netflow-sampling), [templates](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/448589/netflow-templates), [NP7 NetFlow/IPFIX](https://docs.fortinet.com/document/fortigate/7.6.0/fortinet-carrier-grade-nat-field-reference-architecture-guide/811477/netflow-ipfix), [sFlow](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/505119/sflow)
- Palo Alto: [NetFlow monitoring](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/netflow-monitoring), [configure exports](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/netflow-monitoring/configure-netflow-exports), [10.2 server profile](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-web-interface-help/device/device-server-profiles-netflow)
- Juniper: [inline IPFIX templates](https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/services-ipfix-flow-template-flow-aggregation-configuring.html), [flow-active-timeout](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/flow-active-timeout-edit-forwarding-options.html), [flow-inactive-timeout](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/flow-inactive-timeout-edit-forwarding-options.html), [IPFIX for SRX J-Flow](https://www.juniper.net/documentation/en_US/junos/topics/concept/understanding-ipfix-formatting-for-existing-srx-j-flow-functionality.html), [flow-server](https://juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/ref/statement/flow-server-edit-forwarding-options-sv.html), [EX sFlow](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/example/sflow-configuring-ex-series.html)
- Meraki: [NetFlow overview](https://documentation.meraki.com/MX/Monitoring_and_Reporting/NetFlow_Overview)
- Sophos: [NetFlow configuration, SFOS 21.5](https://docs.sophos.com/nsg/sophos-firewall/21.5/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/NetflowConfiguration/index.html)
- MikroTik: [Traffic Flow](https://help.mikrotik.com/docs/spaces/ROS/pages/21102653/Traffic+Flow)
- OPNsense: [NetFlow](https://docs.opnsense.org/manual/netflow.html), [ng_netflow(4)](https://man.freebsd.org/cgi/man.cgi?query=ng_netflow&sektion=4&manpath=FreeBSD+14.0-RELEASE)
- pfSense: [pflow](https://docs.netgate.com/pfsense/en/latest/firewall/pflow.html), [softflowd recipe](https://docs.netgate.com/pfsense/en/latest/recipes/netflow-with-softflowd.html), [softflowd](https://github.com/irino/softflowd/wiki/softflowd)
- Ubiquiti: [Traffic Flows and Traffic Logging](https://help.ui.com/hc/en-us/articles/32201256219799-Traffic-Flows-and-Traffic-Logging-in-UniFi-Network)
- HPE Aruba *(unverified)*: [AOS-CX IPFIX](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.15/HTML/monitoring_8100-83xx-9300-10000/Content/Chp_flow/conf-ipfix.htm), [AOS-CX sFlow](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.17/HTML/ip_services_8100-83xx-93xx-100xx/Content/Chp_sFlow/sFlow_cmds/sfl-sam.htm)
