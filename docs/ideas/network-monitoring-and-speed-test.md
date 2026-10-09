# Network monitoring and a speed test: what the market teaches

> **Nothing here exists yet.** This is the research behind two features the
> owner intends to build: network-wide bandwidth monitoring "kinda like
> NetFlow", and an internet speed test. Each gets an ADR when it is started;
> this file is what those ADRs start from. Researched 2026-10-08.

What is already in the tree and is the foundation for the first one:

- `src/services/flow/flowExport.ts` decodes NetFlow v5/v9 and IPFIX into
  normalised flow records (addresses, ports, protocol, bytes, packets, absolute
  start/end, interfaces, AS numbers, VLAN, sampling interval).
  `MemoryTemplateStore(replace = true)` is the store a collector wants; the
  packet tree uses first-definition-wins only because the reference does.
- `src/services/flow/sflow.ts` decodes sFlow v5: `sampledPackets()` and
  `interfaceReadings()` - ifIndex, ifSpeed, 64-bit octets in/out, errors,
  discards, with the agent's uptime to turn them into rates.
- `dissectors/snmp.ts`, and the whole local capture with TCP analysis.

## Part 1 - network-wide flow monitoring

### Who was studied

PRTG, SolarWinds NTA, ManageEngine NetFlow Analyzer, ntopng + nProbe, Plixer
Scrutinizer, Kentik, Auvik TrafficInsights, ElastiFlow, LibreNMS / Observium /
Zabbix, GlassWire / NetLimiter, and Wireshark's own Statistics menu.

### What they agree on

**Four ways in, and Inwire already reads two.** Flow export (NetFlow, IPFIX,
sFlow flow samples); **sFlow counter samples**, which carry ifSpeed and 64-bit
in/out octets, discards and errors every 20-120 s - SNMP-grade utilisation
with no polling at all ([sFlow v5](https://sflow.org/sflow_version_5.txt));
SNMP ifHC* polling; and local packet capture.

**"Overload" is a threshold with hysteresis and a sustain, per direction.**
SolarWinds fires a top-talker alert at 75% and resets below 50%
([NTA alerts](https://documentation.solarwinds.com/en/success_center/nta/content/nta-netflow-specific-predefined-alerts-sw1797.htm));
LibreNMS defaults to 80% and the community adds a 30-minute delay; Zabbix to
90%, overridable per interface, with interface errors as a separate trigger
([Zabbix Cisco template](https://www.zabbix.com/integrations/cisco_snmp));
ManageEngine's rule is "% utilisation, N times within a window"
([alert profile](https://www.manageengine.com/products/netflow/blog/alert-profile-in-netflow-analyzer.html)).
PRTG has the 95th percentile but only in reports. Kentik alerts against a
historical baseline. 32-bit counters wrap in 34 s at 1 Gb/s, so 64-bit only.

**Utilisation % is only as right as the link speed.** ManageEngine computes
actual/link speed from SNMP or a typed value, and a wrong speed is a wrong
percentage
([blog](https://www.manageengine.com/products/netflow/blog/interface-link-speed-vs-interface-bandwidth-command-what-netflow-analyzer-reports.html)).
Plixer keeps a per-interface totals table so utilisation does not depend on
SNMP at all
([aggregation](https://docs.plixer.com/projects/plixer-scrutinizer-docs/en/latest/features_and_functionality/fnf_aggregation.html)).

**Retention is raw-for-hours, rolled-up-forever.** ManageEngine: raw flows
1 h-1 month, top 100 per interface per 10 min kept forever, rolled to
hourly/daily/weekly
([storage](https://www.manageengine.com/products/netflow/help/storage-settings-netflow.html)).
Plixer: 1m -> 5m -> 30m -> 2h -> 12h, summaries drop ports. SolarWinds keeps
1-minute detail for an hour.

### What goes wrong for their users - and is the product

Every one of these has a vendor knowledge-base article, which is the tell that
the product could have explained it instead:

- **Spikes from a long active timeout.** A 30-minute flow lands in one minute.
  ManageEngine and Auvik each publish the fix (active timeout 60 s)
  ([ManageEngine](https://www.manageengine.com/products/netflow/help/troubleshoot-incorrect-spikes-in-4-steps.html),
  [Auvik](https://support.auvik.com/hc/en-us/articles/360035298792-Avoiding-traffic-spikes-caused-by-NetFlow-configuration)).
  Spread a flow's bytes across its start-end interval rather than its export
  minute, and when an exporter's flows are long, say why the chart is spiky.
- **Sampling.** PRTG makes you type the rate and is wrong if it differs from
  the device; ElastiFlow learns it from options data and a forum thread reports
  a 6.24 GB transfer showing as 1.4 GB. Kentik shows the **actual vs configured
  rate** with a yellow/red marker
  ([flow overview](https://kb.kentik.com/docs/flow-overview.md)). Show the rate
  in effect, where it came from, and mark every sampled number as an estimate.
- **Templates.** v9/IPFIX data before its template is lost; refresh is often
  30 minutes; ElastiFlow calls "template not received" normal for 15-30 min
  ([FAQ](https://docs.elastiflow.com/additional-resources-reference-articles/faq/flow_template_not_received)).
  Say "waiting for template" per exporter, and put `template data timeout 60`
  in the onboarding snippet.
- **Clocks.** Exporters run hours off; v5 is uptime-relative and wraps at 49.7
  days. Plixer buckets by export time only when the exporter is within a
  minute of the collector, otherwise by arrival time; OpenNMS moved to
  per-exporter windows after one skewed exporter closed everyone's.
- **Licensing and weight.** Per-sensor (PRTG) and per-interface (ManageEngine)
  licensing, server-grade setups (ManageEngine, the Elastic stack under
  ElastiFlow), alerting held back for paid tiers (ntopng), nProbe's licence
  cut-off. A desktop app with none of that is a position, not a gap.
- **No sub-second view.** 5-minute averages hide microbursts; discards at low
  utilisation almost always mean them
  ([Netdata](https://www.netdata.cloud/guides/network/network-interface-discards/)).
  Fortinet's technique is Wireshark's I/O Graph at 1 ms
  ([Fortinet](https://community.fortinet.com/fortigate-3/troubleshooting-tip-detecting-microburst-congestion-using-wireshark-227843)).
  **Only a packet capture can show this**, which is Inwire's unique angle.

### Feasibility on one machine

A small or medium site exports hundreds to a few thousand flows a second
(Plixer sizes 25 exporters at 1,500 fps; ntopng tops out near 35 kfps per
interface). The store measured ~31,000 frames/s, so ingest is not the limit;
storage is - 1,000 fps is 86 M flows a day, 5-13 GB raw. Hence the
raw-for-hours, rolled-up-forever shape, inside the capture store's own files,
deleted only under a setting the user chose (ADR 0012, 0052).

**Who owns the UDP port** is the decision that wants an ADR, because ADR 0033
keeps hostile bytes out of the privileged agent:

| | How | Cost |
|---|---|---|
| **A. Passive capture** | The agent captures `udp port 2055 or 4739 or 6343 or 9995 or 9996` with the capture filter it already has (ADR 0050); datagrams take the existing frame path to the Worker. No socket at all. | A capture must run on that adapter. Npcap sees frames below the firewall, so no prompt - but with no listener the host may answer ICMP port-unreachable to the exporter. **Measure that first.** |
| **B. Unprivileged socket** | A `utilityProcess` binds the port and forwards opaque datagrams to the Worker, as main forwards pipe batches. | Windows' "allow access" prompt, unless the elevated installer pre-creates a program-scoped inbound UDP rule on private/domain profiles. |
| ~~C. Agent socket~~ | The LocalSystem agent binds it. | A network-facing surface on a privileged service. Against ADR 0033's spirit. No. |

SNMP polling, if added, is outbound only, belongs in an unprivileged process,
and its community string stays in main like the key log path does.

### What to build, in order

**First - the MVP**

1. **Exporters appear and are approved** (Auvik). A row per exporter: address,
   protocol and version, flows/s, template status, **sampling rate and its
   source** ("1:1024 from options data" / "assumed 1:1" / typed), clock offset.
2. **Interface utilisation from sFlow counter samples**, then from flow totals
   against an editable link speed. In and out as % of link speed
   (SolarWinds' unit toggle), discards and errors as their own line (Zabbix).
3. **One chart with brush-to-drill.** Brush a range; below it, Top Talkers,
   Top Applications, Top Conversations, each with its **share of the link** -
   the report SolarWinds users asked for and could not get. Missing intervals
   are gaps, never zeros.
4. **An overload rule with good defaults**: above 80% for 3 of 5 minutes,
   clears below 60%, overridable per interface. Local notification only.
5. **Onboarding snippets** filled in with this PC's address and the right
   timeouts, for Cisco FNF, Juniper, MikroTik, FortiGate, pfSense/softflowd,
   Ubiquiti (Plixer's exporter library, Auvik's guides).

**Second**

6. **This machine's bandwidth by process** - GlassWire's timeline, built from
   the local capture and the agent's socket table (ADR 0009). Needs no router,
   so it is where most users of this app start.
7. **95th percentile as a live line**, not only in a report.
8. **Retention settings with predicted disk use.**
9. **SNMP ifHC\* polling** for devices that cannot export.
10. **Flows from Inwire's own captures** - the same views over a pcap or a live
    capture (ntopng's model).

**Later**

11. Baselines ("this hour vs the same hour, last four weeks") and "new top
    destination" rules (Kentik).
12. **The microburst lens**: from a discards alert, jump to a 1 ms I/O graph
    of the local capture at that moment. No flow tool can do this.
13. Sankey src -> application -> dst (Kentik), and flows in the PDF report.

Throughout: **clicking a talker opens the display filter** (`ip.addr == x`)
over the capture - the flow-to-packet pivot ntopng sells and Inwire already
has.

## Part 2 - an internet speed test

> **Built - ADR 0054 (2026-10-09).** Cloudflare, our own engine, a Network
> panel section and a sheet. What is below stays as the research it was;
> where the build measured something different (latency from the server's
> TCP RTT, 5 MB requests, 600/200 MB caps), the ADR is the record. Tagging
> the test's frames and the per-connection diagnosis are the next steps.

### Who was studied

Ookla Speedtest, Netflix fast.com, Cloudflare's speed test, M-Lab NDT7 (which
Google's uses), LibreSpeed, Waveform's bufferbloat test, nPerf, Apple's
`networkQuality` / the IETF responsiveness draft, and iperf3.

### Who can be used at all

- **Ookla, fast.com, nPerf: no.** No public API; Ookla's CLI licence is
  personal non-commercial and embedding is a paid "Speedtest Custom" licence.
- **Cloudflare: yes, as the default.** `GET /__down?bytes=N`, `POST /__up`; the
  `@cloudflare/speedtest` library is MIT. Its method: sequential transfers
  from 100 kB to 250 MB, per-request speed net of server time, the 90th
  percentile; idle latency the median of 20 empty requests; loaded latency
  sampled during transfers. **Its library posts results to
  `speed.cloudflare.com/__results` by default** - port the method, do not ship
  the library. It also deliberately under-saturates fast links.
- **M-Lab NDT7: yes, opt-in only.** One BBR TCP stream over WebSocket for
  ~10 s, server chosen by `locate.measurementlab.net`, no key; the server
  streams its own TCP_INFO (retransmits, RTT, what limited it). **M-Lab
  publishes every client's IP address publicly and permanently** and requires
  informed consent before the test. 40 tests per client per day.
- **LibreSpeed / iperf3: a server the user names.** For self-hosted and LAN
  tests. LibreSpeed's public server list has no usage policy, so it is not a
  default.

### How to measure

Idle latency, then download, then upload. Four parallel connections, adding
up to 8-16 while the total still rises; 10 s per direction (15 s above
1 Gb/s); random, incompressible upload bodies. Count bytes in 100 ms slices,
drop the first 2 s (slow start), report the median with the 10th and 90th
percentiles. Probe latency every 100-200 ms on a separate connection
throughout, and report **loaded latency** beside idle, in ms and in RPM
(60,000 / RTT). Grade bufferbloat on loaded minus idle latency (the bands in
common use: A+ < 5 ms, A < 30, B < 60, C < 200, D < 400, F above - not
confirmed from Waveform's own page). Do not claim packet loss; report the
retransmission rate from the capture instead.

### Where it runs

**Main, not the renderer.** The renderer's CSP stays as it is; the hosts go in
`MAIN_OUTBOUND_HOSTS` with their purposes, like the update feed and npcap.com,
and `scripts/electron/shell.ts` holds them absent from the policy. The renderer
picks a backend and never passes a URL. Use Node's own HTTP/WebSocket clients
rather than `net.fetch`: Chromium's stack may negotiate HTTP/3 to Cloudflare,
which would put the test on QUIC where the TCP analysis cannot see it, and
Node lets main know each connection's local port. One click per test, the
consent copy says which company sees the address, and M-Lab has its own.

### The Inwire angle - why a packet analyzer's speed test is different

Every other speed test reports a number. This one can say **why**:

- Main knows each test connection's 5-tuple and timing, so those frames can be
  **tagged in the capture** ("speed test - download, stream 3/6"), filtered
  and coloured.
- A capture during the test - filtered to the test servers, 128-byte snaplen
  so it costs nothing at gigabit (ADR 0050) - feeds the existing TCP analysis,
  per connection: **receive-window limited** (window full, no loss),
  **loss-limited** (retransmissions clustered where throughput dips),
  **bufferbloat** (RTT climbs steadily under load), **sender-limited** (gaps
  with nothing in flight), and **competing traffic** (other flows in the
  capture during the test).
- With NDT7, the server's own TCP_INFO can sit beside the capture's view of
  the same connection.

A LAN test is an iperf3-compatible client in main against a host running
`iperf3 -s`. Inwire stays a client: no listening port, and the agent never
gets one.

### Results

Download, upload, idle and loaded latency, jitter, bufferbloat grade,
retransmission rate, server and its location, and the diagnosis above. History
in a local file, never uploaded.

## How the two meet

A speed test is the flow monitor's best demo: the test's flows land in the
same Top Talkers and utilisation chart, and an overload during a test is the
first thing the microburst lens should look at.
