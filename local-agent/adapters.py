"""What the operating system knows about the adapter a capture is taken on.

A capture shows you the network as it looked from one point on it. What it
cannot show you is how that point was *configured*: which address the machine
was told to use, which gateway it was told to send through, which resolver it
was told to ask, and when the lease that granted all three runs out. Those are
facts about the machine, held by the machine, and a program running on it can
simply read them.

That makes this the second entry in the seam that `sockets.py` opened, and it
follows the same rule (`docs/decisions/0009-off-wire-enrichment.md`): **enrich
only from the captured machine, never from a third party.** Nothing here asks
the network a question. Nothing here reaches a server. Every value comes from
the kernel, the registry, or a tool that reads them.

The point of collecting it is the comparison. The capture independently reveals
most of the same facts - the gateway is whoever answers ARP for the router, the
resolvers are whoever was actually asked, the DHCP server is whoever sent the
ACK - so putting configured beside observed turns two half-answers into one
diagnosis. A resolver that is queried but not configured, or a gateway MAC that
does not match the neighbour table, is a finding rather than a curiosity.

**No text output is parsed.** Not `ipconfig`, not `ifconfig`, not `ipconfig
/all`. Those are written for a person and translated for their locale, and this
machine's own adapter is named `\\u200f\\u200fEthernet 2` with two right-to-left
marks in front of it - which is exactly the kind of thing that makes a regex
over display text a bug waiting for a different user. Every provider here reads
a structured source: the Windows registry through `winreg`, `ip -j` and
`resolvectl --json` on Linux, and JSON from PowerShell where nothing else
carries a field.

**Anything a provider cannot supply is None, and never a guess.** An adapter
whose lease time cannot be read reports no lease time. It does not report zero,
and it does not report the value from another adapter. `source` says which
provider answered for each group, so a value on screen can always be traced
back to where it came from.
"""
import ipaddress
import json
import os
import re
import subprocess
import sys

import psutil

WINDOWS = sys.platform == "win32"
DARWIN = sys.platform == "darwin"

# Windows keeps per-adapter TCP/IP configuration under the adapter's GUID.
# These are the two hives the brief names, and between them they carry DHCP
# state, lease times, static and DHCP-assigned resolvers, and the gateway.
_TCPIP4_INTERFACES = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
_TCPIP6_INTERFACES = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces"

# NL_SUFFIX_ORIGIN. The one value worth naming: an address whose suffix was
# generated at random is a privacy address - what `ipconfig /all` labels
# "Temporary" - and it rotates, so a capture taken yesterday will not match it.
# Compared as an integer deliberately: PowerShell renders these enums as numbers
# under ConvertTo-Json, and a number cannot be translated.
_SUFFIX_ORIGIN_RANDOM = 5

# Windows records the gateway's hardware address in DhcpGatewayHardware as a
# packed record per gateway: 4 bytes of IPv4 address, a 32-bit little-endian
# hardware length, then that many bytes of hardware address. Verified against
# a live machine, where 0a 00 00 8a | 06 00 00 00 | 44 15 24 aa bb cc decoded
# to 10.0.0.138 and 44:15:24:aa:bb:cc - the same pairing Get-NetNeighbor gives,
# without spawning anything.
_GATEWAY_HW_HEADER = 8


# Windows prefixes adapter names with right-to-left marks on a machine set to
# an RTL locale - this one reports `‏‏Ethernet 2`. `agent.py`'s
# build_interface_label already strips them from the capture list, and the two
# names have to match or the Network tab will not look like the picker.
_BIDI_MARKS = "‎‏‪‫‬‭‮"


def _text(value):
    """A registry or JSON value as a non-empty string, or None."""
    if value is None:
        return None
    text = str(value).strip().strip(_BIDI_MARKS).strip()
    return text or None


def _mac(value):
    """A MAC in the lowercase colon form every other part of this app uses."""
    text = _text(value)
    if text is None:
        return None
    text = text.replace("-", ":").lower()
    return text if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", text) else None


def _strip_zone(address):
    """Drops an IPv6 zone index, as `sockets.normalize_address` does.

    A captured frame carries `fe80::1`; the OS reports `fe80::1%8`. Comparing
    the two without this is how link-local traffic - which is most of what a
    quiet segment carries - ends up matching nothing.
    """
    text = _text(address)
    if text is None:
        return None
    at = text.find("%")
    return text if at == -1 else text[:at]


def address_scope(address):
    """`global`, `link-local`, `ula`, `loopback`, or None if unparseable.

    Grouping the IPv6 addresses is the whole readability of the Addresses
    section: a machine routinely holds four or five, and only one or two of
    them mean anything to somebody reading a capture.
    """
    try:
        parsed = ipaddress.ip_address(_strip_zone(address))
    except (ValueError, TypeError):
        return None
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link-local"
    if parsed.version == 6 and parsed.is_private and not parsed.is_global:
        # fc00::/7. `is_private` alone also catches link-local, which the
        # branch above has already taken.
        return "ula"
    return "global"


def _broadcast(address, prefix_length):
    """The IPv4 broadcast address, computed rather than reported.

    Windows does not report one at all (`psutil` returns None for every
    adapter), and it is a pure function of the address and the prefix, so
    computing it is not a guess - it is arithmetic the OS declined to do.
    """
    if address is None or prefix_length is None:
        return None
    try:
        network = ipaddress.ip_network(f"{address}/{prefix_length}", strict=False)
    except ValueError:
        return None
    return str(network.broadcast_address) if network.version == 4 else None


def _prefix_from_mask(mask):
    """A dotted-quad netmask as a prefix length."""
    text = _text(mask)
    if text is None:
        return None
    try:
        return ipaddress.ip_network(f"0.0.0.0/{text}", strict=False).prefixlen
    except ValueError:
        return None


def _run_json(argv, timeout=10):
    """Runs a command that speaks JSON and returns the parsed result, or None.

    Every provider that shells out goes through here, and every one of them
    asks for JSON. That is the whole defence against locale: a JSON key is a
    property name the tool chose, not a label translated for the reader.
    """
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            # Windows would otherwise flash a console window for each of these
            # when the agent runs interactively.
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    try:
        return json.loads(completed.stdout)
    except ValueError:
        return None


def _as_list(value):
    """PowerShell's ConvertTo-Json emits a bare object for a single-element
    collection and an array for more than one. Everything downstream wants a
    list, and a one-adapter machine is not a special case worth having a bug in.
    """
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# --- Windows ------------------------------------------------------------------


def read_registry_interface(guid):
    """Every value under both TCP/IP hives for one adapter GUID.

    IPv6 values are prefixed `v6_` so the two hives can share one flat dict
    without either shadowing the other.

    Readable without elevation - verified - which matters because the agent may
    run as a service but this module must also work when it is run by hand.
    """
    if not WINDOWS:
        return {}
    try:
        import winreg
    except ImportError:
        return {}

    values = {}
    for path, prefix in ((_TCPIP4_INTERFACES, ""), (_TCPIP6_INTERFACES, "v6_")):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path + "\\" + guid) as key:
                index = 0
                while True:
                    try:
                        name, value, _kind = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    values[prefix + name] = value
                    index += 1
        except OSError:
            # A missing key is the normal state for an adapter that has never
            # had that family configured, not an error.
            continue
    return values


def decode_gateway_hardware(blob):
    """`{ipv4 address: MAC}` from DhcpGatewayHardware, or an empty dict.

    Defensive about the record count rather than trusting
    DhcpGatewayHardwareCount: the count and the blob are two separate values
    that a half-written key could disagree about, and walking the blob until it
    runs out cannot read past the end.
    """
    if not isinstance(blob, (bytes, bytearray)):
        return {}
    out = {}
    at = 0
    while at + _GATEWAY_HW_HEADER <= len(blob):
        address = ".".join(str(b) for b in blob[at:at + 4])
        length = int.from_bytes(blob[at + 4:at + 8], "little")
        start = at + _GATEWAY_HW_HEADER
        if length <= 0 or start + length > len(blob):
            break
        mac = _mac(":".join(f"{b:02x}" for b in blob[start:start + length]))
        if mac is not None:
            out[address] = mac
        at = start + length
    return out


def _windows_ip_detail():
    """Prefix lengths, address origins, default routes and neighbours.

    One PowerShell invocation for all four, because a spawn costs about half a
    second measured and four of them would cost two. It is the only thing here
    that shells out on Windows, and it is needed for exactly one fact nothing
    else carries: whether an IPv6 address is a temporary one.

    `-Depth 4` because the default of 2 flattens the nested selections into
    type names. `SilentlyContinue` so an adapter-less machine returns empty
    collections rather than a non-zero exit.
    """
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "[pscustomobject]@{"
        " addr = @(Get-NetIPAddress | Select-Object InterfaceIndex,IPAddress,"
        "PrefixLength,AddressFamily,SuffixOrigin,PrefixOrigin);"
        " route = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' |"
        " Select-Object InterfaceIndex,NextHop,DestinationPrefix);"
        " neigh = @(Get-NetNeighbor | Where-Object { $_.LinkLayerAddress } |"
        " Select-Object InterfaceIndex,IPAddress,LinkLayerAddress)"
        "} | ConvertTo-Json -Depth 4 -Compress"
    )
    parsed = _run_json(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=20,
    )
    return parsed if isinstance(parsed, dict) else None


def _windows_adapters(if_list, stats, registry_reader, ip_detail):
    adapters = []
    detail = ip_detail or {}
    by_index = {}
    for row in _as_list(detail.get("addr")):
        by_index.setdefault(row.get("InterfaceIndex"), []).append(row)
    routes = _as_list(detail.get("route"))
    neighbours = _as_list(detail.get("neigh"))

    for entry in if_list:
        guid = _text(entry.get("guid"))
        if guid is None:
            continue
        # Two names, and they are not interchangeable. `raw_name` is the key
        # psutil reports its stats under, right-to-left marks and all; `name`
        # is the same string cleaned up for display, matching what the capture
        # picker shows. Looking the stats up by the cleaned name silently
        # returns nothing on an RTL machine, which is how speed, MTU and link
        # state all went null here once.
        raw_name = entry.get("name")
        name = _text(raw_name) or guid
        index = entry.get("index")
        values = registry_reader(guid)
        stat = stats.get(raw_name) or stats.get(name)

        # The device name Npcap capture uses, which is what the interface list
        # the app already has is keyed by. Building it here rather than matching
        # display names is what makes the join exact: `interface_stats.py` has to
        # do a longest-prefix match on the friendly name because it has no GUID
        # to work with, and that is a heuristic this does not need.
        device = "\\Device\\NPF_" + guid

        rows = by_index.get(index, [])
        prefix_by_address = {}
        temporary = set()
        for row in rows:
            address = _strip_zone(row.get("IPAddress"))
            if address is None:
                continue
            prefix_by_address[address] = row.get("PrefixLength")
            if row.get("SuffixOrigin") == _SUFFIX_ORIGIN_RANDOM:
                temporary.add(address)

        ipv4, ipv6 = [], []
        static_mask = _prefix_from_mask(values.get("SubnetMask"))
        dhcp_mask = _prefix_from_mask(values.get("DhcpSubnetMask"))
        for raw in entry.get("ips") or []:
            address = _strip_zone(raw)
            if address is None:
                continue
            try:
                version = ipaddress.ip_address(address).version
            except ValueError:
                continue
            prefix = prefix_by_address.get(address)
            if version == 4:
                if prefix is None:
                    prefix = static_mask if static_mask is not None else dhcp_mask
                ipv4.append({
                    "address": address,
                    "prefixLength": prefix,
                    "broadcast": _broadcast(address, prefix),
                })
            else:
                ipv6.append({
                    "address": address,
                    "prefixLength": prefix,
                    "scope": address_scope(address),
                    # Only ever True when the OS actually said so. Without the
                    # detail call this is False rather than None, because the
                    # claim being made is "known temporary", and an unmarked
                    # address is simply one nothing marked.
                    "temporary": address in temporary,
                })

        gateway_v4 = None
        for key in ("DhcpDefaultGateway", "DefaultGateway"):
            candidates = [g for g in _as_list(values.get(key)) if _text(g)]
            if candidates:
                gateway_v4 = _text(candidates[0])
                break
        gateway_v6 = None
        for route in routes:
            if route.get("InterfaceIndex") != index:
                continue
            hop = _strip_zone(route.get("NextHop"))
            if not hop or hop in ("0.0.0.0", "::"):
                continue
            if route.get("DestinationPrefix") == "::/0":
                gateway_v6 = hop
            elif gateway_v4 is None:
                gateway_v4 = hop

        # The registry's own answer first - it costs nothing and is already
        # read - then the neighbour table for anything it did not cover.
        gateway_macs = decode_gateway_hardware(values.get("DhcpGatewayHardware"))
        gateway_mac = gateway_macs.get(gateway_v4) if gateway_v4 else None
        if gateway_mac is None:
            for row in neighbours:
                if row.get("InterfaceIndex") != index:
                    continue
                if _strip_zone(row.get("IPAddress")) in (gateway_v4, gateway_v6):
                    gateway_mac = _mac(row.get("LinkLayerAddress"))
                    if gateway_mac is not None:
                        break

        dns = []
        for key in ("NameServer", "DhcpNameServer", "v6_NameServer"):
            text = _text(values.get(key))
            if text:
                dns.extend(part for part in re.split(r"[\s,]+", text) if part)
        for server in entry.get("nameservers") or []:
            text = _strip_zone(server)
            if text:
                dns.append(text)
        seen = set()
        dns_servers = [d for d in dns if not (d in seen or seen.add(d))]

        enable_dhcp = values.get("EnableDHCP")
        adapters.append({
            "id": device,
            "name": name,
            "description": _text(entry.get("description")),
            "mac": _mac(entry.get("mac")),
            "status": ("up" if stat.isup else "down") if stat else None,
            # psutil reports 0 for an adapter whose speed it cannot read, which
            # is not a speed. Only a positive number is an answer.
            "speedMbps": (stat.speed or None) if stat else None,
            "mtu": (stat.mtu or None) if stat else None,
            "dhcpEnabled": bool(enable_dhcp) if enable_dhcp is not None else None,
            "dhcpServer": _text(values.get("DhcpServer")),
            # Epoch seconds, as the registry stores them. Formatting a time is
            # the one job that genuinely belongs to whoever knows the reader's
            # locale, and that is the browser, not this.
            "leaseObtained": values.get("LeaseObtainedTime"),
            "leaseExpires": values.get("LeaseTerminatesTime"),
            "ipv4": ipv4,
            "ipv6": ipv6,
            "gatewayV4": gateway_v4,
            "gatewayV6": gateway_v6,
            "gatewayMac": gateway_mac,
            "dnsServers": dns_servers,
            "dnsSuffix": _text(values.get("Domain")) or _text(values.get("DhcpDomain")),
            "source": {
                "adapter": "windows_iflist",
                "addresses": "windows_iflist+powershell" if rows else "windows_iflist",
                "dhcp": "registry",
                "gateway": "registry" if gateway_macs else "powershell",
                "dns": "registry",
            },
        })
    return adapters


# --- Linux --------------------------------------------------------------------


def _linux_dns():
    """Resolvers and the search domain, from systemd-resolved or resolv.conf."""
    parsed = _run_json(["resolvectl", "--json=short", "status"])
    if isinstance(parsed, dict):
        servers, suffix = [], None
        for link in _as_list(parsed.get("LinkDNS")) + _as_list(parsed.get("DNS")):
            address = _text(link.get("Address") if isinstance(link, dict) else link)
            if address:
                servers.append(address)
        for domain in _as_list(parsed.get("LinkDomains")) + _as_list(parsed.get("Domains")):
            suffix = suffix or _text(domain.get("Domain") if isinstance(domain, dict) else domain)
        if servers:
            return servers, suffix, "resolvectl"

    servers, suffix = [], None
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                # Keyword-and-value, not prose: `resolv.conf` is a
                # configuration file with a fixed grammar, so this is parsing a
                # format rather than parsing a message written for a person.
                parts = line.split("#", 1)[0].split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
                elif len(parts) >= 2 and parts[0] in ("search", "domain"):
                    suffix = suffix or parts[1]
    except OSError:
        return [], None, None
    return servers, suffix, "resolv.conf"


def _linux_adapters(stats):
    links = _run_json(["ip", "-j", "addr"]) or []
    routes = _run_json(["ip", "-j", "route"]) or []
    neighbours = _run_json(["ip", "-j", "neigh"]) or []
    dns_servers, dns_suffix, dns_source = _linux_dns()

    gateway_by_link = {}
    for route in routes:
        if route.get("dst") in ("default", "0.0.0.0/0", "::/0") and route.get("gateway"):
            gateway_by_link.setdefault(route.get("dev"), []).append(route["gateway"])

    mac_by_address = {}
    for row in neighbours:
        address, mac = _strip_zone(row.get("dst")), _mac(row.get("lladdr"))
        if address and mac:
            mac_by_address[address] = mac

    adapters = []
    for link in links:
        name = _text(link.get("ifname"))
        if name is None:
            continue
        stat = stats.get(name)
        ipv4, ipv6 = [], []
        for info in link.get("addr_info") or []:
            address = _strip_zone(info.get("local"))
            if address is None:
                continue
            prefix = info.get("prefixlen")
            if info.get("family") == "inet":
                ipv4.append({
                    "address": address,
                    "prefixLength": prefix,
                    "broadcast": _text(info.get("broadcast")) or _broadcast(address, prefix),
                })
            elif info.get("family") == "inet6":
                ipv6.append({
                    "address": address,
                    "prefixLength": prefix,
                    "scope": address_scope(address),
                    # `ip` reports the RFC 4941 temporary flag directly, so on
                    # Linux this needs nothing extra.
                    "temporary": bool(info.get("temporary")),
                })

        gateway_v4 = gateway_v6 = None
        for gateway in gateway_by_link.get(name, []):
            try:
                if ipaddress.ip_address(_strip_zone(gateway)).version == 6:
                    gateway_v6 = gateway_v6 or gateway
                else:
                    gateway_v4 = gateway_v4 or gateway
            except ValueError:
                continue

        adapters.append({
            "id": name,
            "name": name,
            "description": _text(link.get("ifalias")),
            "mac": _mac(link.get("address")),
            "status": "up" if "UP" in (link.get("flags") or []) else "down",
            "speedMbps": (stat.speed or None) if stat else None,
            "mtu": link.get("mtu") or ((stat.mtu or None) if stat else None),
            # `ip` says nothing about how an address was obtained, and guessing
            # from the lease files below would be a guess. Only the lease read
            # can answer this, and it answers for itself.
            "dhcpEnabled": None,
            "dhcpServer": None,
            "leaseObtained": None,
            "leaseExpires": None,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "gatewayV4": gateway_v4,
            "gatewayV6": gateway_v6,
            "gatewayMac": mac_by_address.get(_strip_zone(gateway_v4))
                           or mac_by_address.get(_strip_zone(gateway_v6)),
            "dnsServers": list(dns_servers),
            "dnsSuffix": dns_suffix,
            "source": {
                "adapter": "ip",
                "addresses": "ip",
                "dhcp": None,
                "gateway": "ip",
                "dns": dns_source,
            },
        })
    _linux_apply_leases(adapters)
    return adapters


def _linux_apply_leases(adapters):
    """Fills DHCP lease details from whichever client wrote them, if any.

    Best-effort by design: which client is installed, and where it keeps its
    leases, is a property of the distribution rather than of the protocol. An
    adapter whose lease cannot be found keeps its Nones.
    """
    directories = (
        "/var/lib/NetworkManager", "/var/lib/dhcp", "/var/lib/dhclient",
        "/var/lib/dhcpcd",
    )
    for adapter in adapters:
        for directory in directories:
            try:
                names = os.listdir(directory)
            except OSError:
                continue
            for filename in names:
                if adapter["id"] not in filename:
                    continue
                try:
                    with open(os.path.join(directory, filename), "r",
                              encoding="utf-8", errors="replace") as handle:
                        body = handle.read()
                except OSError:
                    continue
                server = re.search(r"(?:dhcp-server-identifier|SERVER_ADDRESS)"
                                   r"[=\s]+([0-9.]+)", body)
                if server:
                    adapter["dhcpEnabled"] = True
                    adapter["dhcpServer"] = server.group(1)
                    adapter["source"]["dhcp"] = "lease-file"
                return


# --- macOS --------------------------------------------------------------------


def _darwin_run(argv, timeout=10):
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _darwin_lease(interface):
    """DHCP lease details from `ipconfig getpacket`.

    This is a decoded DHCP packet, not a status message: the keys are the
    protocol's own option names, so they are the same on every machine in every
    language. That is what makes reading them different in kind from parsing
    `ifconfig`.
    """
    body = _darwin_run(["ipconfig", "getpacket", interface])
    if not body:
        return {}
    server = re.search(r"server_identifier[^=]*=\s*([0-9.]+)", body)
    lease = re.search(r"lease_time[^=]*=\s*(?:0x([0-9a-fA-F]+)|(\d+))", body)
    out = {}
    if server:
        out["dhcpServer"] = server.group(1)
        out["dhcpEnabled"] = True
    if lease:
        out["leaseSeconds"] = int(lease.group(1), 16) if lease.group(1) else int(lease.group(2))
    return out


def _darwin_adapters(stats):
    addresses = psutil.net_if_addrs()
    gateway_line = _darwin_run(["route", "-n", "get", "default"])
    gateway_v4 = None
    found = re.search(r"gateway:\s*(\S+)", gateway_line)
    if found:
        gateway_v4 = _strip_zone(found.group(1))
    gateway_mac = None
    if gateway_v4:
        arp = _darwin_run(["arp", "-n", gateway_v4])
        mac = re.search(r"at\s+([0-9a-fA-F:]{11,17})\s", arp)
        if mac:
            # macOS prints a MAC with leading zeros omitted (`4:7c:16:...`).
            gateway_mac = _mac(":".join(part.rjust(2, "0")
                                        for part in mac.group(1).split(":")))

    scutil = _darwin_run(["scutil", "--dns"])
    dns_servers = list(dict.fromkeys(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", scutil)))
    suffix = re.search(r"domain\s*:\s*(\S+)", scutil)

    adapters = []
    for name, entries in addresses.items():
        stat = stats.get(name)
        mac, ipv4, ipv6 = None, [], []
        for entry in entries:
            if entry.family == psutil.AF_LINK:
                mac = _mac(entry.address)
            elif entry.family.name == "AF_INET":
                prefix = _prefix_from_mask(entry.netmask)
                ipv4.append({
                    "address": entry.address,
                    "prefixLength": prefix,
                    "broadcast": _text(entry.broadcast) or _broadcast(entry.address, prefix),
                })
            elif entry.family.name == "AF_INET6":
                address = _strip_zone(entry.address)
                ipv6.append({
                    "address": address,
                    "prefixLength": _prefix_from_mask(entry.netmask),
                    "scope": address_scope(address),
                    # Nothing cheap on macOS distinguishes a temporary address,
                    # and claiming False would be claiming knowledge. This is
                    # the one platform where the flag is honestly unknown.
                    "temporary": None,
                })
        lease = _darwin_lease(name)
        adapters.append({
            "id": name,
            "name": name,
            "description": None,
            "mac": mac,
            "status": ("up" if stat.isup else "down") if stat else None,
            "speedMbps": (stat.speed or None) if stat else None,
            "mtu": (stat.mtu or None) if stat else None,
            "dhcpEnabled": lease.get("dhcpEnabled"),
            "dhcpServer": lease.get("dhcpServer"),
            "leaseObtained": None,
            "leaseExpires": None,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "gatewayV4": gateway_v4,
            "gatewayV6": None,
            "gatewayMac": gateway_mac,
            "dnsServers": list(dns_servers),
            "dnsSuffix": _strip_zone(suffix.group(1)) if suffix else None,
            "source": {
                "adapter": "psutil",
                "addresses": "psutil",
                "dhcp": "ipconfig-getpacket" if lease else None,
                "gateway": "route",
                "dns": "scutil",
            },
        })
    return adapters


# --- the public reading -------------------------------------------------------


def read_adapters(provider=None, keep=None):
    """Every adapter this machine has, in the one schema the app knows.

    `provider` is injected so the tests can drive a platform's shape without
    being run on that platform - the same reason `sockets.read_socket_table`
    takes a `source`.

    `keep` narrows the result to a set of device ids, and the agent always
    passes the capture list. Windows reports **51** adapters here - every LWF
    binding, QoS scheduler, WAN miniport and Teredo tunnel - which is the same
    reason `agent.py:1341` refuses `get_windows_if_list()` for the capture list
    itself. Sending all of them would be 30 KB a message instead of 3, and
    would hand the browser the configuration of adapters the user is not
    capturing on, which the privacy rule for this data does not justify.
    """
    adapters = _read_all(provider)
    if keep is None:
        return adapters
    return [a for a in adapters if a["id"] in keep]


def _read_all(provider=None):
    if provider is not None:
        return provider()
    try:
        stats = psutil.net_if_stats()
    except Exception:
        stats = {}
    try:
        if WINDOWS:
            from scapy.arch.windows import get_windows_if_list
            return _windows_adapters(
                get_windows_if_list(), stats, read_registry_interface,
                _WindowsDetailCache.get(),
            )
        if DARWIN:
            return _darwin_adapters(stats)
        return _linux_adapters(stats)
    except Exception:
        # An adapter list nobody can read is a missing panel, never a stopped
        # capture. Same rule the socket loop follows.
        return []


class _WindowsDetailCache:
    """Caches the PowerShell reading, and re-takes it only when it can matter.

    The call is 0.48 s measured, and the poll is every 10 s - so re-running it
    unconditionally would spend 5% of a core spawning processes forever, in a
    process that is supposed to be invisible. Everything it returns is a
    function of the addresses the machine holds, so the address list is the
    cache key: when no address has changed, neither has a prefix length, an
    origin, a default route or the neighbour behind it.

    `invalidate()` is what `refresh_adapters` calls, so a user who has just
    changed something and pressed Refresh is answered from the machine rather
    than from a reading taken before they changed it.
    """

    _key = None
    _value = None

    @classmethod
    def get(cls):
        try:
            from scapy.arch.windows import get_windows_if_list
            key = tuple(sorted(
                (str(entry.get("guid")), tuple(sorted(str(i) for i in entry.get("ips") or [])))
                for entry in get_windows_if_list()
            ))
        except Exception:
            key = None
        if key is not None and key == cls._key and cls._value is not None:
            return cls._value
        value = _windows_ip_detail()
        cls._key, cls._value = key, value
        return value

    @classmethod
    def invalidate(cls):
        cls._key = None
        cls._value = None


def invalidate_caches():
    """Forgets anything cached, so the next read goes to the machine."""
    if WINDOWS:
        _WindowsDetailCache.invalidate()


class AdapterTracker:
    """Turns successive readings into a message, or into nothing.

    Unlike the socket table this sends whole snapshots rather than deltas, and
    that is a size judgement rather than an inconsistency: a machine has a
    handful of adapters and the whole list is a couple of kilobytes, where the
    socket table is 890 entries and 52 KB. A delta protocol for two kilobytes
    would cost more in complexity than it could ever save in bytes.

    What it does share is the silence. Adapter configuration changes when a
    lease renews or a cable moves - minutes or hours apart - so the common poll
    is one that has nothing to say, and saying nothing is the right answer.
    """

    def __init__(self, provider=None, keep=None):
        self._provider = provider
        # A callable rather than a set, because the capture list is re-read
        # whenever a client connects and a tracker that captured it once would
        # go on reporting an adapter that has since been unplugged.
        self._keep = keep
        self._previous = None

    def reset(self):
        """Forgets the last reading, so the next poll always sends."""
        self._previous = None

    def poll(self):
        """The next message for subscribers, or None when nothing changed."""
        adapters = read_adapters(self._provider, self._keep() if self._keep else None)
        # Compared by value rather than by a hash or a timestamp: the whole
        # message is small, and the comparison is the only thing standing
        # between "the lease clock ticked" and a re-render every ten seconds.
        if self._previous is not None and adapters == self._previous:
            return None
        self._previous = adapters
        return {"type": "adapter_config", "adapters": adapters}
