"""List LAN clients found in the router's neighbours and DHCP leases."""

from collections import defaultdict
import ipaddress
import json
from pathlib import Path
import subprocess
import time

from packets import MAC_PATTERN

MAX_DEVICES = 512


def command(*args):
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                errors="replace", timeout=0.8, check=False)
        return result.stdout if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def ubus(object, method, args=None):
    output = command("ubus", "-t", "1", "call", object, method, json.dumps(args or {}))
    try:
        result = json.loads(output)
    except ValueError:
        return {}
    return result if isinstance(result, dict) else {}


def read_file(path):
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def address(value):
    try:
        ip = ipaddress.ip_address(value.split("/", 1)[0].split("%", 1)[0])
    except (ValueError, AttributeError):
        return None
    return ip if not (ip.is_loopback or ip.is_unspecified or ip.is_multicast) else None


def mac_address(value):
    if isinstance(value, str) and MAC_PATTERN.fullmatch(value):
        raw = bytes.fromhex(value.replace(":", ""))
        if any(raw) and not raw[0] & 1:
            return value.lower()
    return None


def device_name(value):
    if not isinstance(value, str):
        return ""
    value = value.strip()[:80]
    return value if value not in {"*", "-"} and value.isprintable() else ""


def interface_scopes(networks, selected):
    scopes = defaultdict(set)
    if selected != "any":
        scopes[selected]
    for network in networks:
        device = network.get("l3_device") or network.get("device")
        logical = network.get("interface", "")
        if not device or device in {"lo", "any"} or not network.get("up", False):
            continue
        if device != selected and (
            logical.startswith(("wan", "wwan")) or
            (logical != "lan" and any(route.get("mask") == 0 for route in network.get("route", [])))
        ):
            continue
        valid = scopes[device]
        for group in ("ipv4-address", "ipv6-address", "ipv6-prefix-assignment"):
            for item in network.get(group, []):
                try:
                    prefix = ipaddress.ip_network((item.get("address"), item.get("mask")), strict=False)
                except (ValueError, TypeError):
                    continue
                if prefix.prefixlen:
                    valid.add(prefix)
    if not scopes:
        scopes["br-lan"]
    return scopes


def neighbour_rows(lines, arp, scopes):
    for line in lines.splitlines():
        fields = line.split()
        if not fields or not {"dev", "lladdr"}.issubset(fields) or {"FAILED", "INCOMPLETE", "NOARP"} & set(fields):
            continue
        dev = fields[fields.index("dev") + 1:][:1]
        mac = fields[fields.index("lladdr") + 1:][:1]
        if dev and mac and dev[0] in scopes:
            yield dev[0], address(fields[0]), mac_address(mac[0])
    for line in arp.splitlines():
        fields = line.split()
        if len(fields) == 6 and fields[1] == "0x1" and fields[2] in {"0x2", "0x6"} and fields[5] in scopes:
            yield fields[5], address(fields[0]), mac_address(fields[3])


def dnsmasq_leases(lines, now):
    for line in lines.splitlines():
        fields = line.split()
        if len(fields) < 4 or not fields[0].isdigit():
            continue
        expiry = int(fields[0])
        if not expiry or expiry > now:
            yield {"macaddr": fields[1], "ipaddr": fields[2], "hostname": fields[3]}


def device_records(scopes, neighbours, leases, names):
    devices = {}
    bindings = {}

    def add(interface, ip, mac, name=""):
        device = devices.setdefault(mac, {"ips": set(), "interfaces": set(), "name": ""})
        device["ips"].add(ip)
        device["interfaces"].add(interface)
        if name and not device["name"]:
            device["name"] = name

    for interface, ip, mac in neighbours:
        if ip and mac:
            # Prefer a recent kernel neighbour to a dnsmasq lease or ARP fallback.
            owner = bindings.setdefault(ip, {}).setdefault(interface, mac)
            if owner == mac:
                add(interface, ip, mac)

    for lease in leases:
        expires = lease.get("expires")
        if type(expires) is int and expires <= 0:
            continue
        name = device_name(lease.get("hostname"))
        mac = mac_address(lease.get("macaddr"))
        ips = [lease.get("ipaddr"), lease.get("ip6addr"), *lease.get("ip6addrs", [])]
        for value in ips:
            ip = address(value)
            if ip is None:
                continue
            current = bindings.get(ip)
            if current:
                for dev, owner in current.items():
                    if mac is None or owner == mac:
                        add(dev, ip, owner, name)
                continue
            if not mac:
                continue
            matching_scopes = [(prefix.prefixlen, dev) for dev, prefixes in scopes.items()
                               for prefix in prefixes if ip.version == prefix.version and ip in prefix]
            if matching_scopes:
                longest = max(length for length, _ in matching_scopes)
                interfaces = {dev for length, dev in matching_scopes if length == longest}
                if len(interfaces) == 1:
                    add(interfaces.pop(), ip, mac, name)

    records = [{
        "mac": mac,
        "name": names.get(mac) or info["name"],
        "ips": [str(ip) for ip in sorted(info["ips"], key=lambda ip: (ip.version, ip.is_link_local, int(ip)))[:16]],
        "interfaces": sorted(info["interfaces"]),
    } for mac, info in devices.items()]
    return sorted(records, key=lambda row: (not row["name"], row["name"].casefold(), row["ips"][0], row["mac"]))


def discover_devices(selected):
    scopes = interface_scopes(ubus("network.interface", "dump").get("interface", []), selected)
    if not any(scopes.values()):
        for dev in scopes:
            for line in command("ip", "addr", "show", "dev", dev).splitlines():
                fields = line.split()
                if len(fields) > 1 and fields[0] in {"inet", "inet6"}:
                    try:
                        scopes[dev].add(ipaddress.ip_interface(fields[1]).network)
                    except ValueError:
                        pass
    neighbours = neighbour_rows(command("ip", "neigh", "show"), read_file("/proc/net/arp"), scopes)
    data = ubus("luci-rpc", "getDHCPLeases")
    leases = data.get("dhcp_leases", []) + data.get("dhcp6_leases", [])
    if not data:
        leases = dnsmasq_leases(read_file("/tmp/dhcp.leases"), int(time.time()))
    names = {}
    for host in ubus("uci", "get", {"config": "dhcp", "type": "host"}).get("values", {}).values():
        name = device_name(host.get("name"))
        if not name:
            continue
        addresses = host.get("mac", [])
        if isinstance(addresses, str):
            addresses = addresses.split()
        for item in addresses:
            mac = mac_address(item)
            if mac:
                names[mac] = name
    records = device_records(scopes, neighbours, leases, names)
    return records[:MAX_DEVICES], len(records) > MAX_DEVICES
