"""Identify a configured LAN host using the router's neighbour cache."""

import ipaddress
from pathlib import Path
import subprocess

from packets import Device, MAC_PATTERN


def macs_from_neighbours(lines, address, interface):
    for line in lines.splitlines():
        fields = line.split()
        if not fields or fields[0] != str(address) or "lladdr" not in fields:
            continue
        if interface != "any" and ("dev" not in fields or
                                   fields[fields.index("dev") + 1:][:1] != [interface]):
            continue
        if "FAILED" in fields or "INCOMPLETE" in fields or "NOARP" in fields:
            continue
        for mac in fields[fields.index("lladdr") + 1:][:1]:
            if MAC_PATTERN.fullmatch(mac):
                yield mac.lower()


def macs_from_arp(lines, address, interface):
    for line in lines.splitlines():
        fields = line.split()
        if (len(fields) == 6 and fields[0] == str(address) and fields[1] == "0x1"
                and fields[2] in ("0x2", "0x6") and MAC_PATTERN.fullmatch(fields[3])
                and (interface == "any" or fields[5] == interface)):
            yield fields[3].lower()


def neighbour_macs(address, interface):
    command = ["ip", f"-{address.version}", "neigh", "show", "to", str(address)]
    if interface != "any":
        command += ["dev", interface]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, errors="replace",
                                timeout=0.5, check=False)
        if result.returncode == 0:
            matches = set(macs_from_neighbours(result.stdout, address, interface))
            if matches:
                return matches
    except (OSError, subprocess.TimeoutExpired):
        pass
    if address.version == 4:
        try:
            return set(macs_from_arp(Path("/proc/net/arp").read_text(), address, interface))
        except OSError:
            pass
    return set()


def capture_device(device, interface, previous_mac=None):
    if device.mac:
        return device
    resolved = set()
    for packed in sorted(device.addresses):
        matches = neighbour_macs(ipaddress.ip_address(packed), interface)
        if len(matches) != 1:
            break
        resolved.update(matches)
        if len(resolved) > 1:
            break
    else:
        mac = resolved.pop()
        if previous_mac and previous_mac != mac:
            raise ValueError("当前 IP 的 MAC 与基线不同，请为这台 Xbox 重新录制基线。")
        try:
            return Device(mac)
        except ValueError:
            return device
    return Device(previous_mac) if previous_mac else device
