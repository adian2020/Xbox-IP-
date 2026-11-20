"""Extract destination addresses, DNS questions and TLS ClientHello names."""

from collections import OrderedDict
from functools import lru_cache
import ipaddress
import re
import struct
import time

SNAPLEN = 8192
MAX_PACKET = 262144
MAX_STREAM = 16384
MAX_FLOWS = 128
FLOW_TIMEOUT = 30

LINK_ETHERNET = 1
LINK_SLL = 113
LINK_SLL2 = 276
VLAN_TYPES = (0x8100, 0x88A8, 0x9100)
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
MAC_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
DOMAIN_PATTERN = re.compile(rb"[a-zA-Z0-9_-]{1,63}(?:\.[a-zA-Z0-9_-]{1,63})+")


def number(data, offset, length=2):
    return int.from_bytes(data[offset:offset + length], "big")


class Device:
    def __init__(self, value):
        if not isinstance(value, str):
            raise ValueError("请输入 Xbox 的 MAC 地址或局域网 IP。")
        value = value.strip()
        self.mac = None
        self.addresses = set()
        if MAC_PATTERN.fullmatch(value):
            self.mac = bytes.fromhex(value.replace(":", ""))
            if self.mac[0] & 1 or not any(self.mac):
                raise ValueError("请输入 Xbox 的单播 MAC 地址。")
            self.label = value.lower()
            self.filter = "ether src " + self.label
            return

        if not 1 <= len(value.split(",")) <= 4 or "%" in value:
            raise ValueError("请输入 MAC 地址，或用逗号分隔最多 4 个 IP。")
        try:
            addresses = list(dict.fromkeys(
                ipaddress.ip_address(item.strip()) for item in value.split(",")
            ))
        except ValueError:
            raise ValueError("请输入有效的 MAC、IPv4 或 IPv6 地址。") from None
        if any(addr.is_unspecified or addr.is_multicast or addr.is_loopback
               or str(addr) == "255.255.255.255" for addr in addresses):
            raise ValueError("请输入 Xbox 的单播局域网 IP。")
        self.addresses = {addr.packed for addr in addresses}
        self.label = ", ".join(str(addr) for addr in addresses)
        self.filter = " or ".join("src host " + str(addr) for addr in addresses)


def capture_filter(device, cooked=False, vlan=False):
    if cooked and device.mac:
        # Linux cooked v2 records the sender's link-layer address on ingress.
        prefix = int.from_bytes(device.mac[:4], "big")
        suffix = int.from_bytes(device.mac[4:], "big")
        return (
            "link[8:2] = 1 and link[10] != 4 and link[11] = 6"
            f" and link[12:4] = 0x{prefix:08x} and link[16:2] = 0x{suffix:04x}"
        )
    if vlan and not device.mac:
        return f"({device.filter}) or (vlan and ({device.filter}))"
    return device.filter


def read_pcap(source):
    header = source.read(24)
    if not header:
        return
    endian = PCAP_MAGIC.get(header[:4])
    if not endian or len(header) != 24:
        raise ValueError("抓包程序没有提供有效的 PCAP 文件头。")
    major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", header[4:])
    link &= 0xffff
    if (major, minor) != (2, 4) or not 1 <= snaplen <= MAX_PACKET:
        raise ValueError("抓包程序提供了不支持的 PCAP 格式。")
    if link not in (LINK_ETHERNET, LINK_SLL, LINK_SLL2):
        raise ValueError("此接口的抓包格式不支持所选地址。请使用 Xbox 所在的 LAN 接口。")

    packet_header = struct.Struct(endian + "IIII")
    while True:
        header = source.read(packet_header.size)
        if not header:
            return
        if len(header) != packet_header.size:
            raise ValueError("PCAP 数据包文件头不完整。")
        _, _, size, original_length = packet_header.unpack(header)
        if size > snaplen or size > original_length:
            raise ValueError("PCAP 数据包长度无效。")
        frame = source.read(size)
        if len(frame) != size:
            raise ValueError("PCAP 数据包不完整。")
        yield link, frame


def network_packet(link, frame, device):
    if link == LINK_ETHERNET:
        if len(frame) < 14 or (device.mac and frame[6:12] != device.mac):
            return
        ethertype, offset = number(frame, 12), 14
    elif link == LINK_SLL:
        if len(frame) < 16 or (device.mac and (
            number(frame, 0) == 4 or number(frame, 2) != 1 or
            number(frame, 4) != 6 or frame[6:12] != device.mac
        )):
            return
        ethertype, offset = number(frame, 14), 16
    elif link == LINK_SLL2:
        if len(frame) < 20 or (device.mac and (
            number(frame, 8) != 1 or frame[10] == 4 or
            frame[11] != 6 or frame[12:18] != device.mac
        )):
            return
        ethertype, offset = number(frame, 0), 20
    else:
        return

    for _ in range(4):
        if ethertype not in VLAN_TYPES:
            break
        if offset + 4 > len(frame):
            return
        ethertype = number(frame, offset + 2)
        offset += 4

    data = memoryview(frame)[offset:]
    if ethertype == 0x0800 and len(data) >= 20 and data[0] >> 4 == 4:
        start = (data[0] & 0x0f) * 4
        end = number(data, 2)
        if start < 20 or start > len(data) or start > end:
            return
        source, dest = bytes(data[12:16]), bytes(data[16:20])
        if device.addresses and source not in device.addresses:
            return
        fragmented = number(data, 6) & 0x3fff
        return source, dest, data[9], data[start:end] if not fragmented else data[:0]

    if ethertype == 0x86dd and len(data) >= 40 and data[0] >> 4 == 6:
        source, dest = bytes(data[8:24]), bytes(data[24:40])
        if device.addresses and source not in device.addresses:
            return
        protocol, start = data[6], 40
        data = data[:40 + number(data, 4)]
        for _ in range(8):
            if protocol not in (0, 43, 44, 51, 60, 135):
                return source, dest, protocol, data[start:]
            if start + 2 > len(data):
                break
            next_protocol, length = data[start:start + 2]
            if protocol == 44:
                if start + 8 > len(data) or number(data, start + 2) & 0xfff9:
                    break
                start += 8
            elif protocol == 51:
                start += (length + 2) * 4
            else:
                start += (length + 1) * 8
            if start > len(data):
                break
            protocol = next_protocol
        return source, dest, 0, data[:0]


def domain_name(value):
    if len(value) <= 253 and DOMAIN_PATTERN.fullmatch(value):
        return value.decode("ascii").lower()
    return None


def dns_name(data, start):
    labels = []
    position = start
    following = None
    total = 0
    for _ in range(128):
        if position >= len(data):
            break
        size = data[position]
        if size == 0:
            return domain_name(b".".join(labels)), following or position + 1
        if size & 0xc0 == 0xc0 and position + 1 < len(data):
            target = number(data, position) & 0x3fff
            if not 12 <= target < position:
                break
            if following is None:
                following = position + 2
            position = target
            continue
        if size > 63 or position + 1 + size > len(data):
            break
        total += size + 1
        if total > 254:
            break
        label = bytes(data[position + 1:position + 1 + size])
        if b"." in label:
            break
        labels.append(label)
        position += size + 1
    raise ValueError("invalid DNS name")


def dns_questions(data):
    if len(data) < 12 or data[2] & 0xf8:
        return set()
    count, offset = number(data, 4), 12
    if not 1 <= count <= 32:
        return set()
    domains = set()
    try:
        for _ in range(count):
            domain, offset = dns_name(data, offset)
            if offset + 4 > len(data):
                return set()
            if domain:
                domains.add(domain)
            offset += 4
    except ValueError:
        return set()
    return domains


def client_hello_name(hello):
    if len(hello) < 39:
        return None
    start = 35 + hello[34]
    for size_length in (2, 1):
        if start + size_length > len(hello):
            return None
        start += size_length + number(hello, start, size_length)
    end = start + 2 + number(hello, start)
    if start + 2 > len(hello) or end != len(hello):
        return None
    start += 2
    while start + 4 <= end:
        kind, length = number(hello, start), number(hello, start + 2)
        start += 4
        extension_end = start + length
        if extension_end > end:
            return None
        if kind == 0:
            if length < 5 or number(hello, start) != length - 2:
                return None
            start += 2
            while start + 3 <= extension_end:
                name_kind, length = hello[start], number(hello, start + 1)
                start += 3
                if start + length > extension_end:
                    return None
                if name_kind == 0:
                    return domain_name(bytes(hello[start:start + length]))
                start += length
            return None
        start = extension_end
    return None


def sequence_distance(left, right):
    return ((left - right + 0x80000000) & 0xffffffff) - 0x80000000


class Stream:
    def __init__(self, sequence, dns, now):
        self.initial = sequence
        self.sequence = sequence
        self.dns = dns
        self.last_seen = now
        self.pending = {}
        self.pending_bytes = 0
        self.buffer = bytearray()
        self.handshake = bytearray()
        self.done = False

    def add(self, sequence, data):
        domains = set()
        difference = sequence_distance(sequence, self.sequence)
        if difference > 0:
            previous_size = len(self.pending.get(sequence, b""))
            if (difference + len(data) <= MAX_STREAM and
                (previous_size or len(self.pending) < 8) and
                previous_size < len(data) <= MAX_STREAM - self.pending_bytes + previous_size):
                self.pending[sequence] = bytes(data)
                self.pending_bytes += len(data) - previous_size
            return domains

        self.consume(data[-difference:], domains)
        while self.pending and not self.done:
            sequence = min(self.pending, key=lambda value: sequence_distance(value, self.sequence))
            difference = sequence_distance(sequence, self.sequence)
            if difference > 0:
                break
            queued = self.pending.pop(sequence)
            self.pending_bytes -= len(queued)
            self.consume(queued[-difference:], domains)
        return domains

    def consume(self, data, domains):
        self.sequence = (self.sequence + len(data)) & 0xffffffff
        if len(self.buffer) + len(data) > MAX_STREAM:
            self.done = True
            return
        self.buffer.extend(data)
        while not self.done:
            if self.dns:
                if len(self.buffer) < 2:
                    return
                length = number(self.buffer, 0)
                if not 12 <= length <= MAX_STREAM - 2:
                    self.done = True
                    return
                if len(self.buffer) < 2 + length:
                    return
                domains.update(dns_questions(self.buffer[2:2 + length]))
                del self.buffer[:2 + length]
                continue

            if not self.buffer:
                return
            if self.buffer[0] != 22 or (len(self.buffer) >= 2 and self.buffer[1] != 3):
                self.done = True
                return
            if len(self.buffer) < 5:
                return
            length = number(self.buffer, 3)
            if not 1 <= length <= MAX_STREAM - 5 or len(self.handshake) + length > MAX_STREAM:
                self.done = True
                return
            if len(self.buffer) < 5 + length:
                return
            self.handshake.extend(self.buffer[5:5 + length])
            del self.buffer[:5 + length]
            if self.handshake[0] != 1:
                self.done = True
                return
            if len(self.handshake) >= 4:
                size = number(self.handshake, 1, 3)
                if size > MAX_STREAM - 4:
                    self.done = True
                elif len(self.handshake) >= 4 + size:
                    domain = client_hello_name(self.handshake[4:4 + size])
                    if domain:
                        domains.add(domain)
                    self.done = True


class PacketDecoder:
    def __init__(self, device):
        self.device = device
        self.streams = OrderedDict()

    def inspect(self, link, frame):
        packet = network_packet(link, frame, self.device)
        if packet is None:
            return None, set(), None
        source, dest, protocol, data = packet
        if protocol == 17 and len(data) >= 8 and number(data, 2) == 53:
            udp_length = number(data, 4)
            if 8 <= udp_length <= len(data):
                return dest, dns_questions(data[8:udp_length]), "DNS"
        if protocol == 6 and len(data) >= 20:
            offset = (data[12] >> 4) * 4
            if 20 <= offset <= len(data):
                port = number(data, 2)
                domains = self.tcp(
                    (source, dest, number(data, 0), port), number(data, 4, 4),
                    data[13], data[offset:],
                )
                return dest, domains, "DNS" if port == 53 else "TLS SNI"
        return dest, set(), None

    def tcp(self, key, sequence, flags, payload):
        if not payload and not flags & 0x07:
            return set()

        now = time.monotonic()
        while self.streams:
            first = next(iter(self.streams.values()))
            if now - first.last_seen <= FLOW_TIMEOUT:
                break
            self.streams.popitem(last=False)

        stream = self.streams.get(key)
        if flags & 0x02:
            sequence = (sequence + 1) & 0xffffffff
            if stream is None or sequence != stream.initial:
                stream = Stream(sequence, key[3] == 53, now)
        elif stream is None and payload and (key[3] == 53 or payload[0] == 22):
            stream = Stream(sequence, key[3] == 53, now)
        if stream is None:
            return set()

        domains = stream.add(sequence, payload) if payload else set()
        if stream.done or flags & 0x05:
            self.streams.pop(key, None)
        else:
            stream.last_seen = now
            self.streams[key] = stream
            self.streams.move_to_end(key)
            if len(self.streams) > MAX_FLOWS:
                self.streams.popitem(last=False)
        return domains


@lru_cache(maxsize=512)
def is_public(address):
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast and not ip.is_reserved
