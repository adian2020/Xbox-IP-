"""Download and look up a local IPv4/IPv6 AS origin database."""

from bisect import bisect_left, bisect_right
from contextlib import contextmanager
import gzip
from http.client import HTTPException
import ipaddress
import mmap
import os
from pathlib import Path
import struct
import threading
import time
from urllib.request import Request, urlopen
import zlib

SOURCE_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
MAX_DOWNLOAD = 24 * 1024 * 1024
MAX_INDEX_SIZE = 48 * 1024 * 1024
MAX_ROWS = 2_500_000
MAX_LINE = 4096
MAX_NAME_BYTES = 192

MAGIC = b"XAS1"
HEADER = struct.Struct(">4sIII")
RANGES = {4: struct.Struct(">4sI"), 6: struct.Struct(">16sI")}
NUMBER = struct.Struct(">I")
NAME = struct.Struct(">IIH")


def download_feed(destination):
    request = Request(SOURCE_URL, headers={"User-Agent": "Xbox-Capture/1.5.0"})
    deadline = time.monotonic() + 150
    with urlopen(request, timeout=20) as response, destination.open("wb") as file:
        if not response.geturl().startswith("https://"):
            raise ValueError("归属库的下载地址必须使用 HTTPS。")
        total = 0
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DOWNLOAD:
                raise ValueError("归属库压缩文件超过大小限制。")
            if time.monotonic() >= deadline:
                raise ValueError("下载归属库超时。")
            file.write(chunk)


def build_index(lines, file):
    """Use one ordered boundary per contiguous ASN range and a shared name table."""
    counts = {4: 0, 6: 0}
    names = {}
    family = 4
    last_end = -1
    last_asn = 0
    file.write(b"\0" * HEADER.size)

    def boundary(start, asn):
        spec = RANGES[family]
        file.write(spec.pack(start.to_bytes(spec.size - NUMBER.size, "big"), asn))
        counts[family] += 1
        if file.tell() > MAX_INDEX_SIZE:
            raise ValueError("归属索引超过大小限制。")

    for line_number, line in enumerate(lines, 1):
        if len(line) > MAX_LINE or line_number > MAX_ROWS:
            raise ValueError("归属数据超过大小限制。")
        fields = line.rstrip(b"\r\n").split(b"\t", 4)
        try:
            first, last, number, _, description = fields
            start_ip, end_ip = ipaddress.ip_address(first.decode()), ipaddress.ip_address(last.decode())
            start, end = int(start_ip), int(end_ip)
            asn = int(number)
        except (UnicodeDecodeError, ValueError):
            raise ValueError("归属库数据格式无效。") from None
        if (start_ip.version != end_ip.version or start_ip.version < family or start > end
                or not 0 <= asn <= 0xffffffff):
            raise ValueError("归属库包含无效的地址范围。")

        if start_ip.version != family:
            if last_asn and last_end < 0xffffffff:
                boundary(last_end + 1, 0)
            family = start_ip.version
            last_end, last_asn = -1, 0
        if start <= last_end:
            raise ValueError("归属库包含重叠或未排序的地址范围。")
        if last_asn and start > last_end + 1:
            boundary(last_end + 1, 0)
            last_asn = 0
        if asn != last_asn:
            boundary(start, asn)
        last_end, last_asn = end, asn

        if asn and asn not in names:
            text = description.decode(errors="replace").strip()
            sanitized = "".join(char if char.isprintable() else " " for char in text)
            names[asn] = sanitized.encode()[:MAX_NAME_BYTES]
            if len(names) > 220_000:
                raise ValueError("归属库包含过多的 ASN。")

    if last_asn and last_end < (1 << (128 if family == 6 else 32)) - 1:
        boundary(last_end + 1, 0)
    if not all(counts.values()):
        raise ValueError("归属库缺少 IPv4 或 IPv6 数据。")

    name_offset = 0
    ordered = sorted(names.items())
    for asn, description in ordered:
        file.write(NAME.pack(asn, name_offset, len(description)))
        name_offset += len(description)
    if file.tell() + name_offset > MAX_INDEX_SIZE:
        raise ValueError("归属索引超过大小限制。")
    for _, description in ordered:
        file.write(description)
    file.seek(0)
    file.write(HEADER.pack(MAGIC, counts[4], counts[6], len(ordered)))


class ASNIndex:
    def __init__(self, data):
        if not HEADER.size <= len(data) <= MAX_INDEX_SIZE:
            raise ValueError("invalid database size")
        magic, self.count4, self.count6, self.name_count = HEADER.unpack_from(data)
        self.v6_start = HEADER.size + self.count4 * RANGES[4].size
        self.name_start = self.v6_start + self.count6 * RANGES[6].size
        self.text_start = self.name_start + self.name_count * NAME.size
        if magic != MAGIC or self.text_start > len(data):
            raise ValueError("invalid database header")
        self.data = data

    def lookup(self, address):
        ip = ipaddress.ip_address(address)
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        target = ip.packed
        width = len(target)
        spec = RANGES[ip.version]
        beginning, count = (HEADER.size, self.count4) if ip.version == 4 else (self.v6_start, self.count6)

        def key(position):
            start = beginning + position * spec.size
            return self.data[start:start + width]

        position = bisect_right(range(count), target, key=key) - 1
        if position < 0:
            return None
        asn = NUMBER.unpack_from(self.data, beginning + position * spec.size + width)[0]
        if not asn:
            return None

        def name_key(position):
            return NUMBER.unpack_from(self.data, self.name_start + position * NAME.size)[0]

        position = bisect_left(range(self.name_count), asn, key=name_key)
        organization = ""
        if position < self.name_count and name_key(position) == asn:
            _, offset, length = NAME.unpack_from(self.data, self.name_start + position * NAME.size)
            start = self.text_start + offset
            if start + length <= len(self.data):
                organization = self.data[start:start + length].decode(errors="ignore")
        return {"asn": asn, "organization": organization}

    def annotate(self, entry):
        if "sources" not in entry:
            owner = self.lookup(entry["value"])
            if owner:
                entry["owner"] = owner


class ASNStore:
    def __init__(self, directory):
        self.path = Path(directory) / "asn.db"
        self.download_path = self.path.with_suffix(".tsv.gz.part")
        self.build_path = self.path.with_suffix(".db.part")
        self.lock = threading.Lock()
        self.loading = False
        self.error = None

    @contextmanager
    def reader(self):
        try:
            file = self.path.open("rb")
        except OSError:
            yield None
            return
        with file:
            try:
                mapping = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
            except (OSError, ValueError):
                yield None
                return
            with mapping:
                try:
                    database = ASNIndex(mapping)
                except ValueError:
                    database = None
                yield database

    def status(self):
        with self.lock:
            try:
                info = self.path.stat()
                updated = int(info.st_mtime)
            except OSError:
                updated = None
            return {"loading": self.loading, "updated": updated, "error": self.error}

    def update(self):
        with self.lock:
            if not self.loading:
                self.loading = True
                self.error = None
                worker = threading.Thread(target=self.refresh, daemon=True, name="asn-update")
                try:
                    worker.start()
                except RuntimeError:
                    self.loading = False
                    self.error = "无法启动归属库更新。"
        return self.status()

    def refresh(self):
        error = "无法更新归属库。"
        try:
            download_feed(self.download_path)
            with gzip.open(self.download_path, "rb") as rows, self.build_path.open("wb") as file:
                build_index(iter(lambda: rows.readline(MAX_LINE + 1), b""), file)
            os.replace(self.build_path, self.path)
            error = None
        except ValueError as exc:
            error = str(exc)
        except (EOFError, HTTPException, OSError, zlib.error):
            error = "归属库下载或读取失败。请检查路由器网络和可用空间。"
        finally:
            for path in (self.download_path, self.build_path):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            with self.lock:
                self.loading = False
                self.error = error
