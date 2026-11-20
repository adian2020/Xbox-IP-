"""Convert and merge Mihomo domain and ipcidr rule sets."""

import ipaddress
import os
from pathlib import Path
import subprocess
import tempfile

KINDS = ("domain", "ipcidr")
DEFAULT_NAMES = {"domain": "domain.mrs", "ipcidr": "ip.mrs"}
MAX_MRS = 512 * 1024
MAX_TEXT = 4 * 1024 * 1024
CHUNK_BYTES = 10 * 1024
ZSTD_MAGIC = bytes.fromhex("28b52ffd")
CORE_PATHS = ("/usr/bin/mihomo", "/etc/openclash/core/clash_meta", "/usr/bin/clash-meta")


def segment(value, field):
    if (not isinstance(value, str) or not value or value != value.strip()
            or not value.isprintable() or len(value.encode()) > 200
            or value.lower() in (".", "..", ".git") or "/" in value or "\\" in value):
        raise ValueError(f"{field}包含无效的名称。")
    return value


def mrs_names(domain_name, ip_name):
    names = {}
    for kind, name in zip(KINDS, (domain_name, ip_name)):
        name = segment(name, "MRS 文件名")
        if not name.lower().endswith(".mrs"):
            name += ".mrs"
        if len(name.encode()) > 200 or name.lower() == ".mrs":
            raise ValueError("请为 MRS 文件填写有效的名称。")
        names[kind] = name
    if names["domain"].casefold() == names["ipcidr"].casefold():
        raise ValueError("域名和 IP 文件需要使用不同的名称。")
    return names


def merge_rules(kind, first, second):
    combined = first | second
    if kind == "domain":
        return combined
    by_version = ([], [])
    for value in combined:
        network = ipaddress.ip_network(value, strict=False)
        by_version[network.version == 6].append(network)
    return {str(network) for family in by_version for network in ipaddress.collapse_addresses(family)}


class Codec:
    def __init__(self, directory):
        self.directory = directory
        configured = os.environ.get("XBOX_CAPTURE_MIHOMO")
        candidates = (configured,) if configured else CORE_PATHS
        self.binary = next((path for path in candidates
                            if Path(path).is_absolute() and Path(path).is_file()
                            and os.access(path, os.X_OK)), None)
        if self.binary is None:
            raise ValueError("未找到 Mihomo 内核。请安装 Mihomo 或下载 OpenClash 的 Meta 内核。")

    def convert(self, kind, format, data, limit):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            source = Path(temporary) / "source"
            output = Path(temporary) / "output"
            source.write_bytes(data)
            # Bound file writes from the converter while permitting large rule sets.
            command = [
                "/bin/sh", "-c", 'ulimit -f 8192 || exit 1; exec "$@"', "mrs-convert",
                self.binary, "convert-ruleset", kind, format, str(source), str(output),
            ]
            try:
                result = subprocess.run(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=15, cwd=temporary,
                    env={**os.environ, "GOMEMLIMIT": "64MiB", "GOMAXPROCS": "2"},
                    check=False,
                )
            except subprocess.TimeoutExpired:
                raise ValueError("Mihomo 转换 MRS 超时。") from None
            if result.returncode or not output.is_file():
                raise ValueError(f"无法转换 {kind} MRS。请检查文件类型和 Mihomo 内核版本。")
            if not 0 < output.stat().st_size <= limit:
                raise ValueError(f"{kind} MRS 为空或超出允许大小。")
            return output.read_bytes()

    def encode(self, kind, rules):
        data = ("\n".join(sorted(rules)) + "\n").encode()
        if len(data) > MAX_TEXT:
            raise ValueError("合并后的规则文本过大。")
        return self.convert(kind, "text", data, MAX_MRS)

    def decode(self, kind, data):
        if not data.startswith(ZSTD_MAGIC) or len(data) > MAX_MRS:
            raise ValueError(f"{kind} 文件格式无效或大于 512 KiB。")
        text = self.convert(kind, "mrs", data, MAX_TEXT)
        try:
            rules = {line.strip() for line in text.decode().splitlines() if line.strip()}
            return merge_rules(kind, rules, set())
        except ValueError:
            raise ValueError(f"无法读取 {kind} MRS 中的规则。") from None
