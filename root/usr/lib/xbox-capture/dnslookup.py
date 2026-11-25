"""Resolve a recorded domain only when the LuCI user requests a lookup."""

import base64
from collections import OrderedDict
from http.client import HTTPException
import ipaddress
import json
import struct
import subprocess
import sys
import threading
from urllib.request import HTTPRedirectHandler, Request, build_opener

from packets import dns_answers, is_public


RESOLVERS = {"system": "路由器 DNS 补查", "alidns": "阿里公共 DNS 补查"}
MAX_LOOKUPS = 192
MAX_PENDING = 2
MAX_ANSWERS = 16
MAX_DNS_BYTES = 65535


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def resolve_system(name):
    # Isolate libc's resolver so a slow upstream can be stopped independently.
    script = (
        "import json, socket, sys\n"
        "try:\n"
        "    rows = socket.getaddrinfo(sys.argv[1], None, type=socket.SOCK_STREAM)\n"
        "except socket.gaierror as exc:\n"
        "    if exc.errno not in (socket.EAI_NONAME, getattr(socket, 'EAI_NODATA', socket.EAI_NONAME)):\n"
        "        raise\n"
        "    rows = []\n"
        "print(json.dumps([row[4][0] for row in rows]))\n"
    )
    data = subprocess.check_output([sys.executable, "-B", "-c", script, name + "."],
                                   timeout=6, stderr=subprocess.DEVNULL)
    return {ipaddress.ip_address(address).packed for address in json.loads(data)}


def resolve_alidns(name):
    opener = build_opener(NoRedirect())
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    answers = set()
    replies = 0
    for kind in (1, 28):
        question = struct.pack(">6H", 0, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">2H", kind, 1)
        encoded = base64.urlsafe_b64encode(question).rstrip(b"=").decode("ascii")
        request = Request("https://dns.alidns.com/dns-query?dns=" + encoded,
                          headers={"Accept": "application/dns-message"})
        try:
            with opener.open(request, timeout=4) as response:
                if response.headers.get_content_type() != "application/dns-message":
                    continue
                data = response.read(MAX_DNS_BYTES + 1)
                if not 12 <= len(data) <= MAX_DNS_BYTES or data[:2] != b"\0\0" or not data[2] & 0x80:
                    continue
                if data[3] & 0x0f not in (0, 3):
                    continue
                replies += 1
                answers.update(ip for domain, ip in dns_answers(data) if domain == name)
        except (OSError, HTTPException):
            continue
    if not replies:
        raise OSError("public DNS unavailable")
    return answers


class DomainLookups:
    def __init__(self):
        self.jobs = OrderedDict()
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            return self.jobs.get(key)

    def start(self, key, resolver):
        with self.lock:
            current = self.jobs.get(key)
            if current and current["pending"]:
                return
            if sum(job["pending"] for job in self.jobs.values()) >= MAX_PENDING:
                raise ValueError("已有域名在补查，请稍后重试。")
            self.jobs[key] = {"pending": True, "bindings": (), "error": None}
            self.jobs.move_to_end(key)
            if len(self.jobs) > MAX_LOOKUPS:
                oldest = next(item for item, job in self.jobs.items() if not job["pending"])
                self.jobs.pop(oldest)
            try:
                threading.Thread(target=self.resolve, args=(key, resolver), daemon=True, name="domain-asn").start()
            except RuntimeError:
                self.jobs.pop(key)
                raise ValueError("无法启动域名补查。") from None

    def resolve(self, key, resolver):
        bindings, error = (), "DNS 补查失败，请稍后重试。"
        try:
            addresses = resolve_system(key[1]) if resolver == "system" else resolve_alidns(key[1])
            public = sorted(ip for ip in addresses if is_public(ip))
            bindings = tuple((ip, RESOLVERS[resolver]) for ip in public[:MAX_ANSWERS])
            if bindings:
                error = None
            elif resolver == "system" and addresses:
                error = "路由器 DNS 只返回了私网地址或 Fake IP。可改用阿里公共 DNS 补查。"
            else:
                error = "所选 DNS 没有返回可匹配的公网地址。"
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        finally:
            with self.lock:
                self.jobs[key] = {"pending": False, "bindings": bindings, "error": error}
