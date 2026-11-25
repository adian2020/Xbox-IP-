"""LuCI RPC, session control, and Clash export for Xbox Capture."""

import argparse
from collections import OrderedDict
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time

from neighbours import capture_device
from devices import discover_devices
from packets import Device, PacketDecoder, SNAPLEN, capture_filter, domain_name, is_public, read_pcap

STATE = Path(os.environ.get("XBOX_CAPTURE_STATE_DIR", "/var/run/xbox-capture"))
METHODS = {
    "status": {},
    "devices": {"interface": "", "offset": 0},
    "live": {"id": "", "kind": "", "query": "", "offset": 0},
    "asn_status": {},
    "asn_update": {},
    "domain_lookup": {"id": "", "domain": "", "resolver": ""},
    "domain_auto": {"id": "", "domains": []},
    "start": {"name": "", "interface": "", "device": "", "minutes": 0, "baseline_id": ""},
    "stop": {},
    "sessions": {},
    "get": {"id": "", "offset": 0},
    "export": {"id": "", "format": "", "policy": "", "omit": "", "offset": 0},
    "remove": {"id": ""},
    "remove_many": {"ids": []},
    "mrs_build": {"id": "", "omit": ""},
    "mrs_status": {"job": ""},
    "mrs_download": {"job": "", "kind": "", "offset": 0},
    "mrs_import": {"job": "", "kind": "", "offset": 0, "data": "", "done": False},
    "github_login": {"token": ""},
    "github_publish": {"token": "", "job": "", "repository": "", "branch": "",
                       "directory": "", "game": "", "domain_name": "", "ip_name": ""},
}
MAX_ENTRIES = 2000
MAX_DOMAIN_IPS = 8
MAX_TARGET_PORTS = 24
MAX_SESSION_PORTS = 8192
MAX_HISTORY = 20
MAX_REQUEST = 16 * 1024
MAX_RESPONSE = 48 * 1024
PAGE_BYTES = 20 * 1024
LIVE_ROWS = 24
AUTO_BATCH = 16
SESSION_ID = re.compile(r"[0-9a-f]{32}")
INTERFACE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}")
BASELINE_STATES = {"stopped", "timeout", "shutdown"}


def epoch():
    return int(time.time())


def dumps(data):
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def label(value, prompt):
    if not isinstance(value, str):
        raise ValueError(prompt)
    value = value.strip()
    if not 1 <= len(value) <= 64 or not value.isprintable():
        raise ValueError(prompt)
    return value


def result_entries(result):
    ip_ports = result.get("ip_ports", {})
    return result["domains"] + [
        {"value": value, "ports": ip_ports[value]} if value in ip_ports else {"value": value}
        for value in result["ips"]
    ]


def selected_entries(result, omit):
    entries = result_entries(result)
    if not isinstance(omit, str) or len(omit) > len(entries) or set(omit) - {"0", "1"}:
        raise ValueError("条目筛选无效。")
    return [entry for index, entry in enumerate(entries)
            if index >= len(omit) or omit[index] == "0"]


def page(items, offset, size):
    if type(offset) is not int or not 0 <= offset <= len(items):
        raise ValueError("分页位置无效。")
    end, used = offset, 0
    while end < len(items):
        used += size(items[end])
        if used > PAGE_BYTES and end > offset:
            break
        end += 1
    return items[offset:end], end if end < len(items) else None


def export_rules(result, format, policy, omit, offset):
    if format not in ("provider", "inline"):
        raise ValueError("请选择 Clash 配置或 Classical 规则集。")
    if format == "inline":
        policy = label(policy, "请输入 Clash 策略组名称，最多 64 个字符。")
        if "," in policy:
            raise ValueError("Clash 策略组名称不能包含逗号。")
    rules = []
    for entry in selected_entries(result, omit):
        value = entry["value"]
        if "sources" in entry:
            rule = "DOMAIN," + value
        else:
            kind, length = ("IP-CIDR6", 128) if ":" in value else ("IP-CIDR", 32)
            rule = f"{kind},{value}/{length}"
        if format == "inline":
            rule += "," + policy
        if "sources" not in entry:
            rule += ",no-resolve"
        rules.append("  - " + dumps(rule) + "\n")

    key = "rules" if format == "inline" else "payload"
    lines, next_offset = page(rules, offset, lambda line: len(dumps(line).encode()))
    header = (key + (":\n" if rules else ": []\n")) if offset == 0 else ""
    name = "".join(char if char.isalnum() or char in "-_" else "-"
                   for char in result["summary"]["name"]).strip("-")
    return {
        "yaml": header + "".join(lines),
        "next": next_offset,
        "filename": f'{name or "xbox"}-{result["summary"]["id"][:8]}-{format}.yaml',
    }


class Session:
    def __init__(self, name, interface, device, selector, minutes, baseline):
        self.summary = {
            "id": os.urandom(16).hex(), "name": name, "interface": interface, "device": device.label,
            "started": epoch(), "ended": None, "state": "recording", "minutes": minutes,
            "domain_count": 0, "ip_count": 0, "truncated": False, "kernel_drops": None,
            "frame_count": 0, "packet_count": 0, "fakeip_count": 0, "domain_asn": True,
        }
        if selector.mac:
            self.summary["capture_mac"] = selector.label
        self.baseline_domains = set()
        self.baseline_addresses = set()
        if baseline is not None:
            reference = baseline["summary"]
            self.summary["baseline"] = {"id": reference["id"], "name": reference["name"]}
            self.baseline_domains = {entry["value"] for entry in baseline["domains"]}
            self.baseline_addresses = {ipaddress.ip_address(value).packed for value in baseline["ips"]}
        self.decoder = PacketDecoder(selector, reply_addresses=device.addresses)
        self.process = None
        self.domains = {}
        self.domain_ips = {}
        self.addresses = set()
        self.address_ports = {}
        self.domain_ports = {}
        self.port_total = 0
        self.recent = OrderedDict()
        self.started = time.monotonic()
        self.reason = None
        self.timer = None

    def remember_port(self, targets, value, endpoint):
        ports = targets.get(value, ())
        if endpoint in ports:
            return False
        if self.port_total >= MAX_SESSION_PORTS or len(ports) >= MAX_TARGET_PORTS:
            self.summary["ports_truncated"] = True
            return False
        targets.setdefault(value, set()).add(endpoint)
        self.port_total += 1
        return True

    def touch(self, kind, value):
        key = (kind, value)
        self.recent[key] = epoch()
        self.recent.move_to_end(key)

    def link_domain(self, domain, address, source):
        if not is_public(address):
            return False
        bindings = self.domain_ips.setdefault(domain, {})
        if address in bindings:
            if source == "TLS SNI" and bindings[address] != source:
                bindings[address] = source
                return True
            return False
        if len(bindings) >= MAX_DOMAIN_IPS:
            if source != "TLS SNI":
                return False
            replaced = next((value for value, origin in bindings.items() if origin == "DNS 回应"), None)
            if replaced is None:
                return False
            del bindings[replaced]
        bindings[address] = source
        return True

    def observe_answers(self, answers):
        for domain, address in sorted(answers):
            if domain in self.domains and self.link_domain(domain, address, "DNS 回应"):
                self.touch("domain", domain)

    def domain_bindings(self, domain):
        return sorted(self.domain_ips.get(domain, {}).items(), key=lambda item: item[1] != "TLS SNI")

    def observe(self, dest, domains, origin, endpoint=None):
        self.summary["packet_count"] += 1
        new_address = False
        if len(dest) == 4 and dest[0] == 198 and dest[1] in (18, 19):
            self.summary["fakeip_count"] += 1
        elif dest not in self.baseline_addresses and dest not in self.addresses and is_public(dest):
            if len(self.addresses) < MAX_ENTRIES:
                self.addresses.add(dest)
                self.summary["ip_count"] = len(self.addresses)
                new_address = True
            else:
                self.summary["truncated"] = True
        new_port = endpoint and dest in self.addresses and self.remember_port(self.address_ports, dest, endpoint)
        if new_address or new_port:
            self.touch("ip", dest)
        for domain in domains:
            if domain in self.baseline_domains:
                continue
            if domain not in self.domains and len(self.domains) >= MAX_ENTRIES:
                self.summary["truncated"] = True
                continue
            sources = self.domains.setdefault(domain, set())
            new_source = origin not in sources
            sources.add(origin)
            self.summary["domain_count"] = len(self.domains)
            new_port = origin == "TLS SNI" and endpoint and self.remember_port(self.domain_ports, domain, endpoint)
            new_binding = origin == "TLS SNI" and self.link_domain(domain, dest, origin)
            if new_source or new_port or new_binding:
                self.touch("domain", domain)

    def entry(self, kind, value):
        if kind == "domain":
            entry = {"value": value, "sources": sorted(self.domains[value])}
            ports = self.domain_ports.get(value)
        else:
            entry = {"value": str(ipaddress.ip_address(value))}
            ports = self.address_ports.get(value)
        if ports:
            entry["ports"] = sorted(ports)
        return entry

    def live_page(self, kind, query, offset):
        matching = []
        for key in reversed(self.recent):
            entry_kind, value = key
            if kind != "all" and entry_kind != kind:
                continue
            if query:
                target = value if entry_kind == "domain" else str(ipaddress.ip_address(value))
                ports = (self.domain_ports if entry_kind == "domain" else self.address_ports).get(value, ())
                if query not in target and not any(query in f"{proto.lower()} {port}" for proto, port in ports):
                    continue
            matching.append(key)
        total = len(matching)
        start = min(offset, ((total - 1) // LIVE_ROWS) * LIVE_ROWS) if total else 0
        end = min(start + LIVE_ROWS, total)
        return {
            "id": self.summary["id"], "total": total, "offset": start,
            "previous": max(0, start - LIVE_ROWS) if start else None,
            "next": end if end < total else None,
            "entries": [dict(self.entry(*key), kind=key[0], seen=self.recent[key]) for key in matching[start:end]],
        }

    def result(self):
        return {
            "summary": self.summary,
            "domains": [self.entry("domain", value) for value in sorted(self.domains)],
            "ips": [str(ipaddress.ip_address(value))
                    for value in sorted(self.addresses, key=lambda value: (len(value), value))],
            "ip_ports": {str(ipaddress.ip_address(value)): sorted(ports)
                         for value, ports in self.address_ports.items()},
            "domain_ips": {
                domain: [(str(ipaddress.ip_address(address)), origin) for address, origin in self.domain_bindings(domain)]
                for domain in self.domain_ips
            },
        }


class Controller:
    def __init__(self, directory):
        from asn import ASNStore
        from dnslookup import DomainLookups
        from publisher import Publisher

        self.directory = directory
        self.publisher = Publisher(directory)
        self.asn = ASNStore(directory)
        self.domain_lookups = DomainLookups()
        self.device_snapshot = None
        self.active = None
        self.lock = threading.Lock()
        self.unsaved = {}
        self.history = {}
        for file in self.directory.glob("*.json"):
            if SESSION_ID.fullmatch(file.stem):
                try:
                    self.history[file.stem] = self.get(file.stem)["summary"]
                except (ValueError, KeyError):
                    continue

    def status(self):
        with self.lock:
            if not self.active:
                return {"active": None}
            return {"active": {**self.active.summary, "elapsed": int(time.monotonic() - self.active.started)}}

    def devices(self, interface, offset):
        if not isinstance(interface, str) or not INTERFACE.fullmatch(interface):
            raise ValueError("请填写有效的 LAN 接口。")
        snapshot = self.device_snapshot
        now = time.monotonic()
        if offset == 0 or not snapshot or snapshot[0] != interface or now - snapshot[1] > 10:
            records, truncated = discover_devices(interface)
            snapshot = self.device_snapshot = (interface, now, records, truncated)
        rows, next_offset = page(snapshot[2], offset, lambda entry: len(dumps(entry).encode()) + 1)
        return {"devices": rows, "next": next_offset, "truncated": snapshot[3]}

    def live(self, id, kind, query, offset):
        self.path(id)
        if (kind not in ("all", "ip", "domain") or not isinstance(query, str) or len(query) > 128
                or type(offset) is not int or not 0 <= offset <= 2 * MAX_ENTRIES):
            raise ValueError("实时面板参数无效。")
        with self.lock:
            if self.active is None or self.active.summary["id"] != id:
                return {"id": None}
            result = self.active.live_page(kind, query.strip().lower(), offset)
            bindings = {entry["value"]: self.active.domain_bindings(entry["value"])
                        for entry in result["entries"] if "sources" in entry}
        with self.asn.reader() as index:
            if index is not None:
                for entry in result["entries"]:
                    self.annotate_owner(index, id, entry, bindings)
        return result

    def annotate_owner(self, index, id, entry, bindings):
        name = entry["value"]
        index.annotate(entry, bindings.get(name, ()))
        if "sources" in entry and not entry.get("owners"):
            job = self.domain_lookups.get((id, name))
            if job and job["bindings"]:
                index.annotate(entry, job["bindings"])
            if "DNS" in entry["sources"] and not entry.get("owners"):
                from dnslookup import automatic_name

                if not automatic_name(name):
                    entry["auto_lookup"] = "unavailable"
                    return
                automatic = self.domain_lookups.get((None, name))
                if automatic:
                    index.annotate(entry, automatic["bindings"])
                    if not entry.get("owners"):
                        entry["auto_lookup"] = "pending" if automatic["pending"] else "unavailable"

    def automatic_lookups(self, id, names):
        from dnslookup import automatic_name

        self.path(id)
        if (not isinstance(names, list) or not 1 <= len(names) <= AUTO_BATCH
                or any(not isinstance(name, str) or len(name) > 253 or not name.isascii()
                       or domain_name(name.encode("ascii")) != name for name in names)):
            raise ValueError("自动补查的域名列表无效。")
        with self.lock:
            if self.active and self.active.summary["id"] == id:
                session = self.active
                sources = {name: session.domains.get(name, ()) for name in names}
                bindings = {name: session.domain_bindings(name) for name in names}
            else:
                result = self.get(id)
                sources = {row["value"]: row["sources"] for row in result["domains"]}
                bindings = result.get("domain_ips", {})
        rows = []
        with self.asn.reader() as index:
            if index is None:
                return {"entries": rows}
            for name in dict.fromkeys(names):
                if not automatic_name(name) or "DNS" not in sources.get(name, ()):
                    rows.append({"value": name, "auto_lookup": "unavailable"})
                    continue
                entry = {"value": name, "sources": ["DNS"]}
                self.annotate_owner(index, id, entry, bindings)
                if not entry.get("owners") and "auto_lookup" not in entry:
                    manual = self.domain_lookups.get((id, name))
                    if manual and manual["pending"]:
                        continue
                    if not self.domain_lookups.start((None, name), "auto"):
                        continue
                    entry["auto_lookup"] = "pending"
                rows.append(entry)
        return {"entries": rows}

    def domain_lookup(self, id, name, resolver):
        self.path(id)
        if (not isinstance(name, str) or len(name) > 253 or not name.isascii()
                or domain_name(name.encode("ascii")) != name):
            raise ValueError("请选择录制中的有效域名。")
        key = (id, name)
        if resolver != "":
            if resolver not in ("system", "alidns"):
                raise ValueError("请选择用于补查的 DNS。")
            with self.lock:
                if self.active and self.active.summary["id"] == id:
                    recorded = name in self.active.domains
                else:
                    recorded = any(row["value"] == name for row in self.get(id)["domains"])
            if not recorded:
                raise ValueError("该域名不在这条录制中。")
            with self.asn.reader() as index:
                if index is None:
                    raise ValueError("请先下载归属库。")
            self.domain_lookups.start(key, resolver)
        job = self.domain_lookups.get(key)
        if job is None:
            raise ValueError("找不到此补查，请重新查询。")
        if job["pending"] or job["error"]:
            return {"pending": job["pending"], "error": job["error"]}
        entry = {"value": name, "sources": ["DNS"]}
        with self.asn.reader() as index:
            if index is not None:
                index.annotate(entry, job["bindings"])
        if not entry.get("owners"):
            return {"pending": False, "error": "当前归属库未收录这些公网地址。可以更新归属库后再试。"}
        return {"pending": False, "owners": entry["owners"]}

    def start(self, name, interface, device, minutes, baseline_id=""):
        name = label(name, "请输入游戏或软件名称，最多 64 个字符。")
        if type(minutes) is not int or not 1 <= minutes <= 360:
            raise ValueError("最长录制时间应在 1 至 360 分钟之间。")

        with self.lock:
            if self.active:
                raise ValueError("已有录制，结束后才能开始下一次。")
            if len(self.history) >= MAX_HISTORY:
                raise ValueError(f"已保存 {MAX_HISTORY} 次录制。请先下载并删除旧录制。")

            baseline = None
            if baseline_id != "":
                baseline = self.get(baseline_id)
                reference = baseline["summary"]
                if reference.get("baseline") or reference["state"] not in BASELINE_STATES:
                    raise ValueError("请选择已正常结束的完整录制作为基线。")
                baseline_device = Device(reference["device"])
                interface = reference["interface"] if interface is None else interface
                device = baseline_device if device is None else Device(device)
                if (interface != reference["interface"] or device.mac != baseline_device.mac
                        or device.addresses != baseline_device.addresses):
                    raise ValueError("新增录制需要使用基线的 LAN 接口和 Xbox 地址。")
            else:
                device = Device(device)

            if not isinstance(interface, str) or not INTERFACE.fullmatch(interface):
                raise ValueError("请输入有效的 LAN 接口名称，例如 br-lan。")
            cooked = interface == "any"
            vlan = False
            if not cooked:
                try:
                    socket.if_nametoindex(interface)
                except OSError:
                    raise ValueError(f"接口 {interface} 不存在。可填写 LAN 设备名或 any。") from None
                try:
                    vlan = (Path("/sys/class/net") / interface / "type").read_text().strip() == "1"
                except OSError:
                    pass

            previous_mac = baseline["summary"].get("capture_mac") if baseline else None
            selector = capture_device(device, interface, previous_mac)
            session = Session(name, interface, device, selector, minutes, baseline)
            command = [
                "tcpdump", "-n", "-p", "-U", "--immediate-mode", "-s", str(SNAPLEN), "-B", "512",
                "-i", interface,
            ]
            if cooked:
                command += ["-y", "LINUX_SLL2"]
            command += ["-w", "-", capture_filter(
                selector, cooked=cooked, vlan=vlan, reply_addresses=device.addresses,
            )]
            error_log = tempfile.TemporaryFile(dir=self.directory)
            try:
                session.process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=error_log, env={**os.environ, "LC_ALL": "C"},
                )
            except OSError as exc:
                error_log.close()
                raise ValueError(f"无法启动 tcpdump：{exc.strerror}") from None
            self.active = session
            session.timer = threading.Timer(minutes * 60, self.request_stop, args=(session, "timeout"))
            session.timer.daemon = True
            session.timer.start()
            threading.Thread(target=self.record, args=(session, error_log), daemon=True).start()
            return {"active": {**session.summary, "elapsed": 0}}

    def request_stop(self, session, reason):
        with self.lock:
            if session is not self.active or session.reason:
                return
            session.reason = reason
            session.summary["state"] = "stopping"
            session.process.send_signal(signal.SIGINT)
            timer = threading.Timer(4, session.process.kill)
            timer.daemon = True
            timer.start()

    def stop(self):
        with self.lock:
            session = self.active
        if session is not None:
            self.request_stop(session, "stopped")
        return self.status()

    def record(self, session, error_log):
        process = session.process
        error = None
        try:
            with process.stdout as source:
                for link, frame in read_pcap(source):
                    observed = session.decoder.inspect(link, frame)
                    with self.lock:
                        session.summary["frame_count"] += 1
                        if observed[0] is not None:
                            session.observe(*observed)
                        elif session.decoder.answers:
                            session.observe_answers(session.decoder.answers)
        except (OSError, ValueError) as exc:
            error = str(exc)
            process.kill()

        try:
            code = process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            code = process.wait()
            error = error or "抓包程序没有正常退出。"
        with error_log:
            error_log.seek(0)
            log = error_log.read(8192).decode(errors="replace")
        drops = re.search(r"(\d+) packets? dropped by kernel", log)
        session.timer.cancel()

        with self.lock:
            if not session.reason or code not in (0, -signal.SIGINT, 130):
                diagnostics = [line for line in log.splitlines() if line.startswith("tcpdump:")]
                error = error or " ".join(diagnostics)[:500] or f"tcpdump 意外退出（{code}）。"
            session.summary.update(
                ended=epoch(), state="error" if error else session.reason,
                kernel_drops=int(drops[1]) if drops else None,
            )
            if error:
                session.summary["error"] = error
            result = session.result()
            try:
                self.save(result)
            except OSError as exc:
                session.summary["storage_warning"] = f"无法写入录制目录：{exc.strerror}。请尽快下载。"
                self.unsaved[session.summary["id"]] = result
            self.history[session.summary["id"]] = session.summary
            self.active = None

    def save(self, result):
        destination = self.path(result["summary"]["id"])
        temporary = destination.with_suffix(".tmp")
        try:
            with temporary.open("w", encoding="utf-8") as file:
                file.write(dumps(result))
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)

    def path(self, id):
        if not isinstance(id, str) or not SESSION_ID.fullmatch(id):
            raise ValueError("录制编号无效。")
        return self.directory / f"{id}.json"

    def get(self, id):
        path = self.path(id)
        try:
            return self.unsaved[id] if id in self.unsaved else json.loads(path.read_bytes())
        except FileNotFoundError:
            raise ValueError("找不到该录制。") from None
        except (OSError, ValueError):
            raise ValueError("录制文件无法读取。") from None

    def summaries(self):
        return sorted(self.history.values(), key=lambda summary: summary["started"], reverse=True)

    def remove(self, id):
        path = self.path(id)
        if id in self.unsaved:
            del self.unsaved[id]
        else:
            path.unlink(missing_ok=True)
        self.history.pop(id, None)
        return {"removed": id}

    def remove_many(self, ids):
        if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_HISTORY:
            raise ValueError("请选择有效的录制记录。")
        for id in ids:
            self.path(id)
        removed, failed = [], []
        for id in dict.fromkeys(ids):
            try:
                self.remove(id)
            except OSError:
                failed.append(id)
            else:
                removed.append(id)
        return {"removed": removed, "failed": failed}

    def dispatch(self, method, args):
        if method == "status":
            return self.status()
        if method == "devices":
            return self.devices(args.get("interface"), args.get("offset", 0))
        if method == "live":
            return self.live(args.get("id"), args.get("kind", "all"), args.get("query", ""), args.get("offset", 0))
        if method == "asn_status":
            return self.asn.status()
        if method == "asn_update":
            return self.asn.update()
        if method == "domain_lookup":
            return self.domain_lookup(args.get("id"), args.get("domain"), args.get("resolver", ""))
        if method == "domain_auto":
            return self.automatic_lookups(args.get("id"), args.get("domains"))
        if method == "start":
            return self.start(args.get("name"), args.get("interface"), args.get("device"),
                              args.get("minutes"), args.get("baseline_id", ""))
        if method == "stop":
            return self.stop()
        if method == "sessions":
            with self.lock:
                return {"sessions": self.summaries()}
        if method == "get":
            id = args.get("id")
            with self.lock:
                result = self.get(id)
            bindings = result.get("domain_ips", {})
            with self.asn.reader() as index:
                def size(entry):
                    if index is not None:
                        self.annotate_owner(index, id, entry, bindings)
                    return len(dumps(entry).encode()) + 1

                rows = [entry.copy() for entry in result_entries(result)]
                entries, next_offset = page(rows, args.get("offset", 0), size)
            return {"summary": result["summary"], "entries": entries, "next": next_offset}
        if method == "export":
            with self.lock:
                result = self.get(args.get("id"))
            return export_rules(result, args.get("format", "provider"), args.get("policy", "Xbox"),
                                args.get("omit", ""), args.get("offset", 0))
        if method == "remove":
            with self.lock:
                return self.remove(args.get("id"))
        if method == "remove_many":
            with self.lock:
                return self.remove_many(args.get("ids"))
        if method == "mrs_build":
            with self.lock:
                entries = selected_entries(self.get(args.get("id")), args.get("omit", ""))
            return self.publisher.build(entries)
        return self.publisher.dispatch(method, args)

    def shutdown(self):
        with self.lock:
            session = self.active
        if session:
            self.request_stop(session, "shutdown")
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline and self.status()["active"]:
                time.sleep(0.05)


class RPCHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        try:
            request = load_line(self.rfile, MAX_REQUEST)
            if not isinstance(request.get("args"), dict):
                raise ValueError("RPC 参数无效。")
            response = self.server.controller.dispatch(request.get("method"), request["args"])
        except (ValueError, OSError) as exc:
            response = {"error": str(exc)}
        except Exception as exc:
            print(f"xbox-capture: RPC 处理失败 ({type(exc).__name__})", file=sys.stderr)
            response = {"error": "录制服务处理请求时出错。请查看路由器系统日志。"}
        try:
            self.wfile.write(dumps(response).encode() + b"\n")
        except OSError:
            pass


def load_line(stream, limit, allow_empty=False, empty_message="RPC 请求为空。"):
    line = stream.readline(limit + 1)
    if not line and allow_empty:
        return {}
    if not line:
        raise ValueError(empty_message)
    if len(line) > limit:
        raise ValueError("RPC 消息超过大小限制。")
    try:
        value = json.loads(line)
    except ValueError:
        raise ValueError("RPC 消息格式无效。") from None
    if not isinstance(value, dict):
        raise ValueError("RPC 消息格式无效。")
    return value


def serve():
    STATE.mkdir(mode=0o700, exist_ok=True, parents=True)
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise OSError("录制目录必须由服务用户拥有。")
    os.chmod(STATE, 0o700)
    socket_path = STATE / "rpc.sock"
    with (STATE / "server.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        socket_path.unlink(missing_ok=True)
        controller = Controller(STATE)
        with socketserver.UnixStreamServer(str(socket_path), RPCHandler) as server:
            server.controller = controller
            os.chmod(socket_path, 0o600)
            server.timeout = 0.25
            stopping = False

            def signal_stop(*_):
                nonlocal stopping
                stopping = True

            signal.signal(signal.SIGTERM, signal_stop)
            signal.signal(signal.SIGINT, signal_stop)
            try:
                while not stopping:
                    server.handle_request()
            finally:
                controller.shutdown()
                socket_path.unlink(missing_ok=True)


def call(method, args):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(11 if method == "github_login" else 5)
            connection.connect(str(STATE / "rpc.sock"))
            connection.sendall(dumps({"method": method, "args": args}).encode() + b"\n")
            with connection.makefile("rb") as stream:
                return load_line(stream, MAX_RESPONSE,
                                 empty_message="录制服务未返回结果。请查看路由器系统日志。")
    except OSError:
        return {"error": "录制服务未响应。请检查 /etc/init.d/xbox-capture status。"}
    except ValueError as exc:
        return {"error": str(exc)}


def cli():
    if sys.argv[1:] == ["list"]:
        print(dumps(METHODS))
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "call":
        try:
            response = call(sys.argv[2], load_line(sys.stdin.buffer, MAX_REQUEST, allow_empty=True))
        except ValueError as exc:
            response = {"error": str(exc)}
        print(dumps(response))
        return 0

    parser = argparse.ArgumentParser(description="Xbox 网络录制与 Clash 导出")
    sub = parser.add_subparsers(dest="action", required=True)
    for command in ("serve", "status", "stop", "sessions"):
        sub.add_parser(command)
    start = sub.add_parser("start")
    start.add_argument("name")
    start.add_argument("device", nargs="?")
    start.add_argument("--interface")
    start.add_argument("--minutes", default=120, type=int)
    start.add_argument("--baseline", dest="baseline_id", default="",
                       help="对比指定的完整录制，只保留新增条目")
    for command in ("get", "export", "remove"):
        options = sub.add_parser(command)
        options.add_argument("id")
        if command == "export":
            options.add_argument("--format", choices=("provider", "inline"), default="provider")
            options.add_argument("--policy", default="Xbox")
    args = vars(parser.parse_args())
    action = args.pop("action")
    if action == "start" and not args["baseline_id"] and args["interface"] is None:
        args["interface"] = "br-lan"
    if action == "serve":
        os.umask(0o077)
        try:
            serve()
        except OSError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    result = call(action, args)
    if "error" in result:
        print(result["error"], file=sys.stderr)
        return 1
    if action in ("get", "export"):
        key = "entries" if action == "get" else "yaml"
        parts = [result[key]]
        follow = result["next"]
        while follow is not None:
            response = call(action, {**args, "offset": follow})
            if "error" in response:
                print(response["error"], file=sys.stderr)
                return 1
            parts.append(response[key])
            follow = response["next"]
        if action == "export":
            print("".join(parts), end="")
        else:
            print(json.dumps({"summary": result["summary"], "entries": sum(parts, [])},
                             ensure_ascii=False, indent=2))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(cli())
