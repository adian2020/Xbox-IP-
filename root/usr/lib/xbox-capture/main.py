"""LuCI RPC, session control, and Clash export for Xbox Capture."""

import argparse
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

from packets import Device, PacketDecoder, SNAPLEN, is_public, read_pcap

STATE = Path(os.environ.get("XBOX_CAPTURE_STATE_DIR", "/var/run/xbox-capture"))
METHODS = {
    "status": {},
    "start": {"name": "", "interface": "", "device": "", "minutes": 0, "baseline_id": ""},
    "stop": {},
    "sessions": {},
    "get": {"id": "", "offset": 0},
    "export": {"id": "", "format": "", "policy": "", "omit": "", "offset": 0},
    "remove": {"id": ""},
    "mrs_build": {"id": "", "omit": ""},
    "mrs_status": {"job": ""},
    "mrs_download": {"job": "", "kind": "", "offset": 0},
    "mrs_import": {"job": "", "kind": "", "offset": 0, "data": "", "done": False},
    "github_login": {"token": ""},
    "github_publish": {"token": "", "job": "", "repository": "", "branch": "",
                       "directory": "", "game": "", "domain_name": "", "ip_name": ""},
}
MAX_ENTRIES = 2000
MAX_HISTORY = 20
MAX_REQUEST = 16 * 1024
MAX_RESPONSE = 48 * 1024
PAGE_BYTES = 20 * 1024
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
    return result["domains"] + [{"value": value} for value in result["ips"]]


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
    def __init__(self, name, interface, device, minutes, baseline):
        self.summary = {
            "id": os.urandom(16).hex(), "name": name, "interface": interface, "device": device.label,
            "started": epoch(), "ended": None, "state": "recording", "minutes": minutes,
            "domain_count": 0, "ip_count": 0, "truncated": False, "kernel_drops": None,
        }
        self.baseline_domains = set()
        self.baseline_addresses = set()
        if baseline is not None:
            reference = baseline["summary"]
            self.summary["baseline"] = {"id": reference["id"], "name": reference["name"]}
            self.baseline_domains = {entry["value"] for entry in baseline["domains"]}
            self.baseline_addresses = {ipaddress.ip_address(value).packed for value in baseline["ips"]}
        self.decoder = PacketDecoder(device)
        self.process = None
        self.domains = {}
        self.addresses = set()
        self.started = time.monotonic()
        self.reason = None
        self.timer = None

    def observe(self, dest, domains, origin):
        if (dest is not None and dest not in self.baseline_addresses
                and dest not in self.addresses and is_public(dest)):
            if len(self.addresses) < MAX_ENTRIES:
                self.addresses.add(dest)
                self.summary["ip_count"] = len(self.addresses)
            else:
                self.summary["truncated"] = True
        for domain in domains:
            if domain in self.baseline_domains:
                continue
            if domain in self.domains:
                self.domains[domain].add(origin)
            elif len(self.domains) < MAX_ENTRIES:
                self.domains[domain] = {origin}
                self.summary["domain_count"] = len(self.domains)
            else:
                self.summary["truncated"] = True

    def result(self):
        return {
            "summary": self.summary,
            "domains": [{"value": value, "sources": sorted(self.domains[value])}
                        for value in sorted(self.domains)],
            "ips": [str(ipaddress.ip_address(value))
                    for value in sorted(self.addresses, key=lambda value: (len(value), value))],
        }


class Controller:
    def __init__(self, directory):
        from publisher import Publisher

        self.directory = directory
        self.publisher = Publisher(directory)
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
            try:
                socket.if_nametoindex(interface)
            except OSError:
                raise ValueError(f"接口 {interface} 不存在。请填写设备名，例如 br-lan。") from None

            session = Session(name, interface, device, minutes, baseline)
            command = [
                "tcpdump", "-n", "-p", "-U", "-s", str(SNAPLEN), "-B", "512",
                "-i", interface, "-w", "-", device.filter,
            ]
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
                for link, frame in read_pcap(source, session.decoder.device):
                    observed = session.decoder.inspect(link, frame)
                    if observed[0] is not None:
                        with self.lock:
                            session.observe(*observed)
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

    def dispatch(self, method, args):
        if method == "status":
            return self.status()
        if method == "start":
            return self.start(args.get("name"), args.get("interface"), args.get("device"),
                              args.get("minutes"), args.get("baseline_id", ""))
        if method == "stop":
            return self.stop()
        if method == "sessions":
            with self.lock:
                return {"sessions": self.summaries()}
        if method == "get":
            with self.lock:
                result = self.get(args.get("id"))
            entries, next_offset = page(result_entries(result), args.get("offset", 0),
                                        lambda entry: len(dumps(entry).encode()) + 1)
            return {"summary": result["summary"], "entries": entries, "next": next_offset}
        if method == "export":
            with self.lock:
                result = self.get(args.get("id"))
            return export_rules(result, args.get("format", "provider"), args.get("policy", "Xbox"),
                                args.get("omit", ""), args.get("offset", 0))
        if method == "remove":
            with self.lock:
                return self.remove(args.get("id"))
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
        try:
            self.wfile.write(dumps(response).encode() + b"\n")
        except OSError:
            pass


def load_line(stream, limit, allow_empty=False):
    line = stream.readline(limit + 1)
    if not line and allow_empty:
        return {}
    if not line or len(line) > limit:
        raise ValueError("RPC 消息为空或过大。")
    value = json.loads(line)
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
                return load_line(stream, MAX_RESPONSE)
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
