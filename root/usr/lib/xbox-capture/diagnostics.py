"""Sample capture counters and the router's load without keeping packet payloads."""

from collections import deque
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import signal
import threading
import time


MAX_SAMPLES = 240
LOG_BYTES = 8192
STAT_KEYS = {
    "captured": "captured", "received by filter": "received",
    "dropped by kernel": "dropped", "dropped by interface": "interface_dropped",
}
STAT_LINE = r"(\d+) packets? (" + "|".join(STAT_KEYS) + ")"
CLOCK_TICKS = os.sysconf("SC_CLK_TCK")
COLUMNS = (
    ("utc", "时间 UTC"), ("seconds", "已录秒数"), ("captured", "已抓取"),
    ("received", "过滤命中"), ("dropped", "内核丢包累计"), ("drop_delta", "内核新增丢包"),
    ("cpu", "CPU %"), ("core", "最高单核 %"), ("softirq", "软中断 CPU %"),
    ("tcpdump_cpu", "tcpdump CPU %"), ("service_cpu", "录制服务 CPU %"),
    ("load", "1 分钟负载"), ("available", "可用内存 MiB"),
    ("net_drop", "softnet 新增丢包"), ("net_squeeze", "softnet 新增预算耗尽"),
    ("rx_drop", "接口新增 RX 丢包"),
)


def parse_stats(text, final=False):
    pattern = "^" + STAT_LINE + r"\s*$" if final else STAT_LINE
    return {STAT_KEYS[reason]: int(value) for value, reason in re.findall(pattern, text, re.MULTILINE)}


def read(path):
    try:
        return Path(path).read_text()
    except OSError:
        return ""


def snapshot(interface, pid):
    cpus = {}
    for line in read("/proc/stat").splitlines():
        fields = line.split()
        if fields and fields[0].startswith("cpu") and len(fields) >= 9:
            values = tuple(map(int, fields[1:9]))
            cpus[fields[0]] = (sum(values), values[3] + values[4], values[6])
    load = read("/proc/loadavg").split()
    mem = re.search(r"^MemAvailable:\s+(\d+)", read("/proc/meminfo"), re.MULTILINE)

    softnet = [line.split() for line in read("/proc/net/softnet_stat").splitlines()]
    softnet = [fields for fields in softnet if len(fields) >= 3]
    rx = read(f"/sys/class/net/{interface}/statistics/rx_dropped").strip()
    data = {
        "cpus": cpus, "load": float(load[0]) if load else None,
        "available": round(int(mem[1]) / 1024, 1) if mem else None,
        "net_drop": sum(int(fields[1], 16) for fields in softnet) if softnet else None,
        "net_squeeze": sum(int(fields[2], 16) for fields in softnet) if softnet else None,
        "rx_drop": int(rx) if rx.isdecimal() else None,
    }
    for key, process_id in (("tcpdump_cpu", pid), ("service_cpu", os.getpid())):
        fields = read(f"/proc/{process_id}/stat").rpartition(")")[2].split()
        data[key] = int(fields[11]) + int(fields[12]) if len(fields) > 12 else None
    return data


def delta(current, previous):
    return current - previous if current is not None and previous is not None and current >= previous else None


def cpu_interval(current, previous):
    if previous:
        total, idle, softirq = (now - before for now, before in zip(current, previous))
        if total > 0 and 0 <= idle <= total and 0 <= softirq <= total:
            return round(100 * (total - idle) / total, 1), round(100 * softirq / total, 1)
    return None, None


def utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


class CaptureDiagnostics:
    def __init__(self, interface, minutes, started):
        self.interface = interface
        self.started = started
        self.interval = max(15, (minutes * 60 + MAX_SAMPLES - 3) // (MAX_SAMPLES - 2))
        self.halted = threading.Event()
        self.worker = None
        self.samples = deque(maxlen=MAX_SAMPLES)
        self.previous = {}
        self.previous_time = started
        self.dropped = 0

    def start(self, process, log):
        worker = threading.Thread(target=self.run, args=(process, log), daemon=True, name="capture-diagnostics")
        try:
            worker.start()
        except RuntimeError:
            return
        self.worker = worker

    def sample(self, pid, stats):
        now = time.monotonic()
        try:
            current = snapshot(self.interface, pid)
        except (OSError, ValueError):
            current = {}
        row = {"utc": utc(time.time()), "seconds": max(0, round(now - self.started)), **stats}
        row["load"] = current.get("load")
        row["available"] = current.get("available")
        row["drop_delta"] = delta(stats.get("dropped"), self.dropped)
        if "dropped" in stats:
            self.dropped = stats["dropped"]
        for key in ("net_drop", "net_squeeze", "rx_drop"):
            row[key] = delta(current.get(key), self.previous.get(key))
        elapsed = now - self.previous_time
        for key in ("tcpdump_cpu", "service_cpu"):
            ticks = delta(current.get(key), self.previous.get(key))
            row[key] = round(100 * ticks / CLOCK_TICKS / elapsed, 1) if ticks is not None and elapsed > 0 else None
        previous_cpus = self.previous.get("cpus", {})
        cores = []
        for name, counters in current.get("cpus", {}).items():
            busy, softirq = cpu_interval(counters, previous_cpus.get(name))
            if name == "cpu":
                row["cpu"], row["softirq"] = busy, softirq
            elif busy is not None:
                cores.append(busy)
        row["core"] = max(cores, default=None)
        self.previous, self.previous_time = current, now
        self.samples.append(row)

    def live_stats(self, process, log):
        try:
            fd = log.fileno()
            if b"listening on " not in os.pread(fd, 2048, 0) or process.poll() is not None:
                return {}
            offset = os.fstat(fd).st_size
            if self.halted.is_set():
                return {}
            process.send_signal(signal.SIGUSR1)
            for _ in range(8):
                if self.halted.wait(.1):
                    break
                text = os.pread(fd, 2048, offset).decode(errors="replace")
                stats = parse_stats(text)
                if "dropped" in stats:
                    return stats
        except (OSError, ValueError):
            pass
        return {}

    def run(self, process, log):
        self.sample(process.pid, {})
        while not self.halted.wait(self.interval):
            stats = self.live_stats(process, log)
            if not self.halted.is_set():
                self.sample(process.pid, stats)

    def finish(self, process, log, code):
        self.halted.set()
        if self.worker is not None:
            self.worker.join()
        try:
            fd = log.fileno()
            size = os.fstat(fd).st_size
            first = os.pread(fd, LOG_BYTES // 2, 0).decode(errors="replace") if size > LOG_BYTES else ""
            tail = os.pread(fd, LOG_BYTES, max(0, size - LOG_BYTES)).decode(errors="replace")
        except OSError:
            first, tail = "", "无法读取 tcpdump 诊断消息。"
        final = parse_stats(tail, final=True)
        self.sample(process.pid, final)
        messages = [line[:500] for line in (first + "\n" + tail).splitlines() if line.strip() and not parse_stats(line)]
        return {
            "interval": self.interval, "samples": list(self.samples), "final": final,
            "stderr": list(dict.fromkeys(messages))[-16:], "exit_code": code,
        }


def report_lines(result):
    summary = result["summary"]
    ended = summary.get("ended")
    lines = [
        "Xbox 抓包诊断日志", f"录制：{summary['name']}", f"接口：{summary.get('interface', '未知')}",
        f"开始（UTC）：{utc(summary['started'])}" if summary.get("started") is not None else "开始：未知",
        f"结束（UTC）：{utc(ended)}" if ended is not None else "结束：未知",
        f"状态：{summary.get('state', '未知')}",
    ]
    for label, key in (("已读取帧数", "frame_count"), ("目标设备报文", "packet_count"), ("内核抓包丢包", "kernel_drops")):
        value = summary.get(key)
        lines.append(f"{label}：{value if value is not None else '未知'}")
    if summary.get("error"):
        lines.append(f"录制错误：{summary['error']}")
    diagnostics = result.get("diagnostics")
    if not diagnostics:
        lines.extend(["", "此录制创建时尚未采样诊断。可在升级后重新录制以收集丢包时间与负载。"])
    else:
        lines.extend([
            f"tcpdump 退出码：{diagnostics['exit_code']}",
            f"抓包缓冲区：{diagnostics['buffer_kib']} KiB（请求值）",
            f"即时抓包模式：{'开启' if diagnostics['immediate'] else '关闭'}",
            "", "tcpdump 退出统计",
        ])
        final = diagnostics["final"]
        for key, label in (("captured", "已抓取"), ("received", "过滤命中"), ("dropped", "内核丢包"),
                           ("interface_dropped", "接口丢包")):
            lines.append(f"{label}：{final.get(key, '未知')}")
        lines.extend([
            "", f"抓包时间线（采样间隔约 {diagnostics['interval']} 秒）",
            "新增丢包按相邻可用计数相减。进程 CPU 用量以一个核心为 100%。短于采样周期的峰值可能无法显示。",
            "\t".join(label for _, label in COLUMNS),
        ])
        for sample in diagnostics["samples"]:
            lines.append("\t".join(str(sample[key]) if sample.get(key) is not None else "-" for key, _ in COLUMNS))
        messages = diagnostics["stderr"]
        lines.extend(["", "tcpdump 诊断消息", *(messages or ["无"])])
    return [line + "\n" for line in lines]
