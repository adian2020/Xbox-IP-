"""Keep temporary MRS downloads and publish jobs off the capture request thread."""

import base64
import ipaddress
import os
import threading
import time

from github import Destination, GitHub
from mrs import CHUNK_BYTES, KINDS, MAX_MRS, Codec

JOB_LIMIT = 8
JOB_TTL = 20 * 60


class Publisher:
    def __init__(self, directory):
        self.directory = directory
        self.lock = threading.Lock()
        self.jobs = {}

    def create(self, state):
        now = time.monotonic()
        for key, job in list(self.jobs.items()):
            if job["state"] != "running" and now - job["time"] >= JOB_TTL:
                del self.jobs[key]
        if len(self.jobs) >= JOB_LIMIT:
            key = min((key for key, job in self.jobs.items() if job["state"] != "running"),
                      key=lambda key: self.jobs[key]["time"])
            del self.jobs[key]
        key = os.urandom(16).hex()
        self.jobs[key] = {"state": state, "time": now, "files": {}}
        return key

    def get(self, key):
        job = self.jobs.get(key) if isinstance(key, str) else None
        if not job or (job["state"] != "running" and time.monotonic() - job["time"] >= JOB_TTL):
            raise ValueError("MRS 操作已过期。请重新生成或选择文件。")
        return job

    def start(self, work):
        with self.lock:
            if any(job["state"] == "running" for job in self.jobs.values()):
                raise ValueError("正在处理另一个 MRS 操作。请稍后重试。")
            key = self.create("running")
        threading.Thread(target=self.run, args=(key, work), daemon=True).start()
        return {"job": key}

    def run(self, key, work):
        try:
            result = {"state": "ready", **work()}
        except (ValueError, OSError) as exc:
            result = {"state": "error", "message": str(exc)}
        except Exception:
            result = {"state": "error", "message": "无法处理 MRS 操作。请检查文件和目标仓库后重试。"}
        with self.lock:
            self.jobs[key].update(result, time=time.monotonic())

    def build(self, entries):
        domains = {entry["value"] for entry in entries if "sources" in entry}
        addresses = {str(ipaddress.ip_network(entry["value"])) for entry in entries if "sources" not in entry}
        if not domains and not addresses:
            raise ValueError("请至少选中一个域名或 IP。")

        def build_files():
            codec = Codec(self.directory)
            files = {kind: codec.encode(kind, rules)
                     for kind, rules in zip(KINDS, (domains, addresses)) if rules}
            return {"files": files}

        return self.start(build_files)

    def status(self, key):
        with self.lock:
            job = self.get(key)
            return {field: job[field] for field in ("state", "message", "report") if field in job} | {
                "kinds": list(job["files"]),
            }

    def download(self, key, kind, offset):
        if kind not in KINDS or type(offset) is not int:
            raise ValueError("MRS 下载参数无效。")
        with self.lock:
            job = self.get(key)
            data = job["files"].get(kind)
        if not data or job["state"] != "ready" or not 0 <= offset < len(data):
            raise ValueError("找不到可下载的 MRS 文件。")
        end = min(offset + CHUNK_BYTES, len(data))
        return {"data": base64.b64encode(data[offset:end]).decode(), "next": end if end < len(data) else None}

    def import_chunk(self, key, kind, offset, data, done):
        if (kind not in KINDS or type(offset) is not int or type(done) is not bool
                or not isinstance(data, str) or len(data) > (CHUNK_BYTES + 2) // 3 * 4):
            raise ValueError("MRS 上传参数无效。")
        try:
            raw = base64.b64decode(data, validate=True)
        except ValueError:
            raise ValueError("MRS 文件分片无效。") from None
        if not 0 < len(raw) <= CHUNK_BYTES or not 0 <= offset <= MAX_MRS - len(raw):
            raise ValueError("单个 MRS 文件大小上限为 512 KiB。")

        with self.lock:
            if key == "":
                if offset != 0:
                    raise ValueError("请从头上传 MRS 文件。")
                key = self.create("importing")
                self.jobs[key]["finished"] = set()
            job = self.get(key)
            if job["state"] != "importing" or kind in job["finished"]:
                raise ValueError("请重新选择要上传的 MRS 文件。")
            buffer = job["files"].setdefault(kind, bytearray())
            if len(buffer) != offset:
                raise ValueError("MRS 文件分片顺序有误。")
            buffer.extend(raw)
            if done:
                job["finished"].add(kind)
            job["time"] = time.monotonic()
        return {"job": key}

    def publish(self, args):
        github = GitHub(args.get("token"))
        destination = Destination(args.get("repository"), args.get("branch", ""), args.get("directory", "rules"),
                                  args.get("game"), args.get("domain_name"), args.get("ip_name"))
        with self.lock:
            job = self.get(args.get("job"))
            files = job["files"]
            if not files or (job["state"] != "ready"
                             and (job["state"] != "importing" or files.keys() != job["finished"])):
                raise ValueError("请先准备要发布的 MRS 文件。")
            data = {kind: bytes(content) for kind, content in files.items()}

        def publish_files():
            return {"report": github.publish(destination, data, Codec(self.directory))}

        return self.start(publish_files)

    def dispatch(self, method, args):
        if method == "github_login":
            return GitHub(args.get("token")).login()
        if method == "github_publish":
            return self.publish(args)
        if method == "mrs_status":
            return self.status(args.get("job"))
        if method == "mrs_download":
            return self.download(args.get("job"), args.get("kind"), args.get("offset", 0))
        if method == "mrs_import":
            return self.import_chunk(args.get("job", ""), args.get("kind"), args.get("offset", 0),
                                     args.get("data"), args.get("done"))
        raise ValueError("未知操作。")
