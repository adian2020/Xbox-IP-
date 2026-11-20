"""Publish both MRS rule sets as a single GitHub commit."""

import base64
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from mrs import KINDS, MAX_MRS, merge_rules, mrs_names, segment

API = "https://api.github.com"
MAX_RESPONSE = 2 * 1024 * 1024
REPOSITORY = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}")
TOKEN = re.compile(r"[A-Za-z0-9_-]{20,255}")


class GitHubError(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def branch_name(branch):
    if (not isinstance(branch, str) or not 1 <= len(branch.encode()) <= 200
            or not branch.isprintable() or any(char in branch for char in " ~^:?*[\\")
            or ".." in branch or "@{" in branch or branch == "@" or branch.startswith("-")
            or branch.endswith(".") or any(not part or part.startswith(".") or part.endswith(".lock")
                                          for part in branch.split("/"))):
        raise ValueError("请输入有效的 GitHub 分支名，或留空使用默认分支。")
    return branch


class Destination:
    def __init__(self, repository, branch, directory, game, domain_name, ip_name):
        if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
            raise ValueError("仓库请填写 owner/repository。")
        self.repository = repository
        self.branch = branch_name(branch) if branch != "" else ""
        if not isinstance(directory, str) or len(directory.encode()) > 400:
            raise ValueError("GitHub 目录过长。")
        parent = directory.split("/") if directory else []
        if len(parent) > 6:
            raise ValueError("GitHub 目录最多可包含 6 层。")
        self.game = segment(game, "游戏或软件目录名")
        self.directory = tuple(segment(part, "GitHub 目录") for part in parent) + (self.game,)
        self.names = mrs_names(domain_name, ip_name)

    def path(self, kind):
        return "/".join((*self.directory, self.names[kind]))


class GitHub:
    def __init__(self, token):
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            raise ValueError("请输入有效的 GitHub Personal Access Token。")
        self.token = token
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, path, method="GET", body=None):
        data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
        request = Request(API + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token,
            "User-Agent": "Xbox-Capture-OpenWrt",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        })
        try:
            with self.opener.open(request, timeout=8) as response:
                data = response.read(MAX_RESPONSE + 1)
        except HTTPError as exc:
            status = exc.code
            exc.close()
            messages = {
                401: "GitHub 令牌已失效或无效。",
                403: "GitHub 拒绝访问。请检查仓库的 Contents 写入权限、分支保护或访问频率限制。",
                404: "找不到 GitHub 仓库、分支或文件。请核对名称和令牌的仓库访问范围。",
                409: "GitHub 仓库尚未初始化，或分支刚刚有新的提交。",
                422: "GitHub 拒绝更新分支。请检查目标分支是否允许提交。",
            }
            raise GitHubError(status, messages.get(status, f"GitHub 请求失败（HTTP {status}）。")) from None
        except (URLError, OSError):
            raise ValueError("无法连接 GitHub API。请检查路由器网络、系统时间和 CA 证书。") from None
        if len(data) > MAX_RESPONSE:
            raise ValueError("GitHub 响应过大。")
        try:
            response = json.loads(data)
        except ValueError:
            raise ValueError("GitHub 返回了无法读取的响应。") from None
        if not isinstance(response, dict):
            raise ValueError("GitHub 返回了意外的响应。")
        return response

    def login(self):
        login = self.request("/user").get("login")
        if not isinstance(login, str) or not login:
            raise ValueError("当前令牌无法读取 GitHub 用户。")
        return {"login": login}

    def head(self, prefix, branch):
        return self.request(f"{prefix}/git/ref/heads/{quote(branch, safe='/')}")["object"]["sha"]

    def directory_entries(self, prefix, tree, directory):
        for part in directory:
            entries = self.tree(prefix, tree)
            entry = entries.get(part)
            if not entry:
                return {}
            if entry["type"] != "tree":
                raise ValueError("目标目录与仓库中已有文件同名。")
            tree = entry["sha"]
        return self.tree(prefix, tree)

    def tree(self, prefix, sha):
        result = self.request(f"{prefix}/git/trees/{sha}")
        if result.get("truncated"):
            raise ValueError("GitHub 目录条目过多，无法安全比对。")
        return {entry["path"]: entry for entry in result["tree"]}

    def blob(self, prefix, entry):
        if entry["type"] != "blob" or entry["mode"] not in ("100644", "100755"):
            raise ValueError("目标路径与目录、符号链接或子模块同名。")
        if entry.get("size", 0) > MAX_MRS:
            raise ValueError("GitHub 上的旧 MRS 超过 512 KiB。")
        blob = self.request(f"{prefix}/git/blobs/{entry['sha']}")
        if blob.get("size", 0) > MAX_MRS or blob.get("encoding") != "base64":
            raise ValueError("GitHub 上的旧 MRS 文件过大或无法读取。")
        return base64.b64decode("".join(blob["content"].split()), validate=True)

    def publish(self, destination, files, codec):
        prefix = "/repos/" + destination.repository
        repo = self.request(prefix)
        branch = destination.branch or branch_name(repo.get("default_branch"))
        fresh = {kind: codec.decode(kind, files[kind]) for kind in KINDS if kind in files}
        for _ in range(3):
            base = self.head(prefix, branch)
            base_tree = self.request(f"{prefix}/git/commits/{base}")["tree"]["sha"]
            existing = self.directory_entries(prefix, base_tree, destination.directory)
            changes = []
            updates = []
            for kind, fresh_rules in fresh.items():
                path = destination.path(kind)
                entry = existing.get(destination.names[kind])
                merged = files[kind]
                mode = "100644"
                action = "created"
                if entry:
                    old = codec.decode(kind, self.blob(prefix, entry))
                    combined = merge_rules(kind, old, fresh_rules)
                    if combined != old:
                        merged = codec.encode(kind, combined)
                    if combined == old or codec.decode(kind, merged) == old:
                        updates.append({"path": path, "action": "unchanged"})
                        continue
                    mode = entry["mode"]
                    action = "merged"
                changes.append((path, mode, merged))
                updates.append({"path": path, "action": action})

            web = "https://github.com/" + destination.repository
            if not changes:
                directory = quote("/".join(destination.directory), safe="/")
                return {"commit": "", "url": f"{web}/tree/{base}/{directory}", "files": updates}

            tree = []
            for path, mode, data in changes:
                blob = self.request(f"{prefix}/git/blobs", "POST", {
                    "content": base64.b64encode(data).decode(), "encoding": "base64",
                })
                tree.append({"path": path, "mode": mode, "type": "blob", "sha": blob["sha"]})
            tree_sha = self.request(f"{prefix}/git/trees", "POST", {"base_tree": base_tree, "tree": tree})["sha"]
            commit = self.request(f"{prefix}/git/commits", "POST", {
                "message": f"合并 {destination.game} 的 MRS 规则", "tree": tree_sha, "parents": [base],
            })["sha"]
            try:
                self.request(f"{prefix}/git/refs/heads/{quote(branch, safe='/')}", "PATCH", {
                    "sha": commit, "force": False,
                })
            except GitHubError as exc:
                if exc.status in (409, 422) and self.head(prefix, branch) != base:
                    continue
                raise
            return {"commit": commit, "url": f"{web}/commit/{commit}", "files": updates}
        raise ValueError("目标分支持续更新。请重试，插件会重新读取最新 MRS。")
