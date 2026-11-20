"""Run with a Mihomo binary that supports convert-ruleset."""

import base64
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "root/usr/lib/xbox-capture"))

from github import Destination, GitHub, GitHubError
from main import Controller
from mrs import Codec


class Repository(GitHub):
    """Represent Git endpoints using local immutable trees and a mutable ref."""

    def __init__(self, files):
        self.trees = {}
        self.blobs = {}
        self.commits = {}
        self.tip = self.commit(files)
        self.racing = None
        self.pushes = 0

    def commit(self, files):
        for data in files.values():
            self.blobs.setdefault(data.hex(), data)
        tree = "tree" + str(len(self.trees))
        sha = "commit" + str(len(self.commits))
        self.trees[tree] = files
        self.commits[sha] = tree
        return sha

    def files(self):
        return self.trees[self.commits[self.tip]]

    def tree(self, prefix, sha):
        del prefix
        root, _, folder = sha.partition(":")
        entries = {}
        for path, data in self.trees[root].items():
            if path.startswith(folder):
                name, separator, _ = path[len(folder):].partition("/")
                if separator:
                    entries[name] = {"type": "tree", "sha": f"{root}:{folder}{name}/"}
                else:
                    entries[name] = {"type": "blob", "mode": "100644", "size": len(data), "sha": data.hex()}
        return entries

    def request(self, path, method="GET", body=None):
        prefix = "/repos/owner/xbox"
        if path == prefix:
            return {"default_branch": "main"}
        endpoint = path.removeprefix(prefix + "/git/")
        if method == "GET":
            if endpoint == "ref/heads/main":
                return {"object": {"sha": self.tip}}
            if endpoint.startswith("commits/"):
                return {"tree": {"sha": self.commits[endpoint.split("/")[-1]]}}
            if endpoint.startswith("blobs/"):
                data = self.blobs[endpoint.split("/")[-1]]
                return {"size": len(data), "content": base64.b64encode(data).decode(), "encoding": "base64"}
        if method == "POST":
            if endpoint == "blobs":
                data = base64.b64decode(body["content"], validate=True)
                self.blobs[data.hex()] = data
                return {"sha": data.hex()}
            if endpoint == "trees":
                files = dict(self.trees[body["base_tree"]])
                files.update({entry["path"]: self.blobs[entry["sha"]] for entry in body["tree"]})
                tree = "tree" + str(len(self.trees))
                self.trees[tree] = files
                return {"sha": tree}
            if endpoint == "commits":
                assert body["parents"] == [self.tip]
                sha = "commit" + str(len(self.commits))
                self.commits[sha] = body["tree"]
                return {"sha": sha}
        if method == "PATCH" and endpoint == "refs/heads/main":
            assert body["force"] is False
            if self.racing:
                self.tip = self.commit(self.racing)
                self.racing = None
                raise GitHubError(422, "concurrent update")
            self.tip = body["sha"]
            self.pushes += 1
            return {}
        raise AssertionError((method, endpoint))


class MRSTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        try:
            self.codec = Codec(self.directory)
        except ValueError as exc:
            self.skipTest(str(exc))
        self.destination = Destination("owner/xbox", "", "rules", "新 游戏", "domains", "ip")
        self.domain = self.destination.path("domain")
        self.ip = self.destination.path("ipcidr")

    def test_first_publish_then_merge_with_concurrent_changes(self):
        repository = Repository({"README.md": b"existing"})
        original = {
            "domain": self.codec.encode("domain", {"+.old.example"}),
            "ipcidr": self.codec.encode("ipcidr", {"192.0.2.0/24"}),
        }
        report = repository.publish(self.destination, original, self.codec)
        self.assertEqual([file["action"] for file in report["files"]], ["created", "created"])

        racing = dict(repository.files())
        racing[self.domain] = self.codec.encode("domain", {"+.old.example", "concurrent.example"})
        repository.racing = racing
        incoming = {
            "domain": self.codec.encode("domain", {"new.example"}),
            "ipcidr": self.codec.encode("ipcidr", {"192.0.2.33/32", "2001:db8::1/128"}),
        }
        report = repository.publish(self.destination, incoming, self.codec)
        self.assertEqual([file["action"] for file in report["files"]], ["merged", "merged"])
        self.assertEqual(repository.pushes, 2)
        self.assertEqual(repository.files()["README.md"], b"existing")
        self.assertEqual(self.codec.decode("domain", repository.files()[self.domain]),
                         {"+.old.example", "new.example", "concurrent.example"})
        self.assertEqual(self.codec.decode("ipcidr", repository.files()[self.ip]),
                         {"192.0.2.0/24", "2001:db8::1/128"})

        tip = repository.tip
        report = repository.publish(self.destination, incoming, self.codec)
        self.assertEqual(report["commit"], "")
        self.assertEqual(repository.tip, tip)

    def test_wrong_type_aborts_both_updates(self):
        remote_domain = self.codec.encode("ipcidr", {"192.0.2.0/24"})
        repository = Repository({self.domain: remote_domain})
        files = {
            "domain": self.codec.encode("domain", {"game.example"}),
            "ipcidr": self.codec.encode("ipcidr", {"2001:db8::1/128"}),
        }
        with self.assertRaises(ValueError):
            repository.publish(self.destination, files, self.codec)
        self.assertEqual(repository.files(), {self.domain: remote_domain})
        self.assertEqual(repository.pushes, 0)

    def test_recording_selection_build_and_import(self):
        controller = Controller(self.directory)
        recording = "f" * 32
        controller.save({
            "summary": {"id": recording, "name": "示例录制"},
            "domains": [{"value": "omit.example", "sources": ["DNS"]},
                        {"value": "game.example", "sources": ["DNS"]}],
            "ips": ["2001:db8::1"],
        })
        job = controller.dispatch("mrs_build", {"id": recording, "omit": "100"})["job"]
        for _ in range(100):
            reply = controller.dispatch("mrs_status", {"job": job})
            if reply["state"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(reply["state"], "ready", reply)
        self.assertEqual(set(reply["kinds"]), {"domain", "ipcidr"})
        for kind, expected in (("domain", {"game.example"}), ("ipcidr", {"2001:db8::1/128"})):
            result = controller.dispatch("mrs_download", {"job": job, "kind": kind})
            self.assertIsNone(result["next"])
            self.assertEqual(self.codec.decode(kind, base64.b64decode(result["data"])), expected)

        data = self.codec.encode("domain", {"game.example"})
        piece = base64.b64encode(data[:4]).decode()
        import_job = controller.dispatch("mrs_import", {
            "kind": "domain", "offset": 0, "data": piece, "done": False,
        })["job"]
        with self.assertRaises(ValueError):
            controller.dispatch("mrs_import", {
                "job": import_job, "kind": "domain", "offset": 3, "data": piece, "done": True,
            })
        controller.dispatch("mrs_import", {
            "job": import_job, "kind": "domain", "offset": 4,
            "data": base64.b64encode(data[4:]).decode(), "done": True,
        })
        self.assertEqual(bytes(controller.publisher.get(import_job)["files"]["domain"]), data)


if __name__ == "__main__":
    unittest.main()
