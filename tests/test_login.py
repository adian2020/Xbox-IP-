"""Regression tests for GitHub login on the split OpenWrt Python runtime."""

from contextlib import redirect_stderr
from http.client import IncompleteRead
from io import BytesIO, StringIO
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "root/usr/lib/xbox-capture"))

from github import GitHub
from main import RPCHandler, load_line


TOKEN = "dummy_token_for_login_test"


class LoginTests(unittest.TestCase):
    def test_missing_idna_reports_required_package(self):
        with patch("github.lookup", side_effect=LookupError("unknown encoding: idna")):
            with self.assertRaisesRegex(ValueError, "python3-codecs"):
                GitHub(TOKEN).login()

    def test_incomplete_http_response_returns_a_network_error(self):
        client = GitHub(TOKEN)
        client.opener = Mock()
        client.opener.open.side_effect = IncompleteRead(b"")
        with self.assertRaisesRegex(ValueError, "无法连接 GitHub API"):
            client.login()

    def test_successful_login_returns_only_the_username(self):
        client = GitHub(TOKEN)
        with patch.object(client.opener, "open", return_value=BytesIO(b'{"login":"sample-user"}')) as open_url:
            self.assertEqual(client.login(), {"login": "sample-user"})
        request = open_url.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/user")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + TOKEN)

    def test_rpc_does_not_drop_connection_or_echo_unexpected_error(self):
        handler = object.__new__(RPCHandler)
        handler.connection = Mock()
        handler.rfile = BytesIO(json.dumps({"method": "github_login", "args": {"token": TOKEN}}).encode())
        handler.wfile = BytesIO()
        handler.server = Mock()
        handler.server.controller.dispatch.side_effect = RuntimeError(TOKEN)
        log = StringIO()
        with redirect_stderr(log):
            handler.handle()
        self.assertIn("录制服务处理请求时出错", json.loads(handler.wfile.getvalue())["error"])
        self.assertIn("RuntimeError", log.getvalue())
        self.assertNotIn(TOKEN, log.getvalue() + handler.wfile.getvalue().decode())

    def test_empty_and_oversize_rpc_messages_are_distinct(self):
        with self.assertRaisesRegex(ValueError, "未返回"):
            load_line(BytesIO(), 128, empty_message="录制服务未返回结果")
        with self.assertRaisesRegex(ValueError, "超过大小限制"):
            load_line(BytesIO(b"x" * 129), 128)
        self.assertEqual(load_line(BytesIO(), 128, allow_empty=True), {})


if __name__ == "__main__":
    unittest.main()
