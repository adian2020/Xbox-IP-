"""Regression tests for local IP ownership and lookup-only metadata."""

import gzip
import ipaddress
from io import BytesIO
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "root/usr/lib/xbox-capture"))

from asn import ASNIndex, ASNStore, build_index
from main import Controller, PAGE_BYTES, Session, dumps
from packets import Device


FEED = (
    b"1.0.0.0\t1.0.0.2\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n"
    b"1.0.0.3\t1.0.0.4\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n"
    b"1.0.0.8\t1.0.0.9\t8075\tUS\tMICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation\n"
    b"1.0.0.10\t1.0.0.10\t0\tNone\tNot routed\n"
    b"2606:4700::1100\t2606:4700::11ff\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n"
)


class OwnershipTests(unittest.TestCase):
    def test_ipv4_and_ipv6_boundaries(self):
        output = BytesIO()
        build_index(BytesIO(FEED), output)
        index = ASNIndex(output.getvalue())
        for ip in ("1.0.0.0", "1.0.0.4", "2606:4700::1100", "2606:4700::11ff", "::ffff:1.0.0.3"):
            self.assertEqual(index.lookup(ip)["asn"], 13335)
        self.assertEqual(index.lookup("1.0.0.9")["asn"], 8075)
        for ip in ("0.255.255.255", "1.0.0.5", "1.0.0.10", "1.0.0.11", "2606:4700::1200"):
            self.assertIsNone(index.lookup(ip))

    def test_failed_refresh_keeps_the_previous_database(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ASNStore(Path(temp))
            with patch("asn.download_feed", side_effect=lambda path: path.write_bytes(gzip.compress(FEED))):
                store.refresh()
            published = store.path.read_bytes()
            self.assertIsNone(store.status()["error"])
            with patch("asn.download_feed", side_effect=lambda path: path.write_bytes(gzip.compress(b"bad"))):
                store.refresh()
            self.assertEqual(store.path.read_bytes(), published)
            self.assertIn("格式无效", store.status()["error"])
            self.assertFalse(store.build_path.exists())
            self.assertFalse(store.download_path.exists())

    def test_live_and_history_enrich_ip_rows_and_keep_exports(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            controller = Controller(directory)
            with controller.asn.path.open("wb") as output:
                build_index(BytesIO(FEED), output)
            device = Device("192.168.1.50")
            session = Session("Game", "br-lan", device, device, 10, None)
            session.observe(ipaddress.ip_address("1.0.0.8").packed, {"auth.example.com"}, "TLS SNI", ("TCP", 443))
            controller.active = session
            id = session.summary["id"]
            live = controller.dispatch("live", {"id": id})["entries"]
            self.assertNotIn("owner", live[0])
            self.assertEqual(live[1]["owner"]["asn"], 8075)
            controller.save(session.result())
            result = controller.dispatch("get", {"id": id})
            self.assertEqual(result["entries"][1]["owner"], live[1]["owner"])
            self.assertNotIn('"owner"', dumps(controller.get(id)))
            exported = controller.dispatch("export", {"id": id})
            self.assertIn("IP-CIDR,1.0.0.8/32,no-resolve", exported["yaml"])
            self.assertNotIn("Microsoft", exported["yaml"])

    def test_history_pagination_counts_ownership_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            controller = Controller(Path(temp))
            data = (b"1.1.0.0\t1.1.255.255\t1234\tUS\t" + b"A" * 180 + b"\n"
                    + FEED.splitlines()[-1] + b"\n")
            with controller.asn.path.open("wb") as output:
                build_index(BytesIO(data), output)
            id = "a" * 32
            controller.save({"summary": {"id": id, "name": "Many"}, "domains": [],
                             "ips": [str(ipaddress.ip_address(0x01010000 + i)) for i in range(500)]})
            result = controller.dispatch("get", {"id": id, "offset": 0})
            self.assertGreater(result["next"], 0)
            self.assertLess(len(dumps(result).encode()), PAGE_BYTES + 1024)


if __name__ == "__main__":
    unittest.main()
