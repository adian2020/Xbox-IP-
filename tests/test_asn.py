"""Regression tests for local IP ownership and lookup-only metadata."""

import gzip
import ipaddress
from io import BytesIO
from pathlib import Path
import struct
import sys
import tempfile
import time
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

    def test_country_follows_each_range(self):
        feed = FEED.replace(b"1.0.0.3\t1.0.0.4\t13335\tUS", b"1.0.0.3\t1.0.0.4\t13335\tJP")
        feed = feed.replace(b"2606:4700::11ff\t13335\tUS", b"2606:4700::11ff\t13335\tUnknown")
        output = BytesIO()
        build_index(BytesIO(feed), output)
        index = ASNIndex(output.getvalue())
        self.assertEqual(index.lookup("1.0.0.2")["country"], "US")
        self.assertEqual(index.lookup("::ffff:1.0.0.3")["country"], "JP")
        self.assertIsNone(index.lookup("2606:4700::11ff")["country"])

    def test_existing_database_still_loads_and_gets_the_update_hint(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ASNStore(Path(temp))
            legacy = (struct.pack(">4sIII", b"XAS1", 1, 1, 1)
                      + struct.pack(">4sI", ipaddress.ip_address("1.0.0.0").packed, 13335)
                      + struct.pack(">16sI", ipaddress.ip_address("2606:4700::1100").packed, 13335)
                      + struct.pack(">IIH", 13335, 0, len(b"Cloudflare"))
                      + b"Cloudflare")
            store.path.write_bytes(legacy)
            self.assertFalse(store.status()["has_country"])
            self.assertIsNotNone(store.status()["updated"])
            with store.reader() as index:
                self.assertEqual(index.lookup("1.0.0.0"), {"asn": 13335, "organization": "Cloudflare"})
                self.assertEqual(index.lookup("2606:4700::1100")["asn"], 13335)
            with patch("asn.download_feed", side_effect=lambda path, _: path.write_bytes(gzip.compress(FEED))):
                store.refresh()
            self.assertTrue(store.status()["has_country"])
            with store.reader() as index:
                self.assertEqual(index.lookup("2606:4700::1100")["country"], "US")

    def test_failed_refresh_keeps_the_previous_database(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ASNStore(Path(temp))
            with patch("asn.download_feed", side_effect=lambda path, _: path.write_bytes(gzip.compress(FEED))):
                store.refresh()
            published = store.path.read_bytes()
            self.assertIsNone(store.status()["error"])
            with patch("asn.download_feed", side_effect=lambda path, _: path.write_bytes(gzip.compress(b"bad"))):
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
            session.observe_answers({
                ("auth.example.com", ipaddress.ip_address("1.0.0.8").packed),
                ("auth.example.com", ipaddress.ip_address("1.0.0.2").packed),
                ("auth.example.com", ipaddress.ip_address("198.18.0.1").packed),
            })
            controller.active = session
            id = session.summary["id"]
            live = controller.dispatch("live", {"id": id})["entries"]
            self.assertNotIn("owner", live[0])
            self.assertEqual([(owner["asn"], owner["source"]) for owner in live[0]["owners"]],
                             [(8075, "TLS SNI"), (13335, "DNS 回应")])
            self.assertEqual(live[1]["owner"]["asn"], 8075)
            self.assertEqual(live[1]["owner"]["country"], "US")
            controller.save(session.result())
            result = controller.dispatch("get", {"id": id})
            self.assertEqual(result["entries"][0]["owners"], live[0]["owners"])
            self.assertEqual(result["entries"][1]["owner"], live[1]["owner"])
            self.assertNotIn('"owner"', dumps(controller.get(id)))
            self.assertNotIn('"owners"', dumps(controller.get(id)))
            exported = controller.dispatch("export", {"id": id})
            self.assertIn("IP-CIDR,1.0.0.8/32,no-resolve", exported["yaml"])
            self.assertNotIn("Microsoft", exported["yaml"])
            self.assertNotIn("IP-CIDR,1.0.0.2", exported["yaml"])

    def test_progress_reports_download_and_index_before_completion(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ASNStore(Path(temp))
            feed = gzip.compress(FEED)

            def download(path, report):
                report(20, len(feed))
                path.write_bytes(feed)
                report(len(feed), len(feed))

            with patch("asn.download_feed", side_effect=download), patch.object(store, "report", wraps=store.report) as report:
                store.refresh()
            self.assertEqual([call.args[0] for call in report.call_args_list],
                             ["download", "download", "index", "finalize"])
            self.assertIsNone(store.status()["progress"])
            self.assertIsNone(store.status()["error"])

    def test_domain_lookup_falls_back_without_changing_the_recording(self):
        with tempfile.TemporaryDirectory() as temp:
            controller = Controller(Path(temp))
            with controller.asn.path.open("wb") as output:
                build_index(BytesIO(FEED), output)
            device = Device("192.168.1.50")
            session = Session("Game", "br-lan", device, device, 10, None)
            name = "game.example"
            session.observe(ipaddress.ip_address("192.168.1.1").packed, {name}, "DNS", ("UDP", 53))
            controller.active = session
            id = session.summary["id"]
            args = {"id": id, "domain": name}

            def lookup(resolver):
                result = controller.dispatch("domain_lookup", {**args, "resolver": resolver})
                deadline = time.monotonic() + 1
                while result["pending"] and time.monotonic() < deadline:
                    time.sleep(.01)
                    result = controller.dispatch("domain_lookup", args)
                self.assertFalse(result["pending"])
                return result

            with patch("dnslookup.resolve_system", return_value={ipaddress.ip_address("198.18.0.1").packed}) as resolve:
                with self.assertRaisesRegex(ValueError, "不在"):
                    controller.dispatch("domain_lookup", {**args, "domain": "other.example", "resolver": "system"})
                resolve.assert_not_called()
                self.assertIn("Fake IP", lookup("system")["error"])

            address = ipaddress.ip_address("1.0.0.8").packed
            with patch("dnslookup.resolve_alidns", return_value={address}):
                owner, = lookup("alidns")["owners"]
            self.assertEqual((owner["asn"], owner["country"], owner["source"]), (8075, "US", "阿里公共 DNS 补查"))
            live, = controller.dispatch("live", {"id": id})["entries"]
            self.assertEqual(live["owners"], [owner])
            self.assertNotIn("ports", live)
            controller.save(session.result())
            controller.active = None
            recorded, = controller.dispatch("get", {"id": id})["entries"]
            self.assertEqual(recorded["owners"], [owner])
            self.assertEqual(controller.get(id)["domain_ips"], {})
            yaml = controller.dispatch("export", {"id": id})["yaml"]
            self.assertIn("DOMAIN,game.example", yaml)
            self.assertNotIn("1.0.0.8", yaml)

            session.observe(address, {name}, "TLS SNI", ("TCP", 443))
            controller.active = session
            live, = controller.dispatch("live", {"id": id, "kind": "domain"})["entries"]
            self.assertEqual(live["owners"][0]["source"], "TLS SNI")

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
