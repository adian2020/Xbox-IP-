"""Regression tests for capture diagnostics and legacy reports."""

from pathlib import Path
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "root/usr/lib/xbox-capture"))

from diagnostics import CaptureDiagnostics, MAX_SAMPLES, parse_stats
from main import Controller, PAGE_BYTES, dumps


LIVE = "tcpdump: 220 packets captured, 260 packets received by filter, 11 packets dropped by kernel\n"
FINAL = "900 packets captured\n950 packets received by filter\n48 packets dropped by kernel\n"


class DiagnosticsTests(unittest.TestCase):
    def test_live_statistics_do_not_override_the_exit_summary(self):
        self.assertEqual(parse_stats(LIVE)["dropped"], 11)
        self.assertEqual(parse_stats(LIVE, final=True), {})
        self.assertEqual(parse_stats(LIVE + FINAL, final=True),
                         {"captured": 900, "received": 950, "dropped": 48})
        self.assertEqual(parse_stats("1 packet dropped by kernel\n", final=True), {"dropped": 1})

    def test_stats_signal_and_timeline_context(self):
        trace = CaptureDiagnostics("br-lan", 360, 1000)
        baseline = {"cpus": {"cpu": (100, 60, 10), "cpu0": (50, 30, 5)}, "net_drop": 4, "rx_drop": 0}
        next_snapshot = {
            "cpus": {"cpu": (200, 100, 23), "cpu0": (100, 40, 13)},
            "net_drop": 7, "rx_drop": 2, "available": 320,
        }
        with tempfile.TemporaryFile() as log:
            log.write(b"tcpdump: listening on br-lan\n")
            log.flush()

            def send_signal(value):
                self.assertEqual(value, signal.SIGUSR1)
                log.write(LIVE.encode())
                log.flush()

            process = SimpleNamespace(poll=lambda: None, send_signal=send_signal, pid=123)
            with patch("diagnostics.snapshot", side_effect=[baseline, next_snapshot, next_snapshot]), \
                    patch("diagnostics.time.monotonic", side_effect=[1000, 1090, 1110]):
                trace.sample(process.pid, {})
                trace.sample(process.pid, trace.live_stats(process, log))
                log.write(FINAL.encode())
                log.flush()
                result = trace.finish(process, log, 0)

        first, during, last = result["samples"]
        self.assertIsNone(first["drop_delta"])
        self.assertEqual((during["drop_delta"], last["drop_delta"]), (11, 37))
        self.assertEqual((during["cpu"], during["core"], during["softirq"]), (60.0, 80.0, 13.0))
        self.assertEqual((during["net_drop"], during["rx_drop"], during["available"]), (3, 2, 320))
        self.assertEqual(result["stderr"], ["tcpdump: listening on br-lan"])
        self.assertLessEqual(360 * 60 // result["interval"] + 2, MAX_SAMPLES)

    def test_report_paginates_and_old_recording_can_download_its_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            controller = Controller(Path(temp))
            id = "c" * 32
            recording = {
                "summary": {"id": id, "name": "Game", "kernel_drops": 198, "packet_count": 332125},
                "domains": [], "ips": [],
            }
            controller.save(recording)
            legacy = controller.dispatch("diagnostics", {"id": id})
            self.assertIn("内核抓包丢包：198", legacy["text"])
            self.assertIn("尚未采样诊断", legacy["text"])
            self.assertIsNone(legacy["next"])

            recording["diagnostics"] = {
                "interval": 15, "buffer_kib": 512, "immediate": True, "exit_code": 0,
                "final": parse_stats(FINAL, final=True),
                "samples": [{"utc": "2026-01-01T00:00:00+00:00", "dropped": 12345678, "received": index,
                             "captured": 12345678, "cpu": 100, "tcpdump_cpu": 100, "service_cpu": 100,
                             "core": 100, "softirq": 100, "seconds": index * 15,
                             "net_drop": 1234, "net_squeeze": 12345, "rx_drop": 12345} for index in range(MAX_SAMPLES)],
                "stderr": ["tcpdump: listening on br-lan"],
            }
            controller.save(recording)
            parts, offset = [], 0
            while offset is not None:
                report = controller.dispatch("diagnostics", {"id": id, "offset": offset})
                self.assertLess(len(dumps(report).encode()), PAGE_BYTES + 1024)
                parts.append(report["text"])
                offset = report["next"]
            self.assertGreater(len(parts), 1)
            self.assertEqual("".join(parts).count("2026-01-01T00:00:00+00:00"), MAX_SAMPLES)
            self.assertTrue("".join(parts).endswith("tcpdump: listening on br-lan\n"))


if __name__ == "__main__":
    unittest.main()
