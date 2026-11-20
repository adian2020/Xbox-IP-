"""Regression tests for dual-stack capture and cooked Linux frames."""

import io
import ipaddress
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "root/usr/lib/xbox-capture"))

from main import Controller, Session, export_rules, result_entries
from neighbours import capture_device, macs_from_arp, macs_from_neighbours
from packets import LINK_ETHERNET, LINK_SLL2, Device, PacketDecoder, read_pcap

MAC = "00:11:22:33:44:55"
ADDRESS = "192.168.42.236"


def packed(value):
    return ipaddress.ip_address(value).packed


def ipv6():
    return (struct.pack(">IHBB", 0x60000000, 0, 59, 64)
            + packed("fd00::236") + packed("2606:4700::1111"))


def cooked(source=MAC, packet_type=0):
    address = bytes.fromhex(source.replace(":", ""))
    return struct.pack(">HHIHBB8s", 0x86dd, 0, 42, 1, packet_type, 6, address) + ipv6()


class CaptureTests(unittest.TestCase):
    def test_neighbour_scope(self):
        neighbours = (
            f"{ADDRESS} dev br-lan lladdr {MAC} STALE\n"
            f"{ADDRESS} dev br-other lladdr 00:11:22:33:44:99 REACHABLE\n"
            f"{ADDRESS} dev br-lan lladdr 00:11:22:33:44:96 FAILED\n"
        )
        self.assertEqual(list(macs_from_neighbours(neighbours, ADDRESS, "br-lan")), [MAC])
        arp = (f"{ADDRESS} 0x1 0x0 00:11:22:33:44:96 * br-lan\n"
               f"{ADDRESS} 0x1 0x2 {MAC} * br-lan\n")
        self.assertEqual(list(macs_from_arp(arp, ADDRESS, "br-lan")), [MAC])

    def test_ipv4_selector_upgrades_to_mac_for_ipv6(self):
        device = Device(ADDRESS)
        with patch("neighbours.neighbour_macs", return_value={MAC}):
            selector = capture_device(device, "br-lan")
            self.assertEqual(selector.label, MAC)
            with self.assertRaises(ValueError):
                capture_device(device, "br-lan", "00:11:22:33:44:99")

        frame = (bytes.fromhex("020000000001001122334455") + bytes.fromhex("8100004086dd") + ipv6())
        self.assertIsNone(PacketDecoder(device).inspect(LINK_ETHERNET, frame)[0])
        self.assertEqual(PacketDecoder(selector).inspect(LINK_ETHERNET, frame)[0], packed("2606:4700::1111"))

        with patch("neighbours.neighbour_macs", return_value={MAC, "00:11:22:33:44:99"}):
            self.assertIs(capture_device(device, "any"), device)

    def test_cooked_ingress_mac(self):
        decoder = PacketDecoder(Device(MAC))
        frame = cooked()
        pcap = (struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 8192, LINK_SLL2)
                + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)
        (link, frame), = list(read_pcap(io.BytesIO(pcap)))
        self.assertEqual(decoder.inspect(link, frame)[0], packed("2606:4700::1111"))
        for unwanted in (cooked(packet_type=4), cooked(source="00:11:22:33:44:99"), frame[:19]):
            self.assertIsNone(decoder.inspect(LINK_SLL2, unwanted)[0])

    def test_private_and_fakeip_are_counted_as_traffic(self):
        session = Session("GTA", "br-lan", Device(ADDRESS), Device(MAC), 10, None)
        session.observe(packed("192.168.42.1"), set(), None)
        session.observe(packed("198.18.0.2"), set(), None)
        self.assertEqual(session.summary["packet_count"], 2)
        self.assertEqual(session.summary["fakeip_count"], 1)
        self.assertEqual(session.summary["ip_count"], 0)

    def test_ports_are_kept_for_ip_and_tls_domain(self):
        device = Device(ADDRESS)
        decoder = PacketDecoder(device)
        session = Session("Game", "br-lan", device, device, 10, None)
        target = packed("8.8.4.4")
        udp = struct.pack(">HHHH", 18000, 3074, 8, 0)
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 28, 0, 0, 64, 17, 0)
        ethernet = bytes.fromhex("0200000000010011223344550800")
        observed = decoder.inspect(LINK_ETHERNET, ethernet + ip + packed(ADDRESS) + target + udp)
        self.assertEqual(observed[3], ("UDP", 3074))
        session.observe(*observed)
        session.observe(target, {"game.example"}, "TLS SNI", ("TCP", 8443))
        session.observe(packed("192.168.42.1"), {"dns-only.example"}, "DNS", ("UDP", 53))
        result = session.result()
        self.assertEqual(result_entries(result), [
            {"value": "dns-only.example", "sources": ["DNS"]},
            {"value": "game.example", "sources": ["TLS SNI"], "ports": [("TCP", 8443)]},
            {"value": "8.8.4.4", "ports": [("TCP", 8443), ("UDP", 3074)]},
        ])
        rules = export_rules(result, "inline", "Xbox", "", 0)["yaml"]
        self.assertIn('"IP-CIDR,8.8.4.4/32,Xbox,no-resolve"', rules)
        self.assertNotIn("3074", rules)
        self.assertNotIn("8443", rules)

    def test_bulk_delete_validates_before_removing(self):
        with tempfile.TemporaryDirectory() as temp:
            ids = ["1" * 32, "2" * 32, "3" * 32]
            controller = Controller(Path(temp))
            for id in ids:
                controller.save({"summary": {"id": id, "started": 1}, "domains": [], "ips": []})
            controller = Controller(Path(temp))
            with self.assertRaises(ValueError):
                controller.dispatch("remove_many", {"ids": [ids[0], "../invalid"]})
            self.assertEqual(len(controller.history), 3)
            response = controller.dispatch("remove_many", {"ids": [ids[0], ids[1], ids[0]]})
            self.assertEqual(response, {"removed": ids[:2], "failed": []})
            self.assertEqual(set(controller.history), {ids[2]})
            self.assertEqual(list(Path(temp).glob("*.json")), [controller.path(ids[2])])


if __name__ == "__main__":
    unittest.main()
