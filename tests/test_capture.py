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

from main import LIVE_ROWS, Controller, Session, export_rules, result_entries
from devices import device_records, dnsmasq_leases, interface_scopes, neighbour_rows
from neighbours import capture_device, macs_from_arp, macs_from_neighbours
from packets import LINK_ETHERNET, LINK_SLL2, Device, PacketDecoder, dns_answers, read_pcap

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
    def test_device_picker_merges_leases_and_neighbours(self):
        scope = interface_scopes([
            {"interface": "lan", "up": True, "l3_device": "br-lan",
             "ipv4-address": [{"address": "192.168.42.1", "mask": 24}]},
            {"interface": "guest", "up": True, "l3_device": "br-guest",
             "ipv4-address": [{"address": "192.168.50.1", "mask": 24}]},
            {"interface": "wan", "up": True, "l3_device": "eth1",
             "ipv4-address": [{"address": "192.168.99.2", "mask": 24}]},
        ], "br-lan")
        neighbours = neighbour_rows(
            f"{ADDRESS} dev br-lan lladdr {MAC} REACHABLE\n"
            f"fe80::42 dev br-lan lladdr {MAC} STALE\n"
            "192.168.50.23 dev br-guest lladdr 00:11:22:33:44:66 FAILED\n"
            "192.168.99.1 dev eth1 lladdr 00:11:22:33:44:99 REACHABLE\n", "", scope
        )
        leases = [
            {"ipaddr": ADDRESS, "hostname": "xbox-dhcp", "macaddr": MAC, "expires": 180},
            {"ipaddr": ADDRESS, "hostname": "old-host", "macaddr": "00:11:22:33:44:77", "expires": 180},
            {"ipaddr": "192.168.50.23", "hostname": "guest", "macaddr": "00:11:22:33:44:66", "expires": False},
            {"ipaddr": "192.168.50.24", "hostname": "expired", "macaddr": "00:11:22:33:44:88", "expires": 0},
        ]
        records = {item["mac"]: item for item in device_records(scope, neighbours, leases, {MAC: "Xbox 客厅"})}
        self.assertEqual(set(records), {MAC, "00:11:22:33:44:66"})
        self.assertEqual(records[MAC], {
            "mac": MAC, "name": "Xbox 客厅", "interfaces": ["br-lan"], "ips": [ADDRESS, "fe80::42"],
        })
        self.assertEqual(records["00:11:22:33:44:66"]["interfaces"], ["br-guest"])
        self.assertEqual(list(dnsmasq_leases(
            f"4 {MAC} {ADDRESS} expired *\n0 {MAC} {ADDRESS} Xbox *", 8
        )), [{"macaddr": MAC, "ipaddr": ADDRESS, "hostname": "Xbox"}])

    def test_live_panel_pages_and_searches_active_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            controller = Controller(Path(temp))
            device = Device(ADDRESS)
            active = Session("Game", "br-lan", device, device, 10, None)
            controller.active = active
            for number in range(LIVE_ROWS + 4):
                active.observe(packed("8.8.4.4"), {f"game{number}.example"}, "TLS SNI", ("TCP", 443))
            active.observe(packed("8.8.4.4"), set(), None, ("UDP", 3074))
            active.observe(packed("8.8.4.4"), set(), None, ("UDP", 3074))
            active.observe(packed("198.18.0.1"), set(), None, ("UDP", 3075))
            args = {"id": active.summary["id"]}
            first = controller.dispatch("live", args)
            self.assertEqual(len(first["entries"]), LIVE_ROWS)
            self.assertEqual(first["total"], LIVE_ROWS + 5)
            self.assertEqual(first["entries"][0]["ports"], [("TCP", 443), ("UDP", 3074)])
            self.assertEqual(first["next"], LIVE_ROWS)
            second = controller.dispatch("live", {**args, "offset": first["next"]})
            self.assertEqual(len(second["entries"]), 5)
            domains = controller.dispatch("live", {**args, "kind": "domain", "query": "game0"})
            self.assertEqual([row["value"] for row in domains["entries"]], ["game0.example"])
            ip = controller.dispatch("live", {**args, "query": "udp 3074"})
            self.assertEqual([row["value"] for row in ip["entries"]], ["8.8.4.4"])
            self.assertEqual(controller.dispatch("live", {"id": "f" * 32}), {"id": None})

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

    def test_dns_reply_links_only_answers_for_the_selected_device(self):
        device = Device(ADDRESS)
        session = Session("Game", "br-lan", device, Device(MAC), 10, None)
        resolver = packed("192.168.42.1")
        session.observe(resolver, {"game.example"}, "DNS", ("UDP", 53))
        alias = b"\x03cdn\x07example\x00"
        v4, v6 = packed("8.8.4.4"), packed("2606:4700::1111")

        def answer(name, kind, data):
            return name + struct.pack(">HHIH", kind, 1, 60, len(data)) + data

        dns = (struct.pack(">6H", 12, 0x8180, 1, 4, 0, 0)
               + b"\x04game\x07example\x00\x00\x01\x00\x01"
               + answer(b"\xc0\x0c", 5, alias)
               + answer(alias, 1, v4)
               + answer(alias, 28, v6)
               + answer(b"\x05other\x07example\x00", 1, packed("9.9.9.9")))
        expected = {("game.example", v4), ("game.example", v6)}
        self.assertEqual(dns_answers(dns), expected)
        self.assertFalse(dns_answers(dns[:-1]))
        udp = struct.pack(">HHHH", 53, 54400, len(dns) + 8, 0) + dns
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0)
        ethernet = bytes.fromhex("0011223344550200000000010800")
        frame = ethernet + ip + resolver + packed(ADDRESS) + udp
        decoder = session.decoder
        self.assertIsNone(decoder.inspect(LINK_ETHERNET, frame)[0])
        self.assertEqual(decoder.answers, expected)
        session.observe_answers(decoder.answers)
        self.assertEqual(session.summary["packet_count"], 1)
        self.assertEqual(session.summary["ip_count"], 0)
        self.assertEqual(session.result()["domain_ips"], {
            "game.example": [("8.8.4.4", "DNS 回应"), ("2606:4700::1111", "DNS 回应")]
        })
        decoder.inspect(LINK_ETHERNET, bytes.fromhex("001122334499") + frame[6:])
        self.assertFalse(decoder.answers)

        def tcp_reply(sequence, payload):
            tcp = struct.pack(">HHIIBBHHH", 53, 54400, sequence, 0, 0x50, 0x18, 2048, 0, 0) + payload
            header = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0)
            return ethernet + header + resolver + packed(ADDRESS) + tcp

        wire = struct.pack(">H", len(dns)) + dns
        decoder.inspect(LINK_ETHERNET, tcp_reply(100, wire[:15]))
        self.assertFalse(decoder.answers)
        decoder.inspect(LINK_ETHERNET, tcp_reply(115, wire[15:]))
        self.assertEqual(decoder.answers, expected)

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
