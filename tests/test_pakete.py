"""Paketparser, Zusammensetzung und gemeinsame Klassifikation."""

import struct
import unittest

from greenbuddy2.klassifikation import quelle, tls_sni, minecraft_login, http_client, klassifizieren, Unvollstaendig
from greenbuddy2.mitschnitt import Beobachter, bpf
from greenbuddy2.pcap import PcapStream, TcpAnfang, tcp_packet
from greenbuddy2.wol import magic_packet
from fixtures import clienthello, minecraft, ethernet, pcap


class Logger:
    def __init__(self):
        self.rows = []

    def emit(self, row, now=None, **kwargs):
        self.rows.append(dict(row))


CFG = {"target": "192.168.1.110", "plex_hash": "abc123", "plex_clients": ["test-client"],
       "minecraft_whitelist": ["Testspieler"]}


class ParserTests(unittest.TestCase):
    def test_sni_eigenes_clienthello(self):
        self.assertEqual(tls_sni(clienthello()), "client.abc123.plex.direct")
        self.assertEqual(tls_sni(clienthello(split_records=True)), "client.abc123.plex.direct")
        with self.assertRaises(Unvollstaendig):
            tls_sni(clienthello()[:20])
        with self.assertRaises(ValueError):
            tls_sni(b"\x17\x03\x03\x00\x01\x00")

    def test_minecraft_handshake_login_status(self):
        self.assertEqual(minecraft_login(minecraft())["name"], "Testspieler")
        self.assertTrue(minecraft_login(minecraft(status=True))["status"])
        self.assertTrue(minecraft_login(b"\xfe\x01")["status"])
        with self.assertRaises(Unvollstaendig):
            minecraft_login(minecraft()[:-1])
        with self.assertRaises(ValueError):
            minecraft_login(b"\xff" * 6)

    def test_http_client(self):
        header = b"GET /library HTTP/1.1\r\nHost: test.invalid\r\nX-Plex-Client-Identifier: test-client\r\n\r\n"
        self.assertEqual(http_client(header), "test-client")
        self.assertEqual(klassifizieren("192.168.1.9", 32400, header, CFG)["entscheidung"], "wuerde_wecken")
        self.assertEqual(klassifizieren("198.51.100.9", 32400, header, CFG)["entscheidung"], "spam")
        with self.assertRaises(ValueError):
            http_client(header.replace(b"\r\n\r\n", b"\r\nX-Plex-Client-Identifier: zweiter\r\n\r\n"))

    def test_quellklassen(self):
        for address, expected in (("192.168.1.9", "LAN"), ("10.0.0.9", "VPN"), ("198.51.100.9", "WAN"), ("10.1.0.1", "WAN")):
            self.assertEqual(quelle(address), expected)

    def test_klassifikation_sni_whitelist(self):
        row = klassifizieren("198.51.100.9", 32400, clienthello(), CFG)
        self.assertEqual(row["entscheidung"], "wuerde_wecken")
        self.assertEqual(row["weg"], 7)
        self.assertTrue(row["sni_suffix_treffer"])
        self.assertEqual(klassifizieren("198.51.100.9", 32400, clienthello("abc123.plex.direct.evil.invalid"), CFG)["entscheidung"], "spam")
        self.assertEqual(klassifizieren("198.51.100.9", 25565, minecraft(), CFG)["entscheidung"], "wuerde_wecken")
        self.assertEqual(klassifizieren("198.51.100.9", 25565, minecraft("Scanner"), CFG)["entscheidung"], "spam")
        self.assertEqual(klassifizieren("198.51.100.9", 25565, minecraft(status=True), CFG)["entscheidung"], "spam")
        self.assertEqual(klassifizieren("198.51.100.9", 32400, b"", CFG)["entscheidung"], "unklar")

    def test_pcap_strom_in_einzelbytes(self):
        frames = [ethernet(syn=True), ethernet(clienthello(), seq=101)]
        for endian in ("<", ">"):
            for nano in (False, True):
                parser, rows = PcapStream(), []
                for byte in pcap(frames, endian, nano):
                    rows.extend(parser.feed(bytes([byte])))
                parser.finish()
                self.assertEqual([row[1] for row in rows], frames)
                self.assertEqual(tcp_packet(rows[1][1])["payload"], clienthello())

    def test_pcap_kaputt_und_abgebrochen(self):
        parser = PcapStream()
        with self.assertRaises(ValueError):
            parser.feed(b"kein pcap" + b"\x00" * 24)
        parser = PcapStream()
        parser.feed(pcap([ethernet()])[:-2])
        with self.assertRaises(ValueError):
            parser.finish()
        parser = PcapStream()
        with self.assertRaises(ValueError):
            parser.feed(pcap([]) + struct.pack("<IIII", 1, 0, 1000000, 1000000))

    def test_linktypen(self):
        frame = ethernet(clienthello())
        ip = frame[14:]
        sll = b"\x00" * 14 + b"\x08\x00" + ip
        sll2 = b"\x08\x00" + b"\x00" * 18 + ip
        for link, packet in ((1, frame), (101, ip), (113, sll), (276, sll2)):
            self.assertEqual(tcp_packet(packet, link)["payload"], clienthello())

    def test_tcp_mehrere_segmente_und_retransmit(self):
        data = clienthello()
        stream = TcpAnfang(100)
        self.assertEqual(stream.add(120, data[20:]), b"")
        self.assertEqual(stream.add(100, data[:20]), data)
        self.assertEqual(stream.add(100, data[:20]), data)
        self.assertEqual(tls_sni(stream.data()), "client.abc123.plex.direct")
        with self.assertRaises(ValueError):
            stream.add(100, b"\x00")

    def test_mitschnitt_nur_metadaten_und_einmal(self):
        logger = Logger()
        observer = Beobachter(CFG, logger)
        observer.paket(tcp_packet(ethernet(syn=True)), 10)
        data = clienthello()
        observer.paket(tcp_packet(ethernet(data[:40], seq=101)), 11)
        self.assertEqual(logger.rows, [])
        observer.paket(tcp_packet(ethernet(data[40:], seq=141)), 12)
        observer.paket(tcp_packet(ethernet(data[40:], seq=141)), 13)
        self.assertEqual(len(logger.rows), 1)
        self.assertEqual(set(logger.rows[0]), {"zeit", "quell_ip", "quellklasse", "port", "sni_suffix_treffer", "entscheidung", "weg"})
        self.assertTrue(all(row["stream"] is None for row in observer.flows.values()))

    def test_syn_ablauf_und_bpf(self):
        logger = Logger()
        observer = Beobachter(CFG, logger)
        observer.paket(tcp_packet(ethernet(syn=True)), 0)
        observer.ablaufen(6)
        self.assertEqual(logger.rows[0]["entscheidung"], "unklar")
        self.assertIn("dst host 192.168.1.110", bpf(CFG["target"]))
        self.assertIn("8096", bpf(CFG["target"]))
        with self.assertRaises(ValueError):
            bpf("192.168.1.110; id")

    def test_wol_magic_packet(self):
        data = magic_packet("02:00:00:00:00:01")
        self.assertEqual(len(data), 102)
        self.assertEqual(data, b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01" * 16)
        with self.assertRaises(ValueError):
            magic_packet("ungültig")
