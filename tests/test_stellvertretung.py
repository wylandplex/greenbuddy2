"""Weckweg über proxy01: Konfig, cBPF, ARP, nft, Zustandsautomat, Dienst, Register.

Nur synthetische Daten: Doku-Netze 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, Platzhalter-Hashes.
"""

import copy
import json
import unittest
from pathlib import Path

from greenbuddy2 import konfig

ROOT = Path(__file__).resolve().parents[1]
BEISPIEL = json.loads((ROOT / "deploy/proxy01/stellvertreter.example.json").read_text())


def beispiel(**sv):
    cfg = copy.deepcopy(BEISPIEL)
    cfg["stellvertretung"].update(sv)
    return cfg


class KonfigTests(unittest.TestCase):
    def test_beispiel_ist_gueltig_und_normalisiert(self):
        sv = konfig.stellvertretung(beispiel())
        host = sv["hosts"]["vhost01"]
        self.assertEqual(host["ip"], "192.168.1.110")
        self.assertEqual(host["quellen_ports"], {8443: ["203.0.113.10"]})
        self.assertEqual(sv["probe"]["ip"], "192.168.1.199")
        self.assertEqual(sv["interface"], "eth0")
        self.assertEqual(sv["listen_ip"], "192.168.1.100")
        self.assertEqual(sv["vpn_interface"], "wg0")
        self.assertEqual(sv["lan"], ["192.168.1.0/24"])
        self.assertEqual(sv["limits"]["wan_host_tag"], 12)

    def test_ohne_schluessel_fehlt_und_laden_bleibt_moeglich(self):
        cfg = beispiel()
        del cfg["stellvertretung"]
        with self.assertRaisesRegex(ValueError, "^stellvertretung_fehlt$"):
            konfig.stellvertretung(cfg)
        # Ein Formfehler der Stellvertretung darf das GDM-Zählen (laden) nicht verhindern.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sv.json"
            kaputt = beispiel(limits="falsch")
            path.write_text(json.dumps(kaputt))
            self.assertEqual(konfig.laden(path)["stellvertretung"]["limits"], "falsch")

    def test_vpn_interface_optional(self):
        cfg = beispiel()
        del cfg["stellvertretung"]["vpn_interface"]
        self.assertEqual(konfig.stellvertretung(cfg)["vpn_interface"], "")
        del cfg["stellvertretung"]["probe"]
        self.assertIsNone(konfig.stellvertretung(cfg)["probe"])

    def test_jeder_formfehler(self):
        def host(**kw):
            row = copy.deepcopy(BEISPIEL["stellvertretung"]["hosts"]["vhost01"])
            row.update(kw)
            return {"vhost01": row}

        def ohne(key):
            row = copy.deepcopy(BEISPIEL["stellvertretung"]["hosts"]["vhost01"])
            del row[key]
            return {"vhost01": row}

        probe = copy.deepcopy(BEISPIEL["stellvertretung"]["probe"])
        faelle = {
            "liste": beispiel(),
            "hosts_liste": beispiel(hosts=[]),
            "nas01": beispiel(hosts={"nas01": host()["vhost01"]}),
            "probe_als_host": beispiel(hosts={"probe": host()["vhost01"]}),
            "fremder_host": beispiel(hosts={"fremd": host()["vhost01"]}),
            "unbekannter_schluessel": beispiel(extra=1),
            "host_extra": beispiel(hosts=host(extra=1)),
            "host_ohne_mac": beispiel(hosts=ohne("mac")),
            "host_ohne_ports": beispiel(hosts=ohne("syn_ports")),
            "ip_text": beispiel(hosts=host(ip="vhost01")),
            "ip_zahl": beispiel(hosts=host(ip=110)),
            "ip_gateway": beispiel(hosts=host(ip="192.168.1.1")),
            "ip_proxy01": beispiel(hosts=host(ip="192.168.1.100")),
            "ip_nas01": beispiel(hosts=host(ip="192.168.1.115")),
            "ip_ausserhalb_lan": beispiel(hosts=host(ip="198.51.100.10")),
            "ip_broadcast": beispiel(hosts=host(ip="192.168.1.255")),
            "ip_netz": beispiel(hosts=host(ip="192.168.1.0")),
            "mac_kurz": beispiel(hosts=host(mac="00:00:5e:00:53")),
            "mac_multicast": beispiel(hosts=host(mac="01:00:5e:00:00:01")),
            "mac_null": beispiel(hosts=host(mac="00:00:00:00:00:00")),
            "port_null": beispiel(hosts=host(syn_ports=[0])),
            "port_gross": beispiel(hosts=host(inhalt_ports=[65536])),
            "port_text": beispiel(hosts=host(syn_ports=["22"])),
            "port_bool": beispiel(hosts=host(syn_ports=[True])),
            "port_doppelt": beispiel(hosts=host(syn_ports=[22, 22])),
            "ports_dict": beispiel(hosts=host(syn_ports={"22": 1})),
            "quellen_liste": beispiel(hosts=host(quellen_ports=[8443])),
            "quellen_port_text": beispiel(hosts=host(quellen_ports={"x": ["203.0.113.10"]})),
            "quellen_leer": beispiel(hosts=host(quellen_ports={"8443": []})),
            "quellen_ip": beispiel(hosts=host(quellen_ports={"8443": ["kein-ip"]})),
            "quellen_ueberlappt_syn": beispiel(hosts=host(quellen_ports={"22": ["203.0.113.10"]})),
            "quellen_ueberlappt_inhalt": beispiel(hosts=host(quellen_ports={"25565": ["203.0.113.10"]})),
            "ausgenommen_text": beispiel(hosts=host(ausgenommen="192.168.1.1")),
            "ausgenommen_ip": beispiel(hosts=host(ausgenommen=["192.168.1.300"])),
            "probe_gleich_host": beispiel(probe=dict(probe, ip="192.168.1.110")),
            "probe_gesperrt": beispiel(probe=dict(probe, ip="192.168.1.100")),
            "probe_form": beispiel(probe=dict(probe, extra=1)),
            "wan_name_zahl": beispiel(wan_name=5),
            "wan_name_form": beispiel(wan_name="-boese..name"),
            "register_relativ": beispiel(register="register.json"),
            "status_leer": beispiel(status=""),
            "zustand_gleich_status": beispiel(zustand=BEISPIEL["stellvertretung"]["status"]),
            "limits_fehlt": beispiel(limits={"wan_quelle_h": 3}),
            "limits_extra": beispiel(limits=dict(BEISPIEL["stellvertretung"]["limits"], neu=1)),
            "limits_negativ": beispiel(limits=dict(BEISPIEL["stellvertretung"]["limits"], lan_quelle_h=-1)),
            "limits_float": beispiel(limits=dict(BEISPIEL["stellvertretung"]["limits"], lan_quelle_h=1.5)),
            "limits_bool": beispiel(limits=dict(BEISPIEL["stellvertretung"]["limits"], lan_quelle_h=True)),
            "zeit_null": beispiel(stille_s=0),
            "zeit_text": beispiel(garp_s="60"),
            "zeit_nan": beispiel(lebendprobe_s=float("nan")),
            "zeit_gross": beispiel(wol_wiederholen_s=3600),
            "wol_max_kleiner": beispiel(wol_max_s=10),
            "stille_max_kleiner": beispiel(stille_max_s=2),
            "vpn_interface_form": beispiel(vpn_interface="wg0;rm"),
            "vpn_interface_gleich_lan": beispiel(vpn_interface="eth0"),
        }
        for name in ("hosts", "limits", "register", "wol_max_s"):
            cfg = beispiel()
            del cfg["stellvertretung"][name]
            faelle["fehlt_" + name] = cfg
        faelle["liste"]["stellvertretung"] = []
        for basis, wert in (("interface", "eth0 x"), ("listen_ip", "192.168.1.300"), ("listen_ip", "198.51.100.1"),
                            ("lan", "192.168.1.0/24"), ("lan", ["kein-netz"]), ("vpn", [5])):
            cfg = beispiel()
            cfg[basis] = wert
            faelle["basis_%s_%r" % (basis, wert)] = cfg
        cfg = beispiel()
        del cfg["interface"]
        faelle["basis_ohne_interface"] = cfg
        for name, cfg in faelle.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "^stellvertretung_[a-z_]+$"):
                konfig.stellvertretung(cfg)


# ---------------------------------------------------------------- Byte-Fixtures

import ctypes
import ctypes.util
import os
import shutil
import socket
import struct
import subprocess
import tempfile

from greenbuddy2 import uebernahme as ue
from greenbuddy2.klassifikation import klassifizieren
from fixtures import clienthello

ECHT = "00:00:5e:00:53:10"
EIGEN = "02:00:00:00:00:01"
FREMD = "02:00:00:00:00:42"
ALIAS = "192.168.1.110"


def mac(text):
    return bytes.fromhex(text.replace(":", ""))


def ether(payload, src=FREMD, dst=EIGEN, typ=0x0800):
    return mac(dst) + mac(src) + struct.pack("!H", typ) + payload


def ipv4_tcp(src="198.51.100.9", dst=ALIAS, port=22, flags=0x02, optionen=b"", frag=0, proto=6, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", 50000, port, 1000, 0, 0x50, flags, 4096, 0, 0) + payload
    ihl = 5 + len(optionen) // 4
    head = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, ihl * 4 + len(tcp), 1, frag, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    return head + optionen + tcp


def arp_paket(op=1, sha=ECHT, spa=ALIAS, tha="00:00:00:00:00:00", tpa="192.168.1.100"):
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, mac(sha), socket.inet_aton(spa), mac(tha),
                       socket.inet_aton(tpa))


FRAMES = {
    "syn": ether(ipv4_tcp()),
    "syn_optionen": ether(ipv4_tcp(optionen=b"\x01\x01\x01\x00")),
    "syn_ecn": ether(ipv4_tcp(flags=0xc2)),
    "synack": ether(ipv4_tcp(flags=0x12)),
    "ack": ether(ipv4_tcp(flags=0x10)),
    "syn_andere_ip": ether(ipv4_tcp(dst="192.168.1.111")),
    "udp": ether(ipv4_tcp(proto=17)),
    "fragment": ether(ipv4_tcp(frag=8)),
    "arp_echt": ether(arp_paket(), src=ECHT, dst="ff:ff:ff:ff:ff:ff", typ=0x0806),
    # Ein anderes Gerät meldet sich mit der Host-IP als Absender (MAC-Wechsel, belegte Probe-Adresse).
    "arp_fremd": ether(arp_paket(sha=FREMD), src=FREMD, dst="ff:ff:ff:ff:ff:ff", typ=0x0806),
    "arp_fremd_antwort": ether(arp_paket(op=2, sha=FREMD, tha=EIGEN), src=FREMD, dst=EIGEN, typ=0x0806),
    # Ein Client fragt nach .110: Absender ist seine eigene Adresse, kein Anspruch auf .110.
    "arp_fremd_andere_ip": ether(arp_paket(sha=FREMD, spa="192.168.1.18", tpa=ALIAS), src=FREMD,
                                 dst="ff:ff:ff:ff:ff:ff", typ=0x0806),
    # Eigenes GARP von proxy01 (falls es je als eingehend erscheint): nie ein fremder Anspruch.
    "garp_eigen": ether(arp_paket(sha=EIGEN, tpa=ALIAS), src=EIGEN, dst="ff:ff:ff:ff:ff:ff", typ=0x0806),
    "ip_echt": ether(ipv4_tcp(dst="192.168.1.1", proto=17), src=ECHT),
    "syn_von_echt": ether(ipv4_tcp(), src=ECHT),
    "kurz": b"\x00" * 10,
    "abgeschnitten": ether(ipv4_tcp())[:40],
}


def bpf_lauf(programm, paket):
    """Kleiner cBPF-Interpreter: nur die Befehle, die die Generatoren benutzen dürfen."""
    a = x = pc = 0

    def lade(offset, size):
        if offset < 0 or offset + size > len(paket):
            return None
        return int.from_bytes(paket[offset:offset + size], "big")
    while True:
        code, jt, jf, k = programm[pc]
        if code in (0x20, 0x28, 0x30, 0x50):
            value = lade(k + (x if code == 0x50 else 0), {0x20: 4, 0x28: 2, 0x30: 1, 0x50: 1}[code])
            if value is None:
                return 0
            a = value
        elif code == 0xb1:
            value = lade(k, 1)
            if value is None:
                return 0
            x = (value & 0xf) * 4
        elif code == 0x54:
            a &= k
        elif code == 0x15:
            pc += jt if a == k else jf
        elif code == 0x45:
            pc += jt if a & k else jf
        elif code == 0x06:
            return k
        else:
            raise AssertionError("unbekannter BPF-Befehl %#x" % code)
        pc += 1


class PcapFilter:
    """libpcap kompiliert dieselbe Bedingung offline (ohne Socket) als zweite Meinung."""
    class Instruction(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]

    class Program(ctypes.Structure):
        pass

    class Header(ctypes.Structure):
        _fields_ = [("seconds", ctypes.c_long), ("micros", ctypes.c_long),
                    ("caplen", ctypes.c_uint32), ("length", ctypes.c_uint32)]

    Program._fields_ = [("length", ctypes.c_uint), ("instructions", ctypes.POINTER(Instruction))]

    def __init__(self, expression, linktype=1):
        library = ctypes.util.find_library("pcap")
        if not library:
            raise unittest.SkipTest("Offline-libpcap fehlt")
        self.lib = ctypes.CDLL(library)
        self.lib.pcap_open_dead.argtypes = [ctypes.c_int, ctypes.c_int]
        self.lib.pcap_open_dead.restype = ctypes.c_void_p
        self.lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(self.Program), ctypes.c_char_p,
                                         ctypes.c_int, ctypes.c_uint32]
        self.lib.pcap_offline_filter.argtypes = [ctypes.POINTER(self.Program), ctypes.POINTER(self.Header),
                                                 ctypes.c_void_p]
        self.lib.pcap_freecode.argtypes = [ctypes.POINTER(self.Program)]
        self.lib.pcap_close.argtypes = [ctypes.c_void_p]
        self.program = self.Program()
        handle = self.lib.pcap_open_dead(linktype, 65535)
        try:
            if self.lib.pcap_compile(handle, ctypes.byref(self.program), expression.encode(), 1, 0xffffffff):
                raise AssertionError("BPF kompiliert nicht: " + expression)
        finally:
            self.lib.pcap_close(handle)

    def accepts(self, frame):
        header = self.Header(0, 0, len(frame), len(frame))
        return bool(self.lib.pcap_offline_filter(ctypes.byref(self.program), ctypes.byref(header), frame))

    def close(self):
        self.lib.pcap_freecode(ctypes.byref(self.program))


class BpfTests(unittest.TestCase):
    def pruefen(self, programm, erwartet, frames, ausdruck, linktype=1):
        for name, frame in frames.items():
            with self.subTest(frame=name):
                self.assertEqual(bool(bpf_lauf(programm, frame)), name in erwartet)
        reference = PcapFilter(ausdruck, linktype)
        self.addCleanup(reference.close)
        for name, frame in frames.items():
            with self.subTest(libpcap=name):
                self.assertEqual(bool(bpf_lauf(programm, frame)), reference.accepts(frame))

    # ARP mit Absender-IP .110 (arp[14:4]) von jeder MAC außer der eigenen (Review b5: netz-fremde-mac).
    FREMD_110 = "arp[14:4] = 0xc0a8016e and not ether src " + EIGEN

    def test_a_arp_der_echten_mac(self):
        self.pruefen(ue.bpf_arp_von(ECHT, ALIAS, EIGEN), {"arp_echt", "arp_fremd", "arp_fremd_antwort"}, FRAMES,
                     "arp and (ether src %s or (%s))" % (ECHT, self.FREMD_110))

    def test_b_echte_mac_oder_syn_an_alias(self):
        self.pruefen(ue.bpf_uebernommen(ECHT, ALIAS, EIGEN),
                     {"syn", "syn_optionen", "syn_ecn", "arp_echt", "ip_echt", "syn_von_echt", "arp_fremd",
                      "arp_fremd_antwort"}, FRAMES,
                     "ether src %s or (arp and %s) or (ip and dst host %s and tcp[13] & 0x12 = 2)"
                     % (ECHT, self.FREMD_110, ALIAS))

    def test_c_cooked_ab_ip_kopf(self):
        cooked = {name: frame[14:] for name, frame in FRAMES.items() if frame[12:14] == b"\x08\x00"}
        cooked["kurz"] = b"\x45\x00"
        # DLT_RAW = 12 unter Linux: Pakete beginnen mit dem IPv4-Kopf.
        self.pruefen(ue.bpf_syn_cooked(ALIAS), {"syn", "syn_optionen", "syn_ecn", "syn_von_echt"}, cooked,
                     "ip and dst host %s and tcp[13] & 0x12 = 2" % ALIAS, linktype=12)

    def test_kopflaenge_und_sprungweiten(self):
        for programm in (ue.bpf_arp_von(ECHT, ALIAS, EIGEN), ue.bpf_uebernommen(ECHT, ALIAS, EIGEN),
                         ue.bpf_syn_cooked(ALIAS)):
            self.assertLessEqual(len(programm), 64)
            for index, (code, jt, jf, k) in enumerate(programm):
                self.assertLess(index + jt + 1, len(programm) + 1)
                self.assertLess(index + jf + 1, len(programm) + 1)
            self.assertEqual(programm[-1], (0x06, 0, 0, 0))
            self.assertIn((0x06, 0, 0, ue.KOPF), programm)

    def test_kodierung_fuer_so_attach_filter(self):
        programm = ue.bpf_arp_von(ECHT, ALIAS, EIGEN)
        raw = ue.bpf_kodieren(programm)
        self.assertEqual(len(raw), 8 * len(programm))
        self.assertEqual(struct.unpack("=HBBI", raw[:8]), programm[0])

    def test_raw_socket_filter_vor_bind(self):
        calls = []

        class Sock:
            def __init__(self, *args):
                calls.append(("socket",) + args)

            def setsockopt(self, level, option, value):
                calls.append(("setsockopt", level, option, len(value)))

            def bind(self, address):
                calls.append(("bind", address))

            def setblocking(self, flag):
                calls.append(("setblocking", flag))

            def close(self):
                calls.append(("close",))
        sock = ue.raw_socket(Sock, "eth0", ue.bpf_arp_von(ECHT, ALIAS, EIGEN))
        self.assertIsInstance(sock, Sock)
        # Protokoll 0 beim Anlegen: vor dem Filter kommt kein ungefiltertes Paket in die Warteschlange.
        self.assertEqual(calls[0], ("socket", socket.AF_PACKET, socket.SOCK_RAW, 0))
        self.assertEqual(calls[1][:3], ("setsockopt", socket.SOL_SOCKET, 26))
        self.assertEqual(calls[2], ("bind", ("eth0", 3)))
        calls.clear()
        ue.raw_socket(Sock, "wg0", ue.bpf_syn_cooked(ALIAS), cooked=True)
        self.assertEqual(calls[0], ("socket", socket.AF_PACKET, socket.SOCK_DGRAM, 0))
        self.assertEqual(calls[2], ("bind", ("wg0", 0x0800)))

        class Kaputt(Sock):
            def bind(self, address):
                raise OSError("kein Interface")
        calls.clear()
        with self.assertRaises(OSError):
            ue.raw_socket(Kaputt, "eth9", ue.bpf_arp_von(ECHT, ALIAS, EIGEN))
        self.assertEqual(calls[-1], ("close",))


class ArpFrameTests(unittest.TestCase):
    def test_anfrage(self):
        frame = ue.arp_anfrage(EIGEN, "192.168.1.100", ALIAS)
        self.assertEqual(frame[:6], b"\xff" * 6)
        self.assertEqual(frame[6:12], mac(EIGEN))
        self.assertEqual(frame[12:14], b"\x08\x06")
        row = ue.arp_lesen(frame)
        self.assertEqual((row["op"], row["sender_mac"], row["sender_ip"], row["ziel_mac"], row["ziel_ip"]),
                         (1, EIGEN, "192.168.1.100", "00:00:00:00:00:00", ALIAS))
        self.assertEqual(len(frame), 42)

    def test_garp_ankuendigung(self):
        row = ue.arp_lesen(ue.garp(EIGEN, "192.168.1.199"))
        self.assertEqual((row["op"], row["sender_ip"], row["ziel_ip"], row["sender_mac"]),
                         (1, "192.168.1.199", "192.168.1.199", EIGEN))

    def test_antwort_erkennen(self):
        antwort = ether(arp_paket(op=2), src=ECHT, dst=EIGEN, typ=0x0806)
        row = ue.arp_lesen(antwort)
        self.assertEqual((row["op"], row["quelle"], row["sender_mac"], row["sender_ip"]), (2, ECHT, ECHT, ALIAS))
        for kaputt in (antwort[:41], FRAMES["syn"], ether(arp_paket()[:6] + b"\x00\x09" + arp_paket()[8:], typ=0x0806),
                       ether(b"\x00\x06" + arp_paket()[2:], typ=0x0806)):
            self.assertIsNone(ue.arp_lesen(kaputt))


HOST = {"ip": ALIAS, "mac": ECHT, "syn_ports": [22, 8096, 32400], "inhalt_ports": [32400, 25565],
        "quellen_ports": {8443: ["203.0.113.10"]}, "ausgenommen": ["192.168.1.100", "192.168.1.115", "192.168.1.1"]}


class NftTests(unittest.TestCase):
    TEXT = """create table ip gb2_sv_vhost01
create chain ip gb2_sv_vhost01 eingang { type filter hook input priority -300; policy accept; }
create chain ip gb2_sv_vhost01 ausgang { type filter hook output priority -300; policy accept; }
add rule ip gb2_sv_vhost01 eingang ip daddr 192.168.1.110 ip saddr { 192.168.1.100, 192.168.1.115, 192.168.1.1 } drop
add rule ip gb2_sv_vhost01 eingang ip daddr 192.168.1.110 ip saddr 192.168.1.0/24 tcp dport { 32400 } drop
add rule ip gb2_sv_vhost01 eingang ip daddr 192.168.1.110 ip saddr 10.0.0.0/24 tcp dport { 32400 } drop
add rule ip gb2_sv_vhost01 eingang ip daddr 192.168.1.110 tcp dport { 32400, 25565 } accept
add rule ip gb2_sv_vhost01 eingang ip daddr 192.168.1.110 drop
add rule ip gb2_sv_vhost01 ausgang ip daddr 192.168.1.110 drop
create table arp gb2_sv_vhost01_arp
create chain arp gb2_sv_vhost01_arp eingang { type filter hook input priority -300; policy accept; }
add rule arp gb2_sv_vhost01_arp eingang arp saddr ether 00:00:5e:00:53:10 drop
"""

    def test_regeln_exakt(self):
        self.assertEqual(ue.tabellen("vhost01"), (("ip", "gb2_sv_vhost01"), ("arp", "gb2_sv_vhost01_arp")))
        self.assertEqual(ue.nft_regeln("vhost01", HOST, ["192.168.1.0/24"], ["10.0.0.0/24"]), self.TEXT)

    def test_marke_auf_beiden_drop_regeln(self):
        # Review b5: Urheberschaft nach einem abgebrochenen "nft -f" an Tatsachen erkennen (Regelkommentar).
        text = ue.nft_regeln("vhost01", HOST, ["192.168.1.0/24"], ["10.0.0.0/24"], marke="gb2-4711-0a1b2c3d")
        erwartet = self.TEXT.replace("eingang ip daddr 192.168.1.110 drop\n",
                                     'eingang ip daddr 192.168.1.110 drop comment "gb2-4711-0a1b2c3d"\n')
        erwartet = erwartet.replace("ether 00:00:5e:00:53:10 drop\n",
                                    'ether 00:00:5e:00:53:10 drop comment "gb2-4711-0a1b2c3d"\n')
        self.assertEqual(text, erwartet)
        for kaputt in ("", 'a"b', "a b", "x" * 65):
            with self.assertRaises(ValueError):
                ue.nft_regeln("vhost01", HOST, ["192.168.1.0/24"], [], marke=kaputt)

    def test_leere_listen_ohne_leere_mengen(self):
        host = dict(HOST, syn_ports=[22], inhalt_ports=[], ausgenommen=["192.168.1.1", "192.168.1.1"])
        text = ue.nft_regeln("probe", host, ["192.168.1.0/24"], [])
        self.assertNotIn("{  }", text)
        self.assertNotIn("accept\n", text.replace("policy accept;", ""))
        self.assertIn("ip saddr { 192.168.1.1 } drop", text)
        self.assertIn("gb2_sv_probe_arp", text)

    def test_syntax_mit_lokalem_nft(self):
        if not shutil.which("nft") or not shutil.which("unshare"):
            self.skipTest("nft/unshare fehlen")
        if subprocess.run(["unshare", "-Urn", "true"], capture_output=True).returncode:
            self.skipTest("Benutzer-Namensräume gesperrt")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "regeln.nft"
            for name, host in (("vhost01", HOST), ("probe", dict(HOST, syn_ports=[22], quellen_ports={}))):
                path.write_text(ue.nft_regeln(name, host, ["192.168.1.0/24"], ["10.0.0.0/24"],
                                              marke="gb2-4711-0a1b2c3d"))
                run = subprocess.run(["unshare", "-Urn", "nft", "-c", "-f", str(path)], capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr)


class SniLabelTests(unittest.TestCase):
    CFG = {"plex_hash": "abc123", "lan": ["192.168.1.0/24"], "vpn": ["10.0.0.0/24"],
           "sni_label_ips": [ALIAS, "203.0.113.7"], "sni_label_wan_unklar": False}

    def row(self, name, cfg=None, source="198.51.100.9"):
        return klassifizieren(source, 32400, clienthello(name), cfg or self.CFG)

    def test_label_klassen(self):
        for name, label, decision in (
                ("192-168-1-110.abc123.plex.direct", "lan", "wuerde_wecken"),
                ("203-0-113-7.abc123.plex.direct", "wan", "wuerde_wecken"),
                ("198-51-100-20.abc123.plex.direct", "ip_andere", "spam"),
                ("client.abc123.plex.direct", "kein_ip", "spam"),
                ("a.192-168-1-110.abc123.plex.direct", "kein_ip", "spam"),
                ("192-168-1-300.abc123.plex.direct", "kein_ip", "spam"),
                ("010-1-1-1.abc123.plex.direct", "kein_ip", "spam"),
                ("192-168-1-110.fremd99.plex.direct", None, "spam")):
            with self.subTest(name=name):
                row = self.row(name)
                self.assertEqual((row["sni_label"], row["entscheidung"]), (label, decision))

    def test_unbekannte_wan_ip_laesst_jede_oeffentliche_zu(self):
        cfg = dict(self.CFG, sni_label_ips=[ALIAS], sni_label_wan_unklar=True)
        for name, label in (("198-51-100-20.abc123.plex.direct", "wan"),
                            ("10-1-2-3.abc123.plex.direct", "ip_andere"),
                            ("100-64-0-1.abc123.plex.direct", "ip_andere"),
                            ("127-0-0-1.abc123.plex.direct", "ip_andere"),
                            ("192-168-1-50.abc123.plex.direct", "ip_andere"),
                            ("192-168-1-110.abc123.plex.direct", "lan")):
            with self.subTest(name=name):
                self.assertEqual(self.row(name, cfg)["sni_label"], label)
        cfg["sni_label_wan_unklar"] = False
        self.assertEqual(self.row("198-51-100-20.abc123.plex.direct", cfg)["sni_label"], "ip_andere")

    def test_ohne_schluessel_wie_bisher(self):
        cfg = {"plex_hash": "abc123"}
        row = klassifizieren("198.51.100.9", 32400, clienthello("client.abc123.plex.direct"), cfg)
        self.assertNotIn("sni_label", row)
        self.assertEqual(row["entscheidung"], "wuerde_wecken")
        row = klassifizieren("198.51.100.9", 25565, b"", dict(self.CFG))
        self.assertIsNone(row["sni_label"])


# ---------------------------------------------------------------- Fakes für Netz, Sockets, Dateien

import collections
import itertools
import re
import types
from unittest import mock

BOOT = "11111111-2222-3333-4444-555555555555"
SYSCTL = {"/proc/sys/net/ipv4/conf/%s/%s" % (scope, key): value + "\n"
          for scope in ("all", "eth0") for key, value in (("arp_ignore", "1"), ("arp_announce", "2"))}


def ergebnis(code=0, out="", err=""):
    return types.SimpleNamespace(returncode=code, stdout=out, stderr=err)


class Netz:
    """Zustandsbehafteter Ersatz für ip/nft; Störungen: rc (Fehlercode), stumm (rc 0 ohne Wirkung), fehlt."""
    def __init__(self, ereignisse=None):
        self.adressen = [("192.168.1.100", 24, "eth0")]
        self.tabellen = set()
        # Regelkommentare je Tabelle (nft -j list table): daran erkennt der Dienst seine eigenen Tabellen.
        self.kommentare = collections.defaultdict(list)
        self.befehle, self.eingaben = [], []
        self.stoerung = {}
        self.ereignisse = ereignisse if ereignisse is not None else []

    def __call__(self, args, input=None, **kwargs):
        args = list(args)
        self.befehle.append(args)
        self.ereignisse.append(("befehl", " ".join(args)))
        if input is not None:
            self.eingaben.append(input)
        for praefix, art in self.stoerung.items():
            if tuple(args[:len(praefix)]) == praefix:
                if art == "fehlt":
                    raise FileNotFoundError(args[0])
                if art == "rc":
                    return ergebnis(1, "", "Fehler")
                if art == "stumm":
                    return ergebnis(0, "[]" if "-j" in args else "")
                if art == "kaputt":
                    return ergebnis(0, "kein json")
        if args[:4] == ["ip", "-j", "-4", "addr"]:
            rows = collections.OrderedDict()
            for ip, prefix, name in self.adressen:
                rows.setdefault(name, []).append({"family": "inet", "local": ip, "prefixlen": prefix})
            return ergebnis(0, json.dumps([{"ifname": name, "addr_info": info} for name, info in rows.items()]))
        if args[:3] == ["ip", "addr", "add"]:
            ip, prefix = args[3].split("/")
            if any(row[0] == ip for row in self.adressen):
                return ergebnis(2, "", "RTNETLINK answers: File exists")
            self.adressen.append((ip, int(prefix), args[5]))
            return ergebnis()
        if args[:3] == ["ip", "addr", "del"]:
            ip, prefix = args[3].split("/")
            row = (ip, int(prefix), args[5])
            if row not in self.adressen:
                return ergebnis(2, "", "RTNETLINK answers: Cannot assign requested address")
            self.adressen.remove(row)
            return ergebnis()
        if args == ["nft", "-j", "list", "tables"]:
            rows = [{"metainfo": {"version": "1.0.2"}}] + [
                {"table": {"family": f, "name": n, "handle": i}} for i, (f, n) in enumerate(sorted(self.tabellen))]
            return ergebnis(0, json.dumps({"nftables": rows}))
        if args == ["nft", "-f", "-"]:
            neu = [tuple(line.split()[2:4]) for line in input.splitlines() if line.startswith("create table ")]
            if any(t in self.tabellen for t in neu):
                return ergebnis(1, "", "File exists")
            self.tabellen.update(neu)
            for line in input.splitlines():
                treffer = re.match(r'add rule (\S+) (\S+) .* comment "([^"]*)"$', line)
                if treffer:
                    self.kommentare[treffer.group(1, 2)].append(treffer.group(3))
            return ergebnis()
        if args[:4] == ["nft", "-j", "list", "table"]:
            key = (args[4], args[5])
            if key not in self.tabellen:
                return ergebnis(1, "", "No such file or directory")
            rows = [{"metainfo": {"version": "1.0.2"}}, {"table": {"family": key[0], "name": key[1], "handle": 1}},
                    {"rule": {"family": key[0], "table": key[1], "chain": "eingang", "handle": 2, "expr": []}}]
            rows += [{"rule": {"family": key[0], "table": key[1], "chain": "eingang", "handle": 3 + i, "expr": [],
                               "comment": text}} for i, text in enumerate(self.kommentare[key])]
            return ergebnis(0, json.dumps({"nftables": rows}))
        if args[:3] == ["nft", "delete", "table"]:
            key = (args[3], args[4])
            if key not in self.tabellen:
                return ergebnis(1, "", "No such file or directory")
            self.tabellen.remove(key)
            self.kommentare.pop(key, None)
            return ergebnis()
        raise AssertionError("unerwarteter Befehl %r" % args)


class Sock:
    nummer = itertools.count(100)

    def __init__(self, fabrik, family, typ, proto):
        self.fabrik, self.family, self.typ, self.proto = fabrik, family, typ, proto
        self.fd = next(self.nummer)
        self.eingang, self.wartend = collections.deque(), collections.deque()
        self.gesendet, self.optionen = [], []
        self.adresse, self.backlog, self.zu, self.eof, self.blocking = None, None, False, False, True

    def fileno(self):
        return self.fd

    def setsockopt(self, *args):
        self.optionen.append(args)

    def bind(self, adresse):
        if adresse in self.fabrik.bind_fehler:
            raise OSError(99, "Cannot assign requested address")
        self.adresse = adresse
        self.fabrik.ereignisse.append(("bind", adresse))

    def listen(self, backlog):
        self.backlog = backlog

    def setblocking(self, flag):
        self.blocking = flag

    def send(self, data):
        if self.fabrik.sendefehler:
            raise OSError(100, "Network is down")
        self.gesendet.append(bytes(data))
        return len(data)

    def recvfrom(self, size):
        if not self.eingang:
            raise BlockingIOError()
        return self.eingang.popleft()

    def recv(self, size):
        if self.eingang:
            chunk = self.eingang.popleft()
            if isinstance(chunk, Exception):
                raise chunk
            if len(chunk) > size:
                self.eingang.appendleft(chunk[size:])
            return chunk[:size]
        if self.eof:
            return b""
        raise BlockingIOError()

    def accept(self):
        if not self.wartend:
            raise BlockingIOError()
        return self.wartend.popleft()

    def close(self):
        if not self.zu:
            self.fabrik.ereignisse.append(("close", self.adresse))
        self.zu = True

    def bereit(self):
        return not self.zu and bool(self.eingang or self.wartend or self.eof)


class Fabrik:
    def __init__(self, ereignisse=None):
        self.sockets, self.bind_fehler, self.verboten = [], set(), set()
        self.sendefehler = False
        self.ereignisse = ereignisse if ereignisse is not None else []

    def __call__(self, family=socket.AF_INET, typ=socket.SOCK_STREAM, proto=0):
        if family in self.verboten:
            raise PermissionError(1, "Operation not permitted")
        sock = Sock(self, family, typ, proto)
        self.sockets.append(sock)
        return sock

    def gebunden(self, adresse):
        return [s for s in self.sockets if s.adresse == adresse]


def eingehend(frame):
    return (frame, ("eth0", 3, socket.PACKET_HOST, 1, mac(FREMD)))


class Basis(unittest.TestCase):
    def setUp(self):
        self.t = 1000.0
        self.ereignisse = []
        self.netz = Netz(self.ereignisse)
        self.fabrik = Fabrik(self.ereignisse)
        self.log, self.wols, self.sicherungen = [], [], []
        self.dateien = dict(SYSCTL)
        self.dateien["/sys/class/net/eth0/address"] = EIGEN + "\n"
        self.cfg = beispiel()
        self.sv = konfig.stellvertretung(self.cfg)
        self.u = ue.Umgebung(runner=self.netz, uhr=lambda: self.t, wanduhr=lambda: 1.7e9 + self.t,
                             sockets=self.fabrik, lesen=self.lesen, protokoll=self.log.append, wol=self.wol,
                             boot_id=lambda: BOOT)
        self.u.sichern = self.sichern
        self.programme = []
        echt = ue.filter_setzen
        patcher = mock.patch.object(ue, "filter_setzen",
                                    side_effect=lambda sock, prog: (self.programme.append((sock, prog)), echt(sock, prog)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def sichern(self):
        self.ereignisse.append(("sichern", dict(self.ue.zustand()) if hasattr(self, "ue") else None))
        self.sicherungen.append(self.ue.zustand() if hasattr(self, "ue") else None)

    def lesen(self, path):
        if path not in self.dateien:
            raise FileNotFoundError(path)
        return self.dateien[path]

    def wol(self, ziel):
        self.wols.append((self.t, ziel))
        return 2

    def ereignis(self, name):
        return [row for row in self.log if row.get("ereignis") == name]


def reg(phase="schlaf_absicht", zyklus="z1", ablauf_boot=9000.0, boot=BOOT):
    row = {"zyklus": zyklus, "phase": phase, "ablauf": 1.7e9 + 9000, "nachfrage": 0}
    if ablauf_boot is not None:
        row["ablauf_boot"] = ablauf_boot
    if boot is not None:
        row["boot_id"] = boot
    return row


class UebernahmeTests(Basis):
    def setUp(self):
        super().setUp()
        self.ue = ue.Uebernahme("vhost01", self.sv["hosts"]["vhost01"], self.sv, self.u)

    def lauf(self, bis, schritt=0.5):
        while self.t < bis - 1e-9:
            self.t = round(self.t + schritt, 3)
            self.ue.tick(self.t)

    def uebernehmen(self):
        self.ue.register(reg(), self.t)
        self.lauf(self.t + 3)
        self.assertEqual(self.ue.phase, "uebernommen", self.log)

    def test_warte_stille_arp_proben_und_stille(self):
        self.ue.register(reg(), self.t)
        self.assertEqual(self.ue.phase, "warte_stille")
        eth = self.ue.eth
        self.assertEqual(eth.adresse, ("eth0", 3))
        self.assertEqual(self.programme[0][1], ue.bpf_arp_von(ECHT, ALIAS, EIGEN))
        self.ue.tick(self.t)
        self.lauf(1001.0)
        anfrage = ue.arp_anfrage(EIGEN, "192.168.1.100", ALIAS)
        self.assertEqual(eth.gesendet, [anfrage, anfrage])
        # ARP der echten MAC (Antwort auf die Probe) startet die Stille neu.
        self.lauf(1002.5)
        self.ue.frame(FRAMES["arp_echt"], ("eth0", 3, socket.PACKET_BROADCAST, 1, mac(ECHT)), self.t)
        self.lauf(1005.0)
        self.assertEqual(self.ue.phase, "warte_stille")
        self.lauf(1005.5)
        self.assertEqual(self.ue.phase, "uebernommen")
        self.assertEqual(self.ue.phase_bericht(), "uebernommen")

    def test_uebernahme_reihenfolge_und_isolation(self):
        self.uebernehmen()
        befehle = [e[1] for e in self.ereignisse if e[0] == "befehl"]
        laden = befehle.index("nft -f -")
        alias = befehle.index("ip addr add 192.168.1.110/32 dev eth0")
        self.assertLess(laden, alias)
        # Jeder Ladeversuch trägt eine eigene Marke (Regelkommentar), an der er seine Tabellen erkennt.
        self.assertRegex(self.ue.marke, r"^gb2-[0-9]+-[0-9a-f]{8}$")
        self.assertEqual(self.netz.eingaben[-1], ue.nft_regeln("vhost01", self.sv["hosts"]["vhost01"],
                                                               ["192.168.1.0/24"], ["10.0.0.0/24"], self.ue.marke))
        self.assertIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertEqual(self.netz.tabellen, {("ip", "gb2_sv_vhost01"), ("arp", "gb2_sv_vhost01_arp")})
        position = {e: i for i, e in enumerate(self.ereignisse) if e[0] != "sichern"}
        add = position[("befehl", "ip addr add 192.168.1.110/32 dev eth0")]
        for port in (32400, 25565):
            self.assertGreater(position[("bind", (ALIAS, port))], add)
            sock = self.fabrik.gebunden((ALIAS, port))[0]
            self.assertEqual(sock.backlog, 16)
            self.assertFalse(sock.blocking)
        # Zustand ehrlich vor dem Eingriff: Tabellen-/Aliasmerker stehen schon VOR nft/ip.
        vorher = [e[1] for e in self.ereignisse[:add] if e[0] == "sichern"]
        self.assertTrue(vorher[-1]["alias"])
        self.assertTrue(vorher[-1]["nft"])
        # Filter (b) ersetzt (a) auf demselben Socket vor dem Alias.
        eth = [prog for sock, prog in self.programme if sock is self.ue.eth]
        self.assertEqual(eth, [ue.bpf_arp_von(ECHT, ALIAS, EIGEN), ue.bpf_uebernommen(ECHT, ALIAS, EIGEN)])

    def test_garp_und_lebendprobe(self):
        self.uebernehmen()
        start = self.t
        eth = self.ue.eth
        garp = ue.garp(EIGEN, ALIAS)
        probe = ue.arp_anfrage(EIGEN, "192.168.1.100", ALIAS)
        proben_vorher = eth.gesendet.count(probe)
        self.lauf(start + 61)
        # GARP bei 0/1/3 s, danach je garp_s; Lebendprobe je lebendprobe_s.
        self.assertEqual(eth.gesendet.count(garp), 4)
        self.assertEqual(eth.gesendet.count(probe) - proben_vorher, 12)

    def test_vpn_socket_optional_und_neuer_versuch(self):
        self.fabrik.bind_fehler.add(("wg0", 0x0800))
        self.uebernehmen()
        self.assertIsNone(self.ue.vpn)
        self.assertEqual(len(self.ereignis("vpn_socket_fehlt")), 1)
        self.fabrik.bind_fehler.clear()
        self.lauf(self.t + 31)
        self.assertEqual(self.ue.vpn.adresse, ("wg0", 0x0800))
        self.assertEqual(self.ue.vpn.typ, socket.SOCK_DGRAM)
        self.assertEqual(self.programme[-1][1], ue.bpf_syn_cooked(ALIAS))

    def test_echte_mac_gibt_sofort_frei_in_fester_reihenfolge(self):
        self.uebernehmen()
        self.ereignisse.clear()
        listeners = [self.fabrik.gebunden((ALIAS, p))[0] for p in (32400, 25565)]
        self.assertIsNone(self.ue.frame(FRAMES["ip_echt"], ("eth0", 3, socket.PACKET_HOST, 1, mac(ECHT)), self.t))
        self.assertEqual(self.ue.phase, "frei")
        art = [e if e[0] != "sichern" else ("sichern",) for e in self.ereignisse]
        reihenfolge = [art.index(("befehl", "ip addr del 192.168.1.110/32 dev eth0")),
                       art.index(("close", (ALIAS, 32400))),
                       art.index(("befehl", "nft delete table ip gb2_sv_vhost01")),
                       len(art) - 1 - art[::-1].index(("sichern",))]
        self.assertEqual(reihenfolge, sorted(reihenfolge))
        self.assertTrue(all(sock.zu for sock in listeners))
        self.assertEqual(self.netz.tabellen, set())
        self.assertNotIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertIsNone(self.ue.eth)
        self.assertEqual(self.sicherungen[-1]["phase"], "frei")
        self.assertFalse(self.sicherungen[-1]["alias"])
        self.assertEqual(self.ue.erledigt, "z1")
        # Derselbe Zyklus wird nie ein zweites Mal übernommen.
        self.ue.register(reg(), self.t)
        self.assertEqual(self.ue.phase, "frei")
        self.assertEqual(self.wols, [])

    def test_ausgehende_kopie_der_echten_mac_zaehlt_nicht(self):
        self.uebernehmen()
        self.ue.frame(FRAMES["ip_echt"], ("eth0", 3, socket.PACKET_OUTGOING, 1, mac(ECHT)), self.t)
        self.assertEqual(self.ue.phase, "uebernommen")

    # Review b5 (netz-fremde-mac): Antwortet ein anderes Gerät für die Host-IP (MAC-Drift von vhost01 nach
    # NIC-/Bridge-Wechsel, belegte Probe-Adresse), darf proxy01 nie übernehmen bzw. muss sofort freigeben.
    ANDERE = "02:00:00:00:00:77"

    def fremde_antwort(self, ip=ALIAS):
        return (ue.arp_frame(2, self.ANDERE, ip, EIGEN, "192.168.1.100", eth_ziel=mac(EIGEN)),
                ("eth0", 3, socket.PACKET_HOST, 1, mac(self.ANDERE)))

    def test_fremde_mac_in_warte_stille_verhindert_uebernahme(self):
        self.ue.register(reg(), self.t)
        for _ in range(8):
            self.t = round(self.t + 0.5, 3)
            self.ue.frame(*self.fremde_antwort(), self.t)
            self.ue.tick(self.t)
        self.assertEqual(self.ue.phase, "frei", self.ereignis("phase"))
        self.assertEqual(self.netz.befehle, [])
        self.assertEqual(self.ereignis("phase")[-1]["grund"], "fremde_mac")
        self.assertEqual([(r["mac"], r["phase"], r["zyklus"]) for r in self.ereignis("fremde_mac")],
                         [(self.ANDERE, "warte_stille", "z1")])
        self.assertEqual(self.ue.erledigt, "z1")
        # Bei Zweifel WOL statt Alias (Spec 3.7): ein schlafender vhost01 bekommt seinen Weckruf.
        self.assertEqual(len(self.wols), 1)
        self.assertEqual(self.ue.weckung["entscheidung"], "fremde_mac")
        self.ue.register(reg(), self.t)
        self.lauf(self.t + 10)
        self.assertEqual(self.ue.phase, "frei")
        self.assertFalse(any(b[:3] == ["ip", "addr", "add"] for b in self.netz.befehle))

    def test_fremde_mac_in_uebernommen_gibt_sofort_frei(self):
        self.uebernehmen()
        self.ereignisse.clear()
        self.ue.frame(*self.fremde_antwort(), self.t)
        self.assertEqual(self.ue.phase, "frei")
        self.assertEqual(self.ereignis("phase")[-1]["grund"], "fremde_mac")
        self.assertEqual(self.ereignis("fremde_mac")[0]["phase"], "uebernommen")
        self.assertNotIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertEqual(self.netz.tabellen, set())
        self.assertIsNone(self.ue.eth)
        self.assertEqual(self.ue.erledigt, "z1")
        self.assertEqual(len(self.wols), 1)
        self.ue.register(reg(), self.t)
        self.assertEqual(self.ue.phase, "frei")

    def test_eigene_mac_und_fremde_absender_ip_zaehlen_nicht(self):
        self.ue.register(reg(), self.t)
        # Ein Client fragt nach .110 (Absender .18) und ein eigenes GARP als eingehende Kopie: kein Anspruch.
        for name in ("arp_fremd_andere_ip", "garp_eigen"):
            self.ue.frame(*eingehend(FRAMES[name]), self.t)
        self.lauf(self.t + 3)
        self.assertEqual(self.ue.phase, "uebernommen")
        for name in ("arp_fremd_andere_ip", "garp_eigen"):
            self.ue.frame(*eingehend(FRAMES[name]), self.t)
        self.assertEqual(self.ue.phase, "uebernommen")
        self.assertEqual(self.ereignis("fremde_mac"), [])

    def test_probe_adresse_belegt_wird_nie_uebernommen(self):
        probe = ue.Uebernahme("probe", self.sv["probe"], self.sv, self.u, probe=True)
        self.ue = probe
        probe.warte_stille("probe", self.t + 60, self.t)
        self.t += 0.4
        probe.frame(*self.fremde_antwort("192.168.1.199"), self.t)
        self.lauf(self.t + 5)
        self.assertEqual(probe.phase, "frei")
        self.assertEqual(self.ereignis("phase")[-1]["grund"], "fremde_mac")
        self.assertEqual(self.netz.befehle, [])
        self.assertEqual(self.wols, [])
        # Kein GARP: die ARP-Caches im LAN bleiben beim Gerät, dem die Adresse gehört.
        garp = ue.garp(EIGEN, "192.168.1.199")
        self.assertFalse(any(garp in s.gesendet for s in self.fabrik.sockets))

    def test_register_ausloeser(self):
        for name, row, grund in (("angemeldet", reg("angemeldet"), "register_angemeldet"),
                                 ("neuer_zyklus", reg("abgemeldet", "z2"), "neuer_zyklus"),
                                 ("lease_abgelaufen", reg("lease_abgelaufen"), "register_lease_abgelaufen"),
                                 ("abgemeldet", reg("abgemeldet"), "register_phase"),
                                 ("fehlt", None, "register_fehlt")):
            with self.subTest(name=name):
                self.setUp()
                self.uebernehmen()
                self.ue.register(row, self.t)
                self.assertEqual(self.ue.phase, "frei")
                self.assertEqual(self.ereignis("phase")[-1]["grund"], grund)
                self.assertEqual(self.netz.tabellen, set())
                self.assertEqual(self.wols, [])

    def test_lease_ablauf_gibt_frei_und_weckt(self):
        self.ue.register(reg(ablauf_boot=1100.0), self.t)
        self.lauf(1099.5)
        self.assertEqual(self.ue.phase, "uebernommen")
        self.lauf(1100.0)
        self.assertEqual(self.ue.phase, "frei")
        self.assertEqual(self.ereignis("phase")[-1]["grund"], "lease_abgelaufen")
        self.assertEqual(self.wols, [(1100.0, ECHT)])
        self.assertEqual(self.ue.weckung["entscheidung"], "lease_abgelaufen")
        self.assertEqual(set(self.ue.weckung), {"zeit", "weg", "port", "quellklasse", "entscheidung"})
        self.lauf(1130.0)
        self.assertEqual(len(self.wols), 3)
        # vhost01 meldet sich: Nachlauf-Serie endet.
        self.ue.register(reg("angemeldet"), self.t)
        self.lauf(1200.0)
        self.assertEqual(len(self.wols), 3)
        self.assertIsNone(self.ue.serie)

    def test_wol_serie_r4_und_wecken_gescheitert(self):
        self.uebernehmen()
        start = self.t
        info = {"weg": 4, "port": 22, "quellklasse": "VPN", "entscheidung": "wecken"}
        self.assertTrue(self.ue.wecken(info, self.t))
        self.assertEqual(self.ue.phase_bericht(), "wecken")
        self.assertFalse(self.ue.wecken(info, self.t))
        self.lauf(start + 179.5)
        self.assertEqual([round(t - start) for t, _ in self.wols], list(range(0, 180, 15)))
        self.assertEqual(self.ue.phase_bericht(), "wecken")
        self.lauf(start + 180)
        self.assertEqual(len(self.wols), 12)
        self.assertEqual(self.ue.phase_bericht(), "uebernommen")
        self.assertEqual(len(self.ereignis("wecken_gescheitert")), 1)
        # Alias bleibt (R4), neue Nachfrage darf erneut wecken.
        self.assertIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertTrue(self.ue.wecken(info, self.t))
        self.assertEqual(self.ue.weckung["port"], 22)
        self.assertEqual(self.ue.weckung["zeit"], 1.7e9 + self.t)

    def test_echte_mac_beendet_serie_als_erfolg(self):
        self.uebernehmen()
        self.ue.wecken({"weg": 4, "port": 22, "quellklasse": "LAN", "entscheidung": "wecken"}, self.t)
        self.lauf(self.t + 40)
        self.ue.frame(FRAMES["arp_echt"], ("eth0", 3, socket.PACKET_BROADCAST, 1, mac(ECHT)), self.t)
        self.assertEqual(self.ue.phase, "frei")
        self.assertIsNone(self.ue.serie)
        self.assertEqual(self.ereignis("wecken_erfolg")[0]["sekunden"], 40)
        anzahl = len(self.wols)
        self.lauf(self.t + 60)
        self.assertEqual(len(self.wols), anzahl)

    def test_kurze_stille_wacher_host_wird_nicht_uebernommen(self):
        # Netztest 12.10.26: stille_s = 1 bei einer Probe je Sekunde übernahm, obwohl der Host jede Probe nach
        # 1 ms beantwortete, sobald die Schleife 2 ms zu spät aufwachte.
        for stille in (1, 2, 3):
            with self.subTest(stille_s=stille):
                self.setUp()
                self.sv["stille_s"] = stille
                self.ue.register(reg(), self.t)
                eth, proben = self.ue.eth, []
                for _ in range(200):
                    gesendet = len(eth.gesendet)
                    self.t = round(self.ue.naechster_termin(self.t) + 0.002, 6)
                    self.ue.tick(self.t)
                    if len(eth.gesendet) > gesendet:
                        proben.append(self.t)
                        self.t += 0.001
                        self.ue.frame(FRAMES["arp_echt"], ("eth0", 3, socket.PACKET_BROADCAST, 1, mac(ECHT)), self.t)
                self.assertEqual(self.ue.phase, "warte_stille", self.ereignis("phase"))
                self.assertEqual(self.netz.befehle, [])
                # Drei Proben je Stillefenster, höchstens eine je Sekunde (Plan 5.2 bei stille_s = 3).
                abstand = max(b - a for a, b in zip(proben, proben[1:]))
                self.assertAlmostEqual(abstand, min(1.0, stille / 3.0), delta=0.004)
                # Schweigt der Host, übernimmt der Dienst nach stille_s.
                start = self.t
                while self.ue.phase == "warte_stille":
                    self.t = round(self.ue.naechster_termin(self.t) + 0.002, 6)
                    self.ue.tick(self.t)
                self.assertEqual(self.ue.phase, "uebernommen")
                self.assertLessEqual(self.t - start, stille + 0.01)

    def test_stille_bleibt_aus(self):
        self.ue.register(reg(), self.t)
        while self.t < 1600:
            self.t += 1
            self.ue.frame(FRAMES["arp_echt"], ("eth0", 3, socket.PACKET_BROADCAST, 1, mac(ECHT)), self.t)
            self.ue.tick(self.t)
        self.assertEqual(self.ue.phase, "frei")
        self.assertEqual(self.ereignis("phase")[-1]["grund"], "stille_ausgeblieben")
        self.assertEqual(self.wols, [])
        self.assertEqual(self.netz.befehle, [])
        self.ue.register(reg(), self.t)
        self.assertEqual(self.ue.phase, "frei")

    def test_vorpruefung_jeder_fehler(self):
        faelle = {
            "arp_sysctl_ungueltig": lambda: self.dateien.update({"/proc/sys/net/ipv4/conf/eth0/arp_ignore": "0\n"}),
            "arp_sysctl_ungueltig_all": lambda: self.dateien.update({"/proc/sys/net/ipv4/conf/all/arp_announce": "0"}),
            "arp_sysctl_unklar": lambda: self.dateien.pop("/proc/sys/net/ipv4/conf/all/arp_ignore"),
            "interface_unklar": lambda: self.dateien.update({"/sys/class/net/eth0/address": "kaputt"}),
            "mac_eigene": lambda: self.dateien.update({"/sys/class/net/eth0/address": ECHT}),
            "adresse_lokal": lambda: self.netz.adressen.append((ALIAS, 24, "eth1")),
            "listen_ip_fehlt": lambda: self.netz.adressen.remove(("192.168.1.100", 24, "eth0")),
            "adressen_unklar": lambda: self.netz.stoerung.update({("ip", "-j"): "kaputt"}),
            "tabelle_belegt": lambda: self.netz.tabellen.add(("arp", "gb2_sv_vhost01_arp")),
            "nft_fehlt": lambda: self.netz.stoerung.update({("nft",): "fehlt"}),
            "nft_unklar": lambda: self.netz.stoerung.update({("nft", "-j"): "rc"}),
        }
        for name, stoeren in faelle.items():
            with self.subTest(name=name):
                self.setUp()
                self.ue.register(reg(), self.t)
                stoeren()
                self.lauf(self.t + 3)
                self.assertEqual(self.ue.phase, "frei")
                fehler = self.ereignis("uebernahme_fehlgeschlagen")
                self.assertEqual(fehler[0]["grund"], name.replace("_all", ""))
                self.assertFalse(any(b[:3] == ["ip", "addr", "add"] or b[:2] == ["nft", "-f"] for b in self.netz.befehle))
                self.assertEqual(len(self.wols), 1)
                self.assertEqual(self.ue.weckung["entscheidung"], "uebernahme_fehlgeschlagen")
                self.assertEqual(self.ue.erledigt, "z1")

    def test_vorpruefung_ohne_raw_recht(self):
        self.ue.register(reg(), self.t)
        self.fabrik.verboten.add(socket.AF_PACKET)
        self.lauf(self.t + 3)
        self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "raw_socket_fehlt")
        self.setUp()
        self.fabrik.verboten.add(socket.AF_PACKET)
        self.ue.register(reg(), self.t)
        self.assertEqual(self.ue.phase, "frei")
        self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "raw_socket")
        self.assertEqual(len(self.wols), 1)

    def test_nft_laden_scheitert(self):
        for art in ("rc", "stumm"):
            with self.subTest(art=art):
                self.setUp()
                self.netz.stoerung[("nft", "-f")] = art
                self.ue.register(reg(), self.t)
                self.lauf(self.t + 3)
                self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "nft_laden")
                self.assertFalse(any(b[:3] == ["ip", "addr", "add"] for b in self.netz.befehle))
                # Bei Fehlschlag des Ladens wird keine (womöglich fremde) Tabelle gelöscht.
                self.assertFalse(any(b[:2] == ["nft", "delete"] for b in self.netz.befehle))
                self.assertFalse(self.ue.nft)
                self.assertEqual(len(self.wols), 1)

    def test_fremde_tabelle_im_rennen_bleibt_unberuehrt(self):
        echt = self.netz.__call__

        def rennen(args, input=None, **kwargs):
            if list(args) == ["nft", "-f", "-"]:
                # Zwischen Vorprüfung und Laden legt jemand anderes eine gleichnamige Tabelle an.
                self.netz.tabellen.add(("ip", "gb2_sv_vhost01"))
            return echt(args, input=input, **kwargs)
        self.u.runner = rennen
        self.ue.register(reg(), self.t)
        self.lauf(self.t + 3)
        self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "nft_laden")
        self.assertEqual(self.netz.tabellen, {("ip", "gb2_sv_vhost01")})
        self.assertFalse(any(b[:2] == ["nft", "delete"] for b in self.netz.befehle))
        self.assertFalse(self.ue.nft)

    def test_alias_setzen_scheitert_raeumt_tabellen(self):
        for art in ("rc", "stumm"):
            with self.subTest(art=art):
                self.setUp()
                self.netz.stoerung[("ip", "addr", "add")] = art
                self.ue.register(reg(), self.t)
                self.lauf(self.t + 3)
                self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "alias_setzen")
                self.assertEqual(self.netz.tabellen, set())
                self.assertFalse(self.ue.alias or self.ue.nft)
                self.assertEqual(len(self.wols), 1)

    # Review b5 (netz-rc-statt-tatsache): ip/nft reißen die 2-s-Frist erst NACH der Änderung (rtnl_lock,
    # commit_mutex auf dem Pi): rc -1, aber Alias bzw. Tabellen stehen. Es zählen nur Tatsachen.
    def frist_nach_wirkung(self, praefix, danach=None):
        echt = self.netz.__call__

        def runner(args, input=None, **kwargs):
            result = echt(args, input=input, **kwargs)
            if list(args[:len(praefix)]) == praefix:
                if danach:
                    danach()
                raise subprocess.TimeoutExpired(args, 2)
            return result
        self.u.runner = runner

    def test_alias_frist_nach_wirkung_wird_entfernt(self):
        self.frist_nach_wirkung(["ip", "addr", "add"])
        self.ue.register(reg(), self.t)
        self.lauf(self.t + 3)
        self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "alias_setzen")
        self.assertNotIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertEqual(self.netz.tabellen, set())
        self.assertFalse(self.ue.alias or self.ue.nft)
        self.assertEqual(len(self.wols), 1)
        self.assertIsNone(self.ue.vorpruefen())

    def test_alias_frist_und_unklare_adressen_isoliert_bis_nachgeholt(self):
        # Nach dem Abbruch ist auch "ip -j" unklar: Alias gilt als vorhanden, die Tabellen bleiben (R-A4).
        self.frist_nach_wirkung(["ip", "addr", "add"],
                                lambda: self.netz.stoerung.update({("ip", "-j"): "kaputt"}))
        self.ue.register(reg(), self.t)
        self.lauf(self.t + 3)
        self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "alias_setzen")
        self.assertTrue(self.ue.alias)
        self.assertEqual(len(self.netz.tabellen), 2)
        self.assertIsNotNone(self.ue.nachraeumen)
        del self.netz.stoerung[("ip", "-j")]
        self.lauf(self.t + 11)
        self.assertNotIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertEqual(self.netz.tabellen, set())
        self.assertFalse(self.ue.alias or self.ue.nft)

    def test_nft_frist_nach_wirkung_wird_entfernt(self):
        self.frist_nach_wirkung(["nft", "-f", "-"])
        self.ue.register(reg(), self.t)
        self.lauf(self.t + 3)
        self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "nft_laden")
        self.assertEqual(self.netz.tabellen, set())
        self.assertFalse(self.ue.nft)
        self.assertFalse(any(b[:3] == ["ip", "addr", "add"] for b in self.netz.befehle))
        self.assertEqual(len(self.wols), 1)
        self.assertIsNone(self.ue.vorpruefen())

    def test_nft_frist_und_unklare_liste_wird_nachgeholt(self):
        self.frist_nach_wirkung(["nft", "-f", "-"], lambda: self.netz.stoerung.update({("nft", "-j"): "rc"}))
        self.ue.register(reg(), self.t)
        self.lauf(self.t + 3)
        self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "nft_laden")
        self.assertTrue(self.ue.nft)
        self.assertEqual(len(self.netz.tabellen), 2)
        del self.netz.stoerung[("nft", "-j")]
        self.lauf(self.t + 11)
        self.assertEqual(self.netz.tabellen, set())
        self.assertFalse(self.ue.nft)
        self.assertIsNone(self.ue.vorpruefen())

    def test_fremde_tabelle_im_rennen_bei_unklarer_liste_bleibt_unberuehrt(self):
        echt = self.netz.__call__

        def rennen(args, input=None, **kwargs):
            if list(args) == ["nft", "-f", "-"]:
                self.netz.tabellen.add(("ip", "gb2_sv_vhost01"))
                result = echt(args, input=input, **kwargs)
                self.netz.stoerung[("nft", "-j")] = "rc"
                return result
            return echt(args, input=input, **kwargs)
        self.u.runner = rennen
        self.ue.register(reg(), self.t)
        self.lauf(self.t + 3)
        self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "nft_laden")
        del self.netz.stoerung[("nft", "-j")]
        self.lauf(self.t + 11)
        # Ohne die Marke dieses Versuchs ist die Tabelle fremd: nie löschen (R-A7).
        self.assertEqual(self.netz.tabellen, {("ip", "gb2_sv_vhost01")})
        self.assertFalse(any(b[:2] == ["nft", "delete"] for b in self.netz.befehle))
        self.assertFalse(self.ue.nft)

    def test_listener_scheitert(self):
        self.fabrik.bind_fehler.add((ALIAS, 25565))
        self.ue.register(reg(), self.t)
        self.lauf(self.t + 3)
        self.assertEqual(self.ereignis("uebernahme_fehlgeschlagen")[0]["grund"], "listener")
        self.assertEqual(self.netz.tabellen, set())
        self.assertNotIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertTrue(self.fabrik.gebunden((ALIAS, 32400))[0].zu)

    def test_teilfehler_freigabe_ehrlich_und_nachholen(self):
        self.uebernehmen()
        self.netz.stoerung[("ip", "addr", "del")] = "stumm"
        self.ue.freigeben("register_angemeldet", self.t)
        self.assertEqual(self.ue.phase, "frei")
        # Alias noch da: Isolation (nft) bleibt stehen, der Zustand sagt die Wahrheit.
        self.assertIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertEqual(len(self.netz.tabellen), 2)
        self.assertTrue(self.sicherungen[-1]["alias"])
        self.assertTrue(self.sicherungen[-1]["nft"])
        self.assertEqual(self.ereignis("freigabe_unvollstaendig")[0]["fehler"], ["alias", "nft_bleibt"])
        self.assertTrue(all(s.zu for s in self.fabrik.sockets if s.adresse and s.adresse[0] == ALIAS))
        self.lauf(self.t + 5)
        self.assertEqual(len(self.netz.tabellen), 2)
        del self.netz.stoerung[("ip", "addr", "del")]
        self.netz.stoerung[("nft", "delete")] = "rc"
        self.lauf(self.t + 6)
        self.assertNotIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertFalse(self.sicherungen[-1]["alias"])
        self.assertTrue(self.sicherungen[-1]["nft"])
        del self.netz.stoerung[("nft", "delete")]
        self.lauf(self.t + 11)
        self.assertEqual(self.netz.tabellen, set())
        self.assertFalse(self.sicherungen[-1]["nft"])

    def test_boot_zweifel_weckt_statt_alias(self):
        for name, row in (("anderer_boot", reg(boot="99999999-2222-3333-4444-555555555555")),
                          ("ohne_bootfelder", reg(ablauf_boot=None, boot=None)),
                          ("lease_vorbei", reg(ablauf_boot=900.0))):
            with self.subTest(name=name):
                self.setUp()
                self.ue.register(row, self.t)
                self.assertEqual(self.ue.phase, "frei")
                self.assertIsNone(self.ue.eth)
                self.assertEqual(len(self.wols), 1)
                self.assertEqual(self.ue.weckung["entscheidung"],
                                 "lease_abgelaufen" if name == "lease_vorbei" else "lease_unklar")
                self.ue.register(row, self.t + 1)
                self.assertEqual(len(self.wols), 1)

    def test_syn_ereignisse(self):
        self.uebernehmen()
        self.assertEqual(self.ue.frame(*eingehend(FRAMES["syn"]), self.t), {"quelle": "198.51.100.9", "port": 22})
        self.assertEqual(self.ue.frame(*eingehend(FRAMES["syn_optionen"]), self.t)["port"], 22)
        self.assertIsNone(self.ue.frame(*eingehend(FRAMES["synack"]), self.t))
        self.assertIsNone(self.ue.frame(*eingehend(FRAMES["syn_andere_ip"]), self.t))
        cooked = ipv4_tcp(src="10.0.0.2", port=22)
        self.assertEqual(self.ue.frame(cooked, ("wg0", 0x0800, socket.PACKET_HOST, 65534, b""), self.t, cooked=True),
                         {"quelle": "10.0.0.2", "port": 22})

    def test_abschalten_und_dienstende(self):
        self.uebernehmen()
        self.ue.abschalten(self.t)
        self.assertEqual(self.ue.phase, "frei")
        self.assertEqual(self.ue.weckung["entscheidung"], "abgeschaltet")
        self.assertEqual(len(self.wols), 1)
        self.setUp()
        self.uebernehmen()
        self.ue.wecken({"weg": 4, "port": 22, "quellklasse": "LAN", "entscheidung": "wecken"}, self.t)
        self.ue.freigeben("dienst_ende", self.t)
        self.assertIsNone(self.ue.serie)
        self.assertEqual(self.netz.tabellen, set())

    def test_probe_endet_ohne_wol(self):
        probe = ue.Uebernahme("probe", self.sv["probe"], self.sv, self.u, probe=True)
        self.ue = probe
        probe.warte_stille("probe", self.t + 60, self.t)
        self.lauf(self.t + 3)
        self.assertEqual(probe.phase, "uebernommen")
        self.assertEqual(self.netz.tabellen, {("ip", "gb2_sv_probe"), ("arp", "gb2_sv_probe_arp")})
        self.assertIn(("192.168.1.199", 32, "eth0"), self.netz.adressen)
        self.lauf(self.t + 60)
        self.assertEqual(probe.phase, "frei")
        self.assertEqual(self.ereignis("phase")[-1]["grund"], "probe_ende")
        self.assertEqual(self.wols, [])
        self.assertIsNone(probe.serie)

    def test_naechster_termin_und_sockets(self):
        self.assertEqual(self.ue.sockets(), [])
        self.ue.register(reg(), self.t)
        self.ue.tick(self.t)
        self.assertEqual([art for _, art in self.ue.sockets()], ["eth"])
        self.assertAlmostEqual(self.ue.naechster_termin(self.t), self.t + 1)
        self.lauf(self.t + 3)
        arten = [art for _, art in self.ue.sockets()]
        self.assertEqual(arten, ["eth", "vpn", ("listener", 32400), ("listener", 25565)])


# ---------------------------------------------------------------- Register-Protokoll (Plan Abschnitt 4)

import contextlib
import io

from greenbuddy2 import proxy_ssh
from greenbuddy2.register import Register


class RegisterProtokollTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.path, self.status = base / "register.json", base / "status.json"
        self.boot = (BOOT, 500.0)
        self.reg = Register(self.path, status=self.status, boot=lambda: self.boot)

    def bericht(self, zeit, bereit=("vhost01",), weckung=None, **extra):
        data = {"version": 1, "zeit": zeit, "bereit_fuer": list(bereit), "phasen": {"vhost01": "frei"},
                "gruende": {"vhost01": None if bereit else "arp_sysctl_ungueltig"},
                "weckung": {"vhost01": weckung}}
        data.update(extra)
        self.status.write_text(json.dumps(data))

    def ssh(self, original, now, aus=False):
        return proxy_ssh.ausfuehren(["--host", "vhost01"], original, self.reg, now, aus=aus)

    def test_bereitschaft_aus_frischem_statusbericht(self):
        self.bericht(1000)
        row = self.ssh("abmelden z1", 1015)
        self.assertEqual((row["bereit"], row["grund"]), (True, None))
        self.assertEqual(row["stellvertreter"], {"phase": "frei", "alter_s": 15, "grund": None})
        self.assertEqual(set(row), {"host", "bereit", "grund", "zustand", "stellvertreter"})
        for now, grund in ((1015.5, "stellvertreter_status_alt"), (994, "stellvertreter_status_alt")):
            with self.subTest(now=now):
                self.assertEqual(self.ssh("status", now)["grund"], grund)
        self.bericht(1000, bereit=())
        row = self.ssh("status", 1001)
        self.assertEqual((row["bereit"], row["grund"]), (False, "stellvertreter_nicht_bereit"))
        self.assertEqual(row["stellvertreter"]["grund"], "arp_sysctl_ungueltig")
        for kaputt in ("{", "[]", json.dumps({"version": 2, "zeit": 1000, "bereit_fuer": [], "phasen": {}}),
                       json.dumps({"version": 1, "zeit": "jetzt", "bereit_fuer": [], "phasen": {}}),
                       json.dumps({"version": 1, "zeit": 1000, "bereit_fuer": "vhost01", "phasen": {}})):
            with self.subTest(kaputt=kaputt):
                self.status.write_text(kaputt)
                row = self.ssh("status", 1001)
                self.assertEqual((row["bereit"], row["grund"], row["stellvertreter"]),
                                 (False, "stellvertreter_status_fehlt", None))
        self.status.unlink()
        self.assertEqual(self.ssh("status", 1001)["grund"], "stellvertreter_status_fehlt")
        self.status.symlink_to(self.path)
        self.assertEqual(self.ssh("status", 1001)["grund"], "stellvertreter_status_fehlt")

    def test_schlafe_jetzt_mit_sekunden_und_lease(self):
        self.bericht(1000)
        self.ssh("abmelden z1", 1000)
        row = self.ssh("schlafe-jetzt z1 3600", 1001)
        self.assertTrue(row["bereit"])
        zustand = row["zustand"]
        self.assertEqual(zustand["phase"], "schlaf_absicht")
        # R5: Lease = Sekunden + 900 auf proxy01s eigener Uhr, zusätzlich als BOOTTIME mit boot_id.
        self.assertEqual(zustand["ablauf"], 1001 + 3600 + 900)
        self.assertEqual(zustand["ablauf_boot"], 500.0 + 3600 + 900)
        self.assertEqual(zustand["boot_id"], BOOT)
        self.assertEqual(zustand["schlaf_s"], 3600)
        # Wiederholung verlängert nicht.
        self.boot = (BOOT, 900.0)
        self.assertEqual(self.ssh("schlafe-jetzt z1 43200", 1010)["zustand"]["ablauf_boot"], 5000.0)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.reg.lesen()["hosts"]["vhost01"]["phase"], "schlaf_absicht")

    def test_schlafe_jetzt_argumente(self):
        self.bericht(1000)
        self.ssh("abmelden z1", 1000)
        for original, grund in (("schlafe-jetzt z1", "befehl_argumente"),
                                ("schlafe-jetzt z1 599", "sekunden_ungueltig"),
                                ("schlafe-jetzt z1 43201", "sekunden_ungueltig"),
                                ("schlafe-jetzt z1 0600", "sekunden_ungueltig"),
                                ("schlafe-jetzt z1 6e2", "sekunden_ungueltig"),
                                ("schlafe-jetzt z1 -600", "sekunden_ungueltig"),
                                ("schlafe-jetzt z1 600 1", "befehl_argumente"),
                                ("abmelden z1 600", "befehl_argumente"),
                                ("schlafe-jetzt z2 600", "zyklus_passt_nicht")):
            with self.subTest(original=original), self.assertRaisesRegex(ValueError, "^%s$" % grund):
                self.ssh(original, 1001)
        self.assertEqual(self.ssh("schlafe-jetzt z1 600", 1001)["zustand"]["ablauf"], 2501)
        self.assertEqual(self.ssh("schlafe-jetzt z1 43200", 1002)["zustand"]["ablauf"], 2501)

    def test_anmelden_liefert_weckung_nur_aus_diesem_zyklus(self):
        weckung = {"zeit": 1500.0, "weg": 4, "port": 22, "quellklasse": "VPN", "entscheidung": "wecken"}
        self.bericht(1000)
        self.ssh("abmelden z1", 1000)
        self.ssh("schlafe-jetzt z1 3600", 1001)
        self.bericht(2000, weckung=dict(weckung, zusatz="nie weitergeben"))
        row = self.ssh("anmelden z1", 2001)
        self.assertEqual(row["weckung"], weckung)
        self.assertEqual(row["zustand"]["phase"], "angemeldet")
        # Weckung vor dem Zyklusbeginn gehört zu einem früheren Zyklus.
        self.ssh("abmelden z2", 1600)
        self.assertIsNone(self.ssh("anmelden-abbruch z2", 2002)["weckung"])
        self.assertNotIn("weckung", self.ssh("status", 2003))
        self.status.unlink()
        self.ssh("abmelden z3", 1000)
        self.assertIsNone(self.ssh("anmelden z3", 2004)["weckung"])

    def test_abgeschaltet_ohne_registeraenderung(self):
        self.bericht(1000)
        row = self.ssh("abmelden z1", 1000, aus=True)
        self.assertEqual((row["bereit"], row["grund"], row["entscheidung"]), (False, "abgeschaltet", "abgeschaltet"))
        self.assertFalse(self.path.exists())
        self.ssh("abmelden z1", 1000)
        row = self.ssh("schlafe-jetzt z1 600", 1001, aus=True)
        self.assertEqual(row["zustand"]["phase"], "abgemeldet")
        # Anmelden darf immer: es kann eine Übernahme nur beenden.
        self.assertEqual(self.ssh("anmelden z1", 1002, aus=True)["zustand"]["phase"], "angemeldet")
        with self.assertRaises(ValueError):
            self.ssh("abmelden ung;ltig", 1000, aus=True)

    def test_altes_register_bleibt_lesbar(self):
        self.path.write_text(json.dumps({"version": 1, "hosts": {"vhost01": {
            "zyklus": "alt", "phase": "schlaf_absicht", "ablauf": 5000, "nachfrage": 0}}}))
        self.assertEqual(self.reg.lesen()["hosts"]["vhost01"]["zyklus"], "alt")
        for feld, wert in (("beginn", "x"), ("ablauf_boot", float("inf")), ("boot_id", 5), ("schlaf_s", 599),
                           ("schlaf_s", True)):
            with self.subTest(feld=feld):
                data = {"version": 1, "hosts": {"vhost01": {"zyklus": "alt", "phase": "schlaf_absicht",
                                                            "ablauf": 5000, "nachfrage": 0, feld: wert}}}
                self.path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    self.reg.lesen()

    def test_main_json_und_exitcodes(self):
        self.bericht(1000)
        with mock.patch.object(proxy_ssh, "Register", return_value=self.reg), \
                mock.patch.object(proxy_ssh.time, "time", return_value=1001), \
                mock.patch.object(proxy_ssh, "abgeschaltet", return_value=False), \
                mock.patch.object(proxy_ssh.sys, "argv", ["gb-proxy-ssh", "--host", "vhost01"]):
            for original, code, key, wert in (("abmelden z1", 0, "bereit", True),
                                              ("schlafe-jetzt z1 10", 1, "fehler", "sekunden_ungueltig"),
                                              ("anmelden fremd", 1, "fehler", "zyklus_passt_nicht"),
                                              ("status; id", 1, "fehler", "befehl_unbekannt")):
                with self.subTest(original=original), mock.patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": original}):
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        self.assertEqual(proxy_ssh.main(), code)
                    row = json.loads(out.getvalue())
                    self.assertEqual(row[key], wert)
                    if code:
                        self.assertEqual(row["bereit"], False)


# ---------------------------------------------------------------- Dienst (select-Schleife)

from greenbuddy2 import stellvertreter as sv_mod
from fixtures import minecraft


class Logger:
    def __init__(self):
        self.rows = []

    def emit(self, row, now=None, heartbeat=False):
        if not heartbeat:
            self.rows.append(dict(row))
        return True


class SofortFaden:
    """Ersetzt threading.Thread: läuft synchron, damit Tests ohne echte Nebenläufigkeit auskommen."""
    starts = 0

    def __init__(self, target, daemon=None):
        self.target = target

    def start(self):
        SofortFaden.starts += 1
        self.target()


class DienstBasis(Basis):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.cfg = beispiel(register=str(base / "register.json"), status=str(base / "status/stellvertreter.json"),
                            zustand=str(base / "sv/uebernahme.json"))
        self.cfg.update(plex_hash="abc123", minecraft_whitelist=["Testspieler"], log=str(base / "log.jsonl"),
                        aus=str(base / "aus"))
        self.logger = Logger()
        self.timeouts = []
        self.aus = False
        self.aufgeloest = []

    def waehlen(self, rlist, timeout):
        self.timeouts.append(timeout)
        bereit = [s for s in rlist if s.bereit()]
        if not bereit:
            self.t = round(self.t + timeout, 6)
        return bereit

    def dienst(self, probe=None, cfg=None, aufloesen=None):
        self.d = sv_mod.Dienst(cfg or self.cfg, self.u, self.logger, probe=probe, waehlen=self.waehlen,
                               aus=lambda: self.aus, aufloesen=aufloesen or self.aufloesen, faden=SofortFaden,
                               pid=4242)
        self.ue = self.d.uebernahmen.get("probe" if probe else "vhost01")
        return self.d

    def aufloesen(self, name):
        self.aufgeloest.append((self.t, name))
        return ["203.0.113.7"]

    def register(self, phase="schlaf_absicht", zyklus="z1", ablauf_boot=None, beginn=None):
        row = reg(phase, zyklus, ablauf_boot=self.t + 7200 if ablauf_boot is None else ablauf_boot)
        row["beginn"] = 1.7e9 + (self.t if beginn is None else beginn)
        path = Path(self.cfg["stellvertretung"]["register"])
        path.write_text(json.dumps({"version": 1, "hosts": {"vhost01": row}}))
        os.utime(path, ns=(int(self.t * 1e9) + 1, int(self.t * 1e9) + 1))

    def bis(self, bedingung, sekunden=30):
        ende = self.t + sekunden
        for _ in range(100000):
            if bedingung():
                return
            self.assertLess(self.t, ende, "Bedingung nicht erreicht: %r" % self.logger.rows[-5:])
            self.d.schritt()
        self.fail("Busy-Loop: Zeit läuft nicht weiter")

    def laufen(self, sekunden):
        # Ohne bereite Sockets muss jeder Schritt Zeit verbrauchen; sonst wäre es ein Busy-Loop.
        ende = self.t + sekunden
        for _ in range(int(sekunden * 4) + 1000):
            if self.t >= ende - 1e-6:
                return
            self.d.schritt()
        self.fail("Busy-Loop: Zeit läuft nicht weiter")

    def status(self):
        return json.loads(Path(self.cfg["stellvertretung"]["status"]).read_text())

    def zeilen(self, **filter):
        return [r for r in self.logger.rows if all(r.get(k) == v for k, v in filter.items())]

    def uebernommen(self):
        self.dienst()
        self.d.starten()
        self.register()
        self.bis(lambda: self.ue.phase == "uebernommen")


class DienstTests(DienstBasis):
    def test_start_gdm_status_und_bereitschaft(self):
        self.dienst().starten()
        self.d.schritt()
        gdm = self.fabrik.gebunden(("0.0.0.0", 32414))[0]
        self.assertIn((socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                       socket.inet_aton("239.0.0.250") + socket.inet_aton("192.168.1.100")), gdm.optionen)
        status = self.status()
        self.assertEqual(status["bereit_fuer"], ["vhost01"])
        self.assertEqual(status["phasen"], {"vhost01": "frei"})
        self.assertEqual(status["gruende"], {"vhost01": None})
        self.assertEqual(status["weckung"], {"vhost01": None})
        self.assertEqual(status["zeit"], 1.7e9 + 1000)
        self.assertEqual(Path(self.cfg["stellvertretung"]["status"]).stat().st_mode & 0o777, 0o640)
        gdm.eingang.append((b"M-SEARCH", ("192.168.1.18", 32414)))
        self.d.schritt()
        self.assertEqual(self.d.zaehler.counts["192.168.1.18"], 1)
        # Statusbericht spätestens alle 5 s, Register höchstens jede Sekunde.
        zeit = status["zeit"]
        self.laufen(5.5)
        self.assertGreater(self.status()["zeit"], zeit)
        self.assertTrue(all(0 <= t <= 1 for t in self.timeouts))

    def test_nicht_bereit_mit_grund_und_erneuter_pruefung(self):
        self.dateien["/proc/sys/net/ipv4/conf/all/arp_ignore"] = "0"
        self.dienst().starten()
        self.d.schritt()
        self.assertEqual(self.status()["bereit_fuer"], [])
        self.assertEqual(self.status()["gruende"]["vhost01"], "arp_sysctl_ungueltig")
        self.dateien["/proc/sys/net/ipv4/conf/all/arp_ignore"] = "1"
        self.laufen(31)
        self.assertEqual(self.status()["bereit_fuer"], ["vhost01"])

    def test_bereitschaft_waehrend_uebernahme_und_sofort_nach_freigabe(self):
        # Netztest 12.10.26: während jeder Übernahme und bis zu 30 s nach einer sauberen Freigabe meldete der
        # Bericht "freigabe_unvollstaendig"; Alias und Tabelle gehören in "uebernommen" zum Normalbetrieb.
        echt = (FRAMES["arp_echt"], ("eth0", 3, socket.PACKET_BROADCAST, 1, mac(ECHT)))
        self.uebernommen()
        self.laufen(31)
        self.assertEqual((self.status()["phasen"]["vhost01"], self.status()["gruende"]["vhost01"]),
                         ("uebernommen", None))
        self.ue.eth.eingang.append(echt)
        self.d.schritt()
        self.assertEqual(self.ue.phase, "frei")
        self.assertEqual((self.status()["gruende"]["vhost01"], self.status()["bereit_fuer"]), (None, ["vhost01"]))
        # Hängt eine Freigabe, steht das im selben Durchlauf im Bericht, nicht erst nach 30 s.
        self.register("schlaf_absicht", "z2")
        self.bis(lambda: self.ue.phase == "uebernommen")
        self.netz.stoerung[("ip", "addr", "del")] = "stumm"
        self.ue.eth.eingang.append(echt)
        self.d.schritt()
        self.assertEqual(self.ue.phase, "frei")
        self.assertEqual((self.status()["gruende"]["vhost01"], self.status()["bereit_fuer"]),
                         ("freigabe_unvollstaendig", []))
        # Freigabe per Lease-Ablauf (im Takt, nicht beim Lesen): ebenfalls sofort neu geprüft.
        del self.netz.stoerung[("ip", "addr", "del")]
        self.laufen(11)
        self.assertEqual(self.status()["gruende"]["vhost01"], None)
        self.register("schlaf_absicht", "z3", ablauf_boot=self.t + 5)
        self.bis(lambda: self.ue.phase == "uebernommen")
        self.netz.stoerung[("ip", "addr", "del")] = "stumm"
        self.bis(lambda: self.ue.phase == "frei")
        self.assertEqual(self.status()["gruende"]["vhost01"], "freigabe_unvollstaendig")

    def test_formfehler_stellvertretung_gdm_laeuft_weiter(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["stellvertretung"]["limits"] = {"wan_quelle_h": 3}
        self.dienst(cfg=cfg).starten()
        self.d.schritt()
        self.assertTrue(self.fabrik.gebunden(("0.0.0.0", 32414)))
        self.assertEqual(self.d.uebernahmen, {})
        status = self.status()
        self.assertEqual((status["bereit_fuer"], status["stellvertretung"]), ([], "stellvertretung_limits"))
        self.assertEqual(len(self.zeilen(ereignis="stellvertretung_ungueltig")), 1)

    def test_register_nur_bei_aenderung_lesen(self):
        self.dienst().starten()
        self.register("abgemeldet")
        with mock.patch.object(sv_mod.Register, "lesen", autospec=True, side_effect=sv_mod.Register.lesen) as lesen:
            self.laufen(5)
            self.assertEqual(lesen.call_count, 1)
            self.register("abgemeldet", "z2")
            self.laufen(2)
            self.assertEqual(lesen.call_count, 2)

    def test_register_unklar_haelt_zustand(self):
        self.uebernommen()
        Path(self.cfg["stellvertretung"]["register"]).write_text("{kaputt")
        self.laufen(3)
        self.assertEqual(self.ue.phase, "uebernommen")
        self.assertEqual(len(self.zeilen(ereignis="register_unklar")), 1)
        Path(self.cfg["stellvertretung"]["register"]).unlink()
        self.laufen(2)
        self.assertEqual(self.ue.phase, "frei")

    def test_echte_mac_gibt_im_selben_durchlauf_frei(self):
        self.uebernommen()
        self.ue.eth.eingang.append((FRAMES["arp_echt"], ("eth0", 3, socket.PACKET_BROADCAST, 1, mac(ECHT))))
        self.d.schritt()
        self.assertEqual(self.ue.phase, "frei")
        self.assertNotIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertEqual(self.status()["phasen"]["vhost01"], "frei")

    def test_vpn_syn_weckt_einmal_und_laufende_weckung_zaehlt_nicht(self):
        self.uebernommen()
        syn = ipv4_tcp(src="10.0.0.2", port=22)
        self.ue.vpn.eingang.append((syn, ("wg0", 0x0800, socket.PACKET_HOST, 65534, b"")))
        self.d.schritt()
        self.assertEqual([m for _, m in self.wols], [ECHT])
        zeile = self.zeilen(entscheidung="wecken")[0]
        self.assertEqual((zeile["quell_ip"], zeile["port"], zeile["quellklasse"], zeile["weg"], zeile["zyklus"]),
                         ("10.0.0.2", 22, "VPN", 4, "z1"))
        self.assertIn("zeit", zeile)
        self.assertEqual(self.status()["phasen"]["vhost01"], "wecken")
        weckung = self.status()["weckung"]["vhost01"]
        self.assertEqual({k: weckung[k] for k in ("weg", "port", "quellklasse", "entscheidung")},
                         {"weg": 4, "port": 22, "quellklasse": "VPN", "entscheidung": "wecken"})
        self.assertNotIn("10.0.0.2", json.dumps(self.status()))
        for _ in range(5):
            self.ue.vpn.eingang.append((syn, ("wg0", 0x0800, socket.PACKET_HOST, 65534, b"")))
            self.d.schritt()
        self.assertEqual(len(self.zeilen(entscheidung="wecken")), 1)
        self.assertEqual(self.d.grenzen.anzahl("vpn_quelle_h", ("vhost01", "10.0.0.2"), self.t), 1)

    def test_vpn_limit_6_je_stunde_mit_rollendem_fenster(self):
        self.uebernommen()
        syn = (ipv4_tcp(src="10.0.0.2", port=22), ("wg0", 0x0800, socket.PACKET_HOST, 65534, b""))
        beginn = self.t
        for runde in range(8):
            self.ue.vpn.eingang.append(syn)
            self.d.schritt()
            self.laufen(181)
        self.assertEqual(len(self.zeilen(entscheidung="wecken")), 6)
        limits = self.zeilen(entscheidung="limit")
        self.assertEqual(len(limits), 1)
        self.assertEqual(limits[0]["limit"], "vpn_quelle_h")
        self.assertEqual(len(self.zeilen(ereignis="wecken_gescheitert")), 6)
        self.laufen(beginn + 3600 - self.t + 1)
        self.ue.vpn.eingang.append(syn)
        self.d.schritt()
        self.assertEqual(len(self.zeilen(entscheidung="wecken")), 7)
        # Limit-Wiederholungen sind verdichtet, ohne Quelladresse.
        self.d.verdichter.flush(1.7e9 + self.t + 7200)
        verdichtet = self.zeilen(entscheidung="limit", verdichtet=True)
        self.assertEqual(verdichtet[0]["anzahl"], 1)
        self.assertNotIn("quell_ip", verdichtet[0])

    def test_lan_syn_und_listenport(self):
        self.uebernommen()
        frames = [ether(ipv4_tcp(src="192.168.1.18", port=32400)),
                  ether(ipv4_tcp(src="192.168.1.18", port=25565)),
                  ether(ipv4_tcp(src="192.168.1.1", port=22)),
                  ether(ipv4_tcp(src="198.51.100.9", port=22)),
                  ether(ipv4_tcp(src="198.51.100.9", port=8443)),
                  ether(ipv4_tcp(src="203.0.113.10", port=8443))]
        for frame in frames:
            self.ue.eth.eingang.append(eingehend(frame))
        self.d.schritt()
        wecken = self.zeilen(entscheidung="wecken")
        self.assertEqual([(z["quell_ip"], z["port"]) for z in wecken], [("192.168.1.18", 32400)])
        self.d.verdichter.flush(1.7e9 + self.t + 3600)
        verdichtet = {(r["port"], r["quellklasse"], r["entscheidung"]): r["anzahl"]
                      for r in self.zeilen(verdichtet=True)}
        self.assertEqual(verdichtet, {(25565, "LAN", "ignoriert"): 1, (22, "LAN", "ausgenommen"): 1,
                                      (22, "WAN", "ignoriert"): 1, (8443, "WAN", "verworfen"): 1,
                                      (8443, "WAN", "wecken_laeuft"): 1})
        # Allowlist-Quelle zählt im eigenen Limit liste_h (Weg 5), nicht im WAN-Limit.
        self.laufen(181)
        self.ue.eth.eingang.append(eingehend(frames[-1]))
        self.d.schritt()
        zeile = self.zeilen(entscheidung="wecken")[-1]
        self.assertEqual((zeile["quell_ip"], zeile["weg"], zeile["quellklasse"]), ("203.0.113.10", 5, "WAN"))
        self.assertEqual(self.d.grenzen.anzahl("liste_h", ("vhost01", 8443), self.t), 1)
        self.assertEqual(self.d.grenzen.anzahl("wan_host_h", ("vhost01",), self.t), 0)

    def verbindung(self, port, quelle, daten=b"", eof=False):
        listener = self.ue.listener[port]
        conn = self.fabrik(socket.AF_INET, socket.SOCK_STREAM, 0)
        if daten:
            conn.eingang.append(daten)
        conn.eof = eof
        listener.wartend.append((conn, (quelle, 50000)))
        return conn

    def rst(self, conn):
        return conn.zu and (socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)) in conn.optionen

    def test_wan_sni_label_weckt_und_rst(self):
        self.cfg["stellvertretung"]["wan_name"] = "ddns.example"
        self.uebernommen()
        spam = self.verbindung(32400, "198.51.100.9", clienthello("198-51-100-20.abc123.plex.direct"))
        self.d.schritt()
        self.d.schritt()
        self.assertTrue(self.rst(spam))
        self.assertEqual(self.wols, [])
        gut = self.verbindung(32400, "198.51.100.9", clienthello("203-0-113-7.abc123.plex.direct"))
        self.d.schritt()
        self.d.schritt()
        self.assertTrue(self.rst(gut))
        zeile = self.zeilen(entscheidung="wecken")[0]
        self.assertEqual((zeile["quellklasse"], zeile["weg"], zeile["sni_label"], zeile["port"]),
                         ("WAN", 7, "wan", 32400))
        self.assertNotIn("wan_ip_unklar", zeile)
        self.assertEqual(self.aufgeloest[0][1], "ddns.example")
        self.assertEqual(self.d.grenzen.anzahl("wan_host_tag", ("vhost01",), self.t), 1)

    def test_wan_ip_unbekannt_laesst_oeffentliche_label_zu(self):
        self.uebernommen()
        conn = self.verbindung(32400, "198.51.100.9", clienthello("198-51-100-20.abc123.plex.direct"))
        self.d.schritt()
        self.d.schritt()
        self.assertTrue(self.rst(conn))
        zeile = self.zeilen(entscheidung="wecken")[0]
        self.assertTrue(zeile["wan_ip_unklar"])
        self.assertEqual(self.aufgeloest, [])

    def test_wan_aufloesung_hoechstens_alle_10_min_und_fehler(self):
        self.cfg["stellvertretung"]["wan_name"] = "ddns.example"
        antworten = [["203.0.113.7"], OSError("kein dns"), ["203.0.113.8"]]

        def aufloesen(name):
            self.aufgeloest.append(self.t)
            antwort = antworten.pop(0)
            if isinstance(antwort, Exception):
                raise antwort
            return antwort
        self.dienst(aufloesen=aufloesen).starten()
        self.laufen(10)
        self.assertEqual(self.aufgeloest, [])
        self.register()
        self.bis(lambda: self.ue.phase == "uebernommen")
        self.assertEqual(self.d.wan.aktuell(self.t), ["203.0.113.7"])
        self.laufen(590)
        self.assertEqual(len(self.aufgeloest), 1)
        self.laufen(15)
        self.assertEqual(len(self.aufgeloest), 2)
        self.assertIsNone(self.d.wan.aktuell(self.t))
        self.assertEqual(len(self.zeilen(ereignis="wan_ip_unklar")), 1)
        self.laufen(600)
        self.assertEqual(self.d.wan.aktuell(self.t), ["203.0.113.8"])

    def test_wan_aufloesung_haengt_gilt_nach_frist_als_unbekannt(self):
        wan = sv_mod.WanAdresse("ddns.example", aufloesen=lambda n: ["203.0.113.7"],
                                faden=lambda target, daemon=None: types.SimpleNamespace(start=lambda: None))
        wan.werte, wan.stand = ["203.0.113.9"], 0.0
        wan.anstossen(600.0)
        self.assertEqual(wan.aktuell(601.0), ["203.0.113.9"])
        self.assertIsNone(wan.aktuell(602.5))
        wan.anstossen(700.0)
        self.assertEqual(wan.versuch, 600.0)

    def test_minecraft_whitelist_aus_lan_mit_lan_limit(self):
        self.uebernommen()
        conn = self.verbindung(25565, "192.168.1.22", minecraft("Testspieler"))
        self.d.schritt()
        self.d.schritt()
        self.assertTrue(self.rst(conn))
        zeile = self.zeilen(entscheidung="wecken")[0]
        self.assertEqual((zeile["quellklasse"], zeile["port"], zeile["weg"]), ("LAN", 25565, 4))
        self.assertNotIn("Testspieler", json.dumps(self.logger.rows))
        self.assertEqual(self.d.grenzen.anzahl("lan_quelle_h", ("vhost01", "192.168.1.22"), self.t), 1)

    def test_ausgenommene_quelle_am_listener_weckt_nie(self):
        self.uebernommen()
        conn = self.verbindung(25565, "192.168.1.1", minecraft("Testspieler"))
        self.d.schritt()
        self.d.schritt()
        self.assertTrue(self.rst(conn))
        self.assertEqual(self.wols, [])
        self.d.verdichter.flush(1.7e9 + self.t + 3600)
        self.assertEqual(self.zeilen(entscheidung="ausgenommen", verdichtet=True)[0]["port"], 25565)

    def test_verbindung_grenzen_64_16kib_5s(self):
        self.uebernommen()
        conns = [self.verbindung(25565, "198.51.100.%d" % i) for i in range(65)]
        self.d.schritt()
        self.d.schritt()
        self.d.schritt()
        self.d.schritt()
        self.d.schritt()
        offen = [c for c in conns if not c.zu]
        self.assertEqual(len(offen), 64)
        self.assertTrue(self.rst(conns[-1]))
        self.assertEqual(len(self.d.verbindungen), 64)
        self.laufen(5.5)
        self.assertEqual(self.d.verbindungen, {})
        self.assertTrue(all(self.rst(c) for c in conns))
        # ClientHello über zwei Records: bleibt "unklar", bis die 16-KiB-Grenze greift.
        anfang = b"\x16\x03\x01\x40\x00\x01\x00\x40\x00" + b"\x00" * 20000
        gross = self.verbindung(32400, "198.51.100.9", anfang)
        self.d.schritt()
        self.d.schritt()
        self.assertTrue(self.rst(gross))
        self.assertEqual(sum(map(len, gross.eingang)), len(anfang) - 16384)
        ende = self.verbindung(32400, "198.51.100.9", b"\x16\x03", eof=True)
        for _ in range(3):
            self.d.schritt()
        self.assertTrue(self.rst(ende))
        self.d.verdichter.flush(1.7e9 + self.t + 3600)
        self.assertEqual(self.zeilen(entscheidung="verbindungslimit", verdichtet=True)[0]["anzahl"], 1)
        self.assertEqual(self.wols, [])

    def test_abschalter_gibt_frei_und_weckt(self):
        self.uebernommen()
        gdm = self.fabrik.gebunden(("0.0.0.0", 32414))[0]
        self.aus = True
        self.d.schritt()
        self.assertEqual(self.ue.phase, "frei")
        self.assertEqual(len(self.wols), 1)
        self.assertTrue(gdm.zu)
        status = self.status()
        self.assertEqual((status["bereit_fuer"], status["gruende"]["vhost01"], status["abgeschaltet"]),
                         ([], "abgeschaltet", True))
        self.register("schlaf_absicht", "z9")
        self.laufen(5)
        self.assertEqual(self.ue.phase, "frei")
        self.aus = False
        self.laufen(2)
        self.assertEqual(len([s for s in self.fabrik.gebunden(("0.0.0.0", 32414)) if not s.zu]), 1)

    def test_stopp_merker_beendet_die_schleife(self):
        self.dienst()
        schritte = []

        def schritt():
            schritte.append(self.t)
            self.assertLess(len(schritte), 10, "Schleife beachtet den Stopp-Merker nicht")
            if len(schritte) == 3:
                self.d.stopp = True
        with mock.patch.object(self.d, "schritt", side_effect=schritt):
            self.d.laufen()
        self.assertEqual(len(schritte), 3)
        self.d.beenden()
        self.assertEqual(self.zeilen(ereignis="ende")[0]["grund"], "dienst_ende")

    def test_beenden_meldet_nicht_bereit(self):
        self.uebernommen()
        self.d.beenden("dienst_ende")
        self.assertEqual(self.netz.tabellen, set())
        self.assertNotIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        status = self.status()
        self.assertEqual((status["bereit_fuer"], status["gruende"]["vhost01"]), ([], "dienst_beendet"))
        zustand = json.loads(Path(self.cfg["stellvertretung"]["zustand"]).read_text())
        self.assertEqual(zustand["hosts"]["vhost01"]["phase"], "frei")
        self.assertFalse(zustand["hosts"]["vhost01"]["alias"])
        self.assertEqual(self.wols, [])

    def test_beenden_holt_haengende_freigabe_nach(self):
        self.uebernommen()
        self.netz.stoerung[("ip", "addr", "del")] = "stumm"
        self.ue.frame(FRAMES["arp_echt"], ("eth0", 3, socket.PACKET_BROADCAST, 1, mac(ECHT)), self.t)
        self.assertTrue(self.ue.alias)
        del self.netz.stoerung[("ip", "addr", "del")]
        self.d.beenden("dienst_ende")
        self.assertFalse(self.ue.alias or self.ue.nft)
        self.assertEqual(self.netz.tabellen, set())

    def test_neustart_kennt_erledigte_zyklen(self):
        self.uebernommen()
        self.ue.frame(FRAMES["arp_echt"], ("eth0", 3, socket.PACKET_BROADCAST, 1, mac(ECHT)), self.t)
        self.d.beenden("dienst_ende")
        self.dienst().starten()
        self.laufen(10)
        self.assertEqual(self.ue.phase, "frei")
        self.assertEqual(self.ue.erledigt, "z1")

    def test_neustart_nach_absturz_raeumt_auf_und_uebernimmt_neu(self):
        self.uebernommen()
        # SIGKILL: kein beenden(); Alias und Tabellen bleiben, Zustandsdatei sagt uebernommen.
        self.assertEqual(json.loads(Path(self.cfg["stellvertretung"]["zustand"]).read_text())
                         ["hosts"]["vhost01"]["phase"], "uebernommen")
        self.dienst().starten()
        self.assertEqual(self.netz.tabellen, set())
        self.assertNotIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.bis(lambda: self.ue.phase == "uebernommen")
        self.assertEqual(self.ue.zyklus, "z1")

    def test_neustart_nach_dienstende_uebernimmt_wieder(self):
        # Dienstende/Abschalter sind keine Tatsache über den Host: derselbe Zyklus darf wieder übernommen werden.
        self.uebernommen()
        self.d.beenden("dienst_ende")
        self.assertIsNone(json.loads(Path(self.cfg["stellvertretung"]["zustand"]).read_text())
                          ["hosts"]["vhost01"]["erledigt"])
        self.dienst().starten()
        self.bis(lambda: self.ue.phase == "uebernommen")
        self.assertEqual(self.ue.zyklus, "z1")

    def test_nach_abschalter_und_weckserie_wieder_uebernehmen(self):
        self.uebernommen()
        self.aus = True
        self.d.schritt()
        self.aus = False
        self.laufen(60)
        self.assertEqual(self.ue.phase, "frei")
        self.bis(lambda: self.ue.phase == "uebernommen", 200)
        self.assertEqual(len(self.wols), 12)

    def test_zustand_anderer_boot_wird_ignoriert(self):
        path = Path(self.cfg["stellvertretung"]["zustand"])
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"version": 1, "boot_id": "alt", "hosts": {"vhost01": {"erledigt": "z1"}}}))
        self.dienst().starten()
        self.register()
        self.bis(lambda: self.ue.phase == "warte_stille")

    def test_anmelden_bekommt_weckung_aus_dem_status(self):
        self.uebernommen()
        reg_obj = Register(self.cfg["stellvertretung"]["register"], status=self.cfg["stellvertretung"]["status"],
                           boot=lambda: (BOOT, self.t))
        self.ue.eth.eingang.append(eingehend(ether(ipv4_tcp(src="192.168.1.18", port=22))))
        self.laufen(6)
        row = reg_obj.befehl("vhost01", "anmelden", "z1", 1.7e9 + self.t)
        self.assertEqual(row["weckung"]["port"], 22)
        self.assertEqual(row["weckung"]["quellklasse"], "LAN")


class GrenzenTests(unittest.TestCase):
    LIMITS = {"wan_quelle_h": 3, "wan_host_h": 4, "wan_host_tag": 12, "lan_quelle_h": 3, "vpn_quelle_h": 6,
              "liste_h": 6}

    def versuch(self, grenzen, art, quelle, now, port=32400):
        keys = sv_mod.limit_schluessel("vhost01", art, quelle, port)
        voll = grenzen.voll(keys, now)
        if not voll:
            grenzen.zaehlen(keys, now)
        return voll

    def test_lan_genau_3_je_stunde_rollend(self):
        grenzen = sv_mod.Grenzen(self.LIMITS)
        self.assertEqual([self.versuch(grenzen, "lan", "192.168.1.9", t) for t in (0, 10, 20, 3599)],
                         [None, None, None, "lan_quelle_h"])
        self.assertIsNone(self.versuch(grenzen, "lan", "192.168.1.8", 3599))
        self.assertIsNone(self.versuch(grenzen, "lan", "192.168.1.9", 3600))
        self.assertEqual(self.versuch(grenzen, "lan", "192.168.1.9", 3601), "lan_quelle_h")

    def test_wan_quelle_host_stunde_und_tag(self):
        grenzen = sv_mod.Grenzen(self.LIMITS)
        quellen = ["198.51.100.%d" % i for i in range(1, 40)]
        ergebnisse = []
        for stunde in range(4):
            for minute in range(5):
                ergebnisse.append(self.versuch(grenzen, "wan", quellen[stunde * 5 + minute],
                                               stunde * 3600 + minute * 60))
        self.assertEqual(ergebnisse[:5], [None] * 4 + ["wan_host_h"])
        self.assertEqual(ergebnisse.count(None), 12)
        self.assertEqual(self.versuch(grenzen, "wan", "198.51.100.200", 4 * 3600), "wan_host_tag")
        self.assertIsNone(self.versuch(grenzen, "wan", "198.51.100.200", 86400))
        grenzen = sv_mod.Grenzen(self.LIMITS)
        self.assertEqual([self.versuch(grenzen, "wan", "198.51.100.1", t) for t in (0, 1, 2, 3)],
                         [None, None, None, "wan_quelle_h"])

    def test_null_haelt_weg_aus_und_liste_eigenes_limit(self):
        grenzen = sv_mod.Grenzen(dict(self.LIMITS, vpn_quelle_h=0))
        self.assertEqual(self.versuch(grenzen, "vpn", "10.0.0.2", 0), "vpn_quelle_h")
        for i in range(6):
            self.assertIsNone(self.versuch(grenzen, "liste", "203.0.113.10", i, port=8443))
        self.assertEqual(self.versuch(grenzen, "liste", "203.0.113.10", 7, port=8443), "liste_h")
        self.assertIsNone(self.versuch(grenzen, "wan", "203.0.113.10", 8))


class AusloeserRegelTests(unittest.TestCase):
    def test_tabelle_r3(self):
        host = konfig.stellvertretung(beispiel())["hosts"]["vhost01"]
        for quelle, klasse, port, erwartet in (
                ("192.168.1.18", "LAN", 22, ("lan", None)),
                ("192.168.1.18", "LAN", 8096, ("lan", None)),
                ("192.168.1.18", "LAN", 32400, ("lan", None)),
                ("10.0.0.2", "VPN", 32400, ("vpn", None)),
                ("198.51.100.9", "WAN", 32400, (None, "ignoriert")),
                ("198.51.100.9", "WAN", 22, (None, "ignoriert")),
                ("192.168.1.18", "LAN", 25565, (None, "ignoriert")),
                ("192.168.1.18", "LAN", 445, (None, "ignoriert")),
                ("203.0.113.10", "WAN", 8443, ("liste", None)),
                ("198.51.100.9", "WAN", 8443, (None, "verworfen")),
                ("192.168.1.18", "LAN", 8443, (None, "verworfen")),
                ("192.168.1.115", "LAN", 22, (None, "ausgenommen")),
                ("192.168.1.100", "LAN", 32400, (None, "ausgenommen"))):
            with self.subTest(quelle=quelle, port=port):
                self.assertEqual(sv_mod.syn_regel(host, quelle, klasse, port), erwartet)


class ProbeTests(DienstBasis):
    def test_probe_uebernimmt_nur_probe_ip_ohne_register_und_gdm(self):
        self.register()
        self.dienst(probe=60)
        self.assertEqual(list(self.d.uebernahmen), ["probe"])
        self.d.starten()
        self.assertEqual(self.ue.phase, "warte_stille")
        self.bis(lambda: self.ue.phase == "uebernommen", 5)
        self.assertIn(("192.168.1.199", 32, "eth0"), self.netz.adressen)
        self.assertEqual(self.netz.tabellen, {("ip", "gb2_sv_probe"), ("arp", "gb2_sv_probe_arp")})
        self.assertNotIn(("192.168.1.110", 32, "eth0"), self.netz.adressen)
        self.assertFalse(self.fabrik.gebunden(("0.0.0.0", 32414)))
        self.assertFalse(Path(self.cfg["stellvertretung"]["status"]).exists())
        zustand = Path(self.cfg["stellvertretung"]["zustand"]).with_name("uebernahme-probe.json")
        self.assertEqual(json.loads(zustand.read_text())["hosts"]["probe"]["phase"], "uebernommen")
        self.assertFalse(Path(self.cfg["stellvertretung"]["zustand"]).exists())
        self.ue.eth.eingang.append(eingehend(ether(ipv4_tcp(src="192.168.1.110", dst="192.168.1.199", port=22))))
        self.d.schritt()
        self.assertEqual([m for _, m in self.wols], ["02:00:00:00:00:99"])
        self.assertEqual(self.zeilen(entscheidung="wecken")[0]["host"], "probe")

    def test_probe_endet_nach_sekunden(self):
        self.dienst(probe=30)
        with mock.patch.object(self.d, "starten", wraps=self.d.starten):
            self.d.laufen()
        self.assertEqual(self.ue.phase, "frei")
        self.assertGreaterEqual(self.t, 1030)
        self.assertLess(self.t, 1032)
        self.d.beenden("probe_ende")
        self.assertEqual(self.netz.tabellen, set())
        self.assertNotIn(("192.168.1.199", 32, "eth0"), self.netz.adressen)
        self.assertTrue(all(t > 0 for t in self.timeouts[1:]))

    def test_probe_exitcode_bei_unvollstaendiger_freigabe(self):
        class Fake:
            def __init__(self, *args, **kwargs):
                self.uebernahmen = {"probe": types.SimpleNamespace(alias=True, nft=True)}

            def laufen(self):
                pass

            def beenden(self, grund):
                pass
        path = Path(self.tmp.name) / "sv.json"
        path.write_text(json.dumps(self.cfg))
        with mock.patch.object(sv_mod, "Dienst", Fake), mock.patch.object(sv_mod.signal, "signal"), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sv_mod.main(["--probe", "10", "--config", str(path)]), 1)
            Fake.__init__ = lambda inner, *a, **k: setattr(inner, "uebernahmen", {
                "probe": types.SimpleNamespace(alias=False, nft=False)})
            self.assertEqual(sv_mod.main(["--probe", "10", "--config", str(path)]), 0)

    def test_probe_ohne_konfig(self):
        del self.cfg["stellvertretung"]["probe"]
        with self.assertRaisesRegex(ValueError, "probe_fehlt"):
            self.dienst(probe=30)


class AufraeumenTests(DienstBasis):
    def absturz(self):
        """Dienst und Probe übernehmen, dann ohne beenden() verschwinden (SIGKILL)."""
        self.uebernommen()
        self.u = ue.Umgebung(runner=self.netz, uhr=lambda: self.t, wanduhr=lambda: 1.7e9 + self.t,
                             sockets=self.fabrik, lesen=self.lesen, protokoll=self.log.append, wol=self.wol,
                             boot_id=lambda: BOOT)
        self.dienst(probe=600)
        self.d.starten()
        self.bis(lambda: self.ue.phase == "uebernommen", 5)
        self.assertEqual(len(self.netz.tabellen), 4)

    def test_nach_absturz_alles_entfernt_und_idempotent(self):
        self.absturz()
        self.netz.befehle.clear()
        ergebnis = ue.aufraeumen(self.cfg, self.netz, laeuft=lambda pid, eigene: False)
        self.assertEqual(ergebnis["fehler"], [])
        self.assertEqual(sorted(ergebnis["entfernt"]), ["alias:probe", "alias:vhost01", "nft:probe", "nft:vhost01"])
        self.assertEqual(self.netz.tabellen, set())
        self.assertEqual(self.netz.adressen, [("192.168.1.100", 24, "eth0")])
        zustand = Path(self.cfg["stellvertretung"]["zustand"])
        self.assertFalse(zustand.exists())
        self.assertFalse(zustand.with_name("uebernahme-probe.json").exists())
        self.netz.befehle.clear()
        ergebnis = ue.aufraeumen(self.cfg, self.netz)
        self.assertEqual((ergebnis["fehler"], ergebnis["entfernt"]), ([], []))
        self.assertFalse(any(b[:3] == ["ip", "addr", "del"] or b[:2] == ["nft", "delete"] for b in self.netz.befehle))

    def test_ohne_zustandsdatei_aus_konfig(self):
        self.netz.adressen.append((ALIAS, 32, "eth0"))
        self.netz.tabellen.update({("ip", "gb2_sv_vhost01"), ("arp", "gb2_sv_vhost01_arp"), ("ip", "fremd")})
        ergebnis = ue.aufraeumen(self.cfg, self.netz)
        self.assertEqual(ergebnis["fehler"], [])
        self.assertEqual(self.netz.tabellen, {("ip", "fremd")})
        self.assertNotIn((ALIAS, 32, "eth0"), self.netz.adressen)

    def test_zustand_kennt_alte_ip_und_sperren_gelten(self):
        path = Path(self.cfg["stellvertretung"]["zustand"])
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"version": 1, "hosts": {
            "vhost01": {"ip": "192.168.1.111", "interface": "eth0", "alias": True, "nft": True},
            "fremd1": {"ip": "192.168.1.100", "interface": "eth0", "alias": True, "nft": False},
            "fremd2": {"ip": "192.168.1.1", "interface": "eth0", "alias": True, "nft": False},
            "kaputt": {"ip": "192.168.1.112", "interface": "eth0;x", "alias": True, "nft": False}}}))
        self.netz.adressen += [("192.168.1.111", 32, "eth0"), (ALIAS, 24, "eth0"), ("192.168.1.1", 32, "eth0"),
                               ("192.168.1.112", 32, "eth0")]
        ergebnis = ue.aufraeumen(self.cfg, self.netz)
        self.assertNotIn(("192.168.1.111", 32, "eth0"), self.netz.adressen)
        # Gesperrte Adressen, fremde Präfixe und ungültige Interfaces bleiben unberührt.
        for row in (("192.168.1.100", 24, "eth0"), (ALIAS, 24, "eth0"), ("192.168.1.1", 32, "eth0"),
                    ("192.168.1.112", 32, "eth0")):
            self.assertIn(row, self.netz.adressen)
        self.assertIn("alias_gesperrt:fremd1", ergebnis["uebersprungen"])
        self.assertIn("alias_gesperrt:fremd2", ergebnis["uebersprungen"])
        self.assertIn("alias_gesperrt:kaputt", ergebnis["uebersprungen"])
        self.assertFalse(path.exists())

    def test_alias_bleibt_dann_bleibt_tabelle_und_zustand(self):
        self.absturz()
        self.netz.stoerung[("ip", "addr", "del")] = "stumm"
        ergebnis = ue.aufraeumen(self.cfg, self.netz, nur={"vhost01"})
        self.assertEqual(sorted(ergebnis["fehler"]), ["alias:vhost01", "nft_bleibt:vhost01"])
        self.assertIn(("ip", "gb2_sv_vhost01"), self.netz.tabellen)
        self.assertTrue(Path(self.cfg["stellvertretung"]["zustand"]).exists())
        # nur={"vhost01"} lässt die Probe unangetastet.
        self.assertIn(("ip", "gb2_sv_probe"), self.netz.tabellen)

    def test_laufende_probe_wird_ausgelassen(self):
        self.absturz()
        gefragt = []
        ergebnis = ue.aufraeumen(self.cfg, self.netz,
                                 laeuft=lambda pid, eigene: gefragt.append(pid) or True)
        self.assertEqual(gefragt, [4242])
        self.assertIn("probe_laeuft", ergebnis["uebersprungen"])
        self.assertIn(("ip", "gb2_sv_probe"), self.netz.tabellen)
        self.assertNotIn(("ip", "gb2_sv_vhost01"), self.netz.tabellen)
        self.assertTrue(Path(self.cfg["stellvertretung"]["zustand"]).with_name("uebernahme-probe.json").exists())
        self.assertFalse(ue.probe_laeuft(os.getpid(), os.getpid()))
        self.assertFalse(ue.probe_laeuft("123"))

    def test_unlesbarer_probezustand_wird_nicht_angefasst(self):
        self.absturz()
        probe = Path(self.cfg["stellvertretung"]["zustand"]).with_name("uebernahme-probe.json")
        probe.write_text("{nicht lesbar")
        ergebnis = ue.aufraeumen(self.cfg, self.netz, laeuft=lambda pid, eigene: False)
        self.assertIn("probe_unklar", ergebnis["uebersprungen"])
        self.assertIn(("ip", "gb2_sv_probe"), self.netz.tabellen)
        self.assertIn(("192.168.1.199", 32, "eth0"), self.netz.adressen)
        self.assertTrue(probe.exists())
        self.assertNotIn(("ip", "gb2_sv_vhost01"), self.netz.tabellen)

    def test_altlast_phantom_und_unlesbarer_zustand(self):
        phantom = Path(self.tmp.name) / "phantom.json"
        phantom.write_text(json.dumps({"ip": "192.168.1.199", "interface": "eth0", "alias": True, "tabelle": True}))
        self.cfg["arp_state"] = str(phantom)
        path = Path(self.cfg["stellvertretung"]["zustand"])
        path.parent.mkdir(parents=True)
        path.write_text("{kaputt")
        self.netz.adressen.append(("192.168.1.199", 32, "eth0"))
        self.netz.tabellen.update({("ip", "gb2_phantom"), ("ip", "gb2_sv_vhost01")})
        ergebnis = ue.aufraeumen(self.cfg, self.netz)
        self.assertEqual(ergebnis["fehler"], [])
        self.assertEqual(self.netz.tabellen, set())
        self.assertNotIn(("192.168.1.199", 32, "eth0"), self.netz.adressen)
        self.assertIn("zustand_unlesbar:dienst", ergebnis["uebersprungen"])
        self.assertFalse(phantom.exists())

    def test_ohne_nft_kein_fehler_und_ohne_ip_fehler(self):
        self.netz.stoerung[("nft",)] = "fehlt"
        self.assertEqual(ue.aufraeumen(self.cfg, self.netz)["fehler"], [])
        self.netz.stoerung = {("ip",): "rc"}
        self.assertEqual(ue.aufraeumen(self.cfg, self.netz)["fehler"], ["adressen_unklar"])
        self.assertEqual(ue.aufraeumen({}, self.netz)["fehler"], [])


class KommandozeileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "sv.json"
        self.path.write_text(json.dumps(BEISPIEL))

    def aufruf(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sv_mod.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_aufraeumen_ohne_sockets(self):
        with mock.patch.object(sv_mod, "aufraeumen", return_value={"entfernt": [], "fehler": [],
                                                                    "uebersprungen": []}) as cleanup, \
                mock.patch.object(sv_mod.socket, "socket") as sock, \
                mock.patch.object(sv_mod, "Dienst") as dienst:
            code, out, _ = self.aufruf("--aufraeumen", "--config", str(self.path))
            self.assertEqual(code, 0)
            self.assertEqual(cleanup.call_args.args[0]["stellvertretung"]["hosts"]["vhost01"]["ip"], ALIAS)
            self.assertEqual(json.loads(out)["fehler"], [])
            cleanup.return_value = {"entfernt": [], "fehler": ["alias:vhost01"], "uebersprungen": []}
            self.assertEqual(self.aufruf("--aufraeumen", "--config", str(self.path) + ".fehlt")[0], 1)
            self.assertEqual(cleanup.call_args.args[0], {})
            sock.assert_not_called()
            dienst.assert_not_called()

    def test_probe_sekunden_grenzen(self):
        with mock.patch.object(sv_mod, "Dienst") as dienst, mock.patch.object(sv_mod.signal, "signal"):
            for wert in ("0", "901", "-5"):
                with self.subTest(wert=wert):
                    self.assertEqual(self.aufruf("--probe", wert, "--config", str(self.path))[0], 2)
            dienst.assert_not_called()

    def test_signal_im_finalizer_beendet_den_dienst(self):
        # Netztest 12.10.26: SIGTERM während Popen.__del__ -> das SystemExit des Handlers wurde verschluckt
        # ("Exception ignored while calling deallocator"), der Dienst lief weiter bis zum SIGKILL.
        handler, dienste = {}, []

        class Fake:
            def __init__(inner, *args, **kwargs):
                inner.uebernahmen, inner.stopp, inner.runden, inner.grund = {}, False, 0, None
                dienste.append(inner)

            def laufen(inner):
                class Finalizer:
                    def __del__(self):
                        handler[inner.signal](inner.signal, None)
                Finalizer()
                while not inner.stopp and inner.runden < 5:
                    inner.runden += 1

            def beenden(inner, grund):
                inner.grund = grund
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum):
                Fake.signal = signum
                with mock.patch.object(sv_mod, "Dienst", Fake), \
                        mock.patch.object(sv_mod.signal, "signal", side_effect=handler.__setitem__):
                    code, _, err = self.aufruf("--config", str(self.path))
                self.assertEqual(code, 0)
                self.assertNotIn("Exception ignored", err)
                self.assertEqual((dienste[-1].stopp, dienste[-1].runden, dienste[-1].grund), (True, 0, "dienst_ende"))

    def test_probe_ohne_gueltige_stellvertretung(self):
        cfg = copy.deepcopy(BEISPIEL)
        cfg["log"] = str(Path(self.tmp.name) / "log.jsonl")
        cfg["stellvertretung"]["limits"] = {}
        self.path.write_text(json.dumps(cfg))
        with mock.patch.object(sv_mod.signal, "signal"):
            code, _, err = self.aufruf("--probe", "60", "--config", str(self.path))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(err)["fehler"], "stellvertretung_limits")


# ---------------------------------------------------------------- Netztest im Wegwerf-Namensraum (Plan 7, opt-in)

import signal
import sys
import threading
import time

LAN_HILFE = r'''
import json, socket, struct, sys, time
def mac(t): return bytes.fromhex(t.replace(":", ""))
def arp(op, sha, spa, tpa, dst="ff:ff:ff:ff:ff:ff"):
    return (mac(dst) + mac(sha) + b"\x08\x06" + struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, mac(sha),
            socket.inet_aton(spa), b"\x00" * 6, socket.inet_aton(tpa)))
def roh():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)); s.bind(("vh0", 0)); s.settimeout(0.05)
    return s
def lauschen(s, sekunden):
    ende, out = time.time() + sekunden, []
    while time.time() < ende:
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            continue
        if addr[2] != socket.PACKET_OUTGOING:
            out.append(data)
    return out
def arp_antworten(frames, ip):
    return [f[6:12].hex(":") for f in frames if f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02"
            and socket.inet_ntoa(f[28:32]) == ip]
'''


@unittest.skipUnless(os.environ.get("GB_NETNS_INNEN") == "1", "läuft nur im Wegwerf-Namensraum (GB_NETNS=1)")
class NetzInnenTests(unittest.TestCase):
    """Echter Kernel: veth eth0 (proxy01) <-> vh0 im Namensraum lan (LAN-Client .18 und WAN-Client)."""

    @classmethod
    def setUpClass(cls):
        def sh(*args):
            subprocess.run(args, check=True, capture_output=True, text=True)
        sh("mount", "-t", "tmpfs", "tmpfs", "/run")
        Path("/run/netns").mkdir()
        sh("mount", "-t", "sysfs", "sysfs", "/sys")
        sh("ip", "link", "set", "lo", "up")
        sh("ip", "link", "add", "eth0", "address", EIGEN, "type", "veth", "peer", "name", "vh0")
        sh("ip", "netns", "add", "lan")
        sh("ip", "link", "set", "vh0", "netns", "lan")
        sh("ip", "addr", "add", "192.168.1.100/24", "dev", "eth0")
        sh("ip", "link", "set", "eth0", "up")
        sh("ip", "route", "add", "198.51.100.0/24", "dev", "eth0")
        for scope in ("all", "eth0"):
            Path("/proc/sys/net/ipv4/conf/%s/arp_ignore" % scope).write_text("1")
            Path("/proc/sys/net/ipv4/conf/%s/arp_announce" % scope).write_text("2")
        sh("nsenter", "--net=/run/netns/lan", "sh", "-c",
           "ip link set lo up && ip addr add 192.168.1.18/24 dev vh0 && ip addr add 198.51.100.9/24 dev vh0 "
           "&& ip link set vh0 up")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        cfg = beispiel(register=str(base / "register.json"), status=str(base / "status.json"),
                       zustand=str(base / "sv/uebernahme.json"), vpn_interface="", stille_s=1)
        cfg.update(plex_hash="abc123", log=str(base / "log.jsonl"), aus=str(base / "aus"))
        self.cfg_path = base / "sv.json"
        self.cfg_path.write_text(json.dumps(cfg))
        self.cfg = cfg
        self.dienst = None
        self.addCleanup(self.aufraeumen)

    def aufraeumen(self):
        if self.dienst:
            if self.dienst.poll() is None:
                self.dienst.kill()
                self.dienst.wait()
            self.dienst.stdout.close()
            self.dienst.stderr.close()
        self.cli("--aufraeumen")

    def cli(self, *args, **kwargs):
        code = "import sys; sys.path.insert(0, %r); from greenbuddy2.stellvertreter import main; " \
               "sys.exit(main(sys.argv[1:]))" % str(ROOT)
        return subprocess.Popen([sys.executable, "-I", "-c", code, "--config", str(self.cfg_path)] + list(args),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs) \
            if kwargs.pop("hintergrund", False) else subprocess.run(
                [sys.executable, "-I", "-c", code, "--config", str(self.cfg_path)] + list(args),
                capture_output=True, text=True, timeout=60)

    def lan(self, code, timeout=20):
        run = subprocess.run(["nsenter", "--net=/run/netns/lan", sys.executable, "-I", "-c", LAN_HILFE + code],
                             capture_output=True, text=True, timeout=timeout)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout.strip().splitlines()[-1])

    def register(self, lease):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        jetzt = time.clock_gettime(time.CLOCK_BOOTTIME)
        Path(self.cfg["stellvertretung"]["register"]).write_text(json.dumps({"version": 1, "hosts": {"vhost01": {
            "zyklus": "netz1", "phase": "schlaf_absicht", "ablauf": time.time() + lease, "nachfrage": 0,
            "beginn": time.time(), "ablauf_boot": jetzt + lease, "boot_id": boot}}}))

    def warten(self, bedingung, sekunden=10):
        ende = time.time() + sekunden
        while time.time() < ende:
            if bedingung():
                return
            time.sleep(0.05)
        self.fail("Zeit abgelaufen; Log: %s" % self.log()[-5:])

    def log(self):
        path = Path(self.cfg["log"])
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def phase(self):
        try:
            return json.loads(Path(self.cfg["stellvertretung"]["status"]).read_text())["phasen"]["vhost01"]
        except (OSError, ValueError, KeyError):
            return None

    def alias_da(self, ip=ALIAS):
        sock = socket.socket()
        try:
            sock.bind((ip, 0))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def starten(self, lease=600):
        self.register(lease)
        self.dienst = self.cli(hintergrund=True)
        self.warten(lambda: self.phase() == "uebernommen")
        self.assertTrue(self.alias_da())
        self.assertEqual({t for t in ue.nft_tabellen(subprocess.run)} & {("ip", "gb2_sv_vhost01"),
                                                                       ("arp", "gb2_sv_vhost01_arp")},
                         {("ip", "gb2_sv_vhost01"), ("arp", "gb2_sv_vhost01_arp")})

    def test_isolation_syn_wecken_sni_und_freigabe_unter_100ms(self):
        fremd = socket.socket()
        fremd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        fremd.bind(("0.0.0.0", 2222))
        fremd.listen(4)
        self.addCleanup(fremd.close)
        self.starten()
        ergebnis = self.lan(r'''
s = roh()
s.send(arp(1, "02:00:00:00:00:42", "192.168.1.18", "192.168.1.110"))
antworten = arp_antworten(lauschen(s, 0.5), "192.168.1.110")
def verbinden(ziel, quelle=None, nutzlast=None):
    c = socket.socket(); c.settimeout(1.5)
    if quelle: c.bind((quelle, 0))
    try:
        c.connect(ziel)
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "rst"
    if nutzlast is None:
        return "verbunden"
    c.sendall(bytes.fromhex(nutzlast))
    try:
        return "daten:" + repr(c.recv(10))
    except ConnectionResetError:
        return "rst_nach_daten"
    except socket.timeout:
        return "keine_antwort"
wol = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); wol.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
wol.bind(("0.0.0.0", 9)); wol.settimeout(3)
out = {"arp": antworten,
       "fremder_dienst": verbinden(("192.168.1.110", 2222)),
       "eigene_adresse": verbinden(("192.168.1.100", 2222)),
       "ssh_syn": verbinden(("192.168.1.110", 22))}
try:
    out["magic"] = wol.recv(200).hex()
except socket.timeout:
    out["magic"] = None
out["sni"] = verbinden(("192.168.1.110", 32400), "198.51.100.9", "HELLO_HEX")
print(json.dumps(out))
'''.replace("HELLO_HEX", clienthello("192-168-1-110.abc123.plex.direct").hex()))
        self.assertEqual(ergebnis["arp"], [EIGEN])
        # Isolation: proxy01-Dienste antworten nie unter der Host-IP (DROP, kein RST).
        self.assertEqual(ergebnis["fremder_dienst"], "timeout")
        self.assertEqual(ergebnis["eigene_adresse"], "verbunden")
        self.assertEqual(ergebnis["ssh_syn"], "timeout")
        self.assertEqual(ergebnis["magic"], ("ff" * 6) + ECHT.replace(":", "") * 16)
        self.assertEqual(ergebnis["sni"], "rst_nach_daten")
        self.warten(lambda: self.phase() == "wecken")
        zeile = [r for r in self.log() if r.get("entscheidung") == "wecken"][0]
        self.assertEqual((zeile["quell_ip"], zeile["port"], zeile["quellklasse"]), ("192.168.1.18", 22, "LAN"))
        # Freigabe: Alias weg < 100 ms nach dem ersten Frame der echten MAC.
        weg = []

        def beobachten():
            ende = time.time() + 5
            while time.time() < ende:
                if not self.alias_da():
                    weg.append(time.time())
                    return
        faden = threading.Thread(target=beobachten)
        faden.start()
        gesendet = self.lan(r'''
s = roh(); time.sleep(0.3)
t = time.time(); s.send(arp(1, "%s", "192.168.1.110", "192.168.1.110")); print(json.dumps(t))
''' % ECHT)
        faden.join()
        self.assertTrue(weg)
        self.assertLess(weg[0] - gesendet, 0.1)
        self.warten(lambda: self.phase() == "frei")
        self.assertEqual(ue.nft_tabellen(subprocess.run) & {("ip", "gb2_sv_vhost01"), ("arp", "gb2_sv_vhost01_arp")},
                         set())
        freigabe = [r for r in self.log() if r.get("ereignis") == "phase" and r.get("nach") == "frei"][-1]
        self.assertEqual(freigabe["grund"], "echte_mac")

    def test_keine_arp_antwort_auf_proben_der_echten_mac(self):
        self.starten()
        # Dienst anhalten: nur die nft-ARP-Tabelle entscheidet, ob proxy01s Kernel antwortet.
        self.dienst.send_signal(signal.SIGSTOP)
        try:
            ergebnis = self.lan(r'''
s = roh()
s.send(arp(1, "%s", "0.0.0.0", "192.168.1.110"))
echt = arp_antworten(lauschen(s, 0.5), "192.168.1.110")
s.send(arp(1, "02:00:00:00:00:42", "192.168.1.18", "192.168.1.110"))
fremd = arp_antworten(lauschen(s, 0.5), "192.168.1.110")
print(json.dumps({"echt": echt, "fremd": fremd}))
''' % ECHT)
        finally:
            self.dienst.send_signal(signal.SIGCONT)
        self.assertEqual(ergebnis, {"echt": [], "fremd": [EIGEN]})
        # Der gepufferte Frame der echten MAC gibt nach dem Fortsetzen sofort frei.
        self.warten(lambda: not self.alias_da(), 3)

    def test_lease_ablauf_gibt_frei_und_sendet_wol(self):
        self.starten(lease=5)
        ergebnis = self.lan(r'''
wol = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); wol.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
wol.bind(("0.0.0.0", 9)); wol.settimeout(8)
print(json.dumps(wol.recv(200).hex()))
''')
        self.assertEqual(ergebnis, ("ff" * 6) + ECHT.replace(":", "") * 16)
        self.warten(lambda: not self.alias_da(), 3)
        self.assertEqual([r["grund"] for r in self.log() if r.get("ereignis") == "phase" and r.get("nach") == "frei"],
                         ["lease_abgelaufen"])

    def test_aufraeumen_nach_sigkill(self):
        self.starten()
        self.dienst.kill()
        self.dienst.wait()
        self.assertTrue(self.alias_da())
        run = self.cli("--aufraeumen")
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(sorted(json.loads(run.stdout)["entfernt"]), ["alias:vhost01", "nft:vhost01"])
        self.assertFalse(self.alias_da())
        self.assertEqual(ue.nft_tabellen(subprocess.run), set())
        run = self.cli("--aufraeumen")
        self.assertEqual((run.returncode, json.loads(run.stdout)["entfernt"]), (0, []))

    def test_probe_modus_ende_raeumt_auf(self):
        probe = self.cli("--probe", "4", hintergrund=True)
        self.dienst = probe
        self.warten(lambda: self.alias_da("192.168.1.199"), 6)
        self.assertEqual(ue.nft_tabellen(subprocess.run), {("ip", "gb2_sv_probe"), ("arp", "gb2_sv_probe_arp")})
        self.assertEqual(probe.wait(timeout=10), 0)
        self.assertFalse(self.alias_da("192.168.1.199"))
        self.assertEqual(ue.nft_tabellen(subprocess.run), set())
        self.assertIn('"grund": "probe_ende"', probe.stdout.read())


class NetzNamensraumTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("GB_NETNS") == "1", "opt-in: GB_NETNS=1 (unshare -Urnm, veth, nft)")
    def test_wegwerf_namensraum(self):
        env = dict(os.environ, GB_NETNS_INNEN="1", PYTHONPATH="%s:%s" % (ROOT, ROOT / "tests"))
        run = subprocess.run(["unshare", "-Urnm", sys.executable, "-m", "unittest", "-v",
                              "test_stellvertretung.NetzInnenTests"],
                             cwd=str(ROOT / "tests"), env=env, capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stderr[-4000:])
        self.assertEqual(run.stderr.count(" ... ok"), 5, run.stderr[-4000:])
