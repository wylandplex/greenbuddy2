"""b6 "Wachseite filtert Spam": Legitim-Datei zwischen gb-mitschnitt (schreibt) und gb-schlaf (liest).

Live-Befund 13.10.26: Scanner auf 32400 (bis 46 Veto-Runden ohne Plex-Sitzung) und auf 8880
(18 Runden) sowie eine stündliche Haarnadel-Verbindung von der eigenen WAN-Adresse hielten vhost01 im
Tagschlaffenster wach. Nur synthetische Daten aus Doku-Netzen; alle Hostbefehle über den Fake-Runner.
"""

import json
import os
import signal
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from greenbuddy2 import fakten_vhost as f, legitim, mitschnitt
from greenbuddy2.konfig import SCHLAF
from greenbuddy2.pcap import tcp_packet
from fixtures import MDSTAT, clienthello, ethernet, minecraft, pcap
from test_verbraucher import Host, LAUSCHEND, konto

JETZT = 1000
SCANNER = "198.51.100.7"
APP = "203.0.113.5"
EIGENE = "203.0.113.1"


def zeile(lokal, peer):
    return "0 0 %s %s\n" % (lokal, peer)


class SchlafseiteTests(unittest.TestCase):
    """gb-schlaf: WAN-Gegenstellen zählen nur, wenn sie legitim sind (R1, R3, R5, R6)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pfad = Path(self.tmp.name) / "legitim" / "vhost01.json"
        self.pfad.parent.mkdir()

    def datei(self, quellen=None, zeit=JETZT, ttl=3600, eigene=None, roh=None, letztes=None):
        if roh is None:
            data = {"version": 1, "zeit": zeit, "ttl_s": ttl, "quellen": quellen or {},
                    "letztes_paket": zeit if letztes is None else letztes}
            if eigene is not None:
                data["eigene_wan_ip"] = eigene
            roh = json.dumps(data)
        self.pfad.write_text(roh)
        self.pfad.chmod(0o600)

    def sammeln(self, host, besitzer=None, **cfg):
        cfg = dict(SCHLAF, ansprueche="/nicht/vorhanden", raid_degradiert_erlaubt=True, legitim=str(self.pfad),
                   **cfg)
        with mock.patch.object(f, "jellyfin", return_value=(False, None)), \
                mock.patch.object(Path, "read_text", return_value=MDSTAT), \
                mock.patch.object(f.ET, "parse", side_effect=ValueError("Test")), \
                mock.patch.object(f.pwd, "getpwnam", side_effect=konto):
            uids = {os.getuid()} if besitzer is None else None if besitzer == "standard" else besitzer
            sammler = f.Sammler(cfg, runner=host, proc=lambda: [["mdmon", "md127"]], besitzer=uids)
            return sammler.sammeln(JETZT)

    def host(self, *verbindungen, lauschend=LAUSCHEND):
        host = Host()
        host.lauschend = lauschend
        host.verbindungen = "".join(zeile(*v) for v in verbindungen)
        return host

    # Pflicht: Scanner ohne Legitim-Eintrag
    def test_scanner_auf_32400_ohne_eintrag_kein_veto(self):
        self.datei()
        data = self.sammeln(self.host(("[::ffff:192.168.1.110]:32400", "[::ffff:%s]:50000" % SCANNER)))
        self.assertNotIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["legitim"], "ok")
        self.assertEqual(data["fakten"]["verbindungen"][32400], 0)
        self.assertEqual(data["fakten"]["verbindungen_wan_ignoriert"], {32400: 1})
        self.assertNotIn("verbindungen_unklar", data["unklar"])
        # Das Schlaflog bekommt Zähler, nie Adressen.
        self.assertNotIn(SCANNER, json.dumps(data))

    def test_legitime_wan_ip_ist_veto(self):
        self.datei({APP: JETZT - 10})
        data = self.sammeln(self.host(("192.168.1.110:32400", "%s:50000" % APP)))
        self.assertIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen"][32400], 1)
        self.assertEqual(data["fakten"]["verbindungen_wan_ignoriert"], {})

    def test_legitime_ip_zaehlt_auf_allen_ports(self):
        # Eine Plex-App-IP ist ein echter Mensch: auch ihr Webhook-/SSH-Zugriff zählt.
        self.datei({APP: JETZT - 10})
        data = self.sammeln(self.host(("192.168.1.110:8443", "%s:50000" % APP),
                                      ("192.168.1.110:22", "%s:50001" % APP)))
        self.assertIn("verbindung:8443", data["vetos"])
        self.assertIn("verbindung:22", data["vetos"])

    def test_lan_und_vpn_wie_bisher(self):
        self.datei()
        data = self.sammeln(self.host(("192.168.1.110:445", "192.168.1.20:50123"),
                                      ("[::ffff:192.168.1.110]:32400", "[::ffff:10.0.0.2]:40000"),
                                      ("192.168.1.110:9090", "10.0.0.3:40001")))
        for port in (445, 32400, 9090):
            self.assertIn("verbindung:%d" % port, data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_wan_ignoriert"], {})

    def test_lan_vpn_netze_aus_der_konfig(self):
        self.datei()
        host = self.host(("192.168.1.110:445", "%s:50123" % SCANNER))
        self.assertNotIn("verbindung:445", self.sammeln(host)["vetos"])
        self.assertIn("verbindung:445", self.sammeln(host, vpn=["198.51.100.0/24"])["vetos"])

    def test_nicht_oeffentliche_und_ipv6_gegenstellen_zaehlen_wie_bisher(self):
        # Container-Netze, CGNAT und Link-local kommen nie über die Portweiterleitung; der Mitschnitt
        # sieht nur IPv4, eine IPv6-Gegenstelle kann darum nie legitim werden und bleibt beim b5-Verhalten.
        self.datei()
        data = self.sammeln(self.host(("192.168.1.110:9090", "172.17.0.2:40000"),
                                      ("192.168.1.110:8081", "100.64.0.9:40001"),
                                      ("[2001:db8::10]:445", "[2001:db8::99]:40002")))
        for port in (9090, 8081, 445):
            self.assertIn("verbindung:%d" % port, data["vetos"])

    # Pflicht: R6, Caddy lauscht dual-stack
    def test_gemappte_wan_gegenstelle_auf_8880_kein_veto(self):
        self.datei()
        lauschend = LAUSCHEND + "LISTEN 0      4096               *:8880        *:*\n"
        data = self.sammeln(self.host(("[::ffff:192.168.1.110]:8880", "[::ffff:%s]:40000" % SCANNER),
                                      lauschend=lauschend))
        self.assertNotIn("verbindung:8880", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_wan_ignoriert"], {8880: 1})
        data = self.sammeln(self.host(("[::ffff:192.168.1.110]:8880", "[::ffff:192.168.1.20]:40000"),
                                      lauschend=lauschend))
        self.assertIn("verbindung:8880", data["vetos"])

    # Pflicht: R5
    def test_haarnadel_kein_veto(self):
        self.datei({EIGENE: JETZT - 5}, eigene=[EIGENE])
        data = self.sammeln(self.host(("[::ffff:192.168.1.110]:32400", "[::ffff:%s]:50000" % EIGENE)))
        self.assertNotIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_haarnadel"], {32400: 1})
        self.assertEqual(data["fakten"]["verbindungen_wan_ignoriert"], {})

    def test_ohne_eigene_wan_ip_keine_haarnadel_ausnahme(self):
        self.datei({EIGENE: JETZT - 5})
        data = self.sammeln(self.host(("192.168.1.110:32400", "%s:50000" % EIGENE)))
        self.assertIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_haarnadel"], {})

    # Pflicht: Allowlist (R1)
    def test_allowlist_nur_auf_ihrem_port(self):
        self.datei()
        threema = "203.0.113.10"
        host = self.host(("192.168.1.110:8443", "%s:40000" % threema))
        data = self.sammeln(host, legitim_quellen={"8443": [threema]})
        self.assertIn("verbindung:8443", data["vetos"])
        host = self.host(("192.168.1.110:32400", "%s:40000" % threema))
        data = self.sammeln(host, legitim_quellen={"8443": [threema]})
        self.assertNotIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_wan_ignoriert"], {32400: 1})

    # Pflicht: TTL
    def test_abgelaufener_eintrag_nicht_legitim(self):
        host = self.host(("192.168.1.110:32400", "%s:50000" % APP))
        self.datei({APP: JETZT - 3601}, ttl=3600)
        self.assertNotIn("verbindung:32400", self.sammeln(host)["vetos"])
        self.datei({APP: JETZT - 3600}, ttl=3600)
        self.assertIn("verbindung:32400", self.sammeln(host)["vetos"])
        self.datei({APP: JETZT - 100}, ttl=60)
        self.assertNotIn("verbindung:32400", self.sammeln(host)["vetos"])

    # Pflicht: R4 – jeder Zweifel an der Datei = beta.5-Verhalten samt Diagnose, nie unklar
    def rueckfall(self, erwartet, **cfg):
        data = self.sammeln(self.host(("[::ffff:192.168.1.110]:32400", "[::ffff:%s]:50000" % SCANNER)), **cfg)
        self.assertIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["legitim"], erwartet)
        self.assertEqual(data["fakten"]["verbindungen"][32400], 1)
        self.assertEqual(data["fakten"]["verbindungen_wan_ignoriert"], {})
        self.assertNotIn("verbindungen_unklar", data["unklar"])
        self.assertFalse([x for x in data["unklar"] if "legitim" in x], data["unklar"])
        return data

    def test_datei_fehlt(self):
        self.rueckfall("fehlt")
        self.pfad.parent.rmdir()
        self.rueckfall("fehlt")

    def test_datei_veraltet(self):
        self.datei(zeit=JETZT - 181)
        self.rueckfall("veraltet")
        self.datei(zeit=JETZT - 100)
        self.rueckfall("veraltet", legitim_max_alter_s=60)
        self.datei(zeit=JETZT - 180)
        self.assertEqual(self.sammeln(self.host())["fakten"]["legitim"], "ok")

    def test_datei_aus_der_zukunft(self):
        self.datei(zeit=JETZT + 61)
        self.rueckfall("zukunft")
        # Der Mitschnitt darf während der laufenden Runde schreiben.
        self.datei(zeit=JETZT + 30)
        self.assertEqual(self.sammeln(self.host())["fakten"]["legitim"], "ok")

    def test_datei_kaputt_oder_schemawidrig(self):
        gut = {"version": 1, "zeit": JETZT, "ttl_s": 3600, "quellen": {}, "letztes_paket": JETZT}
        for roh in ("", "{", "[]", "null", json.dumps(dict(gut, version=2)), json.dumps(dict(gut, version=True)),
                    json.dumps(dict(gut, zeit="1000")), json.dumps(dict(gut, zeit=True)),
                    '{"version": 1, "zeit": NaN, "ttl_s": 3600, "quellen": {}, "letztes_paket": 1000}',
                    json.dumps({k: v for k, v in gut.items() if k != "letztes_paket"}),
                    json.dumps(dict(gut, letztes_paket=JETZT + 1)), json.dumps(dict(gut, letztes_paket="1000")),
                    json.dumps(dict(gut, letztes_paket=None)),
                    json.dumps(dict(gut, ttl_s=0)), json.dumps(dict(gut, ttl_s=-5)),
                    json.dumps(dict(gut, quellen=[SCANNER])), json.dumps(dict(gut, quellen={"kein": 1})),
                    json.dumps(dict(gut, quellen={"198.051.100.7": 900})),
                    json.dumps(dict(gut, quellen={"2001:db8::1": 900})),
                    json.dumps(dict(gut, quellen={SCANNER: "900"})),
                    json.dumps(dict(gut, quellen={SCANNER: JETZT + 1})),
                    json.dumps(dict(gut, eigene_wan_ip=EIGENE)), json.dumps(dict(gut, eigene_wan_ip=["x"])),
                    json.dumps(dict(gut, eigene_wan_ip=[EIGENE] * 17)),
                    json.dumps(dict(gut, unbekannt=1)),
                    json.dumps({k: v for k, v in gut.items() if k != "ttl_s"}),
                    json.dumps({k: v for k, v in gut.items() if k != "zeit"}),
                    json.dumps(gut) + " " * (1024 * 1024)):
            with self.subTest(roh=roh[:80]):
                self.datei(roh=roh)
                self.rueckfall("ungueltig")

    def test_symlink_ist_ungueltig(self):
        echt = self.pfad.parent / "echt.json"
        echt.write_text(json.dumps({"version": 1, "zeit": JETZT, "ttl_s": 3600, "quellen": {},
                                    "letztes_paket": JETZT}))
        echt.chmod(0o600)
        self.pfad.symlink_to(echt)
        self.rueckfall("ungueltig")

    def test_fremder_besitzer_oder_schreibbar_ist_ungueltig(self):
        self.datei()
        data = self.sammeln(self.host(("192.168.1.110:32400", "%s:50000" % SCANNER)), besitzer={os.getuid() + 1})
        self.assertEqual(data["fakten"]["legitim"], "ungueltig")
        self.assertIn("verbindung:32400", data["vetos"])
        for modus in (0o620, 0o602, 0o666):
            with self.subTest(modus=oct(modus)):
                self.pfad.chmod(modus)
                self.rueckfall("ungueltig")
        self.pfad.unlink()
        self.pfad.mkdir()
        self.rueckfall("ungueltig")

    def test_standardbesitzer_root_und_mitschnitt(self):
        from greenbuddy2 import legitim
        with mock.patch.object(legitim.pwd, "getpwnam", return_value=mock.Mock(pw_uid=987)):
            self.assertEqual(legitim.besitzer(), {0, 987})
        with mock.patch.object(legitim.pwd, "getpwnam", side_effect=KeyError("gb-mitschnitt")):
            self.assertEqual(legitim.besitzer(), {0})
        # Ohne ausdrückliche UIDs gilt die Standardliste: eine Datei des Testkontos ist fremd.
        self.datei()
        if os.getuid() != 0:
            self.assertEqual(self.sammeln(self.host(), besitzer="standard")["fakten"]["legitim"], "ungueltig")

    # Review 13.10.26: Eine frische Datei beweist nur, dass die Schleife läuft. Live kommen ~40 Scanner-Flüsse
    # je Minute auf 32400; erfasst der Mitschnitt nichts (falsches target), filtert gb-schlaf nicht.
    def test_mitschnitt_erfasst_nichts(self):
        self.datei(letztes=JETZT - 901)
        self.rueckfall("still")
        self.datei(letztes=JETZT - 100)
        self.rueckfall("still", legitim_stille_s=60)
        self.datei(letztes=JETZT - 900)
        self.assertEqual(self.sammeln(self.host())["fakten"]["legitim"], "ok")

    def test_schalter_wan_filter_aus(self):
        self.datei()
        self.rueckfall("aus", wan_filter=False)

    def test_ruhe_regel_gilt_weiter_fuer_legitime_verbindungen(self):
        from test_verbraucher import info
        self.datei({APP: JETZT - 10})
        verbindung = ("[::ffff:192.168.1.110]:32400", "[::ffff:%s]:9250" % APP)
        host = self.host(verbindung)
        host.info = info(*verbindung, lastrcv=21586543)
        cfg = dict(SCHLAF, ansprueche="/nicht/vorhanden", raid_degradiert_erlaubt=True, legitim=str(self.pfad))
        with mock.patch.object(f, "jellyfin", return_value=(False, None)), \
                mock.patch.object(Path, "read_text", return_value=MDSTAT), \
                mock.patch.object(f.ET, "parse", side_effect=ValueError("Test")), \
                mock.patch.object(f.pwd, "getpwnam", side_effect=konto):
            sammler = f.Sammler(cfg, runner=host, proc=lambda: [["mdmon", "md127"]], besitzer={os.getuid()})
            sammler.sammeln(JETZT - 60)
            data = sammler.sammeln(JETZT)
        self.assertNotIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_ruhend"], {32400: 1})

    def dauersammler(self, host, **cfg):
        """Ein Sammler über mehrere Runden wie im Dienst; die Datei wechselt zwischen den Runden."""
        cfg = dict(SCHLAF, ansprueche="/nicht/vorhanden", raid_degradiert_erlaubt=True, legitim=str(self.pfad),
                   **cfg)
        for ziel, name, kwargs in ((f, "jellyfin", {"return_value": (False, None)}),
                                   (Path, "read_text", {"return_value": MDSTAT}),
                                   (f.ET, "parse", {"side_effect": ValueError("Test")}),
                                   (f.pwd, "getpwnam", {"side_effect": konto})):
            patcher = mock.patch.object(ziel, name, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)
        return f.Sammler(cfg, runner=host, proc=lambda: [["mdmon", "md127"]], besitzer={os.getuid()})

    # Review 13.10.26: Legitimität hängt an der Verbindung, nicht an der TTL der Quell-IP
    def test_legitime_verbindung_zaehlt_bis_zu_ihrem_ende(self):
        from test_verbraucher import info
        verbindung = ("[::ffff:192.168.1.110]:32400", "[::ffff:%s]:9250" % APP)
        host = self.host(verbindung)
        sammler = self.dauersammler(host)

        def runde(minute, quellen, acked):
            now = JETZT + 60 * minute
            self.datei(quellen, zeit=now)
            host.info = info(*verbindung, lastrcv=60000 * minute, acked=acked)
            return sammler.sammeln(now)
        # Download über eine einzige Anfrage: Nach dem ClientHello sendet der Client nur ACKs, der
        # Mitschnitt sieht davon nichts (BPF nur SYN oder Nutzdaten) und frischt den Eintrag nie auf.
        self.assertIn("verbindung:32400", runde(0, {APP: JETZT}, 10 ** 6)["vetos"])
        # Neustart des Mitschnitts: die Datei beginnt leer, der Download läuft weiter.
        self.assertIn("verbindung:32400", runde(1, {}, 10 ** 8)["vetos"])
        # Länger als ttl_s: Der Eintrag ist verfallen, bytes_acked wächst weiter.
        data = runde(62, {}, 10 ** 10)
        self.assertIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_wan_ignoriert"], {})
        # Danach Leerlauf auf derselben Verbindung: die Ruhe-Regel gilt unverändert.
        data = runde(63, {}, 10 ** 10)
        self.assertNotIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_ruhend"], {32400: 1})
        # Eine neue Verbindung derselben IP nach der TTL zählt nicht, eine beendete ist vergessen.
        neu = ("[::ffff:192.168.1.110]:32400", "[::ffff:%s]:9251" % APP)
        host.verbindungen = zeile(*neu)
        self.datei({}, zeit=JETZT + 64 * 60)
        data = sammler.sammeln(JETZT + 64 * 60)
        self.assertNotIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_wan_ignoriert"], {32400: 1})
        host.verbindungen = zeile(*verbindung)
        data = runde(65, {}, 2 * 10 ** 10)
        self.assertNotIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_wan_ignoriert"], {32400: 1})

    def test_gebundene_verbindung_uebersteht_rueckfall_und_unklare_runde(self):
        verbindung = ("192.168.1.110:22", "%s:9250" % APP)
        scanner = ("192.168.1.110:22", "%s:50000" % SCANNER)
        host = self.host(verbindung, scanner)
        sammler = self.dauersammler(host)
        self.datei({APP: JETZT})
        data = sammler.sammeln(JETZT)
        self.assertEqual((data["fakten"]["verbindungen"][22], data["fakten"]["verbindungen_wan_ignoriert"]),
                         (1, {22: 1}))
        # Rückfallebene: jede Verbindung zählt, aber keine wird dabei neu als legitim gemerkt.
        self.pfad.unlink()
        data = sammler.sammeln(JETZT + 60)
        self.assertEqual((data["fakten"]["legitim"], data["fakten"]["verbindungen"][22]), ("fehlt", 2))
        # Unklare Runde (ss scheitert): Die Merkliste bleibt.
        host.fehler.add("info")
        self.assertIn("verbindungen_unklar", sammler.sammeln(JETZT + 120)["unklar"])
        host.fehler.clear()
        self.datei({}, zeit=JETZT + 3700)
        data = sammler.sammeln(JETZT + 3700)
        self.assertIn("verbindung:22", data["vetos"])
        self.assertEqual((data["fakten"]["verbindungen"][22], data["fakten"]["verbindungen_wan_ignoriert"]),
                         (1, {22: 1}))

    def test_haarnadel_bleibt_haarnadel_auch_wenn_gemerkt(self):
        # Vor der ersten Auflösung kann die eigene Adresse legitim sein; sobald sie bekannt ist, zählt
        # auch ihre schon gemerkte Verbindung nicht mehr.
        host = self.host(("192.168.1.110:32400", "%s:50000" % EIGENE))
        sammler = self.dauersammler(host)
        self.datei({EIGENE: JETZT})
        self.assertIn("verbindung:32400", sammler.sammeln(JETZT)["vetos"])
        self.datei({}, zeit=JETZT + 60, eigene=[EIGENE])
        data = sammler.sammeln(JETZT + 60)
        self.assertNotIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_haarnadel"], {32400: 1})


ROOT = Path(__file__).resolve().parents[1]
CFG = {"interface": "eno1", "target": "192.168.1.110", "plex_hash": "abc123", "plex_clients": ["test-client"],
       "minecraft_whitelist": ["Testspieler"], "lan": ["192.168.1.0/24"], "vpn": ["10.0.0.0/24"]}


def gestrichelt(ip):
    return ip.replace(".", "-") + ".abc123.plex.direct"


class Logger:
    def __init__(self):
        self.rows = []

    def emit(self, row, now=None, **kwargs):
        self.rows.append(dict(row))
        return True


class Wan:
    """Steht für wan.WanAdresse: feste Antwort, kein Faden."""

    def __init__(self, werte=None):
        self.werte, self.angestossen = werte, []

    def anstossen(self, now):
        self.angestossen.append(now)

    def aktuell(self, now):
        return self.werte


class MitschnittTests(unittest.TestCase):
    """gb-mitschnitt führt die Legitim-Datei (R1, R2, R5)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pfad = Path(self.tmp.name) / "legitim" / "vhost01.json"
        self.pfad.parent.mkdir()
        self.logger = Logger()

    def lesen(self):
        return legitim.lesen(self.pfad, {os.getuid()})

    def beobachter(self, wan=None, **kwargs):
        self.schreiber = legitim.Schreiber(self.pfad, wan=wan or Wan(), logger=self.logger, **kwargs)
        return mitschnitt.Beobachter(CFG, self.logger, legitim=self.schreiber)

    def fluss(self, observer, source, payload, port=32400, now=10.0):
        observer.paket(tcp_packet(ethernet(syn=True, source=source, port=port)), now)
        observer.paket(tcp_packet(ethernet(payload, seq=101, source=source, port=port)), now + 0.1)

    # Pflicht: "wuerde_wecken" aus dem WAN wird eingetragen
    def test_traegt_wuerde_wecken_ein(self):
        observer = self.beobachter()
        self.fluss(observer, APP, clienthello(gestrichelt(EIGENE)))
        self.fluss(observer, SCANNER, minecraft("Testspieler"), port=25565, now=11.0)
        self.schreiber.takt(12.0)
        data = self.lesen()
        self.assertEqual(data["quellen"], {APP: 10.1, SCANNER: 11.1})
        self.assertEqual((data["version"], data["zeit"], data["ttl_s"]), (1, 12.0, 3600))
        self.assertNotIn("eigene_wan_ip", data)
        self.assertEqual([r["entscheidung"] for r in self.logger.rows if "quell_ip" in r],
                         ["wuerde_wecken", "wuerde_wecken"])

    # Pflicht: nie "spam" oder "unklar"; LAN/VPN braucht keinen Eintrag
    def test_spam_unklar_und_lan_nie(self):
        observer = self.beobachter()
        observer.paket(tcp_packet(ethernet(syn=True, source="198.51.100.20")), 1.0)
        self.fluss(observer, "198.51.100.21", clienthello("scanner.example.net"))
        self.fluss(observer, "198.51.100.22", minecraft("Scanner"), port=25565)
        self.fluss(observer, "198.51.100.23", minecraft(status=True), port=25565)
        self.fluss(observer, "198.51.100.24", b"\x16\x03\x03\x00\x01\x00")
        self.fluss(observer, "198.51.100.25", b"GET / HTTP/1.1\r\nX-Plex-Client-Identifier: test-client\r\n\r\n")
        self.fluss(observer, "192.168.1.20", clienthello(gestrichelt("192.168.1.110")))
        self.fluss(observer, "10.0.0.2", minecraft("Testspieler"), port=25565)
        observer.paket(tcp_packet(ethernet(syn=True, source="198.51.100.26", port=8443)), 12.0)
        observer.ablaufen(20.0)
        entscheidungen = sorted(r["entscheidung"] for r in self.logger.rows if "quell_ip" in r)
        # spam: fremdes SNI, Scanner-Name, Status-Ping, WAN-HTTP; unklar: nur SYN, halbes TLS, 8443.
        self.assertEqual(entscheidungen, ["spam"] * 4 + ["unklar"] * 3 + ["wuerde_wecken"] * 2)
        self.schreiber.takt(21.0)
        self.assertEqual(self.lesen()["quellen"], {})

    # Ruling: wie proxy01 (Weg 7) muss das SNI-Label die LAN-IP oder die aktuelle WAN-IP sein
    def test_sni_label_wie_auf_proxy01(self):
        observer = self.beobachter(Wan([EIGENE]))
        self.fluss(observer, "198.51.100.30", clienthello(gestrichelt("198.51.100.99")))
        self.fluss(observer, "198.51.100.31", clienthello(gestrichelt(EIGENE)))
        self.fluss(observer, "198.51.100.32", clienthello(gestrichelt("192.168.1.110")))
        self.fluss(observer, "198.51.100.33", clienthello(gestrichelt("192.168.1.50")))
        self.schreiber.takt(12.0)
        self.assertEqual(sorted(self.lesen()["quellen"]), ["198.51.100.31", "198.51.100.32"])
        labels = [r.get("sni_label") for r in self.logger.rows if "quell_ip" in r]
        self.assertEqual(labels, ["ip_andere", "wan", "lan", "ip_andere"])

    def test_ohne_wan_ip_jede_oeffentliche_als_label(self):
        observer = self.beobachter(Wan(None))
        self.fluss(observer, "198.51.100.30", clienthello(gestrichelt("198.51.100.99")))
        self.fluss(observer, "198.51.100.33", clienthello(gestrichelt("172.16.0.5")))
        self.schreiber.takt(12.0)
        self.assertEqual(sorted(self.lesen()["quellen"]), ["198.51.100.30"])

    # Pflicht: nie die eigene WAN-IP (R5)
    def test_eigene_wan_ip_nie_legitim(self):
        wan = Wan([EIGENE])
        observer = self.beobachter(wan)
        self.fluss(observer, EIGENE, clienthello(gestrichelt(EIGENE)))
        self.schreiber.takt(12.0)
        data = self.lesen()
        self.assertEqual(data["quellen"], {})
        self.assertEqual(data["eigene_wan_ip"], [EIGENE])
        # Vor der ersten Auflösung eingetragen (neuer Fluss nach 60 s): sobald die Adresse bekannt ist,
        # fliegt sie heraus, und zwar sofort, nicht erst mit dem Herzschlag.
        wan.werte = None
        self.fluss(observer, EIGENE, clienthello(gestrichelt(EIGENE)), now=80.0)
        self.schreiber.takt(81.0)
        self.assertEqual(list(self.lesen()["quellen"]), [EIGENE])
        self.assertNotIn("eigene_wan_ip", self.lesen())
        wan.werte = [EIGENE]
        self.schreiber.takt(82.0)
        data = self.lesen()
        self.assertEqual((data["quellen"], data["zeit"], data["eigene_wan_ip"]), ({}, 82.0, [EIGENE]))

    def test_laufender_legitimer_fluss_haelt_eintrag_frisch(self):
        # Keep-alive: weitere Anfragen im selben TLS-Fluss ohne neuen Handshake; "zuletzt gesehen" wandert
        # mit (höchstens alle 10 s), damit eine länger als ttl offene, benutzte Verbindung legitim bleibt.
        observer = self.beobachter()
        self.fluss(observer, APP, clienthello(gestrichelt(EIGENE)), now=10.0)
        self.fluss(observer, SCANNER, clienthello("scanner.example.net"), now=10.0)
        anfrage = b"\x17\x03\x03\x00\x05hallo"
        for jetzt in (15.0, 40.0, 70.0, 75.0):
            for quelle in (APP, SCANNER):
                observer.paket(tcp_packet(ethernet(anfrage, seq=3000 + int(jetzt), source=quelle)), jetzt)
        self.schreiber.takt(76.0)
        self.assertEqual(self.lesen()["quellen"], {APP: 70.0})

    # Pflicht: Herzschlag ohne Änderung
    def test_herzschlag_ohne_aenderung(self):
        schreiber = legitim.Schreiber(self.pfad, wan=Wan(), logger=self.logger)
        schreiber.takt(1000.0)
        self.assertEqual(self.lesen()["zeit"], 1000.0)
        schreiber.takt(1029.0)
        self.assertEqual(self.lesen()["zeit"], 1000.0)
        schreiber.takt(1030.0)
        self.assertEqual(self.lesen()["zeit"], 1030.0)
        # Eine neue Quelle wird sofort geschrieben, eine bekannte erst mit dem Herzschlag.
        schreiber.eintragen(APP, 1031.0)
        schreiber.takt(1031.5)
        self.assertEqual(self.lesen()["quellen"], {APP: 1031.0})
        schreiber.eintragen(APP, 1040.0)
        schreiber.takt(1040.5)
        self.assertEqual(self.lesen()["quellen"], {APP: 1031.0})
        schreiber.takt(1061.5)
        self.assertEqual(self.lesen()["quellen"], {APP: 1040.0})
        self.assertLessEqual(legitim.HERZSCHLAG_S, 60)

    # Pflicht: Obergrenze
    def test_obergrenze_aelteste_fliegen(self):
        schreiber = legitim.Schreiber(self.pfad, maximum=3, wan=Wan(), logger=self.logger)
        for index, ip in enumerate(("203.0.113.1", "203.0.113.2", "203.0.113.3")):
            schreiber.eintragen(ip, 100.0 + index)
        schreiber.eintragen("203.0.113.1", 110.0)
        schreiber.eintragen("203.0.113.4", 111.0)
        schreiber.takt(112.0)
        self.assertEqual(self.lesen()["quellen"], {"203.0.113.3": 102.0, "203.0.113.1": 110.0, "203.0.113.4": 111.0})
        self.assertEqual(legitim.Schreiber(self.pfad).maximum, 4096)

    # Pflicht: TTL
    def test_letztes_paket(self):
        # Ab dem ersten Takt, dann je erfasstem Paket für das Ziel; nie später als die Schreibzeit.
        observer = self.beobachter()
        self.schreiber.takt(1000.0)
        self.assertEqual(self.lesen()["letztes_paket"], 1000.0)
        self.schreiber.takt(1030.0)
        self.assertEqual(self.lesen()["letztes_paket"], 1000.0)
        self.schreiber.takt(1900.0)
        self.assertEqual(legitim.filter_laden({"legitim": str(self.pfad)}, 1900.0, {os.getuid()})[0], "ok")
        self.assertEqual(legitim.filter_laden({"legitim": str(self.pfad)}, 1901.0, {os.getuid()})[0], "still")
        # Ein Paket an ein anderes Ziel zählt nicht.
        observer.paket(dict(tcp_packet(ethernet(syn=True, source=SCANNER)), target="192.168.1.111"), 1910.0)
        self.schreiber.takt(1940.0)
        self.assertEqual(self.lesen()["letztes_paket"], 1000.0)
        observer.paket(tcp_packet(ethernet(syn=True, source=SCANNER)), 1950.0)
        self.schreiber.takt(1971.0)
        self.assertEqual(self.lesen()["letztes_paket"], 1950.0)
        self.assertEqual(legitim.filter_laden({"legitim": str(self.pfad)}, 1971.0, {os.getuid()})[0], "ok")

    def test_ttl_laeuft_ab(self):
        schreiber = legitim.Schreiber(self.pfad, ttl=3600, wan=Wan(), logger=self.logger)
        schreiber.eintragen(APP, 0.0)
        schreiber.takt(3590.0)
        self.assertEqual(self.lesen()["quellen"], {APP: 0.0})
        schreiber.takt(3601.0)
        self.assertEqual(self.lesen()["quellen"], {})
        self.assertEqual(self.lesen()["zeit"], 3601.0)

    def test_klemmt_eintraege_nach_uhrsprung(self):
        schreiber = legitim.Schreiber(self.pfad, wan=Wan(), logger=self.logger)
        schreiber.eintragen(APP, 2000.0)
        schreiber.takt(1000.0)
        self.assertEqual(self.lesen()["quellen"], {APP: 1000.0})

    # Pflicht: atomar
    def test_atomar_kein_halbes_json(self):
        schreiber = legitim.Schreiber(self.pfad, wan=Wan(), logger=self.logger)
        for index in range(768):
            netz = ("192.0.2", "198.51.100", "203.0.113")[index // 256]
            schreiber.eintragen("%s.%d" % (netz, index % 256), 1.0 + index / 10000)
        schreiber.takt(2.0)
        fehler, stopp = [], threading.Event()

        def lesen():
            while not stopp.is_set():
                try:
                    json.loads(self.pfad.read_bytes())
                except Exception as error:
                    fehler.append(repr(error))
        faden = threading.Thread(target=lesen)
        faden.start()
        try:
            for runde in range(60):
                schreiber.takt(100.0 + runde * 30)
        finally:
            stopp.set()
            faden.join()
        self.assertEqual(fehler, [])
        self.assertEqual(sorted(p.name for p in self.pfad.parent.iterdir()), ["vhost01.json"])

    def test_schreibfehler_laesst_alte_datei_und_meldet_einmal(self):
        schreiber = legitim.Schreiber(self.pfad, wan=Wan(), logger=self.logger)
        schreiber.takt(1000.0)
        alt = self.pfad.read_bytes()
        schreiber.eintragen(APP, 1001.0)
        with mock.patch.object(os, "fsync", side_effect=OSError("voll")):
            schreiber.takt(1001.5)
            schreiber.takt(1003.0)
        self.assertEqual(self.pfad.read_bytes(), alt)
        self.assertEqual(sorted(p.name for p in self.pfad.parent.iterdir()), ["vhost01.json"])
        self.assertEqual([r for r in self.logger.rows if r.get("ereignis") == "legitim_schreibfehler"],
                         [{"ereignis": "legitim_schreibfehler"}])
        schreiber.takt(1004.0)
        self.assertEqual(self.lesen()["quellen"], {APP: 1001.0})

    # Pflicht: DNS blockiert den Mitschnitt nicht (R5)
    def test_haengender_resolver_blockiert_nicht(self):
        from greenbuddy2.wan import WanAdresse
        frei, aufrufe = threading.Event(), []

        def aufloesen(name):
            aufrufe.append(name)
            frei.wait(10)
            return [EIGENE]
        wan = WanAdresse("wan.example.net", aufloesen=aufloesen)
        observer = self.beobachter(wan)
        beginn = time.monotonic()
        self.schreiber.takt(1000.0)
        self.fluss(observer, APP, clienthello(gestrichelt(EIGENE)), now=1000.5)
        self.schreiber.takt(1003.0)
        self.assertLess(time.monotonic() - beginn, 1.0)
        self.assertEqual(aufrufe, ["wan.example.net"])
        self.assertNotIn("eigene_wan_ip", self.lesen())
        self.assertEqual(list(self.lesen()["quellen"]), [APP])
        frei.set()
        for _ in range(200):
            if not wan.laeuft:
                break
            time.sleep(0.01)
        self.schreiber.takt(1004.0)
        self.assertEqual(self.lesen()["eigene_wan_ip"], [EIGENE])
        # Höchstens alle 10 Minuten neu auflösen.
        self.schreiber.takt(1500.0)
        self.assertEqual(len(aufrufe), 1)
        self.schreiber.takt(1600.5)
        for _ in range(200):
            if len(aufrufe) == 2:
                break
            time.sleep(0.01)
        self.assertEqual(len(aufrufe), 2)

    def test_ohne_wan_name_keine_aufloesung(self):
        from greenbuddy2.wan import WanAdresse
        aufrufe = []
        wan = WanAdresse("", aufloesen=lambda name: aufrufe.append(name) or [EIGENE])
        schreiber = legitim.Schreiber(self.pfad, wan=wan, logger=self.logger)
        schreiber.takt(1000.0)
        schreiber.takt(2000.0)
        self.assertEqual(aufrufe, [])
        self.assertNotIn("eigene_wan_ip", self.lesen())


class MitschnittDienstTests(unittest.TestCase):
    """main(): tcpdump-Strom bis zur Legitim-Datei; Abschalter respektiert."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.pfad = base / "legitim" / "vhost01.json"
        self.pfad.parent.mkdir()
        self.aus = base / "aus"
        self.cfg = base / "mitschnitt.json"
        self.cfg.write_text(json.dumps(dict(CFG, log=str(base / "mitschnitt.jsonl"), aus=str(self.aus),
                                            legitim=str(self.pfad))))
        alt = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, alt)

    def tcpdump(self, daten):
        lesen, schreiben = os.pipe()
        os.write(schreiben, daten)
        os.close(schreiben)
        return types.SimpleNamespace(stdout=os.fdopen(lesen, "rb"), terminate=lambda: None,
                                     wait=lambda timeout=None: 0, kill=lambda: None)

    def test_strom_bis_zur_legitim_datei(self):
        frames = [ethernet(syn=True, source=APP), ethernet(clienthello(gestrichelt(EIGENE)), seq=101, source=APP),
                  ethernet(syn=True, source=SCANNER)]
        child = self.tcpdump(pcap(frames))
        with mock.patch.object(sys, "argv", ["gb-mitschnitt", "--config", str(self.cfg)]), \
                mock.patch.object(mitschnitt.subprocess, "Popen", return_value=child):
            self.assertEqual(mitschnitt.main(), 1)
        data = legitim.lesen(self.pfad, {os.getuid()})
        self.assertEqual(list(data["quellen"]), [APP])
        self.assertEqual(data["ttl_s"], 3600)

    # Review 13.10.26: Ohne gültigen plex_hash wird keine Plex-Quelle legitim; eine frische Datei mit
    # leerer Liste hieße "ok" und würde jede WAN-Verbindung still ignorieren.
    def test_ohne_gueltigen_plex_hash_keine_datei(self):
        vorlage = json.loads((ROOT / "deploy/vhost01/mitschnitt.example.json").read_text())["plex_hash"]
        frames = [ethernet(syn=True, source=APP),
                  ethernet(clienthello(gestrichelt(EIGENE).replace("abc123", "0123456789abcdef")), seq=101,
                           source=APP)]
        log = Path(self.tmp.name) / "mitschnitt.jsonl"
        for wert in (vorlage, "", "abc12", "abc123.plex.direct"):
            with self.subTest(plex_hash=wert):
                self.cfg.write_text(json.dumps(dict(json.loads(self.cfg.read_text()), plex_hash=wert)))
                with mock.patch.object(sys, "argv", ["gb-mitschnitt", "--config", str(self.cfg)]), \
                        mock.patch.object(mitschnitt.subprocess, "Popen", return_value=self.tcpdump(pcap(frames))):
                    self.assertEqual(mitschnitt.main(), 1)
                self.assertFalse(self.pfad.exists())
                self.assertEqual(legitim.filter_laden({"legitim": str(self.pfad)}, time.time())[0], "fehlt")
                zeilen = [json.loads(z) for z in log.read_text().splitlines()]
                self.assertEqual([dict(z, utc=None) for z in zeilen if z.get("ereignis") == "legitim_aus"],
                                 [{"ereignis": "legitim_aus", "grund": "plex_hash", "utc": None}])
                log.unlink()

    def test_abschalter_schreibt_nichts(self):
        self.aus.touch()
        with mock.patch.object(sys, "argv", ["gb-mitschnitt", "--config", str(self.cfg)]), \
                mock.patch.object(mitschnitt.subprocess, "Popen") as popen, \
                mock.patch.object(mitschnitt.time, "sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                mitschnitt.main()
        popen.assert_not_called()
        self.assertFalse(self.pfad.exists())


class KonfigTests(unittest.TestCase):
    """R7: neue Schlüssel mit Standardwerten, Beispielkonfigs und strenger Prüfung."""

    def laden(self, data, defaults=SCHLAF):
        from greenbuddy2.konfig import laden
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.json"
            path.write_text(json.dumps(data))
            return laden(path, defaults)

    def test_standardwerte(self):
        from greenbuddy2.konfig import MITSCHNITT
        self.assertIs(SCHLAF["wan_filter"], True)
        self.assertEqual(SCHLAF["legitim"], "/run/greenbuddy/legitim/vhost01.json")
        self.assertEqual(SCHLAF["legitim_max_alter_s"], 180)
        self.assertEqual(SCHLAF["legitim_stille_s"], 900)
        self.assertEqual(SCHLAF["legitim_quellen"], {})
        self.assertEqual((SCHLAF["lan"], SCHLAF["vpn"]), (["192.168.1.0/24"], ["10.0.0.0/24"]))
        self.assertEqual(MITSCHNITT, {"legitim": "/run/greenbuddy/legitim/vhost01.json", "legitim_ttl_s": 3600,
                                      "legitim_max": 4096, "wan_name": ""})

    def test_beispielkonfigs(self):
        from greenbuddy2.konfig import MITSCHNITT
        schlaf = json.loads((ROOT / "deploy/vhost01/schlaf.example.json").read_text())
        mitschnitt = json.loads((ROOT / "deploy/vhost01/mitschnitt.example.json").read_text())
        for name in ("wan_filter", "legitim", "legitim_max_alter_s", "legitim_stille_s", "legitim_quellen", "lan",
                     "vpn"):
            self.assertEqual(schlaf[name], SCHLAF[name], name)
        for name, value in MITSCHNITT.items():
            self.assertEqual(mitschnitt[name], value, name)
        # Beide Dienste müssen dieselbe Datei meinen; kein DDNS-Name im Repo (R8).
        self.assertEqual(schlaf["legitim"], mitschnitt["legitim"])
        self.assertEqual(mitschnitt["wan_name"], "")
        self.assertEqual(self.laden(schlaf)["legitim_quellen"], {})
        self.assertEqual(self.laden(mitschnitt, MITSCHNITT)["legitim_max"], 4096)

    def test_gueltige_werte(self):
        cfg = self.laden({"legitim_quellen": {"8443": ["203.0.113.10", "203.0.113.11"]}, "wan_filter": False,
                          "legitim_max_alter_s": 120, "legitim_stille_s": 1800, "lan": ["192.168.1.0/24"],
                          "vpn": []})
        self.assertEqual(cfg["legitim_stille_s"], 1800)
        self.assertEqual(cfg["legitim_quellen"], {"8443": ["203.0.113.10", "203.0.113.11"]})
        self.assertIs(cfg["wan_filter"], False)
        cfg = self.laden({"wan_name": "wan.example.net", "legitim_ttl_s": 600, "legitim_max": 1}, {})
        self.assertEqual(cfg["wan_name"], "wan.example.net")

    def test_ungueltige_werte(self):
        for data in ({"wan_filter": "true"}, {"wan_filter": 1}, {"legitim": ""}, {"legitim": 5},
                     {"legitim_max_alter_s": 0}, {"legitim_max_alter_s": float("inf")},
                     {"legitim_max_alter_s": "180"}, {"legitim_ttl_s": -1}, {"legitim_ttl_s": True},
                     {"legitim_stille_s": 0}, {"legitim_stille_s": "900"}, {"legitim_stille_s": None},
                     {"legitim_max": 0}, {"legitim_max": 1.5}, {"legitim_max": True},
                     {"legitim_quellen": []}, {"legitim_quellen": {"8443": "203.0.113.10"}},
                     {"legitim_quellen": {"8443": []}}, {"legitim_quellen": {"0": ["203.0.113.10"]}},
                     {"legitim_quellen": {"65536": ["203.0.113.10"]}}, {"legitim_quellen": {"x": ["203.0.113.10"]}},
                     {"legitim_quellen": {"8443": ["keine.ip"]}}, {"legitim_quellen": {"8443": ["2001:db8::1"]}},
                     {"legitim_quellen": {"8443": [5]}},
                     {"lan": "192.168.1.0/24"}, {"lan": ["192.168.1.5/24"]}, {"vpn": ["2001:db8::/64"]},
                     {"vpn": [10]}, {"wan_name": 5}, {"wan_name": "kein name"}, {"wan_name": "a..b"}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.laden(data)


if __name__ == "__main__":
    unittest.main()
