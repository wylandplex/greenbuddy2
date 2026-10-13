"""Vertrag proxy01 ↔ vhost01: echte Antworten des Zwangsbefehls laufen durch die Prüfung von vhost01."""

import json
import tempfile
import unittest
from pathlib import Path

from greenbuddy2 import proxy_ssh
from greenbuddy2 import register_client as rc
from greenbuddy2.register import Register


class VertragTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.status = base / "stellvertreter.json"
        self.register = Register(path=base / "register.json", status=self.status,
                                 boot=lambda: ("0f1e2d3c-aaaa-bbbb-cccc-000011112222", 5000.0))

    def tearDown(self):
        self.tmp.cleanup()

    def bericht(self, now, weckung=None, bereit=True):
        self.status.write_text(json.dumps({
            "version": 1, "zeit": now, "pid": 1, "abgeschaltet": False, "stellvertretung": "ok",
            "bereit_fuer": ["vhost01"] if bereit else [], "gruende": {"vhost01": None if bereit else "nft_fehlt"},
            "phasen": {"vhost01": "frei"}, "zyklen": {"vhost01": None},
            "weckung": {"vhost01": weckung}, "register": "ok", "wan_ip_bekannt": False}))

    def senden(self, befehl, now, aus=False):
        """Wie proxy_ssh.main: eine JSON-Zeile auf stdout, Exit 0."""
        row = proxy_ssh.ausfuehren(["--host", "vhost01"], befehl, register=self.register, now=now, aus=aus)
        teile = befehl.split()
        return rc.antwort(teile[0], teile[1] if len(teile) > 1 else None, 0,
                          json.dumps(row, ensure_ascii=False) + "\n")

    def zyklus_bis_anmelden(self, weckung):
        self.bericht(1000.0)
        self.assertTrue(self.senden("abmelden z1", 1000.0)["bereit"])
        self.assertEqual(self.senden("schlafe-jetzt z1 3600", 1001.0)["zustand"]["phase"], "schlaf_absicht")
        self.bericht(2100.0, weckung=weckung)
        return self.senden("anmelden z1", 2100.0)["weckung"]

    def test_weckung_ueber_vpn_wird_angenommen(self):
        weckung = {"zeit": 2000.0, "weg": 4, "port": 22, "quellklasse": "VPN", "entscheidung": "wecken"}
        self.assertEqual(self.zyklus_bis_anmelden(weckung), weckung)

    def test_weckung_durch_lease_ablauf_wird_angenommen(self):
        weckung = {"zeit": 2000.0, "weg": None, "port": None, "quellklasse": None,
                   "entscheidung": "lease_abgelaufen"}
        self.assertEqual(self.zyklus_bis_anmelden(weckung), weckung)

    def test_ohne_weckung_kommt_null(self):
        self.assertIsNone(self.zyklus_bis_anmelden(None))

    def test_abschalter_ist_absage_mit_grund(self):
        self.zyklus_bis_anmelden(None)
        self.bericht(3000.0)
        with self.assertRaises(rc.StellvertreterNichtBereit) as ctx:
            self.senden("abmelden z2", 3000.0, aus=True)
        self.assertEqual(ctx.exception.detail, "abgeschaltet")

    def test_stellvertreter_nicht_bereit_ist_absage_mit_grund(self):
        self.bericht(1000.0, bereit=False)
        with self.assertRaises(rc.StellvertreterNichtBereit) as ctx:
            self.senden("abmelden z1", 1000.0)
        self.assertEqual(ctx.exception.detail, "stellvertreter_nicht_bereit")

    def test_ohne_statusbericht_ist_absage(self):
        with self.assertRaises(rc.StellvertreterNichtBereit) as ctx:
            self.senden("abmelden z1", 1000.0)
        self.assertEqual(ctx.exception.detail, "stellvertreter_status_fehlt")

    def test_anmelden_abbruch_nach_absage_wird_angenommen(self):
        self.bericht(1000.0, bereit=False)
        with self.assertRaises(rc.StellvertreterNichtBereit):
            self.senden("abmelden z1", 1000.0)
        self.assertEqual(self.senden("anmelden-abbruch z1", 1001.0)["zustand"]["phase"], "angemeldet")


if __name__ == "__main__":
    unittest.main()
