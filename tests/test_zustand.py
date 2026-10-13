"""Register und Protokollaufbewahrung ohne Rechte oder Netz."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from greenbuddy2.jsonlog import JsonLog
from greenbuddy2.proxy_ssh import ausfuehren
from greenbuddy2.register import Register, atomar
from greenbuddy2.stellvertreter import GDMZaehler


class RegisterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "register.json"
        self.reg = Register(self.path, lease_seconds=100)

    def test_atomare_datei_und_fsync(self):
        with mock.patch("greenbuddy2.register.os.fsync", wraps=__import__('os').fsync) as sync:
            atomar(self.path, {"test": 1})
            self.assertEqual(sync.call_count, 2)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        atomar(self.path, {"test": 1}, modus=0o640)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        with mock.patch("greenbuddy2.register.os.replace", side_effect=OSError("Testabbruch")):
            with self.assertRaises(OSError):
                atomar(self.path, {"test": 2})
        self.assertEqual(json.loads(self.path.read_text()), {"test": 1})
        self.assertEqual(list(Path(self.tmp.name).glob('.register.json.*')), [])

    def test_lease_und_zyklus(self):
        row = self.reg.befehl("vhost01", "abmelden", "zyklus1", 10)
        # Ohne frischen Statusbericht des Stellvertreters keine Bereitschaft (Plan R1).
        self.assertFalse(row["bereit"])
        self.assertEqual(row["grund"], "stellvertreter_status_fehlt")
        self.assertEqual(row["zustand"]["ablauf"], 110)
        self.assertEqual(row["zustand"]["beginn"], 10)
        self.assertEqual(self.reg.befehl("vhost01", "abmelden", "zyklus1", 20)["zustand"]["ablauf"], 110)
        with self.assertRaises(ValueError):
            self.reg.befehl("vhost01", "anmelden", "falsch", 20)
        # Ohne Bereitschaft bleibt die Phase abgemeldet; der Host bricht ab.
        row = self.reg.befehl("vhost01", "schlafe-jetzt", "zyklus1", 20, sekunden=600)
        self.assertEqual(row["zustand"]["phase"], "abgemeldet")
        self.assertEqual(self.reg.befehl("vhost01", "status", None, 110)["zustand"]["phase"], "lease_abgelaufen")
        with self.assertRaises(ValueError):
            self.reg.befehl("vhost01", "schlafe-jetzt", "zyklus1", 120, sekunden=600)
        self.assertEqual(self.reg.befehl("vhost01", "anmelden-abbruch", "zyklus1", 120)["zustand"]["phase"], "angemeldet")
        with self.assertRaises(ValueError):
            self.reg.befehl("vhost01", "abmelden", "zyklus1", 130)
        # Ein neuer Zyklus ersetzt jeden alten; der Stellvertreter gibt dann frei (Plan 5.5).
        self.reg.befehl("vhost01", "abmelden", "zyklus2", 140)
        self.assertEqual(self.reg.befehl("vhost01", "abmelden", "zyklus3", 150)["zustand"]["zyklus"], "zyklus3")

    def test_neustart_und_hostbindung(self):
        self.reg.befehl("nas01", "abmelden", "naszyklus", 10)
        self.reg.befehl("vhost01", "abmelden", "vhostzyklus", 10)
        self.reg = Register(self.path)
        self.assertEqual(self.reg.befehl("nas01", "status", None, 20)["zustand"]["zyklus"], "naszyklus")
        with self.assertRaises(ValueError):
            self.reg.befehl("vhost01", "anmelden", "naszyklus", 20)

    def test_ssh_host_nur_argv(self):
        self.reg.befehl("nas01", "abmelden", "naszyklus", 10)
        for original in ("abmelden nas01 naszyklus", "--host nas01 status", "status nas01", "status; id", "suspend", "anmelden naszyklus"):
            with self.subTest(original=original), self.assertRaises(ValueError):
                ausfuehren(["--host", "vhost01"], original, self.reg, 20)
        row = ausfuehren(["--host", "vhost01"], "status", self.reg, 20)
        self.assertEqual(row["host"], "vhost01")
        self.assertEqual(self.reg.befehl("nas01", "status", None, 20)["zustand"]["phase"], "abgemeldet")
        ausfuehren(["--host", "vhost01"], "abmelden test1", self.reg, 20)
        self.assertEqual(ausfuehren(["--host", "vhost01"], "anmelden test1", self.reg, 21)["zustand"]["phase"], "angemeldet")

    def test_beschaedigtes_register_und_argv(self):
        for data in ([], {'version': 1, 'hosts': {'vhost01': {'zyklus': 5}}}):
            self.path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                self.reg.lesen()
        with self.assertRaises(ValueError):
            ausfuehren(['--host', 'fremd'], 'status', self.reg, 1)


class LogTests(unittest.TestCase):
    def test_rotation_heartbeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'log.jsonl'
            log = JsonLog(path, limit=150, rotations=2)
            self.assertTrue(log.emit({'entscheidung': 'beobachten'}, 1000, heartbeat=True))
            size = path.stat().st_size
            self.assertTrue(log.emit({'entscheidung': 'beobachten'}, 1001, heartbeat=True))
            self.assertEqual(size, path.stat().st_size)
            for stamp in (1060, 1120, 1180, 1240):
                self.assertTrue(log.emit({'entscheidung': 'beobachten'}, stamp, heartbeat=True))
            self.assertLessEqual(len(list(Path(tmp).iterdir())), 3)
            self.assertTrue(all(p.stat().st_size <= 150 for p in Path(tmp).iterdir()))

    def test_quell_ips_maximal_14_tage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'log.jsonl'
            old = {'zeit': 1, 'quell_ip': '198.51.100.9', 'quellklasse': 'WAN', 'port': 32400, 'entscheidung': 'spam'}
            path.write_text(json.dumps(old) + '\n' + json.dumps(old) + '\n')
            log = JsonLog(path, ip_retention=True)
            log.bereinigen(15 * 86400)
            text = path.read_text()
            self.assertNotIn('198.51.100.9', text)
            self.assertEqual(json.loads(text)['anzahl'], 2)

    def test_gdm_quellen_pro_stunde(self):
        logger = mock.Mock()
        counter = GDMZaehler(logger)
        counter.add('192.168.1.9', 1)
        counter.add('192.168.1.9', 2)
        self.assertEqual(logger.emit.call_count, 0)
        counter.flush(3601)
        self.assertEqual(logger.emit.call_args[0][0]['anzahl'], 2)
        self.assertEqual(logger.emit.call_args[0][0]['quell_ip'], '192.168.1.9')
