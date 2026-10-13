"""gb-wecken: feste MAC-Tabelle, Paketaufbau und Warten – ohne echtes Netz."""

import contextlib
import io
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from greenbuddy2 import wecken, wol

ROOT = Path(__file__).resolve().parents[1]
KONFIG = {"hosts": {"vhost01": {"mac": "00:00:5e:00:53:10", "adresse": "192.168.1.110", "port": 22},
                    "nas01": {"mac": "00:00:5e:00:53:15", "adresse": "192.168.1.115", "port": 22}}}


class Sock:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def setsockopt(self, *args):
        self.log.append(("setsockopt",) + args)

    def sendto(self, data, target):
        self.log.append(("sendto", data, target))
        if target in getattr(self, "kaputt", ()):
            raise OSError(101, "Network is unreachable")
        return len(data)


class KaputtSock(Sock):
    def __init__(self, log, kaputt):
        super().__init__(log)
        self.kaputt = kaputt


class Uhr:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def schlafen(self, s):
        self.t += s


class WolTests(unittest.TestCase):
    def test_broadcast_an_beide_ziele(self):
        log = []
        n = wol.senden("00:00:5e:00:53:10", wecken.ZIELE, socket_factory=lambda *a: Sock(log))
        self.assertEqual(n, 2)
        packet = b"\xff" * 6 + bytes.fromhex("00005e005310") * 16
        self.assertIn(("setsockopt", socket.SOL_SOCKET, socket.SO_BROADCAST, 1), log)
        self.assertEqual([x[1:] for x in log if x[0] == "sendto"],
                         [(packet, ("192.168.1.255", 9)), (packet, ("255.255.255.255", 9))])

    def test_ein_kaputtes_ziel_verhindert_das_andere_nicht(self):
        log = []
        n = wol.senden("00:00:5e:00:53:10", wecken.ZIELE,
                       socket_factory=lambda *a: KaputtSock(log, {("192.168.1.255", 9)}))
        self.assertEqual(n, 1)
        self.assertEqual([x[2] for x in log if x[0] == "sendto"], [("192.168.1.255", 9), ("255.255.255.255", 9)])

    def test_alle_ziele_kaputt_liefert_null_ohne_ausnahme(self):
        log = []
        n = wol.senden("00:00:5e:00:53:10", wecken.ZIELE,
                       socket_factory=lambda *a: KaputtSock(log, set(wecken.ZIELE)))
        self.assertEqual(n, 0)

    def test_standardziel_unveraendert(self):
        log = []
        wol.senden("02:00:00:00:00:01", socket_factory=lambda *a: Sock(log))
        self.assertEqual([x[2] for x in log if x[0] == "sendto"], [("192.168.1.255", 9)])


class KonfigTests(unittest.TestCase):
    def schreiben(self, tmp, data):
        path = Path(tmp) / "wecken.json"
        path.write_text(json.dumps(data))
        return path

    def test_beispiel_enthaelt_feste_macs(self):
        data = wecken.laden(ROOT / "deploy/proxy01/wecken.example.json")
        self.assertEqual(data["vhost01"]["mac"], "00:00:5e:00:53:10")
        self.assertEqual(data["nas01"]["mac"], "00:00:5e:00:53:15")
        self.assertEqual(data["vhost01"]["adresse"], "192.168.1.110")
        self.assertEqual(data["nas01"]["adresse"], "192.168.1.115")

    def test_ungueltige_konfiguration(self):
        faelle = ([], {"hosts": {}}, {"hosts": {"vhost01": {"mac": "kaputt", "adresse": "192.168.1.110", "port": 22}}},
                  {"hosts": {"vhost01": {"mac": 5, "adresse": "192.168.1.110", "port": 22}}},
                  {"hosts": {"vhost01": {"mac": "00:00:5e:00:53:10", "adresse": "kein.host", "port": 22}}},
                  {"hosts": {"vhost01": {"mac": "00:00:5e:00:53:10", "adresse": "192.168.1.110", "port": True}}},
                  {"hosts": {"vhost01": {"mac": "00:00:5e:00:53:10", "adresse": "192.168.1.110", "port": 70000}}},
                  {"hosts": {"VHOST 01": {"mac": "00:00:5e:00:53:10", "adresse": "192.168.1.110", "port": 22}}})
        for data in faelle:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    wecken.laden(self.schreiben(tmp, data))


class WeckenTests(unittest.TestCase):
    def setUp(self):
        self.hosts = {name: dict(row) for name, row in KONFIG["hosts"].items()}
        self.gesendet = []

    def senden(self, mac, ziele):
        self.gesendet.append((mac, tuple(ziele)))
        return len(ziele)

    def test_ohne_warten(self):
        row, code = wecken.wecken("nas01", self.hosts, warten=False, senden=self.senden,
                                  pruefen=mock.Mock(side_effect=AssertionError("nicht prüfen")))
        self.assertEqual(code, 0)
        self.assertEqual(self.gesendet, [("00:00:5e:00:53:15", wecken.ZIELE)])
        self.assertEqual(row["pakete"], 2)

    def test_unbekannter_host_sendet_nichts(self):
        with self.assertRaises(ValueError):
            wecken.wecken("proxy01", self.hosts, senden=self.senden)
        self.assertEqual(self.gesendet, [])

    def test_warten_bis_erreichbar(self):
        uhr = Uhr()
        antworten = iter([False, False, True])
        pruefen = mock.Mock(side_effect=lambda adresse, port: next(antworten))
        row, code = wecken.wecken("vhost01", self.hosts, warten=True, senden=self.senden, pruefen=pruefen,
                                  uhr=uhr, schlafen=uhr.schlafen)
        self.assertEqual(code, 0)
        self.assertTrue(row["erreichbar"])
        pruefen.assert_called_with("192.168.1.110", 22)

    def test_standard_wartet_180s_mit_wiederholung(self):
        # Messung 07.10.26: tote Platten verzögern das Einschlafen bis ~60 s; ein WOL in dieser
        # Phase verpufft. Deshalb standardmäßig >= 3 min wiederholen, bis TCP antwortet.
        uhr = Uhr()
        row, code = wecken.wecken("vhost01", self.hosts, senden=self.senden,
                                  pruefen=lambda adresse, port: False, uhr=uhr, schlafen=uhr.schlafen)
        self.assertEqual(code, 1)
        self.assertFalse(row["erreichbar"])
        self.assertGreaterEqual(uhr.t, 180)
        self.assertLessEqual(uhr.t, 182)
        self.assertGreaterEqual(len(self.gesendet), 12)
        self.assertLessEqual(len(self.gesendet), 14)

    def test_sendefehler_beendet_die_wiederholung_nicht(self):
        uhr = Uhr()
        versuche = []

        def senden(mac, ziele):
            versuche.append(uhr.t)
            if len(versuche) == 1:
                raise OSError(101, "Network is unreachable")
            return 2

        antworten = iter([False] * 10 + [True])
        row, code = wecken.wecken("vhost01", self.hosts, senden=senden,
                                  pruefen=lambda adresse, port: next(antworten), uhr=uhr, schlafen=uhr.schlafen)
        self.assertEqual(code, 0)
        self.assertTrue(row["erreichbar"])
        self.assertGreater(len(versuche), 1)
        self.assertEqual(row["sendefehler"], 1)

    def test_kein_einziges_paket_ist_eigener_fehler(self):
        uhr = Uhr()
        row, code = wecken.wecken("vhost01", self.hosts, senden=lambda mac, ziele: 0,
                                  pruefen=lambda adresse, port: False, uhr=uhr, schlafen=uhr.schlafen)
        self.assertEqual(code, 3)
        self.assertEqual(row["fehler"], "senden_fehlgeschlagen")

    def test_main_unbekannter_host_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "wecken.json"
            path.write_text(json.dumps(KONFIG))
            with mock.patch.object(wecken.wol, "senden", return_value=2) as send, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(wecken.main(["--config", str(path), "proxy01"]), 2)
                send.assert_not_called()
                out = io.StringIO()
                with mock.patch.object(wecken, "erreichbar", return_value=True) as tcp, \
                        contextlib.redirect_stdout(out):
                    self.assertEqual(wecken.main(["--config", str(path), "vhost01"]), 0)
                send.assert_called_once_with("00:00:5e:00:53:10", wecken.ZIELE)
                tcp.assert_called_with("192.168.1.110", 22)
                self.assertTrue(json.loads(out.getvalue())["erreichbar"])

    def test_main_nur_senden_prueft_nicht(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "wecken.json"
            path.write_text(json.dumps(KONFIG))
            out = io.StringIO()
            with mock.patch.object(wecken.wol, "senden", return_value=2) as send, \
                    mock.patch.object(wecken, "erreichbar", side_effect=AssertionError("nicht prüfen")), \
                    contextlib.redirect_stdout(out):
                self.assertEqual(wecken.main(["--config", str(path), "--nur-senden", "nas01"]), 0)
            send.assert_called_once_with("00:00:5e:00:53:15", wecken.ZIELE)
            self.assertEqual(json.loads(out.getvalue())["pakete"], 2)
            with mock.patch.object(wecken.wol, "senden", return_value=0), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(wecken.main(["--config", str(path), "--nur-senden", "nas01"]), 3)

    def test_main_kaputte_konfig_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(wecken.wol, "senden") as send, \
                contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wecken.main(["--config", str(Path(tmp) / "fehlt.json"), "vhost01"]), 2)
            send.assert_not_called()

    def test_erreichbar_ohne_netz(self):
        with mock.patch.object(wecken.socket, "create_connection", side_effect=OSError("Test")):
            self.assertFalse(wecken.erreichbar("192.168.1.110", 22))
        conn = mock.MagicMock()
        with mock.patch.object(wecken.socket, "create_connection", return_value=conn) as create:
            self.assertTrue(wecken.erreichbar("192.168.1.110", 22))
            self.assertEqual(create.call_args.args[0], ("192.168.1.110", 22))


if __name__ == "__main__":
    unittest.main()
