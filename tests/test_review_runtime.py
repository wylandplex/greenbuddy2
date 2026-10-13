"""Regressionen der Review-Befunde: nur synthetische Daten und Fake-Befehle."""

import contextlib
import ctypes
import ctypes.util
import io
import json
import os
import socket
import tempfile
import threading
import types
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from greenbuddy2 import fakten_vhost as f, schlaf, webhook
from greenbuddy2.jsonlog import JsonLog
from greenbuddy2.konfig import SCHLAF
from greenbuddy2.mitschnitt import Beobachter, bpf
from greenbuddy2.pcap import TcpAnfang, tcp_packet
from fixtures import clienthello, ethernet, MEDIA
from test_webhook import callback, SECRET


def result(text="", code=0):
    return types.SimpleNamespace(stdout=text, returncode=code)


class Filter:
    """libpcap kompiliert und prüft ausschließlich Byte-Fixtures, ohne Socket."""
    class Instruction(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]

    class Header(ctypes.Structure):
        _fields_ = [("seconds", ctypes.c_long), ("micros", ctypes.c_long),
                    ("caplen", ctypes.c_uint32), ("length", ctypes.c_uint32)]

    def __init__(self, expression):
        class Program(ctypes.Structure):
            _fields_ = [("length", ctypes.c_uint), ("instructions", ctypes.POINTER(Filter.Instruction))]
        library = ctypes.util.find_library("pcap")
        if not library:
            raise unittest.SkipTest("Offline-libpcap fehlt")
        self.lib = ctypes.CDLL(library)
        self.lib.pcap_open_dead.argtypes = [ctypes.c_int, ctypes.c_int]
        self.lib.pcap_open_dead.restype = ctypes.c_void_p
        self.lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(Program), ctypes.c_char_p,
                                         ctypes.c_int, ctypes.c_uint32]
        self.lib.pcap_offline_filter.argtypes = [ctypes.POINTER(Program), ctypes.POINTER(self.Header), ctypes.c_void_p]
        self.lib.pcap_freecode.argtypes = [ctypes.POINTER(Program)]
        self.lib.pcap_close.argtypes = [ctypes.c_void_p]
        self.program = Program()
        handle = self.lib.pcap_open_dead(1, 65535)
        try:
            if self.lib.pcap_compile(handle, ctypes.byref(self.program), expression.encode(), 1, 0xffffffff):
                raise AssertionError("BPF kompiliert nicht")
        finally:
            self.lib.pcap_close(handle)

    def accepts(self, frame):
        header = self.Header(0, 0, len(frame), len(frame))
        return bool(self.lib.pcap_offline_filter(ctypes.byref(self.program), ctypes.byref(header), frame))

    def close(self):
        self.lib.pcap_freecode(ctypes.byref(self.program))


class LogReviewTests(unittest.TestCase):
    def test_w1_keine_symlinks_schreiben(self):
        with tempfile.TemporaryDirectory() as tmp:
            victim, path = Path(tmp) / "fremd", Path(tmp) / "log"
            victim.write_text("unveraendert")
            path.symlink_to(victim)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertFalse(JsonLog(path).emit({"entscheidung": "beobachten"}, 1))
            self.assertEqual(victim.read_text(), "unveraendert")

    def test_w1_bereinigung_folgt_keinem_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            victim, path = Path(tmp) / "fremd", Path(tmp) / "log"
            victim.write_text("unveraendert")
            path.with_name("log.bereinigung").symlink_to(victim)
            path.write_text('{"zeit":1,"quell_ip":"198.51.100.9"}\n')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertFalse(JsonLog(path, ip_retention=True).emit({"entscheidung": "beobachten"}, 15 * 86400))
            self.assertEqual(victim.read_text(), "unveraendert")

    def test_k2_kaputte_bytes_retention_laeuft_weiter(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log"
            old = json.dumps({"zeit": 1, "quell_ip": "198.51.100.9", "entscheidung": "spam"}).encode()
            path.write_bytes(b"\xff\xfe kaputt\n" + old + b"\n")
            JsonLog(path, ip_retention=True).bereinigen(15 * 86400)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(rows[0]["anzahl"], 1)
            self.assertNotIn("198.51.100.9", path.read_text())


class FaktenReviewTests(unittest.TestCase):
    def test_w2_journal_byteliste_ansi(self):
        message = list(b'\x1b[32mThreemaGateway\x1b[0m \xff')
        row = json.dumps({"MESSAGE": message, "__REALTIME_TIMESTAMP": "990000000"})
        self.assertEqual(f.coach_alter_journal("coach.service", 1000, 2700, lambda a: result(row)), 10)

    def test_w2_leer_null_und_health(self):
        for text, reason in (("", "coach_journal_leer"), ('{"MESSAGE":null}', "coach_journal_message_unklar")):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, reason):
                f.coach_alter_journal("coach.service", 1000, 2700, lambda a: result(text))
        self.assertEqual(f.coach_alter_journal("coach.service", 1000, 2700,
                                             lambda a: result('{"MESSAGE":"GET /health"}')), 2700)

    def test_w2_befehle_timeout_10s(self):
        with mock.patch.object(f.subprocess, "run") as run:
            for command in (["journalctl"], ["nvidia-smi"]):
                f.command(command)
                self.assertEqual(run.call_args.kwargs["timeout"], 10)

    def test_k1_fehlende_jobs_nur_explizit_optional(self):
        runner = lambda a: result("LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlPID=0")
        with self.assertRaisesRegex(ValueError, "job_fehlt"):
            f.properties("pflicht.service", runner=runner)
        self.assertFalse(f.properties("alt.service", runner=runner, optional_jobs=["alt.service"]))
        with self.assertRaises(ValueError):
            f.properties("pflicht.service", runner=runner, optional_jobs=["alt.service"])

    def test_k5_user_manager_ohne_pam(self):
        runner = mock.Mock(return_value=result("LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlPID=0"))
        konto = types.SimpleNamespace(pw_uid=1047, pw_gid=1048)
        with mock.patch.object(f.pwd, "getpwnam", return_value=konto):
            f.properties("probe.service", "automation", runner=runner)
        args = runner.call_args.args[0]
        # -M <benutzer>@ scheitert in der gehaerteten Unit (transiente Unit am System-Manager, 06.10.26);
        # setpriv spricht den User-Bus direkt an, ohne PAM-Sitzung.
        self.assertEqual(args[:5], ["/usr/bin/setpriv", "--reuid=1047", "--regid=1048", "--init-groups", "/usr/bin/env"])
        self.assertIn("XDG_RUNTIME_DIR=/run/user/1047", args)
        self.assertEqual(args[args.index("/usr/bin/systemctl"):][:3], ["/usr/bin/systemctl", "--user", "show"])
        self.assertNotIn("-M", args)
        self.assertNotIn("runuser", " ".join(args))

    def test_k7a_konfigfehler_erhalten_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_path = Path
            cfg = dict(SCHLAF, user_jobs=["falsche_form"], log=str(real_path(tmp) / "log"))
            logger = mock.Mock()
            def path(value):
                if str(value) == "/run/greenbuddy/schlaf.lock":
                    return real_path(tmp) / "lock"
                return real_path(value)
            with mock.patch.object(schlaf, "laden", return_value=cfg), \
                    mock.patch.object(schlaf, "Path", side_effect=path), \
                    mock.patch.object(schlaf, "JsonLog", return_value=logger), \
                    mock.patch.object(schlaf, "abgeschaltet", return_value=False), \
                    mock.patch.object(f, "jellyfin", return_value=(False, "jellyfin_unklar")), \
                    mock.patch.object(f, "command", return_value=result("", 1)), \
                    mock.patch.object(f.ET, "parse", side_effect=ValueError("Test")), \
                    mock.patch.object(schlaf, "Sammler") as collector, \
                    mock.patch("sys.argv", ["gb-schlaf", "--einmal"]), contextlib.redirect_stdout(io.StringIO()):
                collector.return_value.sammeln.side_effect = ValueError("user_jobs")
                self.assertEqual(schlaf.main(), 0)
            row = logger.emit.call_args.args[0]
            self.assertEqual((row["entscheidung"], row["grund"]), ("unklar", "konfig_fehler"))
            self.assertFalse(row["ruhe_kandidat"])


class MitschnittReviewTests(unittest.TestCase):
    CFG = {"target": "192.168.1.110", "plex_hash": "abc123"}

    def test_w6_bpf_erfasst_alle_tls_folgesegmente_und_8096_syn(self):
        self.assertIn("8096", bpf(self.CFG["target"]))
        capture = Filter(bpf(self.CFG["target"]))
        self.addCleanup(capture.close)
        for port in (32400, 8443):
            self.assertTrue(capture.accepts(ethernet(clienthello()[40:], port=port)))
            self.assertTrue(capture.accepts(ethernet(b"x" * 1500, port=port)))
            self.assertFalse(capture.accepts(ethernet(port=port)))
        self.assertTrue(capture.accepts(ethernet(syn=True, port=8096)))
        self.assertFalse(capture.accepts(ethernet(b"x", port=22)))
        other = bytearray(ethernet(b"x"))
        other[30:34] = socket.inet_aton("192.168.1.115")
        self.assertFalse(capture.accepts(bytes(other)))

    def test_w6_syn_ohne_puffer_und_ablauf_hoechstens_1hz(self):
        logger = mock.Mock()
        observer = Beobachter(self.CFG, logger)
        with mock.patch("greenbuddy2.mitschnitt.TcpAnfang", wraps=TcpAnfang) as stream, \
                mock.patch.object(observer, "ablaufen", wraps=observer.ablaufen) as expire:
            for i in range(100):
                observer.paket(tcp_packet(ethernet(syn=True)), i / 1000)
            stream.assert_not_called()
            self.assertLessEqual(expire.call_count, 1)
        stream = TcpAnfang(100)
        self.assertEqual(len(stream.buffer) + len(stream.present), 0)
        stream.add(100, b"abc")
        self.assertLess(len(stream.buffer) + len(stream.present), 1024)

    def test_w6_jellyfin_weg4_und_entschiedene_flows_billig(self):
        logger = mock.Mock()
        observer = Beobachter(self.CFG, logger)
        for source in ("192.168.1.9", "10.0.0.9", "198.51.100.9"):
            observer.paket(tcp_packet(ethernet(syn=True, source=source, port=8096)), 1)
        rows = [call.args[0] for call in logger.emit.call_args_list]
        self.assertEqual([row["entscheidung"] for row in rows], ["wuerde_wecken", "wuerde_wecken", "spam"])
        self.assertEqual([row["weg"] for row in rows[:2]], [4, 4])
        with mock.patch("greenbuddy2.mitschnitt.klassifizieren") as classify:
            observer.paket(tcp_packet(ethernet(b"viel_nutzdaten", source="192.168.1.9", port=8096)), 1.1)
            classify.assert_not_called()

    def test_k6_stellvertreter_heartbeat_stuendlich(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log"
            log = JsonLog(path, heartbeat_seconds=3600)
            log.emit({"entscheidung": "beobachten"}, 1, heartbeat=True)
            log.emit({"entscheidung": "beobachten"}, 61, heartbeat=True)
            self.assertEqual(len(path.read_text().splitlines()), 1)
            log.emit({"entscheidung": "unklar"}, 62, heartbeat=True)
            log.emit({"entscheidung": "unklar"}, 3662, heartbeat=True)
            self.assertEqual(len(path.read_text().splitlines()), 3)


class WebhookReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = Path(self.tmp.name) / "secret"
        key.write_text(SECRET)
        key.chmod(0o600)
        self.queue = webhook.Warteschlange(Path(self.tmp.name) / "queue")
        self.addCleanup(self.queue.close)
        self.logger = mock.Mock()
        self.incoming = webhook.Eingang({"secret_file": str(key), "gateway_id": "GATEWAY_ID",
                                       "wake_sender": "ABSENDER_ID", "rate_per_minute": 1},
                                      self.queue, self.logger, clock=lambda: 1000)

    def test_w7_zusatzfelder_und_alte_nachrichten_immer_200(self):
        body = callback() + b"&nickname=Test&optional="
        fields = webhook.pruefen(body, SECRET, "GATEWAY_ID", 1000)
        self.assertNotIn("nickname", fields)
        self.assertTrue(fields["darf_wecken"])
        for stamp in ("1", "1901", "ungueltig"):
            body = callback(now=stamp, message_id=stamp)
            self.assertEqual(self.incoming.annehmen(body, "198.51.100.9")[0], 200)
            self.assertFalse(webhook.pruefen(body, SECRET, "GATEWAY_ID", 1000)["darf_wecken"])
        self.logger.emit.assert_not_called()
        self.assertEqual(len(self.queue.eintraege(1000)), 3)

    def test_w7_frische_grenzen_und_feldlimit(self):
        for stamp, allowed in ((400, True), (399, False), (1030, True), (1031, False)):
            self.assertEqual(webhook.pruefen(callback(now=stamp), SECRET, "GATEWAY_ID", 1000)["darf_wecken"], allowed)
        self.assertTrue(webhook.pruefen(callback() + b"&a=1&b=2&c=3&d=4&e=5", SECRET, "GATEWAY_ID", 1000))
        with self.assertRaises(ValueError):
            webhook.pruefen(callback() + b"&a=1&b=2&c=3&d=4&e=5&f=6", SECRET, "GATEWAY_ID", 1000)

    def test_w7_leeres_datum_angenommen_ohne_weckfreigabe(self):
        self.assertEqual(self.incoming.annehmen(callback(now=""), "198.51.100.9")[0], 200)
        self.assertFalse(self.queue.eintraege(1000)[0]["darf_wecken"])

    def test_w7_frische_verfaellt_waehrend_zustellserie(self):
        for index in range(2):
            self.queue.annehmen(str(index), b"synthetisch", 1000, wecken_bis=1001)
        flags = []
        def send(entry, body, darf_wecken):
            flags.append(darf_wecken)
            return True
        with mock.patch.object(webhook.time, "monotonic", side_effect=[0, 0, 2]):
            self.assertEqual(self.queue.zustellen(send, 1000), 2)
        self.assertEqual(flags, [True, False])

    def test_w8_falsche_mac_verbraucht_keine_gueltige_rate(self):
        for _ in range(3):
            self.assertEqual(self.incoming.annehmen(callback(secret="falsch"), "198.51.100.9")[0], 403)
        self.assertEqual(self.incoming.annehmen(callback(), "198.51.100.9")[0], 200)
        self.assertEqual(self.logger.emit.call_args.args[0]["entscheidung"], "wuerde_wecken")
        # Auch oberhalb des Schattenlimits bleibt ein gültiger Callback angenommen.
        self.assertEqual(self.incoming.annehmen(callback(message_id="zweiter"), "198.51.100.9")[0], 200)
        self.assertEqual(self.logger.emit.call_count, 1)

    def test_w8_wiederholte_fehlmac_billig_drosseln_ohne_gueltige_zu_sperren(self):
        self.incoming.cfg["invalid_rate_per_minute"] = 1
        bad = callback(secret="falsch")
        self.assertEqual(self.incoming.annehmen(bad, "198.51.100.9")[0], 403)
        with mock.patch.object(webhook, "pruefen", wraps=webhook.pruefen) as check:
            self.assertEqual(self.incoming.annehmen(bad, "198.51.100.9")[0], 429)
            check.assert_not_called()
        self.assertEqual(self.incoming.annehmen(callback(), "198.51.100.9")[0], 200)

    def test_w7_gespeicherte_frische_und_upstream_flag(self):
        self.assertEqual(self.incoming.annehmen(callback(), "198.51.100.9")[0], 200)
        self.assertTrue(self.queue.eintraege(1000)[0]["darf_wecken"])
        self.assertFalse(self.queue.eintraege(1601)[0]["darf_wecken"])
        opener = mock.Mock()
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status, response.headers = 200, {"X-GreenBuddy-Quittung": "1"}
        opener.open.return_value = response
        with mock.patch.object(webhook.urllib.request, "build_opener", return_value=opener):
            send = webhook.upstream_sender("http://synthetisch.invalid/threema/incoming")
        self.assertTrue(send(1, b"synthetisch", False))
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("X-greenbuddy-darf-wecken"), "0")

    def test_w8_stille_verbindung_timeout_und_proxy_ip(self):
        self.assertEqual(webhook.handler(self.incoming).timeout, 5)
        self.assertEqual(webhook.client_ip("127.0.0.1", "198.51.100.9"), "198.51.100.9")
        self.assertEqual(webhook.client_ip("192.168.1.9", "198.51.100.9"), "192.168.1.9")
        self.assertEqual(webhook.client_ip("127.0.0.1", "kaputt"), "127.0.0.1")
        self.assertTrue(issubclass(webhook.Server, __import__("socketserver").ThreadingMixIn))

    def test_w8_queue_aus_zwei_threads(self):
        errors = []
        def accept(index):
            try:
                self.queue.annehmen(str(index), b"synthetisch", 1000)
            except Exception as error:
                errors.append(error)
        threads = [threading.Thread(target=accept, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.queue.metriken(1000)["offen"], 2)
