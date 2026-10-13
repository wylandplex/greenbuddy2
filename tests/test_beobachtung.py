"""Fenster, Hostfakten und Schattenentscheidung ohne Hostabfragen testen."""

import datetime as dt
import json
import tempfile
import types
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from greenbuddy2 import __version__
from greenbuddy2 import fakten_vhost as f
from greenbuddy2.fenster import parse, contains, wachfenster, schlafphase, next_wake, trocken, timers_text
from greenbuddy2.konfig import SCHLAF, laden
from greenbuddy2.schlaf import Entscheidung, Uhr
from fixtures import MEDIA, MDSTAT


def result(text="", code=0):
    return types.SimpleNamespace(returncode=code, stdout=text)


class FensterTests(unittest.TestCase):
    def test_mitternacht_und_grenzen(self):
        self.assertTrue(contains(23 * 60, 23 * 60, 3 * 60))
        self.assertTrue(contains(2 * 60, 23 * 60, 3 * 60))
        self.assertFalse(contains(3 * 60, 23 * 60, 3 * 60))
        pairs, lead = parse(MEDIA)
        self.assertTrue(schlafphase(pairs, lead, dt.datetime(2026, 1, 2, 12)))
        self.assertFalse(schlafphase(pairs, lead, dt.datetime(2026, 1, 2, 16, 25)))
        self.assertIn("NAS_NACHT_WINDOW", wachfenster(pairs, lead, dt.datetime(2026, 1, 2, 1)))

    def test_fehlende_schluessel_unklar(self):
        for key in ("WACH_MORGEN_START", "WACH_MORGEN_END", "WACH_ABEND_START", "TAGSCHLAF_END", "VORLAUF_MIN"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                parse("\n".join(line for line in MEDIA.splitlines() if not line.startswith(key + "=")))

    def test_ungueltige_und_doppelte_werte(self):
        for text in (MEDIA + 'VORLAUF_MIN=5\n', MEDIA.replace('06:00', '25:00'), MEDIA.replace('VORLAUF_MIN=5', 'VORLAUF_MIN=999')):
            with self.assertRaises(ValueError):
                parse(text)

    def test_naechster_wecker(self):
        pairs, lead = parse(MEDIA)
        now = dt.datetime(2026, 1, 2, 12).timestamp()
        self.assertEqual(next_wake(pairs, lead, now), dt.datetime(2026, 1, 2, 16, 25).timestamp())

    def test_timer_json_und_fallback(self):
        at = dt.datetime(2026, 1, 2, 12).timestamp()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "media.conf"
            path.write_text(MEDIA)
            runner = mock.Mock(return_value=result(json.dumps([{"unit": "probe.timer", "next": int(at * 1e6)}])))
            self.assertEqual(trocken(path, runner, at)["timer_in_schlafphase"][0]["unit"], "probe.timer")
            runner = mock.Mock(side_effect=[result("", 1), result("Fri 2026-01-02 12:00:00 UTC 5h left - - probe.timer probe.service\n")])
            row = trocken(path, runner, at)
            self.assertEqual(runner.call_count, 2)
            self.assertEqual(row["aktion"], "trockenpruefung")
            self.assertTrue(all("rtcwake" not in args[0][0] for args in runner.call_args_list))
        self.assertEqual(timers_text("- - - - inaktiv.timer inaktiv.service\n"), [])


class FaktenTests(unittest.TestCase):
    def test_mdstat_imsm(self):
        vetos, arrays = f.mdstat(MDSTAT)
        self.assertEqual(vetos, ["raid_degradiert"])
        self.assertEqual(arrays, [{"name": "md126", "soll": 4, "ist": 2}])
        for action in ("resync", "recovery", "check", "reshape"):
            self.assertIn("raid_aktion", f.mdstat(MDSTAT.replace('[4/2]', '[4/4]') + action + ' = 1%\n')[0])
        self.assertEqual(f.mdstat(MDSTAT.replace('[4/2]', '[4/4]'))[0], [])

    def test_mdstat_fehlend(self):
        with self.assertRaises(ValueError):
            f.mdstat("Personalities : [raid10]\nunused devices: <none>")

    def test_loginctl_spalten(self):
        rows = f.loginctl_list("3 1000 test seat0 active no\n7 1001 test online no\n8 1001 test closing yes\n")
        self.assertEqual([r["state"] for r in rows], ["active", "online", "closing"])
        self.assertTrue(f.loginctl_remote("Remote=yes\nType=tty\nState=active"))
        self.assertTrue(f.loginctl_remote("Remote=yes\nType=tty\nState=online"))
        self.assertFalse(f.loginctl_remote("Remote=yes\nType=tty\nState=closing"))
        self.assertFalse(f.loginctl_remote("Remote=no\nType=tty\nState=active"))
        with self.assertRaises(ValueError):
            f.loginctl_list("3 1000 test unbekannt no")

    def test_jellyfin_401_unklar(self):
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.HTTPError("http://127.0.0.1", 401, "Test", {}, None)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "key"
            path.write_text("testtoken")
            path.chmod(0o600)
            self.assertEqual(f.jellyfin(path, opener), (False, "jellyfin_unklar"))
            request = opener.open.call_args[0][0]
            self.assertEqual(request.full_url, "http://127.0.0.1:8096/Sessions")
            self.assertNotIn("testtoken", request.full_url)
            path.unlink()
            self.assertEqual(f.jellyfin(path, opener), (False, "jellyfin_unklar"))

    def test_minecraft_scanner_kein_signal(self):
        self.assertFalse(f.minecraft([["/usr/bin/lazymc", "start"]], connections=7))
        self.assertTrue(f.minecraft([["/usr/bin/java", "-jar", "server.jar"]], connections=0))
        self.assertFalse(f.minecraft([["python3", "probe.jar"]]))

    def test_claude_laeufe(self):
        for args in (["bash", "/opt/run-task.sh"], ["node", "/usr/bin/claude", "-p", "Test"], ["claude", "--print"]):
            self.assertTrue(f.claude_laeuft([args]))
        self.assertFalse(f.claude_laeuft([["claude", "--help"]]))

    def test_plex_container_alle_listen(self):
        row = {"MediaContainer": {"size": 3, "Device": [{}], "Account": [{}], "StatisticsBandwidth": [{}]}}
        self.assertEqual(f.container(row, "StatisticsBandwidth"), [{}])
        row["MediaContainer"]["size"] = 2
        with self.assertRaises(ValueError):
            f.container(row, "StatisticsBandwidth")

    def test_bandwidth_alter_bucket_und_reset(self):
        # beta.2: Nutzung nur über die Bytesumme je Triple in 180 s, nicht über Wachstum.
        cfg, now = {"self_triples": [], "bandbreite_schwelle_bytes": 1000}, 10000
        row = {"at": 100, "accountID": 1, "deviceID": 2, "bytes": 50, "lan": True}
        signal, old, _, reset = f.bandwidth([row], {}, cfg, now)
        self.assertFalse(signal)
        self.assertFalse(reset)
        row["bytes"] += 5000
        signal, old, sources, reset = f.bandwidth([row], old, cfg, now)
        self.assertFalse(signal)
        row["bytes"] = 1
        self.assertTrue(f.bandwidth([row], old, cfg, now)[3])
        row["at"], row["bytes"] = now, 1000
        signal, _, sources, _ = f.bandwidth([row], {}, cfg, now)
        self.assertTrue(signal)
        self.assertEqual(sources, [[1, 2, True]])
        self.assertFalse(f.bandwidth([row], {}, dict(cfg, self_triples=[[1, 2, True]]), now)[0])

    def test_properties_fehler_und_aktive_pid(self):
        inactive = "LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlPID=0"
        self.assertFalse(f.properties("test.service", runner=lambda args: result(inactive)))
        self.assertTrue(f.properties("test.service", runner=lambda args: result(inactive.replace('MainPID=0', 'MainPID=5'))))
        with self.assertRaises(ValueError):
            f.properties("test.service", runner=lambda args: result(inactive, 1))

    def test_ansprueche_und_coach(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "anspruch.json"
            path.write_text(json.dumps({"host": "vhost01", "dienst": "test", "besitzer": "test", "zyklus": "z1", "ablauf": 100}))
            self.assertEqual(f.ansprueche(tmp, 50)[0], ["anspruch"])
            self.assertEqual(f.ansprueche(tmp, 101)[0], [])
            path.write_text("kaputt")
            self.assertEqual(f.ansprueche(tmp, 50)[1], ["anspruch_unklar"])
            path.unlink()
            log = Path(tmp) / "caddy.jsonl"
            log.write_text(json.dumps({"ts": 50, "request": {"headers": {"User-Agent": ["ThreemaGateway"]}}}) + '\n')
            self.assertEqual(f.coach_alter(log, 60), 10)
            log.write_text(json.dumps({"ts": 50, "request": {"headers": {"User-Agent": ["ThreemaGateway/1.0"]}}}) + '\n')
            self.assertEqual(f.coach_alter(log, 60), 10)

    def test_coach_aus_journal(self):
        # Caddy loggt im Konsolenformat ins Journal eines Benutzer-Managers
        def zeile(sekunden, ua):
            return json.dumps({"__REALTIME_TIMESTAMP": str(sekunden * 1000000), "MESSAGE":
                               'INFO http.log.access handled request {"request":{"headers":{"User-Agent":["%s"]}}}' % ua})
        rows = "\n".join([zeile(999900, "ThreemaGateway/1.0"), zeile(999950, "curl/8.0")])
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            return result(rows)
        self.assertEqual(f.coach_alter_journal("bot-caddy.service", 1000000, 2700, runner), 100)
        self.assertIn("_SYSTEMD_USER_UNIT=bot-caddy.service", calls[0])
        self.assertIn("--since=@997300", calls[0])

    def test_coach_journal_ohne_eintrag_ist_unklar(self):
        with self.assertRaisesRegex(ValueError, "coach_journal_leer"):
            f.coach_alter_journal("bot-caddy.service", 1000000, 2700, lambda a, **k: result(""))

    def test_coach_journal_fehler_ist_unklar(self):
        with self.assertRaises(ValueError):
            f.coach_alter_journal("bot-caddy.service", 1000000, 2700, lambda a, **k: result("", 1))

    def test_sammler_fail_safe(self):
        cfg = dict(SCHLAF, ansprueche="/nicht/vorhanden")
        def runner(args, **kwargs):
            if args[:2] == ["loginctl", "list-sessions"]:
                return result("1 1000 test closing yes")
            return result("", 1)
        with mock.patch.object(f, "jellyfin", return_value=(False, "jellyfin_unklar")), mock.patch.object(Path, "read_text", return_value=MDSTAT), mock.patch.object(f.ET, "parse", side_effect=ValueError('Synthetischer Fehler')):
            data = f.Sammler(cfg, runner=runner, proc=lambda: [["lazymc"]]).sammeln(100)
        self.assertIn("raid_degradiert", data["vetos"])
        self.assertIn("gpu_unklar", data["unklar"])
        self.assertIn("jellyfin_unklar", data["unklar"])
        self.assertNotIn("minecraft", data["nutzung"])
        self.assertNotIn("ssh_remote", data["vetos"])


class EntscheidungTests(unittest.TestCase):
    def test_niemals_schlafen(self):
        clean = {"unklar": [], "vetos": [], "nutzung": [], "fakten": {}}
        decision = Entscheidung()
        self.assertFalse(decision.entscheiden(clean, 0)["ruhe_kandidat"])
        row = decision.entscheiden(clean, 2700)
        self.assertTrue(row["ruhe_kandidat"])
        self.assertFalse(row["dependencies_verified"])
        for facts, unknown in ((clean, []), (dict(clean, nutzung=["plex"]), []), (dict(clean, vetos=["raid_degradiert"]), []), (clean, ["zeitfenster_unklar"])):
            self.assertNotEqual(decision.entscheiden(facts, 3000, unknown=unknown)["entscheidung"], "schlafen")
        self.assertEqual(decision.entscheiden({}, 4000, disabled=True)["entscheidung"], "abgeschaltet")

    def test_uhr_resume_kein_sprung(self):
        clock = Uhr()
        clock.pruefen(1000, 100, 100)
        unknown, veto = clock.pruefen(4600, 3700, 101)
        self.assertEqual(unknown, [])
        self.assertEqual(veto, ["mindestwachzeit"])
        self.assertTrue(clock.resumed)
        # beta.2: zehn Minuten Mindestwachzeit nach Start/Resume.
        self.assertEqual(clock.pruefen(4900, 4000, 401), ([], ["mindestwachzeit"]))
        self.assertFalse(clock.resumed)
        self.assertEqual(clock.pruefen(5200, 4300, 701), ([], []))

    def test_echter_uhrsprung(self):
        clock = Uhr()
        clock.pruefen(1000, 100, 100)
        self.assertIn("uhrsprung", clock.pruefen(2000, 160, 160)[0])
        self.assertIn("uhrsprung", clock.pruefen(2060, 220, 220)[0])
        self.assertEqual(clock.pruefen(4700, 2860, 2860)[0], [])

    def test_version_und_freigabe_ueberschrieben(self):
        self.assertEqual(__version__, "2.0.0b6")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.json"
            path.write_text('{"dependencies_verified":true}')
            self.assertFalse(laden(path, SCHLAF)["dependencies_verified"])
