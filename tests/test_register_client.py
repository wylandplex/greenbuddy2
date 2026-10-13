"""Register-Client vhost01 → proxy01: exakte SSH-argv, Frist, strikte Antwortprüfung. Nie echtes ssh."""

import json
import subprocess
import time
import types
import unittest
from unittest import mock

from greenbuddy2 import register_client as rc
from greenbuddy2.fakten_vhost import command

ARGV = ["ssh", "-i", "/etc/greenbuddy/ssh/id_ed25519", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/etc/greenbuddy/ssh/known_hosts",
        "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
        "-T", "gb-register@192.168.1.100"]
PHASE = {"abmelden": "abgemeldet", "schlafe-jetzt": "schlaf_absicht", "anmelden": "angemeldet",
         "anmelden-abbruch": "angemeldet"}
WECKUNG = {"zeit": 1767360000.5, "weg": "syn", "port": 22, "quellklasse": "VPN", "entscheidung": "wecken"}


def result(text="", code=0):
    return types.SimpleNamespace(returncode=code, stdout=text)


def antwort(befehl="abmelden", zyklus="z1", **felder):
    row = {"host": "vhost01", "bereit": True,
           "zustand": {"zyklus": zyklus, "phase": PHASE[befehl], "ablauf": 1.5, "nachfrage": 0}}
    if befehl == "anmelden":
        row["weckung"] = None
    row.update(felder)
    return result(json.dumps(row) + "\n")


class Runner:
    """Fake-Runner: protokolliert argv und Schlüsselwörter, liefert vorbereitete Antworten."""

    def __init__(self, *antworten):
        self.antworten, self.calls = list(antworten), []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        value = self.antworten.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


class AufrufTests(unittest.TestCase):
    def test_argv_exakt_und_gesamtfrist(self):
        runner = Runner(antwort())
        rc.Register(None, runner).abmelden("z1")
        self.assertEqual(runner.calls, [(ARGV + ["abmelden z1"], {"timeout": 20})])

    def test_alle_befehle(self):
        runner = Runner(antwort("schlafe-jetzt"), antwort("anmelden"), antwort("anmelden-abbruch"))
        register = rc.Register(None, runner)
        self.assertIsNone(register.schlafe_jetzt("z1", 900))
        self.assertIsNone(register.anmelden("z1"))
        self.assertIsNone(register.anmelden_abbruch("z1"))
        self.assertEqual([c[0][-1] for c in runner.calls],
                         ["schlafe-jetzt z1 900", "anmelden z1", "anmelden-abbruch z1"])
        self.assertTrue(all(c[0][:-1] == ARGV and c[1] == {"timeout": 20} for c in runner.calls))

    def test_status_nur_lesend(self):
        # Live-Probe ohne Zustandsänderung: ohne Zyklus, jede Phase, bereit darf false sein.
        row = {"host": "vhost01", "bereit": False, "grund": "beta1_nur_register", "zustand": {"phase": "unbekannt"},
               "stellvertreter": {}}
        runner = Runner(result(json.dumps(row) + "\n"))
        self.assertEqual(rc.Register(None, runner).status(), row)
        self.assertEqual(runner.calls, [(ARGV + ["status"], {"timeout": 20})])
        row["zustand"] = {"zyklus": "alt", "phase": "schlaf_absicht"}
        self.assertEqual(rc.Register(None, Runner(result(json.dumps(row)))).status()["zustand"]["zyklus"], "alt")
        for value in (result(json.dumps(dict(row, host="nas01"))), result(json.dumps(dict(row, zustand=None))),
                      result("", 255)):
            with self.subTest(value=value), self.assertRaises(rc.StellvertreterUnklar):
                rc.Register(None, Runner(value)).status()
        with self.assertRaises(rc.StellvertreterNichtBereit):
            rc.Register(None, Runner(result('{"bereit": false, "fehler": "befehl_oder_register_ungueltig"}', 1))).status()

    def test_eigene_konfiguration(self):
        cfg = {"stellvertreter_ziel": "gbtest@192.0.2.7", "stellvertreter_schluessel": "/srv/test/schluessel",
               "stellvertreter_known_hosts": "/srv/test/hosts", "mode": "aktiv"}
        runner = Runner(antwort())
        rc.Register(cfg, runner).abmelden("z1")
        argv = runner.calls[0][0]
        self.assertEqual(argv[1:3], ["-i", "/srv/test/schluessel"])
        self.assertIn("UserKnownHostsFile=/srv/test/hosts", argv)
        self.assertEqual(argv[-2:], ["gbtest@192.0.2.7", "abmelden z1"])

    def test_standardrunner_mit_frist(self):
        self.assertIs(rc.Register().runner, command)
        self.assertEqual(rc.FRIST_S, 20)

    def test_frist_greift_wirklich(self):
        # Echter Kindprozess ohne Netz: die Frist muss ihn beenden, nicht der Takt.
        def runner(argv, timeout):
            return command(["sleep", "5"], timeout=timeout)
        start = time.monotonic()
        with mock.patch.object(rc, "FRIST_S", 0.3), self.assertRaises(rc.StellvertreterUnklar) as fehler:
            rc.Register(None, runner).abmelden("z1")
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(fehler.exception.detail, "frist")

    def test_runner_ausnahmen_sind_unklar(self):
        for ausnahme, detail in ((subprocess.TimeoutExpired(["ssh"], 20), "frist"),
                                 (FileNotFoundError("ssh"), "ssh_start"), (OSError("Test"), "ssh_start")):
            with self.subTest(detail=detail), self.assertRaises(rc.StellvertreterUnklar) as fehler:
                rc.Register(None, Runner(ausnahme)).abmelden("z1")
            self.assertEqual(str(fehler.exception), "stellvertreter_unklar")
            self.assertEqual(fehler.exception.grund, "stellvertreter_unklar")
            self.assertEqual(fehler.exception.detail, detail)

    def test_zyklus_und_sekunden_vor_dem_aufruf_geprueft(self):
        for zyklus in ("", "a b", "z" * 129, "z;id", "z\n", None, 5, "zä"):
            with self.subTest(zyklus=zyklus):
                runner = Runner()
                with self.assertRaises(rc.StellvertreterUnklar):
                    rc.Register(None, runner).abmelden(zyklus)
                with self.assertRaises(rc.StellvertreterUnklar):
                    rc.Register(None, runner).anmelden(zyklus)
                self.assertEqual(runner.calls, [])
        self.assertTrue(rc.re.fullmatch(rc.ZYKLUS, "A-z_09" * 21 + "ab"))
        for sekunden in (599, 43201, 900.0, True, "900", None, -1):
            with self.subTest(sekunden=sekunden):
                runner = Runner()
                with self.assertRaises(rc.StellvertreterUnklar):
                    rc.Register(None, runner).schlafe_jetzt("z1", sekunden)
                self.assertEqual(runner.calls, [])
        runner = Runner(antwort("schlafe-jetzt"), antwort("schlafe-jetzt"))
        rc.Register(None, runner).schlafe_jetzt("z1", 600)
        rc.Register(None, runner).schlafe_jetzt("z1", 43200)
        self.assertEqual([c[0][-1] for c in runner.calls], ["schlafe-jetzt z1 600", "schlafe-jetzt z1 43200"])

    def test_konfigfehler_ruft_nichts_auf(self):
        runner = Runner()
        with self.assertRaises(rc.StellvertreterUnklar) as fehler:
            rc.Register({"stellvertreter_ziel": "-oProxyCommand=id"}, runner).abmelden("z1")
        self.assertEqual(fehler.exception.detail, "konfig_ungueltig")
        self.assertEqual(runner.calls, [])

    def test_sekunden_bis_weckzeit(self):
        self.assertEqual(rc.sekunden_bis(10000.9, 1000), 9000)
        # Zwischen Schlussprüfung und schlafe-jetzt vergangene Sekunden: proxy01 verlangt mindestens 600.
        self.assertEqual(rc.sekunden_bis(1590, 1000), 600)
        self.assertEqual(rc.sekunden_bis(1000 + 50000, 1000), 43200)


class AntwortTests(unittest.TestCase):
    def aufruf(self, befehl, value, zyklus="z1"):
        register = rc.Register(None, Runner(value))
        if befehl == "schlafe-jetzt":
            return register.schlafe_jetzt(zyklus, 900)
        return getattr(register, befehl.replace("-", "_"))(zyklus)

    def assertUnklar(self, befehl, value):
        with self.assertRaises(rc.StellvertreterUnklar) as fehler:
            self.aufruf(befehl, value)
        self.assertEqual(str(fehler.exception), "stellvertreter_unklar")
        return fehler.exception

    def test_erfolg_je_befehl(self):
        for befehl in PHASE:
            with self.subTest(befehl=befehl):
                self.assertIsNone(self.aufruf(befehl, antwort(befehl)))

    def test_zeilenende_optional(self):
        text = antwort().stdout.rstrip("\n")
        self.assertIsNone(self.aufruf("abmelden", result(text)))

    def test_nicht_bereit_mit_grund(self):
        for befehl in ("abmelden", "schlafe-jetzt"):
            with self.subTest(befehl=befehl):
                with self.assertRaises(rc.StellvertreterNichtBereit) as fehler:
                    self.aufruf(befehl, antwort(befehl, bereit=False, grund="dienst_aus"))
                self.assertEqual(str(fehler.exception), "stellvertreter_nicht_bereit:dienst_aus")
                self.assertEqual(fehler.exception.grund, "stellvertreter_nicht_bereit:dienst_aus")
                self.assertIsInstance(fehler.exception, rc.StellvertreterFehler)

    def test_fehlerantwort_mit_exit_1(self):
        value = result('{"bereit": false, "fehler": "zyklus_bereits_aktiv"}\n', 1)
        for befehl in PHASE:
            with self.subTest(befehl=befehl), self.assertRaises(rc.StellvertreterNichtBereit) as fehler:
                self.aufruf(befehl, value)
            self.assertEqual(str(fehler.exception), "stellvertreter_nicht_bereit:zyklus_bereits_aktiv")
        # Auch mit Exit 0 ist "fehler" kein Erfolg.
        with self.assertRaises(rc.StellvertreterNichtBereit):
            self.aufruf("anmelden", result('{"bereit": false, "fehler": "befehl_oder_register_ungueltig"}\n'))

    def test_bereit_false_beim_anmelden_ist_kein_fehler(self):
        # anmelden beendet den Zyklus; ob proxy01 für den nächsten Schlaf bereit ist, zählt hier nicht.
        self.assertIsNone(self.aufruf("anmelden", antwort("anmelden", bereit=False, grund="dienst_aus")))
        self.assertIsNone(self.aufruf("anmelden-abbruch", antwort("anmelden-abbruch", bereit=False)))

    def test_exitcode_ohne_fehlerform_ist_unklar(self):
        for value in (result("", 255), result("Permission denied (publickey).\n", 255),
                      result('{"bereit": false}\n', 1), result('{"bereit": true, "fehler": "x"}\n', 1),
                      result(antwort().stdout, 1), result('{"bereit": false, "fehler": "a b"}\n', 1),
                      result('{"bereit": false, "fehler": 5}\n', 1), result("", -9)):
            with self.subTest(value=value):
                exc = self.assertUnklar("abmelden", value)
                if value.stdout == "":
                    self.assertTrue(exc.detail.startswith("exit_"))

    def test_formfehler_der_zeile(self):
        gut = antwort().stdout
        for value in (result(""), result("\n"), result(gut + gut), result(gut.rstrip("\n") + "\r\n"),
                      result("ok\n"), result("[]\n"), result('"abgemeldet"\n'), result("null\n"),
                      result(gut.replace("1.5", "NaN")), result(gut.replace("1.5", "Infinity")),
                      result(" " * 70000 + gut), result(None), result(gut.encode())):
            with self.subTest(value=repr(value.stdout)[:40]):
                self.assertUnklar("abmelden", value)

    def test_schemafehler(self):
        faelle = (
            {"host": "nas01"}, {"host": None}, {"host": 5},
            {"bereit": "true"}, {"bereit": 1}, {"bereit": None},
            {"zustand": None}, {"zustand": []}, {"zustand": {"zyklus": "z1"}},
            {"zustand": {"zyklus": "z1", "phase": 5}}, {"zustand": {"zyklus": "z1", "phase": "angemeldet"}},
            {"zustand": {"zyklus": "anders", "phase": "abgemeldet"}},
            {"zustand": {"zyklus": 5, "phase": "abgemeldet"}},
            {"bereit": False}, {"bereit": False, "grund": 5}, {"bereit": False, "grund": ""},
            {"bereit": False, "grund": "mit leerzeichen"}, {"bereit": False, "grund": "x" * 81},
            {"bereit": False, "grund": "zeile\nzwei"},
        )
        for felder in faelle:
            with self.subTest(felder=felder):
                self.assertUnklar("abmelden", antwort(**felder))
        row = json.loads(antwort().stdout)
        del row["host"]
        self.assertUnklar("abmelden", result(json.dumps(row)))
        for key in ("bereit", "zustand"):
            row = json.loads(antwort().stdout)
            del row[key]
            with self.subTest(fehlt=key):
                self.assertUnklar("abmelden", result(json.dumps(row)))
        # Ohne Zyklus im Zustand genügt die Phase.
        row = json.loads(antwort().stdout)
        del row["zustand"]["zyklus"]
        self.assertIsNone(self.aufruf("abmelden", result(json.dumps(row))))

    def test_phase_muss_zum_befehl_passen(self):
        for befehl, falsch in (("abmelden", "schlaf_absicht"), ("schlafe-jetzt", "abgemeldet"),
                               ("anmelden", "schlaf_absicht"), ("anmelden-abbruch", "lease_abgelaufen")):
            with self.subTest(befehl=befehl):
                exc = self.assertUnklar(befehl, antwort(befehl, zustand={"zyklus": "z1", "phase": falsch}))
                self.assertEqual(exc.detail, "antwort_phase")

    def test_weckung_wird_geprueft_und_gekuerzt(self):
        mehr = dict(WECKUNG, quell_ip="198.51.100.9", zyklus="z1")
        self.assertEqual(self.aufruf("anmelden", antwort("anmelden", weckung=mehr)), WECKUNG)
        ohne_port = dict(WECKUNG, port=None, weg="lease", zeit=1767360000)
        self.assertEqual(self.aufruf("anmelden", antwort("anmelden", weckung=ohne_port)), ohne_port)
        self.assertIsNone(self.aufruf("anmelden", antwort("anmelden", weckung=None)))

    def test_weckung_in_der_form_von_proxy01(self):
        # Weg-Nummer 4/5/7; ohne Nachfrage (Lease-Ablauf) sind weg, port und quellklasse null.
        for weckung in (dict(WECKUNG, weg=4), dict(WECKUNG, weg=7, port=32400, quellklasse="WAN"),
                        {"zeit": 1767360000.5, "weg": None, "port": None, "quellklasse": None,
                         "entscheidung": "lease_abgelaufen"}):
            with self.subTest(weckung=weckung):
                self.assertEqual(self.aufruf("anmelden", antwort("anmelden", weckung=weckung)), weckung)

    def test_weckung_formfehler(self):
        faelle = ["x", [], 5, {}]
        for key in WECKUNG:
            faelle.append({k: v for k, v in WECKUNG.items() if k != key})
        for key, value in (("zeit", "jetzt"), ("zeit", True), ("zeit", None), ("port", "22"), ("port", 0),
                           ("port", 65536), ("port", True), ("port", 22.0), ("weg", 0), ("weg", 100),
                           ("weg", True), ("weg", 4.0), ("weg", ""), ("quellklasse", ""),
                           ("quellklasse", 3), ("quellklasse", "x" * 65), ("entscheidung", None),
                           ("entscheidung", ["wecken"])):
            faelle.append(dict(WECKUNG, **{key: value}))
        for weckung in faelle:
            with self.subTest(weckung=weckung):
                self.assertUnklar("anmelden", antwort("anmelden", weckung=weckung))
        row = json.loads(antwort("anmelden").stdout)
        del row["weckung"]
        self.assertUnklar("anmelden", result(json.dumps(row)))
        # anmelden-abbruch braucht keine Weckinfo.
        self.assertIsNone(self.aufruf("anmelden-abbruch", result(json.dumps(dict(row, zustand={"phase": "angemeldet"})))))


class EinstellungenTests(unittest.TestCase):
    def test_standardwerte(self):
        self.assertEqual(rc.einstellungen(None), {
            "stellvertreter_ziel": "gb-register@192.168.1.100",
            "stellvertreter_schluessel": "/etc/greenbuddy/ssh/id_ed25519",
            "stellvertreter_known_hosts": "/etc/greenbuddy/ssh/known_hosts",
            "stellvertreter_pflicht": True})
        self.assertEqual(rc.einstellungen({"mode": "aktiv", "log": "/x"}), rc.einstellungen({}))
        self.assertIs(rc.einstellungen({"stellvertreter_pflicht": False})["stellvertreter_pflicht"], False)

    def test_formfehler(self):
        for key, value in (("stellvertreter_ziel", "-oProxyCommand=id"), ("stellvertreter_ziel", "192.168.1.100"),
                           ("stellvertreter_ziel", "gb register@192.168.1.100"),
                           ("stellvertreter_ziel", "gb-register@-oProxyCommand=id"),
                           ("stellvertreter_ziel", "gb-register@"), ("stellvertreter_ziel", ""),
                           ("stellvertreter_ziel", None), ("stellvertreter_ziel", "gb-register@host\n"),
                           ("stellvertreter_schluessel", "etc/greenbuddy/ssh/id_ed25519"),
                           ("stellvertreter_schluessel", "/etc/green buddy/id"),
                           ("stellvertreter_schluessel", "/etc/%d/id"), ("stellvertreter_schluessel", "/etc/../id"),
                           ("stellvertreter_schluessel", ""), ("stellvertreter_schluessel", 5),
                           ("stellvertreter_known_hosts", "/a /b"), ("stellvertreter_known_hosts", None),
                           ("stellvertreter_known_hosts", "/x\n"),
                           ("stellvertreter_pflicht", "true"), ("stellvertreter_pflicht", 1),
                           ("stellvertreter_pflicht", None)):
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "konfig_ungueltig"):
                rc.einstellungen({key: value})


if __name__ == "__main__":
    unittest.main()
