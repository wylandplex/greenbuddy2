"""Aktiver Schlaf (beta.2): jede Schutzprüfung verhindert den Suspend. Keine echten Befehle."""

import contextlib
import copy
import datetime as dt
import io
import json
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from greenbuddy2 import aktiv, fakten_vhost as f, register_client, schlaf
from greenbuddy2.fenster import parse
from greenbuddy2.konfig import SCHLAF, laden
from greenbuddy2.schlaf import Entscheidung, Uhr, Waechter
from fixtures import MEDIA, MDSTAT

CLEAN = {"unklar": [], "vetos": [], "nutzung": [], "fakten": {}}
WAKEUP = "/sys/class/net/eno1/device/power/wakeup"
RTC_WAKEUP = "/sys/class/rtc/rtc0/device/power/wakeup"
FREMDE_UNITS = ("auto-sleep.timer", "auto-sleep.service", "delay-after-suspend.service")


def fremde(**zustand):
    """systemctl-show-Antwort für die Gen-0-Schläfer; Standard: nicht vorhanden."""
    blocks = []
    for unit in FREMDE_UNITS:
        load, active = zustand.get(unit, ("not-found", "inactive"))
        blocks.append("Id=%s\nLoadState=%s\nActiveState=%s\n" % (unit, load, active))
    return "\n".join(blocks)


def result(text="", code=0):
    return types.SimpleNamespace(returncode=code, stdout=text)


SSH = ["ssh", "-i", "/etc/greenbuddy/ssh/id_ed25519", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
       "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/etc/greenbuddy/ssh/known_hosts",
       "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
       "-T", "gb-register@192.168.1.100"]
WECKUNG = {"zeit": 1767360000, "weg": "syn", "port": 32400, "quellklasse": "LAN", "entscheidung": "wecken"}


def register_antwort(befehl, zyklus, bereit=True, grund=None, weckung=None):
    """Antwortzeile des Zwangsbefehls auf proxy01 (Plan 2026-10-12, Abschnitt 4)."""
    phase = {"abmelden": "abgemeldet", "schlafe-jetzt": "schlaf_absicht"}.get(befehl, "angemeldet")
    row = {"host": "vhost01", "bereit": bereit, "zustand": {"zyklus": zyklus, "phase": phase}}
    if grund:
        row["grund"] = grund
    if befehl == "anmelden":
        row["weckung"] = weckung
    return result(json.dumps(row) + "\n")


def lokal(*args):
    return dt.datetime(*args).timestamp()


class Logger:
    def __init__(self, ok=True):
        self.rows, self.ok = [], ok

    def emit(self, row, now=None, heartbeat=False):
        self.rows.append(dict(row))
        return self.ok


class Sammler:
    def __init__(self):
        self.facts = copy.deepcopy(CLEAN)
        self.calls = 0
        self.danach = None

    def sammeln(self, now):
        self.calls += 1
        if self.danach and self.calls > 1:
            return copy.deepcopy(self.danach)
        return copy.deepcopy(self.facts)


class Befehle:
    """Fake-Ausführung: protokolliert argv, führt nie etwas aus."""

    def __init__(self):
        self.calls = []
        self.antworten = {
            "rtcwake": result(""),
            "CanSuspend": result('{"type":"s","data":["yes"]}'),
            "ListInhibitors": result('{"type":"a(ssssuu)","data":[[["sleep","NetworkManager","Netz","delay",0,812]]]}'),
            "suspend": result(""),
            "disable": result(""),
            "fremde": result(fremde()),
        }
        self.wakealarm = None
        self.wakeup = "enabled\n"
        self.rtc_wakeup = "enabled\n"
        # Register-Antworten je Befehl: Ergebnis, Ausnahme, Funktion(zyklus) oder Liste davon (der Reihe nach).
        self.register = {}
        self.fristen = []

    def antwort_register(self, befehl, zyklus):
        value = self.register.get(befehl)
        if isinstance(value, list):
            value = value.pop(0) if value else None
        if isinstance(value, BaseException):
            raise value
        if callable(value):
            return value(zyklus)
        return value or register_antwort(befehl, zyklus)

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if args[0] == "ssh":
            if args[:-1] != SSH:
                raise AssertionError("unerwartete ssh-argv %r" % (args,))
            self.fristen.append(kwargs.get("timeout"))
            teile = args[-1].split()
            return self.antwort_register(teile[0], teile[1])
        if args[0] == "rtcwake" and "disable" in args:
            return self.antworten["disable"]
        if args[0] == "rtcwake":
            self.wakealarm = args[args.index("-t") + 1]
            return self.antworten["rtcwake"]
        if args[0] == "busctl":
            return self.antworten[args[-1]]
        if args[:2] == ["systemctl", "suspend"]:
            if isinstance(self.antworten["suspend"], Exception):
                raise self.antworten["suspend"]
            return self.antworten["suspend"]
        if args[:2] == ["systemctl", "show"]:
            return self.antworten["fremde"]
        raise AssertionError("unerwarteter Befehl %r" % (args,))

    def lesen(self, path):
        if path in (WAKEUP, RTC_WAKEUP):
            value = self.wakeup if path == WAKEUP else self.rtc_wakeup
            if isinstance(value, Exception):
                raise value
            return value
        self.assert_path = path
        if self.wakealarm is None:
            return "\n"
        return self.wakealarm + "\n"

    def suspendiert(self):
        return any(c[:2] == ["systemctl", "suspend"] for c in self.calls)

    def ssh(self):
        """Entfernte Befehle in Reihenfolge, z. B. ["abmelden", "<zyklus>"]."""
        return [c[-1].split() for c in self.calls if c[0] == "ssh"]

    def ablauf(self):
        """Kurzform aller Aufrufe: rtcwake, busctl-Methode, "systemctl show", Register-Befehl."""
        return [c[-1].split()[0] if c[0] == "ssh" else c[-1] if c[0] == "busctl"
                else "rtcwake disable" if c[0] == "rtcwake" and "disable" in c
                else " ".join(c[:2]) if c[0] == "systemctl" else c[0] for c in self.calls]


class Umgebung:
    """Ein vollständig freigegebener Aktivbetrieb in einem Tempverzeichnis."""

    START = lokal(2026, 1, 2, 11, 15)

    def __init__(self, tmp, **cfg):
        base = Path(tmp)
        (base / "media.conf").write_text(MEDIA)
        self.cfg = dict(SCHLAF, mode="aktiv", dependencies_verified=True, media_conf=str(base / "media.conf"),
                        zustand=str(base / "zustand.json"), aus=str(base / "aus"), wol_interface="eno1",
                        log=str(base / "log.jsonl"), takt_stempel=str(base / "takt.json"))
        self.cfg.update(cfg)
        self.logger, self.sammler, self.befehle = Logger(), Sammler(), Befehle()
        self.boot_id = "abcdef01-2345-4678-89ab-cdef01234567"
        self.waechter = self.neu()

    def neu(self, aktiv_flag=None):
        flag = (self.cfg["mode"] == "aktiv" and self.cfg["dependencies_verified"] is True
                if aktiv_flag is None else aktiv_flag)
        w = Waechter(self.cfg, self.logger, self.sammler, Uhr(), Entscheidung(self.cfg["idle_seconds"], flag),
                     zustand=aktiv.Zustand(self.cfg["zustand"], self.boot_id) if flag else None,
                     ausfuehrung=aktiv.Ausfuehrung(self.befehle, self.befehle.lesen) if flag else None)
        self.zeit = None
        w.zeit = lambda: self.zeit
        w.monoton = lambda: w.takt_start
        return w

    def takt(self, wall, boot, mono=None):
        mono = boot if mono is None else mono
        self.zeit = (wall + 1, boot + 1, mono + 1)
        return self.waechter.takt(wall, boot, mono)

    def stempel(self, takt, ruhe_seit, boot_id=None):
        """Beobachtungsstempel eines Vorgängerprozesses (tmpfs) direkt schreiben."""
        Path(self.cfg["takt_stempel"]).write_text(json.dumps(
            {"boot_id": boot_id or self.boot_id, "takt": takt, "ruhe_seit": ruhe_seit}))

    def bis_schlaf(self, offset=2700, start=None):
        """Start (Mindestwachzeit läuft), dann 45 min später erneut."""
        start = self.START if start is None else start
        self.takt(start, 1000)
        return self.takt(start + offset, 1000 + offset)


class BandbreiteTests(unittest.TestCase):
    CFG = {"self_triples": [[1, 672, True], [1, 673, True]], "bandbreite_schwelle_bytes": 262144}
    NOW = 100000

    def row(self, at, account=5, device=9, lan=True, count=1000):
        return {"at": at, "accountID": account, "deviceID": device, "lan": lan, "bytes": count}

    def test_rollendes_fenster_ist_kein_reset(self):
        old = f.bandwidth([self.row(self.NOW - 150), self.row(self.NOW - 60)], {}, self.CFG, self.NOW)[1]
        # Der älteste Bucket fällt hinten heraus, ein neuer kommt hinzu: normales Rollen.
        signal, fresh, sources, reset = f.bandwidth([self.row(self.NOW - 60), self.row(self.NOW)], old, self.CFG, self.NOW + 60)
        self.assertFalse(reset)

    def test_leere_antwort_ist_kein_reset(self):
        old = f.bandwidth([self.row(self.NOW - 60)], {}, self.CFG, self.NOW)[1]
        self.assertFalse(f.bandwidth([], old, self.CFG, self.NOW + 200)[3])

    def test_reset_bei_gefallenem_zaehler(self):
        old = f.bandwidth([self.row(self.NOW - 60, count=5000)], {}, self.CFG, self.NOW)[1]
        self.assertTrue(f.bandwidth([self.row(self.NOW - 60, count=10)], old, self.CFG, self.NOW)[3])

    def test_reset_bei_verschwundenem_bucket_mitten_im_fenster(self):
        rows = [self.row(self.NOW - 150), self.row(self.NOW - 90, device=10), self.row(self.NOW - 30)]
        old = f.bandwidth(rows, {}, self.CFG, self.NOW)[1]
        # Der mittlere Bucket (at ≥ ältester aktueller at) fehlt: Plex hat neu gezählt.
        self.assertTrue(f.bandwidth([rows[0], rows[2]], old, self.CFG, self.NOW)[3])

    def test_schwelle_je_triple_in_180s(self):
        rows = [self.row(self.NOW - 170, count=200000), self.row(self.NOW - 20, count=62144)]
        signal, _, sources, _ = f.bandwidth(rows, {}, self.CFG, self.NOW)
        self.assertTrue(signal)
        self.assertEqual(sources, [[5, 9, True]])
        rows[1]["bytes"] = 62143
        self.assertFalse(f.bandwidth(rows, {}, self.CFG, self.NOW)[0])

    def test_alte_buckets_zaehlen_nicht(self):
        rows = [self.row(self.NOW - 181, count=10 ** 7), self.row(self.NOW - 10, count=100)]
        self.assertFalse(f.bandwidth(rows, {}, self.CFG, self.NOW)[0])

    def test_wachsender_alter_bucket_unter_schwelle_kein_signal(self):
        old = f.bandwidth([self.row(self.NOW - 60, count=1000)], {}, self.CFG, self.NOW)[1]
        self.assertFalse(f.bandwidth([self.row(self.NOW - 60, count=1500)], old, self.CFG, self.NOW)[0])

    def test_eigene_abfragen_und_dauerverkehr(self):
        rows = [self.row(self.NOW - 30, 1, 672, True, 10 ** 6), self.row(self.NOW - 30, 1, 673, True, 10 ** 6),
                self.row(self.NOW - 30, 1, 1, True, 12000), self.row(self.NOW - 30, 4242, 7, False, 500)]
        self.assertFalse(f.bandwidth(rows, {}, self.CFG, self.NOW)[0])
        # Ohne self_triples wären die eigenen Abfragen bei dieser Größe Nutzung.
        self.assertTrue(f.bandwidth(rows, {}, dict(self.CFG, self_triples=[]), self.NOW)[0])

    def test_lan_flag_trennt_triples(self):
        rows = [self.row(self.NOW - 30, 1, 672, False, 300000)]
        self.assertTrue(f.bandwidth(rows, {}, self.CFG, self.NOW)[0])

    def test_standardschwelle(self):
        rows = [self.row(self.NOW - 30, count=262144)]
        self.assertTrue(f.bandwidth(rows, {}, {"self_triples": []}, self.NOW)[0])
        rows[0]["bytes"] -= 1
        self.assertFalse(f.bandwidth(rows, {}, {"self_triples": []}, self.NOW)[0])

    def test_sitzungen_sind_immer_nutzung(self):
        cfg = dict(SCHLAF, plex_preferences="/synthetisch", ansprueche="/nicht/vorhanden")
        root = types.SimpleNamespace(get=lambda key: "token")
        tree = types.SimpleNamespace(getroot=lambda: root)

        def api(port, path, headers):
            if path == "/status/sessions":
                return {"MediaContainer": {"size": 1, "Metadata": [{}]}}
            return {"MediaContainer": {"size": 0}}
        with mock.patch.object(f.ET, "parse", return_value=tree), \
                mock.patch.object(f, "jellyfin", return_value=(False, None)), \
                mock.patch.object(Path, "read_text", return_value=MDSTAT):
            data = f.Sammler(cfg, runner=lambda a, **k: result("", 1), api_call=api, proc=lambda: []).sammeln(self.NOW)
        self.assertIn("plex", data["nutzung"])


class KonfigTests(unittest.TestCase):
    def schreiben(self, tmp, data):
        path = Path(tmp) / "cfg.json"
        path.write_text(json.dumps(data))
        return path

    def test_freigabe_nur_im_aktivmodus(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(laden(self.schreiben(tmp, {"dependencies_verified": True}), SCHLAF)["dependencies_verified"])
            self.assertFalse(laden(self.schreiben(tmp, {"mode": "aktiv"}), SCHLAF)["dependencies_verified"])
            cfg = laden(self.schreiben(tmp, {"mode": "aktiv", "dependencies_verified": True}), SCHLAF)
            self.assertIs(cfg["dependencies_verified"], True)
            self.assertEqual(SCHLAF["mode"], "schatten")
            self.assertIs(SCHLAF["raid_degradiert_erlaubt"], False)
            self.assertEqual(SCHLAF["bandbreite_schwelle_bytes"], 262144)
            self.assertEqual(SCHLAF["zustand"], "/var/lib/greenbuddy/schlaf-zustand.json")

    def test_ungueltige_werte(self):
        for data in ({"mode": "Aktiv"}, {"mode": "aktiv", "dependencies_verified": "ja"},
                     {"raid_degradiert_erlaubt": 1}, {"bandbreite_schwelle_bytes": 0},
                     {"bandbreite_schwelle_bytes": True}, {"bandbreite_schwelle_bytes": 1.5},
                     {"self_triples": [[1, 672]]}, {"self_triples": [[1, 672, "true"]]},
                     {"self_triples": [[True, 672, True]]}, {"zustand": ""}, {"wol_interface": "eno1; id"},
                     {"wol_interface": ".."}, {"wol_interface": "../x"}):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    laden(self.schreiben(tmp, data), SCHLAF)

    def test_beispielkonfiguration(self):
        root = Path(__file__).resolve().parents[1]
        data = json.loads((root / "deploy/vhost01/schlaf.example.json").read_text())
        self.assertEqual(data["mode"], "schatten")
        self.assertIs(data["dependencies_verified"], False)
        self.assertIs(data["raid_degradiert_erlaubt"], False)
        self.assertIn([1, 672, True], data["self_triples"])
        self.assertIn([1, 673, True], data["self_triples"])
        self.assertEqual(data["bandbreite_schwelle_bytes"], 262144)
        # Weckweg über proxy01: Schlüssel stehen mit ihren Standardwerten im Beispiel und sind gültig.
        self.assertEqual({k: v for k, v in data.items() if k.startswith("stellvertreter_")}, register_client.STANDARD)
        self.assertEqual(register_client.einstellungen(data), register_client.STANDARD)


class RaidTests(unittest.TestCase):
    def sammeln(self, mdstat, **cfg):
        cfg = dict(SCHLAF, ansprueche="/nicht/vorhanden", **cfg)
        with mock.patch.object(f, "jellyfin", return_value=(False, None)), \
                mock.patch.object(Path, "read_text", return_value=mdstat), \
                mock.patch.object(f.ET, "parse", side_effect=ValueError("Test")):
            return f.Sammler(cfg, runner=lambda a, **k: result("", 1), proc=lambda: []).sammeln(100)

    def test_degradiert_nur_mit_freigabe_kein_veto(self):
        self.assertIn("raid_degradiert", self.sammeln(MDSTAT)["vetos"])
        data = self.sammeln(MDSTAT, raid_degradiert_erlaubt=True)
        self.assertNotIn("raid_degradiert", data["vetos"])
        self.assertTrue(data["fakten"]["raid_degradiert"])

    def test_raid_aktion_bleibt_veto(self):
        text = MDSTAT + "      [>....]  recovery = 1.0%\n"
        self.assertIn("raid_aktion", self.sammeln(text, raid_degradiert_erlaubt=True)["vetos"])


class FensterAktivTests(unittest.TestCase):
    def test_fensterende_und_weckzeit(self):
        pairs, lead = parse(MEDIA)
        now = lokal(2026, 1, 2, 12)
        self.assertEqual(aktiv.fenster_ende(pairs, lead, now), lokal(2026, 1, 2, 16, 30))
        self.assertEqual(aktiv.weckzeit(lokal(2026, 1, 2, 16, 30), lead, now), lokal(2026, 1, 2, 16, 25))
        with self.assertRaises(ValueError):
            aktiv.fenster_ende(pairs, lead, lokal(2026, 1, 2, 17))

    def test_frueheres_wachfenster_begrenzt_ende(self):
        pairs, lead = parse(MEDIA + 'MITTAG_START="13:00"\nMITTAG_END="13:30"\n')
        self.assertEqual(aktiv.fenster_ende(pairs, lead, lokal(2026, 1, 2, 12)), lokal(2026, 1, 2, 13, 0))

    def test_rtc_grenzen(self):
        now = 1000000
        with self.assertRaisesRegex(ValueError, "weckzeit_ungueltig"):
            aktiv.weckzeit(now + 600 + 5 * 60 - 1, 5, now)
        self.assertEqual(aktiv.weckzeit(now + 600 + 5 * 60, 5, now), now + 600)
        self.assertEqual(aktiv.weckzeit(now + 12 * 3600 + 300, 5, now), now + 12 * 3600)
        with self.assertRaisesRegex(ValueError, "weckzeit_ungueltig"):
            aktiv.weckzeit(now + 12 * 3600 + 301, 5, now)


class ZustandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "zustand.json"

    def test_neu_atomar_privat(self):
        z = aktiv.Zustand(self.path, "boot-a")
        data = z.laden()
        self.assertEqual(data["zyklen"], [])
        data["zyklen"].append(5)
        z.speichern(data)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(aktiv.Zustand(self.path, "boot-a").laden()["zyklen"], [5])

    def test_kaputt_ist_fehler(self):
        for text in ("kaputt", "[]", '{"version":1,"zyklen":"x"}', '{"version":1,"zyklen":[1e999]}',
                     '{"version":2,"zyklen":[]}'):
            self.path.write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                aktiv.Zustand(self.path, "boot-a").laden()

    def test_symlink_ist_fehler(self):
        target = Path(self.tmp.name) / "fremd"
        target.write_text("{}")
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            aktiv.Zustand(self.path, "boot-a").laden()

    def test_zyklen_limit_setzt_sperre(self):
        data = aktiv.Zustand(self.path, "b").laden()
        now = 1000000
        data["zyklen"] = [now - 86401] + [now - 1000 * i for i in range(1, 6)]
        self.assertEqual(aktiv.zyklen_pruefen(data, now), ([], None))
        self.assertEqual(len(data["zyklen"]), 5)
        data["zyklen"].append(now - 10)
        hindernisse, ereignis = aktiv.zyklen_pruefen(data, now)
        self.assertEqual(hindernisse, ["schlafsperre"])
        self.assertEqual(ereignis["ereignis"], "schlafsperre_24h")
        self.assertEqual(data["sperre_bis"], now + 86400)
        # Die Sperre hält 24 h, auch wenn die Zyklen inzwischen verfallen sind.
        self.assertEqual(aktiv.zyklen_pruefen(data, now + 86399), (["schlafsperre"], None))
        self.assertEqual(aktiv.zyklen_pruefen(data, now + 86400 + 90000), ([], None))
        self.assertIsNone(data["sperre_bis"])

    def test_zukunftszeiten_unklar(self):
        data = aktiv.Zustand(self.path, "b").laden()
        data["zyklen"] = [2000000]
        with self.assertRaisesRegex(ValueError, "zustand_zeit"):
            aktiv.zyklen_pruefen(data, 1000000)

    SCHLAF_B4 = {"beginn_wall": 1000.5, "beginn_boot": 50, "summe_vor": 0, "weckzeit": 5000, "boot_id": "b"}

    def zustand_mit(self, schlaf):
        data = dict(aktiv.Zustand(self.path, "b").leer(), schlaf=schlaf)
        self.path.write_text(json.dumps(data))
        return aktiv.Zustand(self.path, "b")

    def test_altes_schema_ohne_zyklus_bleibt_gueltig(self):
        # Zustandsdatei aus 2.0.0b4 (Schlaf ohne Register) muss nach dem Update lesbar bleiben.
        self.assertEqual(self.zustand_mit(dict(self.SCHLAF_B4)).laden()["schlaf"], self.SCHLAF_B4)

    def test_neues_schema_mit_zyklus(self):
        schlaf = dict(self.SCHLAF_B4, zyklus="0123456789abcdef")
        z = self.zustand_mit(schlaf)
        self.assertEqual(z.laden()["schlaf"], schlaf)
        z.speichern(z.laden())
        self.assertEqual(json.loads(self.path.read_text())["schlaf"]["zyklus"], "0123456789abcdef")

    def test_zyklus_formfehler(self):
        for zyklus in (None, 5, "", "a b", "z" * 129, "z\n", ["z"]):
            with self.subTest(zyklus=zyklus), self.assertRaisesRegex(ValueError, "zustand_schema"):
                self.zustand_mit(dict(self.SCHLAF_B4, zyklus=zyklus)).laden()
        with self.assertRaisesRegex(ValueError, "zustand_schema"):
            self.zustand_mit(dict(self.SCHLAF_B4, zyklus="z1", fremd=1)).laden()
        z = aktiv.Zustand(self.path, "b")
        with self.assertRaisesRegex(ValueError, "zustand_schema"):
            z.speichern(dict(z.leer(), schlaf=dict(self.SCHLAF_B4, zyklus="a;b")))

    def test_aufwachen_liefert_zyklus(self):
        for schlaf, boot, boot_s, mono, ereignis in (
                (dict(self.SCHLAF_B4, zyklus="z1"), "b", 9000, 100, "aufgewacht"),
                (dict(self.SCHLAF_B4, zyklus="z1"), "neu", 9000, 9000, "aufgewacht"),
                (dict(self.SCHLAF_B4, zyklus="z1"), "b", 400, 400, "suspend_ohne_wirkung")):
            with self.subTest(ereignis=ereignis, boot=boot):
                data = dict(aktiv.Zustand(self.path, "b").leer(), schlaf=schlaf)
                row = aktiv.aufwachen_pruefen(data, boot, boot_s, mono, 6000)
                self.assertEqual((row["ereignis"], row["zyklus"]), (ereignis, "z1"))
                self.assertIsNone(data["schlaf"])
        data = dict(aktiv.Zustand(self.path, "b").leer(), schlaf=dict(self.SCHLAF_B4))
        self.assertNotIn("zyklus", aktiv.aufwachen_pruefen(data, "b", 9000, 100, 6000))


class AusfuehrungTests(unittest.TestCase):
    def setUp(self):
        self.befehle = Befehle()
        self.a = aktiv.Ausfuehrung(self.befehle, self.befehle.lesen)

    def test_rtcwake_argv_und_rueckleseprobe(self):
        self.a.rtc_setzen(1767369900)
        self.assertEqual(self.befehle.calls[0], ["rtcwake", "-m", "no", "-t", "1767369900"])
        self.assertEqual(self.befehle.assert_path, "/sys/class/rtc/rtc0/wakealarm")

    def test_rtc_fehler(self):
        self.befehle.antworten["rtcwake"] = result("", 1)
        with self.assertRaises(ValueError):
            self.a.rtc_setzen(1767369900)
        befehle = Befehle()
        befehle.lesen = lambda path: "1767360000\n"
        with self.assertRaisesRegex(ValueError, "rtc_nicht_gesetzt"):
            aktiv.Ausfuehrung(befehle, befehle.lesen).rtc_setzen(1767369900)
        befehle.lesen = lambda path: "\n"
        with self.assertRaisesRegex(ValueError, "rtc_nicht_gesetzt"):
            aktiv.Ausfuehrung(befehle, befehle.lesen).rtc_setzen(1767369900)

    def test_rtc_in_lokalzeit_akzeptiert(self):
        weck = 1767369900
        offset = int(dt.datetime.fromtimestamp(weck).astimezone().utcoffset().total_seconds())
        befehle = Befehle()
        befehle.lesen = lambda path: "%d\n" % (weck + offset)
        aktiv.Ausfuehrung(befehle, befehle.lesen).rtc_setzen(weck)

    def test_vorbedingungen_ok(self):
        gelesen = []
        lesen = self.befehle.lesen
        self.a.reader = lambda path: gelesen.append(path) or lesen(path)
        self.assertEqual(self.a.vorbedingungen({"wol_interface": "eno1"}), [])
        # Kein ethtool: dessen WOL-Abfrage braucht CAP_NET_ADMIN, das die Unit nicht hat.
        self.assertFalse(any(c[0] == "ethtool" for c in self.befehle.calls))
        # rtcwake -m no prüft power/wakeup der RTC nicht; der Wächter muss es selbst lesen.
        self.assertIn(RTC_WAKEUP, gelesen)
        self.assertIn(["systemctl", "show", "-p", "Id", "-p", "LoadState", "-p", "ActiveState", "--"]
                      + list(FREMDE_UNITS), self.befehle.calls)

    def test_vorbedingungen_gen0_schlaefer_erledigt(self):
        # Maskiert oder entfernt ist erledigt; ein inaktiver Timer allein ist ohne Auslöser harmlos.
        for antwort in (fremde(), fremde(**{"delay-after-suspend.service": ("masked", "inactive"),
                                            "auto-sleep.timer": ("masked", "inactive"),
                                            "auto-sleep.service": ("masked", "inactive")}),
                        fremde(**{"delay-after-suspend.service": ("masked", "inactive"),
                                  "auto-sleep.timer": ("loaded", "inactive"),
                                  "auto-sleep.service": ("loaded", "failed")})):
            with self.subTest(antwort=antwort):
                befehle = Befehle()
                befehle.antworten["fremde"] = result(antwort)
                self.assertEqual(aktiv.Ausfuehrung(befehle, befehle.lesen).vorbedingungen({"wol_interface": "eno1"}), [])

    def test_vorbedingungen_jeder_fehler(self):
        faelle = (
            ("CanSuspend", result('{"type":"s","data":["challenge"]}'), "suspend_nicht_erlaubt"),
            ("CanSuspend", result("", 1), "suspend_erlaubnis_unklar"),
            ("CanSuspend", result("kaputt"), "suspend_erlaubnis_unklar"),
            ("ListInhibitors", result('{"type":"a(ssssuu)","data":[[["shutdown:sleep","Test","x","block",0,1]]]}'), "inhibitor_block"),
            ("ListInhibitors", result("", 1), "inhibitor_unklar"),
            ("ListInhibitors", result('{"type":"a(ssssuu)","data":[[["sleep"]]]}'), "inhibitor_unklar"),
            ("wakeup", "disabled\n", "wol_nicht_aktiv"),
            ("wakeup", FileNotFoundError("Test"), "wol_unklar"),
            ("wakeup", "\n", "wol_unklar"),
            ("rtc_wakeup", "disabled\n", "rtc_weckquelle_aus"),
            ("rtc_wakeup", FileNotFoundError("Test"), "rtc_weckquelle_unklar"),
            ("rtc_wakeup", "\n", "rtc_weckquelle_unklar"),
            ("fremde", result(fremde(**{"delay-after-suspend.service": ("loaded", "inactive")})),
             "fremder_schlafdienst:delay-after-suspend.service"),
            ("fremde", result(fremde(**{"delay-after-suspend.service": ("masked", "inactive"),
                                        "auto-sleep.timer": ("loaded", "active")})),
             "fremder_schlafdienst:auto-sleep.timer"),
            ("fremde", result(fremde(**{"delay-after-suspend.service": ("masked", "inactive"),
                                        "auto-sleep.service": ("loaded", "activating")})),
             "fremder_schlafdienst:auto-sleep.service"),
            # mask stoppt nichts: ein maskierter, noch laufender Timer feuert weiter.
            ("fremde", result(fremde(**{"delay-after-suspend.service": ("masked", "inactive"),
                                        "auto-sleep.timer": ("masked", "active")})),
             "fremder_schlafdienst:auto-sleep.timer"),
            ("fremde", result("", 1), "fremder_schlafdienst_unklar"),
            ("fremde", result("kaputt"), "fremder_schlafdienst_unklar"),
            ("fremde", result(fremde().rsplit("\n\n", 1)[0]), "fremder_schlafdienst_unklar"),
            ("fremde", result(fremde(**{"auto-sleep.timer": ("loaded", "unbekannt")})), "fremder_schlafdienst_unklar"),
        )
        for key, answer, reason in faelle:
            with self.subTest(reason=reason, key=key):
                befehle = Befehle()
                if key == "wakeup":
                    befehle.wakeup = answer
                elif key == "rtc_wakeup":
                    befehle.rtc_wakeup = answer
                else:
                    befehle.antworten[key] = answer
                self.assertIn(reason, aktiv.Ausfuehrung(befehle, befehle.lesen).vorbedingungen({"wol_interface": "eno1"}))
        self.assertIn("wol_interface_fehlt", self.a.vorbedingungen({"wol_interface": ""}))

    def test_suspend_argv(self):
        self.assertTrue(self.a.suspend())
        self.assertEqual(self.befehle.calls[-1], ["systemctl", "suspend"])
        self.befehle.antworten["suspend"] = result("", 1)
        self.assertFalse(self.a.suspend())


class AktivEntscheidungTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def umgebung(self, **cfg):
        return Umgebung(self.tmp.name, **cfg)

    def assertKeinSchlaf(self, u, row):
        self.assertNotEqual(row["entscheidung"], "schlafen")
        self.assertFalse(u.befehle.suspendiert(), u.befehle.calls)

    def assertKeinNeuerVersuch(self, u, wall, boot, mono=None):
        """Nach einem früheren Suspend-Aufruf: der Takt ruft keinen weiteren Befehl auf."""
        anzahl = len(u.befehle.calls)
        row = u.takt(wall, boot, mono)
        self.assertNotEqual(row["entscheidung"], "schlafen")
        self.assertEqual(u.befehle.calls[anzahl:], [])

    def test_alle_bedingungen_erfuellt_schlaeft(self):
        u = self.umgebung()
        row = u.bis_schlaf()
        self.assertEqual(row["entscheidung"], "schlafen")
        self.assertEqual(row["aktion"], "suspend")
        weck = lokal(2026, 1, 2, 16, 25)
        self.assertEqual(row["weckzeit"], weck)
        # Plan 2026-10-12 Abschnitt 5 mit Spec 3.2 (Review b5): RTC → Schlussprüfung → Vorbedingungen → abmelden
        # → schlafe-jetzt → letzte Prüfung (frische Fakten, Vorbedingungen) → suspend.
        self.assertEqual(u.befehle.ablauf(), ["rtcwake", "CanSuspend", "ListInhibitors", "systemctl show",
                                              "abmelden", "schlafe-jetzt", "CanSuspend", "ListInhibitors",
                                              "systemctl show", "systemctl suspend"])
        self.assertEqual(u.befehle.calls[0], ["rtcwake", "-m", "no", "-t", str(int(weck))])
        # Schlussprüfung und letzte Prüfung nach den SSH-Rundläufen haben frisch gesammelt.
        self.assertEqual(u.sammler.calls, 4)
        data = json.loads(Path(u.cfg["zustand"]).read_text())
        self.assertEqual(len(data["zyklen"]), 1)
        self.assertEqual(data["schlaf"]["weckzeit"], weck)
        zyklus = data["schlaf"]["zyklus"]
        self.assertRegex(zyklus, r"^[0-9a-f]{16}$")
        ssh = [c for c in u.befehle.calls if c[0] == "ssh"]
        # Sekunden bis zum RTC-Termin, gemessen nach der Schlussprüfung (Takt + 1 s).
        self.assertEqual(ssh, [SSH + ["abmelden " + zyklus],
                               SSH + ["schlafe-jetzt %s %d" % (zyklus, int(weck - (u.START + 2701)))]])
        self.assertEqual(u.befehle.fristen, [20, 20])
        einschlafen = [r for r in u.logger.rows if r.get("ereignis") == "einschlafen"]
        self.assertEqual(einschlafen, [{"ereignis": "einschlafen", "weckzeit": weck, "zyklus": zyklus}])

    def test_schattenmodus_schlaeft_nie(self):
        u = self.umgebung(mode="schatten", dependencies_verified=False)
        row = u.bis_schlaf()
        self.assertEqual(row["entscheidung"], "beobachten")
        self.assertTrue(row["ruhe_kandidat"])
        self.assertEqual(u.befehle.calls, [])

    def test_ohne_dependencies_verified_kein_schlaf(self):
        u = self.umgebung(dependencies_verified=False)
        self.assertKeinSchlaf(u, u.bis_schlaf())

    def test_abschalter(self):
        u = self.umgebung()
        u.takt(u.START, 1000)
        Path(u.cfg["aus"]).touch()
        row = u.takt(u.START + 2700, 3700)
        self.assertEqual(row["entscheidung"], "abgeschaltet")
        self.assertKeinSchlaf(u, row)

    def test_abschalter_waehrend_schlusspruefung(self):
        u = self.umgebung()
        original = u.befehle.__call__

        def runner(args, **kwargs):
            if args[0] == "rtcwake" and "disable" not in args:
                Path(u.cfg["aus"]).touch()
            return original(args, **kwargs)
        u.waechter.ausfuehrung = aktiv.Ausfuehrung(runner, u.befehle.lesen)
        row = u.bis_schlaf()
        self.assertKeinSchlaf(u, row)
        self.assertEqual(row["aktion"], "abbruch")
        self.assertIn(["rtcwake", "-m", "disable"], u.befehle.calls)

    def test_ausserhalb_des_fensters(self):
        for start in (lokal(2026, 1, 2, 7), lokal(2026, 1, 2, 16, 26), lokal(2026, 1, 2, 20)):
            with self.subTest(start=start):
                u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
                self.assertKeinSchlaf(u, u.bis_schlaf(start=start - 2700))

    def test_weniger_als_20_min_bis_fensterende(self):
        u = self.umgebung()
        row = u.bis_schlaf(start=lokal(2026, 1, 2, 16, 11) - 2700)
        self.assertIn("fensterende_zu_nah", row["hindernisse"])
        self.assertKeinSchlaf(u, row)
        # Die Schlussprüfung läuft eine Sekunde später und braucht die 20 min ebenfalls.
        u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
        row = u.bis_schlaf(start=lokal(2026, 1, 2, 16, 10) - 2700)
        self.assertEqual(row["abbruch"], ["entscheidung_wach", "fensterende_zu_nah"])
        self.assertKeinSchlaf(u, row)
        u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
        self.assertEqual(u.bis_schlaf(start=lokal(2026, 1, 2, 16, 9) - 2700)["entscheidung"], "schlafen")

    def test_weniger_als_45_min_ruhe(self):
        u = self.umgebung()
        u.takt(u.START, 1000)
        row = u.takt(u.START + 2699, 3699)
        self.assertKeinSchlaf(u, row)

    def test_idle_seconds_unter_45_min_wird_angehoben(self):
        u = self.umgebung(idle_seconds=60)
        u.takt(u.START, 1000)
        self.assertKeinSchlaf(u, u.takt(u.START + 1800, 2800))

    def test_nutzungssignal_setzt_ruhe_zurueck(self):
        for signal in ("plex", "jellyfin", "minecraft", "claude", "coach", "ssh"):
            with self.subTest(signal=signal):
                u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
                u.takt(u.START, 1000)
                u.sammler.facts = dict(CLEAN, nutzung=[signal])
                u.takt(u.START + 600, 1600)
                u.sammler.facts = copy.deepcopy(CLEAN)
                self.assertKeinSchlaf(u, u.takt(u.START + 2700, 3700))
                self.assertKeinSchlaf(u, u.takt(u.START + 600 + 2699, 1600 + 2699))
                self.assertEqual(u.takt(u.START + 600 + 2700, 1600 + 2700)["entscheidung"], "schlafen")

    def test_jedes_veto_verhindert_schlaf(self):
        for veto in ("ssh_remote", "job:media-staging.service", "gpu", "anspruch", "raid_aktion",
                     "raid_degradiert", "verbindung:32400"):
            with self.subTest(veto=veto):
                u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
                u.sammler.facts = dict(CLEAN, vetos=[veto])
                self.assertKeinSchlaf(u, u.bis_schlaf())

    def test_jeder_unklare_punkt_verhindert_schlaf(self):
        for unclear in ("plex_unklar", "jellyfin_unklar", "bandbreitenzaehler_gefallen", "coach_unklar",
                        "job_unklar:offsite-backup.service", "mdmon_fehlt"):
            with self.subTest(unclear=unclear):
                u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
                u.sammler.facts = dict(CLEAN, unklar=[unclear])
                row = u.bis_schlaf()
                self.assertEqual(row["entscheidung"], "unklar")
                self.assertKeinSchlaf(u, row)

    def test_sammelfehler_verhindert_schlaf(self):
        u = self.umgebung()
        u.sammler.sammeln = mock.Mock(side_effect=ValueError("Test"))
        self.assertKeinSchlaf(u, u.bis_schlaf())

    def test_zeitfenster_unklar(self):
        u = self.umgebung()
        Path(u.cfg["media_conf"]).write_text(MEDIA.replace('TAGSCHLAF_END="16:30"\n', ""))
        row = u.bis_schlaf()
        self.assertIn("zeitfenster_unklar", row["unklar"])
        self.assertKeinSchlaf(u, row)
        Path(u.cfg["media_conf"]).unlink()
        self.assertKeinSchlaf(u, u.takt(u.START + 2760, 3760))

    def test_mindestwachzeit_nach_dienststart(self):
        u = self.umgebung()
        # Persistierte Ruhe aus derselben Boot-ID, aber der Dienst lief eben erst an.
        aktiv.Zustand(u.cfg["zustand"], u.boot_id).speichern(
            dict(aktiv.Zustand(u.cfg["zustand"], u.boot_id).leer(), ruhe_seit=0))
        u.stempel(4990, 0)
        u.waechter = u.neu()
        row = u.takt(u.START, 5000)
        self.assertIn("mindestwachzeit", row["vetos"])
        self.assertKeinSchlaf(u, row)
        self.assertKeinSchlaf(u, u.takt(u.START + 599, 5599))
        self.assertEqual(u.takt(u.START + 600, 5600)["entscheidung"], "schlafen")

    def test_mindestwachzeit_und_neue_ruhe_nach_resume(self):
        u = self.umgebung()
        u.takt(u.START, 1000)
        u.takt(u.START + 1800, 2800)
        # Resume: BOOTTIME springt, MONOTONIC nicht. Aufwachen zählt als Signal.
        self.assertKeinSchlaf(u, u.takt(u.START + 3600, 4600, 2860))
        self.assertKeinSchlaf(u, u.takt(u.START + 4200, 5200, 3460))
        self.assertKeinSchlaf(u, u.takt(u.START + 3600 + 2699, 4600 + 2699, 2860 + 2699))

    def test_uhrsprung(self):
        u = self.umgebung()
        u.takt(u.START, 1000)
        row = u.takt(u.START + 2700 + 600, 3700)
        self.assertIn("uhrsprung", row["unklar"])
        self.assertKeinSchlaf(u, row)

    def test_takt_verspaetet(self):
        u = self.umgebung()
        u.takt(u.START, 1000)
        u.waechter.monoton = lambda: u.waechter.takt_start + 56
        self.assertKeinSchlaf(u, u.takt(u.START + 2700, 3700))

    def test_schlusspruefung_aenderung_bricht_ab(self):
        for danach in (dict(CLEAN, nutzung=["plex"]), dict(CLEAN, vetos=["ssh_remote"]),
                       dict(CLEAN, unklar=["gpu_unklar"])):
            with self.subTest(danach=danach):
                u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
                u.takt(u.START, 1000)
                u.sammler.calls = 0
                u.sammler.danach = danach
                row = u.takt(u.START + 2700, 3700)
                self.assertEqual(row["aktion"], "abbruch")
                self.assertKeinSchlaf(u, row)
                self.assertEqual(u.befehle.calls[-1], ["rtcwake", "-m", "disable"])
                data = json.loads(Path(u.cfg["zustand"]).read_text())
                self.assertEqual(data["zyklen"], [])
                self.assertIsNone(data["schlaf"])

    def test_rtc_fehler_kein_suspend(self):
        u = self.umgebung()
        u.befehle.antworten["rtcwake"] = result("", 1)
        row = u.bis_schlaf()
        self.assertEqual((row["aktion"], row["grund"]), ("abbruch", "rtc_fehler"))
        self.assertKeinSchlaf(u, row)
        u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
        u.befehle.lesen = lambda path: "0\n"
        u.waechter = u.neu()
        self.assertKeinSchlaf(u, u.bis_schlaf())

    def test_vorbedingung_fehlt_kein_suspend(self):
        for key, answer in (("CanSuspend", result('{"type":"s","data":["no"]}')),
                            ("ListInhibitors", result('{"type":"a(ssssuu)","data":[[["sleep","x","y","block",0,1]]]}')),
                            ("wakeup", "disabled\n"), ("rtc_wakeup", "disabled\n"),
                            ("fremde", result(fremde(**{"delay-after-suspend.service": ("loaded", "inactive")})))):
            with self.subTest(key=key):
                u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
                if key == "wakeup":
                    u.befehle.wakeup = answer
                elif key == "rtc_wakeup":
                    u.befehle.rtc_wakeup = answer
                else:
                    u.befehle.antworten[key] = answer
                row = u.bis_schlaf()
                self.assertEqual(row["aktion"], "abbruch")
                self.assertKeinSchlaf(u, row)

    def test_logfehler_kein_suspend(self):
        u = self.umgebung()
        u.logger.ok = False
        row = u.bis_schlaf()
        self.assertEqual(row["grund"], "log_schreibfehler")
        self.assertKeinSchlaf(u, row)

    def test_zustand_kaputt_kein_schlaf(self):
        u = self.umgebung()
        Path(u.cfg["zustand"]).write_text("kaputt")
        u.waechter = u.neu()
        row = u.bis_schlaf()
        self.assertIn("zustand_unklar", row["unklar"])
        self.assertKeinSchlaf(u, row)

    def test_boot_id_unklar_kein_schlaf(self):
        u = self.umgebung()
        u.boot_id = None
        u.waechter = u.neu()
        self.assertKeinSchlaf(u, u.bis_schlaf())

    def test_zustand_schreibfehler_kein_suspend(self):
        u = self.umgebung()
        u.takt(u.START, 1000)
        with mock.patch.object(aktiv, "atomar", side_effect=OSError("Test")):
            row = u.takt(u.START + 2700, 3700)
        self.assertKeinSchlaf(u, row)

    def test_suspendfehler(self):
        u = self.umgebung()
        u.befehle.antworten["suspend"] = result("", 1)
        row = u.bis_schlaf()
        self.assertEqual((row["aktion"], row["grund"]), ("abbruch", "suspend_fehler"))
        self.assertEqual(u.befehle.calls[-1], ["rtcwake", "-m", "disable"])
        data = json.loads(Path(u.cfg["zustand"]).read_text())
        self.assertIsNone(data["schlaf"])
        # Kein neuer Versuch im Minutentakt: die Ruhe beginnt neu.
        self.assertEqual(data["ruhe_seit"], 3701)
        self.assertKeinNeuerVersuch(u, u.START + 2760, 3760)

    def test_suspend_ausnahme_kein_absturz(self):
        for fehler in (subprocess.TimeoutExpired(["systemctl", "suspend"], 10), OSError("Test")):
            with self.subTest(fehler=type(fehler).__name__):
                u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
                u.befehle.antworten["suspend"] = fehler
                row = u.bis_schlaf()
                self.assertEqual((row["aktion"], row["grund"]), ("abbruch", "suspend_fehler"))
                self.assertIn("suspend_unklar", row["abbruch"])
                # Ob logind den Auftrag schon angenommen hat, ist offen: der RTC-Wecker bleibt stehen.
                self.assertNotIn(["rtcwake", "-m", "disable"], u.befehle.calls)
                self.assertEqual(u.waechter.decision.quiet_since, 3701)
                data = json.loads(Path(u.cfg["zustand"]).read_text())
                self.assertEqual(data["ruhe_seit"], 3701)
                self.assertKeinNeuerVersuch(u, u.START + 2760, 3760)

    def test_raid_degradiert_mit_freigabe(self):
        u = self.umgebung(raid_degradiert_erlaubt=True)
        # Der Filter sitzt im Sammler; hier liefert er bereits ohne Veto.
        self.assertEqual(u.bis_schlaf()["entscheidung"], "schlafen")

    def test_ratenlimit_sperrt_24h(self):
        u = self.umgebung()
        z = aktiv.Zustand(u.cfg["zustand"], u.boot_id)
        jetzt = u.START + 2700
        z.speichern(dict(z.leer(), zyklen=[jetzt - 3600 * i for i in range(1, 7)]))
        u.waechter = u.neu()
        row = u.bis_schlaf()
        self.assertIn("schlafsperre", row["hindernisse"])
        self.assertKeinSchlaf(u, row)
        self.assertIn("schlafsperre_24h", [r.get("ereignis") for r in u.logger.rows])
        self.assertEqual(json.loads(Path(u.cfg["zustand"]).read_text())["sperre_bis"], u.START + 86400)

    def test_ruhe_wird_persistiert_und_nur_bei_gleicher_boot_id_uebernommen(self):
        u = self.umgebung()
        u.takt(u.START, 1000)
        u.takt(u.START + 60, 1060)
        self.assertEqual(json.loads(Path(u.cfg["zustand"]).read_text())["ruhe_seit"], 1000)
        # Neustart innerhalb von zwei Takten: lückenlos beobachtet, die Ruhe gilt weiter.
        u.waechter = u.neu()
        u.takt(u.START + 1180, 1180)
        self.assertEqual(u.waechter.decision.quiet_since, 1000)
        u.boot_id = "11111111-2222-3333-4444-555555555555"
        u.waechter = u.neu()
        u.takt(u.START + 1240, 50)
        self.assertEqual(u.waechter.decision.quiet_since, 50)

    def test_ruhe_nach_beobachtungsluecke_beginnt_neu(self):
        u = self.umgebung()
        u.takt(u.START, 1000)
        u.takt(u.START + 60, 1060)
        # Dienst gestoppt: niemand hat zwischen 1060 und 2800 hingesehen.
        u.waechter = u.neu()
        u.takt(u.START + 1800, 2800)
        self.assertEqual(u.waechter.decision.quiet_since, 2800)
        u.waechter = u.neu()
        Path(u.cfg["takt_stempel"]).unlink()
        u.takt(u.START + 1860, 2860)
        self.assertEqual(u.waechter.decision.quiet_since, 2860)

    def test_ruhe_nach_schattenpause_beginnt_neu(self):
        # Review-Probe 1: aktiv, 11:00 Schatten, Plex 11:05-12:30, 12:40 wieder aktiv.
        u = self.umgebung()
        start = lokal(2026, 1, 2, 10, 0)
        u.takt(start, 1000)
        u.takt(start + 60, 1060)
        schatten = u.neu(aktiv_flag=False)
        u.waechter = schatten
        for minute in range(1, 100):
            u.takt(start + 3600 + 60 * minute, 4600 + 60 * minute)
        u.waechter = u.neu()
        u.takt(start + 9600, 10600)
        self.assertEqual(u.waechter.decision.quiet_since, 10600)
        self.assertKeinSchlaf(u, u.takt(start + 10200, 11200))
        self.assertKeinSchlaf(u, u.takt(start + 10800, 11800))

    def test_stempel_muss_zur_gespeicherten_ruhe_passen(self):
        # Frischer Stempel, aber für eine andere Ruhe, eine andere Boot-ID oder kaputt: nicht übernehmen.
        for ruhe, boot_id, text in ((900, None, None), (1000, "11111111-2222-3333-4444-555555555555", None),
                                    (1000, None, "kaputt"), (1000, None, '{"boot_id":1,"takt":1,"ruhe_seit":1}')):
            with self.subTest(ruhe=ruhe, boot_id=boot_id, text=text):
                u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
                u.takt(u.START, 1000)
                u.takt(u.START + 60, 1060)
                u.stempel(1100, ruhe, boot_id)
                if text:
                    Path(u.cfg["takt_stempel"]).write_text(text)
                u.waechter = u.neu()
                u.takt(u.START + 120, 1120)
                self.assertEqual(u.waechter.decision.quiet_since, 1120)
        # Gegenprobe: passender frischer Stempel wird übernommen.
        u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
        u.takt(u.START, 1000)
        u.takt(u.START + 60, 1060)
        u.stempel(1100, 1000)
        u.waechter = u.neu()
        u.takt(u.START + 120, 1120)
        self.assertEqual(u.waechter.decision.quiet_since, 1000)

    def test_stempel_wird_je_takt_geschrieben(self):
        u = self.umgebung()
        u.takt(u.START, 1000)
        u.takt(u.START + 60, 1060)
        stempel = json.loads(Path(u.cfg["takt_stempel"]).read_text())
        self.assertEqual(stempel, {"boot_id": u.boot_id, "takt": 1060, "ruhe_seit": 1000})
        self.assertEqual(Path(u.cfg["takt_stempel"]).stat().st_mode & 0o777, 0o600)

    def test_schattenmodus_schreibt_keinen_stempel(self):
        u = self.umgebung(mode="schatten", dependencies_verified=False)
        u.bis_schlaf()
        self.assertFalse(Path(u.cfg["takt_stempel"]).exists())

    def test_ungesehener_schlaf_beim_neustart_setzt_ruhe_zurueck(self):
        # Review-Probe 2: Suspend, Wecken, dann Dienst-Neustart; der neue Prozess sah den Resume nicht.
        u = self.umgebung()
        u.bis_schlaf()
        data = json.loads(Path(u.cfg["zustand"]).read_text())
        self.assertIsNotNone(data["schlaf"])
        # A: Neustart direkt nach dem Suspend-Aufruf, frischer Stempel, noch kein Schlaf messbar.
        u.stempel(3740, data["ruhe_seit"])
        u.waechter = u.neu()
        u.takt(u.START + 2790, 3790, 3789)
        self.assertNotIn("aufgewacht", [r.get("ereignis") for r in u.logger.rows])
        self.assertEqual(u.waechter.decision.quiet_since, 3790)
        # B: 2 h geschlafen, per gb-wecken geweckt, danach Neustart.
        u = Umgebung(tempfile.mkdtemp(dir=self.tmp.name))
        u.bis_schlaf()
        u.waechter = u.neu()
        u.takt(u.START + 2760 + 7200, 3760 + 7200, 3760)
        self.assertEqual(u.waechter.decision.quiet_since, 10960)
        # Nach der Mindestwachzeit (10 min) noch keine 45 min Ruhe: kein erneuter Suspend.
        self.assertKeinNeuerVersuch(u, u.START + 2760 + 7800, 3760 + 7800, 4360)

    def test_aufwachereignis_setzt_ruhe_zurueck(self):
        u = self.umgebung()
        u.takt(u.START, 1000, 900)
        u.takt(u.START + 60, 1060, 960)
        # Ein Schlaf, den dieser Prozess nicht selbst erlebt hat (BOOTTIME-MONOTONIC stand schon vorher bei 100).
        u.waechter.data["schlaf"] = {"beginn_wall": u.START - 3600, "beginn_boot": 500, "summe_vor": 0,
                                     "weckzeit": u.START - 60, "boot_id": u.boot_id}
        u.takt(u.START + 120, 1120, 1020)
        self.assertIn("aufgewacht", [r.get("ereignis") for r in u.logger.rows])
        self.assertEqual(u.waechter.decision.quiet_since, 1120)

    def test_aufgewacht_mit_schlafdauer(self):
        u = self.umgebung()
        u.bis_schlaf()
        # Nach dem Suspend: 3 h geschlafen, MONOTONIC stand still.
        u.takt(u.START + 2700 + 60 + 10800, 3700 + 60 + 10800, 3700 + 60)
        rows = [r for r in u.logger.rows if r.get("ereignis") == "aufgewacht"]
        self.assertEqual(len(rows), 1)
        self.assertAlmostEqual(rows[0]["schlafdauer_s"], 10800, delta=5)
        self.assertIsNone(json.loads(Path(u.cfg["zustand"]).read_text())["schlaf"])

    def test_kein_zweiter_suspend_direkt_danach(self):
        u = self.umgebung()
        u.bis_schlaf()
        anzahl = len(u.befehle.calls)
        row = u.takt(u.START + 2760, 3760)
        self.assertNotEqual(row["entscheidung"], "schlafen")
        self.assertEqual(len(u.befehle.calls), anzahl)


class WeckwegTests(unittest.TestCase):
    """Plan 2026-10-12 (Weg 4/7): Register bei proxy01 vor dem Suspend, anmelden nach dem Resume."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def umgebung(self, **cfg):
        return Umgebung(tempfile.mkdtemp(dir=self.tmp.name), **cfg)

    def zustand(self, u):
        return json.loads(Path(u.cfg["zustand"]).read_text())

    def ereignisse(self, u, name):
        return [r for r in u.logger.rows if r.get("ereignis") == name]

    def assertAbbruch(self, u, row, grund, abbruch=None):
        self.assertEqual((row["entscheidung"], row["aktion"], row["grund"]), ("wach", "abbruch", grund))
        self.assertEqual(row.get("abbruch"), abbruch)
        self.assertFalse(u.befehle.suspendiert(), u.befehle.calls)
        self.assertIn(["rtcwake", "-m", "disable"], u.befehle.calls)

    def assertAbgebrochen(self, u, befehle):
        """Register-Befehle in dieser Reihenfolge, alle mit demselben Zyklus; zuletzt anmelden-abbruch."""
        ssh = u.befehle.ssh()
        self.assertEqual([s[0] for s in ssh], befehle)
        self.assertEqual(len({s[1] for s in ssh}), 1, ssh)
        return ssh[0][1]

    def assertKeinSchlafeintrag(self, u):
        data = self.zustand(u)
        self.assertEqual(data["zyklen"], [])
        self.assertIsNone(data["schlaf"])

    def test_abmelden_nicht_bereit(self):
        u = self.umgebung()
        u.befehle.register["abmelden"] = lambda z: register_antwort("abmelden", z, bereit=False, grund="dienst_aus")
        row = u.bis_schlaf()
        self.assertAbbruch(u, row, "stellvertreter", ["stellvertreter_nicht_bereit:dienst_aus"])
        # proxy01 hat den Zyklus eröffnet (Phase abgemeldet): wieder schließen.
        self.assertAbgebrochen(u, ["abmelden", "anmelden-abbruch"])
        self.assertEqual(row["anmelden_abbruch"], "ok")
        self.assertKeinSchlafeintrag(u)
        self.assertEqual(self.ereignisse(u, "einschlafen"), [])

    def test_abmelden_abgelehnt(self):
        u = self.umgebung()
        u.befehle.register["abmelden"] = result('{"bereit": false, "fehler": "zyklus_bereits_aktiv"}\n', 1)
        row = u.bis_schlaf()
        self.assertAbbruch(u, row, "stellvertreter", ["stellvertreter_nicht_bereit:zyklus_bereits_aktiv"])
        self.assertAbgebrochen(u, ["abmelden", "anmelden-abbruch"])

    def test_abmelden_unklar_oder_frist(self):
        for value, detail in ((subprocess.TimeoutExpired(["ssh"], 20), "frist"), (result("", 255), "exit_255"),
                              (result("kaputt\n"), "antwort_json"),
                              (lambda z: register_antwort("abmelden", "anders"), "antwort_zyklus"),
                              (lambda z: register_antwort("schlafe-jetzt", z), "antwort_phase")):
            with self.subTest(detail=detail):
                u = self.umgebung()
                u.befehle.register["abmelden"] = value
                row = u.bis_schlaf()
                self.assertAbbruch(u, row, "stellvertreter", ["stellvertreter_unklar"])
                self.assertEqual(row["stellvertreter_detail"], detail)
                # Eine verlorene Antwort kann den Zyklus auf proxy01 trotzdem eröffnet haben.
                self.assertAbgebrochen(u, ["abmelden", "anmelden-abbruch"])
                self.assertKeinSchlafeintrag(u)

    def test_schlafe_jetzt_scheitert(self):
        for value, grund in ((lambda z: register_antwort("schlafe-jetzt", z, bereit=False, grund="lease_abgelaufen"),
                              "stellvertreter_nicht_bereit:lease_abgelaufen"),
                             (subprocess.TimeoutExpired(["ssh"], 20), "stellvertreter_unklar")):
            with self.subTest(grund=grund):
                u = self.umgebung()
                u.befehle.register["schlafe-jetzt"] = value
                row = u.bis_schlaf()
                self.assertAbbruch(u, row, "stellvertreter", [grund])
                zyklus = self.assertAbgebrochen(u, ["abmelden", "schlafe-jetzt", "anmelden-abbruch"])
                # Der Schlafeintrag stand schon (Plan: Zustand vor schlafe-jetzt) und wird zurückgenommen.
                self.assertEqual(self.ereignisse(u, "einschlafen")[0]["zyklus"], zyklus)
                self.assertKeinSchlafeintrag(u)

    def test_log_oder_zustandsfehler_nach_abmelden(self):
        u = self.umgebung()
        u.logger.ok = False
        row = u.bis_schlaf()
        self.assertAbbruch(u, row, "log_schreibfehler")
        self.assertAbgebrochen(u, ["abmelden", "anmelden-abbruch"])
        self.assertEqual(row["anmelden_abbruch"], "ok")
        u = self.umgebung()
        u.takt(u.START, 1000)
        with mock.patch.object(aktiv, "atomar", side_effect=OSError("Test")):
            row = u.takt(u.START + 2700, 3700)
        self.assertAbbruch(u, row, "zustand_schreibfehler")
        self.assertAbgebrochen(u, ["abmelden", "anmelden-abbruch"])

    # Review b5 (vhost01-schlusspruefung-vor-ssh): abmelden und schlafe-jetzt dauern je bis zu 20 s (Pi 3B+,
    # SD von 2014). Was in diesem Fenster neu auftaucht, muss den Suspend verhindern (Spec 3.2 Schritt 2/3).
    def waehrend(self, u, befehl, aenderung):
        def antwort(zyklus):
            aenderung()
            return register_antwort(befehl, zyklus)
        u.befehle.register[befehl] = antwort

    def assertLetztePruefungBrichtAb(self, u, row, grund):
        self.assertAbbruch(u, row, "letzte_pruefung", row.get("abbruch"))
        self.assertIn(grund, row["abbruch"])
        zyklus = self.assertAbgebrochen(u, ["abmelden", "schlafe-jetzt", "anmelden-abbruch"])
        self.assertEqual(row["anmelden_abbruch"], "ok")
        self.assertEqual(self.ereignisse(u, "einschlafen")[0]["zyklus"], zyklus)
        self.assertKeinSchlafeintrag(u)
        # Der Wecker wird erst nach anmelden-abbruch gelöscht; kein Suspend dazwischen.
        self.assertEqual(u.befehle.ablauf()[-2:], ["anmelden-abbruch", "rtcwake disable"])

    def test_neue_nutzung_waehrend_ssh_bricht_ab(self):
        for befehl in ("abmelden", "schlafe-jetzt"):
            with self.subTest(befehl=befehl):
                u = self.umgebung()
                self.waehrend(u, befehl, lambda: u.sammler.facts.update(nutzung=["plex"],
                                                                         vetos=["verbindung:32400"]))
                row = u.bis_schlaf()
                self.assertLetztePruefungBrichtAb(u, row, "plex")
                self.assertIn("verbindung:32400", row["abbruch"])
                # Nutzung startet die Ruhezeit neu: kein neuer Versuch in der nächsten Minute.
                self.assertEqual(u.waechter.decision.quiet_since, 3701)

    def test_neuer_job_oder_unklar_waehrend_ssh_bricht_ab(self):
        for name, fakten, grund in (("job", {"vetos": ["job:smb.service"]}, "job:smb.service"),
                                    ("unklar", {"unklar": ["plex_unklar"]}, "plex_unklar")):
            with self.subTest(name=name):
                u = self.umgebung()
                self.waehrend(u, "schlafe-jetzt", lambda: u.sammler.facts.update(fakten))
                self.assertLetztePruefungBrichtAb(u, u.bis_schlaf(), grund)

    def test_abschalter_waehrend_ssh_bricht_ab(self):
        for befehl in ("abmelden", "schlafe-jetzt"):
            with self.subTest(befehl=befehl):
                u = self.umgebung()
                self.waehrend(u, befehl, lambda: Path(u.cfg["aus"]).touch())
                self.assertLetztePruefungBrichtAb(u, u.bis_schlaf(), "abgeschaltet")

    def test_inhibitor_waehrend_ssh_bricht_ab(self):
        # root übergeht block-Inhibitoren: ein Job, der jetzt einen nimmt, muss den Suspend trotzdem verhindern.
        u = self.umgebung()
        block = result('{"type":"a(ssssuu)","data":[[["sleep","backup","Sicherung","block",0,4711]]]}')
        self.waehrend(u, "schlafe-jetzt", lambda: u.befehle.antworten.update(ListInhibitors=block))
        self.assertLetztePruefungBrichtAb(u, u.bis_schlaf(), "inhibitor_block")

    def test_suspend_scheitert_meldet_ab(self):
        u = self.umgebung()
        u.befehle.antworten["suspend"] = result("", 1)
        row = u.bis_schlaf()
        self.assertEqual((row["aktion"], row["grund"], row["anmelden_abbruch"]), ("abbruch", "suspend_fehler", "ok"))
        self.assertEqual(u.befehle.ablauf()[-7:], ["schlafe-jetzt", "CanSuspend", "ListInhibitors", "systemctl show",
                                                   "systemctl suspend", "anmelden-abbruch", "rtcwake disable"])
        self.assertAbgebrochen(u, ["abmelden", "schlafe-jetzt", "anmelden-abbruch"])
        self.assertIsNone(self.zustand(u)["schlaf"])

    def test_anmelden_abbruch_bleibt_best_effort(self):
        u = self.umgebung()
        u.befehle.antworten["suspend"] = result("", 1)
        u.befehle.register["anmelden-abbruch"] = subprocess.TimeoutExpired(["ssh"], 20)
        row = u.bis_schlaf()
        self.assertEqual((row["grund"], row["anmelden_abbruch"]), ("suspend_fehler", "stellvertreter_unklar"))
        self.assertEqual(u.befehle.calls[-1], ["rtcwake", "-m", "disable"])

    def test_suspend_ausnahme_schliesst_zyklus_erst_ohne_wirkung(self):
        # Ob logind den Auftrag angenommen hat, ist offen: erst suspend_ohne_wirkung beendet den Zyklus.
        u = self.umgebung()
        u.befehle.antworten["suspend"] = subprocess.TimeoutExpired(["systemctl", "suspend"], 10)
        row = u.bis_schlaf()
        self.assertEqual(row["abbruch"], ["suspend_unklar"])
        self.assertEqual([s[0] for s in u.befehle.ssh()], ["abmelden", "schlafe-jetzt"])
        zyklus = self.zustand(u)["schlaf"]["zyklus"]
        u.takt(u.START + 2760, 3760)
        self.assertEqual(len(u.befehle.ssh()), 2)
        u.takt(u.START + 3060, 4060)
        self.assertEqual(u.befehle.ssh()[-1], ["anmelden-abbruch", zyklus])
        ereignis = self.ereignisse(u, "suspend_ohne_wirkung")
        self.assertEqual([(e["zyklus"], e["anmelden"]) for e in ereignis], [(zyklus, "ok")])

    def test_pause_nach_registerfehler(self):
        u = self.umgebung()
        u.befehle.register["abmelden"] = [subprocess.TimeoutExpired(["ssh"], 20)]
        self.assertEqual(u.bis_schlaf()["abbruch"], ["stellvertreter_unklar"])
        anzahl = len(u.befehle.calls)
        for minute in (1, 2, 3, 4):
            row = u.takt(u.START + 2700 + 60 * minute, 3700 + 60 * minute)
            self.assertIn("stellvertreter_pause", row["hindernisse"])
            self.assertEqual(row["aktion"], "wach")
        # Kein SSH zu einem kaputten proxy01 im Minutentakt, auch kein RTC.
        self.assertEqual(u.befehle.calls[anzahl:], [])
        # Die Ruhezeit lief weiter; nach 5 min ein neuer Versuch mit neuem Zyklus.
        self.assertEqual(u.waechter.decision.quiet_since, 1000)
        row = u.takt(u.START + 3001, 4001)
        self.assertEqual(row["aktion"], "suspend")
        ssh = u.befehle.ssh()
        self.assertEqual([s[0] for s in ssh], ["abmelden", "anmelden-abbruch", "abmelden", "schlafe-jetzt"])
        self.assertNotEqual(ssh[0][1], ssh[2][1])
        self.assertEqual(ssh[2][1], ssh[3][1])

    def test_pause_auch_nach_schlafe_jetzt_fehler(self):
        u = self.umgebung()
        u.befehle.register["schlafe-jetzt"] = [subprocess.TimeoutExpired(["ssh"], 20)]
        u.bis_schlaf()
        self.assertIn("stellvertreter_pause", u.takt(u.START + 2940, 3940)["hindernisse"])
        self.assertEqual(u.takt(u.START + 3001, 4001)["aktion"], "suspend")

    def test_pflicht_aus_ist_ablauf_b4(self):
        u = self.umgebung(stellvertreter_pflicht=False)
        row = u.bis_schlaf()
        self.assertEqual(row["aktion"], "suspend")
        self.assertEqual(u.befehle.ablauf(), ["rtcwake", "CanSuspend", "ListInhibitors", "systemctl show",
                                              "systemctl suspend"])
        self.assertNotIn("zyklus", self.zustand(u)["schlaf"])
        self.assertEqual(self.ereignisse(u, "einschlafen"), [{"ereignis": "einschlafen", "weckzeit": row["weckzeit"]}])
        u.takt(u.START + 2760 + 10800, 3760 + 10800, 3760)
        self.assertEqual(u.befehle.ssh(), [])
        self.assertNotIn("anmelden", self.ereignisse(u, "aufgewacht")[0])
        # Auch ein gescheiterter Suspend ruft ohne Register nichts bei proxy01 auf.
        u = self.umgebung(stellvertreter_pflicht=False)
        u.befehle.antworten["suspend"] = result("", 1)
        self.assertEqual(u.bis_schlaf()["grund"], "suspend_fehler")
        self.assertEqual(u.befehle.ssh(), [])

    def test_stellvertreter_konfigfehler_ist_unklar(self):
        for key, value in (("stellvertreter_ziel", "-oProxyCommand=id"), ("stellvertreter_pflicht", "ja"),
                           ("stellvertreter_schluessel", "relativ/id"), ("stellvertreter_known_hosts", "/a b")):
            with self.subTest(key=key):
                u = self.umgebung(**{key: value})
                row = u.bis_schlaf()
                self.assertEqual((row["entscheidung"], row["grund"]), ("unklar", "konfig_fehler"))
                self.assertIn("konfig_fehler", row["unklar"])
                self.assertEqual(u.befehle.calls, [])

    def nach_resume(self, u, minute=0, nach_s=3600):
        """Takt minute Minuten nach einem Schlaf von nach_s Sekunden (im Schlaf stand nur MONOTONIC)."""
        return u.takt(u.START + 2760 + nach_s + 60 * minute, 3760 + nach_s + 60 * minute, 3760 + 60 * minute)

    def test_resume_meldet_an_mit_weckung(self):
        u = self.umgebung()
        u.befehle.register["anmelden"] = lambda z: register_antwort(
            "anmelden", z, weckung=dict(WECKUNG, quell_ip="198.51.100.9"))
        u.bis_schlaf()
        zyklus = self.zustand(u)["schlaf"]["zyklus"]
        self.nach_resume(u)
        self.assertEqual(u.befehle.ssh()[-1], ["anmelden", zyklus])
        rows = self.ereignisse(u, "aufgewacht")
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["zyklus"], rows[0]["anmelden"], rows[0]["geweckt_durch"]), (zyklus, "ok", "anderes"))
        self.assertEqual(rows[0]["geweckt_durch_proxy01"], WECKUNG)
        # Keine Quelladresse von proxy01 im Log von vhost01.
        self.assertNotIn("198.51.100.9", json.dumps(u.logger.rows))
        self.assertIsNone(self.zustand(u)["schlaf"])

    def test_resume_durch_rtc_ohne_weckung(self):
        u = self.umgebung()
        u.bis_schlaf()
        # 12:01 eingeschlafen, 16:25:05 aufgewacht (RTC-Termin 16:25).
        row = self.nach_resume(u, 0, 15845)
        auf = self.ereignisse(u, "aufgewacht")[0]
        self.assertEqual((auf["geweckt_durch"], auf["anmelden"]), ("rtc", "ok"))
        self.assertIsNone(auf["geweckt_durch_proxy01"])
        self.assertIn("mindestwachzeit", row["vetos"])

    def test_anmelden_wird_wiederholt(self):
        u = self.umgebung()
        u.befehle.register["anmelden"] = [subprocess.TimeoutExpired(["ssh"], 20), result("", 255),
                                          lambda z: register_antwort("anmelden", z, weckung=WECKUNG)]
        u.bis_schlaf()
        zyklus = self.zustand(u)["schlaf"]["zyklus"]
        self.nach_resume(u)
        auf = self.ereignisse(u, "aufgewacht")[0]
        self.assertEqual((auf["anmelden"], auf["anmelden_grund"]), ("offen", "stellvertreter_unklar"))
        self.assertNotIn("geweckt_durch_proxy01", auf)
        ruhe = u.waechter.decision.quiet_since
        self.assertEqual(ruhe, 3760 + 3600)
        self.nach_resume(u, 1)
        self.assertEqual(self.ereignisse(u, "angemeldet"), [])
        self.nach_resume(u, 2)
        self.assertEqual(self.ereignisse(u, "angemeldet"), [
            {"ereignis": "angemeldet", "zyklus": zyklus, "versuche": 3, "geweckt_durch_proxy01": WECKUNG}])
        self.assertEqual([s for s in u.befehle.ssh() if s[0] == "anmelden"], [["anmelden", zyklus]] * 3)
        # Die Versuche starten die Ruhezeit nicht neu; nach dem Erfolg kein weiterer Aufruf.
        self.assertEqual(u.waechter.decision.quiet_since, ruhe)
        anzahl = len(u.befehle.calls)
        self.nach_resume(u, 3)
        self.assertEqual(u.befehle.calls[anzahl:], [])

    def test_anmelden_aufgegeben_nach_10_min(self):
        u = self.umgebung()
        u.befehle.register["anmelden"] = subprocess.TimeoutExpired(["ssh"], 20)
        u.bis_schlaf()
        zyklus = self.zustand(u)["schlaf"]["zyklus"]
        for minute in range(0, 12):
            self.nach_resume(u, minute)
            self.assertEqual(u.waechter.decision.quiet_since, 3760 + 3600)
        self.assertEqual([s for s in u.befehle.ssh() if s[0] == "anmelden"], [["anmelden", zyklus]] * 10)
        self.assertEqual(self.ereignisse(u, "anmelden_aufgegeben"), [
            {"ereignis": "anmelden_aufgegeben", "zyklus": zyklus, "versuche": 10, "grund": "stellvertreter_unklar"}])

    def test_neustart_waehrend_schlaf_meldet_an(self):
        u = self.umgebung()
        u.bis_schlaf()
        zyklus = self.zustand(u)["schlaf"]["zyklus"]
        u.boot_id = "11111111-2222-3333-4444-555555555555"
        u.waechter = u.neu()
        u.takt(u.START + 7200, 50)
        auf = self.ereignisse(u, "aufgewacht")[0]
        self.assertEqual((auf["neustart"], auf["zyklus"], auf["anmelden"]), (True, zyklus, "ok"))
        self.assertEqual(u.befehle.ssh()[-1], ["anmelden", zyklus])

    def test_main_reicht_konfiguration_an_register(self):
        base = Path(self.tmp.name)
        (base / "media.conf").write_text(MEDIA)
        cfg = dict(SCHLAF, mode="aktiv", dependencies_verified=True, media_conf=str(base / "media.conf"),
                   zustand=str(base / "zustand.json"), takt_stempel=str(base / "takt.json"),
                   aus=str(base / "aus"), log=str(base / "log.jsonl"), stellvertreter_ziel="gbtest@192.0.2.7")
        echt = Path

        def pfad(value):
            return echt(self.tmp.name) / "lock" if str(value) == "/run/greenbuddy/schlaf.lock" else echt(value)
        with mock.patch.object(schlaf, "laden", return_value=cfg), \
                mock.patch.object(schlaf, "Path", side_effect=pfad), \
                mock.patch.object(schlaf, "JsonLog", return_value=mock.Mock()), \
                mock.patch.object(schlaf, "Sammler") as sammler, \
                mock.patch.object(aktiv, "boot_id", return_value="abcdef01-2345-4678-89ab-cdef01234567"), \
                mock.patch.object(aktiv, "Ausfuehrung", wraps=aktiv.Ausfuehrung) as ausfuehrung, \
                mock.patch("sys.argv", ["gb-schlaf", "--einmal"]), contextlib.redirect_stdout(io.StringIO()):
            sammler.return_value.sammeln.side_effect = ValueError("Test")
            self.assertEqual(schlaf.main(), 0)
        register = ausfuehrung.call_args.kwargs["register"]
        self.assertIsInstance(register, register_client.Register)
        self.assertEqual(register.argv("abmelden z1")[-2:], ["gbtest@192.0.2.7", "abmelden z1"])


class KurzeJobsTests(unittest.TestCase):
    """Review 07.10.26: No-op-Timer (kurze Staging- und Nachladejobs; 10 ms) starten zeitgleich mit einer
    Runde und dürfen die 45-min-Ruhe nicht neu starten; sie sperren nur diese eine Runde."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def umgebung(self, **cfg):
        return Umgebung(tempfile.mkdtemp(dir=self.tmp.name), **cfg)

    def runde(self, u, minute, vetos=(), unklar=()):
        """Takt minute Minuten nach dem Start (BOOTTIME 1000) mit diesen Vetos/Unklar-Befunden."""
        u.sammler.facts = dict(CLEAN, vetos=list(vetos), unklar=list(unklar))
        return u.takt(u.START + 60 * minute, 1000 + 60 * minute)

    def test_kurzer_job_in_einer_runde_startet_ruhe_nicht_neu(self):
        u = self.umgebung()
        self.runde(u, 0)
        row = self.runde(u, 10, ["job:media-staging.service"])
        self.assertIn("job:media-staging.service", row["vetos"])
        self.assertEqual(u.waechter.decision.quiet_since, 1000)
        self.assertEqual(row["ruhe_seit_s"], 600)
        self.assertEqual(self.runde(u, 45)["entscheidung"], "schlafen")

    def test_kurzer_job_sperrt_seine_runde(self):
        u = self.umgebung()
        self.runde(u, 0)
        # Ruhe reicht schon, aber in genau dieser Runde läuft der Job: kein Kandidat, kein Suspend.
        row = self.runde(u, 45, ["job:medien-nachladen.service"])
        self.assertFalse(row["ruhe_kandidat"])
        self.assertEqual(row["aktion"], "wach")
        self.assertFalse(u.befehle.suspendiert())
        self.assertEqual(row["ruhe_seit_s"], 2700)
        self.assertEqual(self.runde(u, 46)["entscheidung"], "schlafen")

    def test_job_in_zwei_runden_hintereinander_startet_ruhe_neu(self):
        u = self.umgebung()
        self.runde(u, 0)
        self.runde(u, 10, ["job:offsite-backup.service"])
        self.assertEqual(u.waechter.decision.quiet_since, 1000)
        self.runde(u, 11, ["job:offsite-backup.service"])
        self.assertEqual(u.waechter.decision.quiet_since, 1660)
        self.assertNotEqual(self.runde(u, 45)["entscheidung"], "schlafen")
        self.assertNotEqual(self.runde(u, 55)["entscheidung"], "schlafen")
        self.assertEqual(self.runde(u, 56)["entscheidung"], "schlafen")

    def test_wechselnde_kurze_jobs_zaehlen_je_unit(self):
        u = self.umgebung()
        self.runde(u, 0)
        for minute, unit in ((10, "media-staging.service"), (11, "medien-nachladen.service"),
                             (12, "media-staging.service"), (13, "medien-nachsuche.service")):
            self.runde(u, minute, ["job:" + unit])
            self.assertEqual(u.waechter.decision.quiet_since, 1000, unit)
        self.assertEqual(self.runde(u, 45)["entscheidung"], "schlafen")

    def test_andere_vetos_starten_ruhe_weiter_neu(self):
        for veto in ("gpu", "ssh_remote", "sitzung_closing", "verbindung:32400", "anspruch",
                     "transient:automation:run-r1.service", "raid_aktion"):
            with self.subTest(veto=veto):
                u = self.umgebung()
                self.runde(u, 0)
                self.runde(u, 10, [veto])
                self.assertEqual(u.waechter.decision.quiet_since, 1600)
                self.assertNotEqual(self.runde(u, 45)["entscheidung"], "schlafen")
                self.assertEqual(self.runde(u, 55)["entscheidung"], "schlafen")

    def test_job_nach_unklarer_runde_startet_ruhe_neu(self):
        # Konnte der Job in der Vorrunde nicht abgefragt werden, lief er womöglich schon: Neustart.
        u = self.umgebung()
        self.runde(u, 0)
        self.runde(u, 10, unklar=["job_unklar:offsite-backup.service"])
        self.runde(u, 11, ["job:offsite-backup.service"])
        self.assertEqual(u.waechter.decision.quiet_since, 1660)

    def test_job_in_erster_runde_nach_dienststart_startet_ruhe_neu(self):
        # Die Vorrunde des Vorgängers kennt der neue Prozess nicht: unklar heißt Neustart.
        for vetos, erwartet in ((["job:media-staging.service"], 5000), ([], 0)):
            with self.subTest(vetos=vetos):
                u = self.umgebung()
                z = aktiv.Zustand(u.cfg["zustand"], u.boot_id)
                z.speichern(dict(z.leer(), ruhe_seit=0))
                u.stempel(4990, 0)
                u.waechter = u.neu()
                u.sammler.facts = dict(CLEAN, vetos=vetos)
                u.takt(u.START, 5000)
                # Gegenprobe ohne Job: die lückenlos bezeugte Ruhe gilt weiter.
                self.assertEqual(u.waechter.decision.quiet_since, erwartet)

    def test_schattenmodus_zaehlt_genauso(self):
        u = self.umgebung(mode="schatten", dependencies_verified=False)
        self.runde(u, 0)
        self.assertFalse(self.runde(u, 45, ["job:media-staging.service"])["ruhe_kandidat"])
        self.assertTrue(self.runde(u, 46)["ruhe_kandidat"])


if __name__ == "__main__":
    unittest.main()
