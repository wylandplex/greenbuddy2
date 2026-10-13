"""Weitere Verbraucher (Review 07.10.26): Samba, Fileserver, fremde Ports, closing-Sitzungen, Transienten.

Alle Hostbefehle laufen über einen Fake-Runner; nichts wird ausgeführt.
"""

import json
import re
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from greenbuddy2 import fakten_vhost as f
from greenbuddy2.konfig import SCHLAF, laden
from fixtures import MDSTAT

ROOT = Path(__file__).resolve().parents[1]
KONTEN = {"automation": 1047, "jellyfin": 1048, "mediauser": 1000}
INAKTIV = "LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlPID=0\n"
LAUSCHEND = """LISTEN 0      128          0.0.0.0:22    0.0.0.0:*
LISTEN 0      50           0.0.0.0:445   0.0.0.0:*
LISTEN 0      4096               *:8081        *:*
LISTEN 0      4096               *:32400       *:*
LISTEN 0      4096               *:25565       *:*
LISTEN 0      4096         0.0.0.0:9090  0.0.0.0:*
LISTEN 0      4096       127.0.0.1:7878  0.0.0.0:*
LISTEN 0      4096           [::1]:631      [::]:*
LISTEN 0      4096   127.0.0.53%lo:53    0.0.0.0:*
"""


def result(text="", code=0):
    return types.SimpleNamespace(returncode=code, stdout=text)


class Host:
    """Antwortet wie vhost01 im Leerlauf; einzelne Antworten sind pro Test überschreibbar."""

    def __init__(self):
        self.sitzungen = ""
        self.remote = {}
        self.jobs = {}
        self.lauschend = LAUSCHEND
        self.verbindungen = ""
        self.info = ""
        self.transienten = {None: ""}
        self.fehler = set()
        self.calls = []

    def __call__(self, args, **kwargs):
        args = list(args)
        self.calls.append(args)
        user = None
        if args[0] == "/usr/bin/setpriv":
            uid = int(args[1].split("=", 1)[1])
            user = next(name for name, value in KONTEN.items() if value == uid)
            args = args[args.index("/usr/bin/systemctl"):]
        if args[:2] == ["loginctl", "list-sessions"]:
            return result(self.sitzungen)
        if args[:2] == ["loginctl", "show-session"]:
            return result(self.remote[args[2]])
        if "list-units" in args:
            if ("transient", user) in self.fehler:
                return result("", 1)
            return result(self.transienten.get(user, ""))
        if "show" in args and args[0] == "/usr/bin/systemctl":
            return result(self.jobs.get(args[-1], INAKTIV))
        if args[0] == "nvidia-smi":
            return result("")
        if args == ["ss", "-Htln"]:
            return result(self.lauschend)
        if args[:2] == ["ss", "-Htn"]:
            return result(self.verbindungen)
        if args[:2] == ["ss", "-Htni"]:
            return result("", 1) if "info" in self.fehler else result(self.info)
        return result("", 1)


def konto(name):
    return types.SimpleNamespace(pw_uid=KONTEN[name], pw_gid=KONTEN[name])


class VerbraucherTests(unittest.TestCase):
    def sammeln(self, host, **cfg):
        cfg = dict(SCHLAF, ansprueche="/nicht/vorhanden", raid_degradiert_erlaubt=True, **cfg)
        with mock.patch.object(f, "jellyfin", return_value=(False, None)), \
                mock.patch.object(Path, "read_text", return_value=MDSTAT), \
                mock.patch.object(f.ET, "parse", side_effect=ValueError("Test")), \
                mock.patch.object(f.pwd, "getpwnam", side_effect=konto):
            return f.Sammler(cfg, runner=host, proc=lambda: [["mdmon", "md127"]]).sammeln(1000)

    def test_leerlauf_ohne_veto(self):
        host = Host()
        host.verbindungen = "0 0 192.168.1.110:41234 192.168.1.115:2049\n"
        data = self.sammeln(host)
        self.assertEqual(data["vetos"], [])
        self.assertNotIn("verbindungen_unklar", data["unklar"])
        self.assertNotIn("ssh_unklar", data["unklar"])
        self.assertFalse([x for x in data["unklar"] if x.startswith("transient")], data["unklar"])

    # Befund 4: Samba bei Bedarf
    def test_samba_verbindung_445_ist_veto(self):
        host = Host()
        host.verbindungen = "0 0 192.168.1.110:445 192.168.1.20:50123\n"
        data = self.sammeln(host)
        self.assertIn("verbindung:445", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen"][445], 1)

    def test_smb_service_aktiv_ist_veto(self):
        self.assertIn("smb.service", SCHLAF["system_jobs"])
        beispiel = json.loads((ROOT / "deploy/vhost01/schlaf.example.json").read_text())
        self.assertIn("smb.service", beispiel["system_jobs"])
        host = Host()
        host.jobs["smb.service"] = "LoadState=loaded\nActiveState=active\nMainPID=4242\nControlPID=0\n"
        self.assertIn("job:smb.service", self.sammeln(host)["vetos"])

    # Befund 1: Fileserver und jeder andere lauschende Port
    def test_fileserver_8081_ist_veto(self):
        host = Host()
        host.verbindungen = "0 0 192.168.1.110:8081 192.168.1.20:51000\n"
        self.assertIn("verbindung:8081", self.sammeln(host)["vetos"])

    def test_fremder_lauschender_port_mit_fremdem_peer_ist_veto(self):
        host = Host()
        host.verbindungen = "0 0 192.168.1.110:9090 10.0.0.2:51000\n"
        data = self.sammeln(host)
        self.assertIn("verbindung:9090", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen"][9090], 1)

    def test_ipv6_und_ipv4_mapped(self):
        host = Host()
        host.verbindungen = "0 0 [::ffff:192.168.1.110]:8081 [::ffff:192.168.1.20]:5000\n"
        self.assertIn("verbindung:8081", self.sammeln(host)["vetos"])
        host.verbindungen = "0 0 [fe80::1%eno1]:9090 [fe80::2]:5000\n"
        self.assertIn("verbindung:9090", self.sammeln(host)["vetos"])

    def test_interne_und_ausgehende_verbindungen_kein_veto(self):
        host = Host()
        host.verbindungen = "\n".join([
            "0 0 127.0.0.1:7878 127.0.0.1:45678",           # Loopback zwischen Diensten
            "0 0 127.0.0.1:45678 127.0.0.1:7878",
            "0 0 192.168.1.110:9090 192.168.1.110:40000",   # eigener Host über die LAN-Adresse
            "0 0 [::1]:631 [::1]:4000",
            "0 0 [::ffff:127.0.0.1]:9090 [::ffff:127.0.0.1]:4001",
            "0 0 192.168.1.110:52000 140.82.121.4:443",      # ausgehend, kein lauschender Port
            "0 0 192.168.1.110:25565 198.51.100.7:40000",    # lazymc-Scanner (Ausnahme)
        ]) + "\n"
        data = self.sammeln(host)
        self.assertEqual([v for v in data["vetos"] if v.startswith("verbindung")], [])
        self.assertEqual(data["fakten"]["verbindungen"][25565], 1)

    def test_feste_ports_zaehlen_wie_bisher_auch_intern(self):
        host = Host()
        host.verbindungen = "0 0 127.0.0.1:32400 127.0.0.1:50000\n"
        self.assertIn("verbindung:32400", self.sammeln(host)["vetos"])

    def test_ausnahmen_konfigurierbar(self):
        host = Host()
        host.verbindungen = "0 0 192.168.1.110:9090 192.168.1.20:51000\n"
        data = self.sammeln(host, verbindung_ausnahmen=[25565, 9090])
        self.assertNotIn("verbindung:9090", data["vetos"])
        host.verbindungen = "0 0 192.168.1.110:25565 192.168.1.20:51000\n"
        self.assertNotIn("verbindung:25565", self.sammeln(host)["vetos"])

    def test_ss_fehler_und_kaputte_adressen_unklar(self):
        kaputt = Host()
        kaputt.verbindungen = "0 0 192.168.1.110:keinport 192.168.1.20:1\n"
        self.assertIn("verbindungen_unklar", self.sammeln(kaputt)["unklar"])
        kaputt.verbindungen = "0 0 nichtip:445 192.168.1.20:1\n"
        self.assertIn("verbindungen_unklar", self.sammeln(kaputt)["unklar"])

        class OhneListe(Host):
            def __call__(self, args, **kwargs):
                if list(args) == ["ss", "-Htln"]:
                    return result("", 1)
                return Host.__call__(self, args, **kwargs)
        self.assertIn("verbindungen_unklar", self.sammeln(OhneListe())["unklar"])

    # Befund 1: Arbeit nach dem SSH-Logout
    def test_closing_sitzung_ist_veto(self):
        host = Host()
        host.sitzungen = "12 1001 automation closing\n"
        data = self.sammeln(host)
        self.assertIn("sitzung_closing", data["vetos"])
        self.assertEqual(data["fakten"]["sitzungen_closing"], 1)
        self.assertNotIn("ssh_unklar", data["unklar"])

    def test_aktive_remote_sitzung_bleibt_ssh(self):
        host = Host()
        host.sitzungen = "3 1000 mediauser active\n"
        host.remote["3"] = "Remote=yes\nType=tty\nState=active\n"
        data = self.sammeln(host)
        self.assertIn("ssh_remote", data["vetos"])
        self.assertNotIn("sitzung_closing", data["vetos"])

    # Befund 1: systemd-run-Transienten
    def test_transienten_system_und_user_sind_veto(self):
        host = Host()
        host.transienten = {
            None: "run-u42.service loaded active running /usr/bin/python3 bif-pilot.py\n",
            "automation": "run-p77-i78.scope loaded active running [systemd-run] /usr/bin/bash\n",
        }
        data = self.sammeln(host)
        self.assertIn("transient:run-u42.service", data["vetos"])
        self.assertIn("transient:automation:run-p77-i78.scope", data["vetos"])
        self.assertEqual(data["fakten"]["transienten"], 2)
        abfragen = [c for c in host.calls if "list-units" in c]
        self.assertEqual(len(abfragen), 1 + len(SCHLAF["transient_benutzer"]))
        system = next(c for c in abfragen if c[0] != "/usr/bin/setpriv")
        self.assertEqual(system[-2:], ["run-*.service", "run-*.scope"])
        user = next(c for c in abfragen if "--reuid=1047" in c)
        self.assertIn("XDG_RUNTIME_DIR=/run/user/1047", user)
        self.assertEqual(user[user.index("/usr/bin/systemctl"):][:3], ["/usr/bin/systemctl", "--user", "list-units"])

    def test_transienten_inaktiv_oder_fehlgeschlagen_kein_veto(self):
        host = Host()
        host.transienten = {None: "● run-u1.service loaded failed failed /usr/bin/false\n"
                                  "run-u2.service loaded inactive dead /usr/bin/true\n"}
        data = self.sammeln(host)
        self.assertFalse([v for v in data["vetos"] if v.startswith("transient")])
        self.assertEqual(data["fakten"]["transienten"], 0)

    def test_transienten_abfragefehler_unklar(self):
        host = Host()
        host.fehler.add(("transient", "jellyfin"))
        self.assertIn("transient_unklar:jellyfin", self.sammeln(host)["unklar"])
        host = Host()
        host.transienten = {None: "run-u1.service loaded unbekannt running x\n"}
        self.assertIn("transient_unklar", self.sammeln(host)["unklar"])
        host = Host()
        with mock.patch.object(f.pwd, "getpwnam", side_effect=KeyError("fehlt")):
            data = f.Sammler(dict(SCHLAF, ansprueche="/nicht/vorhanden"), runner=host, proc=lambda: []).sammeln(1000)
        self.assertIn("transient_unklar:automation", data["unklar"])

    def test_konfig_neue_schluessel(self):
        self.assertEqual(SCHLAF["verbindung_ausnahmen"], [25565])
        self.assertEqual(sorted(SCHLAF["transient_benutzer"]), ["automation", "jellyfin", "mediauser"])
        beispiel = json.loads((ROOT / "deploy/vhost01/schlaf.example.json").read_text())
        self.assertEqual(beispiel["verbindung_ausnahmen"], [25565])
        self.assertEqual(sorted(beispiel["transient_benutzer"]), ["automation", "jellyfin", "mediauser"])
        for data in ({"verbindung_ausnahmen": "25565"}, {"verbindung_ausnahmen": [0]},
                     {"verbindung_ausnahmen": [65536]}, {"verbindung_ausnahmen": [True]},
                     {"transient_benutzer": "automation"}, {"transient_benutzer": [""]},
                     {"transient_benutzer": ["automation; id"]}):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "cfg.json"
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    laden(path, SCHLAF)



def info(lokal, peer, lastrcv=None, acked=100447, weiteres="bytes_received:1048 lastsnd:5121 lastack:5061",
         sendq=0):
    """Ausgabe von 'ss -Htni': Socketzeile, darunter die Infozeile mit Tab (ss 6.17)."""
    zeile = "\t cubic wscale:8,7 rto:251 rtt:50.217/2.95 mss:1460 "
    if acked is not None:
        zeile += "bytes_sent:%d bytes_acked:%d " % (acked, acked)
    zeile += weiteres
    if lastrcv is not None:
        zeile += " lastrcv:%d" % lastrcv
    return "0      %d      %s %s \n%s\n" % (sendq, lokal, peer, zeile)


PLEX = ("[::ffff:192.168.1.110]:32400", "[::ffff:203.0.113.5]:9250")


class RuhendeVerbindungenTests(unittest.TestCase):
    """Betreiber 12.10.26: Eine offene Plex-App ohne Wiedergabe darf nach ~15 min nicht mehr wachhalten.

    Gemessen 12.10.: WAN-Verbindung auf 32400, Gegenstelle seit 6 h ohne Daten (lastrcv 21586543 ms,
    3 Datensegmente gesamt), der Server sendet alle paar Sekunden. Blättern und Abspielen schicken
    Anfragen; dann ist lastrcv klein.
    """

    def sammeln(self, host, runden=2, zuwachs=300, **cfg):
        """Ruhend braucht zwei Runden: bytes_acked darf seit der Vorrunde kaum gewachsen sein.

        zuwachs = Bytes, die der Server zwischen den Runden bestätigt bekam (Websocket-Statusmeldungen
        ~280 B/min gemessen; ein Download Megabytes)."""
        cfg = dict(SCHLAF, ansprueche="/nicht/vorhanden", raid_degradiert_erlaubt=True, **cfg)
        with mock.patch.object(f, "jellyfin", return_value=(False, None)), \
                mock.patch.object(Path, "read_text", return_value=MDSTAT), \
                mock.patch.object(f.ET, "parse", side_effect=ValueError("Test")), \
                mock.patch.object(f.pwd, "getpwnam", side_effect=konto):
            sammler = f.Sammler(cfg, runner=host, proc=lambda: [["mdmon", "md127"]])
            for runde in range(runden):
                if runde:
                    host.info = re.sub(r"bytes_acked:([0-9]+)",
                                       lambda m: "bytes_acked:%d" % (int(m.group(1)) + zuwachs), host.info)
                data = sammler.sammeln(1000 + 60 * runde)
            return data

    def host(self, lastrcv, verbindung=PLEX):
        host = Host()
        host.verbindungen = "0 0 %s %s\n" % verbindung
        host.info = info(*verbindung, lastrcv=lastrcv)
        return host

    def test_ruhende_plex_verbindung_ist_kein_veto(self):
        data = self.sammeln(self.host(21586543))
        self.assertNotIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen"][32400], 1)
        self.assertEqual(data["fakten"]["verbindungen_ruhend"], {32400: 1})
        self.assertNotIn("verbindungen_unklar", data["unklar"])

    def test_frische_anfrage_ist_veto(self):
        data = self.sammeln(self.host(120000))
        self.assertIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_ruhend"], {})

    def test_grenze_15_minuten(self):
        self.assertIn("verbindung:32400", self.sammeln(self.host(899999))["vetos"])
        self.assertNotIn("verbindung:32400", self.sammeln(self.host(900000))["vetos"])

    def test_ohne_lastrcv_gilt_als_aktiv(self):
        # ss lässt lastrcv bei 0 weg: gerade eben Daten empfangen.
        self.assertIn("verbindung:32400", self.sammeln(self.host(None))["vetos"])

    def test_verbindung_ohne_infozeile_gilt_als_aktiv(self):
        host = self.host(21586543)
        host.info = ""
        self.assertIn("verbindung:32400", self.sammeln(host)["vetos"])

    def test_nur_eine_von_zwei_verbindungen_ruht(self):
        host = self.host(21586543)
        zweite = ("192.168.1.110:32400", "192.168.1.20:51000")
        host.verbindungen += "0 0 %s %s\n" % zweite
        host.info += info(*zweite, lastrcv=3000)
        data = self.sammeln(host)
        self.assertIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen"][32400], 2)
        self.assertEqual(data["fakten"]["verbindungen_ruhend"], {32400: 1})

    def test_weitere_ports_konfigurierbar(self):
        # Jellyfin-Apps senden alle ~30 s KeepAlive (lastrcv bleibt klein): deshalb nicht Standard.
        jelly = ("192.168.1.110:8096", "192.168.1.20:51000")
        self.assertIn("verbindung:8096", self.sammeln(self.host(21586543, jelly))["vetos"])
        data = self.sammeln(self.host(21586543, jelly), verbindung_ruhe_ports=[32400, 8096])
        self.assertNotIn("verbindung:8096", data["vetos"])

    # Review 12.10.26: Ein Download über eine einzige Anfrage sendet vom Client nur ACKs (lastrcv wächst).
    def test_laufender_download_bleibt_veto(self):
        data = self.sammeln(self.host(21586543), zuwachs=50 * 1024 * 1024)
        self.assertIn("verbindung:32400", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_ruhend"], {})

    def test_grenze_bytes_je_runde(self):
        self.assertNotIn("verbindung:32400", self.sammeln(self.host(21586543), zuwachs=65536)["vetos"])
        self.assertIn("verbindung:32400", self.sammeln(self.host(21586543), zuwachs=65537)["vetos"])

    def test_erste_runde_ohne_vergleich_ist_veto(self):
        self.assertIn("verbindung:32400", self.sammeln(self.host(21586543), runden=1)["vetos"])

    def test_ohne_bytes_acked_gilt_als_aktiv(self):
        host = Host()
        host.verbindungen = "0 0 %s %s\n" % PLEX
        host.info = info(*PLEX, lastrcv=21586543, acked=None)
        self.assertIn("verbindung:32400", self.sammeln(host)["vetos"])

    def test_kleinerer_zaehler_ist_neue_verbindung(self):
        self.assertIn("verbindung:32400", self.sammeln(self.host(21586543), zuwachs=-5000)["vetos"])

    def test_unklare_runde_vergisst_vorrunde(self):
        host = self.host(21586543)
        cfg = dict(SCHLAF, ansprueche="/nicht/vorhanden", raid_degradiert_erlaubt=True)
        with mock.patch.object(f, "jellyfin", return_value=(False, None)), \
                mock.patch.object(Path, "read_text", return_value=MDSTAT), \
                mock.patch.object(f.ET, "parse", side_effect=ValueError("Test")), \
                mock.patch.object(f.pwd, "getpwnam", side_effect=konto):
            sammler = f.Sammler(cfg, runner=host, proc=lambda: [["mdmon", "md127"]])
            sammler.sammeln(1000)
            host.fehler.add("info")
            self.assertIn("verbindungen_unklar", sammler.sammeln(1060)["unklar"])
            host.fehler.discard("info")
            self.assertIn("verbindung:32400", sammler.sammeln(1120)["vetos"])
            self.assertNotIn("verbindung:32400", sammler.sammeln(1180)["vetos"])

    def test_andere_ports_bleiben_veto_auch_bei_alter_gegenstelle(self):
        samba = ("192.168.1.110:445", "192.168.1.20:50123")
        data = self.sammeln(self.host(21586543, samba))
        self.assertIn("verbindung:445", data["vetos"])
        self.assertEqual(data["fakten"]["verbindungen_ruhend"], {})

    def test_abfrage_nur_fuer_ruhe_ports(self):
        host = self.host(21586543)
        self.sammeln(host)
        aufrufe = [c for c in host.calls if c[:2] == ["ss", "-Htni"]]
        self.assertEqual(aufrufe[0], ["ss", "-Htni", "state", "established", "(", "sport", "=", ":32400", ")"])
        host = self.host(21586543)
        self.sammeln(host, verbindung_ruhe_ports=[32400, 8096])
        self.assertEqual([c for c in host.calls if c[:2] == ["ss", "-Htni"]][0],
                         ["ss", "-Htni", "state", "established", "(", "sport", "=", ":32400",
                          "or", "sport", "=", ":8096", ")"])

    def test_infofehler_ist_unklar(self):
        host = self.host(21586543)
        host.fehler.add("info")
        self.assertIn("verbindungen_unklar", self.sammeln(host)["unklar"])

    def test_kaputte_infoausgabe_ist_unklar(self):
        host = self.host(21586543)
        host.info = "\t cubic lastrcv:5\n" + host.info      # Infozeile ohne Socketzeile davor
        self.assertIn("verbindungen_unklar", self.sammeln(host)["unklar"])

    def test_leere_portliste_schaltet_regel_ab(self):
        host = self.host(21586543)
        data = self.sammeln(host, verbindung_ruhe_ports=[])
        self.assertIn("verbindung:32400", data["vetos"])
        self.assertFalse([c for c in host.calls if c[:2] == ["ss", "-Htni"]])

    def test_schwelle_konfigurierbar(self):
        self.assertIn("verbindung:32400", self.sammeln(self.host(1000000), verbindung_ruhe_sekunden=1800)["vetos"])

    def test_standard_und_beispielkonfig(self):
        beispiel = json.loads((ROOT / "deploy/vhost01/schlaf.example.json").read_text())
        for cfg in (SCHLAF, beispiel):
            self.assertEqual(cfg["verbindung_ruhe_ports"], [32400])
            self.assertEqual(cfg["verbindung_ruhe_sekunden"], 900)
            self.assertEqual(cfg["verbindung_ruhe_bytes"], 65536)

    def test_konfig_prueft_ruhe_werte(self):
        for falsch in ({"verbindung_ruhe_ports": [0]}, {"verbindung_ruhe_ports": "32400"},
                       {"verbindung_ruhe_ports": [True]}, {"verbindung_ruhe_sekunden": 0},
                       {"verbindung_ruhe_sekunden": float("nan")}, {"verbindung_ruhe_sekunden": "900"},
                       {"verbindung_ruhe_bytes": -1}, {"verbindung_ruhe_bytes": 1.5}, {"verbindung_ruhe_bytes": True}):
            with tempfile.NamedTemporaryFile("w", suffix=".json") as datei:
                json.dump(falsch, datei)
                datei.flush()
                with self.assertRaises(ValueError, msg=falsch):
                    laden(datei.name, SCHLAF)


if __name__ == "__main__":
    unittest.main()
