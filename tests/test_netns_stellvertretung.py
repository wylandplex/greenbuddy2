"""Netztest Teil A (Spec 5a.6): der echte gb-stellvertreter in Wegwerf-Namensräumen (opt-in, GB_NETNS=1).

Topologie (tests/netns/netz.py): Brücke mit proxy (eth0 192.168.1.100, wg0 10.0.0.1), host (MAC von vhost01,
192.168.1.110), client (192.168.1.18) und router (192.168.1.1, dahinter WAN 198.51.100.0/24 und 203.0.113.0/24);
VPN-Gegenstelle 10.0.0.2 über echtes WireGuard (sonst veth). Das Szenario (tests/netns/szenario.py) läuft als PID 1
in "unshare -Urnmpf --kill-child --mount-proc": endet es oder wird es getötet, sterben alle Prozesse und
Namensräume mit. Dort wird gemessen (Mitschnitt an der Brücke, ip/nft, Sockets, Protokoll, SSH-Antworten), hier
bewertet. Aufruf: GB_NETNS=1 python3 -m unittest tests.test_netns_stellvertretung -v
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SZENARIO = ROOT / "tests" / "netns" / "szenario.py"
FRIST = 180
PFAD = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
UNSHARE = ["unshare", "--user", "--map-root-user", "--net", "--mount", "--pid", "--fork", "--kill-child",
           "--mount-proc"]
ECHT, EIGEN, BROADCAST = "00:00:5e:00:53:10", "02:00:00:00:00:01", "ff:ff:ff:ff:ff:ff"
ANDERE = "02:00:00:00:00:77"
HOST, PROXY, CLIENT = "192.168.1.110", "192.168.1.100", "192.168.1.18"
BEIDE = ["arp gb2_sv_vhost01_arp", "ip gb2_sv_vhost01"]
KEINE = {"alias": False, "tabellen": []}
WECKUNG = {"zeit", "weg", "port", "quellklasse", "entscheidung"}


def hindernis():
    if os.environ.get("GB_NETNS") != "1":
        return "opt-in: GB_NETNS=1 (unshare, Brücke, veth, nft, WireGuard)"
    fehlt = [werkzeug for werkzeug in ("unshare", "ip", "nft") if not shutil.which(werkzeug, path=PFAD)]
    if fehlt:
        return "Werkzeug fehlt: " + ", ".join(fehlt)
    try:
        run = subprocess.run(UNSHARE + ["true"], capture_output=True, timeout=10, env=dict(os.environ, PATH=PFAD))
    except (OSError, subprocess.SubprocessError) as error:
        return "unshare nicht nutzbar: %s" % error
    if run.returncode:
        return "unshare -Urnmpf nicht erlaubt: " + run.stderr.decode("utf-8", "replace").strip()[:200]
    return None


def restprozesse(marke, frist=3):
    """Prozesse, deren Kommandozeile das Arbeitsverzeichnis nennt (Dienst, Szenario); muss leer werden."""
    ende = time.monotonic() + frist
    while True:
        rest = []
        for eintrag in Path("/proc").iterdir():
            if not eintrag.name.isdigit() or int(eintrag.name) == os.getpid():
                continue
            try:
                cmdline = (eintrag / "cmdline").read_bytes()
            except OSError:
                continue
            if marke.encode() in cmdline:
                rest.append(cmdline.replace(b"\0", b" ").decode("utf-8", "replace")[:120])
        if not rest or time.monotonic() > ende:
            return rest
        time.sleep(0.1)


def zusammenfassung(bericht, dauer):
    if not bericht:
        return "Netztest: kein Bericht"
    u, s = bericht.get("umgebung", {}), bericht.get("schritte", {})

    def w(name):
        return (s.get(name) or {}).get("werte", {})
    zeilen = ["Netztest gb-stellvertreter: %.1f s, Python %s, %s, VPN %s" % (
        dauer, u.get("python"), u.get("nft"), u.get("vpn_art"))]
    s1, s2, s6, s7a, s7b, s8 = (w("s1_uebernahme_isolation"), w("s2_wol_zaehlung_limit"), w("s6_host_wacht_auf"),
                                w("s7a_lease_ablauf"), w("s7b_abschalter"), w("s8_lebendprobe"))
    zeilen.append("  Übernahme %s s nach Stille (gemessene Stille %s s), GARP %s s, ARP-Antwort %s, SSH .110: %s"
                  % (s1.get("uebernahme_nach_s"), s1.get("stille_vor_uebernahme_s"), s1.get("garp_abstaende_s"),
                     s1.get("arp_antworten"), s1.get("ssh_110")))
    zeilen.append("  SYN->WOL %s ms, WOL-Versuche je Serie %s, Limitrunden %s" % (
        s2.get("syn_bis_wol_ms"), s2.get("wol_versuche"),
        [[r.get("ausloeser", [{}])[0].get("entscheidung") if r.get("ausloeser") else None, r.get("wol")]
         for r in s2.get("runden", [])]))
    zeilen.append("  Freigabe nach Frame der echten MAC: Alias %s ms, nft %s ms; Lease-Ablauf: Alias %s ms, WOL %s ms;"
                  " Abschalter: Alias %s ms; Lebendprobe: Alias %s ms" % (
                      s6.get("alias_weg_ms"), s6.get("nft_weg_ms"), s7a.get("alias_weg_ms"),
                      s7a.get("wol_nach_lease_ms"), s7b.get("alias_weg_ms"), s8.get("alias_weg_ms")))
    s8b = w("s8b_fremde_mac")
    zeilen.append("  Fremde MAC auf .110: warte_stille ohne Übernahme nach %s s (Phasen %s);"
                  " in uebernommen Alias %s ms, nft %s ms" % (s8b.get("freigabe_warte_stille_s"), (s8b.get("warte_stille") or {}).get("phasen"),
                                   s8b.get("alias_weg_ms"), s8b.get("nft_weg_ms")))
    entscheidungen = w("s9_ende").get("weckentscheidungen", [])
    zeilen.append("  Weckentscheidungen: " + ", ".join(
        "%s/%s/%s/Weg %s=%s%s" % (r.get("quellklasse"), r.get("port"), r.get("quell_ip"), r.get("weg"),
                                  r.get("entscheidung"), ":" + r["limit"] if r.get("limit") else "")
        for r in entscheidungen))
    zeilen.append("  Verdichtet (R9): " + ", ".join(w("s7a_lease_ablauf").get("verdichtet_dienst1", [])))
    for name, eintrag in s.items():
        if eintrag.get("fehler"):
            zeilen.append("  FEHLER %s: %s" % (name, eintrag["fehler"].strip().splitlines()[-1]))
    return "\n".join(zeilen)


def ohne_ip(weckung):
    return set(weckung) == WECKUNG and not any(isinstance(v, str) and v.count(".") == 3 for v in weckung.values())


class NetzStellvertretungTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        grund = hindernis()
        if grund:
            raise unittest.SkipTest(grund)
        cls.tmp = tempfile.TemporaryDirectory(prefix="gb-netns-")
        env = dict(os.environ, GB_NETNS_INNEN="1", PATH=PFAD)
        start = time.monotonic()
        cls.lauf, cls.zeitueberschreitung = None, False
        try:
            cls.lauf = subprocess.run(UNSHARE + [sys.executable, "-I", str(SZENARIO), cls.tmp.name], env=env,
                                      capture_output=True, text=True, timeout=FRIST)
        except subprocess.TimeoutExpired:
            # subprocess tötet unshare; --kill-child nimmt PID 1 und damit den ganzen Namensraum mit.
            cls.zeitueberschreitung = True
        cls.dauer = time.monotonic() - start
        cls.rest = restprozesse(cls.tmp.name)
        try:
            cls.bericht = json.loads((Path(cls.tmp.name) / "bericht.json").read_text())
        except (OSError, ValueError):
            cls.bericht = None
        print("\n" + zusammenfassung(cls.bericht, cls.dauer), file=sys.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def schritt(self, name):
        if self.bericht is None:
            self.fail("kein Bericht; stderr: %s" % (self.lauf.stderr[-3000:] if self.lauf else "Zeitüberschreitung"))
        if self.bericht.get("fehler"):
            self.fail("Aufbau gescheitert: " + self.bericht["fehler"])
        eintrag = self.bericht["schritte"].get(name)
        if eintrag is None:
            self.fail("Schritt %s fehlt (Zeitüberschreitung: %s)" % (name, self.zeitueberschreitung))
        if eintrag["fehler"]:
            self.fail("%s: %s\nLog: %s" % (name, eintrag["fehler"], eintrag.get("log_ende")))
        return eintrag["werte"]

    def ssh_ok(self, row, phase):
        self.assertEqual((row["exit"], row["zeilen"], row["stderr"]), (0, 1, ""), row)
        self.assertEqual(row["antwort"]["zustand"]["phase"], phase, row)
        return row["antwort"]

    def kurz(self, ausloeser, *felder):
        return [tuple(row.get(feld) for feld in ("entscheidung", "port", "quellklasse", "weg") + felder)
                for row in ausloeser]

    # ------------------------------------------------------------ Rahmen

    def test_0_lebensdauer_und_laufzeit(self):
        self.assertFalse(self.zeitueberschreitung, "Szenario länger als %d s" % FRIST)
        self.assertEqual(self.lauf.returncode, 0, self.lauf.stderr[-3000:])
        self.assertLess(self.dauer, FRIST)
        # Kein Dienst, kein Szenario und damit kein Namensraum überlebt den Test.
        self.assertEqual(self.rest, [])
        self.assertIsNone(self.bericht["fehler"])
        self.assertEqual(self.bericht["umgebung"]["bereit_fuer"], ["vhost01"])

    def test_0b_abbruch_mitten_im_lauf_hinterlaesst_nichts(self):
        # Wie bei einer Zeitüberschreitung: unshare wird hart getötet, während Dienst und Netz laufen.
        with tempfile.TemporaryDirectory(prefix="gb-netns-abbruch-") as arbeit:
            lauf = subprocess.Popen(UNSHARE + [sys.executable, "-I", str(SZENARIO), arbeit],
                                    env=dict(os.environ, GB_NETNS_INNEN="1", PATH=PFAD),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                ende = time.monotonic() + 30
                while not (Path(arbeit) / "dienst1.err").exists() and time.monotonic() < ende:
                    time.sleep(0.1)
                time.sleep(1)
                self.assertTrue(restprozesse(arbeit, 0), "Dienst lief nicht")
            finally:
                lauf.kill()
                lauf.wait()
            self.assertEqual(restprozesse(arbeit), [])

    # ------------------------------------------------------------ 1. Übernahme und Isolation

    def test_1_uebernahme_nach_stille_und_isolation(self):
        w = self.schritt("s1_uebernahme_isolation")
        # SSH-Zwangsbefehl wie aus authorized_keys (argv --host, Befehl nur aus SSH_ORIGINAL_COMMAND).
        status = self.ssh_ok(w["status"], "unbekannt")
        self.assertEqual((status["bereit"], status["grund"]), (True, None))
        self.assertEqual((w["schlafe_ohne_sekunden"]["exit"], w["schlafe_ohne_sekunden"]["antwort"]),
                         (1, {"bereit": False, "fehler": "befehl_argumente"}))
        self.assertEqual((w["schlafe_599"]["exit"], w["schlafe_599"]["antwort"]),
                         (1, {"bereit": False, "fehler": "sekunden_ungueltig"}))
        self.assertTrue(self.ssh_ok(w["abmelden"], "abgemeldet")["bereit"])
        schlaf = self.ssh_ok(w["schlafe_jetzt"], "schlaf_absicht")
        self.assertTrue(schlaf["bereit"])
        self.assertEqual(schlaf["zustand"]["schlaf_s"], 600)
        self.assertAlmostEqual(schlaf["zustand"]["ablauf"] - schlaf["zustand"]["beginn"], 1500, delta=5)
        # Host wach: er beantwortet jede Probe, es wird nichts übernommen (Befund stille_s = 1, 12.10.26).
        wach = w["wach_3s"]
        self.assertEqual((wach["phase"], wach["alias"]), ("warte_stille", False))
        self.assertGreaterEqual(wach["proben"], 7)
        self.assertGreaterEqual(wach["antworten_host"], wach["proben"] - 1)
        # Host schweigt: Übernahme frühestens nach stille_s (1 s) seit seinem letzten Rahmen.
        self.assertGreaterEqual(w["stille_vor_uebernahme_s"], 1.0)
        self.assertLess(w["uebernahme_nach_s"], 2.5)
        self.assertEqual(w["fakten"], {"alias": True, "tabellen": BEIDE})
        self.assertEqual(w["ketten"], ["ausgang output -300", "eingang input -300"])
        self.assertEqual([round(t) for t in w["garp_abstaende_s"]], [0, 1, 3])
        # Client fragt nach .110: genau eine Antwort, mit proxy01s MAC.
        self.assertEqual(w["arp_antworten"], [["proxy", EIGEN]])
        self.assertEqual(w["client_neigh_110"], EIGEN)
        # sshd-Ersatz auf 0.0.0.0:22: unter .110 weder SYN-ACK noch RST noch Banner, unter .100 erreichbar.
        self.assertEqual(w["ssh_110"], "timeout")
        self.assertEqual(w["tcp_von_110"], 0)
        self.assertEqual(w["ssh_100"], "banner:SSH-2.0-proxy01-ersatz")
        self.assertEqual(w["sshd_ersatz"], [PROXY])
        # Lokal erzeugter Verkehr an .110 endet in der Ausgangskette.
        self.assertIn(w["lokal_tcp_22"], ("timeout", "EPERM"))
        self.assertIn(w["lokal_tcp_32400"], ("timeout", "EPERM"))
        self.assertEqual(w["lokal_udp"], "EPERM")
        self.assertEqual(w["sshd_ersatz_lokal"], 0)

    # ------------------------------------------------------------ 2. SYN-Wecken, Zählung, Limit

    def test_2_syn_weckt_einmal_und_limit_an_der_grenze(self):
        w = self.schritt("s2_wol_zaehlung_limit")
        self.assertGreaterEqual(w["kernel_syns"], 2)
        # SYN + Wiederholung des Kernels: eine Weckentscheidung, Magic Packet an beide Broadcast-Ziele.
        self.assertEqual(self.kurz(w["ausloeser_kernel"], "quell_ip"), [("wecken", 22, "LAN", 4, CLIENT)])
        self.assertLess(w["syn_bis_wol_ms"], 100)
        self.assertEqual(w["wol_versuche"], [0, 1])
        self.assertEqual(w["wol_ziele"], [[BROADCAST, "192.168.1.255", 9], [BROADCAST, "255.255.255.255", 9]])
        self.assertEqual(w["gescheitert"], 1)
        runden = {row["nr"]: row for row in w["runden"]}
        # Runde 2 schickt zwei SYNs in dieselbe Weckung; gezählt wird einer.
        for nr in (2, 3):
            self.assertEqual(self.kurz(runden[nr]["ausloeser"], "quell_ip"), [("wecken", 22, "LAN", 4, CLIENT)])
            self.assertEqual(runden[nr]["phase"], "wecken")
            self.assertGreaterEqual(runden[nr]["wol"], 1)
        # lan_quelle_h = 3: die vierte Weckung derselben Quelle in der Stunde ist gesperrt, kein WOL.
        self.assertEqual(self.kurz(runden[4]["ausloeser"], "limit"), [("limit", 22, "LAN", 4, "lan_quelle_h")])
        self.assertEqual((runden[4]["wol"], runden[4]["phase"]), (0, "uebernommen"))
        # Das Limit gilt je Quelle.
        self.assertEqual(self.kurz(runden[5]["ausloeser"], "quell_ip"), [("wecken", 22, "LAN", 4, "192.168.1.19")])
        # Ohne Zählung (R6): die Wiederholungen des Kernels und der zweite SYN aus Runde 2.
        verdichtet = self.schritt("s7a_lease_ablauf")["verdichtet_dienst1"]
        self.assertIn("22 LAN wecken_laeuft x%d" % (w["kernel_syns"] - 1 + 1), verdichtet)

    # ------------------------------------------------------------ 3./4. Inhaltsweg (WAN) und Allowlist

    def test_3_wan_tls_sni_und_allowlist(self):
        w = self.schritt("s3_wan_tls")
        for name in ("sni_falscher_hash", "sni_fremdes_label", "http_aus_wan"):
            self.assertEqual(w[name], "rst_nach_daten", name)
        self.assertEqual(w["ohne_daten"], "rst_ohne_daten")
        self.assertAlmostEqual(w["ohne_daten_rst_nach_s"], 5, delta=0.6)
        self.assertEqual((w["wan_ssh_syn"], w["liste_falsche_quelle"]), ("timeout", "timeout"))
        self.assertEqual(w["ohne_weckung"], {"ausloeser": [], "wol": 0, "phase": "uebernommen"})
        self.assertEqual(w["rst_von_32400"], 4)
        self.assertEqual(w["sni_gueltig"], "rst_nach_daten")
        self.assertEqual(self.kurz(w["gueltig"]["ausloeser"], "sni_label", "quell_ip"),
                         [("wecken", 32400, "WAN", 7, "lan", "198.51.100.7")])
        self.assertGreaterEqual(w["gueltig"]["wol"], 1)
        self.assertEqual(w["liste_gueltig"], "timeout")
        self.assertEqual(self.kurz(w["liste"]["ausloeser"], "quell_ip"), [("wecken", 8443, "WAN", 5, "203.0.113.10")])
        self.assertGreaterEqual(w["liste"]["wol"], 1)
        verdichtet = self.schritt("s7a_lease_ablauf")["verdichtet_dienst1"]
        for zeile in ("32400 WAN spam x3", "32400 WAN unklar x1", "8443 WAN verworfen x2"):
            self.assertIn(zeile, verdichtet)

    def test_4_minecraft_status_nein_whitelist_login_ja(self):
        w = self.schritt("s4_minecraft")
        for name in ("status_ping", "legacy_ping", "login_fremd", "login_whitelist"):
            self.assertEqual(w[name], "rst_nach_daten", name)
        self.assertEqual(w["ohne_weckung"], {"ausloeser": [], "wol": 0})
        self.assertEqual(self.kurz(w["weckung"]["ausloeser"], "quell_ip"),
                         [("wecken", 25565, "WAN", 7, "198.51.100.8")])
        self.assertGreaterEqual(w["weckung"]["wol"], 1)
        self.assertEqual(w["rst_von_25565"], 1)
        self.assertIn("25565 WAN spam x3", self.schritt("s7a_lease_ablauf")["verdichtet_dienst1"])

    # ------------------------------------------------------------ 5. VPN

    def test_5_vpn_syn_weckt_als_vpn(self):
        w = self.schritt("s5_vpn")
        self.assertIn(w["vpn_art"], ("wireguard", "veth"))
        self.assertEqual(w["tunnel_kontrolle"], "banner:SSH-2.0-proxy01-ersatz")
        self.assertEqual(w["vpn_ssh_110"], "timeout")
        self.assertEqual(self.kurz(w["weckung"]["ausloeser"], "quell_ip"), [("wecken", 22, "VPN", 4, "10.0.0.2")])
        self.assertGreaterEqual(w["weckung"]["wol"], 1)
        self.assertTrue(ohne_ip(w["status_weckung"]), w["status_weckung"])
        self.assertEqual((w["status_weckung"]["weg"], w["status_weckung"]["quellklasse"]), (4, "VPN"))

    # ------------------------------------------------------------ 6. Host wacht auf

    def test_6_frame_der_echten_mac_gibt_unter_100ms_frei(self):
        w = self.schritt("s6_host_wacht_auf")
        self.assertLess(w["alias_weg_ms"], 100)
        self.assertLess(w["nft_weg_ms"], 100)
        self.assertEqual(w["gruende"], ["echte_mac"])
        self.assertEqual(len(w["wecken_erfolg"]), 1)
        self.assertEqual(w["fakten"], KEINE)
        # proxy01 beantwortet die ARP-Probe des Hosts nicht; die Weckserie endet mit der Freigabe.
        self.assertEqual(w["arp_antworten_proxy"], 0)
        self.assertEqual(w["wol_nach_freigabe"], 0)
        self.assertIsNone(w["grund_nach_freigabe"])
        # Nach dem GARP des Hosts (R7) erreicht der Client ihn direkt unter .110.
        self.assertEqual(w["client_neigh_110"], ECHT)
        self.assertEqual(w["client_ssh_110"], "banner:SSH-2.0-vhost01-ersatz")
        self.assertEqual(w["client_syn_ziel_mac"], ECHT)
        self.assertEqual(w["host_lauscher"], [CLIENT])
        antwort = self.ssh_ok(w["anmelden"], "angemeldet")
        self.assertEqual((antwort["bereit"], antwort["grund"]), (True, None))
        self.assertTrue(ohne_ip(antwort["weckung"]), antwort["weckung"])
        self.assertEqual({k: antwort["weckung"][k] for k in ("weg", "port", "quellklasse", "entscheidung")},
                         {"weg": 4, "port": 22, "quellklasse": "LAN", "entscheidung": "wecken"})

    # ------------------------------------------------------------ 7. Lease, Abschalter, SIGKILL

    def test_7a_lease_ablauf_gibt_frei_und_weckt(self):
        w = self.schritt("s7a_lease_ablauf")
        self.assertEqual(w["sigterm_exit_dienst1"], 0)
        self.assertEqual(w["fakten_uebernommen"], {"alias": True, "tabellen": BEIDE})
        self.assertGreater(w["alias_weg_ms"], -50)
        self.assertLess(w["alias_weg_ms"], 500)
        self.assertLess(w["nft_weg_ms"], 500)
        self.assertLess(w["wol_nach_lease_ms"], 500)
        self.assertEqual((w["gruende"], w["ereignis"]), (["lease_abgelaufen"], 1))
        # Der Zyklus ist erledigt: keine neue Übernahme, obwohl der Host weiter schweigt.
        self.assertEqual(w["fakten_danach"], dict(KEINE, phase="frei"))
        weckung = self.ssh_ok(w["anmelden"], "angemeldet")["weckung"]
        self.assertTrue(ohne_ip(weckung), weckung)
        self.assertEqual((weckung["entscheidung"], weckung["weg"], weckung["port"], weckung["quellklasse"]),
                         ("lease_abgelaufen", None, None, None))

    def test_7b_abschalter_gibt_frei_und_weckt(self):
        w = self.schritt("s7b_abschalter")
        self.assertEqual(w["fakten_uebernommen"], {"alias": True, "tabellen": BEIDE})
        self.assertLess(w["alias_weg_ms"], 1200)
        self.assertLess(w["nft_weg_ms"], 1200)
        self.assertEqual(w["gruende"], ["abgeschaltet"])
        self.assertEqual(w["status"], {"abgeschaltet": True, "bereit_fuer": [], "grund": "abgeschaltet"})
        self.assertGreaterEqual(w["wol"], 1)
        antwort = self.ssh_ok(w["ssh_status"], "schlaf_absicht")
        self.assertEqual((antwort["bereit"], antwort["grund"], antwort["stellvertreter"]["grund"]),
                         (False, "stellvertreter_nicht_bereit", "abgeschaltet"))
        self.assertEqual(w["fakten_abgeschaltet"], KEINE)
        # Abschalter weg, Host schläft weiter: derselbe Zyklus wird wieder übernommen, anmelden gibt frei.
        self.assertLess(w["wieder_uebernommen_s"], 6)
        self.assertEqual(self.ssh_ok(w["anmelden"], "angemeldet")["weckung"]["entscheidung"], "abgeschaltet")
        self.assertEqual(w["gruende_anmelden"], ["register_angemeldet"])
        self.assertLess(w["freigabe_nach_anmelden_s"], 2)
        self.assertEqual(w["fakten_angemeldet"], KEINE)

    def test_7c_sigkill_aufraeumen_und_neustart(self):
        w = self.schritt("s7c_sigkill_neustart")
        self.assertEqual(w["fakten_uebernommen"], {"alias": True, "tabellen": BEIDE})
        # Dienst angehalten: die nft-ARP-Tabelle allein unterdrückt die Antwort an die echte MAC.
        self.assertEqual((w["antwort_auf_echte_mac"], w["antwort_auf_client"]), (0, 1))
        self.assertEqual(w["sigkill_exit"], -9)
        self.assertEqual(w["fakten_nach_sigkill"], {"alias": True, "tabellen": BEIDE})
        self.assertEqual((w["aufraeumen"]["exit"], sorted(w["aufraeumen"]["ausgabe"]["entfernt"]),
                          w["aufraeumen"]["ausgabe"]["fehler"]), (0, ["alias:vhost01", "nft:vhost01"], []))
        self.assertEqual(w["fakten_nach_aufraeumen"], KEINE)
        self.assertEqual((w["aufraeumen_erneut"]["exit"], w["aufraeumen_erneut"]["ausgabe"]["entfernt"]), (0, []))
        # Neustart: Register erlaubt, aber der Host antwortet -> keine Übernahme; schweigt er, dann schon.
        self.assertEqual(w["neustart_host_wach"], dict(KEINE, phase="warte_stille"))
        self.assertLess(w["neustart_uebernahme_s"], 3)
        self.assertEqual((w["sigterm_exit"], w["gruende_sigterm"]), (0, ["dienst_ende"]))
        self.assertEqual(w["fakten_nach_sigterm"], KEINE)
        self.assertLess(w["nach_dienstende_wieder_s"], 3)
        self.ssh_ok(w["anmelden"], "angemeldet")
        self.assertEqual(w["gruende_anmelden"], ["register_angemeldet"])
        # Neustart mit angemeldetem Register: keine Übernahme.
        self.assertEqual(w["sigterm_exit_2"], 0)
        self.assertEqual(w["neustart_angemeldet"], dict(KEINE, phase="frei"))

    # ------------------------------------------------------------ 8. Lebendprobe

    def test_8_lebendprobe_findet_still_erwachten_host(self):
        w = self.schritt("s8_lebendprobe")
        self.assertEqual(w["fakten_uebernommen"], {"alias": True, "tabellen": BEIDE})
        self.assertLess(w["alias_weg_ms"], 1200)
        self.assertLess(w["nft_weg_ms"], 1200)
        # Erster Rahmen des Hosts ist seine Antwort auf proxy01s Lebendprobe (who-has .110 tell .100).
        self.assertEqual(w["erster_host_rahmen"], {"art": "arp", "op": 2, "spa": HOST, "tpa": PROXY, "dst": EIGEN})
        self.assertLess(w["probe_vor_antwort_ms"], 50)
        self.assertTrue(all(abs(a - 1.0) < 0.1 for a in w["proben_abstand_s"]), w["proben_abstand_s"])
        self.assertEqual(w["gruende"], ["echte_mac"])
        self.assertEqual(w["fakten"], KEINE)
        self.assertIsNone(self.ssh_ok(w["anmelden"], "angemeldet")["weckung"])

    def test_8b_fremde_mac_wird_nie_uebernommen_und_gibt_sofort_frei(self):
        # Review b5 (netz-fremde-mac): vhost01 mit gewechselter MAC oder ein anderes Gerät auf .110.
        w = self.schritt("s8b_fremde_mac")
        a = w["warte_stille"]
        self.assertLess(w["freigabe_warte_stille_s"], 3)
        self.assertGreaterEqual(a["antworten_host"], 1)
        self.assertEqual(a["phasen"], ["warte_stille", "frei"])
        self.assertEqual(a["fremde_mac"], [{"mac": ANDERE, "phase": "warte_stille", "zyklus": "netz6"}])
        # Kein GARP, kein Alias, auch nicht, als der Host danach schwieg (Zyklus erledigt); WOL statt Alias.
        self.assertEqual(a["garps_proxy"], 0)
        self.assertEqual(a["fakten"], dict(KEINE, phase="frei"))
        self.assertGreaterEqual(a["wol"], 1)
        self.assertEqual(self.ssh_ok(w["anmelden_netz6"], "angemeldet")["weckung"]["entscheidung"], "fremde_mac")
        # Übernahme steht, ein fremdes GARP für .110: Freigabe wie beim Frame der echten MAC.
        self.assertEqual(w["fakten_uebernommen"], {"alias": True, "tabellen": BEIDE})
        self.assertLess(w["alias_weg_ms"], 100)
        self.assertLess(w["nft_weg_ms"], 100)
        self.assertEqual(w["gruende"], ["fremde_mac"])
        self.assertEqual(w["fremde_mac_uebernommen"], [{"mac": ANDERE, "phase": "uebernommen", "zyklus": "netz7"}])
        self.assertEqual(w["danach"], dict(KEINE, phase="frei"))
        self.assertGreaterEqual(w["wol_uebernommen"], 1)
        self.ssh_ok(w["anmelden_netz7"], "angemeldet")

    # ------------------------------------------------------------ Ende

    def test_9_dienstende_sauber(self):
        w = self.schritt("s9_ende")
        self.assertEqual((w["sigterm_exit"], w["ende"]), (0, ["dienst_ende"]))
        self.assertEqual((w["aufraeumen"]["exit"], w["aufraeumen"]["ausgabe"]["entfernt"]), (0, []))
        self.assertEqual(w["fakten"], KEINE)
        self.assertEqual(w["dienst_stderr"], "")
        # Alle Weckentscheidungen des Laufs (s1-s6), ohne die verdichteten Spam-/Laufend-Zähler.
        lan = ("LAN", 22, 4, "wecken")
        self.assertEqual([(r["quellklasse"], r["port"], r["weg"], r["entscheidung"]) for r in w["weckentscheidungen"]],
                         [lan, lan, lan, ("LAN", 22, 4, "limit"), lan, ("WAN", 32400, 7, "wecken"),
                          ("WAN", 8443, 5, "wecken"), ("WAN", 25565, 7, "wecken"), ("VPN", 22, 4, "wecken"), lan])


if __name__ == "__main__":
    unittest.main()
