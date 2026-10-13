"""Netztest-Szenario Teil A (Spec 5a.6): echter gb-stellvertreter im Wegwerf-Netz, Bericht als JSON.

Nur über tests/test_netns_stellvertretung.py starten; läuft als PID 1 in
"unshare -Urnmpf --kill-child --mount-proc" und endet mit allen Kindprozessen und Namensräumen.
Jeder Schritt misst Tatsachen (Mitschnitt an der Brücke, ip/nft, Sockets, Dienstprotokoll, Register-Antworten)
und legt sie unter bericht["schritte"][name]["werte"] ab; bewertet wird außerhalb.
"""

import errno
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

HIER = Path(__file__).resolve().parent
ROOT = HIER.parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(HIER)]

from fixtures import clienthello, minecraft  # noqa: E402
import netz  # noqa: E402
from netz import (BROADCAST, CLIENT, ECHT, EIGEN, HOST, NULL_MAC, PROXY, VPN_PEER, VPN_PROXY,  # noqa: E402
                  WAN_LISTE, WAN_MC, WAN_TLS, Lauscher, arp_rahmen, jetzt, roh, sh, syn_rahmen, verbinden)

HASH = "abc123def456"
ANDERE = "02:00:00:00:00:77"      # vhost01 nach NIC-/Bridge-Wechsel bzw. ein anderes Gerät auf .110
AUS = "/run/greenbuddy-test/aus"
TABELLEN = {("ip", "gb2_sv_vhost01"), ("arp", "gb2_sv_vhost01_arp")}
# Absichtlich der kleinste erlaubte Wert: damit fiel am 12.10.26 die Übernahme eines antwortenden Hosts auf.
STILLE_S = 1
DIENST = "import sys; sys.path.insert(0, %r); from greenbuddy2.stellvertreter import main; sys.exit(main(sys.argv[1:]))"
SSH = "import sys; sys.path.insert(0, %r); from greenbuddy2.proxy_ssh import main; sys.exit(main())"


class Zeitueberschreitung(AssertionError):
    pass


def alias_bind():
    sock = socket.socket()
    try:
        sock.bind((HOST, 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def gb2_tabellen():
    rows = json.loads(sh("nft", "-j", "list", "tables").stdout)["nftables"]
    return {(row["table"]["family"], row["table"]["name"]) for row in rows
            if "table" in row and row["table"]["name"].startswith("gb2_")}


class Freigabeuhr(threading.Thread):
    """Misst im proxy-Namensraum, wann der Alias (bind-Test) und beide Tabellen (nft -j) verschwunden sind."""

    def __init__(self, frist):
        super().__init__(daemon=True)
        self.frist, self.alias_weg, self.nft_weg = frist, None, None
        self.messungen = 0

    def run(self):
        ende = jetzt() + self.frist
        while jetzt() < ende and (self.alias_weg is None or self.nft_weg is None):
            self.messungen += 1
            if self.alias_weg is None and not alias_bind():
                self.alias_weg = jetzt()
            if self.nft_weg is None and not gb2_tabellen() & TABELLEN:
                self.nft_weg = jetzt()

    def ms(self, start):
        return {"alias_weg_ms": None if self.alias_weg is None else round((self.alias_weg - start) * 1000, 1),
                "nft_weg_ms": None if self.nft_weg is None else round((self.nft_weg - start) * 1000, 1),
                "messungen": self.messungen}


class Szenario:
    def __init__(self, arbeit):
        self.arbeit = Path(arbeit)
        self.cfg_pfad = self.arbeit / "stellvertreter.json"
        self.bericht = {"umgebung": {}, "schritte": {}, "fehler": None}
        self.dienst, self.dienst_nr, self.sport = None, 0, 40000
        self.beginn = jetzt()

    # ------------------------------------------------------------ Grundlagen

    def schreiben(self):
        self.bericht["laufzeit_s"] = round(jetzt() - self.beginn, 1)
        tmp = self.arbeit / "bericht.json.neu"
        tmp.write_text(json.dumps(self.bericht, ensure_ascii=False, default=str, indent=1))
        os.replace(str(tmp), str(self.arbeit / "bericht.json"))

    def konfig(self):
        cfg = json.loads((ROOT / "deploy/proxy01/stellvertreter.example.json").read_text())
        cfg.update(plex_hash=HASH, minecraft_whitelist=["Testspieler"], aus=AUS)
        cfg["stellvertretung"].update(stille_s=STILLE_S, stille_max_s=30, garp_s=60, lebendprobe_s=1,
                                      wol_wiederholen_s=1, wol_max_s=2)
        self.cfg, self.sv = cfg, cfg["stellvertretung"]
        self.cfg_pfad.write_text(json.dumps(cfg))
        os.makedirs(os.path.dirname(AUS))
        self.bericht["umgebung"]["konfig"] = {k: v for k, v in self.sv.items() if k != "hosts" and k != "probe"}

    def warten(self, bedingung, frist, was, takt=0.02):
        start = jetzt()
        while jetzt() - start < frist:
            if bedingung():
                return round(jetzt() - start, 3)
            time.sleep(takt)
        raise Zeitueberschreitung("%s nach %.1f s nicht erreicht; Phase %s; Log %s"
                                  % (was, frist, self.phase(), self.log()[-4:]))

    def status(self):
        try:
            return json.loads(Path(self.sv["status"]).read_text())
        except (OSError, ValueError):
            return None

    def phase(self):
        status = self.status()
        return status["phasen"].get("vhost01") if status else None

    def ist(self, phase, zyklus=None):
        """Statusbericht zeigt phase (und diesen Zyklus); verhindert Lesen eines veralteten Berichts."""
        status = self.status()
        return bool(status) and status["phasen"].get("vhost01") == phase and (
            zyklus is None or (status.get("zyklen") or {}).get("vhost01") == zyklus)

    def freigabe_abwarten(self, seit, frist=4):
        """Freigabe ist erst fertig, wenn die Phasenzeile geschrieben und der Bericht "frei" ist."""
        self.warten(lambda: self.freigaben(seit) and self.ist("frei"), frist, "freigabe")
        return self.freigaben(seit)

    def log(self):
        rows = []
        try:
            for zeile in Path(self.cfg["log"]).read_text().splitlines():
                try:
                    rows.append(json.loads(zeile))
                except ValueError:
                    pass
        except OSError:
            pass
        return rows

    def zeilen(self, seit, **merkmale):
        return [row for row in self.log() if row.get("zeit", 0) >= seit
                and all(row.get(k) == v for k, v in merkmale.items())]

    def ausloeser(self, seit):
        return [{k: row.get(k) for k in ("quell_ip", "port", "quellklasse", "weg", "entscheidung", "limit",
                                          "sni_label", "zyklus") if k in row}
                for row in self.zeilen(seit, ereignis="ausloeser")]

    def verdichtet(self):
        return sorted("%s %s %s x%d" % (row["port"], row["quellklasse"], row["entscheidung"], row["anzahl"])
                      for row in self.log() if row.get("verdichtet"))

    def freigaben(self, seit):
        return [row["grund"] for row in self.zeilen(seit, ereignis="phase", nach="frei")]

    def alias_da(self):
        rows = json.loads(sh("ip", "-j", "-4", "addr", "show", "dev", "eth0").stdout)
        return any(info.get("local") == HOST and info.get("prefixlen") == 32
                   for row in rows for info in row.get("addr_info", []))

    def tabellen(self):
        return sorted("%s %s" % tabelle for tabelle in gb2_tabellen())

    def fakten(self):
        return {"alias": self.alias_da(), "tabellen": self.tabellen()}

    def neigh(self, ns, ip):
        dev = {"client": "eth0", "router": "lan0"}[ns]
        rows = json.loads(netz.nsh(ns, "ip", "-j", "neigh", "show", ip, "dev", dev).stdout or "[]")
        return rows[0].get("lladdr") if rows else None

    def naechster_sport(self):
        self.sport += 1
        return self.sport

    def serie_abwarten(self, frist=6):
        """Weckserie (wol_max_s) zu Ende: Bericht wieder "uebernommen"."""
        if self.phase() == "wecken":
            return self.warten(lambda: self.phase() == "uebernommen", frist, "serienende")
        return 0.0

    # ------------------------------------------------------------ Dienst, Register, SSH

    def dienst_starten(self):
        self.dienst_nr += 1
        with open(str(self.arbeit / ("dienst%d.err" % self.dienst_nr)), "w") as fehler:
            self.dienst = subprocess.Popen([sys.executable, "-I", "-c", DIENST % str(ROOT), "--config",
                                            str(self.cfg_pfad)], stdout=fehler, stderr=subprocess.STDOUT)
        pid = self.dienst.pid
        return self.warten(lambda: (self.status() or {}).get("pid") == pid, 5, "dienst_start")

    def dienst_stoppen(self, sig=signal.SIGTERM):
        if self.dienst is None:
            return None
        if self.dienst.poll() is None:
            self.dienst.send_signal(sig)
        try:
            code = self.dienst.wait(10)
        except subprocess.TimeoutExpired:
            self.dienst.kill()
            code = "haengt"
            self.dienst.wait()
        self.dienst = None
        return code

    def cli(self, *args):
        run = subprocess.run([sys.executable, "-I", "-c", DIENST % str(ROOT), "--config", str(self.cfg_pfad)]
                             + list(args), capture_output=True, text=True, timeout=30)
        try:
            ausgabe = json.loads(run.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            ausgabe = run.stdout[-500:]
        return {"exit": run.returncode, "ausgabe": ausgabe, "stderr": run.stderr[-500:]}

    def ssh(self, befehl):
        """gb-proxy-ssh wie aus authorized_keys: argv --host vhost01, Befehl nur aus SSH_ORIGINAL_COMMAND."""
        env = {"PATH": os.environ["PATH"], "SSH_ORIGINAL_COMMAND": befehl}
        run = subprocess.run([sys.executable, "-I", "-c", SSH % str(ROOT), "--host", "vhost01"], env=env,
                             capture_output=True, text=True, timeout=30)
        zeilen = run.stdout.strip().splitlines()
        try:
            antwort = json.loads(zeilen[-1])
        except (IndexError, ValueError):
            antwort = None
        return {"exit": run.returncode, "zeilen": len(zeilen), "antwort": antwort, "stderr": run.stderr[-300:]}

    def register_setzen(self, zyklus, lease):
        """Testregister wie nach schlafe-jetzt, aber mit kurzem Lease (schlafe-jetzt erlaubt erst 600 s)."""
        wand, boot = time.time(), time.clock_gettime(time.CLOCK_BOOTTIME)
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        data = {"version": 1, "hosts": {"vhost01": {
            "zyklus": zyklus, "phase": "schlaf_absicht", "ablauf": wand + lease, "nachfrage": 0, "beginn": wand,
            "ablauf_boot": boot + lease, "boot_id": boot_id}}}
        pfad = Path(self.sv["register"])
        pfad.parent.mkdir(parents=True, exist_ok=True)
        tmp = pfad.with_name(pfad.name + ".neu")
        tmp.write_text(json.dumps(data))
        os.replace(str(tmp), str(pfad))
        return wand + lease

    def uebernahme_herbeifuehren(self, zyklus, lease, werte):
        self.warten(lambda: self.ist("frei"), 4, "frei vor " + zyklus)
        self.netz.host_schlaeft()
        lease_ende = self.register_setzen(zyklus, lease)
        werte["uebernahme_s"] = self.warten(lambda: self.ist("uebernommen", zyklus), 8, "uebernahme " + zyklus)
        werte["fakten_uebernommen"] = self.fakten()
        return lease_ende

    def neustart_sauber(self):
        self.dienst_stoppen(signal.SIGKILL)
        self.cli("--aufraeumen")
        for pfad in (AUS, self.sv["register"]):
            try:
                os.unlink(pfad)
            except FileNotFoundError:
                pass
        self.netz.host_wach()
        self.dienst_starten()

    def schritt(self, name, funktion):
        werte = {}
        eintrag = {"werte": werte, "fehler": None}
        self.bericht["schritte"][name] = eintrag
        start = jetzt()
        print("schritt %s ..." % name, file=sys.stderr, flush=True)
        try:
            funktion(werte)
        except Exception:
            eintrag["fehler"] = traceback.format_exc()[-3000:]
            eintrag["log_ende"] = self.log()[-8:]
            try:
                self.neustart_sauber()
            except Exception:
                eintrag["fehler"] += "\nNeustart: " + traceback.format_exc()[-1500:]
        eintrag["sekunden"] = round(jetzt() - start, 2)
        self.schreiben()

    # ------------------------------------------------------------ Schritte

    def s1_uebernahme_isolation(self, w):
        m = self.mitschnitt
        w["status"] = self.ssh("status")
        w["schlafe_ohne_sekunden"] = self.ssh("schlafe-jetzt netz1")
        w["abmelden"] = self.ssh("abmelden netz1")
        w["schlafe_599"] = self.ssh("schlafe-jetzt netz1 599")
        w["schlafe_jetzt"] = self.ssh("schlafe-jetzt netz1 600")
        w["warte_stille_s"] = self.warten(lambda: self.ist("warte_stille", "netz1"), 3, "warte_stille")
        # Host noch wach: er beantwortet die Proben, es darf nichts übernommen werden.
        t_wach = jetzt()
        time.sleep(3)
        w["wach_3s"] = {"phase": self.phase(), "alias": self.alias_da(),
                        "proben": len(m.liste(von="proxy", seit=t_wach, art="arp", op=1, spa=PROXY, tpa=HOST)),
                        "antworten_host": len(m.liste(von="host", seit=t_wach, art="arp", op=2, spa=HOST))}
        t_still = jetzt()
        self.netz.host_schlaeft()
        w["uebernahme_nach_s"] = self.warten(lambda: self.ist("uebernommen", "netz1"), 6, "uebernahme")
        time.sleep(3.3)
        garps = m.liste(von="proxy", seit=t_still, art="arp", op=1, sha=EIGEN, spa=HOST, tpa=HOST)
        w["garp_abstaende_s"] = [round(row["zeit"] - garps[0]["zeit"], 2) for row in garps]
        if garps:
            vorher = [row["zeit"] for row in m.liste(von="host", bis=garps[0]["zeit"])]
            w["stille_vor_uebernahme_s"] = round(garps[0]["zeit"] - max(vorher), 3) if vorher else None
        w["fakten"] = self.fakten()
        regeln = json.loads(sh("nft", "-j", "list", "table", "ip", "gb2_sv_vhost01").stdout)["nftables"]
        w["ketten"] = sorted("%s %s %s" % (row["chain"]["name"], row["chain"].get("hook"), row["chain"].get("prio"))
                             for row in regeln if "chain" in row)
        # ARP-Anfrage des Clients: genau eine Antwort, von proxy01s MAC.
        sock = roh("client", "eth0")
        try:
            t = jetzt()
            sock.send(arp_rahmen(1, netz.CLIENT_MAC, CLIENT, NULL_MAC, HOST))
            time.sleep(0.5)
        finally:
            sock.close()
        w["arp_antworten"] = [[row["von"], row["sha"]] for row in m.liste(seit=t, art="arp", op=2, spa=HOST)]
        # Isolation: sshd-Ersatz auf 0.0.0.0:22 ist unter .110 nicht erreichbar (DROP, kein RST, kein Banner).
        self.t_ssh_syn = jetzt()
        w["ssh_110"] = verbinden("client", (HOST, 22), frist=1.8)
        w["ssh_100"] = verbinden("client", (PROXY, 22))
        w["tcp_von_110"] = len([row for row in m.liste(von="proxy", seit=self.t_ssh_syn, art="tcp")
                                if row["quelle"] == HOST])
        w["sshd_ersatz"] = sorted({row["lokal"] for row in self.sshd.angenommen if row["zeit"] >= self.t_ssh_syn})
        w["client_neigh_110"] = self.neigh("client", HOST)
        # Lokal erzeugter Verkehr von proxy01 an .110 wird verworfen (Ausgangskette).
        t = jetzt()
        w["lokal_tcp_22"] = verbinden(None, (HOST, 22), frist=1.0)
        w["lokal_tcp_32400"] = verbinden(None, (HOST, 32400), frist=1.0)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp.sendto(b"x", (HOST, 9))
            w["lokal_udp"] = "gesendet"
        except OSError as error:
            w["lokal_udp"] = errno.errorcode.get(error.errno, str(error.errno))
        finally:
            udp.close()
        w["sshd_ersatz_lokal"] = len([row for row in self.sshd.angenommen if row["zeit"] >= t])

    def s2_wol_zaehlung_limit(self, w):
        m = self.mitschnitt
        t1 = self.t_ssh_syn
        syns = m.liste(von="client", seit=t1, bis=t1 + 1.9, art="tcp", ziel=HOST, dport=22, syn=True, ack=False)
        w["kernel_syns"] = len(syns)
        wol = m.wol(seit=t1)
        w["syn_bis_wol_ms"] = round((wol[0]["zeit"] - syns[0]["zeit"]) * 1000, 1) if wol and syns else None
        w["serie_s"] = self.serie_abwarten()
        w["ausloeser_kernel"] = self.ausloeser(t1)
        w["wol_versuche"] = sorted({round(row["zeit"] - wol[0]["zeit"]) for row in m.wol(seit=t1)}) if wol else []
        w["wol_ziele"] = sorted({(row["dst"], row["ziel"], row["dport"]) for row in m.wol(seit=t1)})
        w["gescheitert"] = len(self.zeilen(t1, ereignis="wecken_gescheitert"))
        sock = roh("client", "eth0")
        runden = []
        try:
            for nr, quelle in ((2, CLIENT), (3, CLIENT), (4, CLIENT), (5, "192.168.1.19")):
                t = jetzt()
                sock.send(syn_rahmen(quelle, HOST, 22, self.naechster_sport()))
                if nr == 2:
                    # zweiter SYN in der laufenden Weckung
                    time.sleep(0.2)
                    sock.send(syn_rahmen(quelle, HOST, 22, self.naechster_sport()))
                time.sleep(1.6 if nr == 4 else 0.5)
                runde = {"nr": nr, "quelle": quelle, "phase": self.phase(), "ausloeser": self.ausloeser(t),
                         "wol": len(m.wol(seit=t))}
                self.serie_abwarten()
                runden.append(runde)
        finally:
            sock.close()
        w["runden"] = runden

    def s3_wan_tls(self, w):
        m = self.mitschnitt
        t = jetzt()
        w["sni_falscher_hash"] = verbinden("wan", (HOST, 32400), WAN_TLS,
                                           clienthello("192-168-1-110.ffffff.plex.direct"))
        w["sni_fremdes_label"] = verbinden("wan", (HOST, 32400), WAN_TLS, clienthello("10-9-8-7.%s.plex.direct" % HASH))
        w["http_aus_wan"] = verbinden("wan", (HOST, 32400), WAN_TLS, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        w["wan_ssh_syn"] = verbinden("wan", (HOST, 22), WAN_TLS, frist=1.2)
        w["liste_falsche_quelle"] = verbinden("wan", (HOST, 8443), WAN_TLS, frist=1.2)
        t0 = jetzt()
        w["ohne_daten"] = verbinden("wan", (HOST, 32400), WAN_TLS, lesen=8)
        w["ohne_daten_rst_nach_s"] = round(jetzt() - t0, 2)
        w["ohne_weckung"] = {"ausloeser": self.ausloeser(t), "wol": len(m.wol(seit=t)), "phase": self.phase()}
        w["rst_von_32400"] = len([row for row in m.liste(von="proxy", seit=t, art="tcp", sport=32400, rst=True)
                                  if row["quelle"] == HOST and row["ziel"] == WAN_TLS])
        t = jetzt()
        w["sni_gueltig"] = verbinden("wan", (HOST, 32400), WAN_TLS, clienthello("192-168-1-110.%s.plex.direct" % HASH))
        time.sleep(0.3)
        w["gueltig"] = {"ausloeser": self.ausloeser(t), "wol": len(m.wol(seit=t)), "phase": self.phase()}
        w["serie_s"] = self.serie_abwarten()
        t = jetzt()
        w["liste_gueltig"] = verbinden("wan", (HOST, 8443), WAN_LISTE, frist=1.5)
        w["liste"] = {"ausloeser": self.ausloeser(t), "wol": len(m.wol(seit=t))}
        self.serie_abwarten()

    def s4_minecraft(self, w):
        m = self.mitschnitt
        t = jetzt()
        w["status_ping"] = verbinden("wan", (HOST, 25565), WAN_MC, minecraft(status=True))
        w["legacy_ping"] = verbinden("wan", (HOST, 25565), WAN_MC, b"\xfe\x01")
        w["login_fremd"] = verbinden("wan", (HOST, 25565), WAN_MC, minecraft("Fremder1"))
        time.sleep(0.3)
        w["ohne_weckung"] = {"ausloeser": self.ausloeser(t), "wol": len(m.wol(seit=t))}
        t = jetzt()
        w["login_whitelist"] = verbinden("wan", (HOST, 25565), WAN_MC, minecraft("Testspieler"))
        time.sleep(0.3)
        w["weckung"] = {"ausloeser": self.ausloeser(t), "wol": len(m.wol(seit=t))}
        w["rst_von_25565"] = len([row for row in m.liste(von="proxy", seit=t, art="tcp", sport=25565, rst=True)
                                  if row["quelle"] == HOST])
        self.serie_abwarten()

    def s5_vpn(self, w):
        m = self.mitschnitt
        w["vpn_art"] = self.netz.vpn_art
        w["tunnel_kontrolle"] = verbinden("vpn", (VPN_PROXY, 22))
        t = jetzt()
        w["vpn_ssh_110"] = verbinden("vpn", (HOST, 22), VPN_PEER, frist=1.8)
        w["weckung"] = {"ausloeser": self.ausloeser(t), "wol": len(m.wol(seit=t))}
        w["status_weckung"] = (self.status() or {}).get("weckung", {}).get("vhost01")
        self.serie_abwarten()

    def s6_host_wacht_auf(self, w):
        m = self.mitschnitt
        sock = roh("client", "eth0")
        try:
            sock.send(syn_rahmen("192.168.1.20", HOST, 22, self.naechster_sport()))
        finally:
            sock.close()
        self.warten(lambda: self.phase() == "wecken", 2, "wecken")
        uhr = Freigabeuhr(5)
        uhr.start()
        host = roh("host", "eno1")
        try:
            time.sleep(0.05)
            t0 = jetzt()
            # Erster Frame nach dem Resume: ARP-Probe 0.0.0.0 -> .110 (wie DAD/arping -D) mit echter MAC.
            host.send(arp_rahmen(1, ECHT, "0.0.0.0", NULL_MAC, HOST))
            uhr.join()
            w.update(uhr.ms(t0))
            w["gruende"] = self.freigabe_abwarten(t0 - 0.5)
            w["wecken_erfolg"] = [row.get("sekunden") for row in self.zeilen(t0 - 0.5, ereignis="wecken_erfolg")]
            time.sleep(1.5)
            w["fakten"] = self.fakten()
            w["arp_antworten_proxy"] = len(m.liste(von="proxy", seit=t0, art="arp", op=2, spa=HOST))
            w["wol_nach_freigabe"] = len(m.wol(seit=t0 + 0.1))
            w["grund_nach_freigabe"] = ((self.status() or {}).get("gruende") or {}).get("vhost01")
            # Host zurück: Adresse, dann GARP wie gb-garp (arping -U, arping -A).
            self.netz.host_wach()
            host.send(arp_rahmen(1, ECHT, HOST, BROADCAST, HOST))
            host.send(arp_rahmen(2, ECHT, HOST, ECHT, HOST))
        finally:
            host.close()
        time.sleep(0.3)
        w["client_neigh_110"] = self.neigh("client", HOST)
        t = jetzt()
        w["client_ssh_110"] = verbinden("client", (HOST, 22))
        syn = m.liste(von="client", seit=t, art="tcp", ziel=HOST, dport=22, syn=True)
        w["client_syn_ziel_mac"] = syn[0]["dst"] if syn else None
        w["host_lauscher"] = [row["peer"] for row in self.host_sshd.angenommen if row["zeit"] >= t]
        w["anmelden"] = self.ssh("anmelden netz1")

    def s7a_lease_ablauf(self, w):
        m = self.mitschnitt
        # Dienstwechsel: SIGTERM schreibt die verdichteten Zähler von s1-s6 (R9), Limits beginnen neu (R-A15).
        w["sigterm_exit_dienst1"] = self.dienst_stoppen(signal.SIGTERM)
        w["verdichtet_dienst1"] = self.verdichtet()
        self.dienst_starten()
        lease_ende = self.uebernahme_herbeifuehren("netz2", 6, w)
        uhr = Freigabeuhr(lease_ende - jetzt() + 3)
        uhr.start()
        uhr.join()
        w.update(uhr.ms(lease_ende))
        time.sleep(0.5)
        wol = m.wol(seit=lease_ende - 0.5)
        w["wol_nach_lease_ms"] = round((wol[0]["zeit"] - lease_ende) * 1000, 1) if wol else None
        w["gruende"] = self.freigabe_abwarten(lease_ende - 1)
        w["ereignis"] = len(self.zeilen(lease_ende - 1, ereignis="lease_abgelaufen"))
        self.serie_abwarten()
        time.sleep(2)
        w["fakten_danach"] = dict(self.fakten(), phase=self.phase())
        w["anmelden"] = self.ssh("anmelden netz2")

    def s7b_abschalter(self, w):
        m = self.mitschnitt
        self.uebernahme_herbeifuehren("netz3", 120, w)
        uhr = Freigabeuhr(4)
        uhr.start()
        t0 = jetzt()
        Path(AUS).write_text("")
        uhr.join()
        w.update(uhr.ms(t0))
        w["gruende"] = self.freigabe_abwarten(t0 - 0.5)
        status = self.status() or {}
        w["status"] = {"abgeschaltet": status.get("abgeschaltet"), "bereit_fuer": status.get("bereit_fuer"),
                       "grund": (status.get("gruende") or {}).get("vhost01")}
        w["wol"] = len(m.wol(seit=t0))
        w["ssh_status"] = self.ssh("status")
        time.sleep(1)
        w["fakten_abgeschaltet"] = self.fakten()
        os.unlink(AUS)
        # Abschalter erledigt den Zyklus nicht: schläft der Host weiter, wird er wieder übernommen.
        w["wieder_uebernommen_s"] = self.warten(lambda: self.ist("uebernommen", "netz3"), 8, "wieder_uebernommen")
        t = jetzt()
        w["anmelden"] = self.ssh("anmelden netz3")
        w["freigabe_nach_anmelden_s"] = self.warten(lambda: not self.alias_da(), 3, "freigabe_anmelden")
        w["gruende_anmelden"] = self.freigabe_abwarten(t)
        w["fakten_angemeldet"] = self.fakten()

    def s7c_sigkill_neustart(self, w):
        m = self.mitschnitt
        self.uebernahme_herbeifuehren("netz4", 300, w)
        # Dienst angehalten: nur die nft-ARP-Tabelle entscheidet, ob proxy01s Kernel antwortet.
        self.dienst.send_signal(signal.SIGSTOP)
        host, client = roh("host", "eno1"), roh("client", "eth0")
        try:
            t = jetzt()
            host.send(arp_rahmen(1, ECHT, "0.0.0.0", NULL_MAC, HOST))
            time.sleep(0.5)
            w["antwort_auf_echte_mac"] = len(m.liste(von="proxy", seit=t, art="arp", op=2, spa=HOST))
            t = jetzt()
            client.send(arp_rahmen(1, netz.CLIENT_MAC, CLIENT, NULL_MAC, HOST))
            time.sleep(0.5)
            w["antwort_auf_client"] = len(m.liste(von="proxy", seit=t, art="arp", op=2, spa=HOST))
        finally:
            host.close()
            client.close()
        w["sigkill_exit"] = self.dienst_stoppen(signal.SIGKILL)
        w["fakten_nach_sigkill"] = self.fakten()
        w["aufraeumen"] = self.cli("--aufraeumen")
        w["fakten_nach_aufraeumen"] = self.fakten()
        w["aufraeumen_erneut"] = self.cli("--aufraeumen")
        # Neustart mit wachem Host: Register erlaubt, Stille nicht -> keine Übernahme.
        self.netz.host_wach()
        self.dienst_starten()
        self.warten(lambda: self.ist("warte_stille", "netz4"), 3, "warte_stille_neustart")
        time.sleep(3)
        w["neustart_host_wach"] = dict(self.fakten(), phase=self.phase())
        self.netz.host_schlaeft()
        w["neustart_uebernahme_s"] = self.warten(lambda: self.ist("uebernommen", "netz4"), 6, "uebernahme_neustart")
        t = jetzt()
        w["sigterm_exit"] = self.dienst_stoppen(signal.SIGTERM)
        w["fakten_nach_sigterm"] = self.fakten()
        w["gruende_sigterm"] = self.freigaben(t)
        self.dienst_starten()
        w["nach_dienstende_wieder_s"] = self.warten(lambda: self.ist("uebernommen", "netz4"), 6,
                                                    "uebernahme_dienstende")
        t = jetzt()
        w["anmelden"] = self.ssh("anmelden netz4")
        w["gruende_anmelden"] = self.freigabe_abwarten(t)
        # Neustart mit angemeldetem Register: keine Übernahme, obwohl der Host weiter schweigt.
        w["sigterm_exit_2"] = self.dienst_stoppen(signal.SIGTERM)
        self.dienst_starten()
        time.sleep(3)
        w["neustart_angemeldet"] = dict(self.fakten(), phase=self.phase())

    def s8_lebendprobe(self, w):
        m = self.mitschnitt
        self.uebernahme_herbeifuehren("netz5", 300, w)
        time.sleep(3.5)
        t_ip = jetzt()
        uhr = Freigabeuhr(4)
        uhr.start()
        # Host wacht still auf: Adresse ohne GARP/IPv6; er antwortet nur auf ARP.
        self.netz.host_wach()
        uhr.join()
        w.update(uhr.ms(t_ip))
        host = m.liste(von="host", seit=t_ip)
        w["erster_host_rahmen"] = {k: host[0].get(k) for k in ("art", "op", "spa", "tpa", "dst")} if host else None
        if host:
            proben = m.liste(von="proxy", bis=host[0]["zeit"], seit=t_ip - 3, art="arp", op=1, spa=PROXY, tpa=HOST)
            w["probe_vor_antwort_ms"] = round((host[0]["zeit"] - proben[-1]["zeit"]) * 1000, 1) if proben else None
            w["proben_abstand_s"] = [round(b["zeit"] - a["zeit"], 2) for a, b in zip(proben, proben[1:])]
        w["gruende"] = self.freigabe_abwarten(t_ip)
        w["fakten"] = self.fakten()
        w["anmelden"] = self.ssh("anmelden netz5")

    def s8b_fremde_mac(self, w):
        """Review b5: ein anderes Gerät antwortet für .110 (vhost01 mit gewechselter MAC, Adresskonflikt)."""
        m = self.mitschnitt
        self.warten(lambda: self.ist("frei"), 4, "frei vor netz6")
        # Teil A: Host wach, aber mit einer anderen MAC als in der Konfig; er beantwortet jede Probe.
        self.netz.host_mac(ANDERE)
        self.netz.host_wach()
        t = jetzt()
        self.register_setzen("netz6", 120)
        w["freigabe_warte_stille_s"] = self.warten(lambda: "fremde_mac" in self.freigaben(t), 6, "fremde_mac")
        # Derselbe Zyklus ist erledigt: auch wenn der Host jetzt schweigt, übernimmt proxy01 nicht.
        self.netz.host_schlaeft()
        time.sleep(3)
        w["warte_stille"] = {
            "fakten": dict(self.fakten(), phase=self.phase()),
            "phasen": [row["nach"] for row in self.zeilen(t, ereignis="phase")],
            "fremde_mac": [{k: row.get(k) for k in ("mac", "phase", "zyklus")}
                           for row in self.zeilen(t, ereignis="fremde_mac")],
            "antworten_host": len(m.liste(von="host", seit=t, art="arp", op=2, spa=HOST, sha=ANDERE)),
            "garps_proxy": len(m.liste(von="proxy", seit=t, art="arp", sha=EIGEN, spa=HOST)),
            "wol": len(m.wol(seit=t))}
        w["anmelden_netz6"] = self.ssh("anmelden netz6")
        # Teil B: Übernahme steht, dann kündigt ein anderes Gerät .110 per GARP an.
        self.netz.host_mac(ECHT)
        self.uebernahme_herbeifuehren("netz7", 120, w)
        uhr = Freigabeuhr(4)
        uhr.start()
        sock = roh("client", "eth0")
        try:
            time.sleep(0.05)
            t0 = jetzt()
            sock.send(arp_rahmen(1, ANDERE, HOST, NULL_MAC, HOST))
        finally:
            sock.close()
        uhr.join()
        w.update(uhr.ms(t0))
        w["gruende"] = self.freigabe_abwarten(t0 - 0.5)
        w["fremde_mac_uebernommen"] = [{k: row.get(k) for k in ("mac", "phase", "zyklus")}
                                       for row in self.zeilen(t0 - 0.5, ereignis="fremde_mac")]
        time.sleep(3)
        w["danach"] = dict(self.fakten(), phase=self.phase())
        w["wol_uebernommen"] = len(m.wol(seit=t0))
        w["anmelden_netz7"] = self.ssh("anmelden netz7")
        self.netz.host_wach()

    def s9_ende(self, w):
        t = jetzt()
        w["sigterm_exit"] = self.dienst_stoppen(signal.SIGTERM)
        w["ende"] = [row.get("grund") for row in self.zeilen(t, ereignis="ende")]
        w["verdichtet"] = self.verdichtet()
        w["aufraeumen"] = self.cli("--aufraeumen")
        w["fakten"] = self.fakten()
        w["dienst_stderr"] = "".join(p.read_text() for p in sorted(self.arbeit.glob("dienst*.err")))[-2000:]
        w["weckentscheidungen"] = [row for row in self.ausloeser(0)]
        w["ereignisse"] = sorted({row["ereignis"] for row in self.log() if "ereignis" in row})

    # ------------------------------------------------------------ Ablauf

    def laufen(self):
        try:
            self.netz = netz.Netz(str(self.arbeit))
            self.netz.aufbauen()
            self.konfig()
            self.bericht["umgebung"].update(
                vpn_art=self.netz.vpn_art, python=sys.version.split()[0],
                nft=sh("nft", "--version").stdout.strip(), kernel=os.uname().release)
            self.mitschnitt = netz.Mitschnitt()
            self.sshd = Lauscher(None, 22, b"SSH-2.0-proxy01-ersatz\r\n")
            self.host_sshd = Lauscher("host", 22, b"SSH-2.0-vhost01-ersatz\r\n")
            self.bericht["umgebung"]["dienst_start_s"] = self.dienst_starten()
            self.bericht["umgebung"]["bereit_fuer"] = (self.status() or {}).get("bereit_fuer")
        except Exception:
            self.bericht["fehler"] = traceback.format_exc()[-3000:]
            self.schreiben()
            return
        for name in ("s1_uebernahme_isolation", "s2_wol_zaehlung_limit", "s3_wan_tls", "s4_minecraft", "s5_vpn",
                     "s6_host_wacht_auf", "s7a_lease_ablauf", "s7b_abschalter", "s7c_sigkill_neustart",
                     "s8_lebendprobe", "s8b_fremde_mac", "s9_ende"):
            self.schritt(name, getattr(self, name))
        self.schreiben()


if __name__ == "__main__":
    if os.getpid() != 1 or not os.environ.get("GB_NETNS_INNEN"):
        sys.exit("nur über tests/test_netns_stellvertretung.py (GB_NETNS=1) im Wegwerf-Namensraum starten")
    Szenario(sys.argv[1]).laufen()
