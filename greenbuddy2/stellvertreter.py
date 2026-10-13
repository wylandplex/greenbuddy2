"""Schlaf-Stellvertreter auf proxy01: GDM zählen, schlafende Hosts übernehmen und bei echter Nachfrage wecken.

Eine select-Schleife über GDM-UDP, Raw-Sockets (nur in warte_stille/uebernommen), Listener am Alias und
angenommene Verbindungen; Register und Statusbericht sind Dateien (Plan Abschnitt 4/5).
"""

import argparse
import collections
import json
import os
import select
import signal
import socket
import struct
import sys
from pathlib import Path

from . import wol
from .jsonlog import JsonLog
from .klassifikation import klassifizieren, quelle
from .konfig import abgeschaltet, laden, stellvertretung
from .register import STATUS, Register, atomar
from .uebernahme import Uebernahme, Umgebung, aufraeumen, probe_pfad
from .wan import WanAdresse
from .wecken import ZIELE

MAX_VERBINDUNGEN, MAX_BYTES, MAX_SEKUNDEN = 64, 16384, 5
STATUS_TAKT, REGISTER_TAKT, BEREIT_TAKT = 5, 1, 30
FENSTER = {"wan_quelle_h": 3600, "wan_host_h": 3600, "wan_host_tag": 86400, "lan_quelle_h": 3600,
           "vpn_quelle_h": 3600, "liste_h": 3600}


class GDMZaehler:
    def __init__(self, logger, maximum=4096):
        self.logger, self.maximum = logger, maximum
        self.hour, self.counts, self.overflow = None, collections.Counter(), 0

    def flush(self, now, force=False):
        hour = int(now // 3600)
        if self.hour is not None and (force or hour != self.hour):
            for source, count in self.counts.items():
                self.logger.emit({"zeit": self.hour * 3600, "quell_ip": source,
                                  "port": 32414, "entscheidung": "zaehlen", "anzahl": count}, now)
            if self.overflow:
                self.logger.emit({"ereignis": "gdm_quellenlimit", "anzahl": self.overflow}, now)
            self.counts.clear()
            self.overflow = 0
        self.hour = hour

    def add(self, source, now):
        self.flush(now)
        if source in self.counts or len(self.counts) < self.maximum:
            self.counts[source] += 1
        else:
            self.overflow += 1


class Verdichter:
    """Plan R9: spam/unklar/wiederholte Limits nur stündlich je Host x Port x Quellklasse x Entscheidung."""
    def __init__(self, logger, maximum=4096):
        self.logger, self.maximum = logger, maximum
        self.stunde, self.zaehler, self.ueberlauf = None, collections.Counter(), 0

    def add(self, host, port, klasse, entscheidung, wall):
        self.flush(wall)
        key = (host, port, klasse, entscheidung)
        if key in self.zaehler or len(self.zaehler) < self.maximum:
            self.zaehler[key] += 1
        else:
            self.ueberlauf += 1

    def flush(self, wall, force=False):
        stunde = int(wall // 3600)
        if self.stunde is not None and (force or stunde != self.stunde):
            for (host, port, klasse, entscheidung), anzahl in sorted(self.zaehler.items(), key=str):
                self.logger.emit({"zeit": self.stunde * 3600, "host": host, "port": port, "quellklasse": klasse,
                                  "entscheidung": entscheidung, "anzahl": anzahl, "verdichtet": True}, wall)
            if self.ueberlauf:
                self.logger.emit({"ereignis": "verdichtung_ueberlauf", "anzahl": self.ueberlauf}, wall)
            self.zaehler.clear()
            self.ueberlauf = 0
        self.stunde = stunde


class Grenzen:
    """Plan R6 mit rollenden Fenstern; gezählt wird erst, wenn eine Weckung wirklich beginnt."""
    def __init__(self, limits):
        self.limits = limits
        self.ereignisse = {}

    def _fenster(self, name, key, now):
        events = self.ereignisse.get((name, key))
        while events and now - events[0] >= FENSTER[name]:
            events.popleft()
        if events is not None and not events:
            del self.ereignisse[(name, key)]
            return collections.deque()
        return events or collections.deque()

    def anzahl(self, name, key, now):
        return len(self._fenster(name, key, now))

    def voll(self, schluessel, now):
        for name, key in schluessel:
            if self.anzahl(name, key, now) >= self.limits[name]:
                return name
        return None

    def zaehlen(self, schluessel, now):
        for name, key in schluessel:
            self.ereignisse.setdefault((name, key), collections.deque()).append(now)

    def aufraeumen(self, now):
        for name, key in list(self.ereignisse):
            self._fenster(name, key, now)


def limit_schluessel(host, art, quelle_ip, port):
    if art == "liste":
        return [("liste_h", (host, port))]
    if art == "wan":
        return [("wan_quelle_h", (host, quelle_ip)), ("wan_host_h", (host,)), ("wan_host_tag", (host,))]
    return [("%s_quelle_h" % art, (host, quelle_ip))]


def syn_regel(host, quelle_ip, klasse, port):
    """Plan R3 für beobachtete SYNs: (limitart, None) = Weckkandidat, sonst (None, entscheidung)."""
    if quelle_ip in host["ausgenommen"]:
        return None, "ausgenommen"
    if port in host["quellen_ports"]:
        return ("liste", None) if quelle_ip in host["quellen_ports"][port] else (None, "verworfen")
    if port in host["syn_ports"] and klasse in ("LAN", "VPN"):
        return klasse.lower(), None
    # WAN auf Inhaltsports entscheidet der Listener; alles andere weckt nie.
    return None, "ignoriert"


class Verbindung:
    __slots__ = ("sock", "ue", "quelle", "port", "beginn", "daten")

    def __init__(self, sock, ue, quelle_ip, port, beginn):
        self.sock, self.ue, self.quelle, self.port, self.beginn = sock, ue, quelle_ip, port, beginn
        self.daten = bytearray()


def rst(sock):
    """SO_LINGER 0: close() sendet RST statt FIN; der Client wiederholt später am wachen Host."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    sock.close()


class Dienst:
    def __init__(self, cfg, umgebung, logger, probe=None, waehlen=None, aus=None, aufloesen=None, faden=None,
                 pid=None):
        self.cfg, self.u, self.logger, self.probe = cfg, umgebung, logger, probe
        self.waehlen = waehlen or (lambda rlist, timeout: select.select(rlist, [], [], timeout)[0])
        self.aus = aus or (lambda: abgeschaltet(cfg))
        self.pid = os.getpid() if pid is None else pid
        try:
            self.sv, self.sv_fehler = stellvertretung(cfg), None
        except ValueError as error:
            self.sv, self.sv_fehler = None, str(error)
        if probe and (self.sv is None or self.sv["probe"] is None):
            raise ValueError(self.sv_fehler or "probe_fehlt")
        self.u.protokoll, self.u.sichern = self.protokoll, self.sichern
        try:
            self.boot = self.u.boot_id()
        except OSError:
            self.boot = None
        hosts = {} if self.sv is None else ({"probe": self.sv["probe"]} if probe else self.sv["hosts"])
        self.uebernahmen = {name: Uebernahme(name, host, self.sv, self.u, probe=bool(probe))
                            for name, host in hosts.items()}
        status = (cfg.get("stellvertretung") or {}).get("status") if isinstance(cfg.get("stellvertretung"), dict) \
            else None
        self.status_pfad = self.sv["status"] if self.sv else (status if isinstance(status, str)
                                                              and status.startswith("/") else STATUS)
        self.zustand_pfad = None if self.sv is None else (
            probe_pfad(self.sv["zustand"]) if probe else self.sv["zustand"])
        self.grenzen = Grenzen(self.sv["limits"] if self.sv else {})
        self.verdichter = Verdichter(logger)
        self.zaehler = GDMZaehler(logger)
        self.wan = WanAdresse(self.sv["wan_name"] if self.sv else "", aufloesen, faden)
        self.verbindungen = collections.OrderedDict()
        self.gdm, self.gdm_versuch = None, None
        self.register_sig, self.register_rows, self.register_ok, self.register_naechst = False, None, True, 0
        self.bereit, self.bereit_naechst, self.bereit_stand = {}, 0, None
        self.status_naechst, self.status_letzt = 0, None
        self.abgeschaltet, self.gestartet, self.beendet, self.stopp = False, False, False, False
        self.limit_gemeldet, self.limit_stunde = set(), None
        self.wan_unklar_gemeldet = False
        self.fehler_gemeldet = set()

    # ---------------------------------------------------------------- Protokoll und Zustand

    def protokoll(self, row):
        wall = self.u.wanduhr()
        self.logger.emit(dict(row, zeit=wall), wall)

    def _einmal(self, key, row):
        if key not in self.fehler_gemeldet:
            self.fehler_gemeldet.add(key)
            self.protokoll(row)

    def sichern(self):
        if not self.zustand_pfad:
            return
        data = {"version": 1, "boot_id": self.boot, "pid": self.pid, "probe": bool(self.probe),
                "hosts": {name: ue.zustand() for name, ue in self.uebernahmen.items()}}
        try:
            atomar(self.zustand_pfad, data)
        except OSError:
            self._einmal("zustand", {"ereignis": "fehler", "grund": "zustand_schreibfehler"})

    def _wiederherstellen(self):
        try:
            saved = json.loads(Path(self.zustand_pfad).read_text())
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            return self.protokoll({"ereignis": "fehler", "grund": "zustand_unlesbar"})
        # /run überlebt keinen Neustart; eine fremde boot_id ist ein Fehler, keine Wahrheit.
        if not isinstance(saved, dict) or saved.get("boot_id") != self.boot or not isinstance(saved.get("hosts"), dict):
            return
        for name, ue in self.uebernahmen.items():
            row = saved["hosts"].get(name)
            if not isinstance(row, dict):
                continue
            if isinstance(row.get("erledigt"), str):
                ue.erledigt = row["erledigt"]
            if isinstance(row.get("weckung"), dict):
                ue.weckung = row["weckung"]

    # ---------------------------------------------------------------- Lebenszyklus

    def starten(self):
        now = self.u.uhr()
        if self.sv is None:
            self.protokoll({"ereignis": "stellvertretung_ungueltig", "grund": self.sv_fehler})
        else:
            self._wiederherstellen()
            nur = {"probe"} if self.probe else set(self.uebernahmen) | {"phantom"}
            ergebnis = aufraeumen(self.cfg, self.u.runner, nur=nur, eigene_pid=self.pid)
            if ergebnis["entfernt"] or ergebnis["fehler"]:
                self.protokoll(dict({"ereignis": "aufraeumen"}, **ergebnis))
            self.sichern()
            if self.probe:
                self.uebernahmen["probe"].warte_stille("probe", now + self.probe, now)
        self.protokoll({"ereignis": "start", "probe": bool(self.probe), "pid": self.pid})
        self.gestartet = True
        self._takt(now)

    def ende(self):
        if not self.probe:
            return False
        ue = self.uebernahmen["probe"]
        return self.gestartet and ue.phase == "frei" and not ue.serie

    def laufen(self):
        self.starten()
        while not self.ende() and not self.stopp:
            self.schritt()

    def beenden(self, grund="dienst_ende"):
        if self.beendet:
            return
        self.beendet = True
        now, wall = self.u.uhr(), self.u.wanduhr()
        for ue in self.uebernahmen.values():
            if ue.phase != "frei":
                ue.freigeben(grund, now)
            elif ue.alias or ue.nft:
                ue.nachraeumen_jetzt(now)
            ue.serie = None
        for conn in list(self.verbindungen):
            rst(conn)
        self.verbindungen.clear()
        self._gdm_schliessen()
        self.zaehler.flush(wall, force=True)
        self.verdichter.flush(wall, force=True)
        self.sichern()
        self._status(now, wall, ende=True)
        self.protokoll({"ereignis": "ende", "grund": grund})

    # ---------------------------------------------------------------- Schleife

    def _lesbar(self):
        rows = {}
        if self.gdm is not None:
            rows[self.gdm] = ("gdm", None)
        for ue in self.uebernahmen.values():
            for sock, art in ue.sockets():
                rows[sock] = (art, ue)
        for sock, verbindung in self.verbindungen.items():
            rows[sock] = ("verbindung", verbindung)
        return rows

    def _termin(self, now):
        # Nur Termine, die _takt auch fortschreibt: ein stehender alter Termin wäre ein Busy-Loop.
        termine = [now + 1]
        if not self.probe:
            termine.append(self.status_naechst)
        if self.sv is not None:
            termine.append(self.bereit_naechst)
            if not self.probe and not self.abgeschaltet:
                termine.append(self.register_naechst)
        termine += [ue.naechster_termin(now) for ue in self.uebernahmen.values()]
        termine += [v.beginn + MAX_SEKUNDEN for v in self.verbindungen.values()]
        return min(termine)

    def schritt(self):
        now = self.u.uhr()
        lesbar = self._lesbar()
        # Kein Busy-Loop: warten bis zum nächsten Termin, höchstens 1 s (Abschalter, Register).
        timeout = min(1.0, max(0.0, self._termin(now) - now))
        for sock in self.waehlen(list(lesbar), timeout):
            art, objekt = lesbar[sock]
            self._lesen(sock, art, objekt, self.u.uhr())
        self._takt(self.u.uhr())

    def _lesen(self, sock, art, objekt, now):
        if art == "gdm":
            for _ in range(64):
                try:
                    _, peer = sock.recvfrom(1024)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                self.zaehler.add(peer[0], self.u.wanduhr())
        elif art in ("eth", "vpn"):
            ue = objekt
            for _ in range(64):
                try:
                    daten, adresse = sock.recvfrom(2048)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                syn = ue.frame(daten, adresse, now, cooked=art == "vpn")
                if syn:
                    self._syn(ue, syn, now)
                if sock not in (ue.eth, ue.vpn):
                    # Freigabe hat den Socket geschlossen (echte MAC).
                    break
        elif art == "verbindung":
            self._empfangen(objekt, now)
        else:
            self._annehmen(sock, objekt, art[1], now)

    def _takt(self, now):
        wall = self.u.wanduhr()
        aus = self.aus()
        if aus and not self.abgeschaltet:
            self.protokoll({"ereignis": "abgeschaltet"})
            for ue in self.uebernahmen.values():
                ue.abschalten(now)
            for conn in list(self.verbindungen):
                rst(conn)
            self.verbindungen.clear()
            self._gdm_schliessen()
            self.zaehler.counts.clear()
        elif not aus and self.abgeschaltet:
            self.protokoll({"ereignis": "eingeschaltet"})
        self.abgeschaltet = aus
        if not aus and not self.probe:
            self._gdm_oeffnen(now)
        if self.sv is not None:
            if not aus and not self.probe:
                self._register(now)
            for ue in self.uebernahmen.values():
                ue.tick(now)
            for verbindung in list(self.verbindungen.values()):
                if now - verbindung.beginn >= MAX_SEKUNDEN:
                    self._abschliessen(verbindung, now)
            # Nach Register und Takt: eine Freigabe dieses Durchlaufs steht schon im folgenden Bericht.
            self._bereitschaft(now)
            if any(ue.phase != "frei" for ue in self.uebernahmen.values()):
                self.wan.anstossen(now)
                self._wan(now)
        self.zaehler.flush(wall)
        self.verdichter.flush(wall)
        stunde = int(wall // 3600)
        if stunde != self.limit_stunde:
            self.limit_stunde, self.limit_gemeldet = stunde, set()
            self.grenzen.aufraeumen(now)
        self._status(now, wall)
        self.logger.emit({"entscheidung": "abgeschaltet" if aus else "beobachten", "ereignis": "heartbeat",
                          "phasen": {name: ue.phase_bericht() for name, ue in self.uebernahmen.items()}},
                         wall, heartbeat=True)

    # ---------------------------------------------------------------- GDM, Register, Bereitschaft, Status

    def _gdm_oeffnen(self, now):
        if self.gdm is not None or (self.gdm_versuch is not None and now < self.gdm_versuch):
            return
        sock = None
        try:
            sock = self.u.sockets(socket.AF_INET, socket.SOCK_DGRAM, 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 32414))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            socket.inet_aton("239.0.0.250") + socket.inet_aton(self.cfg.get("listen_ip",
                                                                                            "192.168.1.100")))
            sock.setblocking(False)
            self.gdm, self.gdm_versuch = sock, None
        except OSError:
            if sock is not None:
                sock.close()
            self.gdm_versuch = now + 60
            self._einmal("gdm", {"ereignis": "fehler", "grund": "gdm_socket"})

    def _gdm_schliessen(self):
        if self.gdm is not None:
            self.gdm.close()
            self.gdm = None

    def _register(self, now):
        if now < self.register_naechst:
            return
        self.register_naechst = now + REGISTER_TAKT
        path = Path(self.sv["register"])
        try:
            info = os.stat(str(path))
            sig = (info.st_mtime_ns, info.st_ino, info.st_size)
        except FileNotFoundError:
            sig = None
        except OSError:
            sig = "unklar"
        if sig != self.register_sig:
            self.register_sig = sig
            try:
                if sig == "unklar":
                    raise ValueError("register_unlesbar")
                self.register_rows = Register(path).lesen()["hosts"] if sig else {}
                self.register_ok = True
                self.fehler_gemeldet.discard("register")
            except (OSError, ValueError, TypeError):
                # Unklar: bestehende Übernahmen halten (die echte MAC gibt frei), keine neue beginnen.
                self.register_ok = False
                self._einmal("register", {"ereignis": "register_unklar"})
        if self.register_ok:
            for name, ue in self.uebernahmen.items():
                ue.register(self.register_rows.get(name), now)

    def _bereitschaft(self, now):
        # Neu prüfen alle 30 s und sofort, wenn sich Phase oder Artefakte ändern (Freigabe, Nachräumen).
        stand = {name: (ue.phase, ue.alias, ue.nft) for name, ue in self.uebernahmen.items()}
        if now < self.bereit_naechst and stand == self.bereit_stand:
            return
        self.bereit_naechst, self.bereit_stand = now + BEREIT_TAKT, stand
        for name, ue in self.uebernahmen.items():
            # Alias und Tabellen gehören zur laufenden Übernahme; dort gilt der Befund von davor.
            if ue.phase == "frei":
                self.bereit[name] = "freigabe_unvollstaendig" if ue.alias or ue.nft else ue.vorpruefen()

    def _status(self, now, wall, ende=False):
        if self.probe:
            return
        phasen = {name: ue.phase_bericht() for name, ue in self.uebernahmen.items()}
        if not ende and now < self.status_naechst and phasen == self.status_letzt:
            return
        self.status_naechst, self.status_letzt = now + STATUS_TAKT, phasen
        gruende = {}
        for name in self.uebernahmen:
            grund = self.bereit.get(name, "unbekannt")
            gruende[name] = "dienst_beendet" if ende else "abgeschaltet" if self.abgeschaltet else grund
        data = {"version": 1, "zeit": wall, "pid": self.pid, "abgeschaltet": self.abgeschaltet,
                "stellvertretung": self.sv_fehler or "ok",
                "bereit_fuer": sorted(name for name, grund in gruende.items() if grund is None),
                "gruende": gruende, "phasen": phasen,
                "zyklen": {name: ue.zyklus for name, ue in self.uebernahmen.items()},
                "weckung": {name: ue.weckung for name, ue in self.uebernahmen.items()},
                "register": "ok" if self.register_ok else "unklar",
                "wan_ip_bekannt": bool(self.wan.werte)}
        try:
            atomar(self.status_pfad, data, modus=0o640)
            self.fehler_gemeldet.discard("status")
        except OSError:
            self._einmal("status", {"ereignis": "fehler", "grund": "status_schreibfehler"})

    def _wan(self, now):
        if not self.wan.name:
            return
        if self.wan.aktuell(now) is None and self.wan.versuch is not None and not self.wan.laeuft:
            if not self.wan_unklar_gemeldet:
                self.wan_unklar_gemeldet = True
                self.protokoll({"ereignis": "wan_ip_unklar"})
        elif self.wan.aktuell(now):
            self.wan_unklar_gemeldet = False

    # ---------------------------------------------------------------- Auslöser

    def _syn(self, ue, syn, now):
        klasse = quelle(syn["quelle"], self.sv["lan"], self.sv["vpn"])
        art, entscheidung = syn_regel(ue.host, syn["quelle"], klasse, syn["port"])
        if art is None:
            return self.verdichter.add(ue.name, syn["port"], klasse, entscheidung, self.u.wanduhr())
        self._ausloesen(ue, syn["quelle"], syn["port"], klasse, art, 5 if art == "liste" else 4, now, {})

    def _ausloesen(self, ue, quelle_ip, port, klasse, art, weg, now, extra):
        wall = self.u.wanduhr()
        if ue.phase != "uebernommen":
            return self.verdichter.add(ue.name, port, klasse, "nicht_uebernommen", wall)
        if ue.serie:
            # R6: Nachfrage während eines Weckvorgangs wird nicht gezählt.
            return self.verdichter.add(ue.name, port, klasse, "wecken_laeuft", wall)
        schluessel = limit_schluessel(ue.name, art, quelle_ip, port)
        voll = self.grenzen.voll(schluessel, now)
        zeile = dict({"ereignis": "ausloeser", "host": ue.name, "zyklus": ue.zyklus, "quell_ip": quelle_ip,
                      "port": port, "quellklasse": klasse, "weg": weg}, **extra)
        if voll:
            key = (ue.name, voll, quelle_ip)
            if key in self.limit_gemeldet:
                return self.verdichter.add(ue.name, port, klasse, "limit", wall)
            self.limit_gemeldet.add(key)
            return self.protokoll(dict(zeile, entscheidung="limit", limit=voll))
        self.grenzen.zaehlen(schluessel, now)
        ue.wecken({"weg": weg, "port": port, "quellklasse": klasse, "entscheidung": "wecken"}, now)
        self.protokoll(dict(zeile, entscheidung="wecken"))

    def _kcfg(self, ue, now):
        wan = self.wan.aktuell(now)
        cfg = dict(self.cfg)
        cfg["lan"], cfg["vpn"] = self.sv["lan"], self.sv["vpn"]
        cfg["sni_label_ips"] = [ue.host["ip"]] + list(wan or [])
        cfg["sni_label_wan_unklar"] = not wan
        return cfg

    def _annehmen(self, sock, ue, port, now):
        for _ in range(16):
            try:
                conn, peer = sock.accept()
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            if len(self.verbindungen) >= MAX_VERBINDUNGEN:
                rst(conn)
                klasse = quelle(peer[0], self.sv["lan"], self.sv["vpn"])
                self.verdichter.add(ue.name, port, klasse, "verbindungslimit", self.u.wanduhr())
                continue
            conn.setblocking(False)
            self.verbindungen[conn] = Verbindung(conn, ue, peer[0], port, now)

    def _empfangen(self, verbindung, now):
        try:
            chunk = verbindung.sock.recv(MAX_BYTES - len(verbindung.daten))
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            chunk = b""
        verbindung.daten.extend(chunk)
        row = klassifizieren(verbindung.quelle, verbindung.port, bytes(verbindung.daten), self._kcfg(verbindung.ue, now))
        if not chunk or row["entscheidung"] != "unklar" or len(verbindung.daten) >= MAX_BYTES:
            self._abschliessen(verbindung, now, row)

    def _abschliessen(self, verbindung, now, row=None):
        rst(verbindung.sock)
        self.verbindungen.pop(verbindung.sock, None)
        ue = verbindung.ue
        if row is None:
            row = klassifizieren(verbindung.quelle, verbindung.port, bytes(verbindung.daten), self._kcfg(ue, now))
        klasse = row["quellklasse"]
        if verbindung.quelle in ue.host["ausgenommen"]:
            return self.verdichter.add(ue.name, verbindung.port, klasse, "ausgenommen", self.u.wanduhr())
        if row["entscheidung"] != "wuerde_wecken":
            return self.verdichter.add(ue.name, verbindung.port, klasse, row["entscheidung"], self.u.wanduhr())
        extra = {}
        if row.get("sni_label"):
            extra["sni_label"] = row["sni_label"]
            if row["sni_label"] == "wan" and not self.wan.aktuell(now):
                extra["wan_ip_unklar"] = True
        self._ausloesen(ue, verbindung.quelle, verbindung.port, klasse, klasse.lower(), row["weg"], now, extra)


# ---------------------------------------------------------------- Kommandozeile


class ProbeLog(JsonLog):
    """Probe: eigenes Protokoll, jede Zeile zusätzlich auf stdout für den Live-Test."""
    def emit(self, row, now=None, heartbeat=False):
        if not heartbeat:
            print(json.dumps(row, ensure_ascii=False, sort_keys=True), flush=True)
        return super().emit(row, now, heartbeat)


def wol_senden(mac):
    return wol.senden(mac, ZIELE)


def main(argv=None):
    parser = argparse.ArgumentParser(description="GDM zählen, schlafende Hosts übernehmen und wecken")
    parser.add_argument("--config", default="/etc/greenbuddy/stellvertreter.json")
    parser.add_argument("--aufraeumen", action="store_true",
                        help="Alias und nft-Tabellen aller Hosts und der Probe entfernen (idempotent)")
    parser.add_argument("--probe", type=int, metavar="SEKUNDEN",
                        help="nur die Probe-IP sofort übernehmen (höchstens 900 s), ohne Register und GDM")
    args = parser.parse_args(argv)
    if args.aufraeumen:
        try:
            cfg = laden(args.config)
        except (OSError, ValueError):
            # Auch mit kaputter Konfig die Zustandsdateien unter den Standardpfaden auswerten.
            cfg = {}
        ergebnis = aufraeumen(cfg)
        print(json.dumps(ergebnis, ensure_ascii=False))
        return 1 if ergebnis["fehler"] else 0
    cfg = laden(args.config)
    if args.probe is not None and not 1 <= args.probe <= 900:
        print(json.dumps({"fehler": "probe_sekunden"}), file=sys.stderr)
        return 2
    if args.probe is not None:
        log = str(cfg["log"])
        log = log[:-len(".jsonl")] + "-probe.jsonl" if log.endswith(".jsonl") else log + ".probe"
        logger = ProbeLog(log, limit=2 * 1024 * 1024, rotations=1, ip_retention=True, heartbeat_seconds=3600)
    else:
        logger = JsonLog(cfg["log"], limit=2 * 1024 * 1024, rotations=3,
                         ip_retention=True, heartbeat_seconds=3600)
    try:
        dienst = Dienst(cfg, Umgebung(wol=wol_senden), logger, probe=args.probe)
    except ValueError as error:
        print(json.dumps({"fehler": str(error)}), file=sys.stderr)
        return 2

    def anhalten(signum, frame):
        # Nur ein Merker: eine Ausnahme aus dem Handler ginge verloren, wenn das Signal in einem Finalizer
        # (Popen.__del__) eintrifft (Netztest 12.10.26). Die Schleife sieht den Merker nach höchstens 1 s.
        dienst.stopp = True
    signal.signal(signal.SIGTERM, anhalten)
    signal.signal(signal.SIGINT, anhalten)
    try:
        dienst.laufen()
    except KeyboardInterrupt:
        pass
    finally:
        dienst.beenden("probe_ende" if args.probe is not None else "dienst_ende")
    # Tatsache statt Hoffnung: blieb ein Alias oder eine Tabelle, ist der Lauf gescheitert.
    return 1 if any(ue.alias or ue.nft for ue in dienst.uebernahmen.values()) else 0
