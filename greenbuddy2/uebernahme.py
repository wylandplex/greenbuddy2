"""Übernahme der IP eines schlafenden Hosts: Zustandsautomat, nft/Alias, ARP-Frames und cBPF.

frei -> warte_stille -> uebernommen (-> wecken) -> frei. Jeder Netzeingriff läuft über einen
injizierbaren Runner (ip/nft) und eine Socket-Fabrik; Erfolg wird an Tatsachen (ip -j / nft -j)
geprüft, nie am Exit-Code allein.
"""

import ctypes
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import time
from pathlib import Path

from .konfig import GESPERRT, INTERFACE
from .pcap import tcp_packet

ETH_P_ALL, ETH_P_IP, ETH_P_ARP = 3, 0x0800, 0x0806
SO_ATTACH_FILTER = 26
# Kopflänge reicht für Ethernet + IPv4 mit Optionen + TCP-Kopf; Nutzdaten braucht der Rohmitschnitt nie.
KOPF = 256
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
LEER_MAC = "00:00:00:00:00:00"

# cBPF-Befehle (linux/filter.h)
LD_W, LD_H, LD_B, LD_B_IND, LDX_MSH = 0x20, 0x28, 0x30, 0x50, 0xb1
AND_K, JEQ_K, JSET_K, RET_K = 0x54, 0x15, 0x45, 0x06


def _mac_bytes(mac):
    if not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
        raise ValueError("mac_ungueltig")
    return bytes.fromhex(mac.replace(":", ""))


def _mac_text(raw):
    return ":".join("%02x" % value for value in raw)


def _bauen(zeilen):
    """Sprungziele als Marken; der Kernel erwartet jt/jf relativ zur nächsten Anweisung."""
    marken, index = {}, 0
    for zeile in zeilen:
        if isinstance(zeile, str):
            marken[zeile] = index
        else:
            index += 1
    programm = []
    for zeile in zeilen:
        if isinstance(zeile, str):
            continue
        code, jt, jf, k = zeile
        position = len(programm)
        jt = marken[jt] - position - 1 if isinstance(jt, str) else jt
        jf = marken[jf] - position - 1 if isinstance(jf, str) else jf
        if not 0 <= jt <= 255 or not 0 <= jf <= 255:
            raise ValueError("bpf_sprung")
        programm.append((code, jt, jf, k))
    return programm


def _echte_mac(mac, treffer, sonst):
    raw = _mac_bytes(mac)
    return [(LD_W, 0, 0, 6), (JEQ_K, 0, sonst, int.from_bytes(raw[:4], "big")),
            (LD_H, 0, 0, 10), (JEQ_K, treffer, sonst, int.from_bytes(raw[4:], "big"))]


def _syn_an(address, basis, sonst):
    """IPv4-Ziel = address, TCP, erstes Fragment, SYN ohne ACK; IP-Optionen über ldxb msh."""
    ziel = int(ipaddress.IPv4Address(address))
    return [(LD_W, 0, 0, basis + 16), (JEQ_K, 0, sonst, ziel),
            (LD_B, 0, 0, basis + 9), (JEQ_K, 0, sonst, 6),
            (LD_H, 0, 0, basis + 6), (JSET_K, sonst, 0, 0x1fff),
            (LDX_MSH, 0, 0, basis), (LD_B_IND, 0, 0, basis + 13),
            (AND_K, 0, 0, 0x12), (JEQ_K, "ok", sonst, 0x02)]


def _arp_fremd(address, eigene, treffer, sonst):
    """ARP (Ethertype schon geprüft) mit Absender-IP = address, Ethernet-Quelle nicht die eigene MAC.

    So meldet sich ein anderes Gerät mit der Host-IP: vhost01 mit gewechselter MAC oder ein Gerät auf der
    Probe-Adresse (Review b5). Eigene GARPs von proxy01 tragen dieselbe Absender-IP und fallen hier heraus.
    """
    raw = _mac_bytes(eigene)
    return [(LD_W, 0, 0, 28), (JEQ_K, 0, sonst, int(ipaddress.IPv4Address(address))),
            (LD_W, 0, 0, 6), (JEQ_K, 0, treffer, int.from_bytes(raw[:4], "big")),
            (LD_H, 0, 0, 10), (JEQ_K, sonst, treffer, int.from_bytes(raw[4:], "big"))]


def bpf_arp_von(mac, address, eigene):
    """(a) warte_stille: ARP der echten MAC und jedes fremde ARP mit Absender-IP = Host-IP."""
    return _bauen([(LD_H, 0, 0, 12), (JEQ_K, 0, "weg", ETH_P_ARP)] + _echte_mac(mac, "ok", "fremd")
                  + ["fremd"] + _arp_fremd(address, eigene, "ok", "weg")
                  + ["ok", (RET_K, 0, 0, KOPF), "weg", (RET_K, 0, 0, 0)])


def bpf_uebernommen(mac, address, eigene):
    """(b) eth0 übernommen: echte MAC ODER fremdes ARP mit Absender-IP = Alias ODER SYN ohne ACK an den Alias."""
    return _bauen(_echte_mac(mac, "ok", "typ") + ["typ", (LD_H, 0, 0, 12), (JEQ_K, "arp", 0, ETH_P_ARP),
                                                  (JEQ_K, 0, "weg", ETH_P_IP)]
                  + _syn_an(address, 14, "weg") + ["arp"] + _arp_fremd(address, eigene, "ok", "weg")
                  + ["ok", (RET_K, 0, 0, KOPF), "weg", (RET_K, 0, 0, 0)])


def bpf_syn_cooked(address):
    """(c) DGRAM-Socket (wg0): Pakete beginnen am IPv4-Kopf."""
    return _bauen([(LD_B, 0, 0, 0), (AND_K, 0, 0, 0xf0), (JEQ_K, 0, "weg", 0x40)] + _syn_an(address, 0, "weg")
                  + ["ok", (RET_K, 0, 0, KOPF), "weg", (RET_K, 0, 0, 0)])


def bpf_kodieren(programm):
    return b"".join(struct.pack("=HBBI", *zeile) for zeile in programm)


def filter_setzen(sock, programm):
    """SO_ATTACH_FILTER ersetzt einen vorhandenen Filter atomar; der Kernel kopiert das Programm."""
    raw = bpf_kodieren(programm)
    puffer = ctypes.create_string_buffer(raw, len(raw))
    fprog = struct.pack("HL", len(programm), ctypes.addressof(puffer))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


def raw_socket(fabrik, interface, programm, cooked=False):
    """Protokoll 0 beim Anlegen, Filter, erst dann bind: keine ungefilterten Pakete in der Warteschlange."""
    sock = fabrik(socket.AF_PACKET, socket.SOCK_DGRAM if cooked else socket.SOCK_RAW, 0)
    try:
        filter_setzen(sock, programm)
        sock.bind((interface, ETH_P_IP if cooked else ETH_P_ALL))
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def arp_frame(op, sender_mac, sender_ip, ziel_mac, ziel_ip, eth_ziel=b"\xff" * 6):
    return (eth_ziel + _mac_bytes(sender_mac) + struct.pack("!H", ETH_P_ARP)
            + struct.pack("!HHBBH6s4s6s4s", 1, ETH_P_IP, 6, 4, op, _mac_bytes(sender_mac),
                          socket.inet_aton(sender_ip), _mac_bytes(ziel_mac), socket.inet_aton(ziel_ip)))


def arp_anfrage(eigene_mac, eigene_ip, ziel_ip):
    """who-has ziel_ip tell eigene_ip, als Broadcast."""
    return arp_frame(1, eigene_mac, eigene_ip, LEER_MAC, ziel_ip)


def garp(eigene_mac, address):
    """Gratuitous ARP als Anfrage (wie arping -U): Absender- und Ziel-IP = übernommene Adresse."""
    return arp_frame(1, eigene_mac, address, LEER_MAC, address)


def arp_lesen(frame):
    if len(frame) < 42 or frame[12:14] != b"\x08\x06":
        return None
    htype, ptype, hlen, plen, op, sha, spa, tha, tpa = struct.unpack("!HHBBH6s4s6s4s", frame[14:42])
    if (htype, ptype, hlen, plen) != (1, ETH_P_IP, 6, 4) or op not in (1, 2):
        return None
    return {"op": op, "quelle": _mac_text(frame[6:12]), "sender_mac": _mac_text(sha),
            "sender_ip": socket.inet_ntoa(spa), "ziel_mac": _mac_text(tha), "ziel_ip": socket.inet_ntoa(tpa)}


def tabellen(name):
    """Tabellennamen enthalten immer den Hostschlüssel: Probe und Dienst kollidieren nie."""
    if not re.fullmatch(r"[a-z0-9]{1,15}", name):
        raise ValueError("name_ungueltig")
    return (("ip", "gb2_sv_" + name), ("arp", "gb2_sv_" + name + "_arp"))


def nft_regeln(name, host, lan, vpn, marke=None):
    """Plan 5.3: input/output -300, ARP der echten MAC verwerfen; "create" scheitert an fremden Tabellen.

    marke: Kommentar an der letzten Regel jeder Tabelle. Bricht "nft -f" erst nach dem Commit ab (Frist),
    erkennt der Dienst seine Tabellen daran und löscht nie eine fremde gleichnamige (Review b5, R-A7).
    """
    if marke is not None and not (isinstance(marke, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", marke)):
        raise ValueError("marke_ungueltig")
    kommentar = "" if marke is None else ' comment "%s"' % marke
    (_, ip_tabelle), (_, arp_tabelle) = tabellen(name)
    ziel = str(ipaddress.IPv4Address(host["ip"]))
    mac = _mac_text(_mac_bytes(host["mac"]))
    kette = "{ type filter hook %s priority -300; policy accept; }"
    zeilen = ["create table ip " + ip_tabelle,
              "create chain ip %s eingang %s" % (ip_tabelle, kette % "input"),
              "create chain ip %s ausgang %s" % (ip_tabelle, kette % "output")]
    regel = "add rule ip %s eingang ip daddr %s " % (ip_tabelle, ziel)
    ausgenommen = list(dict.fromkeys(str(ipaddress.IPv4Address(a)) for a in host["ausgenommen"]))
    if ausgenommen:
        zeilen.append(regel + "ip saddr { %s } drop" % ", ".join(ausgenommen))
    # Inhaltsports, die auch SYN-Ports sind, erreichen den Listener nur aus dem WAN.
    doppelt = [port for port in host["inhalt_ports"] if port in host["syn_ports"]]
    if doppelt:
        for netz in list(lan) + list(vpn):
            zeilen.append(regel + "ip saddr %s tcp dport { %s } drop"
                          % (ipaddress.IPv4Network(netz), ", ".join(map(str, doppelt))))
    if host["inhalt_ports"]:
        zeilen.append(regel + "tcp dport { %s } accept" % ", ".join(map(str, host["inhalt_ports"])))
    zeilen.append(regel + "drop" + kommentar)
    # Kein lokaler Prozess (gb-wecken, Webhook) darf unter der Host-IP sich selbst erreichen.
    zeilen.append("add rule ip %s ausgang ip daddr %s drop" % (ip_tabelle, ziel))
    zeilen += ["create table arp " + arp_tabelle,
               "create chain arp %s eingang %s" % (arp_tabelle, kette % "input"),
               "add rule arp %s eingang arp saddr ether %s drop%s" % (arp_tabelle, mac, kommentar)]
    return "\n".join(zeilen) + "\n"


def boot_uhr():
    # BOOTTIME läuft auch über S3 weiter und springt nie mit der Wanduhr.
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def befehl(runner, args, eingabe=None):
    """ip/nft mit fester Umgebung; ein fehlendes Werkzeug ist rc 127, nie eine Ausnahme."""
    try:
        return runner(args, input=eingabe, text=True, capture_output=True, timeout=2, env=ENV)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, "", "werkzeug_fehlt")
    except (OSError, subprocess.SubprocessError) as error:
        return subprocess.CompletedProcess(args, -1, "", str(error))


def adressen(runner):
    """Alle lokalen IPv4-Adressen als (ip, prefixlen, interface); unklar = ValueError."""
    result = befehl(runner, ["ip", "-j", "-4", "addr"])
    try:
        if result.returncode:
            raise ValueError()
        rows = json.loads(result.stdout)
        out = []
        for row in rows:
            for info in row.get("addr_info", []):
                if info.get("family", "inet") == "inet" and "local" in info:
                    out.append((str(ipaddress.IPv4Address(info["local"])), int(info["prefixlen"]), row["ifname"]))
        return out
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("adressen_unklar")


def nft_tabellen(runner):
    """Vorhandene Tabellen als {(familie, name)} aus nft -j; fehlendes nft = nft_fehlt."""
    result = befehl(runner, ["nft", "-j", "list", "tables"])
    if result.returncode == 127:
        raise ValueError("nft_fehlt")
    try:
        if result.returncode:
            raise ValueError()
        rows = json.loads(result.stdout)["nftables"]
        return {(row["table"]["family"], row["table"]["name"]) for row in rows if "table" in row}
    except (ValueError, TypeError, KeyError):
        raise ValueError("nft_unklar")


def nft_marken(runner, tabelle):
    """Regelkommentare einer Tabelle aus nft -j; unklar (auch: Tabelle weg) = ValueError."""
    result = befehl(runner, ["nft", "-j", "list", "table", tabelle[0], tabelle[1]])
    try:
        if result.returncode:
            raise ValueError()
        rows = json.loads(result.stdout)["nftables"]
        return {row["rule"].get("comment") for row in rows if "rule" in row}
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("nft_unklar")


def listener(fabrik, address, port):
    sock = fabrik(socket.AF_INET, socket.SOCK_STREAM, 0)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, port))
        sock.listen(16)
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


class Umgebung:
    """Verbindung zur Außenwelt; Tests ersetzen jedes Teil."""
    def __init__(self, runner=subprocess.run, uhr=boot_uhr, wanduhr=None, sockets=socket.socket, lesen=None,
                 protokoll=None, wol=None, boot_id=boot_id):
        self.runner, self.uhr, self.sockets = runner, uhr, sockets
        self.wanduhr = wanduhr or time.time
        self.lesen = lesen or (lambda path: Path(path).read_text())
        self.protokoll = protokoll or (lambda row: None)
        self.wol = wol
        self.boot_id = boot_id
        self.sichern = lambda: None


# Diese Gründe beweisen einen wachen Host oder ein bewusstes Ende: laufende Weckserie stoppen.
SERIE_STOPP = ("echte_mac", "register_angemeldet", "neuer_zyklus", "register_lease_abgelaufen", "register_phase",
               "register_fehlt", "dienst_ende", "probe_ende")
# Kein Befund über den Host: derselbe Zyklus darf danach (über warte_stille) erneut übernommen werden.
NICHT_ERLEDIGT = ("dienst_ende", "abgeschaltet", "probe_ende")


class Uebernahme:
    """Zustandsautomat je Host: frei -> warte_stille -> uebernommen (-> wecken) -> frei."""

    def __init__(self, name, host, sv, umgebung, probe=False):
        self.name, self.host, self.sv, self.u, self.probe = name, host, sv, umgebung, probe
        self.interface, self.listen_ip = sv["interface"], sv["listen_ip"]
        if not re.fullmatch(INTERFACE, self.interface) or host["ip"] in GESPERRT | {self.listen_ip}:
            raise ValueError("uebernahme_gesperrt")
        self.tabellen = tabellen(name)
        self.mac = _mac_bytes(host["mac"])
        self.phase, self.zyklus, self.erledigt, self.lease_ende = "frei", None, None, None
        self.alias = self.nft = False
        # Marke des letzten Ladeversuchs; nur_markierte: nach unklarem Laden nur Tabellen mit dieser Marke löschen.
        self.marke, self.nur_markierte = None, False
        self.eth = self.vpn = None
        self.listener = {}
        self.eigene_mac = None
        self.stille_seit = self.warte_beginn = self.naechste_probe = None
        self.garps, self.naechster_garp, self.naechste_lebendprobe, self.vpn_versuch = [], None, None, None
        self.serie, self.weckung, self.nachraeumen = None, None, None
        self.sendefehler_gemeldet = False

    # ---------------------------------------------------------------- Bericht

    def phase_bericht(self):
        return "wecken" if self.phase == "uebernommen" and self.serie else self.phase

    def zustand(self):
        return {"phase": self.phase_bericht(), "zyklus": self.zyklus, "erledigt": self.erledigt,
                "ip": self.host["ip"], "interface": self.interface, "alias": self.alias, "nft": self.nft,
                "tabellen": [list(t) for t in self.tabellen], "weckung": self.weckung}

    def sockets(self):
        rows = [(sock, art) for sock, art in ((self.eth, "eth"), (self.vpn, "vpn")) if sock is not None]
        return rows + [(sock, ("listener", port)) for port, sock in self.listener.items()]

    def naechster_termin(self, now):
        termine = []
        if self.serie:
            termine.append(self.serie["naechst"])
        if self.phase == "frei":
            if (self.alias or self.nft) and self.nachraeumen is not None:
                termine.append(self.nachraeumen)
        else:
            termine.append(self.lease_ende)
        if self.phase == "warte_stille":
            termine += [self.naechste_probe, self.stille_seit + self.sv["stille_s"],
                        self.warte_beginn + self.sv["stille_max_s"]]
        elif self.phase == "uebernommen":
            termine += self.garps[:1] + [self.naechster_garp, self.naechste_lebendprobe]
            if self.vpn is None and self.vpn_versuch is not None:
                termine.append(self.vpn_versuch)
        return min(termine) if termine else now + 3600

    def _log(self, row):
        self.u.protokoll(dict(row, host=self.name))

    def _phase(self, nach, grund, **extra):
        von = self.phase_bericht()
        self.phase = nach
        self._log(dict({"ereignis": "phase", "von": von, "nach": self.phase_bericht(), "grund": grund,
                        "zyklus": self.zyklus}, **extra))

    # ---------------------------------------------------------------- Ablauf

    def register(self, row, now):
        """Registerzeile dieses Hosts (None = fehlt) anwenden; vhost01 meldet sich selbst zurück."""
        if self.serie and self.phase == "frei" and self.serie.get("zyklus") is not None and (
                row is None or row["phase"] == "angemeldet" or row["zyklus"] != self.serie["zyklus"]):
            self.serie = None
            self._log({"ereignis": "wol_serie_ende", "grund": "register"})
        if self.phase != "frei":
            grund = None
            if row is None:
                grund = "register_fehlt"
            elif row["zyklus"] != self.zyklus:
                grund = "neuer_zyklus"
            elif row["phase"] == "angemeldet":
                grund = "register_angemeldet"
            elif row["phase"] == "lease_abgelaufen":
                grund = "register_lease_abgelaufen"
            elif row["phase"] != "schlaf_absicht":
                grund = "register_phase"
            if grund:
                self.freigeben(grund, now)
            return
        if row is None or row["phase"] != "schlaf_absicht" or row["zyklus"] == self.erledigt or self.serie:
            return
        zyklus = row["zyklus"]
        ablauf = row.get("ablauf_boot")
        if row.get("boot_id") != self.u.boot_id() or type(ablauf) not in (int, float):
            # proxy01 neu gestartet oder altes Register: Lease unklar -> wecken statt übernehmen (Spec 3.7).
            self.erledigt = zyklus
            self._wecken_ohne_alias("lease_unklar", now, zyklus)
        elif ablauf <= now:
            self.erledigt = zyklus
            self._wecken_ohne_alias("lease_abgelaufen", now, zyklus)
        else:
            self.warte_stille(zyklus, ablauf, now)

    def warte_stille(self, zyklus, lease_ende, now):
        self.zyklus, self.lease_ende = zyklus, lease_ende
        try:
            self.eigene_mac = self._eigene_mac()
            self.eth = raw_socket(self.u.sockets, self.interface,
                                  bpf_arp_von(self.host["mac"], self.host["ip"], self.eigene_mac))
        except (OSError, ValueError):
            return self._fehlschlag("raw_socket", now)
        self.stille_seit = self.warte_beginn = self.naechste_probe = now
        self.sendefehler_gemeldet = False
        self._phase("warte_stille", "schlaf_absicht")
        self.u.sichern()

    def tick(self, now):
        if self.serie and now >= self.serie["naechst"]:
            if now - self.serie["beginn"] >= self.sv["wol_max_s"]:
                self._serie_ende(now)
            else:
                self._wol()
                self.serie["naechst"] += self.sv["wol_wiederholen_s"]
                if self.serie["naechst"] <= now:
                    # Nach einem Stau der Schleife nicht stoßweise nachholen.
                    self.serie["naechst"] = now + self.sv["wol_wiederholen_s"]
        if self.phase == "frei":
            if (self.alias or self.nft) and self.nachraeumen is not None and now >= self.nachraeumen:
                self._artefakte_entfernen(now)
            return
        if now >= self.lease_ende:
            zyklus = self.zyklus
            if self.probe:
                return self.freigeben("probe_ende", now)
            self.freigeben("lease_abgelaufen", now)
            return self._wecken_ohne_alias("lease_abgelaufen", now, zyklus)
        if self.phase == "warte_stille":
            if now - self.warte_beginn >= self.sv["stille_max_s"]:
                return self.freigeben("stille_ausgeblieben", now)
            if now - self.stille_seit >= self.sv["stille_s"]:
                return self.uebernehmen(now)
            if now >= self.naechste_probe:
                self._senden(arp_anfrage(self.eigene_mac, self.listen_ip, self.host["ip"]))
                # Drei Proben je Stillefenster, höchstens eine je Sekunde: bei stille_s = 1 und 1 s Takt reichte
                # ein um 1 ms verspäteter Tick, um einen antwortenden Host zu übernehmen (Netztest 12.10.26).
                self.naechste_probe = now + min(1.0, self.sv["stille_s"] / 3.0)
            return
        if (self.garps and self.garps[0] <= now) or now >= self.naechster_garp:
            self._senden(garp(self.eigene_mac, self.host["ip"]))
            self.garps = [t for t in self.garps if t > now]
            if now >= self.naechster_garp:
                self.naechster_garp = now + self.sv["garp_s"]
        if now >= self.naechste_lebendprobe:
            # R2c: wacht der Host unbemerkt auf, antwortet er hierauf mit seiner echten MAC.
            self._senden(arp_anfrage(self.eigene_mac, self.listen_ip, self.host["ip"]))
            self.naechste_lebendprobe = now + self.sv["lebendprobe_s"]
        if self.vpn is None and self.vpn_versuch is not None and now >= self.vpn_versuch:
            self._vpn_oeffnen(now)

    def vorpruefen(self):
        """Tatsachen vor jeder Übernahme; None = bereit, sonst Grund."""
        for scope in ("all", self.interface):
            for key, expected in (("arp_ignore", "1"), ("arp_announce", "2")):
                try:
                    value = self.u.lesen("/proc/sys/net/ipv4/conf/%s/%s" % (scope, key)).strip()
                except OSError:
                    return "arp_sysctl_unklar"
                if value != expected:
                    return "arp_sysctl_ungueltig"
        try:
            eigene = self._eigene_mac()
        except (OSError, ValueError):
            return "interface_unklar"
        if eigene == self.host["mac"]:
            return "mac_eigene"
        try:
            lokal = adressen(self.u.runner)
        except ValueError as error:
            return str(error)
        if self.host["ip"] in {row[0] for row in lokal}:
            return "adresse_lokal"
        if (self.listen_ip, self.interface) not in {(row[0], row[2]) for row in lokal}:
            return "listen_ip_fehlt"
        try:
            if set(self.tabellen) & nft_tabellen(self.u.runner):
                return "tabelle_belegt"
        except ValueError as error:
            return str(error)
        try:
            self.u.sockets(socket.AF_PACKET, socket.SOCK_RAW, 0).close()
        except OSError:
            return "raw_socket_fehlt"
        self.eigene_mac = eigene
        return None

    def uebernehmen(self, now):
        grund = self.vorpruefen()
        if grund:
            return self._fehlschlag(grund, now)
        try:
            filter_setzen(self.eth, bpf_uebernommen(self.host["mac"], self.host["ip"], self.eigene_mac))
        except OSError:
            return self._fehlschlag("raw_filter", now)
        self._vpn_oeffnen(now)
        self.marke = "gb2-%d-%s" % (os.getpid(), secrets.token_hex(4))
        self.nft, self.nur_markierte = True, False
        self.u.sichern()
        geladen = befehl(self.u.runner, ["nft", "-f", "-"], nft_regeln(self.name, self.host, self.sv["lan"],
                                                                         self.sv["vpn"], self.marke))
        try:
            vorhanden = set(self.tabellen) & nft_tabellen(self.u.runner)
        except ValueError:
            vorhanden = None
        if geladen.returncode or vorhanden != set(self.tabellen):
            # "create" ist atomar, aber der Exit-Code beweist nichts: reißt nft die Frist erst nach dem Commit
            # (commit_mutex), stehen die Tabellen trotzdem (Review b5). Was dasteht oder unklar ist, räumt
            # freigeben ab, aber nur mit der Marke dieses Versuchs; eine fremde gleichnamige Tabelle bleibt.
            self.nft, self.nur_markierte = vorhanden != set(), True
            return self._fehlschlag("nft_laden", now)
        self.alias = True
        self.u.sichern()
        gesetzt = befehl(self.u.runner, ["ip", "addr", "add", self.host["ip"] + "/32", "dev", self.interface])
        # Tatsache statt Exit-Code: auch ein abgebrochenes "ip addr add" (Frist nach rtnl_lock) kann den Alias
        # gesetzt haben. Nur ein nachweislich fehlender Alias gilt als fehlend; unklar räumt freigeben ab.
        da = self._alias_da()
        if da is False:
            self.alias = False
        if gesetzt.returncode or da is not True:
            return self._fehlschlag("alias_setzen", now)
        try:
            for port in self.host["inhalt_ports"]:
                self.listener[port] = listener(self.u.sockets, self.host["ip"], port)
        except OSError:
            return self._fehlschlag("listener", now)
        self.garps = [now, now + 1, now + 3]
        self.naechster_garp = now + self.sv["garp_s"]
        self.naechste_lebendprobe = now + self.sv["lebendprobe_s"]
        self._phase("uebernommen", "stille")
        self.u.sichern()
        self.tick(now)

    def frame(self, daten, adresse, now, cooked=False):
        """Rohpaket auswerten; liefert {"quelle", "port"} für einen SYN an den Alias, sonst None."""
        if adresse is not None and len(adresse) > 2 and adresse[2] == socket.PACKET_OUTGOING:
            return None
        if not cooked and daten[6:12] == self.mac:
            if self.phase == "warte_stille" and daten[12:14] == b"\x08\x06":
                self.stille_seit = now
            elif self.phase == "uebernommen":
                self.freigeben("echte_mac", now)
            return None
        fremd = None if cooked or self.phase == "frei" else self._fremde_mac(daten)
        if fremd:
            return self._fremd_belegt(fremd, now)
        if self.phase != "uebernommen":
            return None
        packet = tcp_packet(daten, 101 if cooked else 1)
        if not packet or packet["target"] != self.host["ip"] or not packet["syn"] or packet["ack"]:
            return None
        return {"quelle": packet["source"], "port": packet["port"]}

    def wecken(self, info, now):
        """WOL-Serie (R4) bei gehaltenem Alias; False, wenn schon eine Serie läuft."""
        if self.serie or self.phase != "uebernommen":
            return False
        self._serie_starten(info, now, self.zyklus)
        return True

    def abschalten(self, now):
        """Abschalter: Übernahme lösen; registriert schlafende Hosts erhalten WOL (Spec 3.7)."""
        if self.phase != "frei":
            zyklus = self.zyklus
            self.freigeben("abgeschaltet", now)
            if not self.probe:
                self._wecken_ohne_alias("abgeschaltet", now, zyklus)

    def freigeben(self, grund, now):
        """Alias -> Listener -> nft -> Zustand; auch bei Teilfehlern alles Mögliche entfernen."""
        von = self.phase_bericht()
        fehler = self._artefakte_entfernen(now, sichern=False)
        for sock in (self.eth, self.vpn):
            if sock is not None:
                sock.close()
        self.eth = self.vpn = None
        if grund in SERIE_STOPP and self.serie:
            if grund == "echte_mac":
                self._log({"ereignis": "wecken_erfolg", "zyklus": self.zyklus,
                           "sekunden": round(now - self.serie["beginn"], 1)})
            self.serie = None
        if self.zyklus is not None and grund not in NICHT_ERLEDIGT:
            self.erledigt = self.zyklus
        self.phase = "frei"
        self.u.sichern()
        self._log({"ereignis": "phase", "von": von, "nach": "frei", "grund": grund, "zyklus": self.zyklus,
                   "fehler": fehler})
        self.zyklus = self.lease_ende = None
        self.stille_seit = self.warte_beginn = self.naechste_probe = None
        self.garps, self.naechster_garp, self.naechste_lebendprobe, self.vpn_versuch = [], None, None, None

    # ---------------------------------------------------------------- Hilfen

    def nachraeumen_jetzt(self, now):
        """Nach einer unvollständigen Freigabe sofort erneut versuchen (z. B. beim Dienstende)."""
        return self._artefakte_entfernen(now)

    def _eigene_mac(self):
        value = self.u.lesen("/sys/class/net/%s/address" % self.interface).strip().lower()
        _mac_bytes(value)
        return value

    def _alias_da(self):
        try:
            return (self.host["ip"], 32, self.interface) in set(adressen(self.u.runner))
        except ValueError:
            return None

    def _artefakte_entfernen(self, now, sichern=True):
        fehler = []
        if self.alias:
            befehl(self.u.runner, ["ip", "addr", "del", self.host["ip"] + "/32", "dev", self.interface])
            if self._alias_da() is False:
                self.alias = False
            else:
                fehler.append("alias")
        for sock in self.listener.values():
            sock.close()
        self.listener = {}
        if self.nft and self.alias:
            # Solange der Alias besteht, schützt nur die Tabelle proxy01s eigene Dienste unter der Host-IP.
            fehler.append("nft_bleibt")
        elif self.nft:
            try:
                eigene = set(self.tabellen) & nft_tabellen(self.u.runner)
                if self.nur_markierte:
                    # Nach einem unklaren Laden gehört uns nur, was die Marke dieses Versuchs trägt (R-A7).
                    eigene = {t for t in eigene if self.marke in nft_marken(self.u.runner, t)}
                for tabelle in eigene:
                    befehl(self.u.runner, ["nft", "delete", "table", tabelle[0], tabelle[1]])
                if eigene & nft_tabellen(self.u.runner):
                    fehler.append("nft")
                else:
                    self.nft = self.nur_markierte = False
            except ValueError:
                fehler.append("nft")
        self.nachraeumen = now + 10 if fehler else None
        if fehler:
            self._log({"ereignis": "freigabe_unvollstaendig", "fehler": fehler})
        if sichern:
            self.u.sichern()
        return fehler

    def _fremde_mac(self, daten):
        """MAC eines anderen Geräts, das per ARP die Host-IP als Absender nennt; sonst None."""
        row = arp_lesen(daten)
        if row is None or row["sender_ip"] != self.host["ip"] or self.eigene_mac in (row["quelle"],
                                                                                      row["sender_mac"]):
            return None
        return row["quelle"]

    def _fremd_belegt(self, fremd, now):
        """Die Host-IP gehört gerade einem anderen Gerät (MAC-Wechsel von vhost01, belegte Probe-Adresse).

        warte_stille übernimmt nicht, uebernommen gibt sofort frei; der Zyklus ist erledigt. Bei Zweifel WOL
        statt Alias (Spec 3.7): eine Serie an die konfigurierte MAC, außer im Probe-Modus (Review b5).
        """
        zyklus, extra = self.zyklus, {"mac": fremd, "phase": self.phase_bericht()}
        self.freigeben("fremde_mac", now)
        if self.probe:
            self._log(dict({"ereignis": "fremde_mac", "zyklus": zyklus}, **extra))
        else:
            self._wecken_ohne_alias("fremde_mac", now, zyklus, **extra)

    def _fehlschlag(self, grund, now):
        zyklus = self.zyklus
        self._log({"ereignis": "uebernahme_fehlgeschlagen", "grund": grund, "zyklus": zyklus})
        self.freigeben("uebernahme_fehlgeschlagen", now)
        if zyklus is not None:
            self.erledigt = zyklus
        if not self.probe:
            self._wecken_ohne_alias("uebernahme_fehlgeschlagen", now, zyklus)

    def _wecken_ohne_alias(self, entscheidung, now, zyklus, **extra):
        self._log(dict({"ereignis": entscheidung, "zyklus": zyklus}, **extra))
        if not self.serie:
            self._serie_starten({"weg": None, "port": None, "quellklasse": None, "entscheidung": entscheidung},
                                now, zyklus)

    def _serie_starten(self, info, now, zyklus):
        self.serie = {"beginn": now, "naechst": now + self.sv["wol_wiederholen_s"], "zyklus": zyklus}
        self.weckung = {"zeit": self.u.wanduhr(), "weg": info.get("weg"), "port": info.get("port"),
                        "quellklasse": info.get("quellklasse"), "entscheidung": info["entscheidung"]}
        self._wol()
        self.u.sichern()

    def _serie_ende(self, now):
        dauer = round(now - self.serie["beginn"], 1)
        self.serie = None
        if self.phase == "uebernommen":
            # R4: Alias bleibt, die Lebendprobe schützt; neue Nachfrage darf erneut wecken.
            self._log({"ereignis": "wecken_gescheitert", "zyklus": self.zyklus, "sekunden": dauer})
        else:
            self._log({"ereignis": "wol_serie_ende", "grund": "frist", "sekunden": dauer})
        self.u.sichern()

    def _wol(self):
        try:
            gesendet = self.u.wol(self.host["mac"])
        except OSError:
            gesendet = 0
        if not gesendet:
            self._log({"ereignis": "wol_sendefehler"})

    def _senden(self, frame):
        try:
            self.eth.send(frame)
        except OSError:
            if not self.sendefehler_gemeldet:
                self.sendefehler_gemeldet = True
                self._log({"ereignis": "senden_fehler", "phase": self.phase})

    def _vpn_oeffnen(self, now):
        vpn = self.sv.get("vpn_interface")
        if not vpn or self.vpn is not None:
            return
        try:
            self.vpn = raw_socket(self.u.sockets, vpn, bpf_syn_cooked(self.host["ip"]), cooked=True)
            self.vpn_versuch = None
        except OSError:
            # Ohne wg0 weiter; VPN-SYNs werden erst nach einem erfolgreichen neuen Versuch gesehen.
            if self.vpn_versuch is None:
                self._log({"ereignis": "vpn_socket_fehlt", "interface": vpn})
            self.vpn_versuch = now + 30


# ---------------------------------------------------------------- Aufräumen nach Absturz (ExecStopPost)

ZUSTAND = "/run/greenbuddy/stellvertreter/uebernahme.json"
# Phantom-Test bis b4: eigene Zustandsdatei und Tabelle ip gb2_phantom.
PHANTOM = "/run/greenbuddy/stellvertreter/phantom.json"


def probe_pfad(zustand):
    path = Path(zustand)
    return str(path.with_name(path.stem + "-probe" + path.suffix))


def _json_lesen(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        return json.loads(source.read(1 << 20))


def probe_laeuft(pid, eigene_pid=None):
    """Eine noch laufende Probe räumt selbst auf; nur ihr eigener Prozess zählt (PID-Wiederverwendung)."""
    if type(pid) is not int or pid <= 1 or pid == eigene_pid:
        return False
    try:
        cmdline = Path("/proc/%d/cmdline" % pid).read_bytes()
    except OSError:
        return False
    return b"--probe" in cmdline and b"stellvertreter" in cmdline


def aufraeumen(cfg, runner=subprocess.run, nur=None, eigene_pid=None, laeuft=probe_laeuft):
    """Alias und Tabellen aus Zustandsdateien UND Konfig entfernen; fehlende Artefakte sind Erfolg.

    nur: Namen (Hosts, "probe", "phantom"); None = alles. Gesperrte Adressen und fremde Präfixe
    werden nie angefasst; solange ein Alias nicht weicht, bleibt seine Tabelle (Isolation).
    """
    from .konfig import stellvertretung
    ergebnis = {"entfernt": [], "fehler": [], "uebersprungen": []}
    try:
        sv = stellvertretung(cfg)
    except ValueError:
        sv = None
    listen_ip = cfg.get("listen_ip")
    gesperrt = GESPERRT | ({listen_ip} if isinstance(listen_ip, str) else set())
    zustand = sv["zustand"] if sv else ZUSTAND
    kandidaten = {}

    def merken(name, ip, interface, tabs):
        eintrag = kandidaten.setdefault(name, {"aliasse": set(), "tabellen": set()})
        if isinstance(ip, str) and isinstance(interface, str):
            eintrag["aliasse"].add((ip, interface))
        eintrag["tabellen"].update(tabs)

    if sv:
        for name, host in sv["hosts"].items():
            merken(name, host["ip"], sv["interface"], tabellen(name))
        if sv["probe"]:
            merken("probe", sv["probe"]["ip"], sv["interface"], tabellen("probe"))
    probe_pid, probe_unklar, dateien = None, False, {}
    for path, art in ((zustand, "dienst"), (probe_pfad(zustand), "probe")):
        try:
            saved = _json_lesen(path)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            if art == "probe":
                # Probe als root gestartet: ohne lesbare PID nicht zuordenbar, also nicht anfassen.
                probe_unklar = True
                continue
            # Eigene Datei unlesbar: die Konfig deckt die festen Namen trotzdem ab.
            ergebnis["uebersprungen"].append("zustand_unlesbar:" + art)
            dateien[path] = set()
            continue
        hosts = saved.get("hosts") if isinstance(saved, dict) else None
        dateien[path] = set()
        for name, row in (hosts if isinstance(hosts, dict) else {}).items():
            if not isinstance(row, dict) or not re.fullmatch(r"[a-z0-9]{1,15}", str(name)):
                continue
            dateien[path].add(name)
            merken(name, row.get("ip") if row.get("alias") else None, row.get("interface"),
                   tabellen(name) if row.get("nft") or row.get("alias") else ())
        if art == "probe":
            probe_pid = saved.get("pid") if isinstance(saved, dict) else None
    phantom = cfg.get("arp_state", PHANTOM)
    try:
        saved = _json_lesen(phantom)
        dateien[phantom] = {"phantom"}
        merken("phantom", saved.get("ip") if isinstance(saved, dict) and saved.get("alias") else None,
               saved.get("interface") if isinstance(saved, dict) else None, [("ip", "gb2_phantom")])
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        ergebnis["uebersprungen"].append("zustand_unlesbar:phantom")
    merken("phantom", None, None, [("ip", "gb2_phantom")])
    if nur is not None:
        kandidaten = {name: eintrag for name, eintrag in kandidaten.items() if name in nur}
    if "probe" in kandidaten and probe_unklar:
        del kandidaten["probe"]
        ergebnis["uebersprungen"].append("probe_unklar")
    elif "probe" in kandidaten and laeuft(probe_pid, eigene_pid):
        del kandidaten["probe"]
        ergebnis["uebersprungen"].append("probe_laeuft")
    offen = set()
    try:
        lokal = set(adressen(runner))
    except ValueError:
        lokal = None
        if any(eintrag["aliasse"] for eintrag in kandidaten.values()):
            ergebnis["fehler"].append("adressen_unklar")
            offen.update(name for name, eintrag in kandidaten.items() if eintrag["aliasse"])
    for name, eintrag in sorted(kandidaten.items()):
        for ip, interface in sorted(eintrag["aliasse"]):
            try:
                ip = str(ipaddress.IPv4Address(ip))
            except ValueError:
                ergebnis["uebersprungen"].append("alias_ungueltig:" + name)
                continue
            if ip in gesperrt or not re.fullmatch(INTERFACE, interface):
                ergebnis["uebersprungen"].append("alias_gesperrt:" + name)
                continue
            if lokal is None or (ip, 32, interface) not in lokal:
                continue
            befehl(runner, ["ip", "addr", "del", ip + "/32", "dev", interface])
            try:
                weg = (ip, 32, interface) not in set(adressen(runner))
            except ValueError:
                weg = False
            if weg:
                ergebnis["entfernt"].append("alias:" + name)
            else:
                ergebnis["fehler"].append("alias:" + name)
                offen.add(name)
    try:
        vorhanden = nft_tabellen(runner)
    except ValueError as error:
        # Ohne nft-Werkzeug kann keine Tabelle angelegt worden sein.
        vorhanden = set() if str(error) == "nft_fehlt" else None
        if vorhanden is None and any(eintrag["tabellen"] for eintrag in kandidaten.values()):
            ergebnis["fehler"].append("nft_unklar")
            offen.update(kandidaten)
    if vorhanden is not None:
        for name, eintrag in sorted(kandidaten.items()):
            treffer = eintrag["tabellen"] & vorhanden
            if not treffer:
                continue
            if name in offen:
                ergebnis["fehler"].append("nft_bleibt:" + name)
                continue
            for familie, tabelle in sorted(treffer):
                befehl(runner, ["nft", "delete", "table", familie, tabelle])
            try:
                rest = treffer & nft_tabellen(runner)
            except ValueError:
                rest = treffer
            if rest:
                ergebnis["fehler"].append("nft:" + name)
                offen.add(name)
            else:
                ergebnis["entfernt"].append("nft:" + name)
    for path, namen in dateien.items():
        betroffen = namen & set(kandidaten) if nur is not None else namen
        # Eine Zustandsdatei fällt nur, wenn alle ihre Hosts geprüft und sauber sind.
        if (nur is None or namen <= set(kandidaten)) and not (betroffen & offen) and \
                not (path == probe_pfad(zustand) and "probe_laeuft" in ergebnis["uebersprungen"]):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError:
                ergebnis["fehler"].append("zustand_loeschen")
    return ergebnis

