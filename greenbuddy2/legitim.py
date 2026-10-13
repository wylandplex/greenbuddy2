"""Legitime WAN-Quellen (b6): gb-mitschnitt schreibt, gb-schlaf liest.

Eine WAN-Verbindung hält vhost01 nur wach, wenn sie ihn über proxy01 auch wecken dürfte: Ihre Quelle hat
der Mitschnitt mit "wuerde_wecken" beurteilt, oder sie steht für genau diesen Port in `legitim_quellen`.
Jeder Zweifel an der Datei heißt: kein Filter, jede Verbindung zählt wie in beta.5.
"""

import collections
import ipaddress
import json
import math
import os
import pwd
import stat

from .klassifikation import NICHT_OEFFENTLICH, quelle
from .konfig import LEGITIM
from .register import atomar

KONTO = "gb-mitschnitt"
VERSION = 1
MAX_BYTES = 1024 * 1024
MAX_EIGENE = 16
# Die Runde von gb-schlaf beginnt vor dem Lesen; der Mitschnitt darf die Datei währenddessen schreiben.
ZUKUNFT_S = 60
# Spätestens so oft schreibt der Mitschnitt neu, auch ohne Änderung; gb-schlaf duldet 180 s.
HERZSCHLAG_S = 30
FELDER = ("version", "zeit", "ttl_s", "quellen", "letztes_paket")


def besitzer():
    """root und das Konto des Mitschnitts; fehlt das Konto, nur root."""
    try:
        return {0, pwd.getpwnam(KONTO).pw_uid}
    except KeyError:
        return {0}


def _zahl(value):
    return type(value) in (int, float) and math.isfinite(value)


def _ipv4(value):
    """Nur die kanonische Schreibweise; '198.051.100.7' oder IPv6 sind Formfehler."""
    if not isinstance(value, str) or str(ipaddress.IPv4Address(value)) != value:
        raise ValueError("legitim_ip")
    return value


def lesen(path, uids):
    """Keine Symlinks; regulär, vom erwarteten Besitzer, nicht gruppen- oder weltschreibbar; Schema streng."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in uids
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise ValueError("legitim_rechte")
        with os.fdopen(fd, "rb") as source:
            fd = -1
            raw = source.read(MAX_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) > MAX_BYTES:
        raise ValueError("legitim_gross")
    data = json.loads(raw)
    if (not isinstance(data, dict) or any(name not in data for name in FELDER)
            or not set(data) <= set(FELDER) | {"eigene_wan_ip"}
            or type(data["version"]) is not int or data["version"] != VERSION
            or not _zahl(data["zeit"]) or not _zahl(data["ttl_s"]) or data["ttl_s"] <= 0
            or not isinstance(data["quellen"], dict)
            or not _zahl(data["letztes_paket"]) or data["letztes_paket"] > data["zeit"]):
        raise ValueError("legitim_schema")
    for ip, zuletzt in data["quellen"].items():
        _ipv4(ip)
        # Der Mitschnitt klemmt jeden Eintrag auf seine Schreibzeit; später ist ein Formfehler.
        if not _zahl(zuletzt) or zuletzt > data["zeit"]:
            raise ValueError("legitim_schema")
    eigene = data.get("eigene_wan_ip", [])
    if not isinstance(eigene, list) or len(eigene) > MAX_EIGENE:
        raise ValueError("legitim_schema")
    for ip in eigene:
        _ipv4(ip)
    return data


class Schreiber:
    """Mitschnitt-Seite: legitime WAN-Quellen im Speicher (älteste zuerst), Datei atomar per tmp + rename.

    Scanner kommen nie hinein (nur "wuerde_wecken"); die Obergrenze schützt trotzdem den Speicher.
    Die eigene WAN-Adresse (Haarnadel) wird nie eingetragen und fliegt heraus, sobald sie bekannt ist.
    """

    def __init__(self, path=LEGITIM, ttl=3600, maximum=4096, wan=None, logger=None):
        self.path, self.ttl, self.maximum, self.wan, self.logger = path, ttl, maximum, wan, logger
        self.quellen = collections.OrderedDict()
        self.neu, self.versuch, self.fehler = True, None, False
        self.eigene_zuletzt = None
        # Zuletzt ein Paket für das Ziel erfasst (bis zum ersten: der erste Takt); gb-schlaf prüft die Stille.
        self.letztes = None

    def erfasst(self, now):
        self.letztes = now

    def eigene(self, now):
        return list(self.wan.aktuell(now) or []) if self.wan is not None else []

    def eintragen(self, ip, now):
        ip = str(ipaddress.IPv4Address(ip))
        if ip in self.eigene(now):
            return
        if ip not in self.quellen:
            self.neu = True
        self.quellen[ip] = now
        self.quellen.move_to_end(ip)
        while len(self.quellen) > self.maximum:
            self.quellen.popitem(last=False)

    def takt(self, now):
        """Je Schleifendurchlauf: Auflösung anstoßen (nie blockierend), verfallen lassen, bei Bedarf schreiben."""
        if self.wan is not None:
            self.wan.anstossen(now)
        eigene = self.eigene(now)
        if self.letztes is None:
            self.letztes = now
        if eigene != self.eigene_zuletzt:
            # Vor der ersten Auflösung eingetragene Haarnadel-Quellen fliegen jetzt heraus.
            self.eigene_zuletzt, self.neu = eigene, True
            for ip in eigene:
                self.quellen.pop(ip, None)
        # Der Takt läuft bei jedem Paketschub: nur vorne (zuletzt gesehen am längsten her) verfallen lassen.
        while self.quellen:
            ip, zuletzt = next(iter(self.quellen.items()))
            if not now - zuletzt > self.ttl:
                break
            del self.quellen[ip]
            self.neu = True
        # Neues sofort (höchstens 1/s, auch nach einem Schreibfehler), sonst als Herzschlag.
        if self.versuch is not None and 0 <= now - self.versuch < (1 if self.neu else HERZSCHLAG_S):
            return False
        self.versuch = now
        data = {"version": VERSION, "zeit": now, "ttl_s": self.ttl,
                # Nach einem Uhrsprung zurück nie später als die Schreibzeit (gb-schlaf prüft das).
                "quellen": {ip: min(zuletzt, now) for ip, zuletzt in self.quellen.items()},
                "letztes_paket": min(self.letztes, now)}
        if eigene:
            data["eigene_wan_ip"] = eigene[:MAX_EIGENE]
        try:
            atomar(self.path, data)
        except (OSError, ValueError):
            if not self.fehler and self.logger is not None:
                self.logger.emit({"ereignis": "legitim_schreibfehler"}, now)
            self.fehler = True
            return False
        self.neu, self.fehler = False, False
        return True


class Filter:
    """Entscheidet je WAN-Gegenstelle: None = zählt, sonst der Grund, warum sie nicht zählt."""

    def __init__(self, data, now, lan=("192.168.1.0/24",), vpn=("10.0.0.0/24",), erlaubt=None):
        ttl = data["ttl_s"]
        # Auch gb-schlaf prüft die TTL: ein Eintrag verfällt, selbst wenn der Mitschnitt ihn noch führt.
        self.legitim = {ip for ip, zuletzt in data["quellen"].items() if now - zuletzt <= ttl}
        self.eigene = set(data.get("eigene_wan_ip", []))
        self.lan, self.vpn = list(lan), list(vpn)
        self.erlaubt = {int(port): {str(ipaddress.IPv4Address(ip)) for ip in ips}
                        for port, ips in (erlaubt or {}).items()}

    def wan(self, address):
        """Öffentliche IPv4 außerhalb von LAN/VPN; IPv6 sieht der Mitschnitt nie (BPF nur IPv4)."""
        if address.version != 4 or quelle(str(address), self.lan, self.vpn) != "WAN":
            return False
        return not any(address in net for net in NICHT_OEFFENTLICH)

    def grund(self, port, address):
        if not self.wan(address):
            return None
        ip = str(address)
        if ip in self.eigene:
            # Haarnadel: die eigene öffentliche Adresse ist der Host selbst.
            return "haarnadel"
        if ip in self.legitim or ip in self.erlaubt.get(port, ()):
            return None
        return "wan"


def filter_laden(cfg, now, uids=None):
    """(Diagnose, Filter oder None). None heißt beta.5-Verhalten: jede Verbindung zählt.

    Nie unklar: das würde Schlaf ganz sperren; die bekannte Rückfallebene ist beta.5.
    """
    if cfg.get("wan_filter", True) is not True:
        return "aus", None
    try:
        data = lesen(cfg.get("legitim", LEGITIM), besitzer() if uids is None else uids)
    except FileNotFoundError:
        return "fehlt", None
    except Exception:
        # Symlink (ELOOP), Verzeichnis, Rechte, Besitzer, JSON, Schema, Größe.
        return "ungueltig", None
    alter = now - data["zeit"]
    if alter > cfg.get("legitim_max_alter_s", 180):
        return "veraltet", None
    if alter < -ZUKUNFT_S:
        return "zukunft", None
    if now - data["letztes_paket"] > cfg.get("legitim_stille_s", 900):
        # Review 13.10.26: Eine frische Datei beweist nur, dass die Schleife läuft. Live kommen ~40
        # Scanner-Flüsse je Minute; erfasst der Mitschnitt nichts (etwa ein falsches target), wird nie
        # etwas legitim, und der Filter ließe jede WAN-Verbindung fallen.
        return "still", None
    return "ok", Filter(data, now, cfg.get("lan", ["192.168.1.0/24"]), cfg.get("vpn", ["10.0.0.0/24"]),
                        cfg.get("legitim_quellen", {}))
