"""Konfiguration ohne Geheimnisse im Repository."""

import ipaddress
import json
import math
import os
import re
import stat
from pathlib import Path

AUS = "/etc/greenbuddy/aus"
# b6: gb-mitschnitt schreibt die legitimen WAN-Quellen, gb-schlaf liest sie (eigenes Unterverzeichnis).
LEGITIM = "/run/greenbuddy/legitim/vhost01.json"
PREF = "/home/plex/database/Library/Application Support/Plex Media Server/Preferences.xml"
SCHLAF = {
    "mode": "schatten", "dependencies_verified": False, "raid_degradiert_erlaubt": False,
    "idle_seconds": 2700, "poll_seconds": 60,
    "plex_preferences": PREF, "jellyfin_key_file": "/etc/greenbuddy/jellyfin.key",
    "minecraft_argument": ".jar", "coach_log": "/var/log/caddy/bot-access.jsonl",
    "coach_recent_seconds": 2700, "ansprueche": "/run/greenbuddy/ansprueche",
    "media_conf": "/etc/media-staging.conf", "self_triples": [], "bandbreite_schwelle_bytes": 262144,
    "zustand": "/var/lib/greenbuddy/schlaf-zustand.json", "wol_interface": "",
    "system_jobs": ["media-staging.service", "backup-taeglich.service", "offsite-backup.service",
                    "smb.service"],
    "user_jobs": [["automation", "medien-nachladen.service"], ["automation", "medien-nachsuche.service"]],
    "optional_jobs": [],
    # lazymc hält Scanner-Verbindungen auch ohne Spieler; alle anderen Ports mit Gegenstelle sind Veto.
    "verbindung_ausnahmen": [25565],
    # Offene Plex-Apps ohne Anfrage seit 15 min halten nicht wach (Betreiber 12.10.26), solange der Server
    # auf der Verbindung je Runde höchstens verbindung_ruhe_bytes überträgt (sonst: Download).
    "verbindung_ruhe_ports": [32400], "verbindung_ruhe_sekunden": 900, "verbindung_ruhe_bytes": 65536,
    "transient_benutzer": ["automation", "jellyfin", "mediauser"],
    "takt_stempel": "/run/greenbuddy/schlaf-takt.json",
    "log": "/var/log/greenbuddy/schlaf.jsonl", "aus": AUS,
    # b6: WAN-Gegenstellen zählen nur, wenn der Mitschnitt sie für legitim hält (oder sie für den Port in
    # legitim_quellen stehen); false = beta.5-Verhalten. LAN/VPN wie klassifikation.quelle.
    "wan_filter": True, "legitim": LEGITIM, "legitim_max_alter_s": 180, "legitim_quellen": {},
    # Erfasst der Mitschnitt so lange kein Paket, filtert gb-schlaf nicht (Review 13.10.26).
    "legitim_stille_s": 900,
    "lan": ["192.168.1.0/24"], "vpn": ["10.0.0.0/24"],
}
# b6: Schreibseite im Mitschnitt; wan_name leer = keine Haarnadel-Ausnahme.
MITSCHNITT = {"legitim": LEGITIM, "legitim_ttl_s": 3600, "legitim_max": 4096, "wan_name": ""}


def laden(path, defaults=None):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("konfig_ungueltig")
    result = dict(defaults or {})
    result.update(data)
    validieren(result)
    if "dependencies_verified" in result:
        # Die Freigabe wirkt nur zusammen mit "mode": "aktiv"; sonst bleibt alles Schatten.
        result["dependencies_verified"] = result.get("mode") == "aktiv" and result["dependencies_verified"] is True
    return result


def validieren(result):
    """Formfehler erkennen, bevor eine Abfrage außerhalb ihrer Fehlerhülle läuft."""
    for name in ("idle_seconds", "poll_seconds", "coach_recent_seconds", "verbindung_ruhe_sekunden",
                 "legitim_max_alter_s", "legitim_ttl_s", "legitim_stille_s"):
        if name in result and (type(result[name]) not in (int, float)
                               or not math.isfinite(result[name]) or result[name] <= 0):
            raise ValueError("konfig_ungueltig")
    if "minecraft_argument" in result and not result["minecraft_argument"]:
        raise ValueError("konfig_ungueltig")
    for name in ("system_jobs", "optional_jobs"):
        if name in result and (not isinstance(result[name], list)
                               or any(not isinstance(x, str) or not x for x in result[name])):
            raise ValueError("konfig_ungueltig")
    if "user_jobs" in result and (not isinstance(result["user_jobs"], list) or any(
            not isinstance(x, list) or len(x) != 2 or any(not isinstance(v, str) or not v for v in x)
            for x in result["user_jobs"])):
        raise ValueError("konfig_ungueltig")
    for name in ("verbindung_ausnahmen", "verbindung_ruhe_ports"):
        if name in result and (not isinstance(result[name], list) or any(
                type(x) is not int or not 1 <= x <= 65535 for x in result[name])):
            raise ValueError("konfig_ungueltig")
    if "transient_benutzer" in result and (not isinstance(result["transient_benutzer"], list) or any(
            not isinstance(x, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}", x)
            for x in result["transient_benutzer"])):
        raise ValueError("konfig_ungueltig")
    for name in ("log", "aus", "media_conf", "ansprueche", "plex_preferences", "jellyfin_key_file", "zustand",
                 "takt_stempel", "legitim"):
        if name in result and (not isinstance(result[name], str) or not result[name]):
            raise ValueError("konfig_ungueltig")
    if "mode" in result and result["mode"] not in ("schatten", "aktiv"):
        raise ValueError("konfig_ungueltig")
    for name in ("dependencies_verified", "raid_degradiert_erlaubt", "wan_filter"):
        if name in result and type(result[name]) is not bool:
            raise ValueError("konfig_ungueltig")
    if "verbindung_ruhe_bytes" in result and (type(result["verbindung_ruhe_bytes"]) is not int
                                              or result["verbindung_ruhe_bytes"] < 0):
        raise ValueError("konfig_ungueltig")
    if "bandbreite_schwelle_bytes" in result and (type(result["bandbreite_schwelle_bytes"]) is not int
                                                  or result["bandbreite_schwelle_bytes"] <= 0):
        raise ValueError("konfig_ungueltig")
    if "self_triples" in result and (not isinstance(result["self_triples"], list) or any(
            not isinstance(x, list) or len(x) != 3 or type(x[0]) is not int or type(x[1]) is not int
            or type(x[2]) is not bool for x in result["self_triples"])):
        raise ValueError("konfig_ungueltig")
    if "wol_interface" in result and (not isinstance(result["wol_interface"], str) or (
            result["wol_interface"] and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", result["wol_interface"]))):
        raise ValueError("konfig_ungueltig")
    if "legitim_max" in result and (type(result["legitim_max"]) is not int or result["legitim_max"] < 1):
        raise ValueError("konfig_ungueltig")
    for name in ("lan", "vpn"):
        if name in result:
            netze_pruefen(result[name])
    if "legitim_quellen" in result:
        quellen_pruefen(result["legitim_quellen"])
    if "wan_name" in result and (not isinstance(result["wan_name"], str) or (
            result["wan_name"] and not re.fullmatch(HOSTNAME, result["wan_name"]))):
        raise ValueError("konfig_ungueltig")


def netze_pruefen(value):
    if not isinstance(value, list) or any(not isinstance(net, str) for net in value):
        raise ValueError("konfig_ungueltig")
    try:
        for net in value:
            ipaddress.IPv4Network(net)
    except ValueError:
        raise ValueError("konfig_ungueltig") from None


def quellen_pruefen(value):
    """{"<port>": ["<ipv4>", ...]} wie quellen_ports auf proxy01; jede Liste nicht leer."""
    if not isinstance(value, dict):
        raise ValueError("konfig_ungueltig")
    for key, sources in value.items():
        if (not re.fullmatch(r"[1-9][0-9]{0,4}", key) or int(key) > 65535 or not isinstance(sources, list)
                or not sources or any(not isinstance(source, str) for source in sources)):
            raise ValueError("konfig_ungueltig")
        try:
            for source in sources:
                ipaddress.IPv4Address(source)
        except ValueError:
            raise ValueError("konfig_ungueltig") from None


def abgeschaltet(cfg=None):
    return os.path.lexists((cfg or {}).get("aus", AUS))


# Gateway, proxy01 selbst und nas01 (Plan R11) werden nie übernommen; listen_ip kommt zur Laufzeit dazu.
GESPERRT = frozenset(("192.168.1.1", "192.168.1.100", "192.168.1.115"))
STELLVERTRETBAR = ("vhost01",)
SV_PFLICHT = ("hosts", "wan_name", "register", "status", "zustand", "limits", "wol_wiederholen_s", "wol_max_s",
              "stille_s", "stille_max_s", "garp_s", "lebendprobe_s")
SV_LIMITS = ("wan_quelle_h", "wan_host_h", "wan_host_tag", "lan_quelle_h", "vpn_quelle_h", "liste_h")
SV_ZEITEN = {"wol_wiederholen_s": (1, 60), "wol_max_s": (1, 900), "stille_s": (1, 60),
             "stille_max_s": (10, 3600), "garp_s": (5, 3600), "lebendprobe_s": (1, 60)}
HOST_FELDER = ("ip", "mac", "syn_ports", "inhalt_ports", "quellen_ports", "ausgenommen")
INTERFACE = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}"
HOSTNAME = r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"


def stellvertretung(cfg):
    """Strikte Prüfung des Schlüssels "stellvertretung"; jeder Formfehler sperrt nur die Übernahme."""
    def fehler(was):
        return ValueError("stellvertretung_" + was)

    def ipv4(value, was):
        if not isinstance(value, str):
            raise fehler(was)
        try:
            return str(ipaddress.IPv4Address(value))
        except ValueError:
            raise fehler(was)

    def netze(value, was, leer=False):
        if not isinstance(value, list) or (not value and not leer) or any(not isinstance(n, str) for n in value):
            raise fehler(was)
        try:
            return [str(ipaddress.IPv4Network(net)) for net in value]
        except ValueError:
            raise fehler(was)

    def ports(value):
        if not isinstance(value, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in value) \
                or len(set(value)) != len(value):
            raise fehler("ports")
        return list(value)

    def zahl(value, lower, upper, was):
        if type(value) not in (int, float) or not math.isfinite(value) or not lower <= value <= upper:
            raise fehler(was)
        return value

    sv = cfg.get("stellvertretung")
    if sv is None:
        raise fehler("fehlt")
    if not isinstance(sv, dict):
        raise fehler("form")
    if not set(sv) <= set(SV_PFLICHT) | {"probe", "vpn_interface"}:
        raise fehler("schluessel")
    if any(name not in sv for name in SV_PFLICHT):
        raise fehler("schluessel")
    if not isinstance(cfg.get("interface"), str) or not re.fullmatch(INTERFACE, cfg["interface"]):
        raise fehler("interface")
    lan = netze(cfg.get("lan", ["192.168.1.0/24"]), "netze")
    vpn = netze(cfg.get("vpn", ["10.0.0.0/24"]), "netze", leer=True)
    listen_ip = ipv4(cfg.get("listen_ip"), "listen_ip")
    lan_netze = [ipaddress.IPv4Network(net) for net in lan]
    if not any(ipaddress.IPv4Address(listen_ip) in net for net in lan_netze):
        raise fehler("listen_ip")
    gesperrt = GESPERRT | {listen_ip}

    def host_pruefen(row, was):
        if not isinstance(row, dict) or set(row) != set(HOST_FELDER):
            raise fehler(was)
        ip = ipv4(row["ip"], "ip")
        address = ipaddress.IPv4Address(ip)
        netz = next((net for net in lan_netze if address in net), None)
        if netz is None or address in (netz.network_address, netz.broadcast_address):
            raise fehler("ip")
        if ip in gesperrt:
            raise fehler("ip_gesperrt")
        mac = row["mac"]
        if not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac) \
                or int(mac[:2], 16) & 1 or mac.replace(":", "").strip("0") == "":
            raise fehler("mac")
        syn, inhalt = ports(row["syn_ports"]), ports(row["inhalt_ports"])
        quellen = {}
        if not isinstance(row["quellen_ports"], dict):
            raise fehler("quellen_ports")
        for key, sources in row["quellen_ports"].items():
            if not re.fullmatch(r"[1-9][0-9]{0,4}", key) or int(key) > 65535 or int(key) in syn + inhalt:
                raise fehler("quellen_ports")
            if not isinstance(sources, list) or not sources:
                raise fehler("quellen_ports")
            quellen[int(key)] = [ipv4(source, "quellen_ports") for source in sources]
        if not isinstance(row["ausgenommen"], list):
            raise fehler("ausgenommen")
        exempt = [ipv4(source, "ausgenommen") for source in row["ausgenommen"]]
        return {"ip": ip, "mac": mac.lower(), "syn_ports": syn, "inhalt_ports": inhalt,
                "quellen_ports": quellen, "ausgenommen": exempt}

    if not isinstance(sv["hosts"], dict):
        raise fehler("hosts")
    hosts = {}
    for name, row in sv["hosts"].items():
        # Plan R11: nas01 bekommt keine Übernahme; "probe" ist dem Live-Test vorbehalten.
        if name not in STELLVERTRETBAR:
            raise fehler("host")
        hosts[name] = host_pruefen(row, "host")
    if len({row["ip"] for row in hosts.values()}) != len(hosts):
        raise fehler("ip")
    probe = None
    if "probe" in sv:
        probe = host_pruefen(sv["probe"], "probe")
        if probe["ip"] in {row["ip"] for row in hosts.values()}:
            raise fehler("probe")
    if not isinstance(sv["wan_name"], str) or (sv["wan_name"] and not re.fullmatch(HOSTNAME, sv["wan_name"])):
        raise fehler("wan_name")
    paths = []
    for name in ("register", "status", "zustand"):
        value = sv[name]
        if not isinstance(value, str) or not value.startswith("/") or "\0" in value or value.endswith("/"):
            raise fehler("pfad")
        paths.append(value)
    if len(set(paths)) != len(paths):
        raise fehler("pfad")
    limits = sv["limits"]
    if not isinstance(limits, dict) or set(limits) != set(SV_LIMITS) or any(
            type(value) is not int or not 0 <= value <= 1000 for value in limits.values()):
        raise fehler("limits")
    zeiten = {name: zahl(sv[name], lower, upper, "zeiten") for name, (lower, upper) in SV_ZEITEN.items()}
    if zeiten["wol_max_s"] < zeiten["wol_wiederholen_s"] or zeiten["stille_max_s"] < zeiten["stille_s"]:
        raise fehler("zeiten")
    vpn_interface = sv.get("vpn_interface", "")
    if not isinstance(vpn_interface, str) or (vpn_interface and (
            not re.fullmatch(INTERFACE, vpn_interface) or vpn_interface == cfg["interface"])):
        raise fehler("vpn_interface")
    result = {"interface": cfg["interface"], "listen_ip": listen_ip, "lan": lan, "vpn": vpn, "hosts": hosts,
              "probe": probe, "wan_name": sv["wan_name"], "register": paths[0], "status": paths[1],
              "zustand": paths[2], "limits": dict(limits), "vpn_interface": vpn_interface}
    result.update(zeiten)
    return result


def geheimnis(path):
    """Keine Symlinks; nur eine private reguläre Datei akzeptieren."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("schluessel_rechte")
        with os.fdopen(fd, "r", encoding="utf-8") as source:
            fd = -1
            value = source.read(4097).strip()
        if not value or len(value) > 4096 or "\n" in value or "\r" in value:
            raise ValueError("schluessel_format")
        return value
    finally:
        if fd >= 0:
            os.close(fd)
