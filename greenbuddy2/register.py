"""Hostgebundenes Register mit Dateisperre, atomarem Austausch und fsync."""

import contextlib
import fcntl
import json
import math
import os
import re
import tempfile
import time
from pathlib import Path

HOSTS = ("vhost01", "nas01")
REGISTER = "/var/lib/greenbuddy/register.json"
STATUS = "/run/greenbuddy/status/stellvertreter.json"
ZYKLUS = r"[A-Za-z0-9_-]{1,128}"
# Plan R5: zwischen 10 min und 12 h bis zum RTC-Wecker; der Lease läuft 15 min länger.
SCHLAF_MIN, SCHLAF_MAX, NACHLAUF = 600, 43200, 900
STATUS_ALTER = 15
WECKUNG_FELDER = ("zeit", "weg", "port", "quellklasse", "entscheidung")


def atomar(path, data, modus=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        if modus is not None:
            os.fchmod(fd, modus)
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            json.dump(data, target, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, str(path))
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def sperre(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as target:
        fcntl.flock(target, fcntl.LOCK_EX)
        yield


def boot_jetzt():
    return (Path("/proc/sys/kernel/random/boot_id").read_text().strip(), time.clock_gettime(time.CLOCK_BOOTTIME))


def _zahl(value):
    return type(value) in (int, float) and math.isfinite(value)


def status_lesen(path):
    """Statusbericht des Stellvertreters; jede Abweichung vom Schema ist ValueError."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError("status_gross")
    data = json.loads(raw)
    if (not isinstance(data, dict) or data.get("version") != 1 or not _zahl(data.get("zeit"))
            or not isinstance(data.get("bereit_fuer"), list)
            or any(not isinstance(host, str) for host in data["bereit_fuer"])
            or not isinstance(data.get("phasen"), dict)
            or not isinstance(data.get("gruende", {}), dict) or not isinstance(data.get("weckung", {}), dict)):
        raise ValueError("status_schema")
    return data


class Register:
    def __init__(self, path=REGISTER, lease_seconds=900, status=STATUS, boot=boot_jetzt):
        if not 1 <= lease_seconds <= 12 * 3600:
            raise ValueError("lease_ungueltig")
        self.path, self.lease_seconds = Path(path), lease_seconds
        self.status, self.boot = Path(status), boot

    def lesen(self):
        if not self.path.exists():
            return {"version": 1, "hosts": {}}
        if self.path.is_symlink():
            raise ValueError("register_symlink")
        data = json.loads(self.path.read_text())
        if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("hosts"), dict):
            raise ValueError("register_schema")
        for host, row in data["hosts"].items():
            if (host not in HOSTS or not isinstance(row, dict)
                    or not isinstance(row.get("zyklus"), str)
                    or not re.fullmatch(ZYKLUS, row["zyklus"])
                    or row.get("phase") not in ("angemeldet", "abgemeldet", "schlaf_absicht", "lease_abgelaufen")
                    or not _zahl(row.get("ablauf"))
                    or type(row.get("nachfrage")) is not int or row["nachfrage"] < 0):
                raise ValueError("register_schema")
            # Felder ab b5 sind optional: ältere Register bleiben lesbar.
            if ("beginn" in row and not _zahl(row["beginn"])) or (
                    "ablauf_boot" in row and not _zahl(row["ablauf_boot"])) or (
                    "boot_id" in row and (not isinstance(row["boot_id"], str)
                                          or not re.fullmatch(r"[0-9a-f-]{1,64}", row["boot_id"]))) or (
                    "schlaf_s" in row and (type(row["schlaf_s"]) is not int
                                           or not SCHLAF_MIN <= row["schlaf_s"] <= SCHLAF_MAX)):
                raise ValueError("register_schema")
        return data

    def stellvertreter(self, host, now):
        """(bereit, grund, kurzbericht, bericht) aus dem Statusbericht; Plan R1: höchstens 15 s alt."""
        try:
            data = status_lesen(self.status)
        except (OSError, ValueError, TypeError):
            return False, "stellvertreter_status_fehlt", None, None
        alter = now - data["zeit"]
        kurz = {"phase": data["phasen"].get(host), "alter_s": round(alter, 1),
                "grund": data.get("gruende", {}).get(host)}
        # Etwas Zukunft (Schreibzeitpunkt vs. Lesezeitpunkt) ist erlaubt, mehr ist eine kaputte Uhr.
        if not -5 <= alter <= STATUS_ALTER:
            return False, "stellvertreter_status_alt", kurz, data
        if host not in data["bereit_fuer"]:
            return False, "stellvertreter_nicht_bereit", kurz, data
        return True, None, kurz, data

    def befehl(self, host, command, cycle, now, sekunden=None, aus=False):
        if host not in HOSTS:
            raise ValueError("host_unbekannt")
        if command not in ("status", "abmelden", "schlafe-jetzt", "anmelden", "anmelden-abbruch"):
            raise ValueError("befehl_unbekannt")
        if command != "status" and (not isinstance(cycle, str) or not re.fullmatch(ZYKLUS, cycle)):
            raise ValueError("zyklus_ungueltig")
        if command == "schlafe-jetzt" and (type(sekunden) is not int or not SCHLAF_MIN <= sekunden <= SCHLAF_MAX):
            raise ValueError("sekunden_ungueltig")
        bereit, grund, kurz, bericht = self.stellvertreter(host, now)
        if aus:
            bereit, grund = False, "abgeschaltet"
        with sperre(str(self.path) + ".lock"):
            data = self.lesen()
            row = data["hosts"].get(host)
            dirty = False
            if row and row["phase"] in ("abgemeldet", "schlaf_absicht") and row["ablauf"] <= now:
                row["phase"] = "lease_abgelaufen"
                dirty = True
            if aus and command in ("abmelden", "schlafe-jetzt"):
                # Abschalter: keine neue Schlafabsicht eintragen; Anmelden darf weiter (beendet nur Übernahmen).
                pass
            elif command == "abmelden":
                if row and row["zyklus"] == cycle:
                    if row["phase"] in ("angemeldet", "lease_abgelaufen"):
                        raise ValueError("zyklus_beendet")
                else:
                    # Ein neuer Zyklus ersetzt jeden alten; der Stellvertreter gibt dann frei (Plan 5.5).
                    row = {"zyklus": cycle, "phase": "abgemeldet", "ablauf": now + self.lease_seconds,
                           "nachfrage": 0, "beginn": now}
                    data["hosts"][host] = row
                    dirty = True
            elif command != "status":
                if not row or row["zyklus"] != cycle:
                    raise ValueError("zyklus_passt_nicht")
                if command == "schlafe-jetzt":
                    if row["phase"] not in ("abgemeldet", "schlaf_absicht"):
                        raise ValueError("lease_abgelaufen")
                    if row["phase"] == "abgemeldet" and bereit:
                        boot_id, boottime = self.boot()
                        row.update(phase="schlaf_absicht", schlaf_s=sekunden,
                                   ablauf=now + sekunden + NACHLAUF, ablauf_boot=boottime + sekunden + NACHLAUF,
                                   boot_id=boot_id)
                        dirty = True
                else:
                    row["phase"] = "angemeldet"
                    dirty = True
            if dirty:
                atomar(self.path, data, modus=0o640)
            result = {"host": host, "bereit": bereit, "grund": grund,
                      "zustand": dict(row) if row else {"phase": "unbekannt"}, "stellvertreter": kurz}
            if aus:
                result["entscheidung"] = "abgeschaltet"
            if command in ("anmelden", "anmelden-abbruch"):
                result["weckung"] = self.weckung(host, row, bericht)
            return result

    @staticmethod
    def weckung(host, row, bericht):
        """Plan R8: letzte Weckung des Hosts, nur wenn sie nach dem Beginn dieses Zyklus lag; keine IP."""
        if not bericht or not row or not _zahl(row.get("beginn")):
            return None
        value = bericht.get("weckung", {}).get(host)
        if not isinstance(value, dict) or not _zahl(value.get("zeit")) or value["zeit"] <= row["beginn"]:
            return None
        return {key: value.get(key) for key in WECKUNG_FELDER}
