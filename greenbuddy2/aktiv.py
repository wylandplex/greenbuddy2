"""Aktiver Schlaf auf vhost01: Zustand, Schlafgrenzen, RTC-Wecker und Suspend.

Jede Prüfung hier ist eine Sperre: Fehler, fehlende Tatsachen und Parserfehler
verhindern den Schlaf. Befehle laufen ausschließlich über einen injizierbaren Runner.
"""

import datetime as dt
import json
import math
import os
import re
import time
from pathlib import Path

from . import register_client
from .fakten_vhost import command
from .fenster import contains, next_wake
from .register import atomar

MIN_RUHE_S = 2700            # 45 min ohne Nutzungssignal, auch wenn idle_seconds kleiner ist
MIN_BIS_FENSTERENDE_S = 1200  # mindestens 20 min bis zum Ende der Schlafphase
MINDESTWACH_S = 600          # 10 min nach Start/Resume
RTC_MIN_S, RTC_MAX_S = 600, 12 * 3600
MAX_ZYKLEN, ZYKLUS_FENSTER_S, SPERRE_S = 6, 86400, 86400
WAKEALARM = "/sys/class/rtc/rtc0/wakealarm"
WAKEUP = "/sys/class/net/%s/device/power/wakeup"
# "rtcwake -m no" liest dieses Flag nicht; ohne "enabled" maskiert rtc_cmos den Alarm beim Suspend.
RTC_WAKEUP = "/sys/class/rtc/rtc0/device/power/wakeup"
# Gen-0-Schläfer: delay-after-suspend startet auto-sleep.timer nach jedem Resume neu
# (auch deaktiviert); nur Maskieren oder Entfernen verhindert das.
FREMDE_SCHLAEFER = ("auto-sleep.timer", "auto-sleep.service", "delay-after-suspend.service")
NUR_MASKIERT = ("delay-after-suspend.service",)
BOOT_ID = "/proc/sys/kernel/random/boot_id"
LOGIN1 = ["busctl", "--system", "--json=short", "call", "org.freedesktop.login1",
          "/org/freedesktop/login1", "org.freedesktop.login1.Manager"]


def boot_id(path=BOOT_ID):
    value = Path(path).read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value):
        raise ValueError("boot_id_unklar")
    return value


def lokal(date, minutes):
    # mktime nutzt die Host-Zeitzone samt Sommerzeit, ohne zoneinfo-Pflicht.
    return time.mktime(dt.datetime.combine(date, dt.time(minutes // 60, minutes % 60)).timetuple())


def fenster_ende(pairs, lead, epoch):
    """Ende der laufenden Schlafphase: TAGSCHLAF-Ende oder ein früher beginnendes Wachfenster."""
    start, end = pairs["TAGSCHLAF"]
    now = dt.datetime.fromtimestamp(epoch)
    if not contains(now.hour * 60 + now.minute, start, end):
        raise ValueError("ausserhalb_tagschlaf")
    ende = next((point for point in (lokal(now.date() + dt.timedelta(days=d), end) for d in (0, 1))
                 if point > epoch), None)
    if ende is None:
        raise ValueError("fensterende_unklar")
    return min(ende, next_wake(pairs, lead, epoch) + lead * 60)


def weckzeit(ende, lead, epoch):
    """RTC-Termin = Ende minus Vorlauf, frühestens in 10 min, spätestens in 12 h."""
    wake = int(ende - lead * 60)
    if not RTC_MIN_S <= wake - epoch <= RTC_MAX_S:
        raise ValueError("weckzeit_ungueltig")
    return wake


def endlich(value):
    return type(value) in (int, float) and math.isfinite(value)


class Zustand:
    """Persistenter Schlafzustand: letzte Unruhe, Zyklen, Sperre und laufender Schlaf.

    Ein Schlaf mit Register bei proxy01 trägt zusätzlich "zyklus"; Dateien ohne bleiben gültig (b4).
    """

    SCHLAF_FELDER = ("beginn_wall", "beginn_boot", "summe_vor", "weckzeit")

    def __init__(self, path, boot):
        self.path, self.boot = Path(path), boot

    def leer(self):
        return {"version": 1, "boot_id": self.boot, "ruhe_seit": None, "zyklen": [],
                "sperre_bis": None, "schlaf": None}

    def laden(self):
        try:
            fd = os.open(str(self.path), os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return self.leer()
        with os.fdopen(fd, "r", encoding="utf-8") as source:
            data = json.loads(source.read(65536))
        self.pruefen(data)
        return data

    def pruefen(self, data):
        if (not isinstance(data, dict) or data.get("version") != 1
                or set(data) != {"version", "boot_id", "ruhe_seit", "zyklen", "sperre_bis", "schlaf"}
                or not (data["boot_id"] is None or isinstance(data["boot_id"], str))
                or not (data["ruhe_seit"] is None or endlich(data["ruhe_seit"]))
                or not isinstance(data["zyklen"], list) or not all(endlich(x) for x in data["zyklen"])
                or not (data["sperre_bis"] is None or endlich(data["sperre_bis"]))):
            raise ValueError("zustand_schema")
        schlaf = data["schlaf"]
        if schlaf is not None and (not isinstance(schlaf, dict)
                                   or set(schlaf) - {"zyklus"} != set(self.SCHLAF_FELDER) | {"boot_id"}
                                   or not isinstance(schlaf["boot_id"], str)
                                   or not all(endlich(schlaf[k]) for k in self.SCHLAF_FELDER)
                                   or ("zyklus" in schlaf and not (
                                       isinstance(schlaf["zyklus"], str)
                                       and re.fullmatch(register_client.ZYKLUS, schlaf["zyklus"])))):
            raise ValueError("zustand_schema")

    def speichern(self, data):
        self.pruefen(data)
        atomar(self.path, data)


def stempel_lesen(path):
    """Beobachtungsstempel aus dem tmpfs: bis zu welcher BOOTTIME ruhe_seit lückenlos beobachtet ist."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        data = json.loads(source.read(4096))
    if (not isinstance(data, dict) or set(data) != {"boot_id", "takt", "ruhe_seit"}
            or not isinstance(data["boot_id"], str) or not endlich(data["takt"])
            or not (data["ruhe_seit"] is None or endlich(data["ruhe_seit"]))):
        raise ValueError("stempel_schema")
    return data


def stempel_schreiben(path, boot, takt, ruhe_seit):
    atomar(path, {"boot_id": boot, "takt": takt, "ruhe_seit": ruhe_seit})


def zyklen_pruefen(data, wall):
    """Mehr als sechs Schlafzyklen in 24 h sind ausgeschlossen: dann 24 h Sperre."""
    if any(x > wall + 60 for x in data["zyklen"]) or (
            data["sperre_bis"] is not None and data["sperre_bis"] > wall + SPERRE_S + 60):
        raise ValueError("zustand_zeit")
    data["zyklen"] = [x for x in data["zyklen"] if x > wall - ZYKLUS_FENSTER_S]
    if data["sperre_bis"] is not None:
        if data["sperre_bis"] > wall:
            return ["schlafsperre"], None
        data["sperre_bis"] = None
    if len(data["zyklen"]) >= MAX_ZYKLEN:
        data["sperre_bis"] = wall + SPERRE_S
        return ["schlafsperre"], {"ereignis": "schlafsperre_24h", "zyklen_24h": len(data["zyklen"]),
                                  "sperre_bis": data["sperre_bis"]}
    return [], None


def aufwachen_pruefen(data, boot, boot_s, mono, wall):
    """Nach eigenem Suspend: Schlafdauer aus dem Zuwachs von BOOTTIME gegenüber MONOTONIC.

    Das Ereignis trägt den Zyklus des beendeten Schlafs, damit der Wächter sich bei proxy01 anmeldet.
    """
    schlaf = data["schlaf"]
    if schlaf is None:
        return None
    if schlaf["boot_id"] != boot:
        row = {"ereignis": "aufgewacht", "neustart": True}
    else:
        dauer = (boot_s - mono) - schlaf["summe_vor"]
        if dauer > 2:
            row = {"ereignis": "aufgewacht", "schlafdauer_s": round(dauer),
                   "geweckt_durch": "rtc" if wall >= schlaf["weckzeit"] - 60 else "anderes"}
        elif boot_s - schlaf["beginn_boot"] > 300:
            row = {"ereignis": "suspend_ohne_wirkung"}
        else:
            return None
    if "zyklus" in schlaf:
        row["zyklus"] = schlaf["zyklus"]
    data["schlaf"] = None
    return row


def lesen(path):
    with open(path, encoding="ascii") as source:
        return source.read(64)


class Ausfuehrung:
    """RTC, Vorbedingungen, Register (proxy01) und Suspend; nur über den Runner, damit Tests nichts auslösen."""

    def __init__(self, runner=command, reader=lesen, register=None):
        self.runner, self.reader = runner, reader
        self.register = register_client.Register(None, runner) if register is None else register

    def rtc_setzen(self, wake):
        result = self.runner(["rtcwake", "-m", "no", "-t", str(int(wake))])
        if result.returncode:
            raise ValueError("rtcwake_fehler")
        # Tatsache statt Exit-Code: der Kernel muss den Alarm tatsächlich zurückmelden.
        text = self.reader(WAKEALARM).strip()
        if not re.fullmatch(r"[0-9]{1,12}", text):
            self.rtc_loeschen()
            raise ValueError("rtc_nicht_gesetzt")
        value = int(text)
        offset = dt.datetime.fromtimestamp(wake).astimezone().utcoffset().total_seconds()
        # Läuft die RTC in Lokalzeit (/etc/adjtime LOCAL), meldet sysfs den Wert verschoben.
        if min(abs(value - wake), abs(value - (wake + offset))) > 2:
            self.rtc_loeschen()
            raise ValueError("rtc_nicht_gesetzt")

    def rtc_loeschen(self):
        try:
            self.runner(["rtcwake", "-m", "disable"])
        except Exception:
            pass

    def login1(self, method):
        result = self.runner(LOGIN1 + [method])
        if result.returncode:
            raise ValueError("login1_fehler")
        data = json.loads(result.stdout)
        if not isinstance(data, dict) or not isinstance(data.get("data"), list) or len(data["data"]) != 1:
            raise ValueError("login1_schema")
        return data["data"][0]

    def vorbedingungen(self, cfg):
        """Suspend-spezifische Tatsachen; jede Abweichung ist ein Abbruchgrund."""
        reasons = []
        try:
            if self.login1("CanSuspend") != "yes":
                reasons.append("suspend_nicht_erlaubt")
        except Exception:
            reasons.append("suspend_erlaubnis_unklar")
        try:
            # root übergeht block-Inhibitoren; darum hier selbst als Sperre werten.
            rows = self.login1("ListInhibitors")
            if not isinstance(rows, list) or any(
                    not isinstance(r, list) or len(r) != 6 or not all(isinstance(x, str) for x in r[:4])
                    for r in rows):
                raise ValueError("inhibitor_schema")
            if any(r[3] == "block" and "sleep" in r[0].split(":") for r in rows):
                reasons.append("inhibitor_block")
        except Exception:
            reasons.append("inhibitor_unklar")
        nic = cfg.get("wol_interface", "")
        if not nic:
            reasons.append("wol_interface_fehlt")
        else:
            # ethtool bräuchte für "Wake-on" CAP_NET_ADMIN. Der Treiber setzt beim Scharfschalten
            # von WOL das PCI-Weckflag; ohne dieses weckt WOL aus S3 ohnehin nicht.
            try:
                state = self.reader(WAKEUP % nic).strip()
                if state == "disabled":
                    reasons.append("wol_nicht_aktiv")
                elif state != "enabled":
                    raise ValueError("wakeup_schema")
            except Exception:
                reasons.append("wol_unklar")
        try:
            # Der RTC-Wecker ist der einzige automatische Weg zurück.
            state = self.reader(RTC_WAKEUP).strip()
            if state == "disabled":
                reasons.append("rtc_weckquelle_aus")
            elif state != "enabled":
                raise ValueError("wakeup_schema")
        except Exception:
            reasons.append("rtc_weckquelle_unklar")
        try:
            reasons += self.fremde_schlaefer()
        except Exception:
            reasons.append("fremder_schlafdienst_unklar")
        return reasons

    def fremde_schlaefer(self):
        """Ein zweiter Schläfer ohne RTC-Wecker (Gen 0) darf nach dem Resume nicht anlaufen."""
        result = self.runner(["systemctl", "show", "-p", "Id", "-p", "LoadState", "-p", "ActiveState", "--"]
                             + list(FREMDE_SCHLAEFER))
        if result.returncode:
            raise ValueError("systemctl_fehler")
        units = {}
        for block in re.split(r"\n\s*\n", result.stdout.strip()):
            data = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            if set(data) != {"Id", "LoadState", "ActiveState"} or data["Id"] in units:
                raise ValueError("systemctl_schema")
            units[data["Id"]] = data
        if set(units) != set(FREMDE_SCHLAEFER):
            raise ValueError("systemctl_schema")
        reasons = []
        for name in FREMDE_SCHLAEFER:
            load, state = units[name]["LoadState"], units[name]["ActiveState"]
            if state not in ("active", "activating", "deactivating", "reloading", "refreshing",
                             "inactive", "failed", "maintenance"):
                raise ValueError("systemctl_schema")
            # mask stoppt keine laufende Unit; aktiv ist darum immer ein Abbruchgrund.
            if state not in ("inactive", "failed") or (
                    name in NUR_MASKIERT and load not in ("masked", "not-found")):
                reasons.append("fremder_schlafdienst:" + name)
        return reasons

    def suspend(self):
        return self.runner(["systemctl", "suspend"]).returncode == 0
