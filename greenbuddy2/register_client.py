"""Register bei proxy01 aus Sicht von vhost01: SSH-Zwangsbefehl, strikt geprüfte JSON-Antwort.

Jede Abweichung ist eine StellvertreterFehler-Ausnahme mit kurzem Grund; der Aufrufer schläft dann
nicht (unklar = wach). Eigene Defaults und Formprüfung, damit konfig.py sie nicht kennen muss.
"""

import json
import math
import re
import subprocess

from .fakten_vhost import command

HOST = "vhost01"
STANDARD = {
    "stellvertreter_ziel": "gb-register@192.168.1.100",
    "stellvertreter_schluessel": "/etc/greenbuddy/ssh/id_ed25519",
    "stellvertreter_known_hosts": "/etc/greenbuddy/ssh/known_hosts",
    # false = Notschalter: Ablauf wie 2.0.0b4 ohne Register; proxy01 hält die Adresse dann nie.
    "stellvertreter_pflicht": True,
}
FRIST_S = 20
SCHLAF_MIN_S, SCHLAF_MAX_S = 600, 43200
ZYKLUS = r"[A-Za-z0-9_-]{1,128}"
GRUND = r"[A-Za-z0-9_.:-]{1,80}"
PHASE = {"abmelden": "abgemeldet", "schlafe-jetzt": "schlaf_absicht", "anmelden": "angemeldet",
         "anmelden-abbruch": "angemeldet"}
MAX_ANTWORT = 65536


class StellvertreterFehler(ValueError):
    def __init__(self, grund, detail=None):
        super().__init__(grund)
        self.grund, self.detail = grund, detail


class StellvertreterUnklar(StellvertreterFehler):
    def __init__(self, detail):
        super().__init__("stellvertreter_unklar", detail)


class StellvertreterNichtBereit(StellvertreterFehler):
    def __init__(self, grund):
        super().__init__("stellvertreter_nicht_bereit:" + grund, grund)


def einstellungen(cfg=None):
    result = dict(STANDARD)
    result.update((k, v) for k, v in (cfg or {}).items() if k in STANDARD)
    # Ziel beginnt nie mit "-" (sonst eine ssh-Option).
    if (not isinstance(result["stellvertreter_ziel"], str)
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}",
                                result["stellvertreter_ziel"])
            or type(result["stellvertreter_pflicht"]) is not bool):
        raise ValueError("konfig_ungueltig")
    for name in ("stellvertreter_schluessel", "stellvertreter_known_hosts"):
        # ssh trennt UserKnownHostsFile an Leerzeichen und expandiert %-Token: beides ausgeschlossen.
        value = result[name]
        if (not isinstance(value, str) or not re.fullmatch(r"/[A-Za-z0-9_.+/-]{1,255}", value)
                or ".." in value.split("/")):
            raise ValueError("konfig_ungueltig")
    return result


def sekunden_bis(weckzeit, jetzt):
    """Sekunden bis zum RTC-Termin; die Register-Aufrufe davor dürfen die Untergrenze nicht reißen."""
    return max(SCHLAF_MIN_S, min(SCHLAF_MAX_S, int(weckzeit - jetzt)))


def grund_gueltig(value):
    return isinstance(value, str) and re.fullmatch(GRUND, value) is not None


def kein_wert(name):
    raise ValueError("json_konstante")


def zeile(stdout):
    if not isinstance(stdout, str) or len(stdout) > MAX_ANTWORT:
        raise StellvertreterUnklar("antwort_form")
    text = stdout[:-1] if stdout.endswith("\n") else stdout
    if not text or "\n" in text or "\r" in text:
        raise StellvertreterUnklar("antwort_zeilen")
    try:
        data = json.loads(text, parse_constant=kein_wert)
    except ValueError:
        raise StellvertreterUnklar("antwort_json") from None
    if not isinstance(data, dict):
        raise StellvertreterUnklar("antwort_json")
    return data


def fehlerform(data):
    """{"bereit": false, "fehler": GRUND} = proxy01 hat den Befehl abgelehnt."""
    if data.get("bereit") is not False or not grund_gueltig(data["fehler"]):
        raise StellvertreterUnklar("antwort_schema")
    raise StellvertreterNichtBereit(data["fehler"])


def kurztext(value):
    return isinstance(value, str) and 1 <= len(value) <= 64


def weckung_pruefen(value):
    """Letzte Weckung laut proxy01 (Plan R8); nur die vereinbarten Felder, nie eine Quelladresse."""
    if value is None:
        return None
    if not isinstance(value, dict) or not {"zeit", "weg", "port", "quellklasse", "entscheidung"} <= set(value):
        raise StellvertreterUnklar("antwort_weckung")
    # proxy01 meldet weg als Nummer des Weckwegs (4/5/7); weg, port und quellklasse sind null,
    # wenn ohne Nachfrage geweckt wurde (Lease-Ablauf, Abschalter).
    if (type(value["zeit"]) not in (int, float) or not math.isfinite(value["zeit"])
            or not (value["weg"] is None or (type(value["weg"]) is int and 1 <= value["weg"] <= 99)
                    or kurztext(value["weg"]))
            or not (value["port"] is None or (type(value["port"]) is int and 1 <= value["port"] <= 65535))
            or not (value["quellklasse"] is None or kurztext(value["quellklasse"]))
            or not kurztext(value["entscheidung"])):
        raise StellvertreterUnklar("antwort_weckung")
    return {k: value[k] for k in ("zeit", "weg", "port", "quellklasse", "entscheidung")}


def antwort(befehl, zyklus, code, stdout):
    if type(code) is not int or code != 0:
        # Nur die vereinbarte Fehlerform ist eine Absage; alles andere (ssh 255, Signal) ist unklar.
        try:
            data = zeile(stdout)
        except StellvertreterUnklar:
            raise StellvertreterUnklar("exit_%s" % code) from None
        if "fehler" in data:
            fehlerform(data)
        raise StellvertreterUnklar("exit_%s" % code)
    data = zeile(stdout)
    if "fehler" in data:
        fehlerform(data)
    if data.get("host") != HOST:
        raise StellvertreterUnklar("antwort_host")
    zustand = data.get("zustand")
    if (type(data.get("bereit")) is not bool or not isinstance(zustand, dict)
            or not isinstance(zustand.get("phase"), str)):
        raise StellvertreterUnklar("antwort_schema")
    if befehl == "status":
        return data
    # Eine Absage zuerst: unter dem Abschalter trägt proxy01 den neuen Zyklus nicht ein.
    if befehl in ("abmelden", "schlafe-jetzt") and not data["bereit"]:
        if not grund_gueltig(data.get("grund")):
            raise StellvertreterUnklar("antwort_schema")
        raise StellvertreterNichtBereit(data["grund"])
    if "zyklus" in zustand and zustand["zyklus"] != zyklus:
        raise StellvertreterUnklar("antwort_zyklus")
    # Tatsache statt Exit-Code: das Register muss den verlangten Zustand tatsächlich melden.
    if zustand["phase"] != PHASE[befehl]:
        raise StellvertreterUnklar("antwort_phase")
    if befehl == "anmelden":
        if "weckung" not in data:
            raise StellvertreterUnklar("antwort_weckung")
        data["weckung"] = weckung_pruefen(data["weckung"])
    return data


class Register:
    def __init__(self, cfg=None, runner=command):
        self.cfg, self.runner = cfg, runner

    def argv(self, entfernt):
        e = einstellungen(self.cfg)
        return ["ssh", "-i", e["stellvertreter_schluessel"], "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + e["stellvertreter_known_hosts"],
                "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
                "-T", e["stellvertreter_ziel"], entfernt]

    def aufrufen(self, befehl, zyklus=None, *extra):
        if befehl != "status" and (not isinstance(zyklus, str) or not re.fullmatch(ZYKLUS, zyklus)):
            raise StellvertreterUnklar("zyklus_ungueltig")
        teile = [befehl] + ([] if zyklus is None else [zyklus]) + [str(x) for x in extra]
        try:
            argv = self.argv(" ".join(teile))
        except ValueError:
            raise StellvertreterUnklar("konfig_ungueltig") from None
        try:
            result = self.runner(argv, timeout=FRIST_S)
        except subprocess.TimeoutExpired:
            raise StellvertreterUnklar("frist") from None
        except Exception:
            raise StellvertreterUnklar("ssh_start") from None
        return antwort(befehl, zyklus, result.returncode, result.stdout)

    def status(self):
        """Nur lesend, für die Live-Probe des SSH-Wegs: die geprüfte Antwortzeile."""
        return self.aufrufen("status")

    def abmelden(self, zyklus):
        self.aufrufen("abmelden", zyklus)

    def schlafe_jetzt(self, zyklus, sekunden):
        if type(sekunden) is not int or not SCHLAF_MIN_S <= sekunden <= SCHLAF_MAX_S:
            raise StellvertreterUnklar("sekunden_ungueltig")
        self.aufrufen("schlafe-jetzt", zyklus, sekunden)

    def anmelden(self, zyklus):
        """Zyklus beenden; liefert die letzte Weckung laut proxy01 oder None."""
        return self.aufrufen("anmelden", zyklus)["weckung"]

    def anmelden_abbruch(self, zyklus):
        self.aufrufen("anmelden-abbruch", zyklus)
