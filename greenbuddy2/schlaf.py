"""Minütlicher Schlafwächter für vhost01: Schatten (Standard) oder aktiv mit Suspend.

Aktiv nur mit "mode": "aktiv" und "dependencies_verified": true. Unklar = wach. Vor jedem Suspend
meldet sich vhost01 bei proxy01 ab (Weckweg, Plan 2026-10-12), nach dem Resume wieder an.
"""

import argparse
import datetime as dt
import fcntl
import json
import secrets
import time
from pathlib import Path

from . import aktiv, register_client
from .fakten_vhost import Sammler
from .fenster import parse, wachfenster, schlafphase
from .jsonlog import JsonLog
from .konfig import SCHLAF, abgeschaltet, laden

REGISTER_PAUSE_S = 300   # nach Register-Fehler kein SSH im Minutentakt zu einem kaputten proxy01
ANMELDEN_FRIST_S = 600   # so lange nach dem Resume wird anmelden wiederholt


class Uhr:
    def __init__(self, threshold=10, mindestwach=aktiv.MINDESTWACH_S):
        self.previous = None
        self.jump_until = 0
        self.resume_until = 0
        self.threshold = threshold
        self.mindestwach = mindestwach
        self.resumed = False

    def pruefen(self, wall, boot, mono):
        unknown, veto = [], []
        self.resumed = False
        if self.previous:
            old_wall, old_boot, old_mono = self.previous
            if abs((wall - old_wall) - (boot - old_boot)) > self.threshold:
                self.jump_until = boot + 2700
            if (boot - old_boot) - (mono - old_mono) > 2:
                self.resume_until = boot + self.mindestwach
                self.resumed = True
        else:
            # Dienststart zählt wie ein Resume; er liegt nie vor dem Boot.
            self.resume_until = boot + self.mindestwach
        self.previous = (wall, boot, mono)
        if boot < self.jump_until:
            unknown.append("uhrsprung")
        if boot < self.resume_until:
            veto.append("mindestwachzeit")
        return unknown, veto


class Entscheidung:
    def __init__(self, idle_seconds=2700, aktiv_modus=False):
        self.idle_seconds, self.quiet_since, self.aktiv = idle_seconds, None, aktiv_modus
        # Job-Vetos der vorigen Auswertung; None = unbekannt (Prozessstart oder unklare Vorrunde).
        self.jobs_zuvor = None

    def entscheiden(self, facts, boot, window_vetos=(), unknown=(), disabled=False,
                    neutrale_vetos=(), hindernisse=()):
        """window_vetos starten die Ruhezeit neu; neutrale_vetos (Fenster, Mindestwachzeit) nicht.

        Ein Job ("job:<unit>") sperrt jede Runde, in der er läuft, startet die Ruhezeit aber erst
        neu, wenn dieselbe Unit schon in der vorigen Auswertung lief: No-op-Timer (10 ms), die
        PID1 beim Abfragen auslöst, fallen genau in eine Runde (Review 07.10.26).
        """
        if disabled:
            self.quiet_since = None
            return {"entscheidung": "abgeschaltet", "ruhe_kandidat": False,
                    "dependencies_verified": False}
        unclear = sorted(set(facts["unklar"]) | set(unknown))
        jobs = {v for v in facts["vetos"] if v.startswith("job:")}
        erstmals = set() if self.jobs_zuvor is None else jobs - self.jobs_zuvor
        self.jobs_zuvor = None if unclear else jobs
        restart = (set(facts["vetos"]) - erstmals) | set(window_vetos)
        vetos = sorted(set(facts["vetos"]) | set(window_vetos) | set(neutrale_vetos))
        if self.quiet_since is None or facts["nutzung"] or unclear or restart:
            self.quiet_since = boot
        idle = max(self.idle_seconds, aktiv.MIN_RUHE_S) if self.aktiv else self.idle_seconds
        candidate = not (unclear or vetos or facts["nutzung"]) and boot - self.quiet_since >= idle
        row = {"ruhe_kandidat": candidate, "vetos": vetos, "nutzung": facts["nutzung"],
               "fakten": facts["fakten"], "ruhe_seit_s": round(max(0, boot - self.quiet_since), 2)}
        if not self.aktiv:
            row.update(entscheidung="unklar" if unclear else "beobachten",
                       unklar=sorted(set(unclear) | {"abhaengigkeiten_ungeprueft"}),
                       dependencies_verified=False, aktion="beobachten")
            return row
        blocked = sorted(set(hindernisse))
        sleep = candidate and not blocked
        row.update(entscheidung="schlafen" if sleep else "unklar" if unclear else "wach",
                   unklar=unclear, hindernisse=blocked, dependencies_verified=True,
                   aktion="schlafen" if sleep else "wach", modus="aktiv")
        return row


def jetzt():
    return time.time(), time.clock_gettime(time.CLOCK_BOOTTIME), time.monotonic()


class Waechter:
    """Ein Takt: Tatsachen sammeln, entscheiden und im Aktivmodus ausführen."""

    def __init__(self, cfg, logger, collector, clock, decision, config_unknown=(), zustand=None,
                 ausfuehrung=None):
        self.cfg, self.logger, self.collector = cfg, logger, collector
        self.clock, self.decision = clock, decision
        self.config_unknown = list(config_unknown)
        self.zustand, self.ausfuehrung = zustand, ausfuehrung
        self.zeit, self.monoton = jetzt, time.monotonic
        self.takt_start = None
        self.data, self.zustand_fehler, self.speicher_fehler = None, None, False
        self.restored = False
        try:
            self.stellvertreter = register_client.einstellungen(cfg)
        except ValueError:
            self.stellvertreter = dict(register_client.STANDARD)
            self.config_unknown.append("konfig_fehler")
        self.zyklus_neu = lambda: secrets.token_hex(8)
        # BOOTTIME, bis zu der nach einem Register-Fehler kein neuer Versuch startet; nur im Speicher,
        # ein Dienstneustart hat ohnehin 10 min Mindestwachzeit.
        self.register_pause_bis = None
        # Offenes anmelden nach dem Resume: {"zyklus", "befehl", "seit", "versuche", "grund"}.
        self.anmelden_offen = None
        if decision.aktiv:
            try:
                if zustand is None or ausfuehrung is None or zustand.boot is None:
                    raise ValueError("boot_id_unklar")
                self.data = zustand.laden()
            except Exception:
                self.zustand_fehler = "zustand_unklar"

    def speichern(self):
        try:
            self.zustand.speichern(self.data)
            self.speicher_fehler = False
            return True
        except Exception:
            self.speicher_fehler = True
            return False

    def ereignis(self, row, wall):
        return self.logger.emit(dict(row), wall)

    def wiederherstellen(self, boot):
        """Letzte Unruhe nur übernehmen, wenn bis eben lückenlos beobachtet wurde; sonst beginnt die Ruhe jetzt.

        Lückenlos heißt: derselbe Boot, kein offener Schlafeintrag und ein Stempel des Vorgängers,
        der höchstens zwei Takte alt ist und genau diese Ruhe bezeugt. Schattenbetrieb, gestoppter
        Dienst und ein Resume, den niemand gesehen hat, hinterlassen keinen frischen Stempel.
        """
        self.restored = True
        stored = self.data["ruhe_seit"]
        try:
            stempel = aktiv.stempel_lesen(self.cfg["takt_stempel"])
            lueckenlos = (stempel["boot_id"] == self.zustand.boot and stempel["ruhe_seit"] == stored
                          and 0 <= boot - stempel["takt"] <= 2 * self.cfg["poll_seconds"])
        except Exception:
            lueckenlos = False
        if (lueckenlos and self.data["boot_id"] == self.zustand.boot and stored is not None
                and stored <= boot and self.data["schlaf"] is None):
            self.decision.quiet_since = stored
        else:
            self.decision.quiet_since = boot
        self.data["boot_id"] = self.zustand.boot

    def stempeln(self, boot):
        """Je Takt im Aktivmodus: ruhe_seit ist bis zu dieser BOOTTIME beobachtet (tmpfs, nur dieser Boot)."""
        try:
            aktiv.stempel_schreiben(self.cfg["takt_stempel"], self.zustand.boot, boot, self.data["ruhe_seit"])
        except Exception:
            # Ohne frischen Stempel beginnt die Ruhe nach einem Neustart neu: die sichere Seite.
            pass

    def bewerten(self, wall, boot, mono):
        cfg, aktiv_modus = self.cfg, self.decision.aktiv
        unknown, neutral = self.clock.pruefen(wall, boot, mono)
        if self.clock.resumed:
            # Aufwachen zählt als Signal: nach jedem Resume erneut volle Ruhezeit.
            self.decision.quiet_since = boot
        unknown += self.config_unknown
        hindernisse, wake = [], None
        try:
            pairs, lead = parse(Path(cfg["media_conf"]).read_text())
            now = dt.datetime.fromtimestamp(wall)
            neutral += wachfenster(pairs, lead, now)
            if not schlafphase(pairs, lead, now):
                neutral.append("ausserhalb_tagschlaf")
            elif aktiv_modus:
                ende = aktiv.fenster_ende(pairs, lead, wall)
                if ende - wall < aktiv.MIN_BIS_FENSTERENDE_S:
                    hindernisse.append("fensterende_zu_nah")
                else:
                    try:
                        wake = aktiv.weckzeit(ende, lead, wall)
                    except ValueError:
                        hindernisse.append("weckzeit_ungueltig")
        except Exception:
            unknown.append("zeitfenster_unklar")
        if aktiv_modus:
            if self.zustand_fehler:
                unknown.append(self.zustand_fehler)
            else:
                if self.speicher_fehler:
                    unknown.append("zustand_schreibfehler")
                try:
                    blocked, event = aktiv.zyklen_pruefen(self.data, wall)
                    hindernisse += blocked
                    if event:
                        self.ereignis(event, wall)
                        if not self.speichern():
                            unknown.append("zustand_schreibfehler")
                except Exception:
                    unknown.append("zustand_unklar")
            if wake is None and not hindernisse:
                hindernisse.append("weckzeit_fehlt")
            if self.register_pause_bis is not None and boot < self.register_pause_bis:
                hindernisse.append("stellvertreter_pause")
        try:
            facts = self.collector.sammeln(wall)
        except Exception:
            # Auch Formfehler zwischen den einzelnen Prüfungen müssen im Log stehen.
            unknown.append("konfig_fehler")
            facts = {"unklar": [], "vetos": [], "nutzung": [], "fakten": {}}
        if self.monoton() - self.takt_start > 55:
            unknown.append("takt_verspaetet")
        row = self.decision.entscheiden(facts, boot, (), unknown, neutrale_vetos=neutral,
                                        hindernisse=hindernisse)
        if "konfig_fehler" in unknown:
            row["grund"] = "konfig_fehler"
        if aktiv_modus and wake is not None:
            row["weckzeit"] = wake
        return row

    def takt(self, wall=None, boot=None, mono=None):
        if wall is None:
            wall, boot, mono = self.zeit()
        self.takt_start = mono
        aktiv_modus = self.decision.aktiv
        if aktiv_modus and self.data is not None:
            if not self.restored:
                self.wiederherstellen(boot)
            try:
                event = aktiv.aufwachen_pruefen(self.data, self.zustand.boot, boot, mono, wall)
            except Exception:
                event = None
                self.zustand_fehler = "zustand_unklar"
            if event:
                # Auch ein Schlaf, den dieser Prozess nicht selbst erlebt hat, startet die Ruhe neu.
                self.decision.quiet_since = boot
                if event.get("zyklus"):
                    befehl = "anmelden-abbruch" if event["ereignis"] == "suspend_ohne_wirkung" else "anmelden"
                    self.anmelden_offen = {"zyklus": event["zyklus"], "befehl": befehl, "seit": boot,
                                           "versuche": 0, "grund": None}
                    event.update(self.anmelden_versuchen())
                self.ereignis(event, wall)
                self.speichern()
            elif self.anmelden_offen is not None:
                self.anmelden_nachholen(wall, boot)
        if abgeschaltet(self.cfg):
            row = self.decision.entscheiden({}, boot, disabled=True)
        else:
            row = self.bewerten(wall, boot, mono)
            if row["entscheidung"] == "schlafen":
                row = self.einschlafen(row)
        if aktiv_modus and self.data is not None:
            if self.data["ruhe_seit"] != self.decision.quiet_since:
                self.data["ruhe_seit"] = self.decision.quiet_since
                self.speichern()
            self.stempeln(boot)
        return row

    def anmelden_versuchen(self):
        """Zyklus bei proxy01 beenden; die Versuche lassen die Ruhezeit unberührt."""
        offen = self.anmelden_offen
        offen["versuche"] += 1
        try:
            if offen["befehl"] == "anmelden":
                weckung = self.ausfuehrung.register.anmelden(offen["zyklus"])
            else:
                self.ausfuehrung.register.anmelden_abbruch(offen["zyklus"])
        except Exception as fehler:
            offen["grund"] = getattr(fehler, "grund", "stellvertreter_unklar")
            return {"anmelden": "offen", "anmelden_grund": offen["grund"]}
        self.anmelden_offen = None
        if offen["befehl"] == "anmelden":
            return {"anmelden": "ok", "geweckt_durch_proxy01": weckung}
        return {"anmelden": "ok"}

    def anmelden_nachholen(self, wall, boot):
        offen = self.anmelden_offen
        if boot - offen["seit"] >= ANMELDEN_FRIST_S:
            self.anmelden_offen = None
            self.ereignis({"ereignis": "anmelden_aufgegeben", "zyklus": offen["zyklus"],
                           "versuche": offen["versuche"], "grund": offen["grund"]}, wall)
            return
        ergebnis = self.anmelden_versuchen()
        if ergebnis["anmelden"] == "ok":
            row = {"ereignis": "angemeldet", "zyklus": offen["zyklus"], "versuche": offen["versuche"]}
            row.update((k, v) for k, v in ergebnis.items() if k != "anmelden")
            self.ereignis(row, wall)

    def abbruch(self, row, grund, gruende=(), zyklus=None):
        result = dict(row, entscheidung="wach", aktion="abbruch", grund=grund)
        if zyklus:
            # Best effort: ein offener Zyklus läuft auf proxy01 ab; der wache Host beantwortet dessen
            # ARP-Proben, darum übernimmt proxy01 die Adresse nicht.
            try:
                self.ausfuehrung.register.anmelden_abbruch(zyklus)
                result["anmelden_abbruch"] = "ok"
            except Exception as fehler:
                result["anmelden_abbruch"] = getattr(fehler, "grund", "stellvertreter_unklar")
        self.ausfuehrung.rtc_loeschen()
        if gruende:
            result["abbruch"] = sorted(set(gruende))
        return result

    def register_fehler(self, row, fehler, boot, zyklus):
        """proxy01 nicht bereit oder unklar: kein Suspend, Zyklus schließen, 5 min Pause."""
        self.register_pause_bis = boot + REGISTER_PAUSE_S
        if isinstance(fehler, register_client.StellvertreterFehler):
            result = self.abbruch(row, "stellvertreter", [fehler.grund], zyklus)
            if isinstance(fehler, register_client.StellvertreterUnklar):
                result["stellvertreter_detail"] = fehler.detail
            return result
        return self.abbruch(row, "stellvertreter", ["stellvertreter_unklar"], zyklus)

    def letzte_pruefung(self):
        """Unmittelbar vor dem Suspend, nach den SSH-Rundläufen zu proxy01: Abbruchgründe, leer = weiter.

        Abschalter, frische Fakten (Nutzung, Verbindungen, Sitzungen, Jobs, Unklares) mit derselben
        Entscheidungslogik wie jeder Takt, danach die Vorbedingungen samt block-Inhibitoren (Review b5).
        """
        if abgeschaltet(self.cfg):
            return ["abgeschaltet"]
        wall, boot, _ = self.zeit()
        try:
            facts = self.collector.sammeln(wall)
        except Exception:
            return ["konfig_fehler"]
        row = self.decision.entscheiden(facts, boot)
        if row["entscheidung"] != "schlafen":
            return ["entscheidung_" + row["entscheidung"]] + row["vetos"] + row["unklar"] + row["nutzung"]
        return self.ausfuehrung.vorbedingungen(self.cfg)

    def einschlafen(self, row):
        """RTC setzen, frisch prüfen, bei proxy01 abmelden, Zustand sichern, schlafe-jetzt, zuletzt erneut prüfen
        und erst dann suspendieren."""
        wake = row["weckzeit"]
        try:
            self.ausfuehrung.rtc_setzen(wake)
        except Exception:
            return dict(row, entscheidung="wach", aktion="abbruch", grund="rtc_fehler")
        wall, boot, mono = self.zeit()
        if abgeschaltet(self.cfg):
            return self.abbruch(row, "schlusspruefung", ["abgeschaltet"])
        final = self.bewerten(wall, boot, mono)
        reasons = []
        if final["entscheidung"] != "schlafen":
            reasons = (["entscheidung_" + final["entscheidung"]] + final["vetos"] + final["unklar"]
                       + final["nutzung"] + final.get("hindernisse", []))
        elif final.get("weckzeit") != wake:
            reasons.append("weckzeit_geaendert")
        if not reasons:
            reasons = self.ausfuehrung.vorbedingungen(self.cfg)
        if reasons:
            return self.abbruch(final, "schlusspruefung", reasons)
        zyklus = None
        if self.stellvertreter["stellvertreter_pflicht"]:
            zyklus = self.zyklus_neu()
            try:
                self.ausfuehrung.register.abmelden(zyklus)
            except Exception as fehler:
                # Auch ohne gültige Antwort kann proxy01 den Zyklus eröffnet haben: abbrechen.
                return self.register_fehler(final, fehler, boot, zyklus)
        event = {"ereignis": "einschlafen", "weckzeit": wake}
        if zyklus:
            event["zyklus"] = zyklus
        if not self.ereignis(event, wall):
            return self.abbruch(final, "log_schreibfehler", zyklus=zyklus)
        self.data["zyklen"].append(wall)
        self.data["schlaf"] = {"beginn_wall": wall, "beginn_boot": boot, "summe_vor": boot - mono,
                               "weckzeit": wake, "boot_id": self.zustand.boot}
        if zyklus:
            self.data["schlaf"]["zyklus"] = zyklus
        if not self.speichern():
            self.data["zyklen"].pop()
            self.data["schlaf"] = None
            return self.abbruch(final, "zustand_schreibfehler", zyklus=zyklus)
        if zyklus:
            try:
                sekunden = register_client.sekunden_bis(wake, self.zeit()[0])
                self.ausfuehrung.register.schlafe_jetzt(zyklus, sekunden)
            except Exception as fehler:
                self.data["zyklen"].pop()
                self.data["schlaf"] = None
                self.speichern()
                return self.register_fehler(final, fehler, boot, zyklus)
            # abmelden und schlafe-jetzt dauern je bis zu 20 s; was seit der Schlussprüfung neu ist, bricht ab
            # (Spec 3.2: Phase A vor der letzten lokalen Prüfung, "lokales neues Signal: Abbruch").
            gruende = self.letzte_pruefung()
            if gruende:
                self.data["zyklen"].pop()
                self.data["schlaf"] = None
                self.speichern()
                return self.abbruch(final, "letzte_pruefung", gruende, zyklus)
        try:
            ok = self.ausfuehrung.suspend()
        except Exception:
            # Zeitüberschreitung oder Startfehler: ob logind den Auftrag schon angenommen hat, ist
            # offen. RTC-Wecker und Schlafeintrag bleiben darum stehen (einen wachen Host stört der
            # Wecker nicht); aufwachen_pruefen meldet danach aufgewacht oder suspend_ohne_wirkung.
            self.decision.quiet_since = boot
            return dict(final, entscheidung="wach", aktion="abbruch", grund="suspend_fehler",
                        abbruch=["suspend_unklar"])
        if not ok:
            self.data["schlaf"] = None
            self.speichern()
            # Kein neuer Versuch im Minutentakt: erst wieder nach voller Ruhezeit.
            self.decision.quiet_since = boot
            return self.abbruch(final, "suspend_fehler", zyklus=zyklus)
        # Nach dem Aufwachen gilt wieder die volle Ruhezeit (Resume setzt sie zusätzlich zurück).
        self.decision.quiet_since = boot
        return dict(final, aktion="suspend")


def main():
    parser = argparse.ArgumentParser(description="vhost01 beobachten oder (aktiv) schlafen legen")
    parser.add_argument("--config", default="/etc/greenbuddy/schlaf.json")
    parser.add_argument("--einmal", action="store_true",
                        help="ein Takt; die Mindestwachzeit des frischen Prozesses verhindert Suspend")
    args = parser.parse_args()
    try:
        cfg, config_unknown = laden(args.config, SCHLAF), []
    except Exception:
        cfg, config_unknown = dict(SCHLAF), ["konfig_fehler"]
    aktiv_modus = cfg["mode"] == "aktiv" and cfg["dependencies_verified"] is True
    zustand = ausfuehrung = None
    if aktiv_modus:
        try:
            boot = aktiv.boot_id()
        except Exception:
            boot = None
        zustand = aktiv.Zustand(cfg["zustand"], boot)
        ausfuehrung = aktiv.Ausfuehrung(register=register_client.Register(cfg))
    logger = JsonLog(cfg["log"])
    decision = Entscheidung(cfg["idle_seconds"], aktiv_modus)
    waechter = Waechter(cfg, logger, Sammler(cfg), Uhr(), decision, config_unknown, zustand, ausfuehrung)
    lock_path = Path("/run/greenbuddy/schlaf.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        while True:
            wall, boot, mono = jetzt()
            row = waechter.takt(wall, boot, mono)
            if not logger.emit(row, wall, heartbeat=True):
                decision.quiet_since = None
            if args.einmal:
                print(json.dumps(row, ensure_ascii=False))
                return 0
            time.sleep(max(0.1, cfg["poll_seconds"] - (time.monotonic() - mono)))
