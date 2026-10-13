"""Eigene WAN-Adresse aus einem DNS-Namen, ohne die Hauptschleife zu blockieren (proxy01 und vhost01)."""

import ipaddress
import socket
import threading


def dns_aufloesen(name):
    return [info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)]


class WanAdresse:
    """WAN-IP aus wan_name: höchstens alle 10 min, im Hintergrund; nach 2 s ohne Antwort unbekannt."""
    def __init__(self, name, aufloesen=None, faden=None, intervall=600, frist=2):
        self.name, self.intervall, self.frist = name, intervall, frist
        self.aufloesen = aufloesen or dns_aufloesen
        self.faden = faden or threading.Thread
        self.werte, self.stand, self.versuch, self.laeuft, self.neu = None, None, None, False, None

    def anstossen(self, now):
        if not self.name or self.laeuft or (self.versuch is not None and now - self.versuch < self.intervall):
            return
        self.versuch, self.laeuft = now, True
        self.faden(target=self._lauf, daemon=True).start()

    def _lauf(self):
        try:
            werte = sorted({str(ipaddress.IPv4Address(value)) for value in self.aufloesen(self.name)}) or None
        except Exception:
            # Jeder Auflösungsfehler heißt "unbekannt", nie Abbruch der Schleife.
            werte = None
        self.neu = (werte,)
        self.laeuft = False

    def aktuell(self, now):
        if self.neu is not None:
            (self.werte,), self.neu = self.neu, None
            self.stand = self.versuch
        if self.laeuft and now - self.versuch > self.frist:
            return None
        if self.werte and self.stand is not None and now - self.stand < self.intervall + self.frist:
            return self.werte
        return None
