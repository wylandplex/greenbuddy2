"""gb-wecken: Notfall-Wecken per WOL von proxy01 aus, nur Hosts aus der festen Tabelle."""

import argparse
import ipaddress
import json
import re
import socket
import sys
import time
from pathlib import Path

from . import wol

WECKEN = "/etc/greenbuddy/wecken.json"
# Subnetz-Broadcast und begrenzter Broadcast; beide im S3-Test vom 06.10.26 bestätigt.
ZIELE = (("192.168.1.255", 9), ("255.255.255.255", 9))
# Messung 07.10.26: tote RAID-Platten verzögern das Einschlafen von vhost01 bis ~60 s; ein WOL in
# dieser Phase vermerkt die NIC, weckt aber nicht. Darum standardmäßig 3 min wiederholen, bis TCP antwortet.
MAX_WARTEN_S = 180
WIEDERHOLEN_S = 15
SENDEN_FEHLGESCHLAGEN = 3


def laden(path=WECKEN):
    """Feste MAC-Tabelle; jeder Formfehler bricht ab, bevor ein Paket gesendet wird."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    hosts = data.get("hosts") if isinstance(data, dict) else None
    if not isinstance(hosts, dict) or not hosts:
        raise ValueError("wecken_konfig")
    result = {}
    for name, row in hosts.items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name) or not isinstance(row, dict):
            raise ValueError("wecken_konfig")
        wol.magic_packet(row.get("mac"))
        if not isinstance(row.get("adresse"), str):
            raise ValueError("wecken_konfig")
        address = str(ipaddress.IPv4Address(row["adresse"]))
        port = row.get("port", 22)
        if type(port) is not int or not 0 < port < 65536:
            raise ValueError("wecken_konfig")
        result[name] = {"mac": row["mac"].lower(), "adresse": address, "port": port}
    return result


def erreichbar(adresse, port, timeout=2):
    try:
        socket.create_connection((adresse, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def wecken(host, hosts, warten=True, senden=None, pruefen=erreichbar, uhr=time.monotonic,
           schlafen=time.sleep):
    if host not in hosts:
        raise ValueError("host_unbekannt")
    send = senden or wol.senden
    ziel = hosts[host]
    row = {"host": host, "pakete": 0, "sendefehler": 0}

    def senden_einmal():
        try:
            row["pakete"] += send(ziel["mac"], ZIELE)
        except OSError:
            row["sendefehler"] += 1

    def ergebnis(code):
        if code and row["pakete"] == 0:
            row["fehler"] = "senden_fehlgeschlagen"
            return row, SENDEN_FEHLGESCHLAGEN
        return row, code

    senden_einmal()
    if not warten:
        return ergebnis(0 if row["pakete"] else 1)
    start = uhr()
    naechstes = start + WIEDERHOLEN_S
    while True:
        if pruefen(ziel["adresse"], ziel["port"]):
            row.update(erreichbar=True, sekunden=round(uhr() - start, 1))
            return row, 0
        if uhr() - start >= MAX_WARTEN_S:
            row.update(erreichbar=False, sekunden=round(uhr() - start, 1))
            return ergebnis(1)
        if uhr() >= naechstes:
            # Ein verlorenes oder in der Einschlafphase verpufftes Paket wird wiederholt.
            senden_einmal()
            naechstes += WIEDERHOLEN_S
        schlafen(2)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Host per Wake-on-LAN wecken (feste MAC-Tabelle)")
    parser.add_argument("host")
    parser.add_argument("--config", default=WECKEN)
    parser.add_argument("--nur-senden", action="store_true",
                        help="einmal senden und nicht auf den Host warten (Standard: bis zu %d s "
                             "alle %d s wiederholen, bis der TCP-Port antwortet)" % (MAX_WARTEN_S, WIEDERHOLEN_S))
    parser.add_argument("--warten", action="store_true", help=argparse.SUPPRESS)  # beta.2-Aufrufe; Warten ist Standard
    args = parser.parse_args(argv)
    try:
        hosts = laden(args.config)
        if args.host not in hosts:
            raise ValueError("host_unbekannt")
    except Exception as error:
        grund = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]+", str(error)) else "konfig_fehler"
        print(json.dumps({"host": args.host, "fehler": grund}, ensure_ascii=False), file=sys.stderr)
        return 2
    row, code = wecken(args.host, hosts, warten=not args.nur_senden, pruefen=erreichbar)
    print(json.dumps(row, ensure_ascii=False))
    return code
