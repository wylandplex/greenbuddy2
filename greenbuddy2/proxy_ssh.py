"""SSH-Zwangsbefehl: Host ausschließlich aus festen argv der Schlüsselzeile."""

import argparse
import json
import os
import re
import shlex
import sys
import time

from .konfig import abgeschaltet
from .register import HOSTS, Register

# Anzahl Wörter je Befehl; schlafe-jetzt trägt die Sekunden bis zum RTC-Wecker (Plan R5).
BEFEHLE = {"status": 1, "abmelden": 2, "schlafe-jetzt": 3, "anmelden": 2, "anmelden-abbruch": 2}


class Argumente(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("ssh_argumente_ungueltig")


def ausfuehren(argv, original, register=None, now=None, aus=False):
    parser = Argumente(description="Hostgebundener SSH-Zwangsbefehl", add_help=False)
    parser.add_argument("--host", required=True, choices=HOSTS)
    args = parser.parse_args(argv)
    parts = shlex.split(original)
    if not parts or parts[0] not in BEFEHLE:
        raise ValueError("befehl_unbekannt")
    if len(parts) != BEFEHLE[parts[0]]:
        raise ValueError("befehl_argumente")
    sekunden = None
    if parts[0] == "schlafe-jetzt":
        if not re.fullmatch(r"[1-9][0-9]{0,4}", parts[2]):
            raise ValueError("sekunden_ungueltig")
        sekunden = int(parts[2])
    return (register or Register()).befehl(args.host, parts[0], parts[1] if len(parts) > 1 else None,
                                           time.time() if now is None else now, sekunden=sekunden, aus=aus)


def main():
    try:
        row = ausfuehren(sys.argv[1:], os.environ.get("SSH_ORIGINAL_COMMAND", ""), aus=abgeschaltet())
        print(json.dumps(row, ensure_ascii=False))
        return 0
    except (ValueError, OSError, SystemExit) as error:
        grund = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]+", str(error)) else \
            "befehl_oder_register_ungueltig"
        print(json.dumps({"bereit": False, "fehler": grund}))
        return 1
