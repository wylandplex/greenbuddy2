"""Begrenzte JSONL-Protokolle, Heartbeat und Entfernung alter Quelladressen."""

import collections
import datetime as dt
import json
import os
import sys
import time
from pathlib import Path


def utc(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat()


class JsonLog:
    def __init__(self, path, limit=20 * 1024 * 1024, rotations=5, ip_retention=False,
                 heartbeat_seconds=60):
        self.path = Path(path)
        self.limit, self.rotations = limit, rotations
        self.ip_retention = ip_retention
        self.heartbeat_seconds = heartbeat_seconds
        self.signature, self.last_write, self.retry_at = None, -float("inf"), 0
        self.last_cleanup = -float("inf")

    def paths(self):
        return [self.path] + [Path(str(self.path) + ".%d" % i)
                              for i in range(1, self.rotations + 1)]

    def bereinigen(self, now):
        """Alte Metadaten durch Tageszähler ersetzen, auch in Rotationen."""
        # Die stündliche Bereinigung hält auch zwischen zwei Läufen höchstens 14 Tage.
        cutoff = now - 14 * 86400 + 3600
        for path in self.paths():
            if not path.exists():
                continue
            kept, counts, changed = [], collections.Counter(), False
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as source:
                for line in source:
                    try:
                        if "\ufffd" in line:
                            raise ValueError("log_zeile_beschaedigt")
                        row = json.loads(line)
                        if "quell_ip" in row and row["zeit"] < cutoff:
                            key = (utc(row["zeit"])[:10], row.get("entscheidung", "unklar"),
                                   row.get("port", 0), row.get("quellklasse", "UNKLAR"))
                            counts[key] += row.get("anzahl", 1)
                            changed = True
                        else:
                            kept.append(line)
                    except (ValueError, KeyError, TypeError):
                        # Beschädigte Zeilen dürfen die Aufbewahrung nicht umgehen.
                        changed = True
            if changed:
                for (day, decision, port, kind), count in sorted(counts.items()):
                    kept.append(json.dumps({"tag": day, "entscheidung": decision, "port": port,
                                            "quellklasse": kind, "anzahl": count},
                                           ensure_ascii=False) + "\n")
                tmp = Path(str(path) + ".bereinigung")
                fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as target:
                    os.fchmod(target.fileno(), 0o600)
                    target.writelines(kept)
                    target.flush()
                    os.fsync(target.fileno())
                tmp.replace(path)

    def emit(self, row, now=None, heartbeat=False):
        now = time.time() if now is None else now
        if now < self.retry_at:
            return False
        sig = json.dumps({k: v for k, v in row.items() if k not in
                          ("utc", "zeit", "ruhe_seit_s", "takt_s", "fakten")}, sort_keys=True)
        if heartbeat and sig == self.signature and 0 <= now - self.last_write < self.heartbeat_seconds:
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.is_symlink():
                raise OSError("log_symlink")
            if self.ip_retention and now - self.last_cleanup >= 3600:
                self.bereinigen(now)
                self.last_cleanup = now
            payload = (json.dumps(dict(row, utc=utc(now)), ensure_ascii=False,
                                  allow_nan=False, separators=(",", ":")) + "\n").encode()
            if len(payload) > self.limit:
                raise OSError("log_gross")
            if self.path.exists() and self.path.stat().st_size + len(payload) > self.limit:
                self.paths()[-1].unlink(missing_ok=True)
                for index in range(self.rotations - 1, 0, -1):
                    old = Path(str(self.path) + ".%d" % index)
                    if old.exists():
                        old.replace(str(self.path) + ".%d" % (index + 1))
                self.path.replace(str(self.path) + ".1")
            fd = os.open(str(self.path), os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "ab") as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(payload)
                target.flush()
            if heartbeat:
                self.signature, self.last_write = sig, now
            return True
        except (OSError, ValueError):
            print("GreenBuddy: log_schreibfehler", file=sys.stderr, flush=True)
            self.retry_at = now + 60
            return False
