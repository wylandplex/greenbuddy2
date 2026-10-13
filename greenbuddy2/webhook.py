"""Nicht installierter Webhook-Baustein mit MAC-Prüfung und haltbarer Warteschlange."""

import argparse
import collections
import functools
import hashlib
import hmac
import http.server
import ipaddress
import json
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .fakten_vhost import NoRedirect
from .jsonlog import JsonLog
from .konfig import abgeschaltet, geheimnis, laden
from .register import Register

FIELDS = ("from", "to", "messageId", "date", "nonce", "box")
BODY_LIMIT = 65536


def mac_berechnen(fields, secret):
    message = "".join(fields[key] for key in FIELDS).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def pruefen(body, secret, gateway_id, now):
    if len(body) > BODY_LIMIT:
        raise ValueError("body_gross")
    pairs = urllib.parse.parse_qsl(body.decode("utf-8"), keep_blank_values=True,
                                  strict_parsing=True, max_num_fields=12)
    fields = dict(pairs)
    required = set(FIELDS) | {"mac"}
    if (len(pairs) != len(fields) or not required <= set(fields)
            or any(not fields[k] for k in required - {"date"})):
        raise ValueError("callback_felder")
    # Zusatzfelder sind kein Teil des MAC und beeinflussen keine Entscheidung.
    fields = {key: fields[key] for key in required}
    supplied = fields["mac"]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", supplied) or not hmac.compare_digest(
            mac_berechnen(fields, secret), supplied.lower()):
        raise ValueError("callback_mac")
    if fields["to"] != gateway_id:
        raise ValueError("callback_empfaenger")
    stamp = int(fields["date"]) if re.fullmatch(r"[0-9]{1,12}", fields["date"]) else None
    fields["darf_wecken"] = stamp is not None and -30 <= now - stamp <= 600
    return fields


def synchronisiert(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return call


class Warteschlange:
    def __init__(self, path, ttl=86400, maximum=500, byte_limit=5 * 1024 * 1024, alarm=None):
        if ttl <= 0 or maximum <= 0 or byte_limit <= 0:
            raise ValueError("queue_konfig")
        self.ttl, self.maximum, self.byte_limit = ttl, maximum, byte_limit
        self.alarm = alarm or (lambda row: None)
        self.lock, self.delivery_lock = threading.RLock(), threading.Lock()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise ValueError("queue_symlink")
        import os
        fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(str(path), 0o600)
        self.db = sqlite3.connect(str(path), timeout=5, check_same_thread=False)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT UNIQUE NOT NULL,
                body BLOB NOT NULL, eingang REAL NOT NULL, ablauf REAL NOT NULL,
                wecken_bis REAL NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS dedupe (message_id TEXT PRIMARY KEY, ablauf REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS zaehler (name TEXT PRIMARY KEY, anzahl INTEGER NOT NULL);
            INSERT OR IGNORE INTO zaehler VALUES ('eingegangen',0),('zugestellt',0),('abgelaufen',0);
        """)
        if "wecken_bis" not in {row[1] for row in self.db.execute("PRAGMA table_info(queue)")}:
            # Alte, bereits gespeicherte Nachrichten dürfen nach Migration nicht wecken.
            self.db.execute("ALTER TABLE queue ADD COLUMN wecken_bis REAL NOT NULL DEFAULT 0")
        self.db.commit()
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @synchronisiert
    def bereinigen(self, now):
        with self.db:
            count = self.db.execute("SELECT count(*) FROM queue WHERE ablauf <= ?", (now,)).fetchone()[0]
            self.db.execute("DELETE FROM queue WHERE ablauf <= ?", (now,))
            self.db.execute("DELETE FROM dedupe WHERE ablauf <= ?", (now,))
            self.db.execute("UPDATE zaehler SET anzahl=anzahl+? WHERE name='abgelaufen'", (count,))
        if count:
            self.alarm({"ereignis": "queue_ttl_alarm", "anzahl": count})
        return count

    @synchronisiert
    def annehmen(self, message_id, body, now, wecken_bis=0):
        self.bereinigen(now)
        with self.db:
            # BEGIN IMMEDIATE serialisiert auch mehrere Prozesse vor der Limitprüfung.
            self.db.execute("BEGIN IMMEDIATE")
            if self.db.execute("SELECT 1 FROM dedupe WHERE message_id=?", (message_id,)).fetchone():
                return None, False
            count, size = self.db.execute("SELECT count(*),coalesce(sum(length(body)),0) FROM queue").fetchone()
            if count >= self.maximum or size + len(body) > self.byte_limit:
                raise OverflowError("queue_voll")
            cursor = self.db.execute("INSERT INTO queue(message_id,body,eingang,ablauf,wecken_bis) VALUES(?,?,?,?,?)",
                                     (message_id, body, now, now + self.ttl, wecken_bis))
            entry_id = cursor.lastrowid
            self.db.execute("INSERT INTO dedupe VALUES(?,?)", (message_id, now + 7 * 86400))
            self.db.execute("UPDATE zaehler SET anzahl=anzahl+1 WHERE name='eingegangen'")
        # Erst nach Commit UND erneuter Lesbarkeit wird der HTTP-Eingang bestätigt.
        check = self.db.execute("SELECT body FROM queue WHERE id=?", (entry_id,)).fetchone()
        if not check or check[0] != body:
            raise OSError("queue_nicht_lesbar")
        return entry_id, True

    @synchronisiert
    def eintraege(self, now):
        self.bereinigen(now)
        return [{"id": row[0], "body": row[1], "eingang": row[2],
                 "wecken_bis": row[3], "darf_wecken": row[3] > 0 and now <= row[3]} for row in
                self.db.execute("SELECT id,body,eingang,wecken_bis FROM queue ORDER BY id")]

    @synchronisiert
    def quittieren(self, entry_id):
        with self.db:
            cursor = self.db.execute("DELETE FROM queue WHERE id=?", (entry_id,))
            if cursor.rowcount:
                self.db.execute("UPDATE zaehler SET anzahl=anzahl+1 WHERE name='zugestellt'")

    def zustellen(self, sender, now):
        delivered = 0
        started = time.monotonic()
        # Während einer langsamen Upstream-Antwort muss der Eingang weiter speichern können.
        with self.delivery_lock:
            for row in self.eintraege(now):
                current = now + max(0, time.monotonic() - started)
                allowed = row["darf_wecken"] and current <= row["wecken_bis"]
                if not sender(row["id"], row["body"], allowed):
                    break
                self.quittieren(row["id"])
                delivered += 1
        return delivered

    @synchronisiert
    def metriken(self, now):
        counters = dict(self.db.execute("SELECT name,anzahl FROM zaehler"))
        oldest = self.db.execute("SELECT min(eingang),count(*) FROM queue").fetchone()
        counters["offen"] = oldest[1]
        counters["eingegangen_minus_zugestellt"] = counters["eingegangen"] - counters["zugestellt"]
        counters["aeltester_alter_s"] = max(0, now - oldest[0]) if oldest[0] is not None else 0
        return counters

    @synchronisiert
    def close(self):
        self.db.close()


class Eingang:
    def __init__(self, cfg, queue, logger, clock=time.time):
        self.cfg, self.queue, self.logger, self.clock = cfg, queue, logger, clock
        self.rates = collections.OrderedDict()
        self.invalid_rates, self.invalid_cache = collections.OrderedDict(), collections.OrderedDict()
        self.lock = threading.RLock()

    def zaehlen(self, rates, peer, now, limit):
        for source, (start, _) in list(rates.items()):
            if now - start >= 60 or now < start:
                del rates[source]
        if peer not in rates and len(rates) >= 4096:
            return False
        start, count = rates.get(peer, (now, 0))
        rates[peer] = (start, count + 1)
        return count < limit

    @synchronisiert
    def annehmen(self, body, peer):
        now = self.clock()
        if len(body) > BODY_LIMIT:
            return 403, {"fehler": "callback_ungueltig"}
        fingerprint = (peer, hashlib.sha256(body).digest())
        previous = self.invalid_cache.get(fingerprint)
        start, invalid_count = self.invalid_rates.get(peer, (now, 0))
        invalid_limit = self.cfg.get("invalid_rate_per_minute", 30)
        # Wiederholte bekannte Fehl-MACs billig ablehnen; gültige Bodies bleiben prüfbar.
        if (previous is not None and 0 <= now - previous < 60 and 0 <= now - start < 60
                and invalid_count >= invalid_limit):
            return 429, {"fehler": "ungueltige_ratenlimit"}
        try:
            fields = pruefen(body, geheimnis(self.cfg["secret_file"]), self.cfg["gateway_id"], now)
        except (ValueError, UnicodeError):
            allowed = self.zaehlen(self.invalid_rates, peer, now, invalid_limit)
            self.invalid_cache[fingerprint] = now
            self.invalid_cache.move_to_end(fingerprint)
            while len(self.invalid_cache) > 4096:
                self.invalid_cache.popitem(last=False)
            return (403 if allowed else 429), {"fehler": "callback_ungueltig"}
        except OSError:
            self.logger.emit({"ereignis": "queue_annahme_alarm"}, now)
            return 503, {"fehler": "warteschlange_nicht_bereit"}
        # Das Limit zählt ausschließlich geprüfte MACs und steuert nur das Schattenereignis.
        within_rate = self.zaehlen(self.rates, peer, now, self.cfg.get("rate_per_minute", 60))
        darf_wecken = fields["darf_wecken"] and fields["from"] == self.cfg["wake_sender"] and within_rate
        try:
            entry, new = self.queue.annehmen(fields["messageId"], body, now,
                                             wecken_bis=int(fields["date"]) + 600 if darf_wecken else 0)
        except (OSError, sqlite3.Error, OverflowError):
            self.logger.emit({"ereignis": "queue_annahme_alarm"}, now)
            return 503, {"fehler": "warteschlange_nicht_bereit"}
        if new and darf_wecken:
            # Der Inhalt ist verschlüsselt: jede Nachricht dieser ID ist ein Ereignis.
            self.logger.emit({"ereignis": "absender_freigegeben", "entscheidung": "wuerde_wecken", "weg": 5}, now)
        return 200, {"gespeichert": True, "duplikat": not new, "eingangs_id": entry}


def upstream_sender(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValueError("upstream_ungueltig")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def senden(entry_id, body, darf_wecken=False):
        request = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": "application/x-www-form-urlencoded", "X-GreenBuddy-Eingangs-ID": str(entry_id),
            "X-GreenBuddy-Darf-Wecken": "1" if darf_wecken else "0"})
        try:
            with opener.open(request, timeout=3) as response:
                return 200 <= response.status < 300 and response.headers.get("X-GreenBuddy-Quittung") == str(entry_id)
        except (OSError, ValueError, urllib.error.URLError):
            return False
    return senden


def host_wach(path, host):
    # Unerreichbarkeit ist kein Schlafbeleg; ohne Registerbeleg keine Zustellung.
    try:
        row = Register(path).lesen()["hosts"].get(host)
        return bool(row and row["phase"] == "angemeldet")
    except (ValueError, OSError):
        return False


def client_ip(peer, forwarded):
    if peer == "127.0.0.1" and forwarded:
        try:
            return str(ipaddress.ip_address(forwarded.split(",", 1)[0].strip()))
        except ValueError:
            pass
    return peer


class Server(http.server.ThreadingHTTPServer):
    # Beim Schließen zuerst die laufenden Handler abwarten, dann die SQLite-Verbindung.
    daemon_threads = False


def handler(eingang):
    class Handler(http.server.BaseHTTPRequestHandler):
        timeout = 5
        def log_message(self, format, *args):
            pass  # Keine Pfade, Header, Absender-IDs oder verschlüsselten Inhalte loggen.

        def antwort(self, status, data):
            payload = json.dumps(data, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if abgeschaltet(eingang.cfg):
                eingang.logger.emit({"entscheidung": "abgeschaltet"}, heartbeat=True)
                self.antwort(503, {"entscheidung": "abgeschaltet"})
            elif self.path == "/health":
                self.antwort(200, {"warteschlange": eingang.queue.metriken(eingang.clock()), "modus": "beta1"})
            else:
                self.antwort(404, {})

        def do_POST(self):
            if abgeschaltet(eingang.cfg):
                eingang.logger.emit({"entscheidung": "abgeschaltet"}, heartbeat=True)
                self.antwort(503, {"entscheidung": "abgeschaltet"})
                return
            if self.path != "/threema/incoming":
                self.antwort(404, {})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,8}", lengths[0]):
                self.antwort(411, {})
                return
            size = int(lengths[0])
            if size > BODY_LIMIT:
                self.antwort(413, {})
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
                self.antwort(415, {})
                return
            self.connection.settimeout(self.timeout)
            try:
                body = self.rfile.read(size)
                if len(body) != size:
                    raise OSError("body_unvollstaendig")
                peer = client_ip(self.client_address[0], self.headers.get("X-Forwarded-For"))
                status, reply = eingang.annehmen(body, peer)
            except OSError:
                status, reply = 400, {}
            self.antwort(status, reply)
    return Handler


def main():
    parser = argparse.ArgumentParser(description="Webhook-Baustein; beta.1 installiert ihn nicht")
    parser.add_argument("--config", default="/etc/greenbuddy/webhook.json")
    args = parser.parse_args()
    cfg = laden(args.config)
    if cfg.get("listen", "127.0.0.1") != "127.0.0.1":
        raise ValueError("webhook_nur_loopback")
    logger = JsonLog(cfg["log"])
    queue = Warteschlange(cfg["queue"], alarm=lambda row: logger.emit(row))
    incoming = Eingang(cfg, queue, logger)
    sender = upstream_sender(cfg["upstream"])
    server = Server(("127.0.0.1", cfg.get("port", 8787)), handler(incoming))
    server.timeout = 1
    try:
        while True:
            if abgeschaltet(cfg):
                logger.emit({"entscheidung": "abgeschaltet"}, heartbeat=True)
            else:
                now = time.time()
                queue.bereinigen(now)
                if host_wach(cfg.get("register", "/var/lib/greenbuddy/register.json"), "vhost01"):
                    queue.zustellen(sender, now)
                metrics = queue.metriken(now)
                logger.emit({"ereignis": "queue_heartbeat", "metriken": metrics,
                             "alarm": metrics["aeltester_alter_s"] > 300}, now, heartbeat=True)
            server.handle_request()
    finally:
        server.server_close()
        queue.close()
