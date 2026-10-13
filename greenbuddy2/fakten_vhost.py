"""Lokale Tatsachen; jeder Abfragefehler bleibt ausdrücklich unklar."""

import datetime as dt
import ipaddress
import json
import math
import os
import pwd
import re
import subprocess
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from . import legitim
from .konfig import geheimnis, validieren


def command(args, timeout=10, env=None):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          env=env or {"PATH": "/usr/sbin:/usr/bin", "LANG": "C"})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("api_redirect")


def api(port, path, headers, opener=None):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path),
                                 headers=dict(headers, Accept="application/json"))
    op = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with op.open(req, timeout=2) as response:
            body = response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        # Auch 401-Antworten schließen; keinen Fehlerbody oder Token weiterreichen.
        error.close()
        raise ValueError("api_http_fehler") from None
    if len(body) > 1024 * 1024:
        raise ValueError("api_gross")
    return json.loads(body)


def jellyfin(path, opener=None):
    try:
        token = geheimnis(path)
        if any(c in token for c in ('"', "\\")):
            raise ValueError("schluessel_format")
        rows = api(8096, "/Sessions", {"Authorization": 'MediaBrowser Token="%s"' % token}, opener)
        if not isinstance(rows, list) or any(not isinstance(x, dict) for x in rows):
            raise ValueError("jellyfin_schema")
        return bool(rows), None
    except Exception:
        return False, "jellyfin_unklar"


def mdstat(text):
    vetos, arrays = [], []
    for block in re.split(r"(?m)(?=^md\d+\s*:)", text):
        if not re.match(r"md\d+\s*:", block):
            continue
        name = block.split()[0]
        # Der inaktive IMSM-Container ist kein degradiertes Daten-Array.
        pairs = re.findall(r"\[(\d+)/(\d+)\]", block)
        if " raid" in block and not pairs:
            raise ValueError("raid_schema")
        for total, members in pairs:
            if int(members) < int(total):
                vetos.append("raid_degradiert")
            arrays.append({"name": name, "soll": int(total), "ist": int(members)})
        if re.search(r"\b(resync|recovery|check|reshape)\b", block):
            vetos.append("raid_aktion")
    if not arrays:
        raise ValueError("raid_fehlt")
    return sorted(set(vetos)), arrays


def loginctl_list(text):
    result = []
    for line in text.splitlines():
        cols = line.split()
        if not cols:
            continue
        if len(cols) < 4 or not cols[1].isdigit() or not re.fullmatch(r"[A-Za-z0-9_-]+", cols[0]):
            raise ValueError("loginctl_schema")
        states = [c for c in cols[3:] if c in ("active", "online", "closing")]
        if len(states) != 1:
            raise ValueError("loginctl_zustand")
        result.append({"id": cols[0], "state": states[0]})
    return result


# Immer gezählt, auch bei Loopback-Gegenstelle: Plex, lazymc, SSH, Threema-Bot, Jellyfin, Samba, Fileserver.
FESTE_PORTS = (32400, 25565, 22, 8443, 8096, 445, 8081)
AKTIV = ("active", "activating", "deactivating", "reloading", "refreshing")
LADEZUSTAENDE = ("loaded", "not-found", "masked", "error", "bad-setting", "stub", "merged")
ZUSTAENDE = AKTIV + ("inactive", "failed", "maintenance")


def ss_adresse(text):
    """'192.168.1.110:8081', '[::ffff:10.0.0.2]:445', '127.0.0.53%lo:53' -> (Adresse oder None, Port)."""
    host, _, port = text.rpartition(":")
    if not host or not re.fullmatch(r"[0-9]{1,5}", port) or int(port) > 65535:
        raise ValueError("ss_schema")
    if host.startswith("["):
        host = host[1:host.index("]")]
    host = host.split("%", 1)[0]
    if host == "*":
        return None, int(port)
    address = ipaddress.ip_address(host)
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address, int(port)


def ss_zeilen(text):
    """(Lokal, Gegenstelle) je Zeile; mit oder ohne Zustandsspalte."""
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        # Ohne Zustands-Spalte: Recv-Q Send-Q Local Peer.
        start = 2 if fields[0].isdigit() else 3
        if len(fields) < start + 2:
            raise ValueError("ss_schema")
        rows.append((fields[start], fields[start + 1]))
    return rows


def verbindung_schluessel(local, peer):
    own, other = ss_adresse(local), ss_adresse(peer)
    if own[0] is None or other[0] is None:
        raise ValueError("ss_schema")
    return own + other


def verbindungs_infos(text):
    """{Schlüssel: (lastrcv in ms, bytes_acked oder None)} aus 'ss -Htni'.

    Unter jeder Socketzeile steht eingerückt die Infozeile. lastrcv = seit wann die Gegenstelle keine
    Daten mehr gesendet hat; ss lässt es weg, wenn es 0 ist (eben erst Daten empfangen) -> 0.
    """
    infos, key, info = {}, None, ""
    for line in text.splitlines() + [""]:
        if line[:1].isspace():
            if key is None:
                raise ValueError("ss_schema")
            info += " " + line
            continue
        if key is not None:
            werte = {}
            for name in ("lastrcv", "bytes_acked"):
                match = re.search(r"(?<!\S)%s:([0-9]+)(?!\S)" % name, info)
                werte[name] = int(match.group(1)) if match else None
            infos[key] = (werte["lastrcv"] or 0, werte["bytes_acked"])
        key, info = None, ""
        if line.strip():
            key = verbindung_schluessel(*ss_zeilen(line)[0])
    return infos


def verbindungen_zaehlen(lauschend, aufgebaut, ausnahmen=(25565,), ruhend=(), ruhe_ports=(), wan=None,
                         gebunden=()):
    """Aufgebaute Verbindungen auf lokal lauschenden Ports = jemand nutzt einen Dienst.

    Feste Ports zählen immer. Jeder andere lauschende Port zählt, sobald die Gegenstelle
    nicht der Host selbst ist (Loopback oder dieselbe Adresse wie lokal). Ausnahmen bleiben Diagnose.
    Auf ruhe_ports zählt eine Verbindung aus `ruhend` (Gegenstelle sendet nichts mehr) nur als Diagnose.
    Mit einem Filter `wan` (b6) zählt eine WAN-Gegenstelle nur, wenn sie legitim ist; die übrigen stehen
    je Grund ("wan", "haarnadel") und Port in `ignoriert`. Ohne Filter zählt jede wie in beta.5.
    Eine Verbindung aus `gebunden` (früher als legitime WAN-Verbindung gezählt) zählt weiter, solange sie
    aufgebaut ist, auch wenn der Eintrag ihrer Quelle verfallen ist; zurück kommen die noch gebundenen.
    """
    ports = {ss_adresse(local)[1] for local, _ in ss_zeilen(lauschend)}
    counts = {port: 0 for port in FESTE_PORTS}
    still, ignoriert, bindung = {}, {"wan": {}, "haarnadel": {}}, set()
    for local, peer in ss_zeilen(aufgebaut):
        key = verbindung_schluessel(local, peer)
        own, port, other = key[0], key[1], key[2]
        if port not in FESTE_PORTS and not (port in ports and not (other.is_loopback or other == own)):
            continue
        grund = wan.grund(port, other) if wan is not None else None
        if grund == "wan" and key in gebunden:
            # Review 13.10.26: Ein Download über eine Anfrage schickt nach dem ClientHello nur ACKs, der
            # Mitschnitt frischt die Quelle nie auf; nach dessen Neustart beginnt die Datei leer.
            grund = None
        if grund:
            ignoriert[grund][port] = ignoriert[grund].get(port, 0) + 1
            continue
        if key in gebunden or (wan is not None and wan.wan(other)):
            # Ohne Filter (Rückfallebene) wird nichts neu gebunden, Gebundenes bleibt.
            bindung.add(key)
        counts[port] = counts.get(port, 0) + 1
        if port in ruhe_ports and key in ruhend:
            still[port] = still.get(port, 0) + 1
    vetos = ["verbindung:%d" % port for port, count in sorted(counts.items())
             if count > still.get(port, 0) and port not in ausnahmen]
    return counts, vetos, still, ignoriert, bindung


def transienten(text):
    """Aktive run-*-Units aus 'systemctl list-units --plain --no-legend'."""
    units = []
    for line in text.splitlines():
        cols = line.split()
        if cols and cols[0] in ("●", "*", "×"):
            cols = cols[1:]
        if not cols:
            continue
        if (len(cols) < 4 or not re.fullmatch(r"run-[^/\s]+\.(service|scope)", cols[0])
                or cols[1] not in LADEZUSTAENDE or cols[2] not in ZUSTAENDE):
            raise ValueError("transient_schema")
        if cols[2] in AKTIV:
            units.append(cols[0])
    return units


def als_benutzer(user, args):
    """systemctl am User-Manager: User-Bus direkt, ohne PAM-Sitzung."""
    # "-M user@" scheitert in der gehaerteten Unit, weil systemctl dafuer eine transiente Unit
    # am System-Manager anlegt.
    konto = pwd.getpwnam(user)
    return ["/usr/bin/setpriv", "--reuid=%d" % konto.pw_uid, "--regid=%d" % konto.pw_gid, "--init-groups",
            "/usr/bin/env", "-i", "PATH=/usr/bin", "XDG_RUNTIME_DIR=/run/user/%d" % konto.pw_uid,
            "/usr/bin/systemctl", "--user"] + list(args)


def transienten_abfragen(user=None, runner=command):
    """systemd-run-Läufe (run-*.service/.scope) im System- oder einem User-Manager."""
    args = ["list-units", "--plain", "--no-legend", "--no-pager", "--", "run-*.service", "run-*.scope"]
    result = runner(als_benutzer(user, args) if user else ["/usr/bin/systemctl"] + args)
    if result.returncode:
        raise ValueError("transient_abfragefehler")
    return transienten(result.stdout)


def loginctl_remote(text):
    data = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    if (data.get("Remote") not in ("yes", "no") or not data.get("Type")
            or data.get("State") not in ("active", "online", "closing")):
        raise ValueError("loginctl_schema")
    return data["Remote"] == "yes" and data["State"] in ("active", "online")


def prozesse(root="/proc"):
    rows = []
    for path in Path(root).iterdir():
        if not path.name.isdigit():
            continue
        try:
            args = (path / "cmdline").read_bytes().split(b"\0")
            rows.append([a.decode("utf-8", "replace") for a in args if a])
        except (FileNotFoundError, ProcessLookupError):
            continue
    return rows


def minecraft(rows, pattern=".jar", connections=None):
    # lazymc und Scanner-Verbindungen sind absichtlich kein Nutzungssignal.
    return any(args and os.path.basename(args[0]) == "java"
               and any(pattern in arg for arg in args[1:]) for args in rows)


def claude_laeuft(rows):
    for args in rows:
        if any(os.path.basename(a) == "run-task.sh" for a in args):
            return True
        for index, arg in enumerate(args):
            if os.path.basename(arg) == "claude" and any(
                    a in ("-p", "--print") or a.startswith("--print=") for a in args[index + 1:]):
                return True
    return False


def coach_alter(path, now):
    with Path(path).open("rb") as source:
        source.seek(0, 2)
        size = source.tell()
        source.seek(max(0, size - 2 * 1024 * 1024))
        if source.tell():
            source.readline()
        lines = source.read().splitlines()
    for line in reversed(lines):
        row = json.loads(line)
        headers = row.get("request", {}).get("headers", {})
        ua = headers.get("User-Agent", headers.get("user-agent", []))
        if isinstance(ua, str):
            ua = [ua]
        if any(str(value).startswith("ThreemaGateway") for value in ua):
            stamp = row.get("ts", row.get("timestamp"))
            if isinstance(stamp, str):
                stamp = dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
            if type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp > now + 30:
                raise ValueError("coach_zeit")
            return max(0, now - stamp)
    raise ValueError("coach_eintrag_fehlt")


def coach_alter_journal(unit, now, window, runner):
    """Nur ein lesbares Journal mit Unit-Einträgen belegt Ruhe im Fenster."""
    since = int(now - window)
    result = runner(["journalctl", "--no-pager", "-q", "-o", "json", "--since=@%d" % since,
                     "_SYSTEMD_USER_UNIT=" + unit])
    if result.returncode:
        raise ValueError("coach_journal_fehler")
    newest = None
    entries = 0
    for line in result.stdout.splitlines():
        row = json.loads(line)
        entries += 1
        message = row.get("MESSAGE")
        if isinstance(message, list) and all(type(x) is int for x in message):
            message = bytes(message).decode("utf-8", "replace")
        if not isinstance(message, str):
            raise ValueError("coach_journal_message_unklar")
        if "ThreemaGateway" in message:
            stamp = int(row["__REALTIME_TIMESTAMP"]) / 1000000
            newest = stamp if newest is None else max(stamp, newest)
    if not entries:
        raise ValueError("coach_journal_leer")
    if newest is None:
        return window
    if not math.isfinite(newest) or newest > now + 30:
        raise ValueError("coach_zeit")
    return max(0, now - newest)


def ansprueche(path, now, host="vhost01"):
    busy, unknown, count = [], [], 0
    if not Path(path).is_dir():
        return busy, ["ansprueche_unklar"], count
    for file in sorted(Path(path).glob("*.json")):
        try:
            if file.is_symlink():
                raise ValueError("anspruch_symlink")
            row = json.loads(file.read_text())
            if (not isinstance(row, dict) or any(not isinstance(row.get(k), str) or not row[k]
                    for k in ("host", "dienst", "besitzer", "zyklus"))
                    or type(row.get("ablauf")) not in (int, float) or not math.isfinite(row["ablauf"])):
                raise ValueError("anspruch_schema")
            if row["host"] == host and row["ablauf"] > now:
                busy.append("anspruch")
                count += 1
        except Exception:
            unknown.append("anspruch_unklar")
    return busy, unknown, count


class Sammler:
    def __init__(self, cfg, runner=command, api_call=api, proc=prozesse, besitzer=None):
        self.cfg, self.runner, self.api_call, self.proc = cfg, runner, api_call, proc
        # Erlaubte UIDs der Legitim-Datei; None = root und gb-mitschnitt (bei jedem Lesen nachgeschlagen).
        self.besitzer = besitzer
        self.previous_bandwidth = {}
        # bytes_acked je Verbindung aus der Vorrunde (nur Ruhe-Ports; unklare Runde vergisst alles).
        self.previous_acked = {}
        # b6: als legitime WAN-Verbindung gezählte Schlüssel; eine unklare Runde vergisst hier nichts.
        self.gebunden = set()

    def sammeln(self, now):
        validieren(self.cfg)
        cfg, busy, unknown, signals, facts = self.cfg, [], [], [], {}

        def pruefen(name, action):
            try:
                action()
            except Exception:
                unknown.append(name + "_unklar")

        def plex():
            token = ET.parse(cfg["plex_preferences"]).getroot().get("PlexOnlineToken")
            if not token or any(c in token for c in "\r\n"):
                raise ValueError("plex_token")
            headers = {"X-Plex-Token": token, "X-Plex-Client-Identifier": "greenbuddy2-beobachter"}
            sessions = container(self.api_call(32400, "/status/sessions", headers), "Metadata")
            rows = container(self.api_call(32400, "/statistics/bandwidth?timespan=6", headers), "StatisticsBandwidth")
            signal, fresh, sources, reset = bandwidth(rows, self.previous_bandwidth, cfg, now)
            self.previous_bandwidth = fresh
            facts["plex"] = {"sitzungen": len(sessions), "bandbreite_signal": signal,
                             "quellen_anzahl": len(sources), "zaehler_reset": reset}
            if sessions or signal:
                signals.append("plex")
            if reset:
                unknown.append("bandbreitenzaehler_gefallen")

        pruefen("plex", plex)
        signal, error = jellyfin(cfg["jellyfin_key_file"])
        if error:
            unknown.append(error)
        if signal:
            signals.append("jellyfin")
        facts["jellyfin_sitzung"] = signal if not error else None

        def processes():
            rows = self.proc()
            java = minecraft(rows, cfg["minecraft_argument"])
            claude = claude_laeuft(rows)
            mdmon = any(a and os.path.basename(a[0]) == "mdmon" for a in rows)
            facts.update(minecraft_java=java, claude_laeuft=claude, mdmon=mdmon)
            if java:
                signals.append("minecraft")
            if claude:
                signals.append("claude")
            if not mdmon:
                unknown.append("mdmon_fehlt")

        pruefen("prozesse", processes)

        def ssh():
            result = self.runner(["loginctl", "list-sessions", "--no-legend"])
            if result.returncode:
                raise ValueError("loginctl_fehler")
            active = closing = 0
            for row in loginctl_list(result.stdout):
                if row["state"] == "closing":
                    # logind hält eine abgemeldete Sitzung nur, solange in ihrem Scope noch Prozesse
                    # laufen (tmux, nohup, Hintergrundjobs): unbekannter Verbraucher = Veto.
                    closing += 1
                    continue
                result = self.runner(["loginctl", "show-session", row["id"], "-p", "Remote", "-p", "Type", "-p", "State"])
                if result.returncode:
                    raise ValueError("loginctl_fehler")
                active += int(loginctl_remote(result.stdout))
            facts["ssh_remote"] = active
            facts["sitzungen_closing"] = closing
            if active:
                busy.append("ssh_remote")
                signals.append("ssh")
            if closing:
                busy.append("sitzung_closing")

        pruefen("ssh", ssh)
        for unit, user in [(x, None) for x in cfg["system_jobs"]] + [(u, p) for p, u in cfg["user_jobs"]]:
            try:
                if properties(unit, user, runner=self.runner, optional_jobs=cfg.get("optional_jobs", [])):
                    busy.append("job:" + unit)
            except Exception:
                unknown.append("job_unklar:" + unit)
        laufend = 0
        for user in [None] + list(cfg.get("transient_benutzer", [])):
            # systemd-run-Läufe stehen in keiner festen Jobliste.
            try:
                units = transienten_abfragen(user, self.runner)
            except Exception:
                unknown.append("transient_unklar" + (":" + user if user else ""))
                continue
            laufend += len(units)
            busy.extend("transient:" + (user + ":" if user else "") + unit for unit in units)
        facts["transienten"] = laufend

        def raid():
            vetos, arrays = mdstat(Path("/proc/mdstat").read_text())
            facts["raid"] = arrays
            facts["raid_degradiert"] = "raid_degradiert" in vetos
            if cfg.get("raid_degradiert_erlaubt") is True:
                # Ausdrückliche Freigabe (Betreiber, 06.10.26) gilt nur für die fehlende Redundanz;
                # resync/recovery/check/reshape bleiben ein Veto.
                vetos = [v for v in vetos if v != "raid_degradiert"]
            busy.extend(vetos)

        pruefen("raid", raid)

        def gpu():
            result = self.runner(["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory", "--format=csv,noheader"])
            if result.returncode:
                raise ValueError("gpu_fehler")
            count = len([line for line in result.stdout.splitlines() if line.strip()])
            facts["gpu_prozesse"] = count
            if count:
                busy.append("gpu")

        pruefen("gpu", gpu)

        def coach():
            if cfg.get("coach_journal_unit"):
                age = coach_alter_journal(cfg["coach_journal_unit"], now, cfg["coach_recent_seconds"], self.runner)
            else:
                age = coach_alter(cfg["coach_log"], now)
            facts["coach_alter_s"] = round(age)
            if age < cfg["coach_recent_seconds"]:
                signals.append("coach")

        pruefen("coach", coach)
        veto, unclear, count = ansprueche(cfg["ansprueche"], now)
        busy.extend(veto)
        unknown.extend(unclear)
        facts["ansprueche"] = count

        def verbindungen():
            ruhe_ports = cfg.get("verbindung_ruhe_ports", [])
            ruhend, vorher, self.previous_acked = set(), self.previous_acked, {}
            if ruhe_ports:
                # Vor der Gesamtliste: eine dazwischen neu aufgebaute Verbindung zählt dann sicher.
                filter_ = sum((["or"] * bool(i) + ["sport", "=", ":%d" % p] for i, p in enumerate(ruhe_ports)), [])
                info = self.runner(["ss", "-Htni", "state", "established", "("] + filter_ + [")"])
                if info.returncode:
                    raise ValueError("ss_fehler")
                infos = verbindungs_infos(info.stdout)
                schwelle_ms = cfg.get("verbindung_ruhe_sekunden", 900) * 1000
                limit = cfg.get("verbindung_ruhe_bytes", 65536)
                for key, (last, acked) in infos.items():
                    # Ruhend nur, wenn die App nichts mehr fragt UND der Server kaum sendet: ein
                    # Download über eine einzige Anfrage bekommt vom Client nur ACKs (Review 12.10.26).
                    alt = vorher.get(key)
                    if last >= schwelle_ms and acked is not None and alt is not None and 0 <= acked - alt <= limit:
                        ruhend.add(key)
                self.previous_acked = {key: acked for key, (_, acked) in infos.items() if acked is not None}
            # b6: WAN-Gegenstellen zählen nur, wenn der Mitschnitt sie für legitim hält; jeder Zweifel an
            # der Legitim-Datei ist Diagnose (nie unklar) und lässt jede Verbindung zählen wie in beta.5.
            facts["legitim"], wan = legitim.filter_laden(cfg, now, self.besitzer)
            lauschend = self.runner(["ss", "-Htln"])
            aufgebaut = self.runner(["ss", "-Htn", "state", "established"])
            if lauschend.returncode or aufgebaut.returncode:
                raise ValueError("ss_fehler")
            counts, vetos, still, ignoriert, self.gebunden = verbindungen_zaehlen(
                lauschend.stdout, aufgebaut.stdout, cfg.get("verbindung_ausnahmen", [25565]), ruhend, ruhe_ports,
                wan, self.gebunden)
            facts["verbindungen"] = counts
            facts["verbindungen_ruhend"] = still
            facts["verbindungen_wan_ignoriert"] = ignoriert["wan"]
            facts["verbindungen_haarnadel"] = ignoriert["haarnadel"]
            busy.extend(vetos)

        pruefen("verbindungen", verbindungen)
        return {"vetos": sorted(set(busy)), "unklar": sorted(set(unknown)),
                "nutzung": sorted(set(signals)), "fakten": facts}


def properties(unit, user=None, runner=command, optional_jobs=()):
    args = ["/usr/bin/systemctl", "show", "-p", "LoadState", "-p", "ActiveState",
            "-p", "MainPID", "-p", "ControlPID", unit]
    if user:
        args = als_benutzer(user, args[1:])
    result = runner(args)
    if result.returncode != 0:
        raise ValueError("job_abfragefehler")
    data = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    load, state = data.get("LoadState"), data.get("ActiveState")
    if load == "not-found":
        if unit in optional_jobs:
            return False
        raise ValueError("job_fehlt")
    if load != "loaded" or state not in {"active", "activating", "deactivating", "inactive", "failed"}:
        raise ValueError("job_schema")
    if state == "failed":
        raise ValueError("job_fehlgeschlagen")
    if any(not re.fullmatch(r"[0-9]+", data.get(k, "")) for k in ("MainPID", "ControlPID")):
        raise ValueError("job_schema")
    return state != "inactive" or int(data["MainPID"]) != 0 or int(data["ControlPID"]) != 0


def container(data, name):
    mc = data["MediaContainer"]
    n, values = mc["size"], mc.get(name, [])
    # /statistics/bandwidth zaehlt in size alle Listen (Device + Account + StatisticsBandwidth),
    # die anderen Endpunkte nur die eine Liste (gemessen 06.10.26: size 15 = 2 + 1 + 12).
    alle = sum(len(v) for v in mc.values() if isinstance(v, list))
    if (type(n) is not int or n < 0 or not isinstance(values, list)
            or n not in (len(values), alle) or any(not isinstance(x, dict) for x in values)):
        raise ValueError("plex_schema")
    return values


def bandwidth(values, old, cfg, wall):
    """Nutzung = Bytesumme je (Konto, Gerät, LAN) in den letzten 180 s über der Schwelle.

    Plex liefert ein rollendes Fenster von ~130–160 s; alte Buckets fallen laufend hinten
    heraus (gemessen 06.10.26). Ein Neustart der Zählung zeigt sich nur an einem kleiner
    gewordenen Zähler oder an einem Bucket, der mitten aus dem aktuellen Fenster fehlt.
    """
    fresh, sums = {}, {}
    ignored = {tuple(x) for x in cfg["self_triples"]}
    limit = cfg.get("bandbreite_schwelle_bytes", 262144)
    for v in values:
        fields = [v["at"], v["accountID"], v["deviceID"], v["bytes"]]
        if (any(type(x) is not int or x < 0 for x in fields) or type(v["lan"]) is not bool
                or fields[0] > wall + 30):
            raise ValueError("bandbreite_schema")
        stamp, account, device, count = fields
        key, triple = (stamp, account, device, v["lan"]), (account, device, v["lan"])
        if key in fresh:
            raise ValueError("bandbreite_doppelt")
        fresh[key] = count
        if stamp >= wall - 180:
            sums[triple] = sums.get(triple, 0) + count
    # Auch bei gefilterten Kennungen Vorsicht: ein gefallener Zähler ist ein Neustart.
    reset = any(key in fresh and fresh[key] < count for key, count in old.items())
    if fresh:
        oldest = min(key[0] for key in fresh)
        reset = reset or any(key not in fresh and key[0] >= oldest for key in old)
    sources = {triple for triple, total in sums.items() if total >= limit and triple not in ignored}
    return bool(sources), fresh, [list(x) for x in sorted(sources)], reset
