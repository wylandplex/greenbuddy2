"""Einzige Zeitquelle lesen; RTC und vorhandene Timer ausschließlich prüfen."""

import argparse
import datetime as dt
import json
import re
import subprocess
import time
from pathlib import Path

from .konfig import AUS, abgeschaltet

REQUIRED = ("WACH_MORGEN", "WACH_ABEND", "TAGSCHLAF")


def minute(value):
    if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value):
        raise ValueError("zeitfenster_format")
    hour, minutes = map(int, value.split(":"))
    return hour * 60 + minutes


def parse(text):
    fields = {}
    for line in text.splitlines():
        match = re.fullmatch(r'\s*([A-Z][A-Z0-9_]*)\s*=\s*"?([^"\s#]+)"?\s*(?:#.*)?', line)
        if match and (match[1].endswith(("_START", "_END")) or match[1] == "VORLAUF_MIN"):
            if match[1] in fields:
                raise ValueError("zeitfenster_doppelt")
            fields[match[1]] = match[2]
    pairs = {}
    for name in set(k.rsplit("_", 1)[0] for k in fields if k != "VORLAUF_MIN") | set(REQUIRED):
        if name + "_START" not in fields or name + "_END" not in fields:
            raise ValueError("zeitfenster_fehlt")
        pairs[name] = (minute(fields[name + "_START"]), minute(fields[name + "_END"]))
        if pairs[name][0] == pairs[name][1]:
            raise ValueError("zeitfenster_leer")
    if not re.fullmatch(r"[0-9]+", fields.get("VORLAUF_MIN", "")):
        raise ValueError("vorlauf_fehlt")
    lead = int(fields["VORLAUF_MIN"])
    if not 0 <= lead <= 120:
        raise ValueError("vorlauf_ungueltig")
    return pairs, lead


def contains(minutes, start, end):
    return start <= minutes < end if start < end else minutes >= start or minutes < end


def wachfenster(pairs, lead, now):
    current = now.hour * 60 + now.minute
    active = []
    for name, (start, end) in pairs.items():
        beginning = (start - lead) % 1440
        if name == "TAGSCHLAF" or not contains(current, beginning, end):
            continue
        if name.endswith("SONNTAG_WINDOW"):
            day = (now.weekday() - 1) % 7 if beginning > end and current < end else now.weekday()
            if day != 6:
                continue
        active.append(name)
    return sorted(active)


def schlafphase(pairs, lead, now):
    return (contains(now.hour * 60 + now.minute, *pairs["TAGSCHLAF"])
            and not wachfenster(pairs, lead, now))


def next_wake(pairs, lead, epoch):
    # mktime nutzt die Host-Zeitzone samt Sommerzeit, ohne zoneinfo-Pflicht.
    day = dt.datetime.fromtimestamp(epoch).date()
    choices = []
    for offset in range(9):
        date = day + dt.timedelta(days=offset)
        for name, (start, _) in pairs.items():
            if name == "TAGSCHLAF" or (name.endswith("SONNTAG_WINDOW") and date.weekday() != 6):
                continue
            point = dt.datetime.combine(date, dt.time(start // 60, start % 60))
            wake = time.mktime(point.timetuple()) - lead * 60
            if wake > epoch:
                choices.append(wake)
    if not choices:
        raise ValueError("weckfenster_fehlt")
    return min(choices)


def timer_time(value):
    if type(value) in (int, float):
        return value / 1000000 if value > 100000000000 else value
    if not isinstance(value, str) or value in ("-", "n/a", ""):
        raise ValueError("timer_zeit_unklar")
    if value.isdigit():
        return timer_time(int(value))
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        for fmt in ("%a %Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S %Z"):
            try:
                parsed = dt.datetime.strptime(value, fmt)
                return (parsed.replace(tzinfo=dt.timezone.utc).timestamp() if value.endswith("UTC")
                        else time.mktime(parsed.timetuple()))
            except ValueError:
                pass
    raise ValueError("timer_zeit_unklar")


def timers_json(text):
    rows = json.loads(text)
    if not isinstance(rows, list):
        raise ValueError("timer_schema")
    return [{"unit": row["unit"], "next": timer_time(row["next"])} for row in rows
            if row.get("next") not in (None, "-", "n/a", 0, "0")]


def timers_text(text):
    result = []
    for line in text.splitlines():
        if not re.search(r"\S+\.timer\b", line):
            continue
        if line.lstrip().startswith("-"):
            continue
        match = re.match(r"\s*((?:\w+ )?\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \S+)", line)
        if not match:
            raise ValueError("timer_text_unklar")
        result.append({"unit": re.search(r"(\S+\.timer)\b", line)[1], "next": timer_time(match[1])})
    return result


def trocken(path, runner=subprocess.run, now=None):
    epoch = time.time() if now is None else now
    pairs, lead = parse(Path(path).read_text())
    args = ["systemctl", "list-timers", "--all", "--output=json", "--no-pager"]
    result = runner(args, capture_output=True, text=True, timeout=5, env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
    try:
        if result.returncode:
            raise ValueError("timer_json_fehler")
        timers = timers_json(result.stdout)
    except (ValueError, KeyError, TypeError):
        result = runner(["systemctl", "list-timers", "--all", "--no-pager"], capture_output=True,
                        text=True, timeout=5, env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
        if result.returncode:
            raise ValueError("timer_abfragefehler")
        timers = timers_text(result.stdout)
    return {"aktion": "trockenpruefung", "rtc_weckzeit": next_wake(pairs, lead, epoch),
            "timer_in_schlafphase": [r for r in timers if schlafphase(pairs, lead, dt.datetime.fromtimestamp(r["next"]))]}


def main():
    parser = argparse.ArgumentParser(description="Fenster und Timer ohne Änderung prüfen")
    parser.add_argument("--media-conf", default="/etc/media-staging.conf")
    args = parser.parse_args()
    try:
        row = {"entscheidung": "abgeschaltet"} if abgeschaltet() else trocken(args.media_conf)
    except Exception:
        row = {"entscheidung": "unklar", "grund": "fenster_oder_timer_unklar"}
    print(json.dumps(row, ensure_ascii=False))
    return int(row.get("entscheidung") == "unklar")
