"""tcpdump-Kindprozess: keine pcap-Datei, ausschließlich Metadaten im Log."""

import argparse
import collections
import ipaddress
import re
import selectors
import subprocess
import time
import signal

from .jsonlog import JsonLog
from .klassifikation import klassifizieren, plex_hash_gueltig
from .konfig import MITSCHNITT, abgeschaltet, laden
from .legitim import Schreiber
from .pcap import PcapStream, TcpAnfang, tcp_packet
from .wan import WanAdresse


def bpf(target):
    address = str(ipaddress.IPv4Address(target))
    at = "((tcp[12] & 0xf0) >> 2)"
    payload_length = "(ip[2:2] - ((ip[0] & 0xf) << 2) - %s)" % at
    return ("ip and dst host %s and tcp and "
            "(dst port 32400 or dst port 25565 or dst port 8443 or dst port 8096) and "
            "((tcp[13] & 0x12 = 0x02) or "
            "((dst port 32400 or dst port 8443) and %s > 0) or "
            "(dst port 25565 and %s > 0 and %s <= 512))") % (address, payload_length, payload_length, payload_length)


class Beobachter:
    def __init__(self, cfg, logger, maximum=2048, legitim=None):
        self.cfg, self.logger, self.maximum, self.legitim = cfg, logger, maximum, legitim
        self.flows = collections.OrderedDict()
        self.last_expiry = -float("inf")

    def kcfg(self, now):
        """Mit Legitim-Datei (b6) wie proxy01 (Weg 7): SNI-Label = LAN-IP des Ziels oder aktuelle WAN-IP,
        unbekannte WAN-IP = jede öffentliche IPv4. So ist "wuerde_wecken" hier dieselbe Entscheidung."""
        if self.legitim is None:
            return self.cfg
        wan = self.legitim.eigene(now)
        return dict(self.cfg, sni_label_ips=[self.cfg["target"]] + wan, sni_label_wan_unklar=not wan)

    def melden(self, key, flow, now):
        if flow["done"]:
            return
        data = flow["stream"].data() if flow["stream"] is not None else b""
        row = klassifizieren(key[0], key[3], data, self.kcfg(now))
        row.update(zeit=now, quell_ip=key[0])
        self.logger.emit(row, now)
        flow["done"] = True
        # Nach Entscheidung sofort alle Paketbytes verwerfen.
        flow["stream"] = None
        if self.legitim is not None and row["entscheidung"] == "wuerde_wecken" and row["quellklasse"] == "WAN":
            # LAN/VPN zählen in gb-schlaf ohnehin; spam und unklar werden nie legitim.
            self.legitim.eintragen(key[0], now)
            flow["legitim"] = now

    def ablaufen(self, now):
        if 0 <= now - self.last_expiry < 1:
            return
        self.last_expiry = now
        for key, flow in list(self.flows.items()):
            if not flow["done"] and now - flow["start"] >= 5:
                self.melden(key, flow, now)
            if now - flow["last"] >= 60:
                del self.flows[key]

    def paket(self, packet, now):
        if now - self.last_expiry >= 1 or now < self.last_expiry:
            self.ablaufen(now)
        if packet["target"] != self.cfg["target"] or packet["port"] not in (32400, 25565, 8443, 8096):
            return
        if self.legitim is not None:
            self.legitim.erfasst(now)
        key = (packet["source"], packet["sport"], packet["target"], packet["port"])
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.maximum:
                first, old = next(iter(self.flows.items()))
                self.melden(first, old, now)
                del self.flows[first]
            base = (packet["seq"] + int(packet["syn"])) & 0xffffffff
            flow = {"stream": None, "base": base, "start": now, "last": now, "done": False}
            self.flows[key] = flow
        flow["last"] = now
        if flow["done"]:
            if flow.get("legitim") is not None and not 0 <= now - flow["legitim"] < 10:
                # Weitere Anfragen im legitimen Fluss (Keep-alive): zuletzt gesehen wandert mit.
                flow["legitim"] = now
                self.legitim.eintragen(key[0], now)
            return
        if packet["port"] == 8096 and packet["syn"] and not packet["ack"]:
            self.melden(key, flow, now)
            return
        if not packet["payload"]:
            return
        try:
            if flow["stream"] is None:
                flow["stream"] = TcpAnfang(flow["base"])
            data = flow["stream"].add(packet["seq"] + int(packet["syn"]), packet["payload"])
            row = klassifizieren(packet["source"], packet["port"], data, self.kcfg(now))
            if row["entscheidung"] != "unklar":
                self.melden(key, flow, now)
        except ValueError:
            self.melden(key, flow, now)


def main():
    parser = argparse.ArgumentParser(description="Verbindungen ohne Wirkung beurteilen")
    parser.add_argument("--config", default="/etc/greenbuddy/mitschnitt.json")
    args = parser.parse_args()
    cfg = laden(args.config, MITSCHNITT)
    signal.signal(signal.SIGTERM, lambda signum, frame: (_ for _ in ()).throw(SystemExit(0)))
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", cfg["interface"]):
        raise ValueError("interface_ungueltig")
    logger = JsonLog(cfg["log"], ip_retention=True)
    legitim = None
    if plex_hash_gueltig(cfg.get("plex_hash")):
        legitim = Schreiber(cfg["legitim"], cfg["legitim_ttl_s"], cfg["legitim_max"], WanAdresse(cfg["wan_name"]),
                            logger)
    else:
        # Review 13.10.26: Ohne gültigen Hash (etwa die Vorlage nach einer Neuinstallation) würde keine
        # Plex-Quelle legitim; eine frische Datei mit leerer Liste hieße in gb-schlaf "ok" und ließe jede
        # WAN-Verbindung still fallen. Ohne Datei bleibt gb-schlaf bei beta.5 ("fehlt" bzw. "veraltet").
        logger.emit({"ereignis": "legitim_aus", "grund": "plex_hash"})
    observer = Beobachter(cfg, logger, legitim=legitim)
    child = None
    selector = selectors.DefaultSelector()
    try:
        while True:
            now = time.time()
            if abgeschaltet(cfg):
                if child:
                    child.terminate()
                    child.wait(timeout=5)
                    selector.unregister(child.stdout)
                    child.stdout.close()
                    child = None
                observer.flows.clear()
                logger.emit({"entscheidung": "abgeschaltet"}, now, heartbeat=True)
                time.sleep(1)
                continue
            if child is None:
                child = subprocess.Popen(["tcpdump", "-n", "-p", "-i", cfg["interface"], "-U", "-w", "-", "-s", "65535", bpf(cfg["target"])],
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                selector.register(child.stdout, selectors.EVENT_READ)
                stream = PcapStream()
            for key, _ in selector.select(timeout=1):
                data = key.fileobj.read1(65536)
                if not data:
                    logger.emit({"entscheidung": "unklar", "grund": "tcpdump_beendet"})
                    return 1
                for _, frame in stream.feed(data):
                    packet = tcp_packet(frame, stream.linktype)
                    if packet:
                        observer.paket(packet, time.time())
            observer.ablaufen(time.time())
            # Unter dem Abschalter schreibt niemand: die Datei veraltet, gb-schlaf fällt auf beta.5 zurück.
            if legitim is not None:
                legitim.takt(time.time())
            logger.emit({"entscheidung": "beobachten", "ereignis": "heartbeat"}, heartbeat=True)
    finally:
        selector.close()
        if child:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            child.stdout.close()
