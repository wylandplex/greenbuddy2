"""Wegwerf-Netz für den Stellvertreter-Netztest (nur innerhalb von unshare -Urnmpf --kill-child --mount-proc).

Der aufrufende Prozess spielt proxy01 (eth0 + wg0). host (vhost01), client, router (Box), wan, vpn und die
Brücke (switch) sind benannte Namensräume unter /run/netns. Sockets entstehen per setns im Zielnamensraum
und bleiben dort, auch wenn der Faden zurückwechselt; nur der aufrufende Faden wechselt.
"""

import contextlib
import ctypes
import errno
import os
import select
import socket
import struct
import subprocess
import threading
import time

CLONE_NEWNET = 0x40000000
ETH_P_ALL = 3
SO_TIMESTAMPNS = 35
BROADCAST = "ff:ff:ff:ff:ff:ff"
NULL_MAC = "00:00:00:00:00:00"

EIGEN = "02:00:00:00:00:01"       # proxy01-Ersatz eth0
ECHT = "00:00:5e:00:53:10"        # vhost01 (Beispielwert der Vorlagen, RFC 7042)
CLIENT_MAC = "02:00:00:00:00:18"
ROUTER_MAC = "02:00:00:00:00:fe"
PROXY, HOST, CLIENT, ROUTER = "192.168.1.100", "192.168.1.110", "192.168.1.18", "192.168.1.1"
VPN_PROXY, VPN_PEER = "10.0.0.1", "10.0.0.2"
WAN_TLS, WAN_MC, WAN_LISTE = "198.51.100.7", "198.51.100.8", "203.0.113.10"
ROLLEN = ("switch", "host", "client", "router", "wan", "vpn")
PORTS = {"proxy": "p-proxy", "host": "p-host", "client": "p-client", "router": "p-router"}

os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
_libc = ctypes.CDLL(None, use_errno=True)


def jetzt():
    # Wanduhr wie die Kernel-Zeitstempel des Mitschnitts (SO_TIMESTAMPNS).
    return time.time()


def sh(*args, eingabe=None, pruefen=True):
    run = subprocess.run(list(args), input=eingabe, capture_output=True, text=True, timeout=20)
    if pruefen and run.returncode:
        raise RuntimeError("%s: rc=%d %s" % (" ".join(args), run.returncode, run.stderr.strip()))
    return run


def _setns(fd, name):
    if _libc.setns(fd, CLONE_NEWNET):
        raise OSError(ctypes.get_errno(), "setns " + name)


@contextlib.contextmanager
def im(name):
    """Aufrufenden Faden in den Namensraum name versetzen; None = bleiben (proxy)."""
    if name is None:
        yield
        return
    eigen = os.open("/proc/thread-self/ns/net", os.O_RDONLY)
    try:
        ziel = os.open("/run/netns/" + name, os.O_RDONLY)
        try:
            _setns(ziel, name)
        finally:
            os.close(ziel)
        try:
            yield
        finally:
            _setns(eigen, "zurueck")
    finally:
        os.close(eigen)


def nsh(ns, *args, **kwargs):
    """Befehl im Namensraum ns: der Kindprozess erbt den Namensraum des aufrufenden Fadens."""
    with im(ns):
        return sh(*args, **kwargs)


def sysctl(ns, schluessel, wert):
    pfad = "/proc/sys/" + schluessel.replace(".", "/")
    with im(ns):
        with open(pfad, "w") as ziel:
            ziel.write(str(wert))
        with open(pfad) as quelle:
            gelesen = quelle.read().strip()
    if gelesen != str(wert):
        raise RuntimeError("sysctl %s in %s: %s" % (schluessel, ns, gelesen))


# ---------------------------------------------------------------- Rahmen bauen und zerlegen (unabhängig vom Dienstcode)


def mac_bytes(text):
    return bytes.fromhex(text.replace(":", ""))


def mac_text(raw):
    return ":".join("%02x" % wert for wert in raw)


def arp_rahmen(op, sha, spa, tha, tpa, dst=BROADCAST):
    return (mac_bytes(dst) + mac_bytes(sha) + b"\x08\x06"
            + struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, mac_bytes(sha), socket.inet_aton(spa),
                          mac_bytes(tha), socket.inet_aton(tpa)))


def _pruefsumme(daten):
    if len(daten) % 2:
        daten += b"\x00"
    summe = sum(struct.unpack("!%dH" % (len(daten) // 2), daten))
    while summe >> 16:
        summe = (summe & 0xffff) + (summe >> 16)
    return ~summe & 0xffff


def syn_rahmen(src_ip, dst_ip, dport, sport, src_mac=CLIENT_MAC, dst_mac=EIGEN):
    """Genau ein SYN mit gültigen Prüfsummen; der Kernel des Clients wiederholt nichts."""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 0x50, 0x02, 64240, 0, 0)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _pruefsumme(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0x4242, 0x4000, 64, 6, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", _pruefsumme(ip)) + ip[12:]
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + b"\x08\x00" + ip + tcp


def magic(mac):
    return b"\xff" * 6 + mac_bytes(mac) * 16


def zerlegen(rahmen):
    if len(rahmen) < 14:
        return None
    info = {"dst": mac_text(rahmen[:6]), "src": mac_text(rahmen[6:12])}
    typ = struct.unpack("!H", rahmen[12:14])[0]
    if typ == 0x0806 and len(rahmen) >= 42:
        _, _, _, _, op, sha, spa, tha, tpa = struct.unpack("!HHBBH6s4s6s4s", rahmen[14:42])
        info.update(art="arp", op=op, sha=mac_text(sha), spa=socket.inet_ntoa(spa), tha=mac_text(tha),
                    tpa=socket.inet_ntoa(tpa))
    elif typ == 0x0800 and len(rahmen) >= 34:
        ip = rahmen[14:]
        kopf, laenge = (ip[0] & 15) * 4, struct.unpack("!H", ip[2:4])[0]
        nutz = ip[kopf:laenge]
        info.update(art="ip", proto=ip[9], quelle=socket.inet_ntoa(ip[12:16]), ziel=socket.inet_ntoa(ip[16:20]))
        if ip[9] == 6 and len(nutz) >= 20:
            sport, dport = struct.unpack("!HH", nutz[:4])
            info.update(art="tcp", sport=sport, dport=dport, syn=bool(nutz[13] & 2), ack=bool(nutz[13] & 16),
                        rst=bool(nutz[13] & 4))
        elif ip[9] == 17 and len(nutz) >= 8:
            sport, dport = struct.unpack("!HH", nutz[:4])
            info.update(art="udp", sport=sport, dport=dport, daten=bytes(nutz[8:]))
    else:
        info["art"] = "typ_%04x" % typ
    return info


# ---------------------------------------------------------------- Mitschnitt an den Brückenports


class Mitschnitt:
    """Jeder Rahmen genau einmal: empfangen am Brückenport des sendenden Namensraums, Kernel-Zeitstempel."""

    def __init__(self):
        self.rahmen, self.sperre, self.laeuft = [], threading.Lock(), True
        self.socks = {}
        with im("switch"):
            for rolle, port in PORTS.items():
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
                sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
                sock.bind((port, 0))
                self.socks[sock] = rolle
        self.faden = threading.Thread(target=self._lauf, daemon=True)
        self.faden.start()

    def _lauf(self):
        while self.laeuft:
            lesbar, _, _ = select.select(list(self.socks), [], [], 0.2)
            for sock in lesbar:
                try:
                    daten, anc, _, adresse = sock.recvmsg(4096, socket.CMSG_SPACE(16))
                except OSError:
                    continue
                if adresse[2] == socket.PACKET_OUTGOING:
                    continue
                zeit = jetzt()
                for ebene, typ, wert in anc:
                    if ebene == socket.SOL_SOCKET and typ == SO_TIMESTAMPNS and len(wert) >= 16:
                        sekunden, nanos = struct.unpack("qq", wert[:16])
                        zeit = sekunden + nanos / 1e9
                info = zerlegen(daten)
                if info:
                    info.update(zeit=zeit, von=self.socks[sock])
                    with self.sperre:
                        self.rahmen.append(info)

    def liste(self, von=None, seit=None, bis=None, **merkmale):
        with self.sperre:
            rows = list(self.rahmen)
        return [row for row in rows if (von is None or row["von"] == von)
                and (seit is None or row["zeit"] >= seit) and (bis is None or row["zeit"] <= bis)
                and all(row.get(k) == v for k, v in merkmale.items())]

    def wol(self, seit=None, bis=None, mac=ECHT):
        return [row for row in self.liste(von="proxy", seit=seit, bis=bis, art="udp", dport=9)
                if row["daten"] == magic(mac)]


# ---------------------------------------------------------------- TCP-Gegenstellen


class Lauscher:
    """TCP-Dienst mit Banner (Ersatz für sshd); merkt sich lokale Adresse und Gegenstelle jeder Verbindung."""

    def __init__(self, ns, port, banner):
        with im(ns):
            self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", port))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.banner, self.angenommen, self.laeuft = banner, [], True
        self.faden = threading.Thread(target=self._lauf, daemon=True)
        self.faden.start()

    def _lauf(self):
        while self.laeuft:
            try:
                conn, peer = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.angenommen.append({"zeit": jetzt(), "lokal": conn.getsockname()[0], "peer": peer[0]})
            try:
                conn.sendall(self.banner)
            except OSError:
                pass
            conn.close()


def verbinden(ns, ziel, quelle=None, nutzlast=None, frist=1.8, lesen=2.0):
    """Echter Kernel-TCP-Verbindungsversuch; Ergebnis als Wort (timeout, rst, EPERM, banner:..., rst_nach_daten)."""
    with im(ns):
        sock = socket.socket()
    try:
        sock.settimeout(frist)
        if quelle:
            sock.bind((quelle, 0))
        try:
            sock.connect(ziel)
        except socket.timeout:
            return "timeout"
        except ConnectionRefusedError:
            return "rst"
        except OSError as error:
            return errno.errorcode.get(error.errno, str(error.errno))
        if nutzlast is not None:
            sock.sendall(nutzlast)
        sock.settimeout(lesen)
        try:
            daten = sock.recv(64)
        except ConnectionResetError:
            return "rst_nach_daten" if nutzlast is not None else "rst_ohne_daten"
        except socket.timeout:
            return "keine_antwort"
        return "banner:" + daten.decode("ascii", "replace").strip() if daten else "fin"
    finally:
        sock.close()


def roh(ns, interface):
    with im(ns):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((interface, 0))
    return sock


# ---------------------------------------------------------------- Topologie


class Netz:
    """LAN-Brücke mit proxy/host/client/router, WAN hinter dem Router, VPN über WireGuard (sonst veth)."""

    def __init__(self, arbeit):
        self.arbeit = arbeit
        self.vpn_art = None

    def aufbauen(self):
        sh("mount", "-t", "tmpfs", "tmpfs", "/run")
        os.mkdir("/run/netns")
        # Register unter dem echten Standardpfad /var/lib/greenbuddy (proxy_ssh.main ohne Pfadoption).
        sh("mount", "-t", "tmpfs", "tmpfs", "/var/lib")
        sh("mount", "-t", "sysfs", "sysfs", "/sys")
        sh("ip", "link", "set", "lo", "up")
        # Kein IPv6: sonst sendet der schweigende Host ND/MLD mit seiner echten MAC.
        for ns in (None,) + ROLLEN:
            if ns:
                sh("ip", "netns", "add", ns)
                nsh(ns, "ip", "link", "set", "lo", "up")
            for scope in ("all", "default"):
                sysctl(ns, "net.ipv6.conf.%s.disable_ipv6" % scope, 1)
                sysctl(ns, "net.ipv4.conf.%s.rp_filter" % scope, 2 if ns is None else 0)
        # Wie proxy01 (Plan 2): ip_forward=1; keine Fremdbindung, damit der bind-Test den Alias belegt.
        sysctl(None, "net.ipv4.ip_forward", 1)
        sysctl(None, "net.ipv4.ip_nonlocal_bind", 0)
        sysctl("router", "net.ipv4.ip_forward", 1)
        sh("ip", "-n", "switch", "link", "add", "br0", "type", "bridge", "stp_state", "0")
        sh("ip", "link", "add", "eth0", "address", EIGEN, "type", "veth", "peer", "name", "p-proxy", "netns", "switch")
        sh("ip", "-n", "host", "link", "add", "eno1", "address", ECHT, "type", "veth", "peer", "name", "p-host",
           "netns", "switch")
        sh("ip", "-n", "client", "link", "add", "eth0", "address", CLIENT_MAC, "type", "veth", "peer", "name",
           "p-client", "netns", "switch")
        sh("ip", "-n", "router", "link", "add", "lan0", "address", ROUTER_MAC, "type", "veth", "peer", "name",
           "p-router", "netns", "switch")
        sh("ip", "-n", "router", "link", "add", "wan0", "type", "veth", "peer", "name", "ext0", "netns", "wan")
        for port in PORTS.values():
            sh("ip", "-n", "switch", "link", "set", port, "master", "br0", "up")
        sh("ip", "-n", "switch", "link", "set", "br0", "up")
        for scope in ("all", "eth0"):
            sysctl(None, "net.ipv4.conf.%s.arp_ignore" % scope, 1)
            sysctl(None, "net.ipv4.conf.%s.arp_announce" % scope, 2)
        for ns, dev, adressen in ((None, "eth0", [PROXY]), ("host", "eno1", [HOST]), ("client", "eth0", [CLIENT]),
                                  ("router", "lan0", [ROUTER])):
            for adresse in adressen:
                nsh(ns, "ip", "addr", "add", adresse + "/24", "dev", dev)
            nsh(ns, "ip", "link", "set", dev, "up")
        for ns in (None, "host", "client"):
            nsh(ns, "ip", "route", "add", "default", "via", ROUTER)
        nsh("router", "ip", "addr", "add", "198.51.100.1/24", "dev", "wan0")
        nsh("router", "ip", "addr", "add", "203.0.113.1/24", "dev", "wan0")
        nsh("router", "ip", "link", "set", "wan0", "up")
        for adresse in (WAN_TLS, WAN_MC, WAN_LISTE):
            nsh("wan", "ip", "addr", "add", adresse + "/24", "dev", "ext0")
        nsh("wan", "ip", "link", "set", "ext0", "up")
        nsh("wan", "ip", "route", "add", "default", "via", "198.51.100.1")
        self.vpn_art = self._vpn()

    def _vpn(self):
        try:
            self._wireguard()
            return "wireguard"
        except (RuntimeError, OSError):
            for ns in (None, "vpn"):
                for dev in ("wg0", "u0"):
                    nsh(ns, "ip", "link", "del", dev, pruefen=False)
        sh("ip", "link", "add", "wg0", "type", "veth", "peer", "name", "wg0", "netns", "vpn")
        nsh(None, "ip", "addr", "add", VPN_PROXY + "/24", "dev", "wg0")
        nsh("vpn", "ip", "addr", "add", VPN_PEER + "/24", "dev", "wg0")
        for ns in (None, "vpn"):
            nsh(ns, "ip", "link", "set", "wg0", "up")
        nsh("vpn", "ip", "route", "add", "192.168.1.0/24", "via", VPN_PROXY)
        return "veth"

    def _wireguard(self):
        """Echtes wg0 wie auf proxy01 (ARPHRD_NONE, Pakete beginnen am IP-Kopf), Unterlage per veth."""
        schluessel = {}
        for rolle in ("proxy", "vpn"):
            privat = sh("wg", "genkey").stdout.strip()
            pfad = os.path.join(self.arbeit, rolle + ".key")
            fd = os.open(pfad, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as ziel:
                ziel.write(privat + "\n")
            schluessel[rolle] = (pfad, sh("wg", "pubkey", eingabe=privat + "\n").stdout.strip())
        sh("ip", "link", "add", "u0", "type", "veth", "peer", "name", "u0", "netns", "vpn")
        nsh(None, "ip", "addr", "add", "10.99.0.1/30", "dev", "u0")
        nsh("vpn", "ip", "addr", "add", "10.99.0.2/30", "dev", "u0")
        for ns in (None, "vpn"):
            nsh(ns, "ip", "link", "set", "u0", "up")
            nsh(ns, "ip", "link", "add", "wg0", "type", "wireguard")
        nsh(None, "wg", "set", "wg0", "private-key", schluessel["proxy"][0], "listen-port", "51820",
            "peer", schluessel["vpn"][1], "allowed-ips", VPN_PEER + "/32")
        nsh("vpn", "wg", "set", "wg0", "private-key", schluessel["vpn"][0], "peer", schluessel["proxy"][1],
            "endpoint", "10.99.0.1:51820", "allowed-ips", "10.0.0.0/24,192.168.1.0/24")
        nsh(None, "ip", "addr", "add", VPN_PROXY + "/24", "dev", "wg0")
        nsh("vpn", "ip", "addr", "add", VPN_PEER + "/24", "dev", "wg0")
        for ns in (None, "vpn"):
            nsh(ns, "ip", "link", "set", "wg0", "up")
        nsh("vpn", "ip", "route", "add", "192.168.1.0/24", "dev", "wg0")

    # ------------------------------------------------------------ Host-Zustände

    def host_schlaeft(self):
        """S3 nachgestellt: Link bleibt oben (WOL-Empfang), aber ohne Adresse antwortet der Host auf nichts."""
        nsh("host", "ip", "addr", "flush", "dev", "eno1")

    def host_wach(self):
        if HOST not in self.host_adressen():
            nsh("host", "ip", "addr", "add", HOST + "/24", "dev", "eno1")

    def host_mac(self, mac):
        """MAC von eno1 im laufenden Betrieb wechseln (wie neue NIC/Bridge); Adresse und Routen bleiben."""
        nsh("host", "ip", "link", "set", "eno1", "address", mac)

    def host_adressen(self):
        run = nsh("host", "ip", "-4", "-o", "addr", "show", "dev", "eno1")
        return [teil.split("/")[0] for zeile in run.stdout.splitlines() for teil in zeile.split()[3:4]]
