"""Dieselbe reine Inhaltsprüfung für Mitschnitt und Stellvertreter."""

import ipaddress
import re
import struct


class Unvollstaendig(ValueError):
    pass


def quelle(address, lan=("192.168.1.0/24",), vpn=("10.0.0.0/24",)):
    ip = ipaddress.ip_address(address)
    for name, networks in (("VPN", vpn), ("LAN", lan)):
        if any(ip in ipaddress.ip_network(net) for net in networks):
            return name
    return "WAN"


def take(data, index, length):
    if index + length > len(data):
        raise Unvollstaendig("paket_unvollstaendig")
    return data[index:index + length], index + length


def tls_sni(data):
    """TLS-Records zusammensetzen; SNI aus dem ClientHello, ohne TLS-Bibliothek."""
    hello, cursor = bytearray(), 0
    while True:
        header, cursor = take(data, cursor, 5)
        if header[0] != 0x16 or header[1] != 3:
            raise ValueError("tls_record")
        length = int.from_bytes(header[3:5], "big")
        if not 0 < length <= 16384:
            raise ValueError("tls_laenge")
        record, cursor = take(data, cursor, length)
        hello.extend(record)
        if len(hello) >= 4:
            if hello[0] != 1:
                raise ValueError("tls_kein_clienthello")
            size = int.from_bytes(hello[1:4], "big")
            if size > 16384:
                raise ValueError("tls_hello_gross")
            if len(hello) >= size + 4:
                break
    body = bytes(hello[4:4 + size])
    try:
        _, pos = take(body, 0, 34)
        raw, pos = take(body, pos, 1)
        _, pos = take(body, pos, raw[0])
        raw, pos = take(body, pos, 2)
        cipher_size = int.from_bytes(raw, "big")
        if not cipher_size or cipher_size % 2:
            raise ValueError("tls_chiffren")
        _, pos = take(body, pos, cipher_size)
        raw, pos = take(body, pos, 1)
        _, pos = take(body, pos, raw[0])
        if pos == len(body):
            return None
        raw, pos = take(body, pos, 2)
        extensions, end = take(body, pos, int.from_bytes(raw, "big"))
        if end != len(body):
            raise ValueError("tls_erweiterungen")
        pos, names = 0, []
        while pos < len(extensions):
            header, pos = take(extensions, pos, 4)
            kind, size = struct.unpack("!HH", header)
            content, pos = take(extensions, pos, size)
            if kind != 0:
                continue
            raw, offset = take(content, 0, 2)
            if int.from_bytes(raw, "big") != len(content) - 2:
                raise ValueError("tls_sni_laenge")
            while offset < len(content):
                item, offset = take(content, offset, 3)
                name, offset = take(content, offset, int.from_bytes(item[1:3], "big"))
                if item[0] == 0:
                    host = name.decode("ascii").lower().rstrip(".")
                    if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
                        raise ValueError("tls_sni_format")
                    names.append(host)
        if len(names) > 1:
            raise ValueError("tls_sni_doppelt")
        return names[0] if names else None
    except Unvollstaendig:
        # Das vollständige Hello enthält widersprüchliche Binnenlängen.
        raise ValueError("tls_hello_schema")


def varint(data, pos=0):
    result = 0
    for offset in range(5):
        raw, pos = take(data, pos, 1)
        result |= (raw[0] & 127) << (7 * offset)
        if not raw[0] & 128:
            if result > 0x7fffffff:
                raise ValueError("minecraft_varint")
            return result, pos
    raise ValueError("minecraft_varint")


def mc_string(data, pos, maximum):
    length, pos = varint(data, pos)
    if length > maximum * 4:
        raise ValueError("minecraft_string_gross")
    raw, pos = take(data, pos, length)
    value = raw.decode("utf-8")
    if len(value) > maximum:
        raise ValueError("minecraft_string_gross")
    return value, pos


def mc_packet(data, pos=0):
    length, pos = varint(data, pos)
    if not 0 < length <= 4096:
        raise ValueError("minecraft_paket_gross")
    return take(data, pos, length)


def minecraft_login(data):
    if data[:1] == b"\xfe":
        return {"status": True, "name": None}
    packet, pos = mc_packet(data)
    try:
        kind, at = varint(packet)
        if kind != 0:
            raise ValueError("minecraft_handshake")
        _, at = varint(packet, at)
        _, at = mc_string(packet, at, 255)
        _, at = take(packet, at, 2)
        next_state, at = varint(packet, at)
        if at != len(packet) or next_state not in (1, 2):
            raise ValueError("minecraft_zustand")
    except Unvollstaendig:
        raise ValueError("minecraft_handshake_schema")
    if next_state == 1:
        return {"status": True, "name": None}
    login, _ = mc_packet(data, pos)
    try:
        kind, at = varint(login)
        if kind != 0:
            raise ValueError("minecraft_login")
        name, at = mc_string(login, at, 16)
        if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", name):
            raise ValueError("minecraft_name")
        return {"status": False, "name": name}
    except Unvollstaendig:
        raise ValueError("minecraft_login_schema")


def http_client(data):
    if len(data) > 16384:
        raise ValueError("http_gross")
    end = data.find(b"\r\n\r\n")
    if end < 0:
        raise Unvollstaendig("http_header_unvollstaendig")
    lines = data[:end].decode("iso-8859-1").split("\r\n")
    if not re.fullmatch(r"(?:GET|POST|HEAD|PUT|OPTIONS) [^\r\n ]+ HTTP/1\.[01]", lines[0]):
        raise ValueError("http_anfang")
    ids = []
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if not sep:
            raise ValueError("http_header")
        if key.lower() == "x-plex-client-identifier":
            ids.append(value.strip())
    if len(ids) > 1:
        raise ValueError("http_client_doppelt")
    return ids[0] if ids else None


# Nie öffentlich: RFC 1918, CGNAT, Loopback, Link-local, Multicast/reserviert und 0/8.
NICHT_OEFFENTLICH = tuple(ipaddress.IPv4Network(net) for net in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"))


def plex_hash_gueltig(value):
    """Form des Plex-Server-Hashs im SNI-Suffix; ohne ihn wird keine Plex-Verbindung "wuerde_wecken"."""
    return isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{6,64}", value) is not None


def sni_label(label, cfg):
    """Plan R3: genau ein Label, gestrichelte IPv4 = LAN-IP des Hosts oder aktuelle WAN-IP."""
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,2})(?:-(?:0|[1-9][0-9]{0,2})){3}", label):
        return "kein_ip"
    try:
        address = ipaddress.IPv4Address(label.replace("-", "."))
    except ValueError:
        return "kein_ip"
    lan = [ipaddress.ip_network(net) for net in cfg.get("lan", ["192.168.1.0/24"])]
    vpn = [ipaddress.ip_network(net) for net in cfg.get("vpn", ["10.0.0.0/24"])]
    if address in {ipaddress.IPv4Address(ip) for ip in cfg["sni_label_ips"]}:
        return "lan" if any(address in net for net in lan) else "wan"
    # Unbekannte WAN-IP: jede öffentliche Adresse zulassen (Spam-Filter, kein Identitätsnachweis).
    if cfg.get("sni_label_wan_unklar") and not any(address in net for net in NICHT_OEFFENTLICH + tuple(lan + vpn)):
        return "wan"
    return "ip_andere"


def klassifizieren(address, port, data, cfg):
    source = quelle(address, cfg.get("lan", ["192.168.1.0/24"]), cfg.get("vpn", ["10.0.0.0/24"]))
    row = {"quellklasse": source, "port": port, "sni_suffix_treffer": False,
           "entscheidung": "unklar", "weg": 7 if source == "WAN" else 4}
    if "sni_label_ips" in cfg:
        row["sni_label"] = None
    try:
        if port == 25565:
            login = minecraft_login(data)
            allowed = not login["status"] and login["name"] in cfg.get("minecraft_whitelist", [])
            row["entscheidung"] = "wuerde_wecken" if allowed else "spam"
        elif port == 32400 and data[:1] == b"\x16":
            name = tls_sni(data)
            server_hash = cfg.get("plex_hash", "")
            if not plex_hash_gueltig(server_hash):
                return row
            suffix = "." + server_hash.lower() + ".plex.direct"
            hit = bool(server_hash and name and name.endswith(suffix) and len(name) > len(suffix))
            row["sni_suffix_treffer"] = hit
            if hit and "sni_label_ips" in cfg:
                row["sni_label"] = sni_label(name[:-len(suffix)], cfg)
                hit = row["sni_label"] in ("lan", "wan")
            # SNI ist ein Spam-Filter, kein Identitätsnachweis.
            row["entscheidung"] = "wuerde_wecken" if hit else "spam"
        elif port == 32400:
            client = http_client(data)
            allowed = source in ("LAN", "VPN") and client in cfg.get("plex_clients", [])
            row["entscheidung"] = "wuerde_wecken" if allowed else "spam"
        elif port == 8443:
            # Verschlüsselte Webhook-Inhalte gehören zum gesonderten MAC-Prüfer.
            row["weg"] = 5
        elif port == 8096:
            row["entscheidung"] = "wuerde_wecken" if source in ("LAN", "VPN") else "spam"
        else:
            row["entscheidung"] = "spam"
    except Unvollstaendig:
        pass
    except (ValueError, UnicodeError, IndexError):
        row["entscheidung"] = "spam" if data else "unklar"
    return row
