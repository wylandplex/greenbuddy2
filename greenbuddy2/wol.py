"""WOL-Magic-Packet; einziger automatischer Aufrufer ist der manuelle Befehl gb-wecken."""

import re
import socket


def magic_packet(mac):
    if not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
        raise ValueError("mac_ungueltig")
    return b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16


def senden(mac, ziele=(("192.168.1.255", 9),), socket_factory=socket.socket):
    """Dasselbe Paket per UDP-Broadcast an jedes Ziel; liefert die Zahl gesendeter Pakete."""
    packet = magic_packet(mac)
    count = 0
    with socket_factory(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for ziel in ziele:
            # Ein unerreichbares Ziel (z. B. Link-Wackler) darf das nächste nicht verhindern.
            try:
                if sock.sendto(packet, tuple(ziel)) == len(packet):
                    count += 1
            except OSError:
                continue
    return count
