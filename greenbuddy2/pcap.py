"""Inkrementeller klassischer pcap-Parser und begrenzte TCP-Zusammensetzung."""

import socket
import struct


class PcapStream:
    def __init__(self):
        self.buffer, self.endian, self.linktype = bytearray(), None, None
        self.snaplen, self.scale = None, None

    def feed(self, data):
        self.buffer.extend(data)
        packets = []
        if self.endian is None:
            if len(self.buffer) < 24:
                return packets
            formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                       b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
            if bytes(self.buffer[:4]) not in formats:
                raise ValueError("pcap_format")
            self.endian, self.scale = formats[bytes(self.buffer[:4])]
            major, minor, _, _, self.snaplen, self.linktype = struct.unpack(self.endian + "HHIIII", self.buffer[4:24])
            if (major, minor) != (2, 4) or not 1 <= self.snaplen <= 65535 or self.linktype not in (1, 101, 113, 276):
                raise ValueError("pcap_kopf")
            del self.buffer[:24]
        while len(self.buffer) >= 16:
            seconds, fraction, captured, original = struct.unpack(self.endian + "IIII", self.buffer[:16])
            if captured > self.snaplen or captured > original or fraction >= self.scale:
                raise ValueError("pcap_paketlaenge")
            if len(self.buffer) < 16 + captured:
                break
            packets.append((seconds + fraction / self.scale, bytes(self.buffer[16:16 + captured])))
            del self.buffer[:16 + captured]
        return packets

    def finish(self):
        if self.buffer or self.endian is None:
            raise ValueError("pcap_abgebrochen")


def tcp_packet(frame, linktype=1):
    if linktype == 1:
        if len(frame) < 14:
            return None
        kind, offset = int.from_bytes(frame[12:14], "big"), 14
        while kind in (0x8100, 0x88a8):
            if len(frame) < offset + 4:
                return None
            kind = int.from_bytes(frame[offset + 2:offset + 4], "big")
            offset += 4
    elif linktype == 113:
        if len(frame) < 16:
            return None
        kind, offset = int.from_bytes(frame[14:16], "big"), 16
    elif linktype == 276:
        if len(frame) < 20:
            return None
        kind, offset = int.from_bytes(frame[:2], "big"), 20
    else:
        kind, offset = 0x800, 0
    if kind != 0x800 or len(frame) < offset + 20:
        return None
    ip = frame[offset:]
    ihl, length = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
    if ip[0] >> 4 != 4 or ihl < 20 or length < ihl + 20 or ip[9] != 6 or int.from_bytes(ip[6:8], "big") & 0x3fff:
        return None
    tcp = ip[ihl:min(length, len(ip))]
    if len(tcp) < 20:
        return None
    header = (tcp[12] >> 4) * 4
    if not 20 <= header <= len(tcp):
        return None
    sport, dport, seq = struct.unpack("!HHI", tcp[:8])
    return {"source": socket.inet_ntoa(ip[12:16]), "target": socket.inet_ntoa(ip[16:20]),
            "sport": sport, "port": dport, "seq": seq, "syn": bool(tcp[13] & 2),
            "ack": bool(tcp[13] & 16), "payload": bytes(tcp[header:])}


class TcpAnfang:
    def __init__(self, seq, limit=16384):
        self.base = seq & 0xffffffff
        self.limit = limit
        self.buffer, self.present = bytearray(), bytearray()
        self.contiguous = 0

    def add(self, seq, payload):
        if not payload:
            return self.data()
        offset = (seq - self.base) & 0xffffffff
        if offset >= self.limit or offset + len(payload) > self.limit:
            raise ValueError("tcp_anfang_gross")
        needed = offset + len(payload) - len(self.buffer)
        if needed > 0:
            self.buffer.extend(b"\x00" * needed)
            self.present.extend(b"\x00" * needed)
        for index, value in enumerate(payload, offset):
            if self.present[index] and self.buffer[index] != value:
                raise ValueError("tcp_widerspruch")
            self.buffer[index], self.present[index] = value, 1
        while self.contiguous < len(self.present) and self.present[self.contiguous]:
            self.contiguous += 1
        return self.data()

    def data(self):
        return bytes(self.buffer[:self.contiguous])
