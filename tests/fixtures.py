"""Ausschließlich synthetische Byte-Fixtures; keine echten Hostdaten."""

import socket
import struct

MEDIA = '''WACH_MORGEN_START="06:00"
WACH_MORGEN_END="10:00"
WACH_ABEND_START="16:30"
WACH_ABEND_END="23:00"
TAGSCHLAF_START="10:00"
TAGSCHLAF_END="16:30"
VORLAUF_MIN=5
NAS_NACHT_WINDOW_START="23:00"
NAS_NACHT_WINDOW_END="03:00"
'''

MDSTAT = '''Personalities : [raid10]
md126 : active raid10 sda[1] sdc[0]
      7814032384 blocks super external:/md127/0 64K chunks 2 near-copies [4/2] [_UU_]
md127 : inactive sdc[1](S) sda[0](S)
      8096 blocks super external:imsm
unused devices: <none>
'''


def clienthello(name="client.abc123.plex.direct", split_records=False):
    hostname = name.encode("ascii")
    item = b"\x00" + struct.pack("!H", len(hostname)) + hostname
    sni = struct.pack("!H", len(item)) + item
    extension = struct.pack("!HH", 0, len(sni)) + sni
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00\x00\x02\x13\x01\x01\x00"
    body += struct.pack("!H", len(extension)) + extension
    hello = b"\x01" + len(body).to_bytes(3, "big") + body

    def record(data):
        return b"\x16\x03\x03" + struct.pack("!H", len(data)) + data
    return record(hello[:19]) + record(hello[19:]) if split_records else record(hello)


def vi(number):
    out = bytearray()
    while True:
        out.append((number & 127) | (128 if number > 127 else 0))
        number >>= 7
        if not number:
            return bytes(out)


def minecraft(name="Testspieler", status=False):
    host = b"test.invalid"
    hello = b"\x00" + vi(765) + vi(len(host)) + host + struct.pack("!H", 25565) + vi(1 if status else 2)
    login = b"\x00" + vi(len(name)) + name.encode()
    return vi(len(hello)) + hello + (b"" if status else vi(len(login)) + login)


def ethernet(payload=b"", seq=100, syn=False, source="198.51.100.9", port=32400):
    tcp = struct.pack("!HHIIBBHHH", 50000, port, seq, 0, 0x50, 2 if syn else 0x18, 4096, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0,
                     socket.inet_aton(source), socket.inet_aton("192.168.1.110"))
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp + payload


def pcap(frames, endian="<", nano=False, link=1):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    out = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 600, link)
    for index, frame in enumerate(frames):
        out += struct.pack(endian + "IIII", 100 + index, 1000, len(frame), len(frame)) + frame
    return out
