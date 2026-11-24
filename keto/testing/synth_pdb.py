"""Minimal PDB 7.00 (MSF) writer for parser tests: streams 1 (info), 2 (TPI), 3 (DBI with an optional debug
header naming a section-header stream), 5 (section headers) and 6 (symbol records with S_PUB32)."""

from __future__ import annotations

import struct
from typing import List, Sequence, Tuple

MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


def numeric(value: int) -> bytes:
    if 0 <= value < 0x8000:
        return struct.pack("<H", value)
    if 0 <= value <= 0xFFFF:
        return struct.pack("<HH", 0x8002, value)  # LF_USHORT
    if 0 <= value <= 0xFFFFFFFF:
        return struct.pack("<HI", 0x8004, value)  # LF_ULONG
    return struct.pack("<HQ", 0x800A, value)  # LF_UQUADWORD


def cstr(text: str) -> bytes:
    return text.encode() + b"\x00"


def pad4(data: bytes) -> bytes:
    n = (-len(data)) % 4
    return data + bytes(0xF0 | (n - i) for i in range(n))


def record(leaf: int, data: bytes) -> bytes:
    body = pad4(struct.pack("<H", leaf) + data)
    return struct.pack("<H", len(body)) + body


def member(type_index: int, offset: int, name: str) -> bytes:
    return pad4(struct.pack("<HHI", 0x150D, 3, type_index) + numeric(offset) + cstr(name))


def enumerate_(value: int, name: str) -> bytes:
    return pad4(struct.pack("<HH", 0x1502, 3) + numeric(value) + cstr(name))


def index(type_index: int) -> bytes:
    return struct.pack("<HHI", 0x1404, 0, type_index)


def structure(fieldlist: int, size: int, name: str, count: int = 0, fwdref: bool = False, union: bool = False) -> Tuple[int, bytes]:
    prop = 0x80 if fwdref else 0
    if union:
        return 0x1506, struct.pack("<HHI", count, prop, fieldlist) + numeric(size) + cstr(name)
    return 0x1505, struct.pack("<HHIII", count, prop, fieldlist, 0, 0) + numeric(size) + cstr(name)


def build(guid_raw: bytes, age: int, types: Sequence[Tuple[int, bytes]], publics: Sequence[Tuple[str, int, int]],
          sections: Sequence[int], block_size: int = 512) -> bytes:
    info = struct.pack("<III", 20000404, 0x5F5E1000, age) + guid_raw + bytes(16)
    recs = b"".join(record(leaf, data) for leaf, data in types)
    tpi = struct.pack("<IIIII", 20040203, 56, 0x1000, 0x1000 + len(types), len(recs)) + \
        struct.pack("<HHIIiIiIiI", 0xFFFF, 0xFFFF, 4, 0x3FFFF, 0, 0, 0, 0, 0, 0) + recs
    sechdr = b"".join(struct.pack("<8sIIIIIIHHI", b".s%d" % i, 0x1000, va, 0, 0, 0, 0, 0, 0, 0)
                      for i, va in enumerate(sections))
    symrec = b"".join(record(0x110E, struct.pack("<IIH", 0, off, seg) + cstr(name)) for name, seg, off in publics)
    dbg = [0xFFFF] * 11
    dbg[5] = 5
    dbi = struct.pack("<iIIHHHHHHiiiiiIiiHHI", -1, 19990903, age, 0xFFFF, 0x8E00, 0xFFFF, 0, 6, 0, 0, 0, 0, 0, 0, 0,
                      22, 0, 0, 0x8664, 0) + struct.pack("<11H", *dbg)
    streams = [b"", info, tpi, dbi, b"", sechdr, symrec]
    return _msf(streams, block_size)


def _msf(streams: List[bytes], bs: int) -> bytes:
    blocks: List[bytes] = [b"", b"", b""]  # superblock, two free-page maps
    lists = []
    for s in streams:
        idx = []
        for i in range(0, len(s), bs):
            idx.append(len(blocks))
            blocks.append(s[i:i + bs])
        lists.append(idx)
    directory = struct.pack("<I", len(streams)) + b"".join(struct.pack("<I", len(s)) for s in streams) + \
        b"".join(struct.pack("<%dI" % len(ix), *ix) for ix in lists)
    dir_blocks = []
    for i in range(0, len(directory), bs):
        dir_blocks.append(len(blocks))
        blocks.append(directory[i:i + bs])
    map_block = len(blocks)
    blocks.append(struct.pack("<%dI" % len(dir_blocks), *dir_blocks))
    blocks[0] = MAGIC + struct.pack("<6I", bs, 1, len(blocks), len(directory), 0, map_block)
    blocks[1] = blocks[2] = b"\xff" * bs
    return b"".join(b.ljust(bs, b"\x00") for b in blocks)
