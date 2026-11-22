"""Small helpers used across the code base (no third-party dependencies)."""

from __future__ import annotations

import datetime as _dt
import hashlib
import math
import re
import struct
from collections import Counter
from typing import Iterator, Tuple

_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_U64 = struct.Struct("<Q")


def u16(data, off=0):
    return _U16.unpack_from(data, off)[0]


def u32(data, off=0):
    return _U32.unpack_from(data, off)[0]


def u64(data, off=0):
    return _U64.unpack_from(data, off)[0]


def p32(v):
    return _U32.pack(v & 0xFFFFFFFF)


def p64(v):
    return _U64.pack(v & 0xFFFFFFFFFFFFFFFF)


def bits(value: int, hi: int, lo: int) -> int:
    """Extract bit field ``hi:lo`` (inclusive, NVIDIA manual notation)."""
    return (value >> lo) & ((1 << (hi - lo + 1)) - 1)


def set_bits(value: int, hi: int, lo: int, field: int) -> int:
    mask = ((1 << (hi - lo + 1)) - 1) << lo
    return (value & ~mask) | ((field << lo) & mask)


def align_down(v: int, a: int) -> int:
    return v - (v % a)


def align_up(v: int, a: int) -> int:
    return (v + a - 1) // a * a


def entropy(data) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0)."""
    n = len(data)
    if not n:
        return 0.0
    ent = 0.0
    for c in Counter(bytes(data)).values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def is_zero(data) -> bool:
    return not any(data) if len(data) < 64 else bytes(data).count(0) == len(data)


_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def printable_ratio(data) -> float:
    if not data:
        return 0.0
    return sum(1 for b in bytes(data) if b in _PRINTABLE) / len(data)


def hexdump(data, base: int = 0, width: int = 16) -> str:
    lines = []
    data = bytes(data)
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexpart = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append("%016x  %-*s  %s" % (base + i, width * 3 - 1, hexpart, asc))
    return "\n".join(lines)


def human_size(n: int) -> str:
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024
    return "%d" % n


def parse_size(text: str) -> int:
    """Parse ``512M`` / ``2G`` / ``4096`` / ``0x1000`` into bytes."""
    t = str(text).strip().upper()
    if t.startswith("0X"):  # hex has no unit suffix ("0x1B" is 27, not 1 byte)
        return int(t, 16)
    mult = 1
    for suffix, m in (("KIB", 1 << 10), ("MIB", 1 << 20), ("GIB", 1 << 30), ("K", 1 << 10),
                      ("M", 1 << 20), ("G", 1 << 30), ("B", 1)):
        if t.endswith(suffix):
            mult, t = m, t[: -len(suffix)]
            break
    return int(t, 0) * mult


def sha256(data) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def utc_from_epoch(epoch):
    if epoch is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(float(epoch), tz=_dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def utcnow():
    return _dt.datetime.now(tz=_dt.timezone.utc)


def iter_strings(data, min_len: int = 6, utf16: bool = True) -> Iterator[Tuple[int, str, str]]:
    """Yield ``(offset, encoding, text)`` for printable runs (ASCII and UTF-16LE)."""
    pat = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
    for m in pat.finditer(data):
        yield m.start(), "ascii", m.group().decode("ascii")
    if utf16:
        pat16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
        for m in pat16.finditer(data):
            yield m.start(), "utf16le", m.group().decode("utf-16-le")


def cstr(data, off: int = 0, limit: int = 256) -> str:
    end = bytes(data[off:off + limit]).find(b"\x00")
    raw = bytes(data[off:off + (limit if end < 0 else end)])
    return raw.decode("utf-8", "replace")
