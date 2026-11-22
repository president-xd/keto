"""BTF (BPF Type Format) reader: kernel structure layouts without a debug kernel or an ISF.

A kernel built with ``CONFIG_DEBUG_INFO_BTF`` exposes its own type information at
``/sys/kernel/btf/vmlinux`` (format: ``include/uapi/linux/btf.h``)::

    header   { u16 magic 0xEB9F; u8 version; u8 flags; u32 hdr_len;
               u32 type_off; u32 type_len; u32 str_off; u32 str_len }
    type     { u32 name_off; u32 info (vlen 15:0, kind 28:24, kind_flag 31); u32 size_or_type }
             followed by kind-specific data (INT u32, ARRAY {type, index_type, nelems},
             STRUCT/UNION vlen x {name_off, type, offset}, ENUM vlen x {name_off, val}, ...)

Type ids start at 1 (0 is void). Member offsets are in bits; with kind_flag set the
top 8 bits are a bitfield size. Taking the BTF from the same boot as a memory image
gives exact layouts for that kernel build.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

BTF_MAGIC = 0xEB9F
INT, PTR, ARRAY, STRUCT, UNION, ENUM, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FUNC_PROTO, VAR, DATASEC, \
    FLOAT, DECL_TAG, TYPE_TAG, ENUM64 = range(1, 20)
_QUALIFIERS = (TYPEDEF, VOLATILE, CONST, RESTRICT, TYPE_TAG)


class BtfError(ValueError):
    pass


class BtfType:
    __slots__ = ("id", "kind", "name", "size", "ref", "members", "nelems", "kind_flag", "encoding", "bits")

    def __init__(self, tid, kind, name, size=0, ref=0):
        self.id, self.kind, self.name, self.size, self.ref = tid, kind, name, size, ref
        self.members: List[Tuple[str, int, int, int]] = []  # (name, type id, bit offset, bitfield size)
        self.nelems = 0
        self.kind_flag = False
        self.encoding = 0
        self.bits = 0

    def __repr__(self):
        return "<BtfType %d kind=%d %s>" % (self.id, self.kind, self.name)


class Btf:
    def __init__(self, data: bytes):
        if len(data) < 24:
            raise BtfError("BTF blob too short")
        magic, version, _flags, hdr_len = struct.unpack_from("<HBBI", data)
        if magic != BTF_MAGIC:
            raise BtfError("not BTF (magic 0x%04x)" % magic)
        type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", data, 8)
        base = hdr_len
        for what, off, length in (("type", type_off, type_len), ("string", str_off, str_len)):
            if base + off + length > len(data):
                raise BtfError("BTF truncated: %s section ends at byte %d, blob has %d" % (what, base + off + length,
                                                                                            len(data)))
        self.version = version
        self._strings = data[base + str_off:base + str_off + str_len]
        self.types: List[Optional[BtfType]] = [None]  # id 0 = void
        self.by_name: Dict[Tuple[int, str], int] = {}
        self._parse(data[base + type_off:base + type_off + type_len])

    def _str(self, off: int) -> str:
        end = self._strings.find(b"\x00", off)
        return self._strings[off:end if end >= 0 else None].decode("utf-8", "replace")

    def _parse(self, blob: bytes):
        try:
            self._parse_types(blob)
        except struct.error:
            raise BtfError("BTF type section truncated inside type %d" % len(self.types))

    def _parse_types(self, blob: bytes):
        pos, n = 0, len(blob)
        while pos + 12 <= n:
            name_off, info, size_or_type = struct.unpack_from("<III", blob, pos)
            pos += 12
            vlen, kind, kflag = info & 0xFFFF, (info >> 24) & 0x1F, bool(info >> 31)
            t = BtfType(len(self.types), kind, self._str(name_off), size_or_type, size_or_type)
            t.kind_flag = kflag
            if kind == INT:
                enc = struct.unpack_from("<I", blob, pos)[0]
                t.encoding, t.bits = (enc >> 24) & 0xF, enc & 0xFF
                pos += 4
            elif kind == ARRAY:
                t.ref, _index, t.nelems = struct.unpack_from("<III", blob, pos)
                pos += 12
            elif kind in (STRUCT, UNION):
                for i in range(vlen):
                    mname, mtype, moff = struct.unpack_from("<III", blob, pos + 12 * i)
                    if kflag:
                        t.members.append((self._str(mname), mtype, moff & 0xFFFFFF, moff >> 24))
                    else:
                        t.members.append((self._str(mname), mtype, moff, 0))
                pos += 12 * vlen
            elif kind == ENUM:
                pos += 8 * vlen
            elif kind == ENUM64:
                pos += 12 * vlen
            elif kind == FUNC_PROTO:
                pos += 8 * vlen
            elif kind == VAR:
                pos += 4
            elif kind == DATASEC:
                pos += 12 * vlen
            elif kind == DECL_TAG:
                pos += 4
            elif kind not in (PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG):
                raise BtfError("unknown BTF kind %d at type %d" % (kind, t.id))
            self.types.append(t)
            if t.name and (kind, t.name) not in self.by_name:
                self.by_name[(kind, t.name)] = t.id

    # -- queries -------------------------------------------------------------------------------
    def find(self, name: str, kinds=(STRUCT, UNION, TYPEDEF)) -> Optional[BtfType]:
        for k in kinds:
            tid = self.by_name.get((k, name))
            if tid:
                return self.types[tid]
        return None

    def struct(self, name: str) -> BtfType:
        t = self.find(name, (STRUCT, UNION))
        if t is None:
            raise BtfError("struct %s not in BTF" % name)
        return t

    def _type(self, tid: int) -> BtfType:
        if not 0 < tid < len(self.types):
            raise BtfError("BTF type id %d out of range (%d types)" % (tid, len(self.types) - 1))
        return self.types[tid]

    def resolve(self, tid: int) -> Optional[BtfType]:
        """Strip typedefs and qualifiers."""
        t = self._type(tid) if tid else None
        for _ in range(64):  # real chains are a few links long; a cycle means a corrupt BTF
            if t is None or t.kind not in _QUALIFIERS:
                return t
            t = self._type(t.ref) if t.ref else None
        raise BtfError("BTF type %d: typedef/qualifier chain does not end (corrupt BTF)" % tid)

    def sizeof(self, tid: int) -> int:
        t = self.resolve(tid)
        if t is None:
            return 0
        if t.kind in (INT, STRUCT, UNION, ENUM, ENUM64, FLOAT, DATASEC):
            return t.size
        if t.kind == PTR:
            return 8
        if t.kind == ARRAY:
            return self.sizeof(t.ref) * t.nelems
        return 0

    def member(self, struct_t: BtfType, path: str) -> Tuple[int, int, int]:
        """``(byte offset, type id, bitfield size)`` of ``a.b.c`` inside ``struct_t``, descending into
        anonymous unions/structs."""
        off, t, bf = 0, struct_t, 0
        for part in path.split("."):
            hit = self._find_member(t, part)
            if hit is None:
                raise BtfError("%s has no member %s" % (struct_t.name or "<anon>", path))
            moff, tid, bf = hit
            off += moff
            t = self.resolve(tid)
            last_tid = tid
            if not bf and t is not None and t.kind == INT and t.bits and t.bits < t.size * 8:
                bf = t.bits  # pre-kind_flag encoding: the INT type carries the bitfield width
        return off // 8 if not bf else off, last_tid, bf  # bitfields keep a bit offset

    def _find_member(self, t: BtfType, name: str):
        if t is None or t.kind not in (STRUCT, UNION):
            return None
        for mname, mtid, moff, bf in t.members:
            if mname == name:
                return moff, mtid, bf
        for mname, mtid, moff, bf in t.members:  # anonymous struct/union members
            if not mname:
                sub = self._find_member(self.resolve(mtid), name)
                if sub is not None:
                    return moff + sub[0], sub[1], sub[2]
        return None

    def offsetof(self, struct_name: str, path: str) -> int:
        off, _, bf = self.member(self.struct(struct_name), path)
        if bf:
            raise BtfError("%s.%s is a bitfield" % (struct_name, path))
        return off

    def has_member(self, struct_name: str, path: str) -> bool:
        try:
            self.member(self.struct(struct_name), path)
            return True
        except BtfError:
            return False


def load(path: str) -> Btf:
    with open(path, "rb") as fh:
        return Btf(fh.read())


# -- encoder (synthetic test data) ---------------------------------------------------------------
class BtfBuilder:
    """Builds a minimal BTF blob: ints, pointers, arrays and structs (enough for test kernels)."""

    def __init__(self):
        self.strings = bytearray(b"\x00")
        self.types = bytearray()
        self.count = 0
        self._str_cache: Dict[str, int] = {"": 0}

    def _s(self, s: str) -> int:
        if s not in self._str_cache:
            self._str_cache[s] = len(self.strings)
            self.strings += s.encode() + b"\x00"
        return self._str_cache[s]

    def _add(self, name, kind, vlen, size_or_type, extra=b"", kflag=False):
        self.types += struct.pack("<III", self._s(name), (int(kflag) << 31) | (kind << 24) | vlen, size_or_type) + extra
        self.count += 1
        return self.count

    def int(self, name: str, size: int, signed: bool = False) -> int:
        return self._add(name, INT, 0, size, struct.pack("<I", (int(signed) << 24) | (size * 8)))

    def ptr(self, target: int) -> int:
        return self._add("", PTR, 0, target)

    def array(self, elem: int, n: int, index_type: int) -> int:
        return self._add("", ARRAY, 0, 0, struct.pack("<III", elem, index_type, n))

    def struct(self, name: str, size: int, members) -> int:
        """``members``: ``[(name, type id, byte offset)]`` or, for bitfields, ``(name, type id, bit offset,
        bits)`` (then the struct is encoded with kind_flag)."""
        kflag = any(len(m) == 4 for m in members)
        enc = []
        for m in members:
            if len(m) == 4:
                enc.append(struct.pack("<III", self._s(m[0]), m[1], (m[3] << 24) | m[2]))
            else:
                enc.append(struct.pack("<III", self._s(m[0]), m[1], m[2] * 8))
        return self._add(name, STRUCT, len(members), size, b"".join(enc), kflag)

    def build(self) -> bytes:
        hdr = struct.pack("<HBBIIIII", BTF_MAGIC, 1, 0, 24, 0, len(self.types), len(self.types), len(self.strings))
        return hdr + bytes(self.types) + bytes(self.strings)
