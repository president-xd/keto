"""Microsoft PDB 7.0 (MSF) reader: GUID/age, CodeView type records and public/global symbols.

Layout (LLVM "The PDB File Format", microsoft-pdb ``cvinfo.h``):

* MSF superblock at 0: the 32-byte magic ``Microsoft C/C++ MSF 7.00\\r\\n\\x1aDS\\0\\0\\0``, then BlockSize,
  FreeBlockMapBlock, NumBlocks, NumDirectoryBytes, Unknown, BlockMapAddr (u32 each). The block at BlockMapAddr
  lists the directory's blocks; the directory is NumStreams, StreamSizes[] (0xFFFFFFFF = nil) and each
  stream's block list.
* Stream 1 (PDB info): Version, Signature, Age, GUID.
* Stream 2 (TPI): a 56-byte header (HeaderSize, TypeIndexBegin, TypeIndexEnd, TypeRecordBytes, ...) then
  records ``u16 length, u16 leaf, data`` numbered from TypeIndexBegin (0x1000).
* Stream 3 (DBI): a 64-byte header (SymRecordStream at +0x14, substream sizes at +0x18..+0x2C, Machine at +0x3A)
  followed by the substreams; the optional debug header (last) holds stream numbers, [5] = section headers,
  [4] = OMAP from source, [10] = original section headers.
* The symbol record stream holds S_PUB32 (0x110E: flags, offset, segment, name) and S_GDATA32/S_LDATA32
  (0x110D/0x110C: type, offset, segment, name); RVA = section[segment-1].VirtualAddress + offset (mapped through
  OMAP when the image was rewritten after linking).

Types are decoded on first use; only names of structs, unions and enums are indexed at load time.
"""

from __future__ import annotations

import bisect
import struct
from array import array
from typing import Dict, List, Optional, Tuple

from keto.winmem.symtab import (ARRAY, BASE, BITFIELD, ENUM, FUNCTION, POINTER, STRUCT, UNION, VOID, SymbolError,
                                SymbolTable, Type)

MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
MSF2_MAGIC = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00"

# leaf kinds (cvinfo.h)
LF_MODIFIER, LF_POINTER, LF_PROCEDURE, LF_MFUNCTION = 0x1001, 0x1002, 0x1008, 0x1009
LF_FIELDLIST, LF_BITFIELD = 0x1203, 0x1205
LF_BCLASS, LF_VBCLASS, LF_IVBCLASS, LF_INDEX, LF_VFUNCTAB, LF_FRIENDCLS = 0x1400, 0x1401, 0x1402, 0x1404, 0x1409, 0x140B
LF_ENUMERATE, LF_ARRAY, LF_CLASS, LF_STRUCTURE, LF_UNION, LF_ENUM = 0x1502, 0x1503, 0x1504, 0x1505, 0x1506, 0x1507
LF_FRIENDFCN, LF_MEMBER, LF_STMEMBER, LF_METHOD, LF_NESTTYPE, LF_ONEMETHOD = 0x150C, 0x150D, 0x150E, 0x150F, 0x1510, 0x1511
LF_NESTTYPEEX, LF_INTERFACE = 0x1512, 0x1519
S_PUB32, S_GDATA32, S_LDATA32 = 0x110E, 0x110D, 0x110C

PROP_FWDREF, PROP_UNIQUE_NAME = 0x0080, 0x0200

_NUMERIC = {0x8000: ("<b", 1), 0x8001: ("<h", 2), 0x8002: ("<H", 2), 0x8003: ("<i", 4), 0x8004: ("<I", 4),
            0x8009: ("<q", 8), 0x800A: ("<Q", 8)}
_NUMERIC_SKIP = {0x8005: 4, 0x8006: 8, 0x8007: 10, 0x8008: 16, 0x800B: 6, 0x800C: 8, 0x800D: 16, 0x800E: 20,
                 0x800F: 32, 0x8017: 16, 0x8018: 16}

# basic type indices < 0x1000: low byte = type, bits 8..11 = pointer mode
_BASIC = {0x03: ("void", 0, False), 0x08: ("HRESULT", 4, True), 0x10: ("signed char", 1, True),
          0x11: ("short", 2, True), 0x12: ("long", 4, True), 0x13: ("long long", 8, True),
          0x20: ("unsigned char", 1, False), 0x21: ("unsigned short", 2, False), 0x22: ("unsigned long", 4, False),
          0x23: ("unsigned long long", 8, False), 0x30: ("bool", 1, False), 0x31: ("bool16", 2, False),
          0x32: ("bool32", 4, False), 0x33: ("bool64", 8, False), 0x40: ("float", 4, True),
          0x41: ("double", 8, True), 0x42: ("long double", 10, True), 0x68: ("__int8", 1, True),
          0x69: ("unsigned __int8", 1, False), 0x70: ("char", 1, True), 0x71: ("wchar_t", 2, False),
          0x72: ("__int16", 2, True), 0x73: ("unsigned __int16", 2, False), 0x74: ("int", 4, True),
          0x75: ("unsigned int", 4, False), 0x76: ("__int64", 8, True), 0x77: ("unsigned __int64", 8, False),
          0x78: ("__int128", 16, True), 0x79: ("unsigned __int128", 16, False), 0x7A: ("char16_t", 2, False),
          0x7B: ("char32_t", 4, False), 0x7C: ("char8_t", 1, False)}
_PTR_MODE_SIZE = {1: 2, 2: 4, 3: 4, 4: 4, 5: 6, 6: 8, 7: 16}
MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C4: "arm"}


def guid_str(raw: bytes) -> str:
    """Symbol-server spelling of a 16-byte GUID (Data1-3 little-endian, Data4 as bytes, no dashes)."""
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    return "%08X%04X%04X%s" % (d1, d2, d3, raw[8:16].hex().upper())


class Msf:
    """Stream access to an MSF 7.00 container held in memory."""

    def __init__(self, data: bytes):
        if data[:len(MSF2_MAGIC)] == MSF2_MAGIC:
            raise SymbolError("PDB 2.00 (JG) files are not supported; use a PDB 7.00 file")
        if data[:32] != MSF7_MAGIC:
            raise SymbolError("not a PDB 7.00 file (bad MSF magic)")
        self.data = data
        bs, _fpm, nblocks, dir_bytes, _unk, map_addr = struct.unpack_from("<6I", data, 32)
        if bs not in (512, 1024, 2048, 4096, 8192, 16384, 32768) or nblocks * bs > len(data) + bs:
            raise SymbolError("PDB block size %d / block count %d inconsistent with the file size" % (bs, nblocks))
        self.bs = bs
        ndir = -(-dir_bytes // bs)
        if map_addr * bs + 4 * ndir > len(data):
            raise SymbolError("PDB block map lies outside the file")
        dir_blocks = struct.unpack_from("<%dI" % ndir, data, map_addr * bs)
        directory = b"".join(self._block(b) for b in dir_blocks)[:dir_bytes]
        if len(directory) < 4:
            raise SymbolError("PDB stream directory is truncated")
        nstreams = struct.unpack_from("<I", directory, 0)[0]
        if 4 + 4 * nstreams > len(directory):
            raise SymbolError("PDB stream directory is truncated")
        sizes = struct.unpack_from("<%dI" % nstreams, directory, 4)
        pos = 4 + 4 * nstreams
        self.streams: List[Optional[Tuple[int, Tuple[int, ...]]]] = []
        for size in sizes:
            if size == 0xFFFFFFFF:
                self.streams.append(None)
                continue
            n = -(-size // bs)
            if pos + 4 * n > len(directory):
                raise SymbolError("PDB stream directory is truncated")
            self.streams.append((size, struct.unpack_from("<%dI" % n, directory, pos)))
            pos += 4 * n

    def _block(self, index: int) -> bytes:
        off = index * self.bs
        if off + self.bs > len(self.data) and off >= len(self.data):
            raise SymbolError("PDB block %d lies outside the file" % index)
        return self.data[off:off + self.bs]

    def stream(self, index: int) -> bytes:
        if index >= len(self.streams) or self.streams[index] is None:
            return b""
        size, blocks = self.streams[index]
        return b"".join(self._block(b) for b in blocks)[:size]


def _cstr(buf: bytes, pos: int) -> Tuple[str, int]:
    end = buf.find(b"\x00", pos)
    if end < 0:
        end = len(buf)
    return buf[pos:end].decode("utf-8", "replace"), end + 1


def _numeric(buf: bytes, pos: int) -> Tuple[int, int]:
    v = struct.unpack_from("<H", buf, pos)[0]
    pos += 2
    if v < 0x8000:
        return v, pos
    if v in _NUMERIC:
        fmt, n = _NUMERIC[v]
        return struct.unpack_from(fmt, buf, pos)[0], pos + n
    if v in _NUMERIC_SKIP:
        return 0, pos + _NUMERIC_SKIP[v]
    if v == 0x8010:  # LF_VARSTRING
        n = struct.unpack_from("<H", buf, pos)[0]
        return 0, pos + 2 + n
    raise SymbolError("unknown numeric leaf 0x%x" % v)


class PdbSymbols(SymbolTable):
    """Symbols and lazily decoded types of one PDB file."""

    def __init__(self, data: bytes, source: str = ""):
        super().__init__(source=source)
        msf = Msf(data)
        info = msf.stream(1)
        if len(info) < 28:
            raise SymbolError("PDB info stream is missing or truncated")
        _ver, _sig, self.age = struct.unpack_from("<III", info, 0)
        self.guid = guid_str(info[12:28])
        self._load_tpi(msf.stream(2))
        self._load_dbi(msf, msf.stream(3))
        self._cache: Dict[int, Type] = {}

    # -- TPI ---------------------------------------------------------------------------------------------
    def _load_tpi(self, tpi: bytes):
        if len(tpi) < 20:
            raise SymbolError("PDB has no type stream (TPI)")
        _ver, hsize, ti_begin, ti_end, nbytes = struct.unpack_from("<5I", tpi, 0)
        if hsize < 20 or hsize + nbytes > len(tpi) or ti_end < ti_begin:
            raise SymbolError("PDB type stream header is inconsistent")
        self._tpi, self._ti_begin = tpi, ti_begin
        offsets = array("I")
        pos, end = hsize, hsize + nbytes
        unpack = struct.unpack_from
        while pos + 4 <= end:
            offsets.append(pos)
            pos += 2 + unpack("<H", tpi, pos)[0]
        if len(offsets) != ti_end - ti_begin:
            self.warnings.append("type stream holds %d records, header says %d" % (len(offsets), ti_end - ti_begin))
        self._offsets = offsets
        self._names: Dict[str, int] = {}
        for i, off in enumerate(offsets):
            leaf = unpack("<H", tpi, off + 2)[0]
            if leaf not in (LF_STRUCTURE, LF_CLASS, LF_UNION, LF_ENUM, LF_INTERFACE):
                continue
            try:
                prop = unpack("<H", tpi, off + 6)[0]
                if prop & PROP_FWDREF:
                    continue
                if leaf == LF_ENUM:
                    npos = off + 4 + 12
                elif leaf == LF_UNION:
                    npos = _numeric(tpi, off + 4 + 8)[1]
                else:
                    npos = _numeric(tpi, off + 4 + 16)[1]
                name = _cstr(tpi, npos)[0]
            except (struct.error, SymbolError):
                continue
            self._names.setdefault(name, ti_begin + i)

    def _record(self, ti: int) -> Tuple[int, int, int]:
        """``(leaf, data start, data end)`` of type index ``ti``."""
        i = ti - self._ti_begin
        if not 0 <= i < len(self._offsets):
            raise SymbolError("type index 0x%x out of range" % ti)
        off = self._offsets[i]
        length, leaf = struct.unpack_from("<HH", self._tpi, off)
        return leaf, off + 4, off + 2 + length

    def _named(self, name: str) -> Optional[Type]:
        ti = self._names.get(name)
        return self._ref(ti) if ti is not None else None

    def _ref(self, ti) -> Optional[Type]:
        if ti is None:
            return None
        t = self._cache.get(ti)
        if t is None:
            t = self._decode(ti)
            self._cache[ti] = t
        return t

    def _decode(self, ti: int) -> Type:
        if ti < self._ti_begin:
            return self._basic(ti)
        leaf, pos, end = self._record(ti)
        buf = self._tpi
        u = struct.unpack_from
        if leaf == LF_MODIFIER:
            return self._ref(u("<I", buf, pos)[0])
        if leaf == LF_POINTER:
            referent, attrs = u("<II", buf, pos)
            size = (attrs >> 13) & 0x3F or 8
            return Type(POINTER, size=size, target=referent)
        if leaf in (LF_PROCEDURE, LF_MFUNCTION):
            return Type(FUNCTION)
        if leaf == LF_ARRAY:
            elem, _idx = u("<II", buf, pos)
            size, npos = _numeric(buf, pos + 8)
            esize = self.sizeof(elem)
            return Type(ARRAY, size=size, target=elem, count=size // esize if esize else 0)
        if leaf == LF_BITFIELD:
            base, length, position = u("<IBB", buf, pos)
            return Type(BITFIELD, size=self.sizeof(base), target=base, bit_pos=position, bit_len=length)
        if leaf in (LF_STRUCTURE, LF_CLASS, LF_INTERFACE, LF_UNION):
            count, prop, flist = u("<HHI", buf, pos)
            size, npos = _numeric(buf, pos + (16 if leaf != LF_UNION else 8))
            name = _cstr(buf, npos)[0]
            if prop & PROP_FWDREF:
                real = self._names.get(name)
                if real is not None and real != ti:
                    return self._ref(real)
                return Type(STRUCT if leaf != LF_UNION else UNION, name=name, incomplete=True)
            t = Type(UNION if leaf == LF_UNION else STRUCT, name=name, size=size)
            t.fields = self._fields(flist, t)
            return t
        if leaf == LF_ENUM:
            _count, prop, utype, flist = u("<HHII", buf, pos)
            name = _cstr(buf, pos + 12)[0]
            base = self._ref(utype)
            t = Type(ENUM, name=name, size=base.size if base else 4, signed=bool(base and base.signed), target=utype)
            t.constants = self._enumerators(flist)
            return t
        return Type(VOID, name="leaf 0x%x" % leaf, incomplete=True)

    def _basic(self, ti: int) -> Type:
        mode = (ti >> 8) & 0xF
        if mode:
            return Type(POINTER, size=_PTR_MODE_SIZE.get(mode, 8), target=ti & 0xFF)
        name, size, signed = _BASIC.get(ti & 0xFF, ("basic 0x%x" % ti, 0, False))
        return Type(VOID if size == 0 else BASE, name=name, size=size, signed=signed)

    def _fieldlist_records(self, flist: int):
        """Yield ``(leaf, buf, pos, end)`` for each member of a field list, following LF_INDEX continuations."""
        seen = set()
        while flist and flist not in seen:
            seen.add(flist)
            leaf, pos, end = self._record(flist)
            if leaf != LF_FIELDLIST:
                return
            buf, nxt = self._tpi, None
            while pos + 2 <= end:
                sub = struct.unpack_from("<H", buf, pos)[0]
                if sub == LF_INDEX:
                    nxt = struct.unpack_from("<I", buf, pos + 4)[0]
                    break
                yield sub, pos + 2
                pos = self._skip_member(sub, pos + 2)
                if pos is None:
                    self.warnings.append("field list 0x%x: unknown member leaf 0x%x, rest ignored" % (flist, sub))
                    return
                while pos < end and buf[pos] >= 0xF0:  # LF_PAD0..LF_PAD15
                    pos += (buf[pos] & 0x0F) or 1
            flist = nxt

    def _skip_member(self, sub: int, pos: int) -> Optional[int]:
        buf = self._tpi
        if sub == LF_MEMBER:
            return _cstr(buf, _numeric(buf, pos + 6)[1])[1]
        if sub == LF_ENUMERATE:
            return _cstr(buf, _numeric(buf, pos + 2)[1])[1]
        if sub == LF_BCLASS:
            return _numeric(buf, pos + 6)[1]
        if sub in (LF_VBCLASS, LF_IVBCLASS):
            return _numeric(buf, _numeric(buf, pos + 10)[1])[1]
        if sub in (LF_STMEMBER, LF_NESTTYPE, LF_FRIENDFCN, LF_NESTTYPEEX):
            return _cstr(buf, pos + 6)[1]
        if sub == LF_METHOD:
            return _cstr(buf, pos + 6)[1]
        if sub == LF_ONEMETHOD:
            attr = struct.unpack_from("<H", buf, pos)[0]
            p = pos + 6 + (4 if ((attr >> 2) & 7) in (4, 6) else 0)
            return _cstr(buf, p)[1]
        if sub in (LF_VFUNCTAB, LF_FRIENDCLS):
            return pos + 6
        return None

    def _fields(self, flist: int, owner: Type) -> List[Tuple[str, int, object]]:
        out = []
        for sub, pos in self._fieldlist_records(flist):
            buf = self._tpi
            if sub == LF_MEMBER:
                _attr, mtype = struct.unpack_from("<HI", buf, pos)
                moff, npos = _numeric(buf, pos + 6)
                out.append((_cstr(buf, npos)[0], moff, mtype))
            elif sub == LF_BCLASS:  # C++ base class: its members appear at the given offset
                _attr, btype = struct.unpack_from("<HI", buf, pos)
                boff = _numeric(buf, pos + 6)[0]
                out.append(("<base>", boff, btype))
        return out

    def _enumerators(self, flist: int) -> Dict[str, int]:
        out = {}
        for sub, pos in self._fieldlist_records(flist):
            if sub == LF_ENUMERATE:
                val, npos = _numeric(self._tpi, pos + 2)
                out[_cstr(self._tpi, npos)[0]] = val
        return out

    # -- DBI / symbols ----------------------------------------------------------------------------------------
    def _load_dbi(self, msf: Msf, dbi: bytes):
        if len(dbi) < 64:
            self.warnings.append("PDB has no DBI stream: no symbols")
            return
        (sig, _ver, _age, _gsi, _build, _psi, _dllver, symrec, _rbld, modi, secc, secm, srci, tsm, _mfc, dbgh,
         ecs, _flags, machine) = struct.unpack_from("<iIIHHHHHHiiiiiIiiHH", dbi, 0)
        self.machine = MACHINES.get(machine, "0x%x" % machine)
        if sig != -1:
            self.warnings.append("unexpected DBI signature %d" % sig)
        opt = 64 + modi + secc + secm + srci + tsm + ecs
        streams = [struct.unpack_from("<H", dbi, opt + 2 * i)[0] for i in range(max(0, dbgh) // 2)
                   if opt + 2 * i + 2 <= len(dbi)]

        def dbg_stream(i):
            return streams[i] if i < len(streams) and streams[i] != 0xFFFF else None

        omap_from = dbg_stream(4)
        sec_stream = dbg_stream(10) if omap_from is not None and dbg_stream(10) is not None else dbg_stream(5)
        sections = []
        if sec_stream is not None:
            raw = msf.stream(sec_stream)
            for i in range(len(raw) // 40):
                sections.append(struct.unpack_from("<I", raw, i * 40 + 12)[0])  # VirtualAddress
        omap = []
        if omap_from is not None:
            raw = msf.stream(omap_from)
            omap = [struct.unpack_from("<II", raw, i) for i in range(0, len(raw) - 7, 8)]
        self.sections = sections
        omap_src = [s for s, _ in omap]

        def rva_of(seg: int, off: int) -> Optional[int]:
            if not 1 <= seg <= len(sections):
                return None
            rva = sections[seg - 1] + off
            if omap:
                j = bisect.bisect_right(omap_src, rva) - 1
                if j < 0 or omap[j][1] == 0:
                    return None
                rva = omap[j][1] + (rva - omap[j][0])
            return rva

        if symrec == 0xFFFF:
            self.warnings.append("PDB has no symbol record stream")
            return
        recs = msf.stream(symrec)
        pos, n = 0, len(recs)
        u = struct.unpack_from
        globals_types: Dict[str, int] = {}
        while pos + 4 <= n:
            length, kind = u("<HH", recs, pos)
            if length < 2:
                break
            body = pos + 4
            if kind == S_PUB32 and body + 10 <= n:
                _flags, off, seg = u("<IIH", recs, body)
                name = _cstr(recs, body + 10)[0]
                rva = rva_of(seg, off)
                if rva is not None:
                    self.symbols.setdefault(name, rva)
            elif kind in (S_GDATA32, S_LDATA32) and body + 10 <= n:
                ti, off, seg = u("<IIH", recs, body)
                name = _cstr(recs, body + 10)[0]
                rva = rva_of(seg, off)
                if rva is not None:
                    self.symbols.setdefault(name, rva)
                    globals_types.setdefault(name, ti)
            pos += 2 + length
        self.symbol_types = globals_types


def load(path: str) -> PdbSymbols:
    with open(path, "rb") as fh:
        data = fh.read()
    table = PdbSymbols(data, source=path)
    import os
    table.pdb_name = os.path.basename(path)
    return table
