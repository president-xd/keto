"""Minimal PE32/PE32+ reader for loaded images (RVA = offset from the image base) and files on disk.

Gives the CodeView (RSDS) record that names a module's PDB (file name, GUID, age), the section table and the
export table. Reference: Microsoft "PE Format" (IMAGE_DOS_HEADER.e_lfanew at 0x3C, IMAGE_FILE_HEADER,
optional-header magic 0x10B / 0x20B, data directories [0] export and [6] debug, IMAGE_DEBUG_DIRECTORY of 28 bytes
with Type 2 = CODEVIEW).
"""

from __future__ import annotations

import struct
from typing import Callable, Dict, List, NamedTuple, Optional, Tuple

from keto.framework.exceptions import InvalidAddressException, KetoError
from keto.winmem.pdb import MACHINES, guid_str


class PeError(KetoError):
    pass


class CodeView(NamedTuple):
    pdb_name: str
    guid: str
    age: int

    @property
    def key(self) -> str:
        return "%s%X" % (self.guid, self.age)


class Section(NamedTuple):
    name: str
    rva: int
    vsize: int
    raw_offset: int
    raw_size: int
    characteristics: int


class PeImage:
    """``read(rva, n) -> bytes`` gives the image as mapped (memory) or through the section table (file)."""

    def __init__(self, read: Callable[[int, int], bytes]):
        self._read = read
        dos = read(0, 0x40)
        if dos[:2] != b"MZ":
            raise PeError("no MZ header")
        self.nt = struct.unpack_from("<I", dos, 0x3C)[0]
        if not 0x40 <= self.nt <= 0x1000:
            raise PeError("implausible e_lfanew 0x%x" % self.nt)
        hdr = read(self.nt, 24)
        if hdr[:4] != b"PE\x00\x00":
            raise PeError("no PE signature")
        (self.machine_id, nsec, self.timestamp, _sym, _nsym, opt_size, self.characteristics) = \
            struct.unpack_from("<HHIIIHH", hdr, 4)
        opt = read(self.nt + 24, opt_size)
        self.magic = struct.unpack_from("<H", opt, 0)[0]
        if self.magic == 0x20B:
            self.image_base, = struct.unpack_from("<Q", opt, 24)
            self.size_of_image, = struct.unpack_from("<I", opt, 56)
            ndirs = struct.unpack_from("<I", opt, 108)[0]
            dirs_at = 112
        elif self.magic == 0x10B:
            self.image_base, = struct.unpack_from("<I", opt, 28)
            self.size_of_image, = struct.unpack_from("<I", opt, 56)
            ndirs = struct.unpack_from("<I", opt, 92)[0]
            dirs_at = 96
        else:
            raise PeError("unknown optional-header magic 0x%x" % self.magic)
        self.directories: List[Tuple[int, int]] = []
        for i in range(min(ndirs, 16)):
            if dirs_at + 8 * i + 8 <= len(opt):
                self.directories.append(struct.unpack_from("<II", opt, dirs_at + 8 * i))
        raw = read(self.nt + 24 + opt_size, 40 * nsec)
        self.sections: List[Section] = []
        for i in range(nsec):
            name, vsize, rva, rsize, roff = struct.unpack_from("<8sIIII", raw, 40 * i)
            chars = struct.unpack_from("<I", raw, 40 * i + 36)[0]
            self.sections.append(Section(name.rstrip(b"\x00").decode("ascii", "replace"), rva, vsize, roff, rsize,
                                         chars))

    @property
    def machine(self) -> str:
        return MACHINES.get(self.machine_id, "0x%x" % self.machine_id)

    def read(self, rva: int, n: int) -> bytes:
        return self._read(rva, n)

    def _dir(self, index: int) -> Tuple[int, int]:
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def codeview(self) -> Optional[CodeView]:
        rva, size = self._dir(6)
        if not rva or not size:
            return None
        data = self.read(rva, min(size, 28 * 32))
        for i in range(len(data) // 28):
            _ch, _ts, _maj, _min, typ, dsize, drva, _dptr = struct.unpack_from("<IIHHIIII", data, 28 * i)
            if typ != 2 or not drva or dsize < 24:
                continue
            cv = self.read(drva, min(dsize, 24 + 260))
            if cv[:4] != b"RSDS":
                continue
            age = struct.unpack_from("<I", cv, 20)[0]
            name = cv[24:].split(b"\x00", 1)[0].decode("utf-8", "replace")
            return CodeView(name.replace("\\", "/").rsplit("/", 1)[-1], guid_str(cv[4:20]), age)
        return None

    def exports(self) -> Dict[str, int]:
        """Export name -> RVA (forwarders are skipped)."""
        rva, size = self._dir(0)
        if not rva or not size:
            return {}
        d = self.read(rva, 40)
        nfuncs, nnames, afuncs, anames, aords = struct.unpack_from("<IIIII", d, 20)
        if nfuncs > 0x20000 or nnames > 0x20000:
            raise PeError("implausible export table")
        funcs = struct.unpack("<%dI" % nfuncs, self.read(afuncs, 4 * nfuncs))
        names = struct.unpack("<%dI" % nnames, self.read(anames, 4 * nnames))
        ords = struct.unpack("<%dH" % nnames, self.read(aords, 2 * nnames))
        out = {}
        for name_rva, ordinal in zip(names, ords):
            if ordinal >= nfuncs:
                continue
            target = funcs[ordinal]
            if rva <= target < rva + size:
                continue  # forwarder string
            out[self._string(name_rva)] = target
        return out

    def _string(self, rva: int, limit: int = 256) -> str:
        return self.read(rva, limit).split(b"\x00", 1)[0].decode("ascii", "replace")


def from_file(path: str) -> PeImage:
    """A PE file on disk, read through its section table."""
    with open(path, "rb") as fh:
        data = fh.read()
    holder: Dict[str, PeImage] = {}

    def read(rva: int, n: int) -> bytes:
        pe = holder.get("pe")
        if pe is None:  # headers: file offset == RVA
            return data[rva:rva + n]
        for s in pe.sections:
            if s.rva <= rva < s.rva + max(s.vsize, s.raw_size):
                off = s.raw_offset + (rva - s.rva)
                return data[off:off + n].ljust(n, b"\x00")
        return data[rva:rva + n]

    pe = PeImage(read)
    holder["pe"] = pe
    return pe


def from_memory(read_va: Callable[[int, int], bytes], base: int) -> PeImage:
    """A PE image mapped at ``base``; unreadable pages surface as InvalidAddressException from ``read_va``."""
    return PeImage(lambda rva, n: read_va(base + rva, n))


def safe_codeview(read_va: Callable[[int, int], bytes], base: int) -> Optional[CodeView]:
    try:
        return from_memory(read_va, base).codeview()
    except (PeError, InvalidAddressException, struct.error):
        return None
