"""A small, defensive ELF32/ELF64 little-endian parser (no dependencies).

Built for carving: every offset is bounds-checked because the input is a
memory region that may be truncated or partially overwritten.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional

from keto.framework.exceptions import FormatError

ELF_MAGIC = b"\x7fELF"
EM_NAMES = {0: "NONE", 3: "x86", 8: "MIPS", 20: "PPC", 21: "PPC64", 40: "ARM", 50: "IA-64", 62: "x86-64",
            183: "AArch64", 190: "CUDA", 243: "RISC-V", 247: "BPF", 224: "AMDGPU"}
ET_NAMES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
SHT_SYMTAB, SHT_STRTAB, SHT_NOTE, SHT_NOBITS, SHT_DYNSYM = 2, 3, 7, 8, 11
STT_NAMES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 10: "GNU_IFUNC", 13: "LOPROC"}
STB_NAMES = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "LOOS"}


class Section:
    __slots__ = ("index", "name_off", "name", "type", "flags", "addr", "offset", "size", "link", "info",
                 "align", "entsize")

    def __init__(self, index, fields):
        (self.name_off, self.type, self.flags, self.addr, self.offset, self.size, self.link, self.info,
         self.align, self.entsize) = fields
        self.index = index
        self.name = ""


class Symbol:
    __slots__ = ("name", "value", "size", "type", "bind", "other", "shndx")

    def __init__(self, name, value, size, info, other, shndx):
        self.name, self.value, self.size, self.other, self.shndx = name, value, size, other, shndx
        self.type = info & 0xF
        self.bind = info >> 4

    @property
    def type_name(self):
        return STT_NAMES.get(self.type, str(self.type))

    @property
    def bind_name(self):
        return STB_NAMES.get(self.bind, str(self.bind))


class Note:
    __slots__ = ("name", "type", "desc", "section")

    def __init__(self, name, ntype, desc, section):
        self.name, self.type, self.desc, self.section = name, ntype, desc, section


class ElfFile:
    def __init__(self, data: bytes):
        if len(data) < 52 or data[:4] != ELF_MAGIC:
            raise FormatError("not an ELF image")
        self.data = bytes(data)
        self.ei_class = data[4]
        if data[5] != 1:
            raise FormatError("only little-endian ELF is supported")
        self.is64 = self.ei_class == 2
        self.osabi = data[7]
        self.abiversion = data[8]
        if self.is64:
            if len(data) < 64:
                raise FormatError("truncated ELF64 header")
            (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff, self.e_shoff, self.e_flags,
             self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        else:
            (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff, self.e_shoff, self.e_flags,
             self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        self.sections: List[Section] = []
        self.truncated = False
        self._parse_sections()

    @property
    def machine_name(self) -> str:
        return EM_NAMES.get(self.e_machine, "EM_%d" % self.e_machine)

    @property
    def type_name(self) -> str:
        return ET_NAMES.get(self.e_type, str(self.e_type))

    def _parse_sections(self):
        if not self.e_shoff or not self.e_shnum or self.e_shnum > 4096:
            return
        fmt = "<IIQQQQIIQQ" if self.is64 else "<IIIIIIIIII"
        esz = struct.calcsize(fmt)
        if self.e_shentsize < esz:
            return
        for i in range(self.e_shnum):
            o = self.e_shoff + i * self.e_shentsize
            if o + esz > len(self.data):
                self.truncated = True
                break
            self.sections.append(Section(i, struct.unpack_from(fmt, self.data, o)))
        if self.e_shstrndx < len(self.sections):
            strtab = self.sections[self.e_shstrndx]
            for s in self.sections:
                s.name = self._str(strtab, s.name_off)

    def _str(self, strtab: Section, off: int) -> str:
        start = strtab.offset + off
        if start >= len(self.data) or off >= strtab.size:
            return ""
        end = self.data.find(b"\x00", start, strtab.offset + strtab.size)
        return self.data[start:end if end >= 0 else start + 256].decode("utf-8", "replace")

    def section(self, name: str) -> Optional[Section]:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def section_data(self, s: Section) -> bytes:
        if s.type == SHT_NOBITS:
            return b""
        end = s.offset + s.size
        if end > len(self.data):
            self.truncated = True
        return self.data[s.offset:min(end, len(self.data))]

    def symbols(self) -> List[Symbol]:
        out = []
        for s in self.sections:
            if s.type not in (SHT_SYMTAB, SHT_DYNSYM) or s.link >= len(self.sections):
                continue
            strtab = self.sections[s.link]
            fmt = "<IBBHQQ" if self.is64 else "<IIIBBH"
            esz = struct.calcsize(fmt)
            data = self.section_data(s)
            for i in range(len(data) // esz):
                if self.is64:
                    name, info, other, shndx, value, size = struct.unpack_from(fmt, data, i * esz)
                else:
                    name, value, size, info, other, shndx = struct.unpack_from(fmt, data, i * esz)
                out.append(Symbol(self._str(strtab, name), value, size, info, other, shndx))
        return out

    def notes(self) -> List[Note]:
        out = []
        for s in self.sections:
            if s.type != SHT_NOTE:
                continue
            data = self.section_data(s)
            pos = 0
            while pos + 12 <= len(data):
                namesz, descsz, ntype = struct.unpack_from("<III", data, pos)
                pos += 12
                name = data[pos:pos + namesz].rstrip(b"\x00").decode("utf-8", "replace")
                pos += (namesz + 3) & ~3
                desc = data[pos:pos + descsz]
                pos += (descsz + 3) & ~3
                out.append(Note(name, ntype, desc, s.name))
                if namesz == 0 and descsz == 0:
                    break
        return out

    def program_headers(self) -> List[Dict[str, int]]:
        out = []
        if not self.e_phoff or not self.e_phnum or self.e_phnum > 512:
            return out
        fmt = "<IIQQQQQQ" if self.is64 else "<IIIIIIII"
        for i in range(self.e_phnum):
            o = self.e_phoff + i * self.e_phentsize
            if o + struct.calcsize(fmt) > len(self.data):
                break
            v = struct.unpack_from(fmt, self.data, o)
            if self.is64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = v
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = v
            out.append({"type": p_type, "flags": p_flags, "offset": p_offset, "vaddr": p_vaddr,
                        "filesz": p_filesz, "memsz": p_memsz})
        return out


def elf_extent(data: bytes) -> Optional[int]:
    """Best-effort size of an ELF image that starts at ``data[0]`` (for carving)."""
    if data[:4] != ELF_MAGIC or len(data) < 52:
        return None
    is64 = data[4] == 2
    try:
        if is64:
            phoff, shoff = struct.unpack_from("<QQ", data, 0x20)
            phentsize, phnum, shentsize, shnum = struct.unpack_from("<HHHH", data, 0x36)
        else:
            phoff, shoff = struct.unpack_from("<II", data, 0x1C)
            phentsize, phnum, shentsize, shnum = struct.unpack_from("<HHHH", data, 0x2A)
    except struct.error:
        return None
    end = 64 if is64 else 52
    if shoff and shnum and shnum < 4096:
        end = max(end, shoff + shnum * shentsize)
        fmt = "<IIQQQQIIQQ" if is64 else "<IIIIIIIIII"
        for i in range(shnum):
            o = shoff + i * shentsize
            if o + struct.calcsize(fmt) > len(data):
                break
            f = struct.unpack_from(fmt, data, o)
            stype, soff, ssize = f[1], f[4], f[5]
            if stype != SHT_NOBITS and soff + ssize < (1 << 32):
                end = max(end, soff + ssize)
    if phoff and phnum and phnum < 512:
        fmt = "<IIQQQQQQ" if is64 else "<IIIIIIII"
        for i in range(phnum):
            o = phoff + i * phentsize
            if o + struct.calcsize(fmt) > len(data):
                break
            v = struct.unpack_from(fmt, data, o)
            off, filesz = (v[2], v[5]) if is64 else (v[1], v[4])
            if off + filesz < (1 << 32):
                end = max(end, off + filesz)
    return end
