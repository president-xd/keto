"""CUDA binaries (cubin): ELF files with ``e_machine == 190`` (EM_CUDA).

Decoded from the binary itself (checked against a cubin JIT-compiled by the
local driver):

* SM architecture from ``e_flags``: ABI version 7 -> bits 7:0; ABI version 8
  (CUDA 12.8+ / 13.x) -> bits 15:8 (``0x06005904`` = sm_89).
* Kernels: ``STT_FUNC`` symbols whose section is ``.text.<name>``; the section's
  ``sh_info`` bits 31:24 hold the register count.
* ``.nv.info`` / ``.nv.info.<kernel>``: attribute records ``{u8 format, u8 attr, ...}``
  (format 1 = no value, 2 = byte, 3 = u16, 4 = u16 size + payload).
* ``.note.nv.tkinfo``: toolkit / ptxas version and command line;
  ``.note.nv.cuinfo``: u16 version, u16 virtual SM (PTX target), u32 toolkit version.
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Dict, List, Optional

from keto.formats.elf import ElfFile

EM_CUDA = 190

#: EIATTR names (as printed by cuobjdump -elf); ids confirmed for the subset seen in real cubins
EIATTR = {
    0x01: "PAD", 0x02: "IMAGE_SLOT", 0x03: "JUMPTABLE_RELOCS", 0x04: "CTAIDZ_USED", 0x05: "MAX_THREADS",
    0x06: "IMAGE_OFFSET", 0x07: "IMAGE_SIZE", 0x08: "TEXTURE_NORMALIZED", 0x09: "SAMPLER_INIT",
    0x0A: "PARAM_CBANK", 0x0B: "SMEM_PARAM_OFFSETS", 0x0C: "CBANK_PARAM_OFFSETS", 0x0D: "SYNC_STACK",
    0x0E: "TEXID_SAMPID_MAP", 0x0F: "EXTERNS", 0x10: "REQNTID", 0x11: "FRAME_SIZE", 0x12: "MIN_STACK_SIZE",
    0x13: "SAMPLER_FORCE_UNNORMALIZED", 0x14: "BINDLESS_IMAGE_OFFSETS", 0x15: "BINDLESS_TEXTURE_BANK",
    0x16: "BINDLESS_SURFACE_BANK", 0x17: "KPARAM_INFO", 0x18: "SMEM_PARAM_SIZE", 0x19: "CBANK_PARAM_SIZE",
    0x1A: "QUERY_NUMATTRIB", 0x1B: "MAXREG_COUNT", 0x1C: "EXIT_INSTR_OFFSETS", 0x1D: "S2RCTAID_INSTR_OFFSETS",
    0x1E: "CRS_STACK_SIZE", 0x1F: "NEED_CNP_WRAPPER", 0x20: "NEED_CNP_PATCH", 0x21: "EXPLICIT_CACHING",
    0x22: "ISTYPEP_USED", 0x23: "MAX_STACK_SIZE", 0x24: "SUQ_USED", 0x25: "LD_CACHEMOD_INSTR_OFFSETS",
    0x26: "LOAD_CACHE_REQUEST", 0x27: "ATOM_SYS_INSTR_OFFSETS", 0x28: "COOP_GROUP_INSTR_OFFSETS",
    0x29: "COOP_GROUP_MAX_REGIDS", 0x2A: "SW1850030_WAR", 0x2B: "WMMA_USED", 0x2C: "HAS_PRE_V10_OBJECT",
    0x2D: "ATOMF16_EMUL_INSTR_OFFSETS", 0x2E: "ATOM16_EMUL_INSTR_REG_MAP", 0x2F: "REGCOUNT",
    0x30: "SW2393858_WAR", 0x31: "INT_WARP_WIDE_INSTR_OFFSETS", 0x32: "SHARED_SCRATCH",
    0x33: "STATISTICS", 0x34: "INDIRECT_BRANCH_TARGETS", 0x35: "SW2861232_WAR", 0x36: "SW_WAR",
    0x37: "CUDA_API_VERSION", 0x38: "NUM_MBARRIERS", 0x39: "MBARRIER_INSTR_OFFSETS",
    0x3A: "COROUTINE_RESUME_ID_OFFSETS", 0x3B: "SAM_REGION_STACK_SIZE", 0x3C: "PER_REG_TARGET_PERF_STATS",
    0x3D: "CTA_PER_CLUSTER", 0x3E: "EXPLICIT_CLUSTER", 0x3F: "MAX_CLUSTER_RANK", 0x40: "INSTR_REG_MAP",
}
EIFMT = {1: "NVAL", 2: "BVAL", 3: "HVAL", 4: "SVAL"}

DEVICE_IMPORTS_OF_INTEREST = {
    "vprintf": "device-side printf",
    "malloc": "device heap allocation",
    "free": "device heap free",
    "__assertfail": "device assert",
    "cudaLaunchDevice": "dynamic parallelism launch",
    "cudaGetParameterBufferV2": "dynamic parallelism",
}


def sm_from_flags(abiversion: int, e_flags: int) -> Optional[int]:
    if abiversion >= 8:
        return (e_flags >> 8) & 0xFF
    return e_flags & 0xFF


def demangle(name: str) -> str:
    """Best-effort Itanium demangling of the function name only (no third-party deps)."""
    m = re.match(r"_Z(?:N(.*?)E|(\d+)(.*))", name)
    if not m:
        return name
    try:
        if m.group(2):
            n = int(m.group(2))
            return m.group(3)[:n] + "(...)"
        parts, s = [], m.group(1)
        while s and s[0].isdigit():
            n_str = re.match(r"\d+", s).group()
            n = int(n_str)
            parts.append(s[len(n_str):len(n_str) + n])
            s = s[len(n_str) + n:]
        return "::".join(parts) + "(...)" if parts else name
    except (ValueError, AttributeError):
        return name


class NvInfoRecord:
    __slots__ = ("fmt", "attr", "value", "payload")

    def __init__(self, fmt, attr, value, payload):
        self.fmt, self.attr, self.value, self.payload = fmt, attr, value, payload

    @property
    def name(self):
        return EIATTR.get(self.attr, "ATTR_0x%02x" % self.attr)


def parse_nvinfo(data: bytes) -> List[NvInfoRecord]:
    out, pos = [], 0
    while pos + 2 <= len(data):
        fmt, attr = data[pos], data[pos + 1]
        pos += 2
        if fmt == 1:
            out.append(NvInfoRecord(fmt, attr, None, b""))
        elif fmt == 2:
            if pos + 1 > len(data):
                break
            out.append(NvInfoRecord(fmt, attr, data[pos], b""))
            pos += 1
        elif fmt == 3:
            if pos + 2 > len(data):
                break
            out.append(NvInfoRecord(fmt, attr, struct.unpack_from("<H", data, pos)[0], b""))
            pos += 2
        elif fmt == 4:
            if pos + 2 > len(data):
                break
            size = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            payload = data[pos:pos + size]
            pos += size
            out.append(NvInfoRecord(fmt, attr, None, payload))
        else:
            break  # unknown format: stop rather than misparse
    return out


class Kernel:
    def __init__(self, name, section, text: bytes, regcount: int):
        self.name = name
        self.demangled = demangle(name)
        self.section = section
        self.text = text
        self.regcount = regcount
        self.attributes: Dict[str, object] = {}
        self.params: List[dict] = []
        self.sha256 = hashlib.sha256(text).hexdigest()

    @property
    def text_offset(self):
        return self.section.offset

    @property
    def size(self):
        return len(self.text)


class Cubin:
    """A parsed CUDA ELF. Construct with :func:`parse_cubin`."""

    def __init__(self, elf: ElfFile):
        self.elf = elf
        self.sm = sm_from_flags(elf.abiversion, elf.e_flags)
        self.virtual_sm: Optional[int] = None
        self.toolkit_version: Optional[str] = None
        self.tool_strings: List[str] = []
        self.kernels: List[Kernel] = []
        self.functions: List[str] = []
        self.globals: List[str] = []
        self.imports: List[str] = []
        self.module_attributes: Dict[str, object] = {}
        self._parse()

    def _parse(self):
        elf = self.elf
        syms = elf.symbols()
        by_index = {s.index: s for s in elf.sections}
        for n in elf.notes():
            if n.section == ".note.nv.cuinfo" and len(n.desc) >= 8:
                ver, vsm, tk = struct.unpack_from("<HHI", n.desc)
                self.virtual_sm = vsm
                self.toolkit_version = "%d.%d" % (tk // 10, tk % 10)
            elif n.section.startswith(".note.nv"):
                self.tool_strings += [s.decode("utf-8", "replace") for s in re.findall(rb"[\x20-\x7e]{4,}", n.desc)
                                      if s != b"NVIDIA Corp"]
        for s in syms:
            sec = by_index.get(s.shndx)
            if s.shndx == 0 and s.name and s.bind in (1, 2):
                self.imports.append(s.name)
                continue
            if sec is None:
                continue
            if s.type == 2 and sec.name == ".text." + s.name:
                self.kernels.append(Kernel(s.name, sec, elf.section_data(sec), (sec.info >> 24) & 0xFF))
            elif s.type == 2:
                self.functions.append(s.name)
            elif s.type == 1:
                self.globals.append(s.name)
        # attributes
        mod = elf.section(".nv.info")
        if mod is not None:
            for r in parse_nvinfo(elf.section_data(mod)):
                if r.fmt == 4 and len(r.payload) == 8:
                    self.module_attributes.setdefault(r.name, []).append(struct.unpack("<II", r.payload))
                elif r.value is not None:
                    self.module_attributes[r.name] = r.value
        for k in self.kernels:
            sec = elf.section(".nv.info." + k.name)
            if sec is None:
                continue
            for r in parse_nvinfo(elf.section_data(sec)):
                if r.attr == 0x17 and len(r.payload) >= 12:  # KPARAM_INFO
                    idx, ordinal, offset, flags = struct.unpack_from("<IHHI", r.payload)
                    k.params.append({"ordinal": ordinal, "offset": offset, "size": (flags >> 18) & 0x3FFF})
                elif r.attr == 0x1C:  # EXIT_INSTR_OFFSETS
                    k.attributes["exit_offsets"] = list(struct.unpack("<%dI" % (len(r.payload) // 4), r.payload))
                elif r.attr == 0x37 and len(r.payload) >= 4:
                    k.attributes["cuda_api_version"] = struct.unpack_from("<I", r.payload)[0]
                elif r.fmt == 4 and len(r.payload) == 4:
                    k.attributes[r.name] = struct.unpack("<I", r.payload)[0]
                elif r.value is not None:
                    k.attributes[r.name] = r.value
                else:
                    k.attributes[r.name] = r.payload.hex() if r.payload else True
            k.params.sort(key=lambda p: p["ordinal"])
        for name, recs in list(self.module_attributes.items()):
            if name in ("REGCOUNT", "FRAME_SIZE", "MIN_STACK_SIZE", "MAX_STACK_SIZE") and isinstance(recs, list):
                symidx = {i: s for i, s in enumerate(syms)}
                for idx, val in recs:
                    sym = symidx.get(idx)
                    for k in self.kernels:
                        if sym is not None and sym.name == k.name:
                            k.attributes[name] = val

    @property
    def arch(self) -> str:
        return "sm_%d" % self.sm if self.sm is not None else "?"

    def kernel_names(self) -> List[str]:
        return [k.name for k in self.kernels]


def parse_cubin(data: bytes) -> Cubin:
    elf = ElfFile(data)
    if elf.e_machine != EM_CUDA:
        raise ValueError("ELF e_machine %d is not EM_CUDA" % elf.e_machine)
    return Cubin(elf)


# ------------------------------------------------------------------------------------------
# minimal cubin writer (synthetic test images; produces a structurally valid CUDA ELF)
# ------------------------------------------------------------------------------------------
def build_cubin(kernels: Dict[str, bytes], sm: int = 89, toolkit: int = 131, virtual_sm: int = 89,
                regcount: int = 16, tool_note: str = "ptxas Cuda compilation tools, release 13.1") -> bytes:
    """Build a small cubin with one ``.text.<name>`` section per kernel."""
    shstr = bytearray(b"\x00")
    strtab = bytearray(b"\x00")

    def add(tab, s):
        off = len(tab)
        tab += s.encode() + b"\x00"
        return off

    sections = []  # (name_off, type, flags, data, link, info, align, entsize)
    names = [".shstrtab", ".strtab", ".symtab", ".note.nv.tkinfo", ".note.nv.cuinfo", ".nv.info"]
    name_offs = {n: add(shstr, n) for n in names}
    kernel_list = list(kernels.items())
    for kname, _ in kernel_list:
        name_offs[".nv.info." + kname] = add(shstr, ".nv.info." + kname)
        name_offs[".text." + kname] = add(shstr, ".text." + kname)

    def note(name, ntype, desc):
        nb = name.encode() + b"\x00"
        out = struct.pack("<III", len(nb), len(desc), ntype) + nb + b"\x00" * (-len(nb) % 4)
        return out + desc + b"\x00" * (-len(desc) % 4)

    tk_desc = struct.pack("<II", 2, 0) + tool_note.encode() + b"\x00"
    cu_desc = struct.pack("<HHI", 2, virtual_sm, toolkit)
    # section indices: 0 null,1 shstrtab,2 strtab,3 symtab,4 tkinfo,5 cuinfo,6 nv.info, then per kernel: info, text
    first_kernel_sec = 7
    syms = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    nvinfo = bytearray()
    for i, (kname, text) in enumerate(kernel_list):
        text_idx = first_kernel_sec + 2 * i + 1
        symname = add(strtab, kname)
        syms.append(struct.pack("<IBBHQQ", symname, (1 << 4) | 2, 0x10, text_idx, 0, len(text)))
        sym_index = len(syms) - 1
        nvinfo += struct.pack("<BBHII", 4, 0x2F, 8, sym_index, regcount)
    sections.append((name_offs[".shstrtab"], 3, 0, None, 0, 0, 1, 0))
    sections.append((name_offs[".strtab"], 3, 0, bytes(strtab), 0, 0, 1, 0))
    sections.append((name_offs[".symtab"], 2, 0, b"".join(syms), 2, 1, 8, 24))
    sections.append((name_offs[".note.nv.tkinfo"], 7, 0x2000000, note("NVIDIA Corp", 2000, tk_desc), 0, 0, 4, 0))
    sections.append((name_offs[".note.nv.cuinfo"], 7, 0x1000000, note("NVIDIA Corp", 1000, cu_desc), 0, 0, 4, 0))
    sections.append((name_offs[".nv.info"], 0x70000000, 0, bytes(nvinfo), 3, 0, 4, 0))
    for i, (kname, text) in enumerate(kernel_list):
        text_idx = first_kernel_sec + 2 * i + 1
        exits = [o for o in range(0, len(text) - 15, 16) if text[o:o + 2] == b"\x4d\x79"]
        kinfo = b""
        if exits:
            kinfo += struct.pack("<BBH", 4, 0x1C, 4 * len(exits)) + struct.pack("<%dI" % len(exits), *exits)
        kinfo += struct.pack("<BBHI", 4, 0x37, 4, toolkit)
        sections.append((name_offs[".nv.info." + kname], 0x70000000, 0x40, kinfo, 3, text_idx, 4, 0))
        sections.append((name_offs[".text." + kname], 1, 6, text, 3, (regcount << 24) | (i + 1), 128, 0))
    shstr_bytes = bytes(shstr)
    # layout: header, then section data, then section headers
    body = bytearray(b"\x00" * 64)
    offsets = []
    for idx, sec in enumerate(sections):
        data = shstr_bytes if sec[3] is None else sec[3]
        align = max(sec[6], 1)
        while len(body) % align:
            body += b"\x00"
        offsets.append((len(body), len(data)))
        body += data
    while len(body) % 8:
        body += b"\x00"
    shoff = len(body)
    shdrs = bytearray(struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    for sec, (off, size) in zip(sections, offsets):
        name_off, stype, flags, _, link, info, align, entsize = sec
        shdrs += struct.pack("<IIQQQQIIQQ", name_off, stype, flags, 0, off, size, link, info, align, entsize)
    e_flags = (6 << 24) | (sm << 8) | 0x04
    ident = b"\x7fELF" + bytes([2, 1, 1, 0x41, 8]) + b"\x00" * 7
    hdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, EM_CUDA, 1, 0, 0, shoff, e_flags, 64, 56, 0, 64,
                              len(sections) + 1, 1)
    body[:64] = hdr
    return bytes(body) + bytes(shdrs)
