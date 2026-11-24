"""ELF cores of virtual machines (and other physical-memory ELF cores) as a physical-address layer.

Which address field holds the guest physical address, verified in each producer's source:

* QEMU ``dump-guest-memory`` (``dump/dump.c`` ``write_elf64_load``/``write_elf32_load``): ``p_paddr`` = guest physical
  address; ``p_vaddr`` = the guest virtual address with paging (``-p``), otherwise a copy of ``p_paddr``; ``p_filesz``
  may be smaller than ``p_memsz`` (the rest is not in the file). With more than 0xFFFF program headers ``e_phnum`` is
  PN_XNUM and the real count is section header 0's ``sh_info``. Per CPU a "CORE" NT_PRSTATUS note and a "QEMU"
  note (type 0) carry the registers; ``QEMUCPUState`` (``target/i386/arch_dump.c``) has ``cr[5]`` at offset 392.
* VirtualBox ``dumpvmcore`` (``DBGFR3CoreWrite.cpp``): ``p_paddr`` = guest physical start of each RAM range,
  ``p_vaddr`` = 0, MMIO ranges have ``p_filesz`` = 0; notes "VBCORE" (type 0xB00, ``DBGFCOREDESCRIPTOR``, magic
  0xC01AC0DE) and one "VBCPU" (0xB01, ``DBGFCORECPU``: cr0/cr2/cr3/cr4 at 288/296/304/312) per CPU.
* Other ELF cores whose ``p_paddr`` are physical addresses (e.g. Linux vmcore) open the same way; segments with
  ``p_paddr`` = -1 (kcore vmalloc) are skipped. A core whose PT_LOADs all have ``p_paddr`` 0 is a process core and
  is refused.
"""

from __future__ import annotations

import struct
from typing import List, Tuple

from keto.formats.memimage import file_runs
from keto.framework.exceptions import FormatError, UnsupportedError

ET_CORE, PT_LOAD, PT_NOTE, PN_XNUM = 4, 1, 4, 0xFFFF
EM = {3: "x86", 62: "x86-64", 183: "aarch64", 40: "arm"}
QEMU_CR_OFFSET = 8 + 18 * 8 + 10 * 24       # version, size, 18 GPRs/rip/rflags, 10 segments of 24 bytes
VBOX_MAGIC = 0xC01AC0DE
NT_VBOXCORE, NT_VBOXCPU = 0xB00, 0xB01
VBOX_CR_OFFSET = 18 * 8 + 6 * 24            # 18 GPRs/rip/rsp/rbp/rflags, 6 DBGFCORESEL of 24 bytes


def _ehdr(head: bytes):
    """``(class_bits, e_type, e_machine, e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize)`` or None."""
    if len(head) < 52 or head[:4] != b"\x7fELF" or head[5] != 1:
        return None
    if head[4] == 2 and len(head) >= 64:
        (e_type, e_machine, _v, _entry, phoff, shoff, _flags, _ehsize, phentsize, phnum, shentsize, _shnum,
         _shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", head, 16)
        return 64, e_type, e_machine, phoff, shoff, phentsize, phnum, shentsize
    if head[4] == 1:
        (e_type, e_machine, _v, _entry, phoff, shoff, _flags, _ehsize, phentsize, phnum, shentsize, _shnum,
         _shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", head, 16)
        return 32, e_type, e_machine, phoff, shoff, phentsize, phnum, shentsize
    return None


def looks_like(head: bytes, size: int) -> bool:
    """An ELF core whose program header table lies inside the file (big-endian cores are recognised so that
    opening them is refused instead of falling back to a raw image)."""
    if len(head) >= 18 and head[:4] == b"\x7fELF" and head[5] == 2:
        return head[4] in (1, 2) and struct.unpack_from(">H", head, 16)[0] == ET_CORE
    h = _ehdr(head)
    if h is None:
        return False
    bits, e_type, _m, phoff, _shoff, phentsize, phnum, _she = h
    if e_type != ET_CORE or phentsize != (56 if bits == 64 else 32) or phnum == 0:
        return False
    return phnum == PN_XNUM or phoff + phentsize * phnum <= size


def _notes(blob: bytes):
    """``(name, type, desc)`` for each note (4-byte aligned name and descriptor, as both producers write them;
    VirtualBox's namesz excludes the NUL and its names are padded to 8, which 4-byte rounding also lands on)."""
    pos = 0
    while pos + 12 <= len(blob):
        namesz, descsz, ntype = struct.unpack_from("<III", blob, pos)
        pos += 12
        name = blob[pos:pos + namesz].rstrip(b"\x00")
        pos += (namesz + 3) & ~3
        desc = blob[pos:pos + descsz]
        pos += (descsz + 3) & ~3
        yield name, ntype, desc


def open_elfcore(name: str, path: str):
    with open(path, "rb") as fh:
        head = fh.read(64)
        if head[:4] == b"\x7fELF" and len(head) > 5 and head[5] == 2:
            raise UnsupportedError("%s is a big-endian ELF core: only little-endian cores are supported" % path)
        h = _ehdr(head)
        if h is None:
            raise FormatError("%s is not a little-endian ELF file" % path)
        bits, e_type, machine, phoff, shoff, phentsize, phnum, shentsize = h
        if e_type != ET_CORE:
            raise FormatError("%s is an ELF file of type %d, not a core (type 4)" % (path, e_type))
        if phnum == PN_XNUM:
            fh.seek(shoff)
            sh0 = fh.read(shentsize)
            if len(sh0) < (64 if bits == 64 else 40):
                raise FormatError("%s: e_phnum is PN_XNUM but section header 0 (offset 0x%x) is missing" % (path, shoff))
            phnum = struct.unpack_from("<I", sh0, 44 if bits == 64 else 28)[0]
        fh.seek(phoff)
        table = fh.read(phentsize * phnum)
        if len(table) < phentsize * phnum:
            raise FormatError("%s: program header table (%d entries at 0x%x) is truncated" % (path, phnum, phoff))
        loads, notes = [], []
        for i in range(phnum):
            if bits == 64:
                p_type, _flags, off, vaddr, paddr, filesz, memsz, _align = struct.unpack_from("<IIQQQQQQ", table,
                                                                                               i * phentsize)
            else:
                p_type, off, vaddr, paddr, filesz, memsz, _flags, _align = struct.unpack_from("<IIIIIIII", table,
                                                                                               i * phentsize)
            if p_type == PT_LOAD:
                loads.append((paddr, vaddr, off, filesz, memsz))
            elif p_type == PT_NOTE and filesz:
                fh.seek(off)
                notes.append(fh.read(filesz))
    meta = {"format": "elfcore", "elf_class": bits, "machine": EM.get(machine, str(machine)), "e_machine": machine,
            "producer": "generic", "cpus": [], "load_segments": len(loads), "warnings": []}
    for blob in notes:
        for nname, ntype, desc in _notes(blob):
            if nname == b"QEMU" and ntype == 0 and len(desc) >= QEMU_CR_OFFSET + 40:
                meta["producer"] = "qemu"
                version, size = struct.unpack_from("<II", desc, 0)
                cr = struct.unpack_from("<5Q", desc, QEMU_CR_OFFSET)
                rip, rflags = struct.unpack_from("<QQ", desc, 8 + 16 * 8)
                meta["cpus"].append({"cpu": len(meta["cpus"]), "cr0": cr[0], "cr2": cr[2], "cr3": cr[3], "cr4": cr[4],
                                     "rip": rip, "rflags": rflags, "qemu_state_version": version})
            elif nname == b"VBCORE" and ntype == NT_VBOXCORE and len(desc) >= 24:
                magic, fmt_version, _cb, vbox_version, revision, ncpus = struct.unpack_from("<6I", desc, 0)
                if magic != VBOX_MAGIC:
                    meta["warnings"].append("VBCORE note has magic 0x%x, expected 0x%x" % (magic, VBOX_MAGIC))
                meta.update(producer="virtualbox", vbox_core_format=fmt_version, vbox_version=vbox_version,
                            vbox_revision=revision, vbox_cpus=ncpus)
            elif nname == b"VBCPU" and ntype == NT_VBOXCPU and len(desc) >= VBOX_CR_OFFSET + 32:
                cr0, cr2, cr3, cr4 = struct.unpack_from("<4Q", desc, VBOX_CR_OFFSET)
                rip, rsp = struct.unpack_from("<QQ", desc, 14 * 8)
                meta["cpus"].append({"cpu": len(meta["cpus"]), "cr0": cr0, "cr2": cr2, "cr3": cr3, "cr4": cr4,
                                     "rip": rip, "rsp": rsp})
    if meta["cpus"]:
        meta["cr3"] = meta["cpus"][0]["cr3"]
    all_ones = (1 << bits) - 1
    phys = [l for l in loads if l[0] != all_ones]
    if len(phys) > 1 and all(l[0] == 0 for l in phys):
        raise UnsupportedError("%s is an ELF core whose %d PT_LOAD segments all have p_paddr 0: a process core "
                               "(virtual addresses only), not a physical memory dump" % (path, len(phys)))
    if meta["producer"] == "qemu":
        meta["qemu_paging"] = any(l[1] != l[0] for l in phys if l[3])
    runs, tail, skipped = _physical_runs(phys)
    if tail:
        meta["warnings"].append("%d byte(s) of PT_LOAD memory (p_memsz beyond p_filesz, e.g. MMIO or filtered "
                                "ranges) are not in the file and read as absent" % tail)
    if skipped:
        meta["warnings"].append("%d byte(s) of PT_LOAD segments alias physical memory already mapped by an earlier "
                                "segment (paging-mode or kernel-text duplicates) and were not mapped twice" % skipped)
    meta["absent_tail_bytes"], meta["aliased_bytes"] = tail, skipped
    layer, warnings = file_runs(name, path, runs, "elfcore")
    meta["warnings"] += warnings
    meta["truncated"] = bool(warnings)
    meta["physical_runs"] = list(layer.ranges())
    return layer, meta


def _physical_runs(loads) -> Tuple[List[Tuple[int, int, int]], int, int]:
    """``(address, length, file_offset)`` from PT_LOADs; where two segments map the same physical bytes (aliases of
    the same RAM), the one starting lower keeps them."""
    tail = sum(max(0, memsz - filesz) for _p, _v, _o, filesz, memsz in loads)
    pieces = sorted((p, min(filesz, memsz), off) for p, _v, off, filesz, memsz in loads if min(filesz, memsz) > 0)
    runs, end, skipped = [], -1, 0
    for addr, length, off in pieces:
        if addr + length <= end:
            skipped += length
            continue
        if addr < end:
            cut = end - addr
            skipped += cut
            addr, length, off = end, length - cut, off + cut
        runs.append((addr, length, off))
        end = addr + length
    return runs, tail, skipped
