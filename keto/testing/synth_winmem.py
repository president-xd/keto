"""Synthetic Windows-relevant physical-memory images with ground truth, for tests/test_winformats.py.

Every field offset below is written from the cited source, independently of the parsers in keto/formats (nothing
is imported from them), so a parser bug in an offset shows up as a test failure instead of being mirrored:

* crash dumps: kdmp-parser ``kdmp-parser-structs.h`` (``HEADER64``, ``BMP_HEADER64``, ``RDMP_HEADER64``,
  ``KERNEL/FULL_RDMP_HEADER64``) and its Rust port's ``RdmpHeader64`` layout notes
* ELF cores: QEMU ``dump/dump.c`` + ``target/i386/arch_dump.c`` (``QEMUCPUState``); VirtualBox
  ``DBGFR3CoreWrite.cpp`` + ``include/VBox/vmm/dbgfcorefmt.h`` (``DBGFCOREDESCRIPTOR``, ``DBGFCORECPU``)
* VMware: crash-utility ``vmware_vmss.h`` (tag bit fields, group descriptor, block tags) and Volatility's
  ``vmware`` address spaces (32-bit block sizes for the old magics)
* hiberfil: Vergilius Project ``PO_MEMORY_IMAGE`` / ``_PO_HIBER_PERF`` per build, ``_KPROCESSOR_STATE`` at 0x1000
  (Sylve et al. 2017), compression set / page descriptor bits (Sylve et al.; Volatility 3 PR #1036 for 24H2)

The compressors here are deliberately simple and independent of keto/formats/xpress.py: a greedy Plain LZ77 encoder
(MS-XCA 2.3) and an LZ77+Huffman encoder with a flat 9-bit code (every one of the 512 symbols gets length 9, a
complete canonical code), which exercises literals, matches, long lengths and offset bits. On Windows,
``ntdll_compress`` gives the real RtlCompressBuffer output, which tests use as ground truth.
"""

from __future__ import annotations

import os
import struct
import sys
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

PAGE = 4096


# -- deterministic content --------------------------------------------------------------------------------------------
def noise(n: int, seed: int) -> bytes:
    """``n`` pseudo-random bytes (xorshift64*, stable across Python versions)."""
    x = (seed * 0x9E3779B97F4A7C15 + 1) & 0xFFFFFFFFFFFFFFFF or 1
    out = bytearray()
    while len(out) < n:
        x ^= x >> 12
        x ^= (x << 25) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 27
        out += ((x * 0x2545F4914F6CDD1D) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    return bytes(out[:n])


def page_content(pfn: int, salt: bytes = b"") -> bytes:
    """A 4 KiB page that names its PFN, half compressible text and half noise (so codecs do real work)."""
    head = b"PFN=%016x %s|" % (pfn, salt)
    text = (b"physical page %x of the synthetic guest; " % pfn) * 64
    body = head + text[:2048 - len(head)] + noise(2048, pfn + 7)
    return body[:PAGE]


# -- ntdll ground truth (Windows) -------------------------------------------------------------------------------------
COMPRESSION_FORMAT_LZNT1, COMPRESSION_FORMAT_XPRESS, COMPRESSION_FORMAT_XPRESS_HUFF = 2, 3, 4
COMPRESSION_ENGINE_STANDARD, COMPRESSION_ENGINE_MAXIMUM = 0, 0x100
_NT = None


def ntdll_available() -> bool:
    return _ntdll() is not None


def _ntdll():
    global _NT
    if _NT is None and sys.platform == "win32":
        import ctypes
        nt = ctypes.WinDLL("ntdll")
        ul, us, vp = ctypes.c_ulong, ctypes.c_ushort, ctypes.c_void_p
        nt.RtlGetCompressionWorkSpaceSize.argtypes = [us, ctypes.POINTER(ul), ctypes.POINTER(ul)]
        nt.RtlCompressBuffer.argtypes = [us, vp, ul, vp, ul, ul, ctypes.POINTER(ul), vp]
        nt.RtlDecompressBufferEx.argtypes = [us, vp, ul, vp, ul, ctypes.POINTER(ul), vp]
        for f in (nt.RtlGetCompressionWorkSpaceSize, nt.RtlCompressBuffer, nt.RtlDecompressBufferEx):
            f.restype = ctypes.c_long
        _NT = nt
    return _NT


def _workspace(fmt: int):
    import ctypes
    ws, fs = ctypes.c_ulong(), ctypes.c_ulong()
    st = _ntdll().RtlGetCompressionWorkSpaceSize(fmt, ctypes.byref(ws), ctypes.byref(fs))
    if st < 0:
        raise OSError("RtlGetCompressionWorkSpaceSize(0x%x) failed: 0x%08x" % (fmt, st & 0xFFFFFFFF))
    return ctypes.create_string_buffer(max(ws.value, 1))


def ntdll_compress(fmt: int, data: bytes, engine: int = COMPRESSION_ENGINE_STANDARD) -> Optional[bytes]:
    """RtlCompressBuffer output, or None when ntdll declines (e.g. STATUS_BUFFER_TOO_SMALL for tiny Xpress input)."""
    import ctypes
    work = _workspace(fmt | engine)
    cap = 2 * len(data) + 8192
    out = ctypes.create_string_buffer(cap)
    src = ctypes.create_string_buffer(bytes(data), max(len(data), 1))
    final = ctypes.c_ulong()
    st = _ntdll().RtlCompressBuffer(fmt | engine, src, len(data), out, cap, 4096, ctypes.byref(final), work)
    if st < 0:
        return None
    return out.raw[:final.value]


def ntdll_decompress(fmt: int, data: bytes, size: int) -> bytes:
    import ctypes
    work = _workspace(fmt)
    out = ctypes.create_string_buffer(max(size, 1))
    src = ctypes.create_string_buffer(bytes(data), max(len(data), 1))
    final = ctypes.c_ulong()
    st = _ntdll().RtlDecompressBufferEx(fmt, out, size, src, len(data), ctypes.byref(final), work)
    if st < 0:
        raise OSError("RtlDecompressBufferEx failed: 0x%08x" % (st & 0xFFFFFFFF))
    return out.raw[:final.value]


# -- independent compressors ------------------------------------------------------------------------------------------
def _matches(data: bytes, max_offset: int, block: int = 0):
    """Greedy LZ77 parse: yields ("lit", byte) / ("match", offset, length); matches never cross a ``block``
    boundary (0 = no limit)."""
    table: Dict[bytes, int] = {}
    i, n = 0, len(data)
    while i < n:
        limit = n if not block else min(n, (i // block + 1) * block)
        best = 0
        if i + 3 <= limit:
            key = data[i:i + 3]
            j = table.get(key)
            table[key] = i
            if j is not None and i - j <= max_offset:
                length = 3
                while i + length < limit and data[j + length] == data[i + length]:
                    length += 1
                best, off = length, i - j
        if best >= 3:
            yield ("match", off, best)
            for k in range(i + 1, min(i + best, n - 2)):
                table[data[k:k + 3]] = k
            i += best
        else:
            yield ("lit", data[i])
            i += 1


def xpress_compress(data: bytes) -> bytes:
    """Plain LZ77 per MS-XCA 2.3: 32-bit flag words (MSB first, 1 = match), 16-bit match tokens (offset-1 << 3 |
    length), shared length nibbles, then byte / 16-bit / 32-bit lengths; unused final flag bits are ones."""
    out = bytearray(4)
    flag_pos, flags, nflags = 0, 0, 0
    half = None

    def flag(bit):
        nonlocal flag_pos, flags, nflags
        flags = (flags << 1) | bit
        nflags += 1
        if nflags == 32:
            struct.pack_into("<I", out, flag_pos, flags)
            flag_pos = len(out)
            out.extend(b"\x00\x00\x00\x00")
            flags, nflags = 0, 0

    for item in _matches(bytes(data), 8192):
        if item[0] == "lit":
            out.append(item[1])
            flag(0)
            continue
        _k, off, length = item
        l3 = length - 3
        out += struct.pack("<H", ((off - 1) << 3) | min(l3, 7))
        if l3 >= 7:
            l7 = l3 - 7
            if half is None:
                half = len(out)
                out.append(min(l7, 15))
            else:
                out[half] |= min(l7, 15) << 4
                half = None
            if l7 >= 15:
                l22 = l7 - 15
                if l22 < 255:
                    out.append(l22)
                else:
                    out.append(255)
                    out += struct.pack("<H", l3) if l3 <= 0xFFFF else struct.pack("<HI", 0, l3)
        flag(1)
    rest = 32 - nflags
    struct.pack_into("<I", out, flag_pos, ((flags << rest) | ((1 << rest) - 1)) & 0xFFFFFFFF)
    return bytes(out)


def _words_loaded(consumed: int) -> int:
    """16-bit words the MS-XCA 2.2.4 decoder has read after consuming ``consumed`` bits: it starts with 32 bits and
    ExtraBitCount 16 and reads another word whenever ExtraBitCount drops below 0."""
    return 2 + (consumed - 1) // 16 if consumed > 16 else 2


class _BitBlock:
    """One LZ77+Huffman block's bit stream with the raw length bytes placed where the decoder reads them: right
    after the words it has loaded at that point."""

    def __init__(self):
        self.bits = []          # (value, nbits)
        self.consumed = 0
        self.raw = []           # (words loaded before the bytes, bytes)

    def put(self, value: int, nbits: int):
        if nbits:
            self.bits.append((value, nbits))
            self.consumed += nbits

    def put_raw(self, data: bytes):
        self.raw.append((_words_loaded(self.consumed), data))

    def assemble(self) -> bytes:
        acc, nacc, words = 0, 0, []
        for value, nbits in self.bits:
            acc = (acc << nbits) | value
            nacc += nbits
            while nacc >= 16:
                nacc -= 16
                words.append((acc >> nacc) & 0xFFFF)
        if nacc:
            words.append((acc << (16 - nacc)) & 0xFFFF)
        need = _words_loaded(self.consumed)  # words loaded when the decoder leaves this block
        words += [0] * (need - len(words))
        out = bytearray()
        raw = list(self.raw)
        for k, w in enumerate(words[:need]):
            out += struct.pack("<H", w)
            while raw and raw[0][0] == k + 1:
                out += raw.pop(0)[1]
        for _k, data in raw:
            out += data
        return bytes(out)


def huffman_flat_compress(data: bytes) -> bytes:
    """LZ77+Huffman with every symbol at code length 9 (table bytes 0x99): code(symbol) = symbol in 9 bits. Blocks
    of 64 KiB output, each with its own table; matches stay inside their block; the last block ends with the EOF
    symbol 256."""
    data = bytes(data)
    out = bytearray()
    starts = list(range(0, len(data), 65536)) or [0]
    items = list(_matches(data, 65535, 65536))
    pos, it = 0, 0
    for bi, start in enumerate(starts):
        end = min(start + 65536, len(data))
        blk = _BitBlock()
        while pos < end:
            item = items[it]
            it += 1
            if item[0] == "lit":
                blk.put(item[1], 9)
                pos += 1
                continue
            _k, off, length = item
            obits = off.bit_length() - 1
            l3 = length - 3
            blk.put(256 + (obits << 4) + min(l3, 15), 9)
            if l3 >= 15:
                blk.put_raw(bytes([l3 - 15]) if l3 - 15 < 255 else b"\xff" + struct.pack("<H", l3))
            blk.put(off - (1 << obits), obits)
            pos += length
        if bi == len(starts) - 1:
            blk.put(256, 9)
        out += b"\x99" * 256 + blk.assemble()
    return bytes(out)


# -- Windows crash dumps (kdmp-parser HEADER64) ----------------------------------------------------------------------
DUMP_FIELDS = dict(major=0xF, minor=26100, dtb=0x1AD000, pfn_database=0xFFFFFA8000000000,
                   ps_loaded_module_list=0xFFFFF80312345670, ps_active_process_head=0xFFFFF80312346780,
                   machine=0x8664, ncpu=8, bugcheck=0x161, params=(1, 2, 3, 4),
                   kd_debugger_data_block=0xFFFFF80312000000, system_time=133800000000000000,
                   comment=b"keto synthetic live dump", uptime=123456789)


def _dump_header(dump_type: int, f: dict, runs: Sequence[Tuple[int, int]] = ()) -> bytearray:
    h = bytearray(b"PAGE" * (0x2000 // 4))     # unused header bytes carry the "PAGE" fill
    h[0x00:0x08] = b"PAGEDU64"                 # Signature 'PAGE', ValidDump 'DU64'
    struct.pack_into("<II", h, 0x08, f["major"], f["minor"])
    struct.pack_into("<Q", h, 0x10, f["dtb"])                      # DirectoryTableBase
    struct.pack_into("<Q", h, 0x18, f["pfn_database"])             # PfnDatabase
    struct.pack_into("<Q", h, 0x20, f["ps_loaded_module_list"])    # PsLoadedModuleList
    struct.pack_into("<Q", h, 0x28, f["ps_active_process_head"])   # PsActiveProcessHead
    struct.pack_into("<I", h, 0x30, f["machine"])                  # MachineImageType
    struct.pack_into("<I", h, 0x34, f["ncpu"])                     # NumberProcessors
    struct.pack_into("<I", h, 0x38, f["bugcheck"])                 # BugCheckCode
    struct.pack_into("<4Q", h, 0x40, *f["params"])                 # BugCheckCodeParameters[4]
    struct.pack_into("<Q", h, 0x80, f["kd_debugger_data_block"])   # KdDebuggerDataBlock
    if runs:                                                       # PhysicalMemoryBlock (PHYSMEM_DESC) @0x88
        struct.pack_into("<IIQ", h, 0x88, len(runs), 0, sum(c for _b, c in runs))
        for i, (base, count) in enumerate(runs):
            struct.pack_into("<QQ", h, 0x98 + 16 * i, base, count)
    struct.pack_into("<I", h, 0xF98, dump_type)                    # DumpType
    struct.pack_into("<q", h, 0xFA8, f["system_time"])             # SystemTime (FILETIME)
    comment = f["comment"]
    if comment is not None:
        h[0xFB0:0x1030] = comment.ljust(128, b"\x00")[:128]        # Comment[128]
    struct.pack_into("<q", h, 0x1030, f["uptime"])                 # SystemUpTime
    return h


def write_crash_dump(path: str, pages: Dict[int, bytes], dump_type: int, bmp_signature: bytes = b"SDMP",
                     bitmap_pages: Optional[int] = None, runs: Optional[Sequence[Tuple[int, int]]] = None,
                     fields: Optional[dict] = None, bmp_valid: bytes = b"DUMP", truncate: int = 0) -> dict:
    """Write a 64-bit crash dump of ``pages`` ({pfn: 4 KiB}). ``dump_type`` 1 uses ``runs`` [(base_pfn, count)]
    (pages missing from ``pages`` are written as zeros); 5/6 write a bitmap header; 8/9/10 an RDMP header with one
    PFN range per run of consecutive PFNs. Returns the truth: {"fields", "pages" (present pfn -> bytes)}."""
    f = dict(DUMP_FIELDS, **(fields or {}))
    present = sorted(pages)
    if dump_type == 1:
        runs = list(runs or _consecutive(present))
        body = bytearray(_dump_header(1, f, runs))
        truth = {}
        for base, count in runs:
            for p in range(base, base + count):
                data = pages.get(p, b"\x00" * PAGE)
                body += data
                truth[p] = data
    elif dump_type in (5, 6):
        nbits = bitmap_pages if bitmap_pages is not None else (present[-1] + 1 if present else 0)
        bitmap = bytearray((nbits + 7) // 8)
        for p in present:
            if p < nbits:
                bitmap[p // 8] |= 1 << (p % 8)  # bit i of the bitmap = PFN i
        inside = [p for p in present if p < nbits]
        first = (0x2038 + len(bitmap) + PAGE - 1) // PAGE * PAGE
        body = bytearray(_dump_header(dump_type, f))
        bmp = bytearray(0x38)
        bmp[0:4], bmp[4:8] = bmp_signature, bmp_valid                         # Signature, ValidDump
        struct.pack_into("<QQQ", bmp, 0x20, first, len(inside), nbits)        # FirstPage, TotalPresentPages, Pages
        body += bmp + bitmap
        body += b"\x00" * (first - len(body))
        truth = {}
        for p in inside:
            body += pages[p]
            truth[p] = pages[p]
    elif dump_type in (8, 9, 10):
        ranges = list(runs or _consecutive(present))
        metadata_size = 0x10 + 16 * len(ranges)            # PhysmemDesc (0x10) + PfnRange[n]
        first = 0x2020 + metadata_size                     # metadata starts after Header64 + RdmpHeader64
        body = bytearray(_dump_header(dump_type, f))
        body += struct.pack("<I4s4sIQQ", 0x40, b"RDMP", b"DUMP", 0, metadata_size, first)
        if dump_type == 10:                                # FULL_RDMP_HEADER64
            body += struct.pack("<IHHQ", len(ranges), 0, 0, sum(c for _b, c in ranges))
        else:                                              # KERNEL_RDMP_HEADER64
            body += struct.pack("<QQ", 0, 0)
        for base, count in ranges:
            body += struct.pack("<QQ", base, count)
        truth = {}
        for base, count in ranges:
            for p in range(base, base + count):
                body += pages[p]
                truth[p] = pages[p]
    else:
        body = bytearray(_dump_header(dump_type, f))
        truth = {}
    if truncate:
        del body[len(body) - truncate:]
    with open(path, "wb") as fh:
        fh.write(body)
    return {"fields": f, "pages": truth}


def _consecutive(pfns: Iterable[int]) -> List[Tuple[int, int]]:
    out: List[List[int]] = []
    for p in sorted(pfns):
        if out and out[-1][0] + out[-1][1] == p:
            out[-1][1] += 1
        else:
            out.append([p, 1])
    return [(b, c) for b, c in out]


# -- ELF cores ----------------------------------------------------------------------------------------------------
def _note(name: bytes, ntype: int, desc: bytes, namesz: Optional[int] = None, align: int = 4) -> bytes:
    nm = name + b"\x00"
    pad_name = (-len(nm)) % align
    pad_desc = (-len(desc)) % align
    return (struct.pack("<III", len(nm) if namesz is None else namesz, len(desc) + (pad_desc if align == 8 else 0),
                        ntype) + nm + b"\x00" * pad_name + desc + b"\x00" * pad_desc)


def qemu_cpu_state(cr3: int, rip: int = 0xFFFFF80000001000, cr0: int = 0x80050033, cr4: int = 0x350EF8) -> bytes:
    """QEMUCPUState (target/i386/arch_dump.c): version, size, rax..r15, rip, rflags, 10 x QEMUCPUSegment
    {u32 selector, limit, flags, pad; u64 base}, cr[5], kernel_gs_base."""
    s = struct.pack("<II", 1, 440)
    s += struct.pack("<16Q", *range(16))
    s += struct.pack("<QQ", rip, 0x246)
    s += b"".join(struct.pack("<IIIIQ", 0x10 + i, 0xFFFFFFFF, 0, 0, 0) for i in range(10))
    s += struct.pack("<5Q", cr0, 0, 0x1234, cr3, cr4)
    s += struct.pack("<Q", 0xFFFFF80000002000)
    return s


def write_qemu_core(path: str, segments: Sequence[Tuple[int, bytes]], cr3s: Sequence[int], elf_class: int = 64,
                    vaddrs: Optional[Sequence[int]] = None, memsz_extra: Sequence[int] = (),
                    xnum: bool = False) -> None:
    """A ``dump-guest-memory`` style core: PT_NOTE (per CPU an NT_PRSTATUS "CORE" note and a "QEMU" note), one
    PT_LOAD per segment with p_paddr = guest physical and p_vaddr = p_paddr unless ``vaddrs`` (paging mode).
    ``memsz_extra[i]`` makes p_memsz exceed p_filesz. ``xnum`` writes e_phnum = PN_XNUM and the count in sh_info."""
    notes = b"".join(_note(b"CORE", 1, b"\x00" * (336 if elf_class == 64 else 144)) for _c in cr3s)
    notes += b"".join(_note(b"QEMU", 0, qemu_cpu_state(c)) for c in cr3s)
    nph = 1 + len(segments)
    ehsize, phsize = (64, 56) if elf_class == 64 else (52, 32)
    phoff = ehsize
    shoff = phoff + phsize * nph if xnum else 0
    data_off = phoff + phsize * nph + (64 if xnum else 0)
    note_off = data_off
    off = note_off + len(notes)
    phdrs = []
    if elf_class == 64:
        phdrs.append(struct.pack("<IIQQQQQQ", 4, 0, note_off, 0, 0, len(notes), len(notes), 0))
    else:
        phdrs.append(struct.pack("<IIIIIIII", 4, note_off, 0, 0, len(notes), len(notes), 0, 0))
    for i, (paddr, data) in enumerate(segments):
        vaddr = vaddrs[i] if vaddrs else paddr     # dump.c: p_vaddr = virt_addr ?: p_paddr
        memsz = len(data) + (memsz_extra[i] if i < len(memsz_extra) else 0)
        if elf_class == 64:
            phdrs.append(struct.pack("<IIQQQQQQ", 1, 0, off, vaddr, paddr, len(data), memsz, 0))
        else:
            phdrs.append(struct.pack("<IIIIIIII", 1, off, vaddr, paddr, len(data), memsz, 0, 0))
        off += len(data)
    phnum = 0xFFFF if xnum else nph
    if elf_class == 64:
        eh = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01", 4, 62, 1, 0, phoff, shoff, 0, 64, 56, phnum,
                         64 if xnum else 0, 1 if xnum else 0, 0)
        sh = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, nph, 0, 0) if xnum else b""
    else:
        eh = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01", 4, 3, 1, 0, phoff, shoff, 0, 52, 32, phnum,
                         40 if xnum else 0, 1 if xnum else 0, 0)
        sh = struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, nph, 0, 0) if xnum else b""
    with open(path, "wb") as fh:
        fh.write(eh + b"".join(phdrs) + sh.ljust(64 if xnum else 0, b"\x00") + notes)
        for _p, data in segments:
            fh.write(data)


def vbox_cpu(cr3: int, rip: int = 0xFFFFF80000003000) -> bytes:
    """DBGFCORECPU (dbgfcorefmt.h): rax..r15 (14), rip, rsp, rbp, rflags, 6 x DBGFCORESEL {u64 base, u32 limit,
    u32 attr, u16 sel, u16, u32}, cr0, cr2, cr3, cr4, dr[8], ... (zero-filled to 0x400 bytes)."""
    s = struct.pack("<14Q", *range(100, 114)) + struct.pack("<4Q", rip, 0xFFFF8000AA00, 0, 0x202)
    s += b"".join(struct.pack("<QIIHHI", 0, 0xFFFFFFFF, 0, 0x10 + i, 0, 0) for i in range(6))
    s += struct.pack("<4Q", 0x80050033, 0x5678, cr3, 0x370678)
    return s.ljust(0x400, b"\x00")


def write_vbox_core(path: str, ranges: Sequence[Tuple[int, int, Optional[bytes]]], cr3s: Sequence[int]) -> None:
    """A ``dumpvmcore`` core: PT_NOTE then one PT_LOAD per range (p_paddr = GCPhysStart, p_vaddr = 0, MMIO ranges
    with p_filesz 0); notes "VBCORE" (0xb00) and "VBCPU" (0xb01) with n_namesz = strlen(name) and 8-byte padding."""
    desc = struct.pack("<6I", 0xC01AC0DE, 0x00010006, 24, (7 << 24) | (1 << 16) | 4, 165100, len(cr3s))
    notes = _note(b"VBCORE", 0xB00, desc, namesz=6, align=8)
    notes += b"".join(_note(b"VBCPU", 0xB01, vbox_cpu(c), namesz=5, align=8) for c in cr3s)
    nph = 1 + len(ranges)
    note_off = 64 + 56 * nph
    off = note_off + len(notes)
    phdrs = [struct.pack("<IIQQQQQQ", 4, 4, note_off, 0, 0, len(notes), 0, 0)]
    for gphys, memsz, data in ranges:
        filesz = len(data) if data is not None else 0
        phdrs.append(struct.pack("<IIQQQQQQ", 1, 4, off, 0, gphys, filesz, memsz, 0))
        off += filesz
    eh = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01", 4, 62, 1, 0, 64, 0, 0, 64, 56, nph, 0, 0, 0)
    with open(path, "wb") as fh:
        fh.write(eh + b"".join(phdrs) + notes)
        for _g, _m, data in ranges:
            if data is not None:
                fh.write(data)


# -- VMware ---------------------------------------------------------------------------------------------------------
def _vm_tag(name: bytes, value: Optional[bytes] = None, idx: Sequence[int] = (), block: Optional[bytes] = None,
            wide: bool = True, compressed: bool = False, pad: int = 3, mem_size: Optional[int] = None) -> bytes:
    """crash vmware_vmss.h: TAG bits 15..8 name length, 7..6 index count, 5..0 value size (63 block, 62 compressed
    block); block = size on disk, size in memory (u64, or u32 for old magics), u16 pad size, pad, data."""
    if block is not None:
        valsize = 62 if compressed else 63
        sizes = struct.pack("<QQ" if wide else "<II", len(block), len(block) if mem_size is None else mem_size)
        val = sizes + struct.pack("<H", pad) + b"\x00" * pad + block
    else:
        valsize = len(value)
        val = value
    tag = (len(name) << 8) | (len(idx) << 6) | valsize
    return struct.pack("<H", tag) + name + b"".join(struct.pack("<I", i) for i in idx) + val


def write_vmware(directory: str, stem: str, regions: Sequence[Tuple[int, int, int]], memory: bytes,
                 cr3s: Sequence[int] = (), ext: str = ".vmss", magic: int = 0xBED2BED2, embedded: bool = False,
                 cr_style: str = "block", write_vmem: bool = True, compressed_memory: bool = False) -> dict:
    """A state file with "memory" and "cpu" groups (plus an unrelated "Checkpoint" group) and, unless ``embedded``,
    a ``stem``.vmem holding ``memory``. ``regions`` are (regionPPN, regionPageNum, regionSize) in pages."""
    wide = magic & 0xF != 0
    mem = _vm_tag(b"align_mask", struct.pack("<I", 0xFFFF))
    if regions:
        mem += _vm_tag(b"regionsCount", struct.pack("<I", len(regions)))
    for i, (ppn, pnum, size) in enumerate(regions):
        mem += _vm_tag(b"regionPageNum", struct.pack("<I", pnum), (i,))
        mem += _vm_tag(b"regionPPN", struct.pack("<I", ppn), (i,))
        mem += _vm_tag(b"regionSize", struct.pack("<I", size), (i,))
    if embedded:
        mem += _vm_tag(b"Memory", idx=(0, 0), block=memory, wide=wide, compressed=compressed_memory,
                       mem_size=len(memory) * 2 if compressed_memory else None)
    mem += b"\x00\x00"
    cpu = _vm_tag(b"cpu:numVCPUs", struct.pack("<I", len(cr3s)))
    for c, cr3 in enumerate(cr3s):
        crs = [0x80050033, 0, 0xABC, cr3, 0x370678, 0, 0, 0, 0]
        if cr_style == "block":
            cpu += _vm_tag(b"CR64", idx=(c,), block=struct.pack("<9Q", *crs), wide=wide, pad=0)
        else:
            for n, v in enumerate(crs[:5]):
                cpu += _vm_tag(b"CR64", struct.pack("<Q", v), (c, n))
    cpu += b"\x00\x00"
    other = _vm_tag(b"checkpoint.id", struct.pack("<I", 7)) + b"\x00\x00"
    groups = [(b"Checkpoint", other), (b"memory", mem), (b"cpu", cpu)]
    off = 12 + 80 * len(groups)
    table, blobs = b"", b""
    for gname, blob in groups:
        table += struct.pack("<64sQQ", gname, off, len(blob))   # cptgroupdesc: name[64], position, size
        blobs += blob
        off += len(blob)
    state = os.path.join(directory, stem + ext)
    with open(state, "wb") as fh:
        fh.write(struct.pack("<III", magic, 8, len(groups)) + table + blobs)
    vmem = None
    if not embedded and write_vmem:
        vmem = os.path.join(directory, stem + ".vmem")
        with open(vmem, "wb") as fh:
            fh.write(memory)
    return {"state": state, "vmem": vmem}


# -- hiberfil.sys -----------------------------------------------------------------------------------------------------
#: Vergilius PO_MEMORY_IMAGE / _PO_HIBER_PERF (x64): LengthSelf (sizeof), FirstBootRestorePage, FirstKernelRestorePage,
#: PerfInfo offset + BootPagesProcessed / KernelPagesProcessed offsets inside PerfInfo, HighestPhysicalPage,
#: FirstSecureRestorePage; set header: Huffman bit and compressed-size width
HIBER_BUILDS = {
    "win8": dict(sizeof=0x360, boot=0x60, kernel=0x68, perf=0x70, bpp=0x150, kpp=0x158, highest=0x330, secure=None,
                 huff_bit=31, size_bits=22),
    "win10_1511": dict(sizeof=0x3B0, boot=0x68, kernel=0x70, perf=0x88, bpp=0x188, kpp=0x190, highest=0x380,
                       secure=0x60, huff_bit=31, size_bits=22),
    "win10_1607": dict(sizeof=0x3C8, boot=0x68, kernel=0x70, perf=0x88, bpp=0x190, kpp=0x198, highest=0x388,
                       secure=0x60, huff_bit=31, size_bits=22),
    "win10_22h2": dict(sizeof=0x3E0, boot=0x68, kernel=0x70, perf=0x88, bpp=0x1A0, kpp=0x1A8, highest=0x398,
                       secure=0x60, huff_bit=31, size_bits=22),
    "win11_23h2": dict(sizeof=0x448, boot=0x68, kernel=0x70, perf=0x88, bpp=0x1A0, kpp=0x1A8, highest=0x400,
                       secure=0x60, huff_bit=31, size_bits=22),
    "win11_24h2": dict(sizeof=0x4D8, boot=0x68, kernel=0x70, perf=0x88, bpp=0x1A8, kpp=0x1B0, highest=0x498,
                       secure=0x60, huff_bit=30, size_bits=21),
    "win11_26h2": dict(sizeof=0x4F0, boot=0x68, kernel=0x70, perf=0x88, bpp=0x1C0, kpp=0x1C8, highest=0x4B0,
                       secure=0x60, huff_bit=30, size_bits=21),
}
Compressor = Callable[[bytes], Optional[bytes]]


def write_hiber(path: str, boot_sets: Sequence[Tuple[Sequence[Tuple[int, int]], str]],
                kernel_sets: Sequence[Tuple[Sequence[Tuple[int, int]], str]], pages: Dict[int, bytes],
                build: str = "win10_22h2", signature: bytes = b"HIBR", cr3: int = 0x1AD000,
                xpress: Compressor = xpress_compress, huffman: Optional[Compressor] = None,
                length_self: Optional[int] = None, wipe_after_header: bool = False, kernel_gap_pages: int = 3,
                secure_page: int = 0, kernel_pages: Optional[Dict[int, bytes]] = None) -> dict:
    """Write a hibernation file. A set is ([(first_pfn, page_count), ...], codec) with codec "stored", "xpress" or
    "huffman"; its data are the descriptors' pages in order. A set whose compressed form is not smaller than the
    pages is stored (as Windows does). ``kernel_pages`` (default ``pages``) supplies the kernel sets' data, so a PFN
    can hold different data in the two sets. Returns {"pages": {pfn: bytes} (the last copy of each PFN), ...}."""
    b = HIBER_BUILDS[build]
    huffman = huffman or huffman_flat_compress
    size_mask = (1 << b["size_bits"]) - 1

    def chain(sets, src):
        out, codecs = bytearray(), []
        for descs, codec in sets:
            raw = b"".join(src[p] for first, count in descs for p in range(first, first + count))
            npages = len(raw) // PAGE
            blob, used = raw, "stored"
            if codec != "stored":
                comp = (xpress if codec == "xpress" else huffman)(raw)
                if comp is not None and len(comp) < len(raw):
                    blob, used = comp, codec
            assert len(blob) <= size_mask and npages <= 16
            hdr = len(descs) | (len(blob) << 8) | ((1 << b["huff_bit"]) if used == "huffman" else 0)
            out += struct.pack("<I", hdr)
            for first, count in descs:
                out += struct.pack("<Q", (first << 4) | (count - 1))   # NumPages (count - 1) in bits 0-3, PageNum above
            out += blob
            codecs.append(used)
        return bytes(out), sum(c for d, _c in sets for _f, c in d), codecs

    kernel_src = pages if kernel_pages is None else kernel_pages
    boot_blob, boot_count, boot_codecs = chain(boot_sets, pages)
    kernel_blob, kernel_count, kernel_codecs = chain(kernel_sets, kernel_src)
    first_boot = 2 if boot_sets else 0                       # page 0 header, page 1 processor state
    boot_end = first_boot * PAGE + len(boot_blob)
    first_kernel = ((boot_end + PAGE - 1) // PAGE + kernel_gap_pages) if kernel_sets else 0
    h = bytearray(PAGE)
    h[0:4] = signature                                      # Signature
    struct.pack_into("<I", h, 0x04, 0)                      # ImageType
    struct.pack_into("<I", h, 0x0C, b["sizeof"] if length_self is None else length_self)   # LengthSelf
    struct.pack_into("<Q", h, 0x10, 0)                      # PageSelf
    struct.pack_into("<I", h, 0x18, PAGE)                   # PageSize
    struct.pack_into("<q", h, 0x20, 133800000000000000)     # SystemTime
    struct.pack_into("<Q", h, 0x58, boot_count)             # NumPagesForLoader
    if b["secure"] is not None:
        struct.pack_into("<Q", h, b["secure"], secure_page)  # FirstSecureRestorePage
    struct.pack_into("<Q", h, b["boot"], first_boot)        # FirstBootRestorePage
    struct.pack_into("<Q", h, b["kernel"], first_kernel)    # FirstKernelRestorePage
    struct.pack_into("<Q", h, b["perf"] + b["bpp"], boot_count)     # PerfInfo.BootPagesProcessed
    struct.pack_into("<Q", h, b["perf"] + b["kpp"], kernel_count)   # PerfInfo.KernelPagesProcessed
    struct.pack_into("<Q", h, b["highest"], max(list(pages) + list(kernel_src)) if pages else 0)   # HighestPhysicalPage
    proc = bytearray(PAGE)
    struct.pack_into("<4Q", proc, 0, 0x80050033, 0x7FF0, cr3, 0x350EF8)  # _KSPECIAL_REGISTERS Cr0, Cr2, Cr3, Cr4
    body = bytearray(h + proc)
    body += boot_blob
    if kernel_sets:
        body += b"\x00" * (first_kernel * PAGE - len(body))
        body += kernel_blob
    body += b"\x00" * ((-len(body)) % PAGE)
    if wipe_after_header:
        body[PAGE:] = b"\x00" * (len(body) - PAGE)
    with open(path, "wb") as fh:
        fh.write(body)
    truth = {}
    for sets, src in ((boot_sets, pages), (kernel_sets, kernel_src)):
        for descs, _c in sets:
            for first, count in descs:
                for p in range(first, first + count):
                    truth[p] = src[p]
    return {"pages": truth, "codecs": boot_codecs + kernel_codecs, "first_kernel": first_kernel,
            "boot_pages": boot_count, "kernel_pages": kernel_count}
