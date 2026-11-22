"""Linux x86-64 kernel virtual memory over a physical RAM image or ``/proc/kcore``.

Address translation (``arch/x86/include/asm/page_64.h``, ``pgtable_64_types.h``):

* kernel image (``_text`` .. ``_end``, above ``__START_KERNEL_map`` = 0xffffffff80000000):
  ``pa = va - __START_KERNEL_map + phys_base``
* direct map (``page_offset_base`` .. + physical RAM): ``pa = va - page_offset_base``
* anything else (vmalloc, vmemmap, modules): walk ``init_top_pgt`` (4-level, or
  5-level when ``__pgtable_l5_enabled``), honouring 1 GiB / 2 MiB large pages.

With KASLR the kernel's physical load address is unknown in a raw image. A kcore
container records it (checked cheaply at its expected location); otherwise it is
recovered by finding the ``linux_banner`` string: for each ``"Linux version "`` hit
the candidate ``phys_base`` is checked against the ``phys_base`` variable stored in
the image itself, which must hold the same value. Over ``/proc/kcore`` it comes from
the kernel-text segment's physical address. Symbol addresses come from
``/proc/kallsyms`` (or ``System.map``) taken from the same boot; struct layouts come
from that boot's BTF (``hostmem.btf``).
"""

from __future__ import annotations

import os
import struct
from typing import Dict, Iterator, List, Optional, Tuple

from keto.framework.exceptions import InvalidAddressException, RequirementError
from keto.framework.layers import DataLayer
from keto.framework.scanners import BytesScanner, scan
from keto.hostmem import btf as btf_mod

START_KERNEL_MAP = 0xFFFFFFFF80000000
PTE_ADDR = 0x000FFFFFFFFFF000
#: symbols the host-memory plugins use; acquisition stores these from /proc/kallsyms
WANTED_SYMBOLS = ("_text", "_stext", "_etext", "_end", "linux_banner", "phys_base", "page_offset_base", "vmalloc_base",
                  "vmemmap_base", "__pgtable_l5_enabled", "init_top_pgt", "init_task", "dxgdrv", "dxgk_fops",
                  "nvidia_fops", "nv_linux_devices", "g_resServ", "g_uvm_global", "init_pid_ns")


def parse_kallsyms(text: str) -> Dict[str, int]:
    """``/proc/kallsyms`` or ``System.map`` text -> {name: address} (first definition wins)."""
    out: Dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            if addr and parts[2] not in out:
                out[parts[2]] = addr
    return out


class KcoreReader:
    """Reads kernel virtual addresses from ``/proc/kcore`` (an ELF core whose PT_LOAD segments are keyed by
    kernel virtual address). Needs root."""

    def __init__(self, path: str = "/proc/kcore"):
        self.fd = os.open(path, os.O_RDONLY)
        hdr = os.pread(self.fd, 64, 0)
        if hdr[:4] != b"\x7fELF" or hdr[4] != 2:
            raise RequirementError("%s is not a 64-bit ELF core" % path)
        phoff, = struct.unpack_from("<Q", hdr, 32)
        phentsize, phnum = struct.unpack_from("<HH", hdr, 54)
        raw = os.pread(self.fd, phentsize * phnum, phoff)
        self.segments: List[Tuple[int, int, int, int]] = []  # (vaddr, size, file offset, paddr)
        for i in range(phnum):
            p_type, _flags, off, vaddr, paddr, filesz = struct.unpack_from("<IIQQQQ", raw, i * phentsize)
            if p_type == 1 and filesz:
                self.segments.append((vaddr, filesz, off, paddr))
        self.segments.sort()

    def read(self, va: int, n: int) -> bytes:
        out = bytearray()
        while n > 0:
            seg = next((s for s in self.segments if s[0] <= va < s[0] + s[1]), None)
            if seg is None:
                raise InvalidAddressException("kcore", va, "kernel address not in /proc/kcore")
            take = min(n, seg[0] + seg[1] - va)
            data = os.pread(self.fd, take, seg[2] + (va - seg[0]))
            if len(data) != take:
                raise InvalidAddressException("kcore", va, "short read")
            out += data
            va += take
            n -= take
        return bytes(out)

    def ram_ranges(self, page_offset_base: int) -> List[Tuple[int, int, int]]:
        """``[(paddr, size, vaddr)]`` of the direct-map segments (physical RAM)."""
        return [(p, s, v) for v, s, _o, p in self.segments
                if p not in (0xFFFFFFFFFFFFFFFF,) and v - p == page_offset_base]

    def text_phys_base(self, text_va: int) -> Optional[int]:
        """``phys_base`` from the segment holding ``_text``: /proc/kcore gives the kernel-text segment
        ``p_paddr = __pa_symbol(_text) = _text - __START_KERNEL_map + phys_base``."""
        for v, s, _o, p in self.segments:
            if v <= text_va < v + s and p != 0xFFFFFFFFFFFFFFFF:
                return p + (text_va - v) - (text_va - START_KERNEL_MAP)
        return None

    def close(self):
        os.close(self.fd)


class KernelMemory:
    """Kernel virtual address space plus typed access through BTF."""

    def __init__(self, btf: btf_mod.Btf, symbols: Dict[str, int], phys: Optional[DataLayer] = None,
                 kcore: Optional[KcoreReader] = None, phys_base: Optional[int] = None,
                 page_offset_base: Optional[int] = None, l5: Optional[bool] = None, pad_gaps=False,
                 phys_base_hint: Optional[int] = None):
        """``pad_gaps``: read omitted (all-zero) pages of a sparse image as zeros - True, or a list of
        ``(start, size)`` physical ranges outside which nothing was acquired. ``phys_base_hint``: the value recorded
        at acquisition, used when the image confirms it (else the image is scanned)."""
        if phys is None and kcore is None:
            raise RequirementError("kernel memory needs a physical RAM image or /proc/kcore")
        self.btf, self.symbols, self.phys, self.kcore, self.pad_gaps = btf, symbols, phys, kcore, pad_gaps
        self.notes: List[str] = []
        # the kernel image is mapped linearly from _text to _end; modules and fixmap above it need the page tables
        self._image = (symbols["_text"], symbols["_end"]) if "_text" in symbols and "_end" in symbols else \
            (START_KERNEL_MAP, 1 << 64)
        self.phys_base = phys_base
        if phys is not None and phys_base is None:
            self.phys_base = self._find_phys_base(phys_base_hint)
        elif kcore is not None and phys_base is None and "_text" in symbols:
            self.phys_base = kcore.text_phys_base(symbols["_text"])
            if self.phys_base is not None:
                self.notes.append("phys_base 0x%x from the /proc/kcore kernel-text segment" % self.phys_base)
        self.page_offset_base = page_offset_base if page_offset_base is not None else \
            self.u64(self.sym("page_offset_base"))
        if l5 is None:
            l5 = bool(self.u32(symbols["__pgtable_l5_enabled"])) if "__pgtable_l5_enabled" in symbols else False
        self.l5 = l5
        self._pgd = None
        if phys is not None and "init_top_pgt" in symbols:
            self._pgd = symbols["init_top_pgt"] - START_KERNEL_MAP + self.phys_base

    # -- symbols / bootstrap ---------------------------------------------------------------------------
    def sym(self, name: str) -> int:
        if name not in self.symbols:
            raise RequirementError("kernel symbol %s not available (kallsyms from the same boot needed)" % name)
        return self.symbols[name]

    def _phys_base_ok(self, cand: int) -> bool:
        """With the kernel loaded at ``cand``, linux_banner is in place and the phys_base variable holds ``cand``."""
        if cand < 0 or cand & 0xFFF:
            return False
        try:
            banner = self.phys.read(self.sym("linux_banner") - START_KERNEL_MAP + cand, 14)
            val = struct.unpack("<Q", self.phys.read(self.sym("phys_base") - START_KERNEL_MAP + cand, 8))[0]
        except InvalidAddressException:
            return False
        return banner == b"Linux version " and val == cand

    def _find_phys_base(self, hint: Optional[int] = None) -> int:
        if hint is not None:
            if self._phys_base_ok(hint):
                self.notes.append("phys_base 0x%x recorded at acquisition, confirmed by linux_banner and the "
                                  "phys_base variable" % hint)
                return hint
            self.notes.append("WARNING: phys_base 0x%x recorded at acquisition is not confirmed by the image; "
                              "scanning for linux_banner" % hint)
        va_banner, _ = self.sym("linux_banner"), self.sym("phys_base")  # missing symbols fail before the scan
        for off, _ in scan(self.phys, BytesScanner(b"Linux version ")):
            cand = off - (va_banner - START_KERNEL_MAP)
            if self._phys_base_ok(cand):
                self.notes.append("phys_base 0x%x located from linux_banner and confirmed by the phys_base "
                                  "variable" % cand)
                return cand
        raise RequirementError("could not locate the kernel image in the RAM image (no linux_banner whose "
                               "phys_base variable is self-consistent) - kallsyms must come from the same boot")

    # -- translation ---------------------------------------------------------------------------------------
    def v2p(self, va: int) -> int:
        if self._image[0] <= va < self._image[1]:
            return va - START_KERNEL_MAP + self.phys_base
        if self.page_offset_base <= va < self.page_offset_base + (1 << (55 if self.l5 else 46)):
            return va - self.page_offset_base
        return self._walk(va)

    def _walk(self, va: int) -> int:
        if self._pgd is None:
            raise InvalidAddressException("kernel", va, "no init_top_pgt for a page-table walk")
        table = self._pgd
        shifts = (48, 39, 30, 21, 12) if self.l5 else (39, 30, 21, 12)
        for level, sh in enumerate(shifts):
            e = struct.unpack("<Q", self._phys_read(table + ((va >> sh) & 0x1FF) * 8, 8))[0]
            if not e & 1:
                raise InvalidAddressException("kernel", va, "not present (level shift %d)" % sh)
            base = e & PTE_ADDR
            if sh in (30, 21) and e & 0x80:  # PS: 1 GiB / 2 MiB page
                return (base & ~((1 << sh) - 1)) | (va & ((1 << sh) - 1))
            if sh == 12:
                return base | (va & 0xFFF)
            table = base
        raise InvalidAddressException("kernel", va, "walk failed")

    def _phys_read(self, pa: int, n: int) -> bytes:
        pad = self.pad_gaps
        if pad and pad is not True:  # zero pages were omitted only inside the acquired ranges
            pad = any(s <= pa and pa + n <= s + size for s, size in pad)
        return self.phys.read(pa, n, pad=bool(pad))

    def read(self, va: int, n: int) -> bytes:
        if self.kcore is not None:
            return self.kcore.read(va, n)
        out = bytearray()
        while n > 0:
            take = min(n, 0x1000 - (va & 0xFFF))
            out += self._phys_read(self.v2p(va), take)
            va += take
            n -= take
        return bytes(out)

    def read_phys(self, pa: int, n: int) -> bytes:
        if self.kcore is not None:
            return self.kcore.read(self.page_offset_base + pa, n)
        return self._phys_read(pa, n)

    def page_to_pa(self, page_va: int) -> int:
        """Physical address of a ``struct page *`` (SPARSEMEM_VMEMMAP: pfn = (page - vmemmap_base) / sizeof)."""
        if not hasattr(self, "_vmemmap"):
            self._vmemmap = self.u64(self.sym("vmemmap_base"))
            self._page_size = self.btf.struct("page").size
        return ((page_va - self._vmemmap) // self._page_size) << 12

    def u32(self, va: int) -> int:
        return struct.unpack("<I", self.read(va, 4))[0]

    def u64(self, va: int) -> int:
        return struct.unpack("<Q", self.read(va, 8))[0]

    def obj(self, type_name: str, va: int) -> "KObj":
        return KObj(self, self.btf.struct(type_name), va)

    def readable(self, va: int) -> bool:
        try:
            self.read(va, 1)
            return True
        except InvalidAddressException:
            return False


class KObj:
    """A kernel structure instance at ``va``; fields read lazily by name through BTF."""

    __slots__ = ("km", "t", "va", "_raw")

    def __init__(self, km: KernelMemory, t: btf_mod.BtfType, va: int):
        self.km, self.t, self.va = km, t, va
        self._raw = None

    @property
    def raw(self) -> bytes:
        if self._raw is None:
            self._raw = self.km.read(self.va, self.t.size)
        return self._raw

    def offset(self, path: str) -> int:
        off, _, bf = self.km.btf.member(self.t, path)
        return off

    def field(self, path: str):
        """Integer / pointer / enum value, bitfield, char array (bytes) or nested KObj."""
        btf = self.km.btf
        off, tid, bf = btf.member(self.t, path)
        if bf:  # bit offset + size
            word = int.from_bytes(self.raw[off // 8:off // 8 + 8].ljust(8, b"\x00"), "little")
            return (word >> (off % 8)) & ((1 << bf) - 1)
        t = btf.resolve(tid)
        if t is None:
            return None
        if t.kind in (btf_mod.STRUCT, btf_mod.UNION):
            return KObj(self.km, t, self.va + off)
        size = btf.sizeof(tid)
        data = self.raw[off:off + size]
        if t.kind == btf_mod.ARRAY:
            return data
        signed = t.kind == btf_mod.INT and t.encoding & 1
        return int.from_bytes(data, "little", signed=bool(signed))

    def __getitem__(self, path: str):
        return self.field(path)

    def string(self, path: str, utf16: bool = False) -> str:
        data = self.field(path)
        if utf16:
            return data.decode("utf-16-le", "replace").split("\x00", 1)[0]
        return data.split(b"\x00", 1)[0].decode("utf-8", "replace")

    def list(self, head_path: str, entry_type: str, link_member: str, limit: int = 100000) -> Iterator["KObj"]:
        """Iterate a ``struct list_head`` at ``head_path`` whose entries are ``entry_type`` linked through
        ``link_member`` (container_of)."""
        head_va = self.va + self.offset(head_path)
        link_off = self.km.btf.offsetof(entry_type, link_member)
        node = self.km.u64(head_va)
        seen = set()
        while node and node != head_va and node not in seen and len(seen) < limit:
            seen.add(node)
            yield self.km.obj(entry_type, node - link_off)
            node = self.km.u64(node)

    def __repr__(self):
        return "<%s @0x%x>" % (self.t.name, self.va)
